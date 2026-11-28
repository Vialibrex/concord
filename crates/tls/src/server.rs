//! The TLS a profile's listeners serve: a certificate and key the profile gives, which a
//! reload of their files replaces under live listeners, ALPN, and the client certificate
//! modes of Go's `tls.ClientAuthType`.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arc_swap::ArcSwap;
use concord_common::{BoxStream, Stream};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{
    ClientHello, ResolvesServerCert, ServerConfig, VerifierBuilderError, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::{self, PemObject};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;

use crate::TlsConn;
use crate::policy::provider;

/// Go's `tls.ClientAuthType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuth {
    None,
    Request,
    RequireAny,
    VerifyIfGiven,
    RequireAndVerify,
}

pub struct ServerOptions<'a> {
    pub certs: Arc<Certs>,
    pub client_auth: ClientAuth,
    /// The CAs a client certificate is verified against, for the verifying modes.
    pub client_ca_pem: Option<&'a [u8]>,
    pub alpn: Vec<Vec<u8>>,
}

/// Why a listener's TLS could not be built, named by the profile field at fault.
#[derive(Debug, thiserror::Error)]
pub enum ServerTlsError {
    #[error("{field}: {source}")]
    Pem {
        field: &'static str,
        source: pem::Error,
    },
    #[error("certificate: no certificate in the PEM")]
    NoCertificate,
    #[error("{field}: {source}")]
    Rustls {
        field: &'static str,
        source: rustls::Error,
    },
    #[error("client-auth-cert: {0}")]
    Verifier(#[from] VerifierBuilderError),
}

fn pem_error(field: &'static str) -> impl FnOnce(pem::Error) -> ServerTlsError {
    move |source| ServerTlsError::Pem { field, source }
}

fn rustls_error(field: &'static str) -> impl FnOnce(rustls::Error) -> ServerTlsError {
    move |source| ServerTlsError::Rustls { field, source }
}

/// The certificate a listener presents, which every new handshake reads, so replacing it
/// leaves established connections alone.
#[derive(Debug)]
pub struct Certs(ArcSwap<CertifiedKey>);

impl Certs {
    pub fn new(certificate_pem: &[u8], private_key_pem: &[u8]) -> Result<Self, ServerTlsError> {
        Ok(Certs(ArcSwap::from_pointee(certified(
            certificate_pem,
            private_key_pem,
        )?)))
    }

    /// Leaves the certificate as it was when the new one does not load.
    pub fn replace(
        &self,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<(), ServerTlsError> {
        self.0
            .store(Arc::new(certified(certificate_pem, private_key_pem)?));
        Ok(())
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        self.0.load_full()
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

fn certified(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<CertifiedKey, ServerTlsError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(certificate_pem)
        .collect::<Result<_, _>>()
        .map_err(pem_error("certificate"))?;
    if chain.is_empty() {
        return Err(ServerTlsError::NoCertificate);
    }
    let key = PrivateKeyDer::from_pem_slice(private_key_pem).map_err(pem_error("private-key"))?;
    let certified =
        CertifiedKey::from_der(chain, key, &provider()).map_err(rustls_error("private-key"))?;
    Ok(certified)
}

#[derive(Clone)]
pub struct TlsServer {
    acceptor: TlsAcceptor,
    records: Arc<ServerConfig>,
}

impl TlsServer {
    pub fn new(options: &ServerOptions<'_>) -> Result<Self, ServerTlsError> {
        let config = server_config(options, rustls::DEFAULT_VERSIONS)?;
        let mut records = config.clone();
        records.enable_secret_extraction = true;
        Ok(TlsServer {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            records: Arc::new(records),
        })
    }

    /// The TLS of a QUIC listener, which QUIC requires to be 1.3.
    pub fn quic(options: &ServerOptions<'_>) -> Result<ServerConfig, ServerTlsError> {
        server_config(options, &[&rustls::version::TLS13])
    }

    pub async fn accept<S: Stream>(&self, stream: S) -> io::Result<ServerTls<S>> {
        Ok(ServerTls(self.acceptor.accept(stream).await?))
    }

    /// The same handshake, past which the connection keeps its own record layer and hands
    /// out the transport beneath at a record boundary, as XTLS Vision needs.
    pub async fn accept_records(&self, stream: BoxStream) -> io::Result<TlsConn> {
        let records = crate::rustls_backend::accept(&self.records, stream).await?;
        Ok(TlsConn::Record(Box::new(records)))
    }
}

fn server_config(
    options: &ServerOptions<'_>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<ServerConfig, ServerTlsError> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)
        .map_err(rustls_error("tls"))?
        .with_client_cert_verifier(client_verifier(options)?)
        .with_cert_resolver(options.certs.clone());
    config.alpn_protocols = options.alpn.clone();
    Ok(config)
}

fn client_verifier(
    options: &ServerOptions<'_>,
) -> Result<Arc<dyn ClientCertVerifier>, ServerTlsError> {
    let verified = |optional: bool| -> Result<Arc<dyn ClientCertVerifier>, ServerTlsError> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(options.client_ca_pem.unwrap_or_default()) {
            roots
                .add(cert.map_err(pem_error("client-auth-cert"))?)
                .map_err(rustls_error("client-auth-cert"))?;
        }
        let builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider());
        let builder = if optional {
            builder.allow_unauthenticated()
        } else {
            builder
        };
        Ok(builder.build()?)
    };
    Ok(match options.client_auth {
        ClientAuth::None => WebPkiClientVerifier::no_client_auth(),
        ClientAuth::Request => Arc::new(AnyClientCert { mandatory: false }),
        ClientAuth::RequireAny => Arc::new(AnyClientCert { mandatory: true }),
        ClientAuth::VerifyIfGiven => verified(true)?,
        ClientAuth::RequireAndVerify => verified(false)?,
    })
}

/// Go's `RequestClientCert` and `RequireAnyClientCert`: any certificate is taken, though
/// the handshake still proves the client holds its key.
#[derive(Debug)]
struct AnyClientCert {
    mandatory: bool,
}

impl ClientCertVerifier for AnyClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct ServerTls<S>(tokio_rustls::server::TlsStream<S>);

impl<S> ServerTls<S> {
    pub fn alpn(&self) -> Option<&[u8]> {
        self.0.get_ref().1.alpn_protocol()
    }
}

impl<S: Stream> AsyncRead for ServerTls<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: Stream> AsyncWrite for ServerTls<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

/// The records hide what the stream beneath could hand out: its socket carries ciphertext.
impl<S: Stream> Stream for ServerTls<S> {
    concord_common::stream_policy!(default: all);
}
