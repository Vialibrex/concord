use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

use crate::ctx::BuildError;

/// mihomo checks the server certificate against the node's `ca` alone, with EKU serverAuth
/// and no host name: OpenVPN servers present certificates named for the server, not for the
/// address a profile dials.
#[derive(Debug)]
struct CaOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for CaOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, name, ocsp, now)
        {
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn invalid(what: &str, err: impl std::fmt::Display) -> BuildError {
    BuildError::invalid(format!("openvpn {what}: {err}"))
}

/// The TLS client mihomo builds per epoch, built once: TLS 1.2 and 1.3, no SNI, no session
/// resumption, the CA-only check, and the client certificate when the node has one.
pub(super) fn config(
    ca: &str,
    cert: &str,
    key: &str,
) -> Result<Arc<rustls::ClientConfig>, BuildError> {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_slice_iter(ca.as_bytes()).filter_map(Result::ok);
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(BuildError::invalid("parse openvpn ca certificate"));
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| invalid("ca", e))?;
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| invalid("TLS", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CaOnly(inner)));
    let mut config = if cert.trim().is_empty() {
        builder.with_no_client_auth()
    } else {
        let chain = CertificateDer::pem_slice_iter(cert.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid("client certificate", e))?;
        let key =
            PrivateKeyDer::from_pem_slice(key.as_bytes()).map_err(|e| invalid("client key", e))?;
        builder
            .with_client_auth_cert(chain, key)
            .map_err(|e| invalid("client certificate/key", e))?
    };
    config.enable_sni = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}
