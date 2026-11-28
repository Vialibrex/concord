use std::io;
use std::sync::Arc;

use concord_common::BoxStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{
    ClientConnectionData, EchConfig, EchMode, Resumption, UnbufferedClientConnection,
};
use rustls::kernel::KernelConnection;
use rustls::server::{ServerConfig, ServerConnectionData, UnbufferedServerConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, InsufficientSizeError, UnbufferedStatus};
use rustls::{
    ClientConfig, DigitallySignedStruct, ExtractedSecrets, SignatureScheme,
    SupportedProtocolVersion,
};
use rustls_pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::TlsError;
use crate::client_auth::ClientAuth;
use crate::policy::{CertPolicy, provider, rustls_error};
use crate::record::{Keys, RecordStream};
use crate::record_io::RecordIo;
use crate::trust::ConfigKey;

#[derive(Debug)]
struct PolicyVerifier {
    policy: Arc<CertPolicy>,
}

impl ServerCertVerifier for PolicyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.clone());
        chain.extend(intermediates.iter().cloned());
        self.policy
            .verify(&chain, server_name, self.policy.now())
            .map_err(rustls_error)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.policy.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.policy.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.policy.algorithms().supported_schemes()
    }
}

pub(crate) fn client_config(
    policy: Arc<CertPolicy>,
    alpn: Vec<Vec<u8>>,
    client_auth: Option<ClientAuth>,
    tls13_only: bool,
    ech: Option<&[u8]>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let versions: &[&'static SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    if client_auth.is_some() || ech.is_some() {
        return client_config_versions(policy, alpn, client_auth, versions, ech);
    }
    let key = ConfigKey {
        policy: policy.key(),
        alpn: alpn.clone(),
        tls13_only,
    };
    let keeper = policy.clone();
    keeper.trust().shared_config(key, || {
        client_config_versions(policy, alpn, None, versions, None)
    })
}

pub(crate) fn client_config_versions(
    policy: Arc<CertPolicy>,
    alpn: Vec<Vec<u8>>,
    client_auth: Option<ClientAuth>,
    versions: &[&'static SupportedProtocolVersion],
    ech: Option<&[u8]>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let builder = ClientConfig::builder_with_provider(provider());
    let builder = match ech {
        Some(list) => {
            let config = EchConfig::new(
                EchConfigListBytes::from(list.to_vec()),
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map_err(|err| TlsError::Config(format!("ech config: {err}")))?;
            builder
                .with_ech(EchMode::Enable(config))
                .map_err(|err| TlsError::Config(format!("ech: {err}")))?
        }
        None => builder
            .with_protocol_versions(versions)
            .map_err(|err| TlsError::Config(format!("tls versions: {err}")))?,
    };
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PolicyVerifier { policy }));
    let mut config = match client_auth {
        Some(auth) => builder
            .with_client_auth_cert(auth.chain, auth.key)
            .map_err(|err| TlsError::Config(format!("client certificate: {err}")))?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn;
    config.resumption = Resumption::disabled();
    config.enable_secret_extraction = true;
    Ok(Arc::new(config))
}

pub(crate) async fn connect(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    io: BoxStream,
    aligned: bool,
) -> io::Result<RecordStream> {
    let mut io = if aligned {
        RecordIo::new(io)
    } else {
        RecordIo::unaligned(io)
    };
    let conn = UnbufferedClientConnection::new(config.clone(), name).map_err(tls_error)?;
    let handover = handshake(conn, &mut io).await?;
    let keys = Keys::from_rustls(handover.secrets, handover.kernel)?;
    Ok(RecordStream::new(
        io,
        keys,
        handover.alpn,
        handover.leftover,
        handover.early,
    ))
}

/// The server side of [`connect`]: a config that allows secret extraction, and records
/// aligned so that a caller can take the transport back at a record boundary.
pub(crate) async fn accept(config: &Arc<ServerConfig>, io: BoxStream) -> io::Result<RecordStream> {
    let mut io = RecordIo::new(io);
    let conn = UnbufferedServerConnection::new(config.clone()).map_err(tls_error)?;
    let handover = handshake(conn, &mut io).await?;
    let keys = Keys::from_rustls(handover.secrets, handover.kernel)?;
    let records = RecordStream::new(io, keys, handover.alpn, handover.leftover, handover.early);
    Ok(records.serving())
}

const HANDSHAKE_READ: usize = 16 * 1024 + 2048 + 5;
pub(crate) type RustlsStream = tokio_rustls::client::TlsStream<RecordIo<BoxStream>>;

pub(crate) async fn connect_buffered(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    io: BoxStream,
) -> io::Result<RustlsStream> {
    tokio_rustls::TlsConnector::from(config.clone())
        .connect(name, RecordIo::unaligned(io))
        .await
}

/// rustls joins a handshake message split across records in the input buffer itself, and takes
/// none above `MAX_HANDSHAKE_SIZE`: room for one such message, its header and the next record.
const MAX_HANDSHAKE_BUFFER: usize = 0xffff + 4 + HANDSHAKE_READ;

fn tls_error(err: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Either side of rustls's unbuffered connection, which the handshake drives alike.
trait Unbuffered {
    type Data: std::marker::Send + 'static;

    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data>;
    fn is_handshaking(&self) -> bool;
    fn alpn(&self) -> Option<Vec<u8>>;
    fn into_kernel(self)
    -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), rustls::Error>;
}

impl Unbuffered for UnbufferedClientConnection {
    type Data = ClientConnectionData;

    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }

    fn is_handshaking(&self) -> bool {
        (**self).is_handshaking()
    }

    fn alpn(&self) -> Option<Vec<u8>> {
        self.alpn_protocol().map(<[u8]>::to_vec)
    }

    fn into_kernel(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), rustls::Error> {
        self.dangerous_into_kernel_connection()
    }
}

impl Unbuffered for UnbufferedServerConnection {
    type Data = ServerConnectionData;

    fn process<'c, 'i>(
        &'c mut self,
        incoming: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Self::Data> {
        self.process_tls_records(incoming)
    }

    fn is_handshaking(&self) -> bool {
        (**self).is_handshaking()
    }

    fn alpn(&self) -> Option<Vec<u8>> {
        self.alpn_protocol().map(<[u8]>::to_vec)
    }

    fn into_kernel(
        self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), rustls::Error> {
        self.dangerous_into_kernel_connection()
    }
}

/// Drives rustls's unbuffered connection to the end of the handshake, then takes the
/// traffic secrets so each direction can run its own record layer.
struct Handover<D> {
    secrets: ExtractedSecrets,
    kernel: KernelConnection<D>,
    alpn: Option<Vec<u8>>,
    leftover: Vec<u8>,
    early: Vec<u8>,
}

fn encode<D>(
    data: &mut rustls::unbuffered::EncodeTlsData<'_, D>,
    outgoing: &mut Vec<u8>,
    encoded: usize,
) -> io::Result<usize> {
    loop {
        match data.encode(outgoing.get_mut(encoded..).unwrap_or_default()) {
            Ok(n) => return Ok(n),
            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                outgoing.resize(encoded + required_size, 0);
            }
            Err(err) => return Err(io::Error::other(err.to_string())),
        }
    }
}

/// What the handshake had read and not yet processed, and encoded and not yet sent. rustls
/// keeps ranges into the read buffer between calls, so each call takes the same buffer.
struct Pending<'a> {
    incoming: &'a mut [u8],
    used: usize,
    outgoing: &'a mut Vec<u8>,
    encoded: usize,
}

/// rustls queues the fatal alert for an error it reports, and gives it out on the next call
/// only; the handshake sends it, as tokio-rustls and Go do, before it fails.
async fn send_alert<C: Unbuffered>(
    conn: &mut C,
    io: &mut RecordIo<BoxStream>,
    pending: Pending<'_>,
) {
    let Pending {
        incoming,
        mut used,
        outgoing,
        mut encoded,
    } = pending;
    for _ in 0..4 {
        let UnbufferedStatus { discard, state } =
            conn.process(incoming.get_mut(..used).unwrap_or_default());
        let more = match state {
            Ok(ConnectionState::EncodeTlsData(mut data)) => {
                match encode(&mut data, outgoing, encoded) {
                    Ok(n) => {
                        encoded += n;
                        true
                    }
                    Err(_) => false,
                }
            }
            Ok(ConnectionState::TransmitTlsData(data)) => {
                data.done();
                false
            }
            _ => false,
        };
        incoming.copy_within(discard..used, 0);
        used -= discard;
        if !more {
            break;
        }
    }
    if encoded > 0 {
        let _ = io
            .write_all(outgoing.get(..encoded).unwrap_or_default())
            .await;
        let _ = io.flush().await;
    }
}

async fn handshake<C: Unbuffered>(
    mut conn: C,
    io: &mut RecordIo<BoxStream>,
) -> io::Result<Handover<C::Data>> {
    let mut incoming = vec![0u8; HANDSHAKE_READ];
    let mut used = 0;
    let mut outgoing: Vec<u8> = Vec::new();
    let mut encoded = 0;
    let mut early = Vec::new();
    loop {
        let UnbufferedStatus { discard, state } =
            conn.process(incoming.get_mut(..used).unwrap_or_default());
        let mut blocked = false;
        let mut writable = false;
        let state = match state {
            Ok(state) => state,
            Err(err) => {
                incoming.copy_within(discard..used, 0);
                used -= discard;
                let pending = Pending {
                    incoming: &mut incoming,
                    used,
                    outgoing: &mut outgoing,
                    encoded,
                };
                send_alert(&mut conn, io, pending).await;
                return Err(tls_error(err));
            }
        };
        match state {
            ConnectionState::EncodeTlsData(mut data) => {
                encoded += encode(&mut data, &mut outgoing, encoded)?;
            }
            ConnectionState::TransmitTlsData(data) => {
                io.write_all(outgoing.get(..encoded).unwrap_or_default())
                    .await?;
                io.flush().await?;
                encoded = 0;
                data.done();
            }
            ConnectionState::BlockedHandshake => blocked = true,
            ConnectionState::ReadTraffic(mut traffic) => {
                while let Some(record) = traffic.next_record() {
                    early.extend_from_slice(record.map_err(tls_error)?.payload);
                }
            }
            ConnectionState::WriteTraffic(_) => writable = true,
            ConnectionState::PeerClosed | ConnectionState::Closed => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake eof",
                ));
            }
            _ => return Err(io::Error::other("tls: unexpected handshake state")),
        }
        incoming.copy_within(discard..used, 0);
        used -= discard;
        if writable && !conn.is_handshaking() {
            break;
        }
        blocked |= writable;
        if blocked {
            if used == incoming.len() {
                if incoming.len() >= MAX_HANDSHAKE_BUFFER {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls: handshake message too long",
                    ));
                }
                incoming.resize((incoming.len() * 2).min(MAX_HANDSHAKE_BUFFER), 0);
            }
            let n = io
                .read(incoming.get_mut(used..).unwrap_or_default())
                .await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake eof",
                ));
            }
            used += n;
        }
    }
    if encoded > 0 {
        io.write_all(outgoing.get(..encoded).unwrap_or_default())
            .await?;
        io.flush().await?;
    }
    let alpn = conn.alpn();
    let (secrets, kernel) = conn.into_kernel().map_err(tls_error)?;
    incoming.truncate(used);
    Ok(Handover {
        secrets,
        kernel,
        alpn,
        leftover: incoming,
        early,
    })
}
