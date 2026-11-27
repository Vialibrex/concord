#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    reason = "the tests run a loopback endpoint on plain sockets"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::packet::UdpPayload;
use concord_common::serve::{Current, EndpointService, InboundCx};
use concord_common::{
    Address, BoxStream, ClockOffset, FlowHandler, FlowMeta, Tasks, UdpFlow, UdpReply,
};
use concord_config::listener::{ClientAuth, ServerTls};
use concord_platform::HomeDir;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::sync::{Notify, watch};

use super::certs::SelfSigned;
use super::{Carried, Keep, ServerEnv, TlsSetup};
use crate::util::lock;

pub(super) fn unnamed_tls() -> ServerTls {
    ServerTls {
        certificate: String::new(),
        private_key: String::new(),
        client_auth: ClientAuth::None,
        client_auth_cert: String::new(),
    }
}

/// A self-signed setup, which reads nothing from the home directory.
pub(super) fn tls_setup() -> TlsSetup {
    let dir = tempfile::tempdir().unwrap();
    let env = ServerEnv {
        home: &Arc::new(HomeDir::new(dir.path())),
        tasks: &Tasks::default(),
        keep: &Keep::Named("in".into()),
        carried: &Carried::default(),
        clock: &Arc::new(ClockOffset::default()),
    };
    TlsSetup::new(&unnamed_tls(), Some(&SelfSigned::default()), &env).unwrap()
}

/// The TCP flows the endpoint opened, their destination and `IN-USER`, and the connection
/// key of each datagram it handed on. It keeps each reply, as the tunnel's NAT does for its
/// idle time.
#[derive(Default)]
pub(super) struct Flows {
    opened: Mutex<Vec<(Address, Option<Arc<str>>)>>,
    datagrams: Mutex<Vec<u64>>,
    replies: Mutex<Vec<Arc<dyn UdpReply>>>,
    changed: Notify,
}

impl Flows {
    pub(super) fn opened(&self) -> Vec<(Address, Option<Arc<str>>)> {
        lock(&self.opened).clone()
    }

    pub(super) async fn wait_for(&self, count: usize) -> Vec<(Address, Option<Arc<str>>)> {
        self.until(|| Some(self.opened()).filter(|opened| opened.len() >= count))
            .await
    }

    pub(super) async fn datagrams(&self, count: usize) -> Vec<u64> {
        self.until(|| Some(lock(&self.datagrams).clone()).filter(|seen| seen.len() >= count))
            .await
    }

    async fn until<T>(&self, done: impl Fn() -> Option<T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let changed = self.changed.notified();
                if let Some(done) = done() {
                    return done;
                }
                changed.await;
            }
        })
        .await
        .unwrap()
    }
}

impl FlowHandler for Flows {
    fn handle_tcp(&self, meta: FlowMeta, _stream: BoxStream) {
        lock(&self.opened).push((meta.dst, meta.inbound.user));
        self.changed.notify_waiters();
    }

    fn handle_udp(&self, flow: UdpFlow<'_>, _payload: UdpPayload<'_>, reply: &Arc<dyn UdpReply>) {
        lock(&self.replies).push(reply.clone());
        lock(&self.datagrams).push(flow.conn);
        self.changed.notify_waiters();
    }
}

/// An endpoint serving on loopback; dropping `current` stops it.
pub(super) struct Running {
    pub(super) addr: SocketAddr,
    pub(super) current: watch::Sender<Current>,
    pub(super) flows: Arc<Flows>,
    pub(super) cx: Arc<InboundCx>,
    serving: tokio::task::JoinHandle<()>,
}

impl Running {
    pub(super) fn start(service: Arc<dyn EndpointService>) -> Running {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let flows = Arc::new(Flows::default());
        let cx = Arc::new(InboundCx {
            name: "in".into(),
            special: None,
            handler: flows.clone(),
            tasks: Tasks::default(),
        });
        let (current, serving) = watch::channel(Current {
            service: service.clone(),
            cx: cx.clone(),
        });
        let run = service.run(socket, serving).unwrap();
        let serving = cx.tasks.spawn(run);
        Running {
            addr,
            current,
            flows,
            cx,
            serving,
        }
    }

    /// Stops the endpoint as a reload does and asserts its port can be bound at once.
    pub(super) async fn stop_and_rebind(self) {
        drop(self.current);
        tokio::time::timeout(Duration::from_secs(5), self.serving)
            .await
            .unwrap()
            .unwrap();
        std::net::UdpSocket::bind(self.addr).unwrap();
    }

    pub(super) async fn connect(&self, alpn: &[u8]) -> quinn::Connection {
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Unchecked))
        .with_no_client_auth();
        crypto.alpn_protocols = vec![alpn.to_vec()];
        let config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config);
        endpoint
            .connect(self.addr, "localhost")
            .unwrap()
            .await
            .unwrap()
    }
}

/// Closes `conn` and waits out the server's drain, three PTOs on loopback, so the server's
/// connection has left its endpoint while the handler still holds what it was given.
pub(super) async fn close_and_drain(conn: &quinn::Connection) {
    conn.close(quinn::VarInt::from_u32(0), b"");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

pub(super) async fn close_code(conn: &quinn::Connection) -> u64 {
    match tokio::time::timeout(Duration::from_secs(5), conn.closed())
        .await
        .unwrap()
    {
        quinn::ConnectionError::ApplicationClosed(close) => close.error_code.into_inner(),
        other => panic!("closed by {other}"),
    }
}

#[derive(Debug)]
struct Unchecked;

impl ServerCertVerifier for Unchecked {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
