use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use concord_common::sync::lock;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, UdpPoller, VarInt};
use tokio::sync::oneshot;

/// A server endpoint's socket, as the endpoint sends through it, and what resolves once the
/// port's own socket is dropped.
pub struct Released {
    socket: Arc<dyn AsyncUdpSocket>,
    gone: oneshot::Receiver<()>,
}

/// `inner`, which tells the receiver beside it once nothing holds it, its pollers included.
pub(crate) fn hold(
    inner: Arc<dyn AsyncUdpSocket>,
) -> (Arc<dyn AsyncUdpSocket>, oneshot::Receiver<()>) {
    let (gone, dropped) = oneshot::channel();
    (Arc::new(Held { inner, _gone: gone }), dropped)
}

impl Released {
    pub(crate) fn new(socket: Arc<dyn AsyncUdpSocket>, gone: oneshot::Receiver<()>) -> Self {
        Released { socket, gone }
    }
}

/// Closes `endpoint` and lets go of its port, within `wait`. The endpoint and its
/// connections move at once onto a socket that only sends, through the endpoint's own, so
/// the close reaches the peers; quinn keeps the socket it replaced until traffic arrives
/// on the new one, so the move is made twice. Once the connections have drained (RFC 9000
/// section 10.2) that socket stops sending, which lets go of the port even where a
/// connection's handle outlives its driver, and this returns when the port's socket is
/// dropped, so the port can be bound again.
pub async fn release_endpoint(endpoint: Endpoint, released: Released, wait: Duration) {
    let deadline = tokio::time::Instant::now() + wait;
    let Released { socket, gone } = released;
    let via = Arc::new(Mutex::new(Some(socket)));
    endpoint.close(VarInt::from_u32(0), b"");
    if let Ok(addr) = endpoint.local_addr() {
        for _ in 0..2 {
            let _ = endpoint.rebind_abstract(Arc::new(Draining {
                addr,
                via: via.clone(),
            }));
        }
    }
    let _ = tokio::time::timeout_at(deadline, endpoint.wait_idle()).await;
    drop(endpoint);
    lock(&via).take();
    let _ = tokio::time::timeout_at(deadline, gone).await;
}

#[derive(Debug)]
struct Held {
    inner: Arc<dyn AsyncUdpSocket>,
    _gone: oneshot::Sender<()>,
}

impl AsyncUdpSocket for Held {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(HeldPoller {
            inner: self.inner.clone().create_io_poller(),
            _socket: self,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Debug)]
struct HeldPoller {
    inner: Pin<Box<dyn UdpPoller>>,
    _socket: Arc<Held>,
}

impl UdpPoller for HeldPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().inner.as_mut().poll_writable(cx)
    }
}

/// Sends through the endpoint's socket until the release takes it away, then drops what it
/// sends; receives nothing.
#[derive(Debug)]
struct Draining {
    addr: SocketAddr,
    via: Arc<Mutex<Option<Arc<dyn AsyncUdpSocket>>>>,
}

impl AsyncUdpSocket for Draining {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let via = lock(&self.via).clone();
        match via.map(|socket| socket.try_send(transmit)) {
            Some(Err(err)) if err.kind() != io::ErrorKind::WouldBlock => Err(err),
            _ => Ok(()),
        }
    }

    fn poll_recv(
        &self,
        _cx: &mut Context<'_>,
        _bufs: &mut [io::IoSliceMut<'_>],
        _meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

#[derive(Debug)]
struct Writable;

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "the test binds the loopback port it releases"
)]
mod tests {
    use super::*;

    struct Served {
        addr: std::net::SocketAddr,
        endpoint: Endpoint,
        released: Released,
        client: quinn::Connection,
        server: quinn::Connection,
    }

    async fn served() -> Served {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let (server, client) = tls();
        let tasks = concord_common::Tasks::default();
        let (endpoint, released) =
            crate::server_endpoint(socket, server, &crate::ObfsSpec::None, &tasks).unwrap();
        let accepting = endpoint.clone();
        let accepted = tokio::spawn(async move { accepting.accept().await.unwrap().await });
        let mut peer = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        peer.set_default_client_config(client);
        let client = peer.connect(addr, "localhost").unwrap().await.unwrap();
        let server = accepted.await.unwrap().unwrap();
        assert!(std::net::UdpSocket::bind(addr).is_err());
        Served {
            addr,
            endpoint,
            released,
            client,
            server,
        }
    }

    async fn releases_at_once(endpoint: Endpoint, released: Released, addr: std::net::SocketAddr) {
        let wait = Duration::from_secs(5);
        let start = tokio::time::Instant::now();
        release_endpoint(endpoint, released, wait).await;
        assert!(start.elapsed() < wait, "the socket outlived the release");
        std::net::UdpSocket::bind(addr).unwrap();
    }

    #[tokio::test]
    async fn a_released_endpoint_tells_its_peers_and_frees_its_port() {
        let served = served().await;
        let _held = served.server;
        releases_at_once(served.endpoint, served.released, served.addr).await;
        assert!(matches!(
            served.client.close_reason(),
            Some(quinn::ConnectionError::ApplicationClosed(_))
        ));
    }

    #[tokio::test]
    async fn a_drained_connection_kept_by_a_handle_frees_the_port() {
        let served = served().await;
        served.client.close(VarInt::from_u32(0), b"");
        served.server.closed().await;
        served.endpoint.wait_idle().await;
        let _held = served.server;
        releases_at_once(served.endpoint, served.released, served.addr).await;
    }

    fn tls() -> (quinn::ServerConfig, quinn::ClientConfig) {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(made.signing_key.serialize_der().into());
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![made.cert.der().clone()], key)
            .unwrap();
        server.alpn_protocols = vec![b"test".to_vec()];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(made.cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"test".to_vec()];
        (
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server).unwrap(),
            )),
            quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(client).unwrap(),
            )),
        )
    }
}
