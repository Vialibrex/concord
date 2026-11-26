//! Receive timestamps over real loopback endpoints: a received batch is stamped when it is read.
#![allow(
    clippy::disallowed_methods,
    reason = "the client endpoint wraps a loopback socket it binds directly"
)]

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use concord_test_support::localhost_tls;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{
    AsyncTimer, AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, Runtime, ServerConfig,
    TokioRuntime, UdpPoller,
};

/// Reading a batch takes this long on the client's clock.
const READ: Duration = Duration::from_millis(200);

/// The client's clock: real time plus whatever the socket's reads have added. Timers are set back by the
/// same amount, so only timestamps see the shift.
#[derive(Debug, Default)]
struct Clock(AtomicU64);

impl Clock {
    fn shift(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::Relaxed))
    }

    fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_nanos() as u64, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct ClockRuntime(Arc<Clock>);

impl Runtime for ClockRuntime {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn AsyncTimer>> {
        let sleep = Box::pin(tokio::time::sleep_until((at - self.0.shift()).into()));
        Box::pin(ShiftedTimer(sleep, self.0.clone()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> Instant {
        Instant::now() + self.0.shift()
    }
}

#[derive(Debug)]
struct ShiftedTimer(Pin<Box<tokio::time::Sleep>>, Arc<Clock>);

impl AsyncTimer for ShiftedTimer {
    fn reset(mut self: Pin<&mut Self>, at: Instant) {
        let real = at - self.1.shift();
        self.0.as_mut().reset(real.into());
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Future::poll(self.0.as_mut(), cx)
    }
}

/// Advances the client's clock by `READ` for every batch it returns.
struct SlowRead(Arc<dyn AsyncUdpSocket>, Arc<Clock>);

impl fmt::Debug for SlowRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SlowRead")
    }
}

impl AsyncUdpSocket for SlowRead {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.0.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.0.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let polled = self.0.poll_recv(cx, bufs, meta);
        if matches!(polled, Poll::Ready(Ok(_))) {
            self.1.advance(READ);
        }
        polled
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.0.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.0.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.0.may_fragment()
    }
}

fn configs() -> (ServerConfig, ClientConfig) {
    let (mut server_tls, mut client_tls) = localhost_tls(rustls::DEFAULT_VERSIONS);
    server_tls.alpn_protocols = vec![b"recv-time".to_vec()];
    client_tls.alpn_protocols = vec![b"recv-time".to_vec()];
    let server =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));
    let client = ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
    (server, client)
}

#[tokio::test]
async fn a_batch_is_stamped_when_it_is_read() {
    let (server_config, client_config) = configs();
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let server = Endpoint::server(server_config, loopback).unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        while let Ok(datagram) = conn.read_datagram().await {
            let _ = conn.send_datagram(datagram);
        }
    });

    let clock = Arc::new(Clock::default());
    let socket = TokioRuntime
        .wrap_udp_socket(UdpSocket::bind(loopback).unwrap())
        .unwrap();
    let mut client = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        Arc::new(SlowRead(socket, clock.clone())),
        Arc::new(ClockRuntime(clock)),
    )
    .unwrap();
    client.set_default_client_config(client_config);
    let conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    for _ in 0..4 {
        conn.send_datagram(bytes::Bytes::from_static(b"ping"))
            .unwrap();
        conn.read_datagram().await.unwrap();
    }

    let stats = conn.stats();
    assert!(stats.frame_rx.acks > 0, "no ACK sampled: {stats:?}");
    assert!(
        stats.path.min_rtt >= READ,
        "an ACK was stamped before it was read: min_rtt {:?}",
        stats.path.min_rtt
    );
}
