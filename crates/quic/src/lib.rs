#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod bbr;
mod congestion;
mod datagram;
mod obfs;
mod session_socket;
mod shared;
mod socket;
mod tasks;
mod transport;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use concord_common::{BoxRead, BoxWrite, Stream, Tasks};
use quinn::congestion::{CubicConfig, NewRenoConfig};
use quinn::{AsyncUdpSocket, Endpoint, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use self::bbr::{BbrProfile, factory as bbr_factory};
pub use self::congestion::{Brutal, Switch, SwitchFactory};
pub use self::datagram::CappedFrame;
pub use self::obfs::GeckoRange;
use self::obfs::{Gecko, Salamander, WeChat, XPlus};
pub use self::session_socket::SessionSocket;
pub use self::shared::{DatagramHub, SharedConn};
pub use self::socket::Hop;
use self::socket::{Obfs, WrappedSocket};
pub use self::tasks::{TrackedRuntime, close_on_stop};
pub use self::transport::{
    CONN_WINDOW, DEFAULT_CWND, MAX_IDLE, STREAM_WINDOW, Transport, bbr_window, or_default,
};

/// quic-go's starting point, which mihomo's QUIC clients share: a 100 ms initial RTT
/// (`DefaultInitialRTT`) and Cubic with a 32-packet initial window
/// (`initialCongestionWindow` of 1280-byte packets).
pub fn transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config
        .initial_rtt(Duration::from_millis(100))
        .congestion_controller_factory(Arc::new(cubic()));
    config
}

/// quic-go's `InitialPacketSize`, the datagram size its congestion controllers count in.
pub const INITIAL_PACKET_SIZE: u64 = 1280;
const INITIAL_WINDOW: u64 = 32 * INITIAL_PACKET_SIZE;
/// quic-go's `maxDatagramRcvQueueLen`: datagrams a connection holds for the reader.
const DATAGRAM_QUEUE: usize = 128;

/// quinn counts its datagram receive buffer in bytes, so quic-go's queue of datagrams
/// becomes that many frames of the size the connection advertises.
pub fn datagram_buffer(frame: u64) -> usize {
    DATAGRAM_QUEUE.saturating_mul(usize::try_from(frame).unwrap_or(usize::MAX))
}

pub fn cubic() -> CubicConfig {
    let mut config = CubicConfig::default();
    config.initial_window(INITIAL_WINDOW);
    config
}

pub fn new_reno() -> NewRenoConfig {
    let mut config = NewRenoConfig::default();
    config.initial_window(INITIAL_WINDOW);
    config
}

pub fn io_error(err: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(err)
}

/// A QUIC connection and the endpoint that carries it.
pub struct QuicConn {
    pub conn: quinn::Connection,
    endpoint: Endpoint,
    pub tasks: Tasks,
}

impl QuicConn {
    pub fn new(conn: quinn::Connection, endpoint: Endpoint, tasks: Tasks) -> Self {
        QuicConn {
            conn,
            endpoint,
            tasks,
        }
    }
}

impl Drop for QuicConn {
    fn drop(&mut self) {
        self.conn.close(quinn::VarInt::from_u32(0), b"");
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

/// What a link keeps of its obfuscation; each connection builds its own state.
#[derive(Clone)]
pub enum ObfsSpec {
    None,
    Salamander(Vec<u8>),
    XPlus(Vec<u8>),
    WeChat(Option<Vec<u8>>),
    Gecko {
        password: Vec<u8>,
        min: usize,
        max: usize,
    },
}

impl ObfsSpec {
    fn build(&self) -> Obfs {
        match self {
            ObfsSpec::None => Obfs::None,
            ObfsSpec::Salamander(password) => Obfs::Seal(Box::new(Salamander::new(password))),
            ObfsSpec::XPlus(key) => Obfs::Seal(Box::new(XPlus::new(key))),
            ObfsSpec::WeChat(key) => Obfs::Seal(Box::new(WeChat::new(key.as_deref()))),
            ObfsSpec::Gecko { password, min, max } => match Gecko::new(password, *min, *max) {
                Ok(gecko) => Obfs::Gecko(Mutex::new(gecko)),
                Err(_) => Obfs::None,
            },
        }
    }

    pub fn check(&self) -> Result<(), GeckoRange> {
        match self {
            ObfsSpec::Gecko { password, min, max } => Gecko::new(password, *min, *max).map(drop),
            _ => Ok(()),
        }
    }
}

pub fn wrap_socket(
    raw: Arc<dyn AsyncUdpSocket>,
    obfs: &ObfsSpec,
    hop: Option<(u16, Hop)>,
    tasks: &Tasks,
) -> Arc<dyn AsyncUdpSocket> {
    match (obfs, hop) {
        #[cfg(windows)]
        (ObfsSpec::None, None) => Arc::new(socket::SingleReceive(raw)),
        #[cfg(not(windows))]
        (ObfsSpec::None, None) => raw,
        (obfs, hop) => WrappedSocket::new(raw, obfs.build(), hop, tasks),
    }
}

/// A bidirectional QUIC stream as a byte stream.
pub struct QuicStream {
    send: SendStream,
    recv: RecvStream,
    _hold: Box<dyn Send + Sync>,
}

impl QuicStream {
    /// `hold` lives as long as the stream: the connection or the slot it counts against.
    pub fn new(send: SendStream, recv: RecvStream, hold: Box<dyn Send + Sync>) -> Self {
        QuicStream {
            send,
            recv,
            _hold: hold,
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, data)
            .map_err(io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

impl Stream for QuicStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let QuicStream { send, recv, _hold } = *self;
        let hold: Arc<dyn Send + Sync> = Arc::from(_hold);
        (
            Box::new(QuicRead {
                recv,
                _hold: hold.clone(),
            }),
            Box::new(QuicWrite { send, _hold: hold }),
        )
    }
}

struct QuicRead {
    recv: RecvStream,
    _hold: Arc<dyn Send + Sync>,
}

impl AsyncRead for QuicRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

struct QuicWrite {
    send: SendStream,
    _hold: Arc<dyn Send + Sync>,
}

impl AsyncWrite for QuicWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().send)
            .poll_write(cx, data)
            .map_err(io::Error::from)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "loopback sockets exercise Quinn's receive-storage contract"
)]
mod receive_scratch_tests;
