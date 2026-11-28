//! What a protocol server implements for the listener that accepts its connections and
//! receives its datagrams. The listener owns the sockets, the ports and the reloads; the
//! server owns the protocol and hands each flow it opens to [`InboundCx::handler`].

use std::any::Any;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::addr::Address;
use crate::flow::FlowHandler;
use crate::meta::{InboundInfo, InboundKind, Special};
use crate::packet::PacketBuf;
use crate::task::Tasks;

pub type ServeFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// How long a client has to finish its handshake once it has connected, so idle clients
/// on an `allow-lan` port cannot hold descriptors.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// A protocol server as a listener runs it: on its TCP port, its UDP port, or both.
#[derive(Clone)]
pub struct Protocol {
    pub kind: InboundKind,
    pub stream: Option<Arc<dyn StreamService>>,
    pub udp: Option<OnUdp>,
}

#[derive(Clone)]
pub enum OnUdp {
    /// Each datagram on its own, through the listener's socket.
    Datagram(Arc<dyn DatagramService>),
    /// The socket whole.
    Endpoint(Arc<dyn EndpointService>),
}

impl Protocol {
    pub fn datagram(&self) -> Option<&Arc<dyn DatagramService>> {
        match &self.udp {
            Some(OnUdp::Datagram(service)) => Some(service),
            _ => None,
        }
    }
}

/// The listener a connection or datagram arrived at.
pub struct InboundCx {
    pub name: Arc<str>,
    pub special: Option<Arc<Special>>,
    pub handler: Arc<dyn FlowHandler>,
    /// Work that outlives the handshake, such as a stream that carries UDP, runs here.
    pub tasks: Tasks,
}

impl InboundCx {
    /// `local` is the address the listener accepted on, which `IN-PORT` matches.
    pub fn inbound(
        &self,
        kind: InboundKind,
        local: SocketAddr,
        user: Option<Arc<str>>,
    ) -> InboundInfo {
        InboundInfo {
            kind,
            name: self.name.clone(),
            addr: Some(local),
            user,
            host: false,
            user_agent: None,
            special: self.special.clone(),
            tcp_carried: false,
        }
    }
}

/// Both ends of an accepted connection, IPv4-mapped addresses unmapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    pub src: SocketAddr,
    pub local: SocketAddr,
}

pub trait StreamService: Send + Sync + 'static {
    /// Runs the handshake of one accepted connection and hands its flow on. The listener
    /// bounds the returned future; what runs past the handshake goes onto `cx.tasks`.
    fn serve(self: Arc<Self>, stream: TcpStream, peer: Peer, cx: Arc<InboundCx>) -> ServeFuture;
}

/// A datagram protocol served on the listener's own UDP socket.
pub trait DatagramService: Send + Sync + 'static {
    /// Unframes one datagram from `client` in place, leaving the payload in `packet`.
    /// `None` drops it: it did not authenticate or did not parse.
    fn open(&self, packet: &mut PacketBuf, client: SocketAddr) -> Option<Opened>;
}

/// A protocol that takes the listener's UDP socket whole, as a QUIC server does: it reads
/// and writes the socket itself and keeps the connections on it.
pub trait EndpointService: Any + Send + Sync {
    /// Opens the endpoint on `socket` and returns what serves it. A reload that keeps the
    /// port leaves it running and sends the service built in this one's place through
    /// `current`, which is of the same type: connections opened from then on take it, open
    /// ones keep theirs. Once the sender of `current` is dropped the endpoint closes, and
    /// the future ends when it has let go of the port.
    fn run(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        current: watch::Receiver<Current>,
    ) -> std::io::Result<ServeFuture>;

    /// What the socket itself carries, such as an obfuscation key, which a running endpoint
    /// cannot change: a reload that changes it binds the port anew.
    fn socket_key(&self) -> u64 {
        0
    }
}

/// What a running endpoint serves now.
#[derive(Clone)]
pub struct Current {
    pub service: Arc<dyn EndpointService>,
    pub cx: Arc<InboundCx>,
}

pub struct Opened {
    pub dst: Address,
    pub user: Option<Arc<str>>,
    pub seal: Arc<dyn DatagramSeal>,
    /// [`UdpFlow::conn`](crate::UdpFlow::conn) of the session the datagram belongs to.
    pub conn: u64,
}

/// Frames the replies of one client session.
pub trait DatagramSeal: Send + Sync + 'static {
    /// The datagram that carries `payload`, the reply from `from`, back to the client.
    fn seal(&self, payload: &[u8], from: &Address) -> io::Result<PacketBuf>;
}
