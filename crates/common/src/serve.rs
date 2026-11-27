//! What a protocol server implements for the listener that accepts its connections and
//! receives its datagrams. The listener owns the sockets, the ports and the reloads; the
//! server owns the protocol and hands each flow it opens to [`InboundCx::handler`].

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

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
    pub datagram: Option<Arc<dyn DatagramService>>,
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
