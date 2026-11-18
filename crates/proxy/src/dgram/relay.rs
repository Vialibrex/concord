use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, ready};

use concord_common::{Address, DialCx, PacketBuf, PacketSession};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use super::{Encoder, Opener};
use crate::node::Egress;

pub(crate) struct Watch {
    pub(crate) closed: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl Watch {
    pub(crate) fn new(closed: Arc<AtomicBool>, task: JoinHandle<()>) -> Self {
        Watch { closed, task }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Carrier {
    Socket(UdpSocket),
    /// The UDP of a `dialer-proxy`, as mihomo's `ListenPacket` through a proxy dialer.
    Session(Arc<dyn PacketSession>),
}

/// Talks to one relay, whose packets carry the real destination.
pub(crate) struct UdpRelay<C> {
    carrier: Carrier,
    relay: SocketAddr,
    relay_addr: Address,
    codec: C,
    inflight: AtomicUsize,
    closed: Arc<AtomicBool>,
    _watch: Option<Watch>,
}

impl<C: Encoder + Opener> UdpRelay<C> {
    /// Fails when the `dialer-proxy` cannot carry UDP, rather than sending from this host.
    pub(crate) async fn open(
        egress: &Egress,
        cx: &DialCx<'_>,
        relay: SocketAddr,
        codec: C,
        watch: Option<Watch>,
    ) -> io::Result<Self> {
        let carrier = match egress.via() {
            Some(via) => {
                let inner = cx.enter(egress.name())?;
                let session = cx
                    .env
                    .nodes
                    .associate_via(via, &inner, &Address::Socket(relay))
                    .await?;
                Carrier::Session(session)
            }
            None => Carrier::Socket(
                cx.env
                    .sockets
                    .bind_udp(relay.ip(), &egress.sock_opts(cx.env))?,
            ),
        };
        Ok(Self::with_carrier(carrier, relay, codec, watch))
    }

    fn with_carrier(carrier: Carrier, relay: SocketAddr, codec: C, watch: Option<Watch>) -> Self {
        UdpRelay {
            carrier,
            relay,
            relay_addr: Address::Socket(relay),
            codec,
            inflight: AtomicUsize::new(0),
            closed: watch
                .as_ref()
                .map_or_else(|| Arc::new(AtomicBool::new(false)), |w| w.closed.clone()),
            _watch: watch,
        }
    }
}

impl<C: Encoder + Opener> PacketSession for UdpRelay<C> {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let queued = self.inflight.load(Ordering::Relaxed);
        if queued == 0 || queued != pkt.len() {
            self.codec.encode(pkt, dst)?;
        }
        let sent = match &self.carrier {
            Carrier::Socket(socket) => socket
                .poll_send_to(cx, pkt.as_slice(), self.relay)
                .map_ok(drop),
            Carrier::Session(session) => session.poll_send(cx, pkt, &self.relay_addr),
        };
        match sent {
            Poll::Ready(result) => {
                self.inflight.store(0, Ordering::Relaxed);
                Poll::Ready(result)
            }
            Poll::Pending => {
                self.inflight.store(pkt.len(), Ordering::Relaxed);
                Poll::Pending
            }
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            match &self.carrier {
                Carrier::Socket(socket) => {
                    let mut read = ReadBuf::new(buf.spare_mut());
                    ready!(socket.poll_recv_from(cx, &mut read))?;
                    let n = read.filled().len();
                    buf.advance(n);
                }
                Carrier::Session(session) => {
                    ready!(session.poll_recv(cx, buf))?;
                }
            }
            match self.codec.open(buf) {
                Ok(from) => return Poll::Ready(Ok(from)),
                Err(err) => {
                    tracing::debug!("dropped a malformed udp packet: {err}");
                    buf.clear();
                }
            }
        }
    }

    fn headroom(&self) -> usize {
        let carrier = match &self.carrier {
            Carrier::Socket(_) => 0,
            Carrier::Session(session) => session.headroom(),
        };
        self.codec.headroom() + carrier
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Carrier::Session(session) = &self.carrier {
            session.close();
        }
    }
}
