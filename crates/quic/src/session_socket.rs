use std::fmt;
use std::future::poll_fn;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker, ready};

use concord_common::sync::lock;
use concord_common::{Address, PacketBuf, PacketSession, Tasks, recv_packet};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const SESSION_QUEUE: usize = 256;

/// A quinn socket over a `PacketSession`, which is how a `dialer-proxy` carries
/// QUIC. A datagram goes to the session from quinn's own send, as quic-go writes its
/// `PacketConn`; received ones wait in a queue that drops when full, as quic-go's does.
pub struct SessionSocket {
    local: SocketAddr,
    target: Address,
    send: Arc<SendSlot>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    session: Arc<dyn PacketSession>,
    pumps: [JoinHandle<()>; 2],
}

/// The one datagram the session left pending, which the send task finishes; until it
/// has, the socket is not writable.
#[derive(Default)]
struct SendSlot(Mutex<Slot>);

#[derive(Default)]
struct Slot {
    packet: Option<PacketBuf>,
    failed: bool,
    task: Option<Waker>,
    writable: Vec<Waker>,
}

impl fmt::Debug for SessionSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSocket")
            .field("remote", &self.target)
            .finish_non_exhaustive()
    }
}

impl Drop for SessionSocket {
    fn drop(&mut self) {
        for pump in &self.pumps {
            pump.abort();
        }
        self.session.close();
    }
}

impl SessionSocket {
    pub fn new(session: Arc<dyn PacketSession>, remote: SocketAddr, tasks: &Tasks) -> Arc<Self> {
        let (deliver, incoming) = mpsc::channel::<(Vec<u8>, SocketAddr)>(SESSION_QUEUE);
        let target = Address::Socket(remote);
        let send = Arc::new(SendSlot::default());
        let send_pump = tasks.spawn(finish_sends(session.clone(), target.clone(), send.clone()));
        let receiver = session.clone();
        let recv_pump = tasks.spawn(async move {
            while let Ok((pkt, from)) = recv_packet(&*receiver).await {
                let from = match from {
                    Address::Socket(addr) => addr,
                    Address::Domain(..) => remote,
                };
                let _ = deliver.try_send((pkt.as_slice().to_vec(), from));
            }
        });
        let local = match remote.ip() {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        Arc::new(SessionSocket {
            local,
            target,
            send,
            incoming: Mutex::new(incoming),
            session,
            pumps: [send_pump, recv_pump],
        })
    }
}

async fn finish_sends(session: Arc<dyn PacketSession>, target: Address, send: Arc<SendSlot>) {
    poll_fn(|cx| {
        loop {
            let mut slot = lock(&send.0);
            let Some(packet) = slot.packet.as_mut() else {
                slot.task = Some(cx.waker().clone());
                return Poll::Pending;
            };
            let sent = ready!(session.poll_send(cx, packet, &target));
            slot.packet = None;
            slot.failed = sent.is_err();
            for waker in slot.writable.drain(..) {
                waker.wake();
            }
            if slot.failed {
                return Poll::Ready(());
            }
        }
    })
    .await;
}

struct SessionPoller {
    send: Arc<SendSlot>,
}

impl fmt::Debug for SessionPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for SessionPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut slot = lock(&self.send.0);
        if slot.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if slot.packet.is_none() {
            return Poll::Ready(Ok(()));
        }
        if !slot.writable.iter().any(|w| w.will_wake(cx.waker())) {
            slot.writable.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl AsyncUdpSocket for SessionSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SessionPoller {
            send: self.send.clone(),
        })
    }

    /// A datagram the session cannot take yet is still accepted, into the slot the send
    /// task finishes with its own waker: the no-op waker here may be the last one the
    /// session saw, and quinn polls writability only when it has another to send.
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut slot = lock(&self.send.0);
        if slot.failed {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if slot.packet.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut packet = PacketBuf::with_headroom(self.session.headroom());
        packet.extend_from_slice(transmit.contents);
        let mut cx = Context::from_waker(Waker::noop());
        match self.session.poll_send(&mut cx, &mut packet, &self.target) {
            Poll::Ready(sent) => sent,
            Poll::Pending => {
                slot.packet = Some(packet);
                if let Some(task) = slot.task.take() {
                    task.wake();
                }
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let next = ready!(lock(&self.incoming).poll_recv(cx));
        let Some((data, from)) = next else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let (Some(buf), Some(slot)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let len = data.len().min(buf.len());
        if let (Some(target), Some(source)) = (buf.get_mut(..len), data.get(..len)) {
            target.copy_from_slice(source);
        }
        *slot = RecvMeta {
            addr: from,
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// Takes datagrams until held, then leaves sends pending until released.
    #[derive(Default)]
    struct Gate {
        sent: Vec<Vec<u8>>,
        hold_after: Option<usize>,
        held: bool,
        fail: bool,
        waker: Option<Waker>,
    }

    #[derive(Default)]
    struct GateSession(Mutex<Gate>);

    impl GateSession {
        fn release(&self) {
            let waker = {
                let mut gate = lock(&self.0);
                gate.held = false;
                gate.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            lock(&self.0).sent.clone()
        }

        fn count(&self) -> usize {
            lock(&self.0).sent.len()
        }
    }

    impl PacketSession for GateSession {
        fn poll_send(
            &self,
            cx: &mut Context<'_>,
            pkt: &mut PacketBuf,
            _dst: &Address,
        ) -> Poll<io::Result<()>> {
            let mut gate = lock(&self.0);
            if gate.held {
                gate.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if gate.fail {
                return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
            }
            gate.sent.push(pkt.as_slice().to_vec());
            if let Some(every) = gate.hold_after
                && gate.sent.len().is_multiple_of(every)
            {
                gate.held = true;
            }
            Poll::Ready(Ok(()))
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            _buf: &mut PacketBuf,
        ) -> Poll<io::Result<Address>> {
            Poll::Pending
        }
    }

    fn remote() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], 443))
    }

    fn transmit(contents: &[u8]) -> Transmit<'_> {
        Transmit {
            destination: remote(),
            ecn: None,
            contents,
            segment_size: None,
            src_ip: None,
        }
    }

    async fn send(socket: &Arc<SessionSocket>, poller: &mut Pin<Box<dyn UdpPoller>>, data: &[u8]) {
        loop {
            poll_fn(|cx| poller.as_mut().poll_writable(cx))
                .await
                .unwrap();
            match socket.try_send(&transmit(data)) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                result => return result.unwrap(),
            }
        }
    }

    #[tokio::test]
    async fn a_session_that_takes_datagrams_gets_them_in_order_from_the_send_itself() {
        let session = Arc::new(GateSession::default());
        let socket = SessionSocket::new(session.clone(), remote(), &Default::default());
        for data in [&b"one"[..], b"two", b"three"] {
            socket.try_send(&transmit(data)).unwrap();
        }
        assert_eq!(
            session.sent(),
            [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_pending_datagram_is_finished_by_the_send_task_and_wakes_the_writer() {
        let session = Arc::new(GateSession::default());
        lock(&session.0).hold_after = Some(1);
        let socket = SessionSocket::new(session.clone(), remote(), &Default::default());
        let mut poller = socket.clone().create_io_poller();
        socket.try_send(&transmit(b"first")).unwrap();
        socket.try_send(&transmit(b"second")).unwrap();
        let blocked = socket.try_send(&transmit(b"third")).unwrap_err();
        assert_eq!(blocked.kind(), io::ErrorKind::WouldBlock);
        let mut writable = std::pin::pin!(poll_fn(|cx| poller.as_mut().poll_writable(cx)));
        assert!(futures_util::poll!(writable.as_mut()).is_pending());
        lock(&session.0).hold_after = None;
        session.release();
        tokio::time::timeout(Duration::from_secs(5), writable)
            .await
            .expect("the writer was never woken once the session took the datagram")
            .unwrap();
        socket.try_send(&transmit(b"third")).unwrap();
        assert_eq!(
            session.sent(),
            [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_that_keeps_stalling_still_gets_every_datagram_in_order() {
        const COUNT: u32 = 1000;
        let session = Arc::new(GateSession::default());
        lock(&session.0).hold_after = Some(7);
        let socket = SessionSocket::new(session.clone(), remote(), &Default::default());
        let releaser = {
            let session = session.clone();
            tokio::spawn(async move {
                while session.count() < COUNT as usize {
                    session.release();
                    tokio::task::yield_now().await;
                }
            })
        };
        let mut poller = socket.clone().create_io_poller();
        tokio::time::timeout(Duration::from_secs(10), async {
            for n in 0..COUNT {
                send(&socket, &mut poller, &n.to_be_bytes()).await;
            }
        })
        .await
        .expect("a stalled datagram was never finished");
        tokio::time::timeout(Duration::from_secs(5), releaser)
            .await
            .expect("the last datagram never left")
            .unwrap();
        let sent: Vec<u32> = session
            .sent()
            .iter()
            .map(|d| u32::from_be_bytes(d[..].try_into().unwrap()))
            .collect();
        assert_eq!(sent, (0..COUNT).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn a_session_error_reaches_the_send_and_the_writer() {
        let session = Arc::new(GateSession::default());
        lock(&session.0).fail = true;
        let socket = SessionSocket::new(session.clone(), remote(), &Default::default());
        assert!(socket.try_send(&transmit(b"x")).is_err());

        let session = Arc::new(GateSession::default());
        lock(&session.0).hold_after = Some(1);
        let socket = SessionSocket::new(session.clone(), remote(), &Default::default());
        let mut poller = socket.clone().create_io_poller();
        socket.try_send(&transmit(b"first")).unwrap();
        socket.try_send(&transmit(b"held")).unwrap();
        lock(&session.0).fail = true;
        session.release();
        let failed = tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| poller.as_mut().poll_writable(cx)),
        )
        .await
        .expect("the writer was never told the session failed");
        assert!(failed.is_err());
        assert!(socket.try_send(&transmit(b"next")).is_err());
    }
}
