//! The node's own connections through its `dialer-proxy`. Bytes and packets wait in fixed
//! buffers made on the runtime, so the Go threads that read and write them only copy and wait,
//! as `Inbox` does for the tailnet's packets: glibc gives each thread that allocates an arena of
//! its own.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, DialCx, DialEnv, Initiator, PacketBuf, PacketSession, Tasks, recv_packet,
    send_packet,
};
use concord_tsnet::{Conns, Io};

use super::wait_on;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// One buffer: a WireGuard packet, a DNS answer within EDNS's usual 4096 bytes, or a read
/// from a stream. A larger packet is dropped, as a smaller socket buffer would.
const SLOT: usize = 4096;
/// Buffers each way for WireGuard's UDP.
const PACKET_SLOTS: usize = concord_tsnet::BATCH;
/// Buffers each way for a stream (control, DERP), which waits on its reader: Go reads a stream
/// one call at a time, so a second buffer would only queue ahead of it.
const STREAM_SLOTS: usize = 1;
/// mihomo's TCP dial timeout, for a dial whose context sets none.
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct Via {
    node: Arc<str>,
    /// `None` when the node has no dialer-proxy, and the library opens its own sockets.
    proxy: Option<Arc<str>>,
    env: Arc<DialEnv>,
    tasks: Tasks,
    pipes: Mutex<HashMap<i64, Arc<Pipe>>>,
    next: AtomicI64,
    stop: CancellationToken,
}

enum Carrier {
    Stream(BoxStream),
    Packets(Arc<dyn PacketSession>),
}

impl Via {
    pub(super) fn new(
        node: Arc<str>,
        proxy: Option<Arc<str>>,
        env: Arc<DialEnv>,
        tasks: Tasks,
    ) -> Via {
        Via {
            node,
            proxy,
            env,
            stop: tasks.child_token(),
            tasks,
            pipes: Mutex::new(HashMap::new()),
            next: AtomicI64::new(1),
        }
    }

    fn pipe(&self, conn: i64) -> Option<Arc<Pipe>> {
        lock(&self.pipes).get(&conn).cloned()
    }
}

impl Conns for Via {
    fn open(&self, datagram: bool, addr: &str, timeout: Option<Duration>) -> Option<i64> {
        let dial = Dial {
            node: self.node.clone(),
            proxy: self.proxy.clone()?,
            env: self.env.clone(),
            dst: Address::parse(addr)?,
            datagram,
        };
        let opened = dial.open(self.stop.clone(), timeout.unwrap_or(OPEN_TIMEOUT));
        let (pipe, carrier) = match wait_on(&self.tasks, opened) {
            Some(Ok(opened)) => opened,
            Some(Err(err)) => {
                tracing::warn!(
                    "[Tailscale]({}) dialing {addr} through a dialer-proxy failed: {err}",
                    self.node
                );
                return None;
            }
            _ => return None,
        };
        let conn = self.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.pipes).insert(conn, pipe.clone());
        let stop = self.stop.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                () = stop.cancelled() => pipe.close(),
                () = pump(&pipe, carrier) => {}
            }
        });
        Some(conn)
    }

    fn read(&self, conn: i64, buf: &mut [u8], from: &mut [u8]) -> (Io, usize) {
        match self.pipe(conn) {
            Some(pipe) => pipe.read(buf, from),
            None => (Io::Failed, 0),
        }
    }

    fn write(&self, conn: i64, data: &[u8], to: &str) -> Io {
        match self.pipe(conn) {
            Some(pipe) => pipe.write(data, to),
            None => Io::Failed,
        }
    }

    fn deadline(&self, conn: i64, read: bool, write: bool, after: Option<Duration>) {
        if let Some(pipe) = self.pipe(conn) {
            pipe.deadline(read, write, after.map(|after| Instant::now() + after));
        }
    }

    fn close(&self, conn: i64) {
        if let Some(pipe) = lock(&self.pipes).remove(&conn) {
            pipe.close();
        }
    }

    fn close_all(&self) {
        self.stop.cancel();
        for (_, pipe) in lock(&self.pipes).drain() {
            pipe.close();
        }
    }
}

/// A connection the node asked for, opened on the runtime.
struct Dial {
    node: Arc<str>,
    proxy: Arc<str>,
    env: Arc<DialEnv>,
    dst: Address,
    datagram: bool,
}

impl Dial {
    async fn open(
        self,
        stop: CancellationToken,
        timeout: Duration,
    ) -> io::Result<(Arc<Pipe>, Carrier)> {
        match stop
            .run_until_cancelled_owned(tokio::time::timeout(timeout, self.connect()))
            .await
        {
            Some(Ok(opened)) => opened,
            Some(Err(elapsed)) => Err(elapsed.into()),
            None => Err(io::ErrorKind::ConnectionAborted.into()),
        }
    }

    async fn connect(self) -> io::Result<(Arc<Pipe>, Carrier)> {
        let cx = DialCx::new(&self.env, Initiator::Proxy, None);
        let inner = cx.enter(&self.node)?;
        let carrier = if self.datagram {
            Carrier::Packets(
                self.env
                    .nodes
                    .associate_via(&self.proxy, &inner, &self.dst)
                    .await?,
            )
        } else {
            Carrier::Stream(
                self.env
                    .nodes
                    .dial_via(&self.proxy, &inner, &self.dst)
                    .await?,
            )
        };
        Ok((Arc::new(Pipe::new(self.datagram)), carrier))
    }
}

struct Slot {
    bytes: Box<[u8]>,
    start: usize,
    end: usize,
    peer: Option<SocketAddr>,
}

/// One direction: filled buffers in order and the empty ones, never more than were made.
struct Lane {
    filled: VecDeque<Slot>,
    empty: Vec<Box<[u8]>>,
    deadline: Option<Instant>,
}

impl Lane {
    fn new(slots: usize) -> Lane {
        Lane {
            filled: VecDeque::with_capacity(slots),
            empty: (0..slots)
                .map(|_| vec![0; SLOT].into_boxed_slice())
                .collect(),
            deadline: None,
        }
    }

    fn fill(&mut self, bytes: Box<[u8]>, len: usize, peer: Option<SocketAddr>) {
        self.filled.push_back(Slot {
            bytes,
            start: 0,
            end: len,
            peer,
        });
    }

    fn put_bytes(&mut self, data: &[u8]) -> usize {
        let mut taken = 0;
        while taken < data.len() {
            let Some(mut bytes) = self.empty.pop() else {
                break;
            };
            let n = copy(&mut bytes, data.get(taken..).unwrap_or_default());
            self.fill(bytes, n, None);
            taken += n;
        }
        taken
    }

    /// A packet larger than a buffer is dropped.
    fn put_packet(&mut self, data: &[u8], peer: SocketAddr) {
        if data.len() > SLOT {
            return;
        }
        if let Some(mut bytes) = self.empty.pop() {
            let n = copy(&mut bytes, data);
            self.fill(bytes, n, Some(peer));
        }
    }

    fn take_bytes(&mut self, buf: &mut [u8]) -> usize {
        let mut copied = 0;
        while let Some(slot) = self.filled.front_mut() {
            let n = copy(
                buf.get_mut(copied..).unwrap_or_default(),
                slot.bytes.get(slot.start..slot.end).unwrap_or_default(),
            );
            copied += n;
            slot.start += n;
            if slot.start < slot.end {
                break;
            }
            self.recycle_front();
        }
        copied
    }

    /// The front packet, cut to `buf`, and the length of its sender written to `from`.
    fn take_packet(&mut self, buf: &mut [u8], from: &mut [u8]) -> (usize, usize) {
        let Some(slot) = self.filled.front() else {
            return (0, 0);
        };
        let n = copy(buf, slot.bytes.get(..slot.end).unwrap_or_default());
        let from_len = write_peer(from, slot.peer);
        self.recycle_front();
        (n, from_len)
    }

    fn recycle_front(&mut self) {
        if let Some(slot) = self.filled.pop_front() {
            self.empty.push(slot.bytes);
        }
    }
}

fn copy(into: &mut [u8], from: &[u8]) -> usize {
    let n = into.len().min(from.len());
    if let (Some(into), Some(from)) = (into.get_mut(..n), from.get(..n)) {
        into.copy_from_slice(from);
    }
    n
}

struct State {
    datagram: bool,
    inbound: Lane,
    outbound: Lane,
    /// The stream ended after what `inbound` holds.
    eof: bool,
    /// Closed by the node, or failed on the network side.
    done: bool,
}

enum Wait {
    Ready,
    TimedOut,
    Done,
}

struct Pipe {
    state: Mutex<State>,
    /// Go threads waiting to read or to write.
    readable: Condvar,
    writable: Condvar,
    /// The pump waiting for packets to send or for an empty buffer to receive into.
    to_send: Notify,
    to_receive: Notify,
    gone: CancellationToken,
}

impl Pipe {
    fn new(datagram: bool) -> Pipe {
        let slots = if datagram { PACKET_SLOTS } else { STREAM_SLOTS };
        Pipe {
            state: Mutex::new(State {
                datagram,
                inbound: Lane::new(slots),
                outbound: Lane::new(slots),
                eof: false,
                done: false,
            }),
            readable: Condvar::new(),
            writable: Condvar::new(),
            to_send: Notify::new(),
            to_receive: Notify::new(),
            gone: CancellationToken::new(),
        }
    }

    /// Waits on `cond` until `ready` or the lane's deadline, on a Go thread.
    fn wait<'a>(
        &self,
        cond: &Condvar,
        mut state: MutexGuard<'a, State>,
        lane: fn(&State) -> &Lane,
        ready: fn(&State) -> bool,
    ) -> (MutexGuard<'a, State>, Wait) {
        loop {
            if ready(&state) {
                return (state, Wait::Ready);
            }
            if state.done {
                return (state, Wait::Done);
            }
            state = match lane(&state).deadline {
                None => cond.wait(state).unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                    Some(left) if !left.is_zero() => {
                        cond.wait_timeout(state, left)
                            .unwrap_or_else(PoisonError::into_inner)
                            .0
                    }
                    _ => return (state, Wait::TimedOut),
                },
            };
        }
    }

    fn read(&self, buf: &mut [u8], from: &mut [u8]) -> (Io, usize) {
        let ready = |s: &State| !s.inbound.filled.is_empty() || s.eof;
        let (mut state, wait) = self.wait(&self.readable, lock(&self.state), |s| &s.inbound, ready);
        let read = match wait {
            Wait::TimedOut => return (Io::TimedOut, 0),
            Wait::Done => return (Io::Failed, 0),
            Wait::Ready if state.datagram => state.inbound.take_packet(buf, from),
            Wait::Ready => (state.inbound.take_bytes(buf), 0),
        };
        drop(state);
        self.to_receive.notify_one();
        (Io::Done(read.0), read.1)
    }

    fn write(&self, data: &[u8], to: &str) -> Io {
        let ready = |s: &State| !s.done && !s.outbound.empty.is_empty();
        let (mut state, wait) =
            self.wait(&self.writable, lock(&self.state), |s| &s.outbound, ready);
        let taken = match wait {
            Wait::TimedOut => return Io::TimedOut,
            Wait::Done => return Io::Failed,
            Wait::Ready if state.datagram => {
                let Ok(peer) = to.parse() else {
                    return Io::Failed;
                };
                state.outbound.put_packet(data, peer);
                data.len()
            }
            Wait::Ready => state.outbound.put_bytes(data),
        };
        drop(state);
        self.to_send.notify_one();
        Io::Done(taken)
    }

    fn deadline(&self, read: bool, write: bool, at: Option<Instant>) {
        let mut state = lock(&self.state);
        if read {
            state.inbound.deadline = at;
        }
        if write {
            state.outbound.deadline = at;
        }
        drop(state);
        self.readable.notify_all();
        self.writable.notify_all();
    }

    fn close(&self) {
        lock(&self.state).done = true;
        self.gone.cancel();
        self.readable.notify_all();
        self.writable.notify_all();
        self.to_send.notify_one();
        self.to_receive.notify_one();
    }

    /// An empty buffer to receive into, once there is one; `None` once the pipe is done.
    async fn empty_inbound(&self) -> Option<Box<[u8]>> {
        loop {
            {
                let mut state = lock(&self.state);
                if state.done {
                    return None;
                }
                if let Some(bytes) = state.inbound.empty.pop() {
                    return Some(bytes);
                }
            }
            self.to_receive.notified().await;
        }
    }

    fn received(&self, bytes: Box<[u8]>, len: usize, peer: Option<SocketAddr>) {
        lock(&self.state).inbound.fill(bytes, len, peer);
        self.readable.notify_all();
    }

    fn unused(&self, bytes: Box<[u8]>) {
        lock(&self.state).inbound.empty.push(bytes);
    }

    /// The stream ended, cleanly or not; a failure also ends writing.
    fn ended(&self, failed: bool) {
        let mut state = lock(&self.state);
        state.eof |= !failed;
        state.done |= failed;
        drop(state);
        self.readable.notify_all();
        self.writable.notify_all();
    }

    /// The next filled buffer to send; `None` once the pipe is done and all sent.
    async fn next_outbound(&self) -> Option<Slot> {
        loop {
            {
                let mut state = lock(&self.state);
                if let Some(slot) = state.outbound.filled.pop_front() {
                    return Some(slot);
                }
                if state.done {
                    return None;
                }
            }
            self.to_send.notified().await;
        }
    }

    fn sent(&self, bytes: Box<[u8]>) {
        lock(&self.state).outbound.empty.push(bytes);
        self.writable.notify_all();
    }
}

fn write_peer(out: &mut [u8], peer: Option<SocketAddr>) -> usize {
    use std::io::Write as _;
    let Some(peer) = peer else { return 0 };
    let room = out.len();
    let mut cursor = io::Cursor::new(out);
    match write!(cursor, "{peer}") {
        Ok(()) => usize::try_from(cursor.position()).unwrap_or(room),
        Err(_) => 0,
    }
}

async fn pump(pipe: &Pipe, carrier: Carrier) {
    match carrier {
        Carrier::Stream(stream) => {
            let (mut rd, mut wr) = stream.into_split();
            let down = async {
                while let Some(mut bytes) = pipe.empty_inbound().await {
                    let read = rd.read(&mut bytes).await;
                    match read {
                        Ok(len) if len > 0 => pipe.received(bytes, len, None),
                        _ => {
                            pipe.unused(bytes);
                            return pipe.ended(read.is_err());
                        }
                    }
                }
            };
            let up = async {
                while let Some(slot) = pipe.next_outbound().await {
                    let sent = wr
                        .write_all(slot.bytes.get(..slot.end).unwrap_or_default())
                        .await;
                    pipe.sent(slot.bytes);
                    if sent.is_err() {
                        return pipe.ended(true);
                    }
                }
                let _ = wr.shutdown().await;
            };
            // Bytes the node wrote before it closed still go out; reading stops at once.
            let down = async {
                tokio::select! {
                    () = down => {}
                    () = pipe.gone.cancelled() => {}
                }
            };
            tokio::join!(down, up);
        }
        Carrier::Packets(session) => {
            let down = async {
                while let Ok((packet, from)) = recv_packet(&*session).await {
                    let Address::Socket(from) = from else {
                        continue;
                    };
                    let Some(mut bytes) = pipe.empty_inbound().await else {
                        return;
                    };
                    let data = packet.as_slice();
                    if data.len() > bytes.len() {
                        pipe.unused(bytes);
                        continue;
                    }
                    let n = copy(&mut bytes, data);
                    pipe.received(bytes, n, Some(from));
                }
            };
            let up = async {
                while let Some(slot) = pipe.next_outbound().await {
                    let mut packet = PacketBuf::take();
                    packet.extend_from_slice(slot.bytes.get(..slot.end).unwrap_or_default());
                    let peer = slot.peer.map(Address::from);
                    pipe.sent(slot.bytes);
                    if let Some(peer) = peer {
                        let _ = send_packet(&*session, &mut packet, &peer).await;
                    }
                }
            };
            tokio::select! {
                () = down => {}
                () = up => {}
            }
        }
    }
    pipe.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocking<T: Send + 'static>(
        work: impl FnOnce() -> T + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        tokio::task::spawn_blocking(work)
    }

    #[tokio::test]
    async fn a_stream_carries_both_ways_and_reports_its_end() {
        let (near, mut far) = tokio::io::duplex(1024);
        let pipe = Arc::new(Pipe::new(false));
        let pumped = pipe.clone();
        tokio::spawn(async move { pump(&pumped, Carrier::Stream(Box::new(near))).await });

        let writer = pipe.clone();
        assert!(matches!(
            blocking(move || writer.write(b"ping", "")).await.unwrap(),
            Io::Done(4)
        ));
        let mut got = [0; 4];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");

        far.write_all(b"pong").await.unwrap();
        drop(far);
        let reader = pipe.clone();
        let (first, ended) = blocking(move || {
            let mut buf = [0; 16];
            let first = reader.read(&mut buf, &mut []);
            let ended = reader.read(&mut buf, &mut []);
            (
                matches!(first, (Io::Done(4), 0)) && &buf[..4] == b"pong",
                ended,
            )
        })
        .await
        .unwrap();
        assert!(first);
        assert!(matches!(ended, (Io::Done(0), 0)));
    }

    #[tokio::test]
    async fn a_deadline_ends_a_waiting_read_and_closing_ends_the_rest() {
        let pipe = Arc::new(Pipe::new(false));
        pipe.deadline(
            true,
            false,
            Some(Instant::now() + Duration::from_millis(20)),
        );
        let reader = pipe.clone();
        assert!(matches!(
            blocking(move || reader.read(&mut [0; 8], &mut []))
                .await
                .unwrap()
                .0,
            Io::TimedOut
        ));

        pipe.deadline(true, false, None);
        let reader = pipe.clone();
        let waiting = blocking(move || reader.read(&mut [0; 8], &mut []).0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        pipe.close();
        assert!(matches!(waiting.await.unwrap(), Io::Failed));
        assert!(matches!(pipe.write(b"late", ""), Io::Failed));
    }

    #[tokio::test]
    async fn packets_keep_their_peer_and_an_oversized_one_is_dropped() {
        let pipe = Pipe::new(true);
        assert!(matches!(
            pipe.write(b"hello", "192.0.2.1:41641"),
            Io::Done(5)
        ));
        assert!(
            matches!(pipe.write(&[0; SLOT + 1], "192.0.2.1:41641"), Io::Done(n) if n == SLOT + 1)
        );
        let slot = pipe.next_outbound().await.unwrap();
        assert_eq!(
            (&slot.bytes[..slot.end], slot.peer),
            (&b"hello"[..], Some("192.0.2.1:41641".parse().unwrap()))
        );
        pipe.sent(slot.bytes);
        assert!(lock(&pipe.state).outbound.filled.is_empty());

        let bytes = pipe.empty_inbound().await.unwrap();
        let n = {
            let mut bytes = bytes;
            let n = copy(&mut bytes, b"reply");
            pipe.received(bytes, n, Some("[2001:db8::1]:3478".parse().unwrap()));
            n
        };
        let (mut buf, mut from) = ([0; 16], [0; 64]);
        let (io, from_len) = pipe.read(&mut buf, &mut from);
        assert!(matches!(io, Io::Done(len) if len == n));
        assert_eq!(&from[..from_len], b"[2001:db8::1]:3478");
    }
}
