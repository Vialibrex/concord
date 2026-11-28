//! The node's own connections through its `dialer-proxy`. Bytes and packets wait in fixed
//! buffers made on the runtime, so the Go threads that read and write them only copy and wait,
//! as `Inbox` does for the tailnet's packets: glibc gives each thread that allocates an arena of
//! its own.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
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
/// Base unit of tailscale's `util/backoff` (`min(n² * 10 ms, max)` with 0.5–1.5x jitter).
const RECONNECT_UNIT: Duration = Duration::from_millis(10);
/// Upper bound of tailscale's DERP reconnect backoff (`magicsock/derp.go`).
const RECONNECT_MAX: Duration = Duration::from_secs(5);

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
        let opened = dial
            .clone()
            .open(self.stop.clone(), timeout.unwrap_or(OPEN_TIMEOUT));
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
                () = pump(&pipe, carrier, &dial) => {}
            }
        });
        Some(conn)
    }

    fn read(&self, conn: i64, buf: &mut [u8], from: &mut [u8]) -> (Io, usize) {
        match self.pipe(conn) {
            Some(pipe) => pipe.read(buf, from),
            None => (Io::Closed, 0),
        }
    }

    fn write(&self, conn: i64, data: &[u8], to: &str) -> Io {
        match self.pipe(conn) {
            Some(pipe) => pipe.write(data, to),
            None => Io::Closed,
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
#[derive(Clone)]
struct Dial {
    node: Arc<str>,
    proxy: Arc<str>,
    env: Arc<DialEnv>,
    dst: Address,
    datagram: bool,
}

impl Dial {
    async fn run_bounded<T>(
        stop: CancellationToken,
        timeout: Duration,
        work: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        match stop
            .run_until_cancelled_owned(tokio::time::timeout(timeout, work))
            .await
        {
            Some(Ok(opened)) => opened,
            Some(Err(elapsed)) => Err(elapsed.into()),
            None => Err(io::ErrorKind::ConnectionAborted.into()),
        }
    }

    async fn open(
        self,
        stop: CancellationToken,
        timeout: Duration,
    ) -> io::Result<(Arc<Pipe>, Carrier)> {
        let gone = stop.child_token();
        Self::run_bounded(stop, timeout, self.connect(gone)).await
    }

    async fn open_packets(
        &self,
        stop: CancellationToken,
        timeout: Duration,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Self::run_bounded(stop, timeout, self.connect_packets()).await
    }

    async fn connect_packets(&self) -> io::Result<Arc<dyn PacketSession>> {
        let cx = DialCx::new(&self.env, Initiator::Proxy, None);
        let inner = cx.enter(&self.node)?;
        self.env
            .nodes
            .associate_via(&self.proxy, &inner, &self.dst)
            .await
    }

    async fn connect(&self, gone: CancellationToken) -> io::Result<(Arc<Pipe>, Carrier)> {
        let carrier = if self.datagram {
            Carrier::Packets(self.connect_packets().await?)
        } else {
            let cx = DialCx::new(&self.env, Initiator::Proxy, None);
            let inner = cx.enter(&self.node)?;
            Carrier::Stream(
                self.env
                    .nodes
                    .dial_via(&self.proxy, &inner, &self.dst)
                    .await?,
            )
        };
        Ok((Arc::new(Pipe::new(self.datagram, gone)), carrier))
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
    /// Datagram carrier is rebuilding its underlying association; reads block and writes drop.
    reconnecting: bool,
    /// Closed explicitly by the node or host (`Via::close` / `Via::close_all`).
    closed: bool,
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
    fn new(datagram: bool, gone: CancellationToken) -> Pipe {
        let slots = if datagram { PACKET_SLOTS } else { STREAM_SLOTS };
        Pipe {
            state: Mutex::new(State {
                datagram,
                inbound: Lane::new(slots),
                outbound: Lane::new(slots),
                eof: false,
                reconnecting: false,
                closed: false,
                done: false,
            }),
            readable: Condvar::new(),
            writable: Condvar::new(),
            to_send: Notify::new(),
            to_receive: Notify::new(),
            gone,
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
            Wait::Done => return (if state.closed { Io::Closed } else { Io::Failed }, 0),
            Wait::Ready if state.datagram => state.inbound.take_packet(buf, from),
            Wait::Ready => (state.inbound.take_bytes(buf), 0),
        };
        drop(state);
        self.to_receive.notify_one();
        (Io::Done(read.0), read.1)
    }

    fn write(&self, data: &[u8], to: &str) -> Io {
        let ready =
            |s: &State| !s.done && (!s.outbound.empty.is_empty() || (s.datagram && s.reconnecting));
        let (mut state, wait) =
            self.wait(&self.writable, lock(&self.state), |s| &s.outbound, ready);
        let taken = match wait {
            Wait::TimedOut => return Io::TimedOut,
            Wait::Done => return if state.closed { Io::Closed } else { Io::Failed },
            Wait::Ready if state.datagram => {
                let Ok(peer) = to.parse() else {
                    return Io::Failed;
                };
                if state.reconnecting {
                    return Io::Done(data.len());
                }
                state.outbound.put_packet(data, peer);
                data.len()
            }
            Wait::Ready => state.outbound.put_bytes(data),
        };
        drop(state);
        self.to_send.notify_one();
        Io::Done(taken)
    }

    /// Marks the UDP pipe as rebuilding its underlying session; drops stale queued outbound
    /// packets and wakes blocked writers so Go senders never stall while the association rebuilds.
    fn set_reconnecting(&self, reconnecting: bool) {
        let mut state = lock(&self.state);
        state.reconnecting = reconnecting;
        if reconnecting {
            while state.outbound.filled.front().is_some() {
                state.outbound.recycle_front();
            }
        }
        drop(state);
        if reconnecting {
            self.writable.notify_all();
        }
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
        {
            let mut state = lock(&self.state);
            state.closed = true;
            state.done = true;
        }
        self.gone.cancel();
        self.readable.notify_all();
        self.writable.notify_all();
        self.to_send.notify_one();
        self.to_receive.notify_one();
    }

    fn finish(&self) {
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

struct ReconnectBackoff {
    attempts: u32,
    unit: Duration,
    max: Duration,
}

impl ReconnectBackoff {
    fn new(unit: Duration, max: Duration) -> Self {
        Self {
            attempts: 0,
            unit,
            max,
        }
    }

    fn reset(&mut self) {
        self.attempts = 0;
    }

    fn next_with_sample(&mut self, sample: f64) -> (Duration, bool) {
        self.attempts = self.attempts.saturating_add(1);
        let sq = u64::from(self.attempts).saturating_mul(u64::from(self.attempts));
        let unclamped = self
            .unit
            .saturating_mul(u32::try_from(sq).unwrap_or(u32::MAX));
        let capped = unclamped >= self.max;
        let base = unclamped.min(self.max);
        let scale = sample.clamp(0.0, 1.0) + 0.5;
        (Duration::from_secs_f64(base.as_secs_f64() * scale), capped)
    }
}

async fn pump(pipe: &Pipe, carrier: Carrier, dial: &Dial) {
    match carrier {
        Carrier::Stream(stream) => pump_stream(pipe, stream).await,
        Carrier::Packets(session) => {
            pump_packets_with_backoff(
                &dial.node,
                pipe,
                session,
                ReconnectBackoff::new(RECONNECT_UNIT, RECONNECT_MAX),
                rand::random::<f64>,
                || dial.open_packets(pipe.gone.clone(), OPEN_TIMEOUT),
            )
            .await;
        }
    }
    pipe.finish();
}

async fn pump_stream(pipe: &Pipe, stream: BoxStream) {
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

fn is_session_broken(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    )
}

async fn pump_packets_once(pipe: &Pipe, session: Arc<dyn PacketSession>) -> bool {
    let mut received_any = false;
    {
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
                received_any = true;
            }
        };
        let up = async {
            while let Some(slot) = pipe.next_outbound().await {
                let mut packet = PacketBuf::take();
                packet.extend_from_slice(slot.bytes.get(..slot.end).unwrap_or_default());
                let peer = slot.peer.map(Address::from);
                pipe.sent(slot.bytes);
                if let Some(peer) = peer
                    && let Err(err) = send_packet(&*session, &mut packet, &peer).await
                    && is_session_broken(&err)
                {
                    return;
                }
            }
        };
        tokio::select! {
            () = pipe.gone.cancelled() => {}
            () = down => {}
            () = up => {}
        }
    }
    session.close();
    received_any
}

async fn pump_packets_with_backoff<S, F, Fut>(
    node: &str,
    pipe: &Pipe,
    initial: Arc<dyn PacketSession>,
    mut backoff: ReconnectBackoff,
    mut sample: S,
    mut reconnect: F,
) where
    S: FnMut() -> f64,
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<Arc<dyn PacketSession>>>,
{
    let mut session = initial;
    loop {
        let received = pump_packets_once(pipe, session).await;
        if pipe.gone.is_cancelled() {
            break;
        }
        if received {
            backoff.reset();
        }
        pipe.set_reconnecting(true);
        tracing::warn!(
            "[Tailscale]({node}) dialer-proxy UDP session ended; rebuilding association"
        );
        let mut warned_first = false;
        let mut warned_cap = false;
        session = loop {
            let (delay, capped) = backoff.next_with_sample(sample());
            if pipe
                .gone
                .run_until_cancelled(tokio::time::sleep(delay))
                .await
                .is_none()
            {
                return;
            }
            match pipe.gone.run_until_cancelled(reconnect()).await {
                None => return,
                Some(Ok(next)) => {
                    pipe.set_reconnecting(false);
                    tracing::info!("[Tailscale]({node}) dialer-proxy UDP association rebuilt");
                    break next;
                }
                Some(Err(err)) => {
                    if pipe.gone.is_cancelled() {
                        return;
                    }
                    if !warned_first || (capped && !warned_cap) {
                        warned_first = true;
                        warned_cap |= capped;
                        tracing::warn!(
                            "[Tailscale]({node}) rebuilding dialer-proxy UDP association failed: {err}"
                        );
                    } else {
                        tracing::debug!(
                            "[Tailscale]({node}) rebuilding dialer-proxy UDP association failed: {err}"
                        );
                    }
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;

    fn blocking<T: Send + 'static>(
        work: impl FnOnce() -> T + Send + 'static,
    ) -> tokio::task::JoinHandle<T> {
        tokio::task::spawn_blocking(work)
    }

    #[tokio::test]
    async fn a_stream_carries_both_ways_and_reports_its_end() {
        let (near, mut far) = tokio::io::duplex(1024);
        let pipe = Arc::new(Pipe::new(false, CancellationToken::new()));
        let pumped = pipe.clone();
        tokio::spawn(async move {
            pump_stream(&pumped, Box::new(near)).await;
            pumped.finish();
        });

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
        let pipe = Arc::new(Pipe::new(false, CancellationToken::new()));
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
        assert!(matches!(waiting.await.unwrap(), Io::Closed));
        assert!(matches!(pipe.write(b"late", ""), Io::Closed));
    }

    #[tokio::test]
    async fn packets_keep_their_peer_and_an_oversized_one_is_dropped() {
        let pipe = Pipe::new(true, CancellationToken::new());
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

    type Datagram = (Vec<u8>, Address);
    type Inbound = io::Result<Datagram>;

    struct MockPackets {
        inbound: Mutex<tokio::sync::mpsc::UnboundedReceiver<Inbound>>,
        outbound: tokio::sync::mpsc::UnboundedSender<Datagram>,
        closed: AtomicBool,
    }

    impl MockPackets {
        fn pair() -> (
            Arc<Self>,
            tokio::sync::mpsc::UnboundedSender<Inbound>,
            tokio::sync::mpsc::UnboundedReceiver<Datagram>,
        ) {
            let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel();
            let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel();
            let session = Arc::new(Self {
                inbound: Mutex::new(in_rx),
                outbound: out_tx,
                closed: AtomicBool::new(false),
            });
            (session, in_tx, out_rx)
        }
    }

    impl PacketSession for MockPackets {
        fn poll_send(
            &self,
            _cx: &mut std::task::Context<'_>,
            pkt: &mut PacketBuf,
            dst: &Address,
        ) -> std::task::Poll<io::Result<()>> {
            if self.closed.load(Ordering::Relaxed) {
                return std::task::Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let _ = self.outbound.send((pkt.as_slice().to_vec(), dst.clone()));
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_recv(
            &self,
            cx: &mut std::task::Context<'_>,
            out: &mut PacketBuf,
        ) -> std::task::Poll<io::Result<Address>> {
            match lock(&self.inbound).poll_recv(cx) {
                std::task::Poll::Pending => std::task::Poll::Pending,
                std::task::Poll::Ready(Some(Ok((data, from)))) => {
                    out.clear();
                    out.extend_from_slice(&data);
                    std::task::Poll::Ready(Ok(from))
                }
                std::task::Poll::Ready(Some(Err(err))) => {
                    self.closed.store(true, Ordering::Relaxed);
                    std::task::Poll::Ready(Err(err))
                }
                std::task::Poll::Ready(None) => {
                    self.closed.store(true, Ordering::Relaxed);
                    std::task::Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
                }
            }
        }

        fn close(&self) {
            self.closed.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn reconnect_backoff_follows_tailscale_quadratic_curve_and_jitter() {
        let mut b = ReconnectBackoff::new(RECONNECT_UNIT, RECONNECT_MAX);
        assert_eq!(b.next_with_sample(0.5), (Duration::from_millis(10), false));
        assert_eq!(b.next_with_sample(0.5), (Duration::from_millis(40), false));
        assert_eq!(b.next_with_sample(0.5), (Duration::from_millis(90), false));
        assert_eq!(b.next_with_sample(0.0), (Duration::from_millis(80), false));
        assert_eq!(b.next_with_sample(1.0), (Duration::from_millis(375), false));
        for _ in 0..20 {
            let _ = b.next_with_sample(0.5);
        }
        assert_eq!(b.next_with_sample(0.5), (Duration::from_secs(5), true));
        assert_eq!(b.next_with_sample(0.0), (Duration::from_millis(2500), true));
        assert_eq!(b.next_with_sample(1.0), (Duration::from_millis(7500), true));
        b.reset();
        assert_eq!(b.next_with_sample(0.5), (Duration::from_millis(10), false));
    }

    #[tokio::test(start_paused = true)]
    async fn a_udp_carrier_rebuilds_its_session_with_backoff_and_keeps_the_pipe_open() {
        struct CloseOnDrop(Arc<Pipe>);
        impl Drop for CloseOnDrop {
            fn drop(&mut self) {
                self.0.close();
            }
        }

        let (first, first_in, mut first_out) = MockPackets::pair();
        let (second, second_in, mut second_out) = MockPackets::pair();
        let pipe = Arc::new(Pipe::new(true, CancellationToken::new()));
        let _guard = CloseOnDrop(pipe.clone());

        let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_gate = Arc::new(Notify::new());
        let first_gate_cb = first_gate.clone();
        let second_slot = Arc::new(Mutex::new(Some(second as Arc<dyn PacketSession>)));
        let attempt_count = Arc::new(AtomicI64::new(0));
        let first_session = first.clone();
        let pumped = pipe.clone();
        let pump_task = tokio::spawn(async move {
            pump_packets_with_backoff(
                "ts",
                &pumped,
                first_session,
                ReconnectBackoff::new(RECONNECT_UNIT, RECONNECT_MAX),
                || 0.5,
                move || {
                    let attempt_tx = attempt_tx.clone();
                    let first_gate = first_gate_cb.clone();
                    let second_slot = second_slot.clone();
                    let attempt_count = attempt_count.clone();
                    async move {
                        let count = attempt_count.fetch_add(1, Ordering::Relaxed) + 1;
                        let _ = attempt_tx.send(tokio::time::Instant::now());
                        if count == 1 {
                            first_gate.notified().await;
                        }
                        if count < 3 {
                            Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                        } else {
                            Ok(lock(&second_slot).take().unwrap())
                        }
                    }
                },
            )
            .await;
            pumped.finish();
        });

        let peer: SocketAddr = "192.0.2.1:41641".parse().unwrap();
        assert!(matches!(
            pipe.write(b"before", "192.0.2.1:41641"),
            Io::Done(6)
        ));
        assert_eq!(first_out.recv().await.unwrap().0, b"before");
        first_in
            .send(Ok((b"in1".to_vec(), Address::Socket(peer))))
            .unwrap();
        let reader = pipe.clone();
        let first_read = blocking(move || {
            let (mut buf, mut from) = ([0; 16], [0; 64]);
            let (io, fl) = reader.read(&mut buf, &mut from);
            (io, buf, fl)
        })
        .await
        .unwrap();
        assert!(matches!(first_read.0, Io::Done(3)));
        assert_eq!(&first_read.1[..3], b"in1");

        let reader = pipe.clone();
        let blocked_read = std::thread::spawn(move || {
            let (mut buf, mut from) = ([0; 32], [0; 64]);
            let (io, fl) = reader.read(&mut buf, &mut from);
            (io, buf, fl, from)
        });
        let dropped_at = tokio::time::Instant::now();
        first_in
            .send(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            .unwrap();
        let t0 = attempt_rx.recv().await.unwrap();
        assert!(lock(&pipe.state).reconnecting);
        assert!(first.closed.load(Ordering::Relaxed));

        let writer = pipe.clone();
        std::thread::spawn(move || {
            for _ in 0..PACKET_SLOTS + 8 {
                assert!(matches!(
                    writer.write(b"drop-during-rebuild", "192.0.2.1:41641"),
                    Io::Done(19)
                ));
            }
        })
        .join()
        .unwrap();

        first_gate.notify_one();
        let t1 = attempt_rx.recv().await.unwrap();
        let t2 = attempt_rx.recv().await.unwrap();
        assert_eq!(t0.duration_since(dropped_at), Duration::from_millis(10));
        assert_eq!(t1.duration_since(t0), Duration::from_millis(40));
        assert_eq!(t2.duration_since(t1), Duration::from_millis(90));

        second_in
            .send(Ok((b"after-rebuild".to_vec(), Address::Socket(peer))))
            .unwrap();
        let (io, buf, fl, from) = tokio::task::spawn_blocking(move || blocked_read.join().unwrap())
            .await
            .unwrap();
        assert!(matches!(io, Io::Done(13)));
        assert_eq!(&buf[..13], b"after-rebuild");
        assert_eq!(&from[..fl], b"192.0.2.1:41641");

        assert!(matches!(
            pipe.write(b"ping2", "192.0.2.1:41641"),
            Io::Done(5)
        ));
        assert_eq!(second_out.recv().await.unwrap().0, b"ping2");

        pipe.close();
        pump_task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn closing_a_udp_pipe_during_reconnect_backoff_ends_immediately() {
        let (first, first_in, _first_out) = MockPackets::pair();
        let pipe = Arc::new(Pipe::new(true, CancellationToken::new()));
        let pumped = pipe.clone();
        let pump_task = tokio::spawn(async move {
            pump_packets_with_backoff(
                "ts",
                &pumped,
                first,
                ReconnectBackoff::new(Duration::from_secs(5), Duration::from_secs(5)),
                || 0.5,
                || async { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) },
            )
            .await;
            pumped.finish();
        });

        first_in
            .send(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            .unwrap();
        while !lock(&pipe.state).reconnecting {
            tokio::task::yield_now().await;
        }
        let closed_at = tokio::time::Instant::now();
        pipe.close();
        pump_task.await.unwrap();
        assert_eq!(closed_at.elapsed(), Duration::ZERO);
        assert!(matches!(pipe.read(&mut [0; 8], &mut [0; 32]).0, Io::Closed));
    }

    #[tokio::test(start_paused = true)]
    async fn closing_a_udp_pipe_while_reconnecting_ends_immediately() {
        let (first, first_in, _first_out) = MockPackets::pair();
        let pipe = Arc::new(Pipe::new(true, CancellationToken::new()));
        let started = Arc::new(Notify::new());
        let started_cb = started.clone();
        let pumped = pipe.clone();
        let pump_task = tokio::spawn(async move {
            pump_packets_with_backoff(
                "ts",
                &pumped,
                first,
                ReconnectBackoff::new(RECONNECT_UNIT, RECONNECT_MAX),
                || 0.5,
                move || {
                    let started = started_cb.clone();
                    async move {
                        started.notify_one();
                        std::future::pending::<io::Result<Arc<dyn PacketSession>>>().await
                    }
                },
            )
            .await;
            pumped.finish();
        });

        first_in
            .send(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            .unwrap();
        started.notified().await;
        let closed_at = tokio::time::Instant::now();
        pipe.close();
        pump_task.await.unwrap();
        assert_eq!(closed_at.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_flappy_udp_session_backs_off_until_a_session_delivers_traffic() {
        let (first, first_in, _first_out) = MockPackets::pair();
        let (flappy, flappy_in, _flappy_out) = MockPackets::pair();
        let (healthy, healthy_in, _healthy_out) = MockPackets::pair();
        let (fourth, _fourth_in, _fourth_out) = MockPackets::pair();
        let pipe = Arc::new(Pipe::new(true, CancellationToken::new()));

        let (attempt_tx, mut attempt_rx) = tokio::sync::mpsc::unbounded_channel();
        let sessions = Arc::new(Mutex::new(VecDeque::<Arc<dyn PacketSession>>::from([
            flappy as Arc<dyn PacketSession>,
            healthy as Arc<dyn PacketSession>,
            fourth as Arc<dyn PacketSession>,
        ])));
        let pumped = pipe.clone();
        let pump_task = tokio::spawn(async move {
            pump_packets_with_backoff(
                "ts",
                &pumped,
                first,
                ReconnectBackoff::new(RECONNECT_UNIT, RECONNECT_MAX),
                || 0.5,
                move || {
                    let attempt_tx = attempt_tx.clone();
                    let sessions = sessions.clone();
                    async move {
                        let _ = attempt_tx.send(tokio::time::Instant::now());
                        lock(&sessions)
                            .pop_front()
                            .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))
                    }
                },
            )
            .await;
            pumped.finish();
        });

        let start = tokio::time::Instant::now();
        flappy_in
            .send(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            .unwrap();
        first_in
            .send(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            .unwrap();
        let t0 = attempt_rx.recv().await.unwrap();
        let t1 = attempt_rx.recv().await.unwrap();
        assert_eq!(t0.duration_since(start), Duration::from_millis(10));
        assert_eq!(t1.duration_since(t0), Duration::from_millis(40));

        let peer: SocketAddr = "192.0.2.1:41641".parse().unwrap();
        healthy_in
            .send(Ok((b"ok".to_vec(), Address::Socket(peer))))
            .unwrap();
        let reader = pipe.clone();
        let (io, _) = blocking(move || reader.read(&mut [0; 16], &mut [0; 64]))
            .await
            .unwrap();
        assert!(matches!(io, Io::Done(2)));

        let dropped_healthy = tokio::time::Instant::now();
        healthy_in
            .send(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
            .unwrap();
        let t2 = attempt_rx.recv().await.unwrap();
        assert_eq!(
            t2.duration_since(dropped_healthy),
            Duration::from_millis(10)
        );

        pipe.close();
        pump_task.await.unwrap();
    }
}
