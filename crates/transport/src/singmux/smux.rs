use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker, ready};
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream, Tasks};
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::MuxSession;
use super::inbox::Inbox;
use crate::http1::invalid;

const VERSION: u8 = 1;
const FIRST_STREAM_ID: u32 = 3;
const CMD_SYN: u8 = 0;
const CMD_FIN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_NOP: u8 = 3;
const CMD_UPD: u8 = 4;
const MAX_FRAME: usize = 32768;
const MAX_RECEIVE_BUFFER: i64 = 4 * 1024 * 1024;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

fn put_frame(out: &mut Vec<u8>, cmd: u8, sid: u32, payload: &[u8]) {
    let len = u16::try_from(payload.len())
        .unwrap_or(u16::MAX)
        .to_le_bytes();
    let [s0, s1, s2, s3] = sid.to_le_bytes();
    out.extend_from_slice(&[VERSION, cmd, len[0], len[1], s0, s1, s2, s3]);
    out.extend_from_slice(payload);
}

/// The session's write half. A stream writes its frame itself, in its own task, as
/// metacubex/smux's writeFrameInternal hands its frame to the connection writer
/// (session.go:671-695), and streams waiting for their turn queue in arrival order.
/// Waiting is the only time a write is pending, so a cancelled write has handed over
/// nothing. A taken frame belongs to the session: the next writer finishes it before its
/// own, and if no one comes the session's driver does, so no write leaves half a frame on
/// the wire or holds up the streams behind it. A writer waiting for its turn drives the
/// frame ahead of it itself; one that stops polling while it waits keeps its place, and
/// the rest of that frame, until it polls again or is dropped.
struct FrameWriter(Mutex<WriterState>);

struct WriterState {
    io: Option<BoxWrite>,
    frame: Vec<u8>,
    off: usize,
    unflushed: bool,
    waiting: VecDeque<(u64, Waker)>,
    next_ticket: u64,
    driver: Option<Waker>,
}

struct Turn {
    writer: Arc<FrameWriter>,
    ticket: Option<u64>,
}

impl Turn {
    fn new(writer: Arc<FrameWriter>) -> Self {
        Turn {
            writer,
            ticket: None,
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        make: impl FnOnce(&mut Vec<u8>),
    ) -> Poll<io::Result<()>> {
        let writer = self.writer.clone();
        writer.poll_send(cx, &mut self.ticket, make)
    }

    fn leave(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.writer.leave(ticket);
        }
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        self.leave();
    }
}

struct WakeAll(Vec<Waker>);

impl Wake for WakeAll {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        for waker in &self.0 {
            waker.wake_by_ref();
        }
    }
}

impl WriterState {
    fn broken() -> io::Error {
        io::ErrorKind::BrokenPipe.into()
    }

    fn busy(&self) -> bool {
        self.off < self.frame.len()
    }

    /// The connection wakes only its last poller, who may be a writer dropped since; the
    /// head of the queue is woken with it, so a frame left half written still finishes.
    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.busy() {
            return Poll::Ready(Ok(()));
        }
        let head = self
            .waiting
            .front()
            .map(|(_, waker)| waker)
            .filter(|w| !w.will_wake(cx.waker()))
            .cloned();
        let Some(head) = head else {
            return self.write_rest(cx);
        };
        let both = Waker::from(Arc::new(WakeAll(vec![cx.waker().clone(), head])));
        self.write_rest(&mut Context::from_waker(&both))
    }

    fn write_rest(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(io) = self.io.as_mut() else {
            return Poll::Ready(Err(Self::broken()));
        };
        while let Some(rest) = self.frame.get(self.off..).filter(|rest| !rest.is_empty()) {
            match ready!(Pin::new(&mut *io).poll_write(cx, rest)) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(n) => self.off += n,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        self.unflushed = true;
        Poll::Ready(Ok(()))
    }

    fn write_taken(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.write_rest(cx) {
            Poll::Ready(Ok(())) if self.waiting.is_empty() => self.poll_flush(cx),
            other => other,
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_progress(cx))?;
        let Some(io) = self.io.as_mut() else {
            return Poll::Ready(Err(Self::broken()));
        };
        ready!(Pin::new(io).poll_flush(cx))?;
        self.unflushed = false;
        Poll::Ready(Ok(()))
    }

    fn head(&self) -> Option<u64> {
        self.waiting.front().map(|(ticket, _)| *ticket)
    }

    fn wait(&mut self, cx: &mut Context<'_>, ticket: &mut Option<u64>) {
        let queued = ticket.and_then(|ticket| self.waiting.iter_mut().find(|(t, _)| *t == ticket));
        match queued {
            Some((_, waker)) => waker.clone_from(cx.waker()),
            None => {
                let next = self.next_ticket;
                self.next_ticket += 1;
                *ticket = Some(next);
                self.waiting.push_back((next, cx.waker().clone()));
            }
        }
    }

    fn fail(&mut self) -> Vec<Waker> {
        self.io = None;
        self.frame.clear();
        self.off = 0;
        self.waiting
            .drain(..)
            .map(|(_, waker)| waker)
            .chain(self.driver.take())
            .collect()
    }
}

impl FrameWriter {
    fn new(io: BoxWrite) -> Arc<Self> {
        Arc::new(FrameWriter(Mutex::new(WriterState {
            io: Some(io),
            frame: Vec::new(),
            off: 0,
            unflushed: false,
            waiting: VecDeque::new(),
            next_ticket: 0,
            driver: None,
        })))
    }

    /// Waits for `ticket`'s turn behind the frame in progress and the writers that came
    /// first, then takes the frame `make` builds and writes what the connection accepts
    /// now; the last writer in line also flushes. Waiting holds no lock, and only the
    /// connection itself not taking bytes stops every stream, as it stops smux's sendLoop.
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        ticket: &mut Option<u64>,
        make: impl FnOnce(&mut Vec<u8>),
    ) -> Poll<io::Result<()>> {
        let mut wake = Vec::new();
        let result = {
            let mut state = lock(&self.0);
            Self::poll_send_locked(&mut state, cx, ticket, make, &mut wake)
        };
        for waker in wake {
            waker.wake();
        }
        result
    }

    fn poll_send_locked(
        state: &mut WriterState,
        cx: &mut Context<'_>,
        ticket: &mut Option<u64>,
        make: impl FnOnce(&mut Vec<u8>),
        wake: &mut Vec<Waker>,
    ) -> Poll<io::Result<()>> {
        match state.poll_progress(cx) {
            Poll::Pending => {
                state.wait(cx, ticket);
                return Poll::Pending;
            }
            Poll::Ready(Err(err)) => {
                *ticket = None;
                wake.extend(state.fail());
                return Poll::Ready(Err(err));
            }
            Poll::Ready(Ok(())) => {}
        }
        let head = state.head();
        if head.is_some() && head != *ticket {
            state.wait(cx, ticket);
            wake.extend(state.waiting.front().map(|(_, waker)| waker.clone()));
            return Poll::Pending;
        }
        if head.is_some() {
            state.waiting.pop_front();
        }
        *ticket = None;
        state.frame.clear();
        make(&mut state.frame);
        state.off = 0;
        // The writer returns once its frame is taken, so the connection wakes the driver,
        // not the writer; a writer that comes back first registers itself instead.
        let written = match state.driver.clone() {
            Some(driver) => state.write_taken(&mut Context::from_waker(&driver)),
            None => state.write_taken(cx),
        };
        if let Poll::Ready(Err(err)) = written {
            wake.extend(state.fail());
            return Poll::Ready(Err(err));
        }
        wake.extend(state.waiting.front().map(|(_, waker)| waker.clone()));
        Poll::Ready(Ok(()))
    }

    fn leave(&self, ticket: u64) {
        let waker = {
            let mut state = lock(&self.0);
            let was_head = state.head() == Some(ticket);
            state.waiting.retain(|(t, _)| *t != ticket);
            match state.waiting.front() {
                Some((_, head)) if was_head => Some(head.clone()),
                None if state.busy() || state.unflushed => state.driver.clone(),
                _ => None,
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The session's driver: finishes a frame its writer left half written and flushes
    /// what the last writer could not, and otherwise sleeps.
    fn poll_drive(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = lock(&self.0);
        if state.io.is_none() {
            return Poll::Ready(());
        }
        match state.driver.as_mut() {
            Some(driver) => driver.clone_from(cx.waker()),
            None => state.driver = Some(cx.waker().clone()),
        }
        let done = if state.unflushed && state.waiting.is_empty() {
            state.poll_flush(cx)
        } else {
            state.poll_progress(cx)
        };
        let wake = match done {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => state.fail(),
            Poll::Ready(Ok(())) => state
                .waiting
                .front()
                .map(|(_, waker)| waker.clone())
                .into_iter()
                .collect(),
        };
        drop(state);
        for waker in wake {
            waker.wake();
        }
        Poll::Pending
    }

    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        lock(&self.0).poll_flush(cx)
    }

    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = lock(&self.0);
        ready!(state.poll_flush(cx))?;
        match state.io.as_mut() {
            Some(io) => Pin::new(io).poll_shutdown(cx),
            None => Poll::Ready(Err(WriterState::broken())),
        }
    }

    fn close(&self) {
        let wakers = lock(&self.0).fail();
        for waker in wakers {
            waker.wake();
        }
    }
}

async fn send_frame(writer: &Arc<FrameWriter>, cmd: u8, sid: u32) -> io::Result<()> {
    let mut turn = Turn::new(writer.clone());
    poll_fn(|cx| turn.poll_send(cx, |out| put_frame(out, cmd, sid, &[]))).await
}

/// Hands a frame over from a context that cannot wait for its turn.
fn send_detached(core: &Core, cmd: u8, sid: u32) {
    let mut ticket = None;
    let mut cx = Context::from_waker(Waker::noop());
    let sent = core
        .writer
        .poll_send(&mut cx, &mut ticket, |out| put_frame(out, cmd, sid, &[]));
    if let Some(ticket) = ticket {
        core.writer.leave(ticket);
    }
    if sent.is_pending() {
        let writer = core.writer.clone();
        core.tasks.spawn_detached(async move {
            let _ = send_frame(&writer, cmd, sid).await;
        });
    }
}

struct Entry {
    inbox: Inbox,
    remote_fin: AtomicBool,
}

struct Core {
    streams: Mutex<HashMap<u32, Arc<Entry>>>,
    next_id: AtomicU32,
    writer: Arc<FrameWriter>,
    closed: AtomicBool,
    bucket: AtomicI64,
    bucket_notify: Notify,
    mode: Mode,
    first_id: u32,
    tasks: Tasks,
}

enum Mode {
    /// Each stream sends its own FIN, and a dropped session closes the connection at once.
    Shared,
    /// A dropped session finishes the frame in progress and ends the one stream with a FIN
    /// unless it already sent one.
    Single { fin_sent: AtomicBool },
}

impl Core {
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let streams = std::mem::take(&mut *lock(&self.streams));
        for entry in streams.values() {
            entry
                .inbox
                .fail(io::ErrorKind::BrokenPipe, "smux session closed");
        }
        self.bucket_notify.notify_one();
    }

    fn return_tokens(&self, n: usize) {
        let n = i64::try_from(n).unwrap_or(i64::MAX);
        if self.bucket.fetch_add(n, Ordering::Relaxed) <= 0 {
            self.bucket_notify.notify_one();
        }
    }
}

pub(super) struct SmuxSession {
    core: Arc<Core>,
    tasks: [JoinHandle<()>; 2],
}

impl SmuxSession {
    pub fn new(io: BoxStream, tasks: &Tasks) -> Self {
        Self::start(io, FIRST_STREAM_ID, Mode::Shared, tasks)
    }

    pub(super) fn with_first_id(io: BoxStream, first_id: u32, tasks: &Tasks) -> Self {
        let mode = Mode::Single {
            fin_sent: AtomicBool::new(false),
        };
        Self::start(io, first_id, mode, tasks)
    }

    fn start(io: BoxStream, first_id: u32, mode: Mode, tasks: &Tasks) -> Self {
        let (read, write) = Box::new(io).into_split();
        let core = Arc::new(Core {
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(first_id),
            writer: FrameWriter::new(write),
            closed: AtomicBool::new(false),
            bucket: AtomicI64::new(MAX_RECEIVE_BUFFER),
            bucket_notify: Notify::new(),
            mode,
            first_id,
            tasks: tasks.clone(),
        });
        let reader = {
            let core = core.clone();
            tasks.spawn(async move {
                let _ = read_loop(&core, read).await;
                core.close();
            })
        };
        let driver = {
            let core = core.clone();
            tasks.spawn(async move {
                poll_fn(|cx| core.writer.poll_drive(cx)).await;
                core.close();
            })
        };
        SmuxSession {
            core,
            tasks: [reader, driver],
        }
    }
}

async fn read_loop(core: &Core, mut io: BoxRead) -> io::Result<()> {
    loop {
        while core.bucket.load(Ordering::Relaxed) <= 0 {
            if core.closed.load(Ordering::Relaxed) {
                return Ok(());
            }
            core.bucket_notify.notified().await;
        }
        let mut header = [0u8; 8];
        io.read_exact(&mut header).await?;
        let [version, cmd, l0, l1, s0, s1, s2, s3] = header;
        if version != VERSION {
            return Err(invalid("smux: invalid protocol version"));
        }
        let len = usize::from(u16::from_le_bytes([l0, l1]));
        let sid = u32::from_le_bytes([s0, s1, s2, s3]);
        match cmd {
            CMD_NOP | CMD_SYN => {}
            CMD_FIN => {
                if let Some(entry) = lock(&core.streams).get(&sid) {
                    entry.remote_fin.store(true, Ordering::Relaxed);
                    entry.inbox.fin();
                }
            }
            CMD_PSH => {
                if len == 0 {
                    continue;
                }
                let mut payload = vec![0u8; len];
                io.read_exact(&mut payload).await?;
                let entry = lock(&core.streams).get(&sid).cloned();
                if let Some(entry) = entry {
                    core.bucket
                        .fetch_sub(i64::try_from(len).unwrap_or(i64::MAX), Ordering::Relaxed);
                    if !entry.inbox.push(Bytes::from(payload)) {
                        core.return_tokens(len);
                    }
                }
            }
            CMD_UPD => {
                let mut update = [0u8; 8];
                io.read_exact(&mut update).await?;
            }
            _ => return Err(invalid("smux: invalid command")),
        }
    }
}

impl Drop for SmuxSession {
    fn drop(&mut self) {
        self.core.close();
        for task in &self.tasks {
            task.abort();
        }
        let Mode::Single { fin_sent } = &self.core.mode else {
            self.core.writer.close();
            return;
        };
        let writer = self.core.writer.clone();
        let fin = !fin_sent.load(Ordering::Relaxed);
        let id = self.core.first_id;
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
        let drain = writer.clone();
        let spawned = self.core.tasks.spawn_detached(async move {
            let _ = tokio::time::timeout_at(deadline, async {
                if fin {
                    send_frame(&drain, CMD_FIN, id).await?;
                }
                poll_fn(|cx| drain.poll_shutdown(cx)).await
            })
            .await;
            drain.close();
        });
        if !spawned {
            writer.close();
        }
    }
}

impl MuxSession for SmuxSession {
    fn open(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            if self.core.closed.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let id = self.core.next_id.fetch_add(2, Ordering::Relaxed);
            let entry = Arc::new(Entry {
                inbox: Inbox::default(),
                remote_fin: AtomicBool::new(false),
            });
            lock(&self.core.streams).insert(id, entry.clone());
            let stream = SmuxStream::new(id, self.core.clone(), entry);
            if let Err(err) = send_frame(&self.core.writer, CMD_SYN, id).await {
                self.core.close();
                return Err(err);
            }
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn streams(&self) -> usize {
        lock(&self.core.streams).len()
    }

    fn is_closed(&self) -> bool {
        self.core.closed.load(Ordering::Relaxed)
    }

    fn close(&self) {
        self.core.close();
        for task in &self.tasks {
            task.abort();
        }
        self.core.writer.close();
    }
}

struct Shared {
    id: u32,
    core: Arc<Core>,
    entry: Arc<Entry>,
    closed: AtomicBool,
}

impl Shared {
    fn release(&self) {
        lock(&self.core.streams).remove(&self.id);
        let dropped = self.entry.inbox.close_read();
        if dropped > 0 {
            self.core.return_tokens(dropped);
        }
    }
}

struct SmuxRead {
    shared: Arc<Shared>,
}

struct SmuxWrite {
    shared: Arc<Shared>,
    turn: Turn,
}

struct SmuxStream {
    write: SmuxWrite,
    read: SmuxRead,
}

impl SmuxStream {
    fn new(id: u32, core: Arc<Core>, entry: Arc<Entry>) -> Self {
        let turn = Turn::new(core.writer.clone());
        let shared = Arc::new(Shared {
            id,
            core,
            entry,
            closed: AtomicBool::new(false),
        });
        SmuxStream {
            write: SmuxWrite {
                shared: shared.clone(),
                turn,
            },
            read: SmuxRead { shared },
        }
    }
}

impl AsyncRead for SmuxRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &*self.get_mut().shared;
        if shared.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(()));
        }
        let n = ready!(shared.entry.inbox.poll_read(cx, buf))?;
        if n > 0 {
            shared.core.return_tokens(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for SmuxRead {
    fn drop(&mut self) {
        let dropped = self.shared.entry.inbox.close_read();
        if dropped > 0 {
            self.shared.core.return_tokens(dropped);
        }
    }
}

impl SmuxWrite {
    fn poll_frame(
        &mut self,
        cx: &mut Context<'_>,
        make: impl FnOnce(&mut Vec<u8>),
    ) -> Poll<io::Result<()>> {
        let sent = ready!(self.turn.poll_send(cx, make));
        if sent.is_err() {
            self.shared.core.close();
        }
        Poll::Ready(sent)
    }
}

impl AsyncWrite for SmuxWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let shared = &*this.shared;
        if shared.closed.load(Ordering::Relaxed) || shared.entry.remote_fin.load(Ordering::Relaxed)
        {
            this.turn.leave();
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let take = data.len().min(MAX_FRAME);
        let Some(chunk) = data.get(..take).filter(|chunk| !chunk.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        let id = shared.id;
        ready!(this.poll_frame(cx, |out| put_frame(out, CMD_PSH, id, chunk)))?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.core.writer.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shared.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(()));
        }
        let id = this.shared.id;
        ready!(this.poll_frame(cx, |out| put_frame(out, CMD_FIN, id, &[])))?;
        let shared = &*this.shared;
        if let Mode::Single { fin_sent } = &shared.core.mode {
            fin_sent.store(true, Ordering::Relaxed);
        }
        shared.closed.store(true, Ordering::Relaxed);
        shared.release();
        Poll::Ready(Ok(()))
    }
}

/// Smux has no half-close, so like `poll_shutdown` this ends the whole stream.
impl Drop for SmuxWrite {
    fn drop(&mut self) {
        self.turn.leave();
        let shared = &*self.shared;
        if !shared.closed.swap(true, Ordering::Relaxed) {
            if let Mode::Shared = shared.core.mode {
                send_detached(&shared.core, CMD_FIN, shared.id);
            }
            shared.release();
        }
    }
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl Stream for SmuxStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let SmuxStream { write, read } = *self;
        (Box::new(read), Box::new(write))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    fn frame(cmd: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_frame(&mut out, cmd, sid, payload);
        out
    }

    async fn read_frame(far: &mut (impl AsyncRead + Unpin)) -> (u8, u32, Vec<u8>) {
        let mut header = [0u8; 8];
        far.read_exact(&mut header).await.unwrap();
        let [_, cmd, l0, l1, s0, s1, s2, s3] = header;
        let mut payload = vec![0; usize::from(u16::from_le_bytes([l0, l1]))];
        far.read_exact(&mut payload).await.unwrap();
        (cmd, u32::from_le_bytes([s0, s1, s2, s3]), payload)
    }

    async fn next_frame(far: &mut (impl AsyncRead + Unpin)) -> (u8, u32) {
        let mut header = [0u8; 8];
        far.read_exact(&mut header).await.unwrap();
        let [_, cmd, l0, l1, s0, s1, s2, s3] = header;
        let mut payload = vec![0; usize::from(u16::from_le_bytes([l0, l1]))];
        far.read_exact(&mut payload).await.unwrap();
        (cmd, u32::from_le_bytes([s0, s1, s2, s3]))
    }

    #[tokio::test]
    async fn first_smux_syn_matches_mihomo_and_sing_box_client_bytes() {
        let (near, mut far) = duplex(128);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let _first = session.open().await.unwrap();
        let mut header = [0; 8];
        far.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [1, 0, 0, 0, 3, 0, 0, 0]);
        let _second = session.open().await.unwrap();
        far.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [1, 0, 0, 0, 5, 0, 0, 0]);
    }

    async fn psh_frames(far: &mut (impl AsyncRead + Unpin), count: usize) -> Vec<u32> {
        let mut ids = Vec::new();
        while ids.len() < count {
            let (cmd, sid) = next_frame(far).await;
            if cmd == CMD_PSH {
                ids.push(sid);
            }
        }
        ids
    }

    #[tokio::test]
    async fn streams_waiting_on_a_full_session_take_turns_in_arrival_order() {
        let (near, mut far) = duplex(64);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let mut streams = Vec::new();
        for _ in 0..4 {
            streams.push(session.open().await.unwrap());
            next_frame(&mut far).await;
        }
        let mut writers = Vec::new();
        for (n, mut stream) in streams.into_iter().enumerate() {
            writers.push(tokio::spawn(async move {
                stream.write_all(&[2; 1000]).await.unwrap();
                if n == 0 {
                    stream.write_all(&[2; 1000]).await.unwrap();
                }
                stream
            }));
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
        }
        let ids = tokio::time::timeout(Duration::from_secs(5), psh_frames(&mut far, 5))
            .await
            .expect("a waiting stream never got the session");
        let first_id = FIRST_STREAM_ID;
        assert_eq!(
            ids,
            [first_id, first_id, first_id + 2, first_id + 4, first_id + 6]
        );
        for writer in writers {
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_writer_gone_mid_frame_leaves_the_whole_frame_before_the_next() {
        let (near, mut far) = duplex(64);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let mut first = session.open().await.unwrap();
        let mut second = session.open().await.unwrap();
        next_frame(&mut far).await;
        next_frame(&mut far).await;
        tokio::time::timeout(Duration::from_secs(1), first.write_all(&[1; 1000]))
            .await
            .expect("a taken frame kept its write pending")
            .unwrap();
        drop(first);
        let other = tokio::spawn(async move {
            second.write_all(&[2; 500]).await.unwrap();
            second
        });
        let frames = tokio::time::timeout(Duration::from_secs(5), async {
            let mut frames = Vec::new();
            while frames.len() < 2 {
                let (cmd, sid, payload) = read_frame(&mut far).await;
                if cmd == CMD_PSH {
                    frames.push((sid, payload));
                }
            }
            frames
        })
        .await
        .expect("the frame left half written held up the session");
        assert_eq!(frames[0], (FIRST_STREAM_ID, vec![1; 1000]));
        assert_eq!(frames[1], (FIRST_STREAM_ID + 2, vec![2; 500]));
        other.await.unwrap();
    }

    #[tokio::test]
    async fn a_frame_nobody_follows_is_finished_by_the_session() {
        let (near, mut far) = duplex(64);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let mut stream = session.open().await.unwrap();
        next_frame(&mut far).await;
        stream.write_all(&[4; 5000]).await.unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut far))
            .await
            .expect("a half-written frame waited for another writer");
        assert_eq!(frame, (CMD_PSH, FIRST_STREAM_ID, vec![4; 5000]));
        drop(stream);
    }

    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn a_writer_that_keeps_writing_never_wakes_the_session() {
        let (near, mut far) = duplex(64);
        let writer = FrameWriter::new(Box::new(near));
        let wakes = Arc::new(Wakes::default());
        let driver = Waker::from(wakes.clone());
        assert!(
            writer
                .poll_drive(&mut Context::from_waker(&driver))
                .is_pending()
        );
        let reader = tokio::spawn(async move {
            let mut sink = Vec::new();
            far.read_to_end(&mut sink).await.unwrap();
            sink.len()
        });
        let mut turn = Turn::new(writer.clone());
        for _ in 0..50 {
            poll_fn(|cx| turn.poll_send(cx, |out| put_frame(out, CMD_PSH, 3, &[7; 1000])))
                .await
                .unwrap();
        }
        poll_fn(|cx| writer.poll_flush(cx)).await.unwrap();
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
        writer.close();
        assert_eq!(reader.await.unwrap(), 50 * 1008);
    }

    #[tokio::test]
    async fn a_writer_dropped_while_waiting_leaves_its_place_to_the_next() {
        let (near, mut far) = duplex(64);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(session.open().await.unwrap());
            next_frame(&mut far).await;
        }
        let mut third = streams.pop().unwrap();
        let mut second = streams.pop().unwrap();
        let mut first = streams.pop().unwrap();
        let busy = tokio::spawn(async move {
            first.write_all(&[1; 1000]).await.unwrap();
            first
        });
        tokio::task::yield_now().await;
        {
            let write = second.write_all(&[2; 1000]);
            tokio::pin!(write);
            assert!(futures_util::poll!(write.as_mut()).is_pending());
        }
        drop(second);
        let last = tokio::spawn(async move {
            third.write_all(&[3; 1000]).await.unwrap();
            third
        });
        let frames = tokio::time::timeout(Duration::from_secs(5), async {
            let mut frames = Vec::new();
            while frames.len() < 2 {
                let (cmd, sid, payload) = read_frame(&mut far).await;
                if cmd == CMD_PSH {
                    frames.push((sid, payload));
                }
            }
            frames
        })
        .await
        .expect("a dropped waiter held its place");
        assert_eq!(frames[0], (FIRST_STREAM_ID, vec![1; 1000]));
        assert_eq!(frames[1], (FIRST_STREAM_ID + 4, vec![3; 1000]));
        busy.await.unwrap();
        last.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn writes_cancelled_at_random_never_tear_a_frame_or_stall_the_session() {
        const STREAMS: u32 = 8;
        const WRITES: u32 = 300;
        let (near, far) = duplex(256);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let reader = tokio::spawn(async move {
            let mut far = far;
            let mut frames = 0usize;
            loop {
                let mut header = [0u8; 8];
                if far.read_exact(&mut header).await.is_err() {
                    return frames;
                }
                let [_, cmd, l0, l1, s0, s1, s2, s3] = header;
                let sid = u32::from_le_bytes([s0, s1, s2, s3]);
                let mut payload = vec![0; usize::from(u16::from_le_bytes([l0, l1]))];
                far.read_exact(&mut payload).await.unwrap();
                if cmd == CMD_PSH {
                    let marker = u8::try_from(sid % 251).unwrap();
                    assert!(
                        payload.iter().all(|&b| b == marker),
                        "stream {sid} sent a torn frame"
                    );
                    frames += 1;
                }
            }
        });
        let mut writers = Vec::new();
        for n in 0..STREAMS {
            let mut stream = session.open().await.unwrap();
            writers.push(tokio::spawn(async move {
                let sid = FIRST_STREAM_ID + 2 * n;
                let marker = u8::try_from(sid % 251).unwrap();
                let mut seed = sid.wrapping_mul(2_654_435_761);
                for _ in 0..WRITES {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    let len = 1 + usize::try_from(seed >> 20).unwrap() % 3000;
                    let wait = Duration::from_micros(u64::from(seed >> 24) % 200);
                    let _ = tokio::time::timeout(wait, stream.write_all(&vec![marker; len])).await;
                }
                stream.write_all(&[marker; 10]).await.unwrap();
                stream
            }));
        }
        let mut streams = Vec::new();
        for writer in writers {
            streams.push(
                tokio::time::timeout(Duration::from_secs(20), writer)
                    .await
                    .expect("a cancelled write stalled the session")
                    .unwrap(),
            );
        }
        drop(streams);
        drop(session);
        let frames = tokio::time::timeout(Duration::from_secs(5), reader)
            .await
            .expect("the session never closed")
            .unwrap();
        assert!(frames >= usize::try_from(STREAMS).unwrap());
    }

    #[tokio::test]
    async fn streams_contending_for_the_session_alternate() {
        const FRAMES: usize = 200;
        let (near, mut far) = duplex(64);
        let session = SmuxSession::new(Box::new(near), &Default::default());
        let mut writers = Vec::new();
        for _ in 0..2 {
            let mut stream = session.open().await.unwrap();
            writers.push(tokio::spawn(async move {
                for _ in 0..FRAMES {
                    stream.write_all(&[3; 1000]).await.unwrap();
                }
                stream
            }));
        }
        let ids = tokio::time::timeout(Duration::from_secs(10), psh_frames(&mut far, 2 * FRAMES))
            .await
            .expect("a stream starved");
        for id in [FIRST_STREAM_ID, FIRST_STREAM_ID + 2] {
            assert_eq!(ids.iter().filter(|&&sid| sid == id).count(), FRAMES);
        }
        let longest_run = ids.chunk_by(|a, b| a == b).map(<[u32]>::len).max().unwrap();
        assert!(
            longest_run <= 2,
            "one stream held the session for {longest_run} frames"
        );
        for writer in writers {
            writer.await.unwrap();
        }
    }

    #[tokio::test]
    async fn dropping_either_half_first_leaves_the_session_to_other_streams() {
        for read_first in [true, false] {
            let (near, far) = duplex(64 * 1024);
            let (mut far_read, mut far_write) = tokio::io::split(far);
            let session = SmuxSession::new(Box::new(near), &Default::default());
            let first = session.open().await.unwrap();
            let mut second = session.open().await.unwrap();
            assert_eq!(next_frame(&mut far_read).await, (CMD_SYN, FIRST_STREAM_ID));
            assert_eq!(
                next_frame(&mut far_read).await,
                (CMD_SYN, FIRST_STREAM_ID + 2)
            );
            let (read, write) = first.into_split();
            let rest: Box<dyn Send> = if read_first {
                drop(read);
                Box::new(write)
            } else {
                drop(write);
                Box::new(read)
            };
            let flood = usize::try_from(MAX_RECEIVE_BUFFER).unwrap() / MAX_FRAME + 8;
            tokio::time::timeout(Duration::from_secs(10), async {
                if !read_first {
                    assert_eq!(next_frame(&mut far_read).await, (CMD_FIN, FIRST_STREAM_ID));
                }
                let chunk = vec![7u8; MAX_FRAME];
                for _ in 0..flood {
                    far_write
                        .write_all(&frame(CMD_PSH, FIRST_STREAM_ID, &chunk))
                        .await
                        .unwrap();
                }
                far_write
                    .write_all(&frame(CMD_PSH, FIRST_STREAM_ID + 2, b"ok"))
                    .await
                    .unwrap();
                let mut got = [0u8; 2];
                second.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"ok");
                drop(rest);
                if read_first {
                    assert_eq!(next_frame(&mut far_read).await, (CMD_FIN, FIRST_STREAM_ID));
                }
            })
            .await
            .expect("a dropped half held the session up");
        }
    }
}
