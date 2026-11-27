use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream, Tasks};
use futures_util::future::BoxFuture;
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::PollSender;

use super::MuxSession;
use super::inbox::{Inbox, send_detached, write_frames};
use crate::http1::invalid;

const TYPE_DATA: u8 = 0;
const TYPE_WINDOW_UPDATE: u8 = 1;
const TYPE_PING: u8 = 2;
const TYPE_GO_AWAY: u8 = 3;
const FLAG_SYN: u16 = 1;
const FLAG_ACK: u16 = 2;
const FLAG_FIN: u16 = 4;
const FLAG_RST: u16 = 8;
const PEER_ASSUMED_WINDOW: u32 = 256 * 1024;
const RECV_WINDOW: u32 = 256 * 1024;
const MAX_MESSAGE: u32 = 64 * 1024 - 12;
const KEEPALIVE: Duration = Duration::from_secs(30);
const QUEUE: usize = 64;
/// metacubex/yamux's `AcceptBacklog`: a SYN past it is reset.
const ACCEPT_BACKLOG: usize = 256;
/// metacubex/yamux's `MaxIncomingStreams`: a SYN past this many open streams is reset.
const MAX_INCOMING_STREAMS: usize = 1000;
const GO_AWAY_PROTOCOL_ERROR: u32 = 1;

fn header(kind: u8, flags: u16, sid: u32, length: u32) -> Vec<u8> {
    let [f0, f1] = flags.to_be_bytes();
    let [s0, s1, s2, s3] = sid.to_be_bytes();
    let [l0, l1, l2, l3] = length.to_be_bytes();
    vec![0, kind, f0, f1, s0, s1, s2, s3, l0, l1, l2, l3]
}

#[derive(Default)]
struct Flow {
    credit: u32,
    buffered: u32,
    write_closed: bool,
    remote_fin: bool,
    reset: bool,
}

struct Entry {
    inbox: Inbox,
    send_window: AtomicU32,
    send_waker: AtomicWaker,
    flow: Mutex<Flow>,
}

struct Core {
    streams: Mutex<HashMap<u32, Arc<Entry>>>,
    next_id: AtomicU32,
    tx: mpsc::Sender<Vec<u8>>,
    closed: AtomicBool,
    received: AtomicU64,
    tasks: Tasks,
    /// Where a peer's SYN goes on a session that serves; None on one that only opens.
    accept: Mutex<Option<mpsc::Sender<BoxStream>>>,
}

impl Core {
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        lock(&self.accept).take();
        let streams = std::mem::take(&mut *lock(&self.streams));
        for entry in streams.values() {
            entry
                .inbox
                .fail(io::ErrorKind::BrokenPipe, "yamux session closed");
            lock(&entry.flow).reset = true;
            entry.send_waker.wake();
        }
    }

    fn remove(&self, sid: u32) {
        lock(&self.streams).remove(&sid);
    }

    /// Leaves a stream the peer has opened since under the same id.
    fn remove_own(&self, sid: u32, entry: &Arc<Entry>) {
        let mut streams = lock(&self.streams);
        if streams
            .get(&sid)
            .is_some_and(|held| Arc::ptr_eq(held, entry))
        {
            streams.remove(&sid);
        }
    }
}

pub(super) struct YamuxSession {
    core: Arc<Core>,
    tasks: Vec<JoinHandle<()>>,
}

impl YamuxSession {
    pub fn new(io: BoxStream, tasks: &Tasks) -> Self {
        Self::start(io, 1, None, tasks)
    }

    /// A session that takes the streams its peer opens, as `yamux.Server`; its own would
    /// be even.
    pub(super) fn server(io: BoxStream, tasks: &Tasks) -> (Self, mpsc::Receiver<BoxStream>) {
        let (accept, accepted) = mpsc::channel(ACCEPT_BACKLOG);
        (Self::start(io, 2, Some(accept), tasks), accepted)
    }

    fn start(
        io: BoxStream,
        first_id: u32,
        accept: Option<mpsc::Sender<BoxStream>>,
        tasks: &Tasks,
    ) -> Self {
        let (read, write) = Box::new(io).into_split();
        let (tx, rx) = mpsc::channel(QUEUE);
        let core = Arc::new(Core {
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(first_id),
            tx,
            closed: AtomicBool::new(false),
            received: AtomicU64::new(0),
            tasks: tasks.clone(),
            accept: Mutex::new(accept),
        });
        let reader = {
            let core = core.clone();
            tasks.spawn(async move {
                let _ = read_loop(&core, read).await;
                core.close();
            })
        };
        let writer = {
            let core = core.clone();
            tasks.spawn(async move {
                let _ = write_frames(write, rx).await;
                core.close();
            })
        };
        let keepalive = {
            let core = core.clone();
            tasks.spawn(async move { keepalive(&core).await })
        };
        YamuxSession {
            core,
            tasks: vec![reader, writer, keepalive],
        }
    }
}

async fn keepalive(core: &Core) {
    let mut last = core.received.load(Ordering::Relaxed);
    let mut pinged = false;
    loop {
        tokio::time::sleep(KEEPALIVE).await;
        let now = core.received.load(Ordering::Relaxed);
        if now != last {
            last = now;
            pinged = false;
            continue;
        }
        if pinged {
            core.close();
            return;
        }
        pinged = true;
        if core
            .tx
            .send(header(TYPE_PING, FLAG_SYN, 0, 1))
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn read_loop(core: &Arc<Core>, mut io: BoxRead) -> io::Result<()> {
    loop {
        let mut raw = [0u8; 12];
        io.read_exact(&mut raw).await?;
        core.received.fetch_add(1, Ordering::Relaxed);
        let [version, kind, f0, f1, s0, s1, s2, s3, l0, l1, l2, l3] = raw;
        if version != 0 {
            return Err(invalid("yamux: invalid protocol version"));
        }
        let flags = u16::from_be_bytes([f0, f1]);
        let sid = u32::from_be_bytes([s0, s1, s2, s3]);
        let length = u32::from_be_bytes([l0, l1, l2, l3]);
        match kind {
            TYPE_DATA | TYPE_WINDOW_UPDATE => {
                handle_stream(core, &mut io, kind, flags, sid, length).await?;
            }
            TYPE_PING => {
                if flags & FLAG_SYN != 0 {
                    let _ = core.tx.send(header(TYPE_PING, FLAG_ACK, 0, length)).await;
                }
            }
            TYPE_GO_AWAY => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("yamux: remote sent go away, code {length}"),
                ));
            }
            _ => return Err(invalid("yamux: invalid message type")),
        }
    }
}

async fn handle_stream(
    core: &Arc<Core>,
    io: &mut BoxRead,
    kind: u8,
    flags: u16,
    sid: u32,
    length: u32,
) -> io::Result<()> {
    if flags & FLAG_SYN != 0 {
        accept(core, sid).await?;
    }
    let entry = lock(&core.streams).get(&sid).cloned();
    let data_len = if kind == TYPE_DATA { length } else { 0 };
    let Some(entry) = entry else {
        return discard(io, data_len).await;
    };
    if flags & FLAG_FIN != 0 {
        let mut flow = lock(&entry.flow);
        flow.remote_fin = true;
        let finished = flow.write_closed;
        drop(flow);
        entry.inbox.fin();
        if finished {
            core.remove(sid);
        }
    }
    if flags & FLAG_RST != 0 {
        lock(&entry.flow).reset = true;
        entry
            .inbox
            .fail(io::ErrorKind::ConnectionReset, "yamux: stream reset");
        entry.send_waker.wake();
        core.remove(sid);
        return discard(io, data_len).await;
    }
    if kind == TYPE_WINDOW_UPDATE {
        entry.send_window.fetch_add(length, Ordering::Relaxed);
        entry.send_waker.wake();
        return Ok(());
    }
    if length == 0 {
        return Ok(());
    }
    {
        let mut flow = lock(&entry.flow);
        if length > flow.credit {
            return Err(invalid("yamux: receive window exceeded"));
        }
        flow.credit -= length;
        flow.buffered += length;
    }
    let mut payload = vec![0u8; usize::try_from(length).map_err(|_| invalid("yamux: length"))?];
    io.read_exact(&mut payload).await?;
    if !entry.inbox.push(Bytes::from(payload)) {
        return_credit(core, sid, &entry, payload_len(length));
    }
    Ok(())
}

/// A session that only opens resets the stream. One that serves takes it as metacubex/yamux's
/// `incomingStream` (`session.go:843-900`): a client's stream is odd, a duplicate ends the
/// session with a go away, and a SYN past [`MAX_INCOMING_STREAMS`] or the backlog is reset
/// without an acknowledgement, which `AcceptStream` sends once the stream is taken.
async fn accept(core: &Arc<Core>, sid: u32) -> io::Result<()> {
    let Some(accept) = lock(&core.accept).clone() else {
        return reset(core, sid).await;
    };
    if sid.is_multiple_of(2) {
        return Err(invalid("both yamux endpoints are clients"));
    }
    let entry = Arc::new(Entry {
        inbox: Inbox::default(),
        send_window: AtomicU32::new(PEER_ASSUMED_WINDOW),
        send_waker: AtomicWaker::new(),
        flow: Mutex::new(Flow {
            credit: RECV_WINDOW,
            ..Flow::default()
        }),
    });
    let admission = {
        let mut streams = lock(&core.streams);
        if streams.contains_key(&sid) {
            Admission::Duplicate
        } else if streams.len() >= MAX_INCOMING_STREAMS {
            // Every stream of a session that serves is one its peer opened.
            Admission::Full
        } else {
            streams.insert(sid, entry.clone());
            Admission::Taken
        }
    };
    match admission {
        Admission::Duplicate => {
            let away = header(TYPE_GO_AWAY, 0, 0, GO_AWAY_PROTOCOL_ERROR);
            let _ = core.tx.send(away).await;
            return Err(invalid("yamux: duplicate stream declared"));
        }
        Admission::Full => return reset(core, sid).await,
        Admission::Taken => {}
    }
    let Ok(taken) = accept.try_reserve() else {
        core.remove(sid);
        return reset(core, sid).await;
    };
    let ack = header(
        TYPE_WINDOW_UPDATE,
        FLAG_ACK,
        sid,
        RECV_WINDOW - PEER_ASSUMED_WINDOW,
    );
    let _ = core.tx.send(ack).await;
    taken.send(Box::new(YamuxStream::new(sid, core.clone(), entry)));
    Ok(())
}

enum Admission {
    Duplicate,
    Full,
    Taken,
}

async fn reset(core: &Core, sid: u32) -> io::Result<()> {
    let _ = core
        .tx
        .send(header(TYPE_WINDOW_UPDATE, FLAG_RST, sid, 0))
        .await;
    Ok(())
}

fn payload_len(length: u32) -> usize {
    usize::try_from(length).unwrap_or(usize::MAX)
}

/// Gives the peer back the window of `n` bytes the stream no longer holds, once enough is free.
fn return_credit(core: &Core, id: u32, entry: &Entry, n: usize) {
    let n = u32::try_from(n).unwrap_or(u32::MAX);
    let delta = {
        let mut flow = lock(&entry.flow);
        flow.buffered = flow.buffered.saturating_sub(n);
        if flow.reset || flow.remote_fin && flow.write_closed {
            return;
        }
        let window = flow.credit + flow.buffered;
        let delta = RECV_WINDOW.saturating_sub(window);
        if delta < RECV_WINDOW / 2 {
            return;
        }
        flow.credit += delta;
        delta
    };
    send_detached(
        &core.tasks,
        &core.tx,
        header(TYPE_WINDOW_UPDATE, 0, id, delta),
    );
}

async fn discard(io: &mut BoxRead, mut left: u32) -> io::Result<()> {
    let mut sink = [0u8; 4096];
    while left > 0 {
        let take = usize::try_from(left).unwrap_or(sink.len()).min(sink.len());
        let Some(window) = sink.get_mut(..take) else {
            return Err(invalid("yamux: discard window"));
        };
        io.read_exact(window).await?;
        left -= u32::try_from(take).unwrap_or(left);
    }
    Ok(())
}

impl Drop for YamuxSession {
    fn drop(&mut self) {
        self.core.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl MuxSession for YamuxSession {
    fn open(&self) -> BoxFuture<'_, io::Result<BoxStream>> {
        Box::pin(async move {
            if self.core.closed.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let id = self.core.next_id.fetch_add(2, Ordering::Relaxed);
            if id >= u32::MAX - 1 {
                return Err(io::Error::other("yamux: streams exhausted"));
            }
            let entry = Arc::new(Entry {
                inbox: Inbox::default(),
                send_window: AtomicU32::new(PEER_ASSUMED_WINDOW),
                send_waker: AtomicWaker::new(),
                flow: Mutex::new(Flow {
                    credit: RECV_WINDOW,
                    ..Flow::default()
                }),
            });
            lock(&self.core.streams).insert(id, entry.clone());
            let stream = YamuxStream::new(id, self.core.clone(), entry);
            self.core
                .tx
                .send(header(
                    TYPE_WINDOW_UPDATE,
                    FLAG_SYN,
                    id,
                    RECV_WINDOW - PEER_ASSUMED_WINDOW,
                ))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
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
    }
}

struct Shared {
    id: u32,
    core: Arc<Core>,
    entry: Arc<Entry>,
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.core.remove_own(self.id, &self.entry);
    }
}

struct YamuxRead {
    shared: Arc<Shared>,
}

struct YamuxWrite {
    shared: Arc<Shared>,
    sender: PollSender<Vec<u8>>,
}

struct YamuxStream {
    write: YamuxWrite,
    read: YamuxRead,
}

impl YamuxStream {
    fn new(id: u32, core: Arc<Core>, entry: Arc<Entry>) -> Self {
        let sender = PollSender::new(core.tx.clone());
        let shared = Arc::new(Shared { id, core, entry });
        YamuxStream {
            write: YamuxWrite {
                shared: shared.clone(),
                sender,
            },
            read: YamuxRead { shared },
        }
    }
}

impl AsyncRead for YamuxRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = ready!(this.shared.entry.inbox.poll_read(cx, buf))?;
        if n > 0 {
            let Shared { id, core, entry } = &*this.shared;
            return_credit(core, *id, entry, n);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for YamuxRead {
    fn drop(&mut self) {
        let Shared { id, core, entry } = &*self.shared;
        if !lock(&entry.flow).reset {
            let dropped = entry.inbox.close_read();
            if dropped > 0 {
                return_credit(core, *id, entry, dropped);
            }
        }
    }
}

impl AsyncWrite for YamuxWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Shared { id, entry, .. } = &*this.shared;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            {
                let flow = lock(&entry.flow);
                if flow.reset {
                    return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
                }
                if flow.write_closed {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
            let window = entry.send_window.load(Ordering::Relaxed);
            if window > 0 {
                let want = u32::try_from(data.len()).unwrap_or(u32::MAX);
                let take = window.min(MAX_MESSAGE).min(want);
                ready!(this.sender.poll_reserve(cx))
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                let n = usize::try_from(take).unwrap_or(0);
                let mut frame = header(TYPE_DATA, 0, *id, take);
                frame.extend_from_slice(data.get(..n).unwrap_or_default());
                this.sender
                    .send_item(frame)
                    .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                entry.send_window.fetch_sub(take, Ordering::Relaxed);
                return Poll::Ready(Ok(n));
            }
            entry.send_waker.register(cx.waker());
            if entry.send_window.load(Ordering::Relaxed) == 0 {
                let flow = lock(&entry.flow);
                if !flow.reset {
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Shared { id, core, entry } = &*this.shared;
        if lock(&entry.flow).write_closed {
            return Poll::Ready(Ok(()));
        }
        ready!(this.sender.poll_reserve(cx))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        this.sender
            .send_item(header(TYPE_WINDOW_UPDATE, FLAG_FIN, *id, 0))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let mut flow = lock(&entry.flow);
        flow.write_closed = true;
        if flow.remote_fin {
            drop(flow);
            core.remove_own(*id, entry);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for YamuxWrite {
    fn drop(&mut self) {
        let Shared { id, core, entry } = &*self.shared;
        let send_fin = {
            let mut flow = lock(&entry.flow);
            let send_fin = !flow.write_closed && !flow.reset;
            flow.write_closed = true;
            send_fin
        };
        if send_fin {
            send_detached(
                &core.tasks,
                &core.tx,
                header(TYPE_WINDOW_UPDATE, FLAG_FIN, *id, 0),
            );
        }
    }
}

impl AsyncRead for YamuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for YamuxStream {
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

impl Stream for YamuxStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let YamuxStream { write, read } = *self;
        (Box::new(read), Box::new(write))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    async fn next_header(far: &mut (impl AsyncRead + Unpin)) -> (u8, u16, u32, u32) {
        let mut h = [0u8; 12];
        far.read_exact(&mut h).await.unwrap();
        (
            h[1],
            u16::from_be_bytes([h[2], h[3]]),
            u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
            u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
        )
    }

    #[tokio::test]
    async fn a_dropped_read_half_still_gives_the_peer_its_window_back() {
        for data_first in [true, false] {
            let (near, far) = duplex(64 * 1024);
            let (mut far_read, mut far_write) = tokio::io::split(far);
            let session = YamuxSession::new(Box::new(near), &Default::default());
            let stream = session.open().await.unwrap();
            let (kind, flags, sid, _) = next_header(&mut far_read).await;
            assert_eq!((kind, flags), (TYPE_WINDOW_UPDATE, FLAG_SYN));
            let (read, _write) = stream.into_split();
            let mut wire = Vec::new();
            for _ in 0..RECV_WINDOW / (64 * 1024) {
                wire.extend(header(TYPE_DATA, 0, sid, 64 * 1024));
                wire.extend_from_slice(&[7u8; 64 * 1024]);
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                if data_first {
                    far_write.write_all(&wire).await.unwrap();
                    tokio::task::yield_now().await;
                    drop(read);
                } else {
                    drop(read);
                    far_write.write_all(&wire).await.unwrap();
                }
                let (kind, _, id, delta) = next_header(&mut far_read).await;
                assert_eq!((kind, id), (TYPE_WINDOW_UPDATE, sid));
                assert!(delta >= RECV_WINDOW / 2, "{delta}");
            })
            .await
            .expect("the peer's window stayed spent");
        }
    }

    fn syn(sid: u32) -> Vec<u8> {
        header(TYPE_WINDOW_UPDATE, FLAG_SYN, sid, 0)
    }

    #[tokio::test]
    async fn a_serving_session_resets_streams_past_the_incoming_limit() {
        let (near, far) = duplex(1 << 20);
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let (_session, mut accepted) = YamuxSession::server(Box::new(near), &Default::default());
        let held = Arc::new(Mutex::new(Vec::new()));
        tokio::spawn({
            let held = held.clone();
            async move {
                while let Some(stream) = accepted.recv().await {
                    lock(&held).push(stream);
                }
            }
        });
        let ids = (0..).map(|n: u32| 2 * n + 1);
        let mut wire = Vec::new();
        for sid in ids.clone().take(MAX_INCOMING_STREAMS + 1) {
            wire.extend(syn(sid));
        }
        far_write.write_all(&wire).await.unwrap();
        for sid in ids.clone().take(MAX_INCOMING_STREAMS) {
            assert_eq!(
                next_header(&mut far_read).await,
                (TYPE_WINDOW_UPDATE, FLAG_ACK, sid, 0)
            );
        }
        let over = 2 * u32::try_from(MAX_INCOMING_STREAMS).unwrap() + 1;
        assert_eq!(
            next_header(&mut far_read).await,
            (TYPE_WINDOW_UPDATE, FLAG_RST, over, 0)
        );
        drop(lock(&held).pop());
        far_write.write_all(&syn(over + 2)).await.unwrap();
        loop {
            let (kind, flags, sid, _) = next_header(&mut far_read).await;
            if sid == over + 2 {
                assert_eq!((kind, flags), (TYPE_WINDOW_UPDATE, FLAG_ACK));
                break;
            }
        }
    }

    #[tokio::test]
    async fn a_full_backlog_resets_a_stream_without_acknowledging_it() {
        let (near, far) = duplex(1 << 20);
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let (_session, _accepted) = YamuxSession::server(Box::new(near), &Default::default());
        let ids = (0..).map(|n: u32| 2 * n + 1);
        for sid in ids.clone().take(ACCEPT_BACKLOG + 1) {
            far_write.write_all(&syn(sid)).await.unwrap();
        }
        for sid in ids.clone().take(ACCEPT_BACKLOG) {
            assert_eq!(
                next_header(&mut far_read).await,
                (TYPE_WINDOW_UPDATE, FLAG_ACK, sid, 0)
            );
        }
        let over = 2 * u32::try_from(ACCEPT_BACKLOG).unwrap() + 1;
        assert_eq!(
            next_header(&mut far_read).await,
            (TYPE_WINDOW_UPDATE, FLAG_RST, over, 0)
        );
    }

    #[tokio::test]
    async fn a_duplicate_syn_ends_the_session_and_the_stream_it_named() {
        let (near, far) = duplex(1 << 16);
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let (_session, mut accepted) = YamuxSession::server(Box::new(near), &Default::default());
        far_write.write_all(&syn(1)).await.unwrap();
        next_header(&mut far_read).await;
        let mut stream = accepted.recv().await.unwrap();
        let reading = tokio::spawn(async move { stream.read(&mut [0u8; 1]).await });
        far_write.write_all(&syn(1)).await.unwrap();
        let away = tokio::time::timeout(Duration::from_secs(5), next_header(&mut far_read)).await;
        assert_eq!(
            away.expect("no go away"),
            (TYPE_GO_AWAY, 0, 0, GO_AWAY_PROTOCOL_ERROR)
        );
        let read = tokio::time::timeout(Duration::from_secs(5), reading)
            .await
            .expect("the first stream was left open")
            .unwrap();
        assert!(read.is_err(), "{read:?}");
    }

    #[tokio::test]
    async fn an_even_stream_from_the_client_ends_the_session() {
        let (near, far) = duplex(1 << 16);
        let (_far_read, mut far_write) = tokio::io::split(far);
        let (_session, mut accepted) = YamuxSession::server(Box::new(near), &Default::default());
        far_write.write_all(&syn(2)).await.unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), accepted.recv()).await;
        assert!(matches!(next, Ok(None)));
    }

    #[tokio::test]
    async fn a_stream_reset_and_opened_again_survives_the_old_one_dropping() {
        let (near, far) = duplex(1 << 16);
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let (_session, mut accepted) = YamuxSession::server(Box::new(near), &Default::default());
        far_write.write_all(&syn(1)).await.unwrap();
        next_header(&mut far_read).await;
        let old = accepted.recv().await.unwrap();
        far_write
            .write_all(&header(TYPE_WINDOW_UPDATE, FLAG_RST, 1, 0))
            .await
            .unwrap();
        far_write.write_all(&syn(1)).await.unwrap();
        let mut new = accepted.recv().await.unwrap();
        drop(old);
        let mut data = header(TYPE_DATA, 0, 1, 1);
        data.push(b'x');
        far_write.write_all(&data).await.unwrap();
        let mut got = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), new.read_exact(&mut got))
            .await
            .expect("the new stream lost its entry to the old one")
            .unwrap();
        assert_eq!(&got, b"x");
    }
}
