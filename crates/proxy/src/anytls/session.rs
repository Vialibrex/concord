use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use concord_common::stream_buffer::{ReadBufferOptions, StreamBuffer};
use concord_common::{BoxRead, BoxStream, Tasks};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::frame::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING, CMD_WASTE, Framer, HEADER, frame,
};
use super::padding::{Padding, parse_map};
use super::pool::Pool;
use super::writer::FrameWriter;
use crate::util::lock;

const OUT_QUEUE: usize = 1;
const CHUNK_QUEUE: usize = 1;
const SYNACK_DEADLINE: Duration = Duration::from_secs(3);

pub(super) enum Out {
    Data(Vec<u8>),
    Owned {
        frame: StreamBuffer,
        continued: bool,
    },
    // These follow the data batch, retaining its extra frame slots until
    // the writer drains it without enlarging every channel item.
    FrameSlot,
    Unbuffer,
}

pub(super) enum Chunk {
    Data(StreamBuffer),
    Fin,
    Error(String),
}

struct Entry {
    tx: mpsc::Sender<Chunk>,
    done: Arc<AtomicBool>,
    reads: Arc<OnceLock<ReadBufferOptions>>,
}

pub(super) struct Session {
    pub(super) seq: u64,
    out: mpsc::Sender<Out>,
    writer: Mutex<Option<FrameWriter>>,
    streams: Mutex<HashMap<u32, Entry>>,
    next_sid: AtomicU32,
    die: CancellationToken,
    peer_version: AtomicU8,
    pub(super) idle_since: Mutex<Instant>,
    synack_watch: Mutex<Option<JoinHandle<()>>>,
    pool: Weak<Pool>,
    padding: Arc<ArcSwap<Padding>>,
    tasks: Tasks,
}

impl Session {
    pub(super) fn start(
        conn: BoxStream,
        seq: u64,
        pool: &Arc<Pool>,
        padding: Arc<ArcSwap<Padding>>,
        client_metadata: &str,
    ) -> Arc<Session> {
        let (out, queue) = mpsc::channel(OUT_QUEUE);
        let (source, sink) = conn.into_split();
        let framer = Framer {
            buffering: true,
            buffer: Vec::new(),
            padding_on: true,
            counter: 0,
            padding: padding.clone(),
        };
        let session = Arc::new(Session {
            seq,
            out,
            writer: Mutex::new(None),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            die: pool.tasks.child_token(),
            peer_version: AtomicU8::new(0),
            idle_since: Mutex::new(Instant::now()),
            synack_watch: Mutex::new(None),
            pool: Arc::downgrade(pool),
            padding,
            tasks: pool.tasks.clone(),
        });
        let settings = format!(
            "v=2\nclient={client_metadata}\npadding-md5={}",
            session.padding.load().md5
        );
        session.queue(Out::Data(frame(CMD_SETTINGS, 0, settings.as_bytes())));
        pool.tasks.spawn(write_loop(
            session.clone(),
            queue,
            FrameWriter { sink, framer },
        ));
        pool.tasks.spawn(read_loop(session.clone(), source));
        session
    }

    pub(super) fn is_closed(&self) -> bool {
        self.die.is_cancelled()
    }

    pub(super) fn close(self: &Arc<Self>) {
        if self.die.is_cancelled() {
            return;
        }
        self.die.cancel();
        if let Some(watch) = lock(&self.synack_watch).take() {
            watch.abort();
        }
        lock(&self.streams).clear();
        if let Some(pool) = self.pool.upgrade() {
            pool.gone(self.seq);
        }
    }

    /// Queues without waiting; a full queue is retried from a task so that a
    /// drop never blocks.
    pub(super) fn queue(&self, out: Out) {
        if let Err(mpsc::error::TrySendError::Full(out)) = self.out.try_send(out) {
            let sender = self.out.clone();
            self.tasks.spawn_detached(async move {
                let _ = sender.send(out).await;
            });
        }
    }

    pub(super) fn try_write_owned(
        &self,
        cx: &mut Context<'_>,
        frame: &mut StreamBuffer,
    ) -> io::Result<bool> {
        if self.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Ok(mut slot) = self.writer.try_lock() else {
            return Ok(false);
        };
        match slot.as_mut() {
            Some(writer) => writer.try_owned(cx, frame),
            None => Ok(false),
        }
    }

    pub(super) fn sender(&self) -> mpsc::Sender<Out> {
        self.out.clone()
    }

    pub(super) async fn open_stream(self: &Arc<Self>) -> io::Result<super::stream::AnyTlsStream> {
        if self.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let sid = self.next_sid.fetch_add(1, Ordering::AcqRel) + 1;
        let (tx, rx) = mpsc::channel(CHUNK_QUEUE);
        let done = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(OnceLock::new());
        if sid >= 2 && self.peer_version.load(Ordering::Acquire) >= 2 {
            let session = self.clone();
            let watch = self.tasks.spawn(async move {
                tokio::time::sleep(SYNACK_DEADLINE).await;
                session.close();
            });
            if let Some(old) = lock(&self.synack_watch).replace(watch) {
                old.abort();
            }
        }
        lock(&self.streams).insert(
            sid,
            Entry {
                tx,
                done: done.clone(),
                reads: reads.clone(),
            },
        );
        let sent = async {
            self.out
                .send(Out::Data(frame(CMD_SYN, sid, &[])))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            self.out
                .send(Out::Unbuffer)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        };
        if let Err(err) = sent.await {
            lock(&self.streams).remove(&sid);
            return Err(err);
        }
        if self.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(super::stream::AnyTlsStream::new(
            sid,
            self.clone(),
            rx,
            done,
            reads,
        ))
    }

    /// Ends the local side of a stream: tells the server and returns the session to the pool.
    pub(super) fn finish_local(self: &Arc<Self>, sid: u32, done: &AtomicBool) {
        if done.swap(true, Ordering::AcqRel) {
            return;
        }
        lock(&self.streams).remove(&sid);
        self.queue(Out::Data(frame(CMD_FIN, sid, &[])));
        self.release();
    }

    fn release(self: &Arc<Self>) {
        if let Some(pool) = self.pool.upgrade() {
            pool.release(self);
        }
    }

    async fn finish_remote(self: &Arc<Self>, sid: u32, last: Chunk) {
        let entry = lock(&self.streams).remove(&sid);
        if let Some(entry) = entry {
            if !entry.done.swap(true, Ordering::AcqRel) {
                self.release();
            }
            let _ = entry.tx.send(last).await;
        }
    }

    /// Reads a data frame into a buffer with the room its stream's writer asked for, so the
    /// stream can hand the frame on whole.
    async fn push(&self, source: &mut BoxRead, sid: u32, len: usize) -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let target = lock(&self.streams)
            .get(&sid)
            .map(|entry| (entry.tx.clone(), entry.reads.get().copied()));
        let options = match target.as_ref().and_then(|(_, options)| *options) {
            Some(options) => options,
            None => ReadBufferOptions::for_copy(Default::default(), Default::default())?,
        };
        let mut buffer = options.take_for_read(len, 0)?;
        let payload = buffer
            .spare_mut()
            .get_mut(..len)
            .ok_or(io::ErrorKind::InvalidInput)?;
        source.read_exact(payload).await?;
        buffer.advance(len)?;
        if let Some((tx, _)) = target {
            let _ = tx.send(Chunk::Data(buffer)).await;
        }
        Ok(())
    }

    async fn dispatch(self: &Arc<Self>, source: &mut BoxRead) -> io::Result<()> {
        loop {
            let mut header = [0u8; HEADER];
            source.read_exact(&mut header).await?;
            let [cmd, a, b, c, d, hi, lo] = header;
            let sid = u32::from_be_bytes([a, b, c, d]);
            let len = usize::from(u16::from_be_bytes([hi, lo]));
            if cmd == CMD_PSH {
                self.push(source, sid, len).await?;
                continue;
            }
            let mut payload = vec![0u8; len];
            let has_payload = matches!(
                cmd,
                CMD_SYNACK
                    | CMD_WASTE
                    | CMD_SETTINGS
                    | CMD_ALERT
                    | CMD_UPDATE_PADDING
                    | CMD_SERVER_SETTINGS
            );
            if has_payload && len > 0 {
                source.read_exact(&mut payload).await?;
            } else {
                payload.clear();
            }
            match cmd {
                CMD_SYNACK => {
                    if let Some(watch) = lock(&self.synack_watch).take() {
                        watch.abort();
                    }
                    if !payload.is_empty() {
                        let message = String::from_utf8_lossy(&payload).into_owned();
                        self.finish_remote(sid, Chunk::Error(format!("remote: {message}")))
                            .await;
                        self.queue(Out::Data(frame(CMD_FIN, sid, &[])));
                    }
                }
                CMD_FIN => self.finish_remote(sid, Chunk::Fin).await,
                CMD_ALERT => {
                    if !payload.is_empty() {
                        tracing::debug!(
                            alert = %String::from_utf8_lossy(&payload),
                            "anytls: alert from server"
                        );
                        return Ok(());
                    }
                }
                CMD_UPDATE_PADDING if !payload.is_empty() => {
                    if let Some(scheme) = Padding::parse(&payload) {
                        self.padding.store(Arc::new(scheme));
                    }
                }
                CMD_HEART_REQUEST => self.queue(Out::Data(frame(CMD_HEART_RESPONSE, sid, &[]))),
                CMD_SERVER_SETTINGS if !payload.is_empty() => {
                    let settings = parse_map(&String::from_utf8_lossy(&payload));
                    if let Some(version) = settings.get("v").and_then(|v| v.parse::<u8>().ok()) {
                        self.peer_version.store(version, Ordering::Release);
                    }
                }
                _ => {}
            }
        }
    }
}

async fn read_loop(session: Arc<Session>, mut source: BoxRead) {
    tokio::select! {
        _ = session.die.cancelled() => {}
        _ = session.dispatch(&mut source) => {}
    }
    session.close();
}

async fn next_write(
    queue: &mut mpsc::Receiver<Out>,
    local: &mut Option<FrameWriter>,
    shared: &Mutex<Option<FrameWriter>>,
) -> Option<(Out, FrameWriter)> {
    if local.is_some() {
        let out = queue.recv().await?;
        return local.take().map(|writer| (out, writer));
    }
    poll_fn(|cx| {
        // Claim the shared writer before dequeue releases the FIFO slot.
        let mut slot = lock(shared);
        let out = ready!(queue.poll_recv(cx));
        Poll::Ready(out.and_then(|out| slot.take().map(|writer| (out, writer))))
    })
    .await
}

async fn write_loop(session: Arc<Session>, mut queue: mpsc::Receiver<Out>, writer: FrameWriter) {
    let mut local = Some(writer);
    let stopped_writer = loop {
        let next = tokio::select! {
            _ = session.die.cancelled() => None,
            next = next_write(&mut queue, &mut local, &session.writer) => next,
        };
        let Some((out, mut writer)) = next else {
            break local.or_else(|| lock(&session.writer).take());
        };
        let continued = matches!(
            out,
            Out::Owned {
                continued: true,
                ..
            }
        );
        if writer.send(out).await.is_err() {
            break Some(writer);
        }
        if continued && writer.framer.passes_through() {
            *lock(&session.writer) = Some(writer);
        } else {
            local = Some(writer);
        }
    };
    session.close();
    if let Some(mut writer) = stopped_writer {
        let _ = writer.sink.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anytls::frame::{MAX_FRAME, data_frames};

    fn queued_stream() -> (
        super::super::stream::AnyTlsStream,
        mpsc::Receiver<Out>,
        mpsc::Sender<Out>,
    ) {
        queued_stream_with(OUT_QUEUE)
    }

    fn queued_stream_with(
        capacity: usize,
    ) -> (
        super::super::stream::AnyTlsStream,
        mpsc::Receiver<Out>,
        mpsc::Sender<Out>,
    ) {
        let (out, queue) = mpsc::channel(capacity);
        let sender = out.clone();
        let session = Arc::new(Session {
            seq: 1,
            out,
            writer: Mutex::new(None),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(1),
            die: CancellationToken::new(),
            peer_version: AtomicU8::new(0),
            idle_since: Mutex::new(Instant::now()),
            synack_watch: Mutex::new(None),
            pool: Weak::new(),
            padding: Arc::new(ArcSwap::from_pointee(Padding::default_scheme())),
            tasks: Tasks::default(),
        });
        let (_, chunks) = mpsc::channel(1);
        let done = Arc::new(AtomicBool::new(false));
        (
            super::super::stream::AnyTlsStream::new(1, session, chunks, done, Default::default()),
            queue,
            sender,
        )
    }

    #[tokio::test]
    async fn a_coalesced_write_retains_the_frame_queue_budget() {
        use std::pin::Pin;
        use std::task::{Context, Waker};

        use tokio::io::AsyncWrite;

        const SLOTS: usize = 16;
        let (mut stream, mut queue, _) = queued_stream_with(SLOTS);
        let data = vec![0x5a; (SLOTS + 1) * MAX_FRAME];
        let accepted = stream.write(&data).await.unwrap();
        assert_eq!(accepted, SLOTS * MAX_FRAME);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut cx, b"cancelled")
                .is_pending()
        );
        let Some(Out::Data(bytes)) = queue.recv().await else {
            panic!("expected coalesced frames");
        };
        assert_eq!(bytes, data_frames(1, &data[..accepted]));
        for _ in 0..SLOTS - 1 {
            assert!(matches!(queue.recv().await, Some(Out::FrameSlot)));
        }
        assert!(queue.try_recv().is_err());
        stream.write_all(b"next").await.unwrap();
        let Some(Out::Data(bytes)) = queue.recv().await else {
            panic!("expected next write");
        };
        assert_eq!(bytes, frame(CMD_PSH, 1, b"next"));
    }

    #[tokio::test]
    async fn a_coalesced_write_uses_only_free_frame_slots() {
        const SLOTS: usize = 16;
        let (mut stream, mut queue, sender) = queued_stream_with(SLOTS);
        for _ in 0..SLOTS - 2 {
            assert!(
                sender
                    .try_send(Out::Data(frame(CMD_HEART_RESPONSE, 0, &[])))
                    .is_ok()
            );
        }
        let data = vec![0x5a; 3 * MAX_FRAME];
        assert_eq!(stream.write(&data).await.unwrap(), 2 * MAX_FRAME);
        assert_eq!(sender.capacity(), 0);
        for _ in 0..SLOTS - 2 {
            let Some(Out::Data(bytes)) = queue.recv().await else {
                panic!("expected earlier control frame");
            };
            assert_eq!(bytes, frame(CMD_HEART_RESPONSE, 0, &[]));
        }
        let Some(Out::Data(bytes)) = queue.recv().await else {
            panic!("expected coalesced frames");
        };
        assert_eq!(bytes, data_frames(1, &data[..2 * MAX_FRAME]));
        assert_eq!(sender.capacity(), SLOTS - 1);
        assert!(matches!(queue.recv().await, Some(Out::FrameSlot)));
        assert_eq!(sender.capacity(), SLOTS);
    }

    fn relay_buffer(front: usize, payload: &[u8]) -> StreamBuffer {
        use concord_common::stream_buffer::{BufferRequirements, ReadBufferOptions};

        let writer = BufferRequirements {
            front,
            ..Default::default()
        };
        let mut buffer = ReadBufferOptions::for_copy(Default::default(), writer)
            .unwrap()
            .take_for_read(payload.len(), 0)
            .unwrap();
        buffer.spare_mut()[..payload.len()].copy_from_slice(payload);
        buffer.advance(payload.len()).unwrap();
        buffer
    }

    async fn write_buffer(
        stream: &mut super::super::stream::AnyTlsStream,
        buffer: &mut StreamBuffer,
    ) -> io::Result<usize> {
        use concord_common::Stream;

        std::future::poll_fn(|cx| stream.poll_write_buffer(cx, buffer)).await
    }

    #[tokio::test]
    async fn an_owned_write_frames_the_relay_buffer_in_place() {
        use concord_common::Stream;

        let (mut stream, mut queue, _) = queued_stream();
        let requirements = stream.write_requirements();
        assert_eq!((requirements.mtu, requirements.front), (MAX_FRAME, HEADER));
        let payload = vec![0x5a; 100];
        let mut buffer = relay_buffer(requirements.front, &payload);
        let start = buffer.as_slice().as_ptr();
        assert_eq!(write_buffer(&mut stream, &mut buffer).await.unwrap(), 100);
        assert!(buffer.is_empty());
        let Some(Out::Owned {
            frame: owned,
            continued: false,
        }) = queue.recv().await
        else {
            panic!("expected the relay's buffer");
        };
        assert_eq!(owned.as_slice(), frame(CMD_PSH, 1, &payload));
        assert_eq!(owned.as_slice().as_ptr(), start.wrapping_sub(HEADER));
    }

    #[tokio::test]
    async fn a_buffer_without_header_room_or_over_a_frame_is_copied() {
        let (mut stream, mut queue, _) = queued_stream_with(2);
        let payload = vec![0x5a; 100];
        let mut buffer = relay_buffer(0, &payload);
        assert_eq!(write_buffer(&mut stream, &mut buffer).await.unwrap(), 100);
        let Some(Out::Data(bytes)) = queue.recv().await else {
            panic!("expected a copied frame");
        };
        assert_eq!(bytes, frame(CMD_PSH, 1, &payload));

        let payload = vec![0x5b; MAX_FRAME + 1];
        let mut buffer = relay_buffer(HEADER, &payload);
        assert_eq!(
            write_buffer(&mut stream, &mut buffer).await.unwrap(),
            MAX_FRAME + 1
        );
        let Some(Out::Data(bytes)) = queue.recv().await else {
            panic!("expected copied frames");
        };
        assert_eq!(bytes, data_frames(1, &payload));
    }

    #[tokio::test]
    async fn a_full_queue_keeps_the_owned_buffer_until_a_slot_frees() {
        use std::task::{Context, Waker};

        use concord_common::Stream;

        let (mut stream, mut queue, sender) = queued_stream();
        for _ in 0..OUT_QUEUE {
            assert!(
                sender
                    .try_send(Out::Data(frame(CMD_HEART_RESPONSE, 0, &[])))
                    .is_ok()
            );
        }
        let payload = vec![0x5a; 100];
        let mut buffer = relay_buffer(HEADER, &payload);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(stream.poll_write_buffer(&mut cx, &mut buffer).is_pending());
        assert_eq!(
            (buffer.as_slice(), buffer.headroom()),
            (&payload[..], HEADER)
        );
        assert!(matches!(queue.recv().await, Some(Out::Data(_))));
        assert_eq!(write_buffer(&mut stream, &mut buffer).await.unwrap(), 100);
        assert_eq!(sender.capacity(), 0);
    }

    #[tokio::test]
    async fn an_idle_owned_write_uses_the_slot_and_queues_only_its_unwritten_tail() {
        use concord_common::Stream;
        use std::task::Waker;

        let (near, mut far) = tokio::io::duplex(16);
        let pool = Pool::new(false, 0, Tasks::default());
        let padding = Arc::new(ArcSwap::from_pointee(Padding::parse(b"stop=0").unwrap()));
        let session = Session::start(Box::new(near), 1, &pool, padding, "");
        let mut stream = session.open_stream().await.unwrap();
        stream.write_all(b"start").await.unwrap();
        assert_eq!(read_frame(&mut far).await.0, CMD_SETTINGS);
        assert_eq!(read_frame(&mut far).await.0, CMD_SYN);
        assert_eq!(read_frame(&mut far).await.2, b"start");

        for (payload, shared) in [(b"start".as_slice(), false), (b"next", true)] {
            let mut frame = relay_buffer(HEADER, payload);
            assert_eq!(
                write_buffer(&mut stream, &mut frame).await.unwrap(),
                payload.len()
            );
            assert_eq!(session.out.capacity(), 0);
            assert_eq!(read_frame(&mut far).await, (CMD_PSH, 1, payload.to_vec()));
            assert_eq!(lock(&session.writer).is_some(), shared);
        }
        let mut input = [0; 1];
        let mut read = tokio::io::ReadBuf::new(&mut input);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut stream), &mut cx, &mut read)
                .is_pending()
        );

        let mut short = relay_buffer(HEADER, b"a");
        assert_eq!(write_buffer(&mut stream, &mut short).await.unwrap(), 1);
        assert_eq!(session.out.capacity(), OUT_QUEUE);
        assert_eq!(read_frame(&mut far).await, (CMD_PSH, 1, b"a".to_vec()));

        let payload = [0x3c; 42];
        let mut long = relay_buffer(HEADER, &payload);
        assert_eq!(
            write_buffer(&mut stream, &mut long).await.unwrap(),
            payload.len()
        );
        assert_eq!(session.out.capacity(), 0);
        let mut next = relay_buffer(HEADER, b"next");
        let mut cx = Context::from_waker(Waker::noop());
        assert!(stream.poll_write_buffer(&mut cx, &mut next).is_pending());
        assert_eq!(next.as_slice(), b"next");

        let (sent, (first, second)) = tokio::join!(write_buffer(&mut stream, &mut next), async {
            (read_frame(&mut far).await, read_frame(&mut far).await)
        });
        assert_eq!(sent.unwrap(), 4);
        assert_eq!(first, (CMD_PSH, 1, payload.to_vec()));
        assert_eq!(second, (CMD_PSH, 1, b"next".to_vec()));

        far.write_all(&frame(CMD_PSH, 1, b"r")).await.unwrap();
        stream.read_exact(&mut input).await.unwrap();
        assert_eq!(input, *b"r");
        let mut reply = relay_buffer(HEADER, b"reply");
        assert_eq!(write_buffer(&mut stream, &mut reply).await.unwrap(), 5);
        assert_eq!(session.out.capacity(), 0);
        assert_eq!(read_frame(&mut far).await, (CMD_PSH, 1, b"reply".to_vec()));
        assert!(lock(&session.writer).is_none());
        let mut resume = relay_buffer(HEADER, b"resume");
        assert_eq!(write_buffer(&mut stream, &mut resume).await.unwrap(), 6);
        assert_eq!(read_frame(&mut far).await, (CMD_PSH, 1, b"resume".to_vec()));
        assert!(lock(&session.writer).is_some());

        let mut final_frame = relay_buffer(HEADER, &payload);
        assert_eq!(
            write_buffer(&mut stream, &mut final_frame).await.unwrap(),
            payload.len()
        );
        drop(stream);
        assert_eq!(read_frame(&mut far).await, (CMD_PSH, 1, payload.to_vec()));
        assert_eq!(read_frame(&mut far).await, (CMD_FIN, 1, Vec::new()));
        session.close();
    }

    #[tokio::test]
    async fn the_writer_finishes_an_accepted_frame_whose_flush_was_pending() {
        use std::task::Waker;
        use tokio::io::BufWriter;

        let (near, mut far) = tokio::io::duplex(3);
        let mut writer = FrameWriter {
            sink: Box::new(BufWriter::with_capacity(64, near)),
            framer: Framer {
                buffering: false,
                buffer: Vec::new(),
                padding_on: false,
                counter: 0,
                padding: Arc::new(ArcSwap::from_pointee(Padding::default_scheme())),
            },
        };
        let mut frame = relay_buffer(0, b"complete");
        let mut cx = Context::from_waker(Waker::noop());
        assert!(!writer.try_owned(&mut cx, &mut frame).unwrap());
        assert!(frame.is_empty());
        let mut received = [0; 8];
        let (sent, read) = tokio::join!(
            writer.send(Out::Owned {
                frame,
                continued: true
            }),
            far.read_exact(&mut received)
        );
        sent.unwrap();
        read.unwrap();
        assert_eq!(&received, b"complete");
    }

    async fn wire_frames(scheme: &str, writes: &[(bool, Vec<u8>)]) -> Vec<(u8, u32, Vec<u8>)> {
        let (near, mut far) = tokio::io::duplex(1 << 20);
        let pool = Pool::new(false, 0, Tasks::default());
        let padding = Arc::new(ArcSwap::from_pointee(
            Padding::parse(scheme.as_bytes()).unwrap(),
        ));
        let session = Session::start(Box::new(near), 1, &pool, padding, "");
        let mut stream = session.open_stream().await.unwrap();
        for (owned, payload) in writes {
            if *owned {
                let mut buffer = relay_buffer(HEADER, payload);
                write_buffer(&mut stream, &mut buffer).await.unwrap();
            } else {
                stream.write_all(payload).await.unwrap();
            }
        }
        let total: usize = writes.iter().map(|(_, payload)| payload.len()).sum();
        let mut frames = Vec::new();
        let mut data = 0;
        while data < total {
            let frame = read_frame(&mut far).await;
            if frame.0 == CMD_PSH {
                data += frame.2.len();
            }
            frames.push(frame);
        }
        session.close();
        frames
    }

    #[tokio::test]
    async fn owned_and_copied_writes_put_the_same_frames_on_the_wire() {
        let payloads: Vec<Vec<u8>> = [10, 300, 32761, 5, 32761, 64]
            .iter()
            .enumerate()
            .map(|(index, &len)| vec![index as u8 + 1; len])
            .collect();
        for scheme in ["stop=0", "stop=4\n1=40-40\n2=100-100,c,200-200\n3=500-500"] {
            let copied: Vec<_> = payloads.iter().map(|p| (false, p.clone())).collect();
            let mixed: Vec<_> = payloads
                .iter()
                .enumerate()
                .map(|(index, p)| (index % 2 == 0, p.clone()))
                .collect();
            let owned: Vec<_> = payloads.iter().map(|p| (true, p.clone())).collect();
            let expected = wire_frames(scheme, &copied).await;
            assert_eq!(wire_frames(scheme, &mixed).await, expected, "{scheme}");
            assert_eq!(wire_frames(scheme, &owned).await, expected, "{scheme}");
        }
    }

    async fn read_frame(far: &mut tokio::io::DuplexStream) -> (u8, u32, Vec<u8>) {
        let mut header = [0u8; HEADER];
        far.read_exact(&mut header).await.unwrap();
        let [cmd, a, b, c, d, hi, lo] = header;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes([hi, lo]))];
        far.read_exact(&mut body).await.unwrap();
        (cmd, u32::from_be_bytes([a, b, c, d]), body)
    }

    #[tokio::test]
    async fn a_stream_opens_with_settings_syn_and_data_then_reuses_the_session() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let pool = Pool::new(false, 0, Tasks::default());
        let padding = Arc::new(ArcSwap::from_pointee(Padding::parse(b"stop=0").unwrap()));
        let session = Session::start(Box::new(near), 1, &pool, padding, "meta");
        assert!(pool.register(session.clone(), pool.ticket()));
        let mut stream = session.open_stream().await.unwrap();
        stream.write_all(b"hello").await.unwrap();

        let (cmd, sid, body) = read_frame(&mut far).await;
        assert_eq!((cmd, sid), (CMD_SETTINGS, 0));
        let settings = String::from_utf8(body).unwrap();
        assert!(settings.starts_with("v=2\nclient=meta\npadding-md5="));
        assert_eq!(read_frame(&mut far).await, (CMD_SYN, 1, Vec::new()));
        assert_eq!(read_frame(&mut far).await, (CMD_PSH, 1, b"hello".to_vec()));

        far.write_all(&frame(CMD_SERVER_SETTINGS, 0, b"v=2"))
            .await
            .unwrap();
        far.write_all(&frame(CMD_PSH, 1, b"world")).await.unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"world");

        far.write_all(&frame(CMD_FIN, 1, &[])).await.unwrap();
        assert_eq!(stream.read(&mut got).await.unwrap(), 0);
        drop(stream);
        assert_eq!(pool.take_idle().map(|idle| idle.seq), Some(1));
    }

    async fn read_buffer(
        stream: &mut super::super::stream::AnyTlsStream,
        options: ReadBufferOptions,
    ) -> StreamBuffer {
        use concord_common::Stream;

        poll_fn(|cx| stream.poll_read_buffer(cx, options))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_data_frame_reaches_the_relay_in_the_buffer_it_was_read_into() {
        use concord_common::Stream;
        use concord_common::stream_buffer::BufferRequirements;
        use std::task::Waker;

        let (near, mut far) = tokio::io::duplex(1 << 17);
        let pool = Pool::new(false, 0, Tasks::default());
        let padding = Arc::new(ArcSwap::from_pointee(Padding::parse(b"stop=0").unwrap()));
        let session = Session::start(Box::new(near), 1, &pool, padding, "");
        let mut stream = session.open_stream().await.unwrap();
        let early: Vec<u8> = (0..MAX_FRAME).map(|i| i.to_le_bytes()[1]).collect();
        far.write_all(&frame(CMD_PSH, 1, &early)).await.unwrap();
        let writer = BufferRequirements {
            front: 16,
            rear: 4,
            ..Default::default()
        };
        let options = ReadBufferOptions::for_copy(stream.read_requirements(), writer).unwrap();

        let mut copied = vec![0];
        stream.read_exact(&mut copied).await.unwrap();
        while copied.len() < early.len() {
            let buffer = read_buffer(&mut stream, options).await;
            assert!(buffer.len() < MAX_FRAME);
            assert!(options.fits(&buffer));
            copied.extend_from_slice(buffer.as_slice());
        }
        assert_eq!(copied, early);

        let mut cx = Context::from_waker(Waker::noop());
        assert!(stream.poll_read_buffer(&mut cx, options).is_pending());
        let late: Vec<u8> = early.iter().rev().copied().collect();
        far.write_all(&frame(CMD_PSH, 1, &late)).await.unwrap();
        let handed = read_buffer(&mut stream, options).await;
        assert_eq!(handed.as_slice(), late);
        assert_eq!((handed.headroom(), handed.tailroom()), (16, 4));
        session.close();
    }

    #[tokio::test]
    async fn large_stream_writes_preserve_payload_across_frame_boundaries() {
        for size in [
            65529,
            65530,
            65535,
            65536,
            131072,
            (OUT_QUEUE + 1) * MAX_FRAME + 37,
        ] {
            let (near, mut far) = tokio::io::duplex(1024);
            let pool = Pool::new(false, 0, Tasks::default());
            let padding = Arc::new(ArcSwap::from_pointee(Padding::parse(b"stop=0").unwrap()));
            let session = Session::start(Box::new(near), 1, &pool, padding, "");
            assert!(pool.register(session.clone(), pool.ticket()));
            let mut stream = session.open_stream().await.unwrap();
            let data: Vec<u8> = (0..size).map(|i| i.to_le_bytes()[0]).collect();
            tokio::join!(
                async {
                    stream.write_all(&data).await.unwrap();
                },
                async {
                    let (cmd, sid, _) = read_frame(&mut far).await;
                    assert_eq!((cmd, sid), (CMD_SETTINGS, 0));
                    assert_eq!(read_frame(&mut far).await, (CMD_SYN, 1, Vec::new()));
                    let mut got = Vec::new();
                    while got.len() < data.len() {
                        let (cmd, sid, body) = read_frame(&mut far).await;
                        assert_eq!((cmd, sid), (CMD_PSH, 1));
                        assert_eq!(body.len(), (data.len() - got.len()).min(MAX_FRAME));
                        got.extend_from_slice(&body);
                    }
                    assert_eq!(got, data);
                }
            );
            session.close();
        }
    }

    #[tokio::test]
    async fn the_halves_work_at_once_and_the_stream_ends_with_the_last_one() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let pool = Pool::new(false, 0, Tasks::default());
        let padding = Arc::new(ArcSwap::from_pointee(Padding::parse(b"stop=0").unwrap()));
        let session = Session::start(Box::new(near), 1, &pool, padding, "meta");
        assert!(pool.register(session.clone(), pool.ticket()));
        let stream: BoxStream = Box::new(session.open_stream().await.unwrap());
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = [0u8; 5];
            read.read_exact(&mut got).await.unwrap();
            (got, read)
        });
        write.write_all(b"hello").await.unwrap();
        for expected in [CMD_SETTINGS, CMD_SYN] {
            assert_eq!(read_frame(&mut far).await.0, expected);
        }
        assert_eq!(read_frame(&mut far).await, (CMD_PSH, 1, b"hello".to_vec()));
        far.write_all(&frame(CMD_SERVER_SETTINGS, 0, b"v=2"))
            .await
            .unwrap();
        far.write_all(&frame(CMD_PSH, 1, b"world")).await.unwrap();
        let (got, read) = reader.await.unwrap();
        assert_eq!(&got, b"world");
        drop(write);
        assert!(pool.take_idle().is_none());
        drop(read);
        assert_eq!(read_frame(&mut far).await, (CMD_FIN, 1, Vec::new()));
        assert_eq!(pool.take_idle().map(|idle| idle.seq), Some(1));
    }

    #[tokio::test]
    async fn a_refused_stream_reports_the_servers_message() {
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let pool = Pool::new(false, 0, Tasks::default());
        let padding = Arc::new(ArcSwap::from_pointee(Padding::default_scheme()));
        let session = Session::start(Box::new(near), 1, &pool, padding, "");
        let mut stream = session.open_stream().await.unwrap();
        far.write_all(&frame(CMD_SYNACK, 1, b"dial failed"))
            .await
            .unwrap();
        let err = stream.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.to_string(), "remote: dial failed");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(matches!(
            concord_common::CoreError::of(&err),
            Some(concord_common::CoreError::TargetRefused(_))
        ));
    }

    #[tokio::test]
    async fn a_closed_connection_ends_the_session_and_its_streams() {
        let (near, far) = tokio::io::duplex(1 << 16);
        let pool = Pool::new(false, 0, Tasks::default());
        let padding = Arc::new(ArcSwap::from_pointee(Padding::default_scheme()));
        let session = Session::start(Box::new(near), 1, &pool, padding, "");
        let mut stream = session.open_stream().await.unwrap();
        drop(far);
        assert!(stream.read(&mut [0u8; 4]).await.is_err());
        assert!(session.is_closed());
    }
}
