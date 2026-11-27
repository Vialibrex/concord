use std::io::{self, IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker, ready};

use concord_common::sync::lock;
use concord_common::{Attached, DirectIo, OwnedTcp};
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::attach::{Handle, PendingAttachment, Socket};
use crate::buffer::{ByteQueue, ChunkPool};

/// Below this much freed receive space the application's reads do not wake the engine; the
/// next segment's ACK carries the window anyway.
const WINDOW_NOTIFY: usize = 16 * 1024;
const DIRECT_SLICES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ConnId {
    pub index: u32,
    pub generation: u32,
}

/// Connections whose application side did something the engine has to act on.
#[derive(Default)]
pub(crate) struct Notifier {
    dirty: Mutex<Vec<ConnId>>,
    waker: AtomicWaker,
}

impl Notifier {
    pub fn push(&self, id: ConnId) {
        lock(&self.dirty).push(id);
        self.waker.wake();
    }

    pub fn register(&self, waker: &Waker) {
        self.waker.register(waker);
    }

    pub fn take(&self, out: &mut Vec<ConnId>) {
        let mut dirty = lock(&self.dirty);
        std::mem::swap(&mut *dirty, out);
    }
}

#[derive(Default)]
pub(crate) struct SharedState {
    /// Bytes from `snd_una` on: sent and unacknowledged, then not yet sent.
    pub send: ByteQueue,
    pub send_cap: usize,
    /// Leading bytes of `send` that have gone out at least once.
    pub transmitted: usize,
    pub write_closed: bool,
    /// In-order bytes the application has not read.
    pub recv: ByteQueue,
    pub recv_eof: bool,
    pub error: Option<io::ErrorKind>,
    pub dropped: bool,
    pub established: bool,
    /// A socket handed over by the application, waiting for the engine to take it.
    pub attach: Option<Box<PendingAttachment>>,
    pub passthrough: Option<Arc<Socket>>,
    pub passed: u64,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    unannounced_read: usize,
}

/// Bytes taken ahead of what the connection sends: more would only wait in memory and
/// leave the cache before going out.
const UNSENT_LIMIT: usize = 512 * 1024;

impl SharedState {
    pub fn send_room(&self) -> usize {
        let unsent = self.send.len().saturating_sub(self.transmitted);
        self.send_cap
            .saturating_sub(self.send.len())
            .min(UNSENT_LIMIT.saturating_sub(unsent))
    }

    pub fn wake_reader(&mut self) -> Option<Waker> {
        self.read_waker.take()
    }

    pub fn wake_writer(&mut self) -> Option<Waker> {
        self.write_waker.take()
    }

    pub fn fail(&mut self, kind: io::ErrorKind) -> [Option<Waker>; 2] {
        if self.error.is_none() {
            self.error = Some(kind);
        }
        [self.read_waker.take(), self.write_waker.take()]
    }
}

pub(crate) struct Shared {
    state: Mutex<SharedState>,
    queued: AtomicBool,
    pub id: ConnId,
    notifier: Arc<Notifier>,
    pub pool: Arc<ChunkPool>,
}

impl Shared {
    pub fn new(id: ConnId, notifier: Arc<Notifier>, pool: Arc<ChunkPool>, send_cap: usize) -> Self {
        Shared {
            state: Mutex::new(SharedState {
                send_cap,
                ..SharedState::default()
            }),
            queued: AtomicBool::new(false),
            id,
            notifier,
            pool,
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, SharedState> {
        lock(&self.state)
    }

    pub(crate) fn notify(&self) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            self.notifier.push(self.id);
        }
    }

    /// Called by the engine when it takes the connection off the dirty list.
    pub fn clear_queued(&self) {
        self.queued.store(false, Ordering::Release);
    }
}

/// Marks the connection dropped when the last holder of the application's end goes away.
struct Closing(Arc<Shared>);

impl Drop for Closing {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.dropped = true;
        state.write_closed = true;
        state.read_waker = None;
        state.write_waker = None;
        drop(state);
        self.0.notify();
    }
}

/// The application's end of a TCP connection terminated by the stack.
pub struct NetStream {
    closing: Closing,
    local: SocketAddr,
    remote: SocketAddr,
}

impl NetStream {
    pub(crate) fn new(shared: Arc<Shared>, local: SocketAddr, remote: SocketAddr) -> Self {
        NetStream {
            closing: Closing(shared),
            local,
            remote,
        }
    }

    fn shared(&self) -> &Arc<Shared> {
        &self.closing.0
    }

    /// Ready once the handshake of a connection from `TcpStack::connect` completes, or with
    /// the error that ended it first.
    pub fn poll_established(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.shared().lock();
        if let Some(kind) = state.error {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        if state.established {
            return Poll::Ready(Ok(()));
        }
        if state.recv_eof {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionRefused)));
        }
        state.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// The address the stack answers as: the destination the peer connected to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }

    /// A reader and a writer on the same connection. The connection counts as dropped, and
    /// its write side as closed, once both are gone.
    pub fn into_split(self) -> (NetReadHalf, NetWriteHalf) {
        let closing = Arc::new(self.closing);
        (
            NetReadHalf {
                closing: closing.clone(),
            },
            NetWriteHalf { closing },
        )
    }
}

fn poll_read_from(
    shared: &Shared,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    let mut state = shared.lock();
    if state.recv.is_empty() {
        if let Some(kind) = state.error {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        if state.recv_eof {
            return Poll::Ready(Ok(()));
        }
        state.read_waker = Some(cx.waker().clone());
        return Poll::Pending;
    }
    let n = state.recv.read(&shared.pool, buf.initialize_unfilled());
    buf.advance(n);
    state.unannounced_read += n;
    let notify = state.unannounced_read >= WINDOW_NOTIFY || state.recv.is_empty();
    if notify {
        state.unannounced_read = 0;
    }
    drop(state);
    if notify {
        shared.notify();
    }
    Poll::Ready(Ok(()))
}

fn poll_write_to(shared: &Shared, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
    let mut state = shared.lock();
    if let Some(kind) = state.error {
        return Poll::Ready(Err(io::Error::from(kind)));
    }
    if state.write_closed {
        return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
    }
    let room = state.send_room();
    if room == 0 {
        state.write_waker = Some(cx.waker().clone());
        return Poll::Pending;
    }
    let n = room.min(data.len());
    if let Some(take) = data.get(..n) {
        state.send.push(&shared.pool, take);
    }
    drop(state);
    shared.notify();
    Poll::Ready(Ok(n))
}

fn close_write(shared: &Shared) {
    let mut state = shared.lock();
    if !state.write_closed {
        state.write_closed = true;
        drop(state);
        shared.notify();
    }
}

impl AsyncRead for NetStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_read_from(self.shared(), cx, buf)
    }
}

impl AsyncWrite for NetStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        poll_write_to(self.shared(), cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        close_write(self.shared());
        Poll::Ready(Ok(()))
    }
}

/// The receiving half of a split [`NetStream`].
pub struct NetReadHalf {
    closing: Arc<Closing>,
}

impl AsyncRead for NetReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        poll_read_from(&self.closing.0, cx, buf)
    }
}

/// The sending half of a split [`NetStream`].
pub struct NetWriteHalf {
    closing: Arc<Closing>,
}

impl AsyncWrite for NetWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        poll_write_to(&self.closing.0, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        close_write(&self.closing.0);
        Poll::Ready(Ok(()))
    }
}

impl concord_common::Stream for NetStream {
    concord_common::stream_policy!(own: direct, into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, into_tcp);

    fn direct(&mut self) -> Option<&mut dyn DirectIo> {
        Some(self)
    }

    fn into_split(self: Box<Self>) -> (concord_common::BoxRead, concord_common::BoxWrite) {
        let (read, write) = NetStream::into_split(*self);
        (Box::new(read), Box::new(write))
    }
}

impl DirectIo for NetStream {
    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        socket: &TcpStream,
    ) -> Poll<io::Result<usize>> {
        let shared = &self.closing.0;
        let mut state = shared.lock();
        if state.recv.is_empty() {
            if let Some(kind) = state.error {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            if state.recv_eof {
                return Poll::Ready(Ok(0));
            }
            state.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let written = loop {
            ready!(socket.poll_write_ready(cx))?;
            let mut slices = [IoSlice::new(&[]); DIRECT_SLICES];
            let count = state.recv.front_slices(&mut slices);
            match socket.try_write_vectored(slices.get(..count).unwrap_or_default()) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                result => break result?,
            }
        };
        state.recv.consume(&shared.pool, written);
        state.unannounced_read += written;
        let notify = state.unannounced_read >= WINDOW_NOTIFY || state.recv.is_empty();
        if notify {
            state.unannounced_read = 0;
        }
        drop(state);
        if notify {
            shared.notify();
        }
        Poll::Ready(Ok(written))
    }

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        socket: &TcpStream,
    ) -> Poll<io::Result<usize>> {
        let shared = &self.closing.0;
        let mut state = shared.lock();
        if let Some(kind) = state.error {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        if state.write_closed {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        let room = state.send_room();
        if room == 0 {
            state.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let read = loop {
            ready!(socket.poll_read_ready(cx))?;
            let mut slices: [IoSliceMut<'_>; DIRECT_SLICES] =
                std::array::from_fn(|_| IoSliceMut::new(&mut []));
            let count = state.send.spare_slices(&shared.pool, room, &mut slices);
            let result = socket.try_read_vectored(slices.get_mut(..count).unwrap_or_default());
            match result {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    state.send.trim(&shared.pool);
                    continue;
                }
                Err(err) => {
                    state.send.trim(&shared.pool);
                    return Poll::Ready(Err(err));
                }
                Ok(n) => break n,
            }
        };
        state.send.commit(&shared.pool, read);
        drop(state);
        if read > 0 {
            shared.notify();
        }
        Poll::Ready(Ok(read))
    }

    fn attach_owned(&mut self, socket: &mut Option<OwnedTcp>) -> Option<Box<dyn Attached>> {
        let shared = self.shared();
        let mut state = shared.lock();
        if state.error.is_some() || state.write_closed || state.attach.is_some() {
            return None;
        }
        let (attachment, link) = PendingAttachment::new(socket.take()?, shared);
        state.attach = Some(Box::new(attachment));
        drop(state);
        shared.notify();
        Some(Box::new(Handle {
            link,
            shared: Arc::clone(shared),
        }))
    }
}
