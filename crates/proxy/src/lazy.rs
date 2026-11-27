use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use concord_common::stream_buffer::{
    BufferRequirements, ReadBufferOptions, StreamBuffer, poll_write_buffer,
};
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Holds the protocol header back until the first write and sends both in one
/// `write`. A zero-length write sends the header alone.
pub(crate) struct HeadFirst<S> {
    inner: S,
    head: Head,
}

enum Head {
    Held(Vec<u8>),
    Staged(Stage),
    Open,
}

struct Stage {
    out: Vec<u8>,
    pos: usize,
    data_len: usize,
}

impl<S> HeadFirst<S> {
    pub(crate) fn new(inner: S, head: Vec<u8>) -> Self {
        HeadFirst {
            inner,
            head: if head.is_empty() {
                Head::Open
            } else {
                Head::Held(head)
            },
        }
    }

    pub(crate) fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HeadFirst<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeadFirst<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.head {
                Head::Staged(stage) => {
                    while let Some(rest) = stage.out.get(stage.pos..).filter(|r| !r.is_empty()) {
                        match Pin::new(&mut this.inner).poll_write(cx, rest) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                            }
                            Poll::Ready(Ok(n)) => stage.pos += n,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let accepted = stage.data_len;
                    this.head = Head::Open;
                    return Poll::Ready(Ok(accepted));
                }
                Head::Open => return Pin::new(&mut this.inner).poll_write(cx, data),
                Head::Held(head) => {
                    let mut out = std::mem::take(head);
                    out.extend_from_slice(data);
                    this.head = Head::Staged(Stage {
                        out,
                        pos: 0,
                        data_len: data.len(),
                    });
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.head, Head::Held(_)) {
            std::task::ready!(Pin::new(&mut *this).poll_write(cx, &[]))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: Stream> Stream for HeadFirst<S> {
    concord_common::stream_policy!(inner;
        forward: read_requirements, poll_read_buffer, peer_addr;
        own: into_split, write_requirements, poll_write_buffer;
        default: tcp, needs_handshake, direct, into_tcp);

    fn write_requirements(&self) -> BufferRequirements {
        BufferRequirements {
            front: match &self.head {
                Head::Held(head) => head.len(),
                Head::Staged(_) | Head::Open => 0,
            },
            ..Default::default()
        }
        .compose_writer(self.inner.write_requirements())
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        if matches!(self.head, Head::Open) {
            self.inner.poll_write_buffer(cx, buffer)
        } else {
            poll_write_buffer(self, cx, buffer)
        }
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let HeadFirst { inner, head } = *self;
        let (read, write) = Box::new(inner).into_split();
        let write = HeadFirst { inner: write, head };
        (read, Box::new(write))
    }
}

/// A read before any write would hang on a server that waits for the header, so it writes
/// nothing first; the tunnel already gave the client its window to send bytes along.
pub(crate) struct Kick<S> {
    inner: S,
    state: KickState,
}

/// A read and a write can come from different tasks. The staged header carries whichever
/// started first, so the other must not finish it in its place and take its count.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KickState {
    Fresh,
    Kicking,
    Writing,
    Done,
}

impl<S> Kick<S> {
    pub(crate) fn new(inner: S) -> Self {
        Kick {
            inner,
            state: KickState::Fresh,
        }
    }
}

fn kick<W: AsyncWrite + Unpin + ?Sized>(
    io: &mut W,
    state: &mut KickState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if matches!(*state, KickState::Fresh | KickState::Kicking) {
        *state = KickState::Kicking;
        std::task::ready!(Pin::new(io).poll_write(cx, &[]))?;
        *state = KickState::Done;
    }
    Poll::Ready(Ok(()))
}

fn kick_write<W: AsyncWrite + Unpin + ?Sized>(
    io: &mut W,
    state: &mut KickState,
    cx: &mut Context<'_>,
    data: &[u8],
) -> Poll<io::Result<usize>> {
    loop {
        match Pin::new(&mut *io).poll_write(cx, data) {
            Poll::Pending => {
                if *state == KickState::Fresh && !data.is_empty() {
                    *state = KickState::Writing;
                }
                return Poll::Pending;
            }
            Poll::Ready(Ok(0)) if *state == KickState::Kicking && !data.is_empty() => {
                *state = KickState::Done;
            }
            Poll::Ready(Ok(n)) => {
                *state = KickState::Done;
                return Poll::Ready(Ok(n));
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Kick<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(kick(&mut this.inner, &mut this.state, cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Kick<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        kick_write(&mut this.inner, &mut this.state, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// The write half until the header is out, shared with the read half that may have to send it.
struct KickShared {
    done: AtomicBool,
    slot: Mutex<Slot>,
}

struct Slot {
    write: Option<BoxWrite>,
    state: KickState,
    /// The inner writer keeps one waker, so a read half waiting on its kick is woken here when the
    /// write half finishes the header.
    reader: Option<Waker>,
}

impl KickShared {
    fn slot(&self) -> MutexGuard<'_, Slot> {
        lock(&self.slot)
    }
}

struct KickRead {
    read: BoxRead,
    shared: Arc<KickShared>,
}

impl AsyncRead for KickRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shared.done.load(Ordering::Acquire) {
            let mut slot = this.shared.slot();
            let Slot {
                write,
                state,
                reader,
            } = &mut *slot;
            if let Some(write) = write {
                if kick(write, state, cx)?.is_pending() {
                    *reader = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                this.shared.done.store(true, Ordering::Release);
            }
        }
        Pin::new(&mut this.read).poll_read(cx, buf)
    }
}

struct KickWrite {
    own: Option<BoxWrite>,
    shared: Arc<KickShared>,
}

impl KickWrite {
    fn with_slot<T>(
        &mut self,
        f: impl FnOnce(&mut BoxWrite, &mut KickState) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if self.own.is_none() && self.shared.done.load(Ordering::Acquire) {
            self.own = self.shared.slot().write.take();
        }
        if let Some(write) = &mut self.own {
            return f(write, &mut KickState::Done);
        }
        let mut slot = self.shared.slot();
        let Slot {
            write,
            state,
            reader,
        } = &mut *slot;
        let Some(write) = write.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let out = f(write, state);
        if *state == KickState::Done {
            self.shared.done.store(true, Ordering::Release);
            if let Some(reader) = reader.take() {
                reader.wake();
            }
        }
        out
    }
}

impl AsyncWrite for KickWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_slot(|io, state| kick_write(io, state, cx, data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_slot(|io, _| Pin::new(io).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_slot(|io, _| Pin::new(io).poll_shutdown(cx))
    }
}

impl<S: Stream> Stream for Kick<S> {
    concord_common::stream_policy!(inner;
        forward: read_requirements, write_requirements, peer_addr;
        own: into_split, poll_read_buffer, poll_write_buffer, needs_handshake;
        default: tcp, direct, into_tcp);

    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        std::task::ready!(kick(&mut self.inner, &mut self.state, cx))?;
        self.inner.poll_read_buffer(cx, options)
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        if self.state == KickState::Done {
            self.inner.poll_write_buffer(cx, buffer)
        } else {
            poll_write_buffer(self, cx, buffer)
        }
    }

    fn needs_handshake(&self) -> bool {
        self.state != KickState::Done
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let Kick { inner, state } = *self;
        let (read, write) = Box::new(inner).into_split();
        if state == KickState::Done {
            return (read, write);
        }
        let shared = Arc::new(KickShared {
            done: AtomicBool::new(false),
            slot: Mutex::new(Slot {
                write: Some(write),
                state,
                reader: None,
            }),
        });
        (
            Box::new(KickRead {
                read,
                shared: shared.clone(),
            }),
            Box::new(KickWrite { own: None, shared }),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    struct OwnedReply {
        inner: tokio::io::DuplexStream,
        reply: Option<StreamBuffer>,
    }

    impl AsyncRead for OwnedReply {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }
    }

    impl AsyncWrite for OwnedReply {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl Stream for OwnedReply {
        fn poll_read_buffer(
            &mut self,
            _: &mut Context<'_>,
            _: ReadBufferOptions,
        ) -> Poll<io::Result<StreamBuffer>> {
            Poll::Ready(Ok(self.reply.take().unwrap_or_default()))
        }
    }

    fn bytes(options: ReadBufferOptions, data: &[u8]) -> StreamBuffer {
        let mut buffer = options.take();
        buffer.spare_mut()[..data.len()].copy_from_slice(data);
        buffer.advance(data.len()).unwrap();
        buffer
    }

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), future)
            .await
            .expect("the test hung")
    }

    fn options() -> ReadBufferOptions {
        ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap()
    }

    #[tokio::test]
    async fn data_written_over_a_pending_kick_is_sent_after_the_header() {
        let (near, mut far) = duplex(2);
        let mut stream = Kick::new(HeadFirst::new(near, b"HEAD".to_vec()));
        let mut cx = Context::from_waker(Waker::noop());
        let mut buf = [0u8; 1];
        assert!(
            Pin::new(&mut stream)
                .poll_read(&mut cx, &mut ReadBuf::new(&mut buf))
                .is_pending()
        );
        assert!(stream.needs_handshake());
        let mut seen = [0u8; 8];
        let (written, read) =
            bounded(async { tokio::join!(stream.write_all(b"data"), far.read_exact(&mut seen)) })
                .await;
        written.unwrap();
        read.unwrap();
        assert_eq!(&seen, b"HEADdata");
        assert!(!stream.needs_handshake());
    }

    #[tokio::test]
    async fn a_write_buffer_carries_the_header_then_goes_straight_through() {
        let (near, mut far) = duplex(1024);
        let mut stream = Kick::new(HeadFirst::new(near, b"HEAD".to_vec()));
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = bytes(options(), b"data");
        assert!(matches!(
            stream.poll_write_buffer(&mut cx, &mut first),
            Poll::Ready(Ok(4))
        ));
        assert!(first.is_empty());
        assert!(!stream.needs_handshake());
        let mut second = bytes(options(), b"more");
        assert!(matches!(
            stream.poll_write_buffer(&mut cx, &mut second),
            Poll::Ready(Ok(4))
        ));
        let mut seen = [0u8; 12];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEADdatamore");
    }

    #[tokio::test]
    async fn a_pending_write_buffer_keeps_its_bytes_and_the_header_pending() {
        let (near, mut far) = duplex(2);
        let mut stream = Kick::new(HeadFirst::new(near, b"HEAD".to_vec()));
        let mut cx = Context::from_waker(Waker::noop());
        let mut buffer = bytes(options(), b"data");
        assert!(stream.poll_write_buffer(&mut cx, &mut buffer).is_pending());
        assert_eq!(buffer.as_slice(), b"data");
        assert!(stream.needs_handshake());
        let mut seen = [0u8; 8];
        let (written, read) = bounded(async {
            tokio::join!(
                poll_fn(|cx| stream.poll_write_buffer(cx, &mut buffer)),
                far.read_exact(&mut seen)
            )
        })
        .await;
        assert_eq!(written.unwrap(), 4);
        read.unwrap();
        assert_eq!(&seen, b"HEADdata");
        assert!(buffer.is_empty());
        assert!(!stream.needs_handshake());
    }

    #[tokio::test]
    async fn a_split_write_half_finishes_the_header_staged_before_the_split() {
        let (inner, mut far) = duplex(2);
        let mut stream = HeadFirst::new(OwnedReply { inner, reply: None }, b"HEAD".to_vec());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut cx, b"data")
                .is_pending()
        );
        let (_read, mut write) = Box::new(stream).into_split();
        let mut seen = [0u8; 8];
        let (written, read) = bounded(async {
            tokio::join!(
                poll_fn(|cx| Pin::new(&mut write).poll_write(cx, b"data")),
                far.read_exact(&mut seen)
            )
        })
        .await;
        assert_eq!(written.unwrap(), 4);
        read.unwrap();
        assert_eq!(&seen, b"HEADdata");
        bounded(write.shutdown()).await.unwrap();
        let mut extra = Vec::new();
        bounded(far.read_to_end(&mut extra)).await.unwrap();
        assert!(extra.is_empty());
    }

    #[tokio::test]
    async fn shutdown_before_any_write_does_not_send_the_header() {
        let (near, mut far) = duplex(1024);
        let mut stream = HeadFirst::new(near, b"HEAD".to_vec());
        bounded(stream.shutdown()).await.unwrap();
        let mut seen = Vec::new();
        bounded(far.read_to_end(&mut seen)).await.unwrap();
        assert!(seen.is_empty());
    }

    #[tokio::test]
    async fn an_owned_read_kicks_a_partial_header_and_forwards_the_owner() {
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        let mut reply = options.take();
        reply.spare_mut()[..5].copy_from_slice(b"reply");
        reply.advance(5).unwrap();
        let pointer = reply.as_slice().as_ptr() as usize;
        let (inner, mut far) = duplex(2);
        let mut stream = Kick::new(HeadFirst::new(
            OwnedReply {
                inner,
                reply: Some(reply),
            },
            b"HEAD".to_vec(),
        ));
        let reader = tokio::spawn(async move {
            let buffer = poll_fn(|cx| stream.poll_read_buffer(cx, options))
                .await
                .unwrap();
            assert!(!stream.needs_handshake());
            buffer
        });
        let mut header = [0; 4];
        far.read_exact(&mut header).await.unwrap();
        assert_eq!(&header, b"HEAD");
        let buffer = reader.await.unwrap();
        assert_eq!(buffer.as_slice(), b"reply");
        assert_eq!(buffer.as_slice().as_ptr() as usize, pointer);
    }

    #[tokio::test]
    async fn the_header_and_first_payload_leave_together() {
        let (near, mut far) = duplex(1024);
        let mut stream = HeadFirst::new(near, b"HEAD".to_vec());
        stream.write_all(b"payload").await.unwrap();
        stream.write_all(b"-more").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut seen = Vec::new();
        far.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"HEADpayload-more");
    }

    #[tokio::test]
    async fn flush_sends_the_header_alone() {
        let (near, mut far) = duplex(1024);
        let mut stream = HeadFirst::new(near, b"HEAD".to_vec());
        stream.flush().await.unwrap();
        let mut seen = [0u8; 4];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEAD");
    }

    #[tokio::test]
    async fn an_empty_write_sends_the_header_alone() {
        let (near, mut far) = duplex(1024);
        let mut stream = HeadFirst::new(near, b"HEAD".to_vec());
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        let mut seen = [0u8; 4];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEAD");
    }

    #[tokio::test]
    async fn a_read_before_any_write_kicks_the_handshake() {
        let (near, mut far) = duplex(1024);
        let mut stream = Kick::new(HeadFirst::new(near, b"HEAD".to_vec()));
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 2];
            stream.read_exact(&mut buf).await.unwrap();
            buf
        });
        let mut seen = [0u8; 4];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEAD");
        far.write_all(b"ok").await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"ok");
    }

    #[tokio::test]
    async fn a_first_write_carries_the_header_and_ends_the_handshake() {
        let (near, mut far) = duplex(1024);
        let mut stream = Kick::new(HeadFirst::new(near, b"HEAD".to_vec()));
        assert!(stream.needs_handshake());
        stream.write_all(b"data").await.unwrap();
        assert!(!stream.needs_handshake());
        let mut seen = [0u8; 8];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEADdata");
    }

    #[tokio::test]
    async fn a_read_and_a_blocked_write_from_two_tasks_send_the_data_once() {
        let (near, mut far) = duplex(4);
        let stream = Kick::new(HeadFirst::new(near, b"HEAD".to_vec()));
        let (mut read, mut write) = tokio::io::split(stream);
        let writer = tokio::spawn(async move { write.write_all(b"data").await.map(|()| write) });
        tokio::task::yield_now().await;
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 2];
            read.read_exact(&mut buf).await.unwrap();
            buf
        });
        let mut seen = [0u8; 8];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEADdata");
        let _write = writer.await.unwrap().unwrap();
        far.write_all(b"ok").await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"ok");
        let mut extra = [0u8; 1];
        let more = tokio::time::timeout(Duration::from_millis(50), far.read(&mut extra)).await;
        assert!(more.is_err(), "the data went out twice");
    }

    #[tokio::test]
    async fn a_write_that_meets_a_pending_kick_still_sends_its_data() {
        let (near, mut far) = duplex(2);
        let stream = Kick::new(HeadFirst::new(near, b"HEAD".to_vec()));
        let (mut read, mut write) = tokio::io::split(stream);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 2];
            read.read_exact(&mut buf).await.unwrap();
            buf
        });
        tokio::task::yield_now().await;
        let writer = tokio::spawn(async move { write.write_all(b"data").await.map(|()| write) });
        let mut seen = [0u8; 8];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEADdata");
        let _write = writer.await.unwrap().unwrap();
        far.write_all(b"ok").await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"ok");
    }

    #[tokio::test]
    async fn a_split_read_half_kicks_while_the_write_half_stays_idle() {
        let (near, mut far) = duplex(1024);
        let (mut read, write) =
            Box::new(Kick::new(HeadFirst::new(near, b"HEAD".to_vec()))).into_split();
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 2];
            read.read_exact(&mut buf).await.unwrap();
            buf
        });
        let mut seen = [0u8; 4];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEAD");
        far.write_all(b"ok").await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"ok");
        let mut write = write;
        write.write_all(b"data").await.unwrap();
        write.shutdown().await.unwrap();
        let mut rest = Vec::new();
        far.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"data");
    }

    struct Flag(std::sync::atomic::AtomicBool);

    impl std::task::Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    fn flag() -> (Arc<Flag>, Waker) {
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        (flag.clone(), Waker::from(flag))
    }

    #[tokio::test]
    async fn a_read_half_waiting_on_its_kick_wakes_when_the_write_half_sends_the_header() {
        let (near, mut far) = duplex(2);
        let (mut read, mut write) =
            Box::new(Kick::new(HeadFirst::new(near, b"HEAD".to_vec()))).into_split();
        let (read_woken, read_waker) = flag();
        let (_, write_waker) = flag();
        let mut buf = [0u8; 2];
        let mut read_buf = ReadBuf::new(&mut buf);
        let mut read_cx = Context::from_waker(&read_waker);
        let mut write_cx = Context::from_waker(&write_waker);
        assert!(
            Pin::new(&mut read)
                .poll_read(&mut read_cx, &mut read_buf)
                .is_pending()
        );
        assert!(
            Pin::new(&mut write)
                .poll_write(&mut write_cx, b"data")
                .is_pending()
        );
        let mut seen = [0u8; 2];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HE");
        assert!(
            Pin::new(&mut write)
                .poll_write(&mut write_cx, b"data")
                .is_pending()
        );
        assert!(read_woken.0.load(Ordering::Relaxed));
        let writer = tokio::spawn(async move { write.write_all(b"data").await.map(|()| write) });
        let mut seen = [0u8; 6];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"ADdata");
        let _write = writer.await.unwrap().unwrap();
        far.write_all(b"ok").await.unwrap();
        read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
    }

    #[tokio::test]
    async fn split_halves_move_data_both_ways_and_shutdown_leaves_the_read_half() {
        let (near, mut far) = duplex(1024);
        let (mut read, mut write) =
            Box::new(Kick::new(HeadFirst::new(near, b"HEAD".to_vec()))).into_split();
        let writer = tokio::spawn(async move {
            write.write_all(b"up").await.unwrap();
            write.shutdown().await.unwrap();
        });
        let mut seen = [0u8; 6];
        far.read_exact(&mut seen).await.unwrap();
        assert_eq!(&seen, b"HEADup");
        writer.await.unwrap();
        far.write_all(b"down").await.unwrap();
        drop(far);
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"down");
    }
}
