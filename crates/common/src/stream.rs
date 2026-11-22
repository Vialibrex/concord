use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::OwnedTcp;
use crate::stream_buffer::{
    BufferRequirements, ReadBufferOptions, StreamBuffer, poll_read_buffer, poll_write_buffer,
};
use crate::sync::lock;

/// A socket handle in a form that needs no `cfg` here: a file descriptor or a
/// `SOCKET`, converted back in `concord-platform`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RawSocket(pub i64);

/// Moves a user-space stack's buffered bytes to and from a bare socket; `Ready(Ok(0))` is end of stream.
pub trait DirectIo: Send {
    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        socket: &tokio::net::TcpStream,
    ) -> Poll<io::Result<usize>>;

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        socket: &tokio::net::TcpStream,
    ) -> Poll<io::Result<usize>>;

    /// Hands over a socket for the stack to move the bytes itself until both directions
    /// close. The socket is taken only on acceptance; refusal leaves it with the caller.
    fn attach_owned(&mut self, _socket: &mut Option<OwnedTcp>) -> Option<Box<dyn Attached>> {
        None
    }
}

/// A connection a stack serves from an attached socket.
pub trait Attached: Send {
    /// Bytes moved so far: from the stack to the socket, and from the socket to the stack.
    fn moved(&self) -> (u64, u64);

    /// Ready once both directions closed, or with the error that ended the connection.
    /// Dropping it before then aborts the connection.
    fn poll_done(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

/// The read half of a split stream.
pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;

/// The write half of a split stream; `poll_shutdown` closes the write direction only.
pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Splits a stream by putting it behind one lock that each half takes for the length of a
/// poll, syscall included. For layers that keep both directions in one state.
pub fn split_with_lock<T>(stream: T) -> (BoxRead, BoxWrite)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let shared = Arc::new(Locked {
        vectored: stream.is_write_vectored(),
        stream: Mutex::new(stream),
    });
    (
        Box::new(LockedRead(shared.clone())),
        Box::new(LockedWrite(shared)),
    )
}

struct Locked<T> {
    stream: Mutex<T>,
    vectored: bool,
}

impl<T> Locked<T> {
    fn lock(&self) -> MutexGuard<'_, T> {
        lock(&self.stream)
    }
}

struct LockedRead<T>(Arc<Locked<T>>);

struct LockedWrite<T>(Arc<Locked<T>>);

impl<T: AsyncRead + Unpin> AsyncRead for LockedRead<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for LockedWrite<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock()).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock()).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.vectored
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_shutdown(cx)
    }
}

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    fn read_requirements(&self) -> BufferRequirements {
        BufferRequirements::default()
    }

    fn write_requirements(&self) -> BufferRequirements {
        BufferRequirements::default()
    }

    /// Shares AsyncRead's byte order. Ready(empty) is EOF; Pending retains partial input in the
    /// reader. A nonempty result transfers its owner with the requested write headroom.
    /// A framed reader may return a complete frame; the writer still enforces its own MTU.
    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        poll_read_buffer(self, cx, options)
    }

    /// `Ready(n)` consumes n plaintext bytes. The same buffer survives Pending, including any in-place framing.
    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        poll_write_buffer(self, cx, buffer)
    }

    /// Some only on a bare TCP socket. `relay` splices when both ends have one.
    fn raw_socket(&self) -> Option<RawSocket> {
        None
    }

    /// Some only on a bare TCP socket, which `relay` may move bytes between with splice.
    fn tcp(&self) -> Option<&tokio::net::TcpStream> {
        None
    }

    /// Transfers stream-local ownership. Relay must first drain both halves' buffers,
    /// read/write queues and pending flushes before calling this handoff.
    fn into_tcp(self: Box<Self>) -> Result<OwnedTcp, BoxStream> {
        Err(Box::new(self))
    }

    /// What `remoteDestination` shows for a stream that dials straight to its target.
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// True while a lazy protocol header still waits for the first write.
    fn needs_handshake(&self) -> bool {
        false
    }

    fn direct(&mut self) -> Option<&mut dyn DirectIo> {
        None
    }

    /// Owned halves for a reader and a writer on different tasks. A layer that keeps
    /// separate state per direction splits its inner stream and gives each half its own,
    /// so neither waits for the other.
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        split_with_lock(self)
    }
}

pub type BoxStream = Box<dyn Stream>;

/// Declares, inside a `Stream` impl over another stream, each capability as `forward` (to the
/// named field, unchanged), `own` (written in the impl) or `default` (the trait default: copy
/// through this type's own I/O, expose nothing beneath). xtask's `stream_policy` test requires
/// every method of `Stream` to be named exactly once; `forward: all` and `default: all` stand alone.
/// A wrapper that owns a lifetime ticket handles `into_tcp` as `own` so a handoff keeps the ticket.
///
/// ```ignore
/// impl<S: Stream> Stream for Wrapper<S> {
///     stream_policy!(inner;
///         forward: read_requirements, poll_read_buffer, peer_addr;
///         own: write_requirements, poll_write_buffer;
///         default: raw_socket, tcp, needs_handshake, direct, into_split, into_tcp);
/// }
/// ```
#[macro_export]
macro_rules! stream_policy {
    (@group [$field:tt] forward $($name:ident)+) => {
        $($crate::stream_policy!(@forward [] [. $field] $name);)+
    };
    (@group [$($field:tt)?] own $($name:ident)+) => {
        $($crate::stream_policy!(@known $name);)+
    };
    (@group [$($field:tt)?] default $($name:ident)+) => {
        $($crate::stream_policy!(@known $name);)+
    };
    (@all [$($pre:tt)*] [$($post:tt)*]) => {
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] read_requirements);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] write_requirements);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] poll_read_buffer);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] poll_write_buffer);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] raw_socket);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] tcp);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] into_tcp);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] peer_addr);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] needs_handshake);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] direct);
        $crate::stream_policy!(@forward [$($pre)*] [$($post)*] into_split);
    };
    (@known read_requirements) => {};
    (@known write_requirements) => {};
    (@known poll_read_buffer) => {};
    (@known poll_write_buffer) => {};
    (@known raw_socket) => {};
    (@known tcp) => {};
    (@known into_tcp) => {};
    (@known peer_addr) => {};
    (@known needs_handshake) => {};
    (@known direct) => {};
    (@known into_split) => {};
    (@forward [$($pre:tt)*] [$($post:tt)*] into_split) => {
        fn into_split(self: ::std::boxed::Box<Self>) -> ($crate::BoxRead, $crate::BoxWrite) {
            $crate::stream_policy!(@split [$($pre)*] [$($post)*] self)
        }
    };
    (@split [* *] [] $this:ident) => {
        $crate::Stream::into_split(*$this)
    };
    (@split [] [. $field:tt] $this:ident) => {
        $crate::Stream::into_split(::std::boxed::Box::new((*$this).$field))
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] read_requirements) => {
        fn read_requirements(&self) -> $crate::stream_buffer::BufferRequirements {
            $crate::Stream::read_requirements(&$($pre)* self $($post)*)
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] write_requirements) => {
        fn write_requirements(&self) -> $crate::stream_buffer::BufferRequirements {
            $crate::Stream::write_requirements(&$($pre)* self $($post)*)
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] poll_read_buffer) => {
        fn poll_read_buffer(
            &mut self,
            cx: &mut ::std::task::Context<'_>,
            options: $crate::stream_buffer::ReadBufferOptions,
        ) -> ::std::task::Poll<::std::io::Result<$crate::stream_buffer::StreamBuffer>> {
            $crate::Stream::poll_read_buffer(&mut $($pre)* self $($post)*, cx, options)
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] poll_write_buffer) => {
        fn poll_write_buffer(
            &mut self,
            cx: &mut ::std::task::Context<'_>,
            buffer: &mut $crate::stream_buffer::StreamBuffer,
        ) -> ::std::task::Poll<::std::io::Result<usize>> {
            $crate::Stream::poll_write_buffer(&mut $($pre)* self $($post)*, cx, buffer)
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] raw_socket) => {
        fn raw_socket(&self) -> ::std::option::Option<$crate::RawSocket> {
            $crate::Stream::raw_socket(&$($pre)* self $($post)*)
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] tcp) => {
        fn tcp(&self) -> ::std::option::Option<&::tokio::net::TcpStream> {
            $crate::Stream::tcp(&$($pre)* self $($post)*)
        }
    };
    (@forward [* *] [] into_tcp) => {
        fn into_tcp(self: ::std::boxed::Box<Self>) -> ::std::result::Result<$crate::OwnedTcp, $crate::BoxStream> {
            (*self).into_tcp()
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] into_tcp) => {
        fn into_tcp(self: ::std::boxed::Box<Self>) -> ::std::result::Result<$crate::OwnedTcp, $crate::BoxStream> {
            $crate::Stream::into_tcp(::std::boxed::Box::new($($pre)* self $($post)*))
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] peer_addr) => {
        fn peer_addr(&self) -> ::std::option::Option<::std::net::SocketAddr> {
            $crate::Stream::peer_addr(&$($pre)* self $($post)*)
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] needs_handshake) => {
        fn needs_handshake(&self) -> bool {
            $crate::Stream::needs_handshake(&$($pre)* self $($post)*)
        }
    };
    (@forward [$($pre:tt)*] [$($post:tt)*] direct) => {
        fn direct(&mut self) -> ::std::option::Option<&mut dyn $crate::DirectIo> {
            $crate::Stream::direct(&mut $($pre)* self $($post)*)
        }
    };
    (default: all) => {};
    (box; forward: all) => {
        $crate::stream_policy!(@all [* *] []);
    };
    ($field:tt; forward: all) => {
        $crate::stream_policy!(@all [] [. $field]);
    };
    ($field:tt; $($kind:ident: $($name:ident),+);+ $(;)?) => {
        $($crate::stream_policy!(@group [$field] $kind $($name)+);)+
    };
    ($($kind:ident: $($name:ident),+);+ $(;)?) => {
        $($crate::stream_policy!(@group [] $kind $($name)+);)+
    };
}

impl Stream for tokio::net::TcpStream {
    stream_policy!(own: poll_read_buffer, raw_socket, tcp, peer_addr, into_split, into_tcp;
        default: read_requirements, write_requirements, poll_write_buffer, needs_handshake, direct);

    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        loop {
            ready!(self.poll_read_ready(cx))?;
            let mut buffer = options.take();
            match self.try_read(buffer.spare_mut()) {
                Ok(0) => return Poll::Ready(Ok(StreamBuffer::default())),
                Ok(filled) => {
                    buffer.advance(filled)?;
                    return Poll::Ready(Ok(buffer));
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
    }

    fn raw_socket(&self) -> Option<RawSocket> {
        None
    }

    fn tcp(&self) -> Option<&tokio::net::TcpStream> {
        Some(self)
    }

    fn into_tcp(self: Box<Self>) -> Result<OwnedTcp, BoxStream> {
        Ok((*self).into())
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        tokio::net::TcpStream::peer_addr(self).ok()
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let (read, write) = tokio::net::TcpStream::into_split(*self);
        (Box::new(read), Box::new(write))
    }
}

impl Stream for tokio::io::DuplexStream {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for tokio::io::BufStream<T> {}

impl<S: Stream + ?Sized> Stream for Box<S> {
    stream_policy!(box; forward: all);
}

/// Replays bytes a sniffer or an inbound parser read ahead, then reads the
/// stream. Writes pass straight through.
pub struct PeekedStream<S> {
    head: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PeekedStream<S> {
    pub fn new(head: Vec<u8>, inner: S) -> Self {
        PeekedStream {
            head,
            offset: 0,
            inner,
        }
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn buffered(&self) -> &[u8] {
        self.head.get(self.offset..).unwrap_or_default()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PeekedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = this.head.get(this.offset..).unwrap_or_default();
        if !pending.is_empty() {
            let take = pending.len().min(buf.remaining());
            if let Some(slice) = pending.get(..take) {
                buf.put_slice(slice);
            }
            this.offset += take;
            if this.offset == this.head.len() {
                this.head = Vec::new();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PeekedStream<S> {
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

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

struct PeekedRead {
    head: Vec<u8>,
    offset: usize,
    inner: BoxRead,
}

impl AsyncRead for PeekedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = this.head.get(this.offset..).unwrap_or_default();
        if !pending.is_empty() {
            let take = pending.len().min(buf.remaining());
            if let Some(slice) = pending.get(..take) {
                buf.put_slice(slice);
            }
            this.offset += take;
            if this.offset == this.head.len() {
                this.head = Vec::new();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: Stream> Stream for PeekedStream<S> {
    stream_policy!(inner;
        forward: read_requirements, write_requirements, poll_write_buffer;
        own: into_split, poll_read_buffer, tcp, direct, into_tcp;
        default: raw_socket, peer_addr, needs_handshake);

    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        options: ReadBufferOptions,
    ) -> Poll<io::Result<StreamBuffer>> {
        if self.buffered().is_empty() {
            self.inner.poll_read_buffer(cx, options)
        } else {
            poll_read_buffer(self, cx, options)
        }
    }

    fn into_tcp(self: Box<Self>) -> Result<OwnedTcp, BoxStream> {
        if self.buffered().is_empty() {
            Box::new(self.inner).into_tcp()
        } else {
            Err(self)
        }
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let PeekedStream {
            head,
            offset,
            inner,
        } = *self;
        let (inner, write) = Box::new(inner).into_split();
        (
            Box::new(PeekedRead {
                head,
                offset,
                inner,
            }),
            write,
        )
    }

    /// Once the head is replayed nothing is left above the socket, so `relay` may splice.
    fn tcp(&self) -> Option<&tokio::net::TcpStream> {
        if self.buffered().is_empty() {
            self.inner.tcp()
        } else {
            None
        }
    }

    fn direct(&mut self) -> Option<&mut dyn DirectIo> {
        if self.buffered().is_empty() {
            self.inner.direct()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_lock_split_moves_both_directions_at_once() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const TOTAL: usize = 1 << 20;
        async fn send(mut write: impl AsyncWrite + Unpin) {
            let chunk = [7u8; 1500];
            let mut left = TOTAL;
            while left > 0 {
                let n = left.min(chunk.len());
                write.write_all(&chunk[..n]).await.unwrap();
                left -= n;
            }
            write.shutdown().await.unwrap();
        }
        async fn drain(mut read: impl AsyncRead + Unpin) -> usize {
            let mut buf = [0u8; 2000];
            let mut total = 0;
            loop {
                let n = read.read(&mut buf).await.unwrap();
                if n == 0 {
                    return total;
                }
                total += n;
            }
        }

        let (near, far) = tokio::io::duplex(4096);
        let (near_read, near_write) = split_with_lock(near);
        let (far_read, far_write) = tokio::io::split(far);
        let (_, _, near_got, far_got) = tokio::join!(
            tokio::spawn(send(near_write)),
            tokio::spawn(send(far_write)),
            tokio::spawn(drain(near_read)),
            tokio::spawn(drain(far_read)),
        );
        assert_eq!((near_got.unwrap(), far_got.unwrap()), (TOTAL, TOTAL));
    }

    use super::*;

    #[tokio::test]
    async fn owned_and_borrowed_reads_share_order_and_keep_requested_headroom() {
        let (mut far, mut near) = duplex(64);
        let options = ReadBufferOptions::for_copy(
            BufferRequirements::default(),
            BufferRequirements {
                mtu: 3,
                front: 5,
                rear: 7,
            },
        )
        .unwrap();
        poll_fn(|cx| match near.poll_read_buffer(cx, options) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(_) => panic!("empty open source must be pending"),
        })
        .await;
        far.write_all(b"abcdef").await.unwrap();
        far.shutdown().await.unwrap();
        let buffer = poll_fn(|cx| near.poll_read_buffer(cx, options))
            .await
            .unwrap();
        assert_eq!(buffer.as_slice(), b"abc");
        assert_eq!(buffer.headroom(), 5);
        assert!(buffer.tailroom() >= 7);
        let mut middle = [0; 2];
        near.read_exact(&mut middle).await.unwrap();
        assert_eq!(&middle, b"de");
        let buffer = poll_fn(|cx| near.poll_read_buffer(cx, options))
            .await
            .unwrap();
        assert_eq!(buffer.as_slice(), b"f");
        let eof = poll_fn(|cx| near.poll_read_buffer(cx, options))
            .await
            .unwrap();
        assert!(eof.is_empty());
        assert_eq!((eof.headroom(), eof.tailroom()), (0, 0));
    }

    struct OwnedOnly(Option<StreamBuffer>);

    impl AsyncRead for OwnedOnly {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }
    }

    impl AsyncWrite for OwnedOnly {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for OwnedOnly {
        fn poll_read_buffer(
            &mut self,
            _: &mut Context<'_>,
            _: ReadBufferOptions,
        ) -> Poll<io::Result<StreamBuffer>> {
            Poll::Ready(Ok(self.0.take().unwrap_or_default()))
        }
    }

    #[tokio::test]
    async fn boxed_peeked_reads_replay_the_prefix_then_forward_the_owner() {
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        let mut payload = options.take();
        payload.spare_mut()[..4].copy_from_slice(b"tail");
        payload.advance(4).unwrap();
        let pointer = payload.as_slice().as_ptr();
        let mut stream: BoxStream = Box::new(PeekedStream::new(
            b"head-".to_vec(),
            OwnedOnly(Some(payload)),
        ));
        let prefix = poll_fn(|cx| stream.poll_read_buffer(cx, options))
            .await
            .unwrap();
        assert_eq!(prefix.as_slice(), b"head-");
        let tail = poll_fn(|cx| stream.poll_read_buffer(cx, options))
            .await
            .unwrap();
        assert_eq!(tail.as_slice(), b"tail");
        assert_eq!(tail.as_slice().as_ptr(), pointer);
        assert!(
            poll_fn(|cx| stream.poll_read_buffer(cx, options))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn refusing_tcp_ownership_keeps_the_owned_read_path() {
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        let mut payload = options.take();
        payload.spare_mut()[..4].copy_from_slice(b"kept");
        payload.advance(4).unwrap();
        let pointer = payload.as_slice().as_ptr();
        let stream: BoxStream = Box::new(OwnedOnly(Some(payload)));
        let mut stream = stream.into_tcp().err().expect("the reader is not bare TCP");
        let buffer = poll_fn(|cx| stream.poll_read_buffer(cx, options))
            .await
            .unwrap();
        assert_eq!(buffer.as_slice(), b"kept");
        assert_eq!(buffer.as_slice().as_ptr(), pointer);
    }

    #[tokio::test]
    async fn replays_the_head_before_reading_the_stream() {
        let (mut far, near) = duplex(64);
        let mut stream = PeekedStream::new(b"head-".to_vec(), near);
        far.write_all(b"tail").await.unwrap();
        far.shutdown().await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"head-tail");
    }

    #[tokio::test]
    async fn split_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let (mut far, near) = duplex(64);
        let (mut read, mut write) =
            (Box::new(PeekedStream::new(b"head-".to_vec(), near)) as BoxStream).into_split();
        let writer = tokio::spawn(async move {
            write.write_all(b"up").await.unwrap();
            write.shutdown().await.unwrap();
        });
        let mut up = Vec::new();
        far.read_to_end(&mut up).await.unwrap();
        assert_eq!(up, b"up");
        writer.await.unwrap();
        far.write_all(b"tail").await.unwrap();
        far.shutdown().await.unwrap();
        let mut out = Vec::new();
        read.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"head-tail");
    }

    #[tokio::test]
    async fn the_socket_shows_through_once_the_head_is_replayed() {
        let (client, mut accepted) = concord_test_support::tcp_pair().await;
        let mut stream = PeekedStream::new(b"head".to_vec(), client);
        assert!(stream.tcp().is_none());
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        assert!(stream.tcp().is_some());
        accepted.write_all(b"tail").await.unwrap();
        accepted.shutdown().await.unwrap();
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
        let tail = poll_fn(|cx| stream.poll_read_buffer(cx, options))
            .await
            .unwrap();
        assert_eq!(tail.as_slice(), b"tail");
        assert!(
            poll_fn(|cx| stream.poll_read_buffer(cx, options))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn refusing_ownership_preserves_an_opaque_stream() {
        let (near, mut far) = duplex(64);
        let stream: BoxStream = Box::new(near);
        let mut stream = stream.into_tcp().err().expect("duplex is not bare TCP");
        stream.write_all(b"still here").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        far.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"still here");
    }

    #[tokio::test]
    async fn boxed_tcp_ownership_waits_for_the_peeked_head() {
        let (client, mut peer) = concord_test_support::tcp_pair().await;
        let stream: BoxStream = Box::new(Box::new(PeekedStream::new(b"head".to_vec(), client)));
        let mut stream = stream.into_tcp().err().expect("head is still buffered");
        let mut head = [0; 4];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"head");
        let mut socket = stream
            .into_tcp()
            .ok()
            .expect("exhausted peek is transparent");
        socket.write_all(b"body").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"body");
    }
}
