use std::io::{self, IoSlice};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;

use crate::{BoxRead, BoxStream, BoxWrite, Stream};

/// Keeps a socket's lifetime ticket with every owner of the socket.
pub struct OwnedTcp {
    stream: TcpStream,
    guard: Option<Arc<dyn Send + Sync>>,
}

impl OwnedTcp {
    pub fn new(stream: TcpStream, guard: Option<Arc<dyn Send + Sync>>) -> Self {
        OwnedTcp { stream, guard }
    }

    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// A duplicate may close before the original during a concurrent reset.
    pub fn share_guard(&self, stream: TcpStream) -> Self {
        Self::new(stream, self.guard.clone())
    }

    pub fn into_std(self) -> io::Result<(std::net::TcpStream, Option<Arc<dyn Send + Sync>>)> {
        Ok((self.stream.into_std()?, self.guard))
    }

    pub fn into_halves(self) -> (TcpRead, BoxWrite) {
        let (read, write) = self.stream.into_split();
        (
            TcpRead(Guarded {
                inner: read,
                _guard: self.guard.clone(),
            }),
            Box::new(Guarded {
                inner: write,
                _guard: self.guard,
            }),
        )
    }
}

impl From<TcpStream> for OwnedTcp {
    fn from(stream: TcpStream) -> Self {
        Self::new(stream, None)
    }
}

impl Deref for OwnedTcp {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl AsyncRead for OwnedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for OwnedTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl Stream for OwnedTcp {
    crate::stream_policy!(stream;
        forward: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, peer_addr;
        own: tcp, into_tcp, into_split;
        default: needs_handshake, direct);

    fn tcp(&self) -> Option<&TcpStream> {
        Some(&self.stream)
    }

    fn into_tcp(self: Box<Self>) -> Result<OwnedTcp, BoxStream> {
        Ok(*self)
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let (read, write) = self.into_halves();
        (Box::new(read), write)
    }
}

/// The read half of a split `OwnedTcp`, which still exposes its socket so a reader can wait
/// for readiness and read vectored itself.
pub struct TcpRead(Guarded<OwnedReadHalf>);

impl TcpRead {
    pub fn tcp(&self) -> &TcpStream {
        self.0.inner.as_ref()
    }
}

impl AsyncRead for TcpRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buffer)
    }
}

/// One half of a split socket; the lifetime ticket goes when both halves have.
struct Guarded<T> {
    inner: T,
    _guard: Option<Arc<dyn Send + Sync>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Guarded<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Guarded<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::DirectIo;

    use concord_test_support::tcp_pair as pair;

    struct Ticket(Arc<AtomicUsize>);

    impl Drop for Ticket {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn a_ticket_outlives_both_socket_close_orders() {
        for duplicate_first in [false, true] {
            let dropped = Arc::<AtomicUsize>::default();
            let (original, _peer) = pair().await;
            let original = OwnedTcp::new(original, Some(Arc::new(Ticket(dropped.clone()))));
            let (duplicate, _peer) = pair().await;
            let duplicate = original.share_guard(duplicate);
            let (first, last) = if duplicate_first {
                (duplicate, original)
            } else {
                (original, duplicate)
            };
            drop(first);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            let held = Arc::new(last);
            let passthrough = held.clone();
            drop(held);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            drop(passthrough);
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn a_split_keeps_the_ticket_until_both_halves_close() {
        for read_first in [false, true] {
            let dropped = Arc::<AtomicUsize>::default();
            let (socket, mut peer) = pair().await;
            let socket = OwnedTcp::new(socket, Some(Arc::new(Ticket(dropped.clone()))));
            let (mut read, mut write) = Stream::into_split(Box::new(socket));
            write.write_all(b"ping").await.unwrap();
            let mut buf = [0; 4];
            peer.read_exact(&mut buf).await.unwrap();
            peer.write_all(b"pong").await.unwrap();
            read.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
            if read_first {
                drop(read);
                assert_eq!(dropped.load(Ordering::Relaxed), 0);
                drop(write);
            } else {
                drop(write);
                assert_eq!(dropped.load(Ordering::Relaxed), 0);
                drop(read);
            }
            assert_eq!(dropped.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn a_ticket_survives_deregistering_the_socket() {
        let dropped = Arc::<AtomicUsize>::default();
        let (stream, _peer) = pair().await;
        let socket = OwnedTcp::new(stream, Some(Arc::new(Ticket(dropped.clone()))));
        let (socket, ticket) = socket.into_std().unwrap();
        drop(socket);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(ticket);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    struct Refusing;

    impl DirectIo for Refusing {
        fn poll_send_to(&mut self, _: &mut Context<'_>, _: &TcpStream) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }

        fn poll_recv_from(
            &mut self,
            _: &mut Context<'_>,
            _: &TcpStream,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }
    }

    #[tokio::test]
    async fn a_default_refusal_keeps_the_socket_usable_through_half_close() {
        let (socket, mut peer) = pair().await;
        let mut slot = Some(socket.into());
        assert!(Refusing.attach_owned(&mut slot).is_none());
        let mut socket = slot.unwrap();
        socket.write_all(b"request").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut request = Vec::new();
        peer.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        peer.write_all(b"reply").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut reply = Vec::new();
        socket.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
    }
}
