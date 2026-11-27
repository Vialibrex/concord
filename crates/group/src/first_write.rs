use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::stream_buffer::StreamBuffer;
use concord_common::{BoxRead, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

type Report = Box<dyn FnOnce(Result<(), &io::Error>) + Send>;

/// Reports how the first write of a stream whose protocol header is still
/// pending ended, like mihomo's `NewFirstWriteCallBackConn`.
pub(crate) struct FirstWrite<S> {
    inner: S,
    report: Option<Report>,
}

impl<S> FirstWrite<S> {
    pub(crate) fn new(inner: S, report: Report) -> Self {
        FirstWrite {
            inner,
            report: Some(report),
        }
    }

    fn finish<T>(&mut self, result: &io::Result<T>) {
        if let Some(report) = self.report.take() {
            report(result.as_ref().map(|_| ()));
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FirstWrite<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FirstWrite<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = std::task::ready!(Pin::new(&mut self.inner).poll_write(cx, data));
        self.finish(&result);
        Poll::Ready(result)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = std::task::ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, bufs));
        self.finish(&result);
        Poll::Ready(result)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: Stream> Stream for FirstWrite<S> {
    concord_common::stream_policy!(inner;
        forward: read_requirements, write_requirements, poll_read_buffer, tcp, peer_addr,
            needs_handshake, direct;
        own: into_split, poll_write_buffer;
        default: into_tcp);

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        let result = std::task::ready!(self.inner.poll_write_buffer(cx, buffer));
        self.finish(&result);
        Poll::Ready(result)
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let FirstWrite { inner, report } = *self;
        let (read, write) = Box::new(inner).into_split();
        (
            read,
            Box::new(FirstWrite {
                inner: write,
                report,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::sync::{Arc, Mutex};

    use concord_common::stream_buffer::{BufferRequirements, ReadBufferOptions};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    use concord_common::sync::lock;

    #[tokio::test]
    async fn only_the_first_write_is_reported() {
        let (near, _far) = duplex(64);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let mut stream = FirstWrite::new(
            near,
            Box::new(move |result| lock(&sink).push(result.is_ok())),
        );
        stream.write_all(b"one").await.unwrap();
        stream.write_all(b"two").await.unwrap();
        assert_eq!(*lock(&seen), [true]);
    }

    /// Hands out one held read owner and answers owned writes from a script, recording each
    /// written buffer's address; a borrowed read or write fails, so a copy cannot pass unnoticed.
    struct Owned {
        reply: Option<StreamBuffer>,
        script: Vec<Poll<io::Result<usize>>>,
        written: Vec<usize>,
    }

    const READ: BufferRequirements = BufferRequirements {
        mtu: 7,
        front: 1,
        rear: 2,
    };
    const WRITE: BufferRequirements = BufferRequirements {
        mtu: 9,
        front: 3,
        rear: 5,
    };

    impl AsyncRead for Owned {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }
    }

    impl AsyncWrite for Owned {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for Owned {
        fn read_requirements(&self) -> BufferRequirements {
            READ
        }

        fn write_requirements(&self) -> BufferRequirements {
            WRITE
        }

        fn poll_read_buffer(
            &mut self,
            _: &mut Context<'_>,
            _: ReadBufferOptions,
        ) -> Poll<io::Result<StreamBuffer>> {
            Poll::Ready(Ok(self.reply.take().unwrap_or_default()))
        }

        fn poll_write_buffer(
            &mut self,
            _: &mut Context<'_>,
            buffer: &mut StreamBuffer,
        ) -> Poll<io::Result<usize>> {
            self.written.push(buffer.as_slice().as_ptr() as usize);
            let next = self.script.remove(0);
            if let Poll::Ready(Ok(n)) = &next {
                buffer.consume(*n).unwrap();
            }
            next
        }
    }

    fn options() -> ReadBufferOptions {
        ReadBufferOptions::for_copy(READ, WRITE).unwrap()
    }

    fn filled(bytes: &[u8]) -> StreamBuffer {
        let mut buffer = options().take();
        buffer.spare_mut()[..bytes.len()].copy_from_slice(bytes);
        buffer.advance(bytes.len()).unwrap();
        buffer
    }

    fn watched(script: Vec<Poll<io::Result<usize>>>) -> (FirstWrite<Owned>, Arc<Mutex<Vec<bool>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let inner = Owned {
            reply: None,
            script,
            written: Vec::new(),
        };
        let stream = FirstWrite::new(
            inner,
            Box::new(move |result| lock(&sink).push(result.is_ok())),
        );
        (stream, seen)
    }

    fn write(stream: &mut FirstWrite<Owned>, buffer: &mut StreamBuffer) -> Poll<io::Result<usize>> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        stream.poll_write_buffer(&mut cx, buffer)
    }

    #[tokio::test]
    async fn owned_buffers_pass_through_without_a_copy() {
        let (mut stream, seen) = watched(vec![Poll::Ready(Ok(5))]);
        assert_eq!(stream.read_requirements(), READ);
        assert_eq!(stream.write_requirements(), WRITE);

        let reply = filled(b"reply");
        let pointer = reply.as_slice().as_ptr() as usize;
        stream.inner.reply = Some(reply);
        let read = poll_fn(|cx| stream.poll_read_buffer(cx, options()))
            .await
            .unwrap();
        assert_eq!(read.as_slice(), b"reply");
        assert_eq!(read.as_slice().as_ptr() as usize, pointer);

        let mut buffer = filled(b"hello");
        let pointer = buffer.as_slice().as_ptr() as usize;
        assert!(matches!(
            write(&mut stream, &mut buffer),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(stream.inner.written, [pointer]);
        assert_eq!(*lock(&seen), [true]);
    }

    #[test]
    fn an_owned_first_write_is_reported_once_after_pending_and_a_partial_write() {
        let (mut stream, seen) =
            watched(vec![Poll::Pending, Poll::Ready(Ok(2)), Poll::Ready(Ok(3))]);
        let mut buffer = filled(b"hello");
        assert!(write(&mut stream, &mut buffer).is_pending());
        assert!(lock(&seen).is_empty());
        assert!(matches!(
            write(&mut stream, &mut buffer),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(*lock(&seen), [true]);
        assert!(matches!(
            write(&mut stream, &mut buffer),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(*lock(&seen), [true]);
    }

    #[test]
    fn a_failed_owned_first_write_is_reported_once_as_an_error() {
        let (mut stream, seen) = watched(vec![
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(5)),
        ]);
        let mut buffer = filled(b"hello");
        assert!(matches!(
            write(&mut stream, &mut buffer),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            write(&mut stream, &mut buffer),
            Poll::Ready(Ok(5))
        ));
        assert_eq!(*lock(&seen), [false]);
    }

    #[tokio::test]
    async fn a_failed_first_write_is_reported_as_an_error() {
        let (near, far) = duplex(64);
        drop(far);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let mut stream = FirstWrite::new(
            near,
            Box::new(move |result| lock(&sink).push(result.is_ok())),
        );
        assert!(stream.write_all(b"one").await.is_err());
        assert_eq!(*lock(&seen), [false]);
    }

    #[tokio::test]
    async fn the_write_half_reports_and_the_read_half_keeps_working() {
        let (near, mut far) = duplex(64);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let stream: concord_common::BoxStream = Box::new(FirstWrite::new(
            near,
            Box::new(move |result| lock(&sink).push(result.is_ok())),
        ));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        far.write_all(b"down").await.unwrap();
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        assert_eq!(*lock(&seen), [true]);
        let mut sent = [0u8; 2];
        far.read_exact(&mut sent).await.unwrap();
        assert_eq!(&sent, b"up");
        far.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"down");
    }
}
