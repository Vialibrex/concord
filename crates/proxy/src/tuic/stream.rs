use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use concord_common::{BoxRead, BoxWrite, CoreError, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Sleep, sleep};

use super::wire::{CMD_RESPONSE, Version};

const FAILED: u8 = 0xff;

/// Checks the three-byte answer a v4 server gives to Connect before any data, within
/// `request-timeout` of the first read, as mihomo's early connection does.
pub(super) struct V4Response<S> {
    inner: S,
    seen: [u8; 3],
    got: usize,
    timeout: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<S> V4Response<S> {
    pub(super) fn new(inner: S, timeout: Duration) -> Self {
        V4Response {
            inner,
            seen: [0; 3],
            got: 0,
            timeout,
            deadline: None,
        }
    }
}

pub(super) fn check_response(answer: &[u8; 3]) -> io::Result<()> {
    match answer {
        [ver, kind, rep] if *ver == Version::V4.byte() && *kind == CMD_RESPONSE => {
            if *rep == FAILED {
                Err(CoreError::TargetRefused("connect failed".into()).into())
            } else {
                Ok(())
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed tuic response",
        )),
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for V4Response<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.got < this.seen.len() {
            let mut window = this.seen.get_mut(this.got..).map(ReadBuf::new);
            let Some(window) = window.as_mut() else {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            };
            if Pin::new(&mut this.inner)
                .poll_read(cx, window)?
                .is_pending()
            {
                if !this.timeout.is_zero() {
                    let timeout = this.timeout;
                    let deadline = this
                        .deadline
                        .get_or_insert_with(|| Box::pin(sleep(timeout)));
                    ready!(deadline.as_mut().poll(cx));
                    return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                }
                return Poll::Pending;
            }
            let added = window.filled().len();
            if added == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.got += added;
            if this.got == this.seen.len() {
                check_response(&this.seen)?;
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for V4Response<S> {
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

impl<S: Stream> Stream for V4Response<S> {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let V4Response {
            inner,
            seen,
            got,
            timeout,
            deadline,
        } = *self;
        let (read, write) = Box::new(inner).into_split();
        (
            Box::new(V4Response {
                inner: read,
                seen,
                got,
                timeout,
                deadline,
            }),
            write,
        )
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn the_answer_is_consumed_and_data_follows() {
        let (near, mut far) = duplex(64);
        let mut stream = V4Response::new(near, Duration::ZERO);
        far.write_all(&[4, 0xff, 0, b'o', b'k']).await.unwrap();
        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ok");
    }

    #[tokio::test]
    async fn the_halves_work_at_once_and_shutdown_keeps_reading() {
        let (near, mut far) = duplex(64);
        let stream: concord_common::BoxStream = Box::new(V4Response::new(near, Duration::ZERO));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        far.write_all(&[4, 0xff, 0, b'd', b'n']).await.unwrap();
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        let mut sent = Vec::new();
        let mut buf = [0u8; 8];
        while sent.len() < 2 {
            let n = far.read(&mut buf).await.unwrap();
            sent.extend_from_slice(&buf[..n]);
        }
        assert_eq!(sent, b"up");
        far.write_all(b"!").await.unwrap();
        far.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"dn!");
    }

    #[tokio::test]
    async fn a_failed_answer_is_an_error() {
        let (near, mut far) = duplex(64);
        let mut stream = V4Response::new(near, Duration::ZERO);
        far.write_all(&[4, 0xff, 0xff]).await.unwrap();
        let err = stream.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.to_string(), "connect failed");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(matches!(
            CoreError::of(&err),
            Some(CoreError::TargetRefused(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_server_times_out_after_the_request_timeout() {
        let (near, _far) = duplex(64);
        let mut stream = V4Response::new(near, Duration::from_secs(8));
        let err = stream.read(&mut [0u8; 4]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
