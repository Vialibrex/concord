use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxWrite, CoreError, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::wire::{RESPONSE_LEN, parse_response_head};

enum Phase {
    Head {
        buf: [u8; RESPONSE_LEN],
        filled: usize,
    },
    Message {
        ok: bool,
        buf: Vec<u8>,
        filled: usize,
    },
    Open,
}

/// With `fast-open` the request leaves before the server has answered; the
/// answer is read, and a refusal reported, on the first read.
pub(super) struct FastOpen<S> {
    inner: S,
    phase: Phase,
}

impl<S> FastOpen<S> {
    pub(super) fn new(inner: S) -> Self {
        FastOpen {
            inner,
            phase: Phase::Head {
                buf: [0; RESPONSE_LEN],
                filled: 0,
            },
        }
    }
}

fn refused(message: &[u8]) -> io::Error {
    CoreError::TargetRefused(format!(
        "connection rejected: {}",
        String::from_utf8_lossy(message)
    ))
    .into()
}

fn fill<S: AsyncRead + Unpin>(
    inner: &mut S,
    cx: &mut Context<'_>,
    buf: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<()>> {
    while *filled < buf.len() {
        let Some(rest) = buf.get_mut(*filled..) else {
            break;
        };
        let mut read = ReadBuf::new(rest);
        ready!(Pin::new(&mut *inner).poll_read(cx, &mut read))?;
        let got = read.filled().len();
        if got == 0 {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        *filled += got;
    }
    Poll::Ready(Ok(()))
}

impl<S: AsyncRead + Unpin> AsyncRead for FastOpen<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.phase {
                Phase::Open => return Pin::new(&mut this.inner).poll_read(cx, out),
                Phase::Head { buf, filled } => {
                    ready!(fill(&mut this.inner, cx, buf, filled))?;
                    let (response, message_len) = parse_response_head(buf);
                    if message_len == 0 {
                        if !response.ok {
                            return Poll::Ready(Err(refused(b"")));
                        }
                        this.phase = Phase::Open;
                    } else {
                        this.phase = Phase::Message {
                            ok: response.ok,
                            buf: vec![0; message_len],
                            filled: 0,
                        };
                    }
                }
                Phase::Message { ok, buf, filled } => {
                    ready!(fill(&mut this.inner, cx, buf, filled))?;
                    if !*ok {
                        return Poll::Ready(Err(refused(buf)));
                    }
                    this.phase = Phase::Open;
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FastOpen<S> {
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

impl<S: Stream> Stream for FastOpen<S> {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let FastOpen { inner, phase } = *self;
        let (read, write) = Box::new(inner).into_split();
        (Box::new(FastOpen { inner: read, phase }), write)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn data_behind_the_response_is_kept() {
        let (near, mut far) = duplex(4096);
        let mut stream = FastOpen::new(near);
        far.write_all(&[1, 0, 0, 0, 0, 0, 2, b'o', b'k', b'h', b'i'])
            .await
            .unwrap();
        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi");
    }

    #[tokio::test]
    async fn the_halves_work_at_once_and_shutdown_keeps_reading() {
        let (near, mut far) = duplex(4096);
        let stream: concord_common::BoxStream = Box::new(FastOpen::new(near));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        far.write_all(&[1, 0, 0, 0, 0, 0, 0, b'd', b'n'])
            .await
            .unwrap();
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
    async fn a_refusal_surfaces_on_the_first_read() {
        let (near, mut far) = duplex(4096);
        let mut stream = FastOpen::new(near);
        far.write_all(&[0, 0, 0, 0, 0, 0, 3, b'n', b'o', b'!'])
            .await
            .unwrap();
        let err = stream.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.to_string(), "connection rejected: no!");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(matches!(
            CoreError::of(&err),
            Some(CoreError::TargetRefused(_))
        ));
    }

    #[tokio::test]
    async fn a_response_trickling_in_still_parses() {
        let (near, mut far) = duplex(4096);
        let mut stream = FastOpen::new(near);
        let reader = tokio::spawn(async move {
            let mut got = [0u8; 3];
            stream.read_exact(&mut got).await.unwrap();
            got
        });
        far.write_all(&[1, 0, 0]).await.unwrap();
        tokio::task::yield_now().await;
        far.write_all(&[0, 0, 0, 0]).await.unwrap();
        tokio::task::yield_now().await;
        far.write_all(b"abc").await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"abc");
    }

    #[tokio::test]
    async fn writes_go_through_before_the_answer() {
        let (near, mut far) = duplex(4096);
        let mut stream = FastOpen::new(near);
        stream.write_all(b"early").await.unwrap();
        let mut got = [0u8; 5];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"early");
    }
}
