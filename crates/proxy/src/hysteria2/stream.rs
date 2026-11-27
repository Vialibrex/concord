use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::{BoxRead, BoxWrite, CoreError, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::wire::{MAX_RESPONSE_HEAD, Response, parse_tcp_response};

enum Phase {
    Header(Vec<u8>),
    Body { leftover: Vec<u8>, pos: usize },
}

/// Reads the server's answer to the TCP request before handing out any data.
pub(crate) struct Hy2Stream<S> {
    inner: S,
    phase: Phase,
}

impl<S> Hy2Stream<S> {
    pub(crate) fn new(inner: S) -> Self {
        Hy2Stream {
            inner,
            phase: Phase::Header(Vec::new()),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Hy2Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.phase {
                Phase::Body { leftover, pos } => {
                    if let Some(rest) = leftover.get(*pos..).filter(|rest| !rest.is_empty()) {
                        let take = rest.len().min(out.remaining());
                        out.put_slice(rest.get(..take).unwrap_or_default());
                        *pos += take;
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut this.inner).poll_read(cx, out);
                }
                Phase::Header(head) => {
                    let mut chunk = [0u8; 2048];
                    let mut read = ReadBuf::new(&mut chunk);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
                    let got = read.filled();
                    if got.is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    head.extend_from_slice(got);
                    match parse_tcp_response(head)? {
                        Some((Response::Ok, used)) => {
                            let leftover = head.get(used..).unwrap_or_default().to_vec();
                            this.phase = Phase::Body { leftover, pos: 0 };
                        }
                        Some((Response::Refused(message), _)) => {
                            return Poll::Ready(Err(CoreError::TargetRefused(format!(
                                "remote error: {message}"
                            ))
                            .into()));
                        }
                        None if head.len() > MAX_RESPONSE_HEAD => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "oversized hysteria2 response",
                            )));
                        }
                        None => {}
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Hy2Stream<S> {
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

impl<S: Stream> Stream for Hy2Stream<S> {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let Hy2Stream { inner, phase } = *self;
        let (read, write) = Box::new(inner).into_split();
        (Box::new(Hy2Stream { inner: read, phase }), write)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn data_behind_the_response_is_not_lost() {
        let (near, mut far) = duplex(4096);
        let mut stream = Hy2Stream::new(near);
        far.write_all(&[0, 0, 2, b'p', b'p', b'h', b'i'])
            .await
            .unwrap();
        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hi");
    }

    #[tokio::test]
    async fn the_halves_work_at_once_and_shutdown_keeps_reading() {
        let (near, mut far) = duplex(4096);
        let stream: concord_common::BoxStream = Box::new(Hy2Stream::new(near));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        far.write_all(&[0, 0, 0, b'd', b'n']).await.unwrap();
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
        let mut stream = Hy2Stream::new(near);
        far.write_all(&[1, 3, b'n', b'o', b'!', 0]).await.unwrap();
        let err = stream.read(&mut [0u8; 8]).await.unwrap_err();
        assert_eq!(err.to_string(), "remote error: no!");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(matches!(
            CoreError::of(&err),
            Some(CoreError::TargetRefused(_))
        ));
    }

    #[tokio::test]
    async fn a_response_split_across_reads_still_parses() {
        let (near, mut far) = duplex(4096);
        let mut stream = Hy2Stream::new(near);
        let reader = tokio::spawn(async move {
            let mut got = [0u8; 3];
            stream.read_exact(&mut got).await.unwrap();
            got
        });
        far.write_all(&[0]).await.unwrap();
        tokio::task::yield_now().await;
        far.write_all(&[0, 1, b'x']).await.unwrap();
        tokio::task::yield_now().await;
        far.write_all(b"abc").await.unwrap();
        assert_eq!(&reader.await.unwrap(), b"abc");
    }
}
