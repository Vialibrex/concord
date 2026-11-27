use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{BoxRead, BoxWrite, Stream};

/// What a layer keeps for reading from the stream under it.
pub trait ReadLayer: Send + Unpin + 'static {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;
}

/// What a layer keeps for writing to the stream under it.
pub trait WriteLayer: Send + Unpin + 'static {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>>;

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>;

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>;
}

/// A layer whose two directions share nothing but the stream under it, so a split hands
/// each half its own state over the inner stream's own halves.
pub struct Layered<S, R, W> {
    io: S,
    read: R,
    write: W,
}

impl<S: Stream, R: ReadLayer, W: WriteLayer> Layered<S, R, W> {
    pub fn new(io: S, read: R, write: W) -> Self {
        Layered { io, read, write }
    }
}

impl<S: Stream, R: ReadLayer, W: WriteLayer> AsyncRead for Layered<S, R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.read.poll_read(&mut this.io, cx, buf)
    }
}

impl<S: Stream, R: ReadLayer, W: WriteLayer> AsyncWrite for Layered<S, R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write.poll_write(&mut this.io, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write.poll_flush(&mut this.io, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write.poll_shutdown(&mut this.io, cx)
    }
}

impl<S: Stream, R: ReadLayer, W: WriteLayer> Stream for Layered<S, R, W> {
    crate::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let Layered { io, read, write } = *self;
        let (io_read, io_write) = Box::new(io).into_split();
        (
            Box::new(ReadPart {
                io: io_read,
                layer: read,
            }),
            Box::new(WritePart {
                io: io_write,
                layer: write,
            }),
        )
    }
}

struct ReadPart<R> {
    io: BoxRead,
    layer: R,
}

impl<R: ReadLayer> AsyncRead for ReadPart<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.layer.poll_read(&mut this.io, cx, buf)
    }
}

struct WritePart<W> {
    io: BoxWrite,
    layer: W,
}

impl<W: WriteLayer> AsyncWrite for WritePart<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.layer.poll_write(&mut this.io, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.layer.poll_flush(&mut this.io, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.layer.poll_shutdown(&mut this.io, cx)
    }
}

/// Writes `out[*off..]` to `io`; clears both once all of it went out.
pub fn poll_drain<W: AsyncWrite + Unpin + ?Sized>(
    io: &mut W,
    cx: &mut Context<'_>,
    out: &mut Vec<u8>,
    off: &mut usize,
) -> Poll<io::Result<()>> {
    while let Some(pending) = out.get(*off..).filter(|pending| !pending.is_empty()) {
        let n = std::task::ready!(Pin::new(&mut *io).poll_write(cx, pending))?;
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        *off += n;
    }
    out.clear();
    *off = 0;
    Poll::Ready(Ok(()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    struct Upper;

    impl ReadLayer for Upper {
        fn poll_read<R: AsyncRead + Unpin + ?Sized>(
            &mut self,
            io: &mut R,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let start = buf.filled().len();
            std::task::ready!(Pin::new(io).poll_read(cx, buf))?;
            buf.filled_mut()
                .get_mut(start..)
                .unwrap_or_default()
                .make_ascii_uppercase();
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct Framed {
        out: Vec<u8>,
        off: usize,
    }

    impl WriteLayer for Framed {
        fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
            &mut self,
            io: &mut W,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            std::task::ready!(poll_drain(io, cx, &mut self.out, &mut self.off))?;
            self.out.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
            self.out.extend_from_slice(data);
            let _ = poll_drain(io, cx, &mut self.out, &mut self.off)?;
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
            &mut self,
            io: &mut W,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            std::task::ready!(poll_drain(io, cx, &mut self.out, &mut self.off))?;
            Pin::new(io).poll_flush(cx)
        }

        fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
            &mut self,
            io: &mut W,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            std::task::ready!(poll_drain(io, cx, &mut self.out, &mut self.off))?;
            Pin::new(io).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn the_halves_keep_their_own_layer_state() {
        let (near, far) = tokio::io::duplex(64);
        let layered: crate::BoxStream = Box::new(Layered::new(near, Upper, Framed::default()));
        let (mut read, mut write) = layered.into_split();
        let (mut far_read, mut far_write) = tokio::io::split(far);
        write.write_all(b"ab").await.unwrap();
        write.shutdown().await.unwrap();
        let mut sent = Vec::new();
        far_read.read_to_end(&mut sent).await.unwrap();
        assert_eq!(sent, [2, b'a', b'b']);
        far_write.write_all(b"xy").await.unwrap();
        far_write.shutdown().await.unwrap();
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"XY");
    }
}
