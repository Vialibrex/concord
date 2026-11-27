use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, ready};

use bytes::{Buf, BytesMut};
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const READ_CHUNK: usize = 32 * 1024;

/// One SSR layer. `encode` frames outbound bytes; `decode` turns inbound bytes into
/// payload and may ask for bytes to be sent back, which the TLS and random-head
/// obfuscations need to finish their handshakes.
pub(super) trait Layer: Send + Unpin + 'static {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()>;

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        reply: &mut Vec<u8>,
    ) -> io::Result<()>;

    /// True while `decode` may still ask for a reply and `encode` depends on the answer.
    fn handshaking(&self) -> bool {
        false
    }

    /// The decode half and the encode half of a layer that is not handshaking.
    fn split(self) -> (BoxLayer, BoxLayer)
    where
        Self: Sized;
}

pub(super) type BoxLayer = Box<dyn Layer>;

pub(super) struct CodecStream<S, L> {
    inner: S,
    layer: L,
    out: Vec<u8>,
    sent: usize,
    input: BytesMut,
    decoded: BytesMut,
}

impl<S, L> CodecStream<S, L> {
    pub(super) fn new(inner: S, layer: L) -> Self {
        CodecStream {
            inner,
            layer,
            out: Vec::new(),
            sent: 0,
            input: BytesMut::new(),
            decoded: BytesMut::new(),
        }
    }

    pub(super) fn layer(&self) -> &L {
        &self.layer
    }
}

impl<S: AsyncWrite + Unpin, L> CodecStream<S, L> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(rest) = self.out.get(self.sent..).filter(|rest| !rest.is_empty()) {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, rest))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.out.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, L: Layer> AsyncRead for CodecStream<S, L> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.out.is_empty()
            && let Poll::Ready(Err(err)) = this.drain(cx)
        {
            return Poll::Ready(Err(err));
        }
        loop {
            if !this.decoded.is_empty() {
                let take = this.decoded.len().min(buf.remaining());
                buf.put_slice(this.decoded.get(..take).unwrap_or_default());
                this.decoded.advance(take);
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; READ_CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            this.input.extend_from_slice(read.filled());
            let mut reply = Vec::new();
            this.layer
                .decode(&mut this.input, &mut this.decoded, &mut reply)?;
            if !reply.is_empty() {
                this.out.extend_from_slice(&reply);
                if let Poll::Ready(Err(err)) = this.drain(cx) {
                    return Poll::Ready(Err(err));
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, L: Layer> AsyncWrite for CodecStream<S, L> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        this.layer.encode(&mut this.out, data)?;
        if let Poll::Ready(Err(err)) = this.drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl<S: Stream, L: Layer> Stream for CodecStream<S, L> {
    concord_common::stream_policy!(inner;
        forward: peer_addr;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            tcp, needs_handshake, direct, into_tcp;
        own: into_split);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let CodecStream {
            inner,
            layer,
            out,
            sent,
            input,
            decoded,
        } = *self;
        let (io_read, io_write) = Box::new(inner).into_split();
        let side = WriteSide {
            io: io_write,
            out,
            sent,
        };
        if layer.handshaking() {
            let shared = Arc::new(Shared {
                settled: AtomicBool::new(false),
                slot: Mutex::new(Slot {
                    layer: Some(layer),
                    write: Some(side),
                    encode: None,
                }),
            });
            return (
                Box::new(ReadPart {
                    io: io_read,
                    mode: ReadMode::Shared(shared.clone()),
                    input,
                    decoded,
                }),
                Box::new(WritePart {
                    mode: WriteMode::Shared(shared),
                }),
            );
        }
        let (decode, encode) = layer.split();
        (
            Box::new(ReadPart::<L> {
                io: io_read,
                mode: ReadMode::Free(decode),
                input,
                decoded,
            }),
            Box::new(WritePart::<L> {
                mode: WriteMode::Free(Free {
                    side,
                    layer: encode,
                }),
            }),
        )
    }
}

struct WriteSide {
    io: BoxWrite,
    out: Vec<u8>,
    sent: usize,
}

impl WriteSide {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(rest) = self.out.get(self.sent..).filter(|rest| !rest.is_empty()) {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, rest))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.out.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        layer: &mut dyn Layer,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.drain(cx))?;
        layer.encode(&mut self.out, data)?;
        if let Poll::Ready(Err(err)) = self.drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(data.len()))
    }
}

/// While a layer handshakes, its reply has to leave in order with the writer's bytes, so
/// the layer and the write side stay together behind a lock that the read half takes to
/// decode and the write half takes to encode. Once the layer is settled it is split, the
/// write half takes its side out and neither half locks again.
struct Shared<L> {
    settled: AtomicBool,
    slot: Mutex<Slot<L>>,
}

struct Slot<L> {
    layer: Option<L>,
    write: Option<WriteSide>,
    encode: Option<BoxLayer>,
}

impl<L> Shared<L> {
    fn slot(&self) -> MutexGuard<'_, Slot<L>> {
        lock(&self.slot)
    }
}

impl<L: Layer> Shared<L> {
    fn settle(&self, cx: &mut Context<'_>) -> io::Result<Option<BoxLayer>> {
        let mut slot = self.slot();
        let Slot {
            layer,
            write,
            encode,
        } = &mut *slot;
        let Some(write) = write.as_mut() else {
            return Ok(None);
        };
        if !write.out.is_empty()
            && let Poll::Ready(Err(err)) = write.drain(cx)
        {
            return Err(err);
        }
        let ready = layer.as_ref().is_some_and(|layer| !layer.handshaking());
        if !ready || !write.out.is_empty() {
            return Ok(None);
        }
        let Some(layer) = layer.take() else {
            return Ok(None);
        };
        let (decode, enc) = layer.split();
        *encode = Some(enc);
        self.settled.store(true, Ordering::Release);
        Ok(Some(decode))
    }
}

enum ReadMode<L> {
    Shared(Arc<Shared<L>>),
    Free(BoxLayer),
}

struct ReadPart<L> {
    io: BoxRead,
    mode: ReadMode<L>,
    input: BytesMut,
    decoded: BytesMut,
}

impl<L: Layer> ReadPart<L> {
    fn decode(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let mut reply = Vec::new();
        let shared = match &mut self.mode {
            ReadMode::Free(layer) => {
                layer.decode(&mut self.input, &mut self.decoded, &mut reply)?;
                if reply.is_empty() {
                    return Ok(());
                }
                return Err(io::Error::other("a settled ssr layer asked to reply"));
            }
            ReadMode::Shared(shared) => shared.clone(),
        };
        {
            let mut guard = shared.slot();
            let slot = &mut *guard;
            if let (Some(layer), Some(write)) = (slot.layer.as_mut(), slot.write.as_mut()) {
                layer.decode(&mut self.input, &mut self.decoded, &mut reply)?;
                if !reply.is_empty() {
                    write.out.extend_from_slice(&reply);
                    if let Poll::Ready(Err(err)) = write.drain(cx) {
                        return Err(err);
                    }
                }
            }
        }
        if let Some(layer) = shared.settle(cx)? {
            self.mode = ReadMode::Free(layer);
        }
        Ok(())
    }
}

impl<L: Layer> AsyncRead for ReadPart<L> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let ReadMode::Shared(shared) = &this.mode
            && let Some(layer) = shared.settle(cx)?
        {
            this.mode = ReadMode::Free(layer);
        }
        loop {
            if !this.decoded.is_empty() {
                let take = this.decoded.len().min(buf.remaining());
                buf.put_slice(this.decoded.get(..take).unwrap_or_default());
                this.decoded.advance(take);
                return Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; READ_CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut read))?;
            if read.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            this.input.extend_from_slice(read.filled());
            this.decode(cx)?;
        }
    }
}

struct Free {
    side: WriteSide,
    layer: BoxLayer,
}

enum WriteMode<L> {
    Shared(Arc<Shared<L>>),
    Free(Free),
}

struct WritePart<L> {
    mode: WriteMode<L>,
}

impl<L: Layer> WritePart<L> {
    fn with<T>(
        &mut self,
        f: impl FnOnce(&mut WriteSide, &mut dyn Layer) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if let WriteMode::Shared(shared) = &self.mode {
            let shared = shared.clone();
            if shared.settled.load(Ordering::Acquire) {
                let mut slot = shared.slot();
                if let (Some(side), Some(layer)) = (slot.write.take(), slot.encode.take()) {
                    self.mode = WriteMode::Free(Free { side, layer });
                }
            } else {
                let mut guard = shared.slot();
                let slot = &mut *guard;
                if let (Some(layer), Some(side)) = (slot.layer.as_mut(), slot.write.as_mut()) {
                    return f(side, layer);
                }
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
        }
        match &mut self.mode {
            WriteMode::Free(free) => f(&mut free.side, &mut *free.layer),
            WriteMode::Shared(_) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
}

impl<L: Layer> AsyncWrite for WritePart<L> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with(|side, layer| side.poll_write(cx, layer, data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().with(|side, _| {
            ready!(side.drain(cx))?;
            Pin::new(&mut side.io).poll_flush(cx)
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().with(|side, _| {
            ready!(side.drain(cx))?;
            Pin::new(&mut side.io).poll_shutdown(cx)
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    /// Answers the first input with a reply larger than the test transport takes at once.
    struct Replying {
        handshaking: bool,
    }

    impl Layer for Replying {
        fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
            out.extend_from_slice(data);
            Ok(())
        }

        fn decode(
            &mut self,
            input: &mut BytesMut,
            decoded: &mut BytesMut,
            reply: &mut Vec<u8>,
        ) -> io::Result<()> {
            if self.handshaking {
                reply.extend_from_slice(&[9; 100]);
                self.handshaking = false;
            }
            decoded.extend_from_slice(&input.split());
            Ok(())
        }

        fn handshaking(&self) -> bool {
            self.handshaking
        }

        fn split(self) -> (BoxLayer, BoxLayer) {
            (
                Box::new(Replying { handshaking: false }),
                Box::new(Replying { handshaking: false }),
            )
        }
    }

    #[tokio::test]
    async fn a_failed_handshake_reply_fails_the_read_on_both_shapes() {
        for split in [false, true] {
            let (near, mut far) = duplex(16);
            let stream = CodecStream::new(near, Replying { handshaking: true });
            let mut read: BoxRead = if split {
                Box::new(stream).into_split().0
            } else {
                Box::new(stream)
            };
            far.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            read.read_exact(&mut buf).await.unwrap();
            drop(far);
            let err = read.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "split {split}");
        }
    }
}
