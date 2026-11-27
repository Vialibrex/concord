use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::stream_buffer::{StreamBuffer, poll_write_buffer};
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const FRAMES: u32 = 8;
const HEADER: usize = 3;
const MAX_PADDING: usize = 255;
const MAX_FRAME: usize = 64 * 1024;
const SHORT_PAYLOAD: usize = 100;
const SPLIT_ABOVE: usize = 200;
const SPLIT_BELOW: usize = 1024;
const SPLIT_CHUNK_MIN: usize = 100;
const SPLIT_CHUNK_MAX: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PaddingType {
    None,
    Variant1,
}

impl PaddingType {
    pub(super) fn parse(text: &str) -> Option<PaddingType> {
        match text {
            "0" => Some(PaddingType::None),
            "1" => Some(PaddingType::Variant1),
            _ => None,
        }
    }

    pub(super) fn wrap(self, stream: BoxStream) -> BoxStream {
        match self {
            PaddingType::None => stream,
            PaddingType::Variant1 => Box::new(Padded {
                inner: stream,
                unpad: Unpad::default(),
                pad: Pad::default(),
            }),
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum ReadState {
    #[default]
    LengthHigh,
    LengthLow,
    PaddingLength,
    Payload,
    Padding,
}

/// The receiving half of Variant1: strips the first frames in place, then passes bytes through.
#[derive(Default)]
struct Unpad {
    frames: u32,
    state: ReadState,
    payload: usize,
    padding: usize,
}

impl Unpad {
    fn done(&self) -> bool {
        self.frames >= FRAMES && self.state == ReadState::LengthHigh
    }

    /// Compacts the payload of `data` to its front and returns its length; zero means the
    /// bytes were all framing, not EOF.
    fn strip(&mut self, data: &mut [u8]) -> usize {
        let (mut read, mut write) = (0, 0);
        while let Some(&byte) = data.get(read) {
            match self.state {
                ReadState::LengthHigh if self.frames >= FRAMES => {
                    data.copy_within(read.., write);
                    return write + data.len() - read;
                }
                ReadState::LengthHigh => {
                    self.payload = usize::from(byte) << 8;
                    self.state = ReadState::LengthLow;
                    read += 1;
                }
                ReadState::LengthLow => {
                    self.payload |= usize::from(byte);
                    self.state = ReadState::PaddingLength;
                    read += 1;
                }
                ReadState::PaddingLength => {
                    self.padding = usize::from(byte);
                    self.state = ReadState::Payload;
                    read += 1;
                }
                ReadState::Payload => {
                    let take = self.payload.min(data.len() - read);
                    data.copy_within(read..read + take, write);
                    (read, write) = (read + take, write + take);
                    self.payload -= take;
                    if self.payload == 0 {
                        self.state = ReadState::Padding;
                    }
                }
                ReadState::Padding => {
                    let take = self.padding.min(data.len() - read);
                    read += take;
                    self.padding -= take;
                }
            }
            if self.state == ReadState::Padding && self.padding == 0 {
                self.frames += 1;
                self.state = ReadState::LengthHigh;
            }
        }
        write
    }

    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        inner: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.done() {
            return Pin::new(inner).poll_read(cx, buf);
        }
        loop {
            let unfilled = buf.initialize_unfilled();
            let mut raw = ReadBuf::new(unfilled);
            ready!(Pin::new(&mut *inner).poll_read(cx, &mut raw))?;
            let read = raw.filled().len();
            if read == 0 {
                return Poll::Ready(Ok(()));
            }
            let payload = self.strip(unfilled.get_mut(..read).unwrap_or_default());
            if payload > 0 {
                buf.advance(payload);
                return Poll::Ready(Ok(()));
            }
        }
    }
}

/// A frame encoded but not yet all written; its payload counts as written once it is.
struct Framed {
    bytes: Vec<u8>,
    sent: usize,
    payload: usize,
    split: bool,
}

/// The sending half of Variant1, shaped as naiveproxy shapes the client's writes to the server.
#[derive(Default)]
struct Pad {
    frames: u32,
    framed: Option<Framed>,
}

impl Pad {
    fn done(&self) -> bool {
        self.frames >= FRAMES && self.framed.is_none()
    }

    fn frame(data: &[u8]) -> Framed {
        let mut rng = rand::rng();
        let padding = if data.len() < SHORT_PAYLOAD {
            rng.random_range(MAX_PADDING - data.len()..=MAX_PADDING)
        } else {
            rng.random_range(0..=MAX_PADDING)
        };
        let payload = data.len().min(MAX_FRAME - HEADER - padding);
        let mut bytes = Vec::with_capacity(HEADER + payload + padding);
        bytes.extend_from_slice(&u16::try_from(payload).unwrap_or(u16::MAX).to_be_bytes());
        bytes.push(u8::try_from(padding).unwrap_or(u8::MAX));
        bytes.extend_from_slice(data.get(..payload).unwrap_or_default());
        bytes.resize(HEADER + payload + padding, 0);
        Framed {
            bytes,
            sent: 0,
            payload,
            split: payload > SPLIT_ABOVE && payload < SPLIT_BELOW,
        }
    }

    fn poll_drain<W: AsyncWrite + Unpin + ?Sized>(
        framed: &mut Framed,
        inner: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while framed.sent < framed.bytes.len() {
            let mut end = framed.bytes.len();
            if framed.split {
                let chunk = rand::rng().random_range(SPLIT_CHUNK_MIN..=SPLIT_CHUNK_MAX);
                end = end.min(framed.sent + chunk);
            }
            let chunk = framed.bytes.get(framed.sent..end).unwrap_or_default();
            let written = ready!(Pin::new(&mut *inner).poll_write(cx, chunk))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            framed.sent += written;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        inner: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.done() {
            return Pin::new(inner).poll_write(cx, data);
        }
        if self.framed.is_none() {
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            self.framed = Some(Pad::frame(data));
            self.frames += 1;
        }
        let Some(framed) = self.framed.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        ready!(Pad::poll_drain(framed, inner, cx))?;
        let payload = framed.payload;
        self.framed = None;
        Poll::Ready(Ok(payload))
    }

    fn poll_settle<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        inner: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.framed.as_mut() {
            Some(framed) => Pad::poll_drain(framed, inner, cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

/// A stream whose first frames each way carry naiveproxy's Variant1 padding.
struct Padded {
    inner: BoxStream,
    unpad: Unpad,
    pad: Pad,
}

impl AsyncRead for Padded {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.unpad.poll_read(&mut this.inner, cx, buf)
    }
}

impl AsyncWrite for Padded {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.pad.poll_write(&mut this.inner, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.pad.poll_settle(&mut this.inner, cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.pad.poll_settle(&mut this.inner, cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl Stream for Padded {
    concord_common::stream_policy!(inner;
        forward: peer_addr;
        own: into_split, poll_write_buffer;
        default: read_requirements, write_requirements, poll_read_buffer, raw_socket, tcp, needs_handshake, direct, into_tcp);

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        if self.pad.done() {
            self.inner.poll_write_buffer(cx, buffer)
        } else {
            poll_write_buffer(self, cx, buffer)
        }
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let Padded { inner, unpad, pad } = *self;
        let (read, write) = inner.into_split();
        (
            Box::new(Half {
                inner: read,
                state: unpad,
            }),
            Box::new(Half {
                inner: write,
                state: pad,
            }),
        )
    }
}

struct Half<T, S> {
    inner: T,
    state: S,
}

impl AsyncRead for Half<BoxRead, Unpad> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.state.poll_read(&mut this.inner, cx, buf)
    }
}

impl AsyncWrite for Half<BoxWrite, Pad> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.state.poll_write(&mut this.inner, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.state.poll_settle(&mut this.inner, cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.state.poll_settle(&mut this.inner, cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
