use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::BoxStream;
use concord_common::layered::{Layered, ReadLayer, WriteLayer};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::http1::invalid;
use crate::outgoing::Outgoing;

const FIRST_PADDINGS: usize = 16;
const MAX_FRAME: usize = 65535;

pub(super) fn encode_request(version: u8, protocol: u8, padding: bool) -> Vec<u8> {
    let mut out = vec![version, protocol];
    if version == 1 {
        out.push(u8::from(padding));
        if padding {
            let len = 256 + rand::rng().random_range(0..512usize);
            out.extend_from_slice(&u16::try_from(len).unwrap_or(256).to_be_bytes());
            out.resize(out.len() + len, 0);
        }
    }
    out
}

/// Sends the session request together with the first bytes the session
/// writes, as one write.
pub(super) fn protocol_conn(inner: BoxStream, request: Vec<u8>) -> BoxStream {
    Box::new(Layered::new(
        inner,
        Passthrough,
        RequestFirst {
            request: Some(request),
            out: Outgoing::new(),
        },
    ))
}

pub(super) struct Passthrough;

impl ReadLayer for Passthrough {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(io).poll_read(cx, buf)
    }
}

struct RequestFirst {
    request: Option<Vec<u8>>,
    out: Outgoing,
}

impl WriteLayer for RequestFirst {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut request = self.request.take();
        let result = self
            .out
            .poll_write_record(io, cx, data, usize::MAX, |out, chunk| {
                if let Some(request) = request.take() {
                    out.extend_from_slice(&request);
                }
                out.extend_from_slice(chunk);
            });
        if request.is_some() {
            self.request = request;
        }
        result
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.out.poll_drain(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.out.poll_drain(io, cx))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

enum Read {
    Header { buf: [u8; 4], have: usize },
    Data { left: usize, padding: usize },
    Skip { left: usize },
}

/// The first sixteen frames each way carry random padding, as `paddingConn`.
pub(super) fn padding_conn(inner: BoxStream) -> BoxStream {
    Box::new(Layered::new(
        inner,
        PaddedRead {
            read: Read::Header {
                buf: [0; 4],
                have: 0,
            },
            frames: 0,
        },
        PaddedWrite {
            frames: 0,
            out: Outgoing::new(),
        },
    ))
}

struct PaddedRead {
    read: Read,
    frames: usize,
}

impl PaddedRead {
    fn after_frame(&mut self) {
        self.read = Read::Header {
            buf: [0; 4],
            have: 0,
        };
    }
}

struct PaddedWrite {
    frames: usize,
    out: Outgoing,
}

impl ReadLayer for PaddedRead {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        loop {
            if this.frames >= FIRST_PADDINGS && matches!(this.read, Read::Header { have: 0, .. }) {
                return Pin::new(&mut *io).poll_read(cx, buf);
            }
            match &mut this.read {
                Read::Header { buf: head, have } => {
                    let Some(window) = head.get_mut(*have..) else {
                        return Poll::Ready(Err(invalid("padding header window")));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(if *have == 0 {
                            Ok(())
                        } else {
                            Err(io::ErrorKind::UnexpectedEof.into())
                        });
                    }
                    *have += got;
                    if *have == head.len() {
                        let [d0, d1, p0, p1] = *head;
                        this.read = Read::Data {
                            left: usize::from(u16::from_be_bytes([d0, d1])),
                            padding: usize::from(u16::from_be_bytes([p0, p1])),
                        };
                        this.frames += 1;
                    }
                }
                Read::Data { left, padding } => {
                    if *left == 0 {
                        this.read = Read::Skip { left: *padding };
                        continue;
                    }
                    let take = (*left).min(buf.remaining());
                    if take == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let target = buf.initialize_unfilled_to(take);
                    let mut window = ReadBuf::new(target);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    buf.advance(got);
                    *left -= got;
                    return Poll::Ready(Ok(()));
                }
                Read::Skip { left } => {
                    if *left == 0 {
                        this.after_frame();
                        continue;
                    }
                    let mut sink = [0u8; 512];
                    let take = (*left).min(sink.len());
                    let Some(window) = sink.get_mut(..take) else {
                        return Poll::Ready(Err(invalid("padding skip window")));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *left -= got;
                }
            }
        }
    }
}

impl WriteLayer for PaddedWrite {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self;
        let frames = &mut this.frames;
        this.out
            .poll_write_record(io, cx, data, MAX_FRAME, |out, chunk| {
                if *frames < FIRST_PADDINGS {
                    *frames += 1;
                    let mut rng = rand::rng();
                    let padding = 256 + rng.random_range(0..512usize);
                    let [d0, d1] = u16::try_from(chunk.len()).unwrap_or(u16::MAX).to_be_bytes();
                    let [p0, p1] = u16::try_from(padding).unwrap_or(256).to_be_bytes();
                    out.extend_from_slice(&[d0, d1, p0, p1]);
                    out.extend_from_slice(chunk);
                    let start = out.len();
                    out.resize(start + padding, 0);
                    if let Some(tail) = out.get_mut(start..) {
                        rng.fill(tail);
                    }
                } else {
                    out.extend_from_slice(chunk);
                }
            })
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        ready!(this.out.poll_drain(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        ready!(this.out.poll_drain(io, cx))?;
        Pin::new(io).poll_shutdown(cx)
    }
}
