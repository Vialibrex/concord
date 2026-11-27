use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::layered::{Layered, ReadLayer, WriteLayer};
use concord_common::{Address, BoxStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::padding::Passthrough;
use crate::http1::invalid;
use crate::outgoing::Outgoing;

const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;
const STATUS_SUCCESS: u8 = 0;
const STATUS_ERROR: u8 = 1;

pub(super) fn mux_destination() -> Address {
    Address::Domain("sp.mux.sing-box.arpa".into(), 444)
}

pub(super) fn put_address(out: &mut Vec<u8>, address: &Address) -> io::Result<()> {
    match address {
        Address::Socket(SocketAddr::V4(addr)) => {
            out.push(0x01);
            out.extend_from_slice(&addr.ip().octets());
        }
        Address::Socket(SocketAddr::V6(addr)) => {
            out.push(0x04);
            out.extend_from_slice(&addr.ip().octets());
        }
        Address::Domain(host, _) => {
            let len = u8::try_from(host.len()).map_err(|_| invalid("domain name too long"))?;
            out.push(0x03);
            out.push(len);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Tcp,
    Udp,
    UdpAddr,
}

pub(super) fn encode_stream_request(kind: Kind, destination: &Address) -> io::Result<Vec<u8>> {
    let flags = match kind {
        Kind::Tcp => 0,
        Kind::Udp => FLAG_UDP,
        Kind::UdpAddr => FLAG_UDP | FLAG_ADDR,
    };
    let mut out = flags.to_be_bytes().to_vec();
    put_address(&mut out, destination)?;
    Ok(out)
}

enum Response {
    Status,
    Length { value: u64, shift: u32 },
    Message { buf: Vec<u8>, left: usize },
    Done,
}

/// A mux stream that sends the destination with its first write (alone, for a
/// zero-length write) and reads the server's status byte before the first payload byte.
pub(super) type ClientStream = Layered<BoxStream, ServerStatus, HeadFirst>;

/// A stream a client opened, which answers with the success status before its first byte,
/// as sing-mux's `serverConn` does (`server_conn.go:36-50`). It never sends the error
/// status mihomo writes when the destination cannot be reached (`HandshakeFailure`,
/// `:25-34`): such a stream closes without one, and the client reads an early end.
pub(super) fn server_stream(inner: BoxStream) -> BoxStream {
    Box::new(Layered::new(
        inner,
        Passthrough,
        HeadFirst {
            request: Some(vec![STATUS_SUCCESS]),
            out: Outgoing::new(),
        },
    ))
}

pub(super) fn client_stream(
    inner: BoxStream,
    kind: Kind,
    destination: &Address,
) -> io::Result<ClientStream> {
    Ok(Layered::new(
        inner,
        ServerStatus {
            response: Response::Status,
        },
        HeadFirst {
            request: Some(encode_stream_request(kind, destination)?),
            out: Outgoing::new(),
        },
    ))
}

pub(super) struct ServerStatus {
    response: Response,
}

/// Sends `request` with the first write, or alone for a zero-length write or a shutdown.
pub(super) struct HeadFirst {
    request: Option<Vec<u8>>,
    out: Outgoing,
}

impl ReadLayer for ServerStatus {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        loop {
            match &mut this.response {
                Response::Done => return Pin::new(&mut *io).poll_read(cx, buf),
                Response::Status => {
                    let status = ready!(poll_byte(io, cx))?;
                    this.response = if status == STATUS_ERROR {
                        Response::Length { value: 0, shift: 0 }
                    } else {
                        Response::Done
                    };
                }
                Response::Length { value, shift } => {
                    let byte = ready!(poll_byte(io, cx))?;
                    if *shift > 63 {
                        return Poll::Ready(Err(invalid("error message length overflow")));
                    }
                    *value |= u64::from(byte & 0x7F) << *shift;
                    *shift += 7;
                    if byte & 0x80 == 0 {
                        let left = usize::try_from(*value)
                            .map_err(|_| invalid("error message length overflow"))?;
                        this.response = Response::Message {
                            buf: Vec::new(),
                            left,
                        };
                    }
                }
                Response::Message { buf: message, left } => {
                    if *left == 0 {
                        let text = String::from_utf8_lossy(message).into_owned();
                        return Poll::Ready(Err(io::Error::other(format!("remote error: {text}"))));
                    }
                    let byte = ready!(poll_byte(io, cx))?;
                    message.push(byte);
                    *left -= 1;
                }
            }
        }
    }
}

fn poll_byte<R: AsyncRead + Unpin + ?Sized>(
    inner: &mut R,
    cx: &mut Context<'_>,
) -> Poll<io::Result<u8>> {
    let mut byte = [0u8; 1];
    let mut window = ReadBuf::new(&mut byte);
    ready!(Pin::new(inner).poll_read(cx, &mut window))?;
    match window.filled().first() {
        Some(value) => Poll::Ready(Ok(*value)),
        None => Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
    }
}

impl WriteLayer for HeadFirst {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self;
        if data.is_empty() {
            if let Some(request) = this.request.take() {
                this.out.queue_raw(&request);
            }
            ready!(this.out.poll_drain(io, cx))?;
            return Poll::Ready(Ok(0));
        }
        if this.request.is_none() {
            if let Some(done) = ready!(this.out.poll_settle(io, cx))? {
                return Poll::Ready(Ok(done));
            }
            return Pin::new(io).poll_write(cx, data);
        }
        let mut request = this.request.take();
        let result = this
            .out
            .poll_write_record(io, cx, data, usize::MAX, |out, chunk| {
                if let Some(request) = request.take() {
                    out.extend_from_slice(&request);
                }
                out.extend_from_slice(chunk);
            });
        if request.is_some() {
            this.request = request;
        }
        result
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
        if let Some(request) = this.request.take() {
            this.out.queue_raw(&request);
        }
        ready!(this.out.poll_drain(io, cx))?;
        Pin::new(io).poll_shutdown(cx)
    }
}
