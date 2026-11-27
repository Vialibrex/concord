use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::{BoxRead, BoxStream, BoxWrite, Stream, split_with_lock};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::boring_backend::{self, BoringStream};
use crate::buffered::{BufferedTls, failed_split, split_event};
use crate::reality::RealityStream;
use crate::record::{RecordStream, TlsRead, TlsWrite};

/// Vision keeps record boundaries for transport handoff. Ordinary unsplit connections
/// retain the upstream record engine until independent directions are requested.
pub enum TlsConn {
    Buffered(BufferedTls),
    /// rustls, and BoringSSL with an AEAD suite, past the handshake.
    Record(Box<RecordStream>),
    /// BoringSSL with a CBC suite, which only BoringSSL's record layer serves.
    Boring(Box<BoringStream>),
    Reality(Box<RealityStream>),
}

impl TlsConn {
    /// The handshakes that are not rustls's read aligned so that BoringSSL holds no bytes
    /// past them; past the handshake a caller that never takes the transport back reads
    /// freely.
    pub(crate) fn set_unaligned(&mut self) {
        match self {
            TlsConn::Buffered(stream) => stream.io_mut().set_unaligned(),
            TlsConn::Record(stream) => stream.set_unaligned(),
            TlsConn::Reality(stream) => stream.set_unaligned(),
            TlsConn::Boring(_) => {}
        }
    }

    /// Owned halves that keep access to the transport under the records; the connection
    /// back when BoringSSL still holds its records (a CBC suite).
    pub fn into_halves(self) -> Result<(TlsRead, TlsWrite), TlsConn> {
        match self {
            TlsConn::Record(stream) => Ok(stream.into_halves()),
            TlsConn::Reality(stream) => Ok(stream.into_record().into_halves()),
            other => Err(other),
        }
    }

    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        match self {
            TlsConn::Buffered(stream) => stream.alpn(),
            TlsConn::Record(stream) => stream.alpn(),
            TlsConn::Boring(stream) => stream.ssl().selected_alpn_protocol(),
            TlsConn::Reality(stream) => stream.negotiated_alpn(),
        }
    }

    pub fn is_tls13(&self) -> bool {
        match self {
            TlsConn::Buffered(stream) => stream.is_tls13(),
            TlsConn::Record(stream) => stream.is_tls13(),
            TlsConn::Boring(stream) => {
                stream.ssl().version2() == Some(boring::ssl::SslVersion::TLS1_3)
            }
            TlsConn::Reality(_) => true,
        }
    }

    pub fn raw_mut(&mut self) -> &mut BoxStream {
        match self {
            TlsConn::Buffered(stream) => stream.io_mut().get_mut(),
            TlsConn::Record(stream) => stream.raw_mut(),
            TlsConn::Boring(stream) => stream.get_mut().get_mut(),
            TlsConn::Reality(stream) => stream.raw_mut(),
        }
    }

    pub fn at_record_boundary(&self) -> bool {
        match self {
            TlsConn::Buffered(stream) => stream.io().at_record_boundary(),
            TlsConn::Record(stream) => stream.at_record_boundary(),
            TlsConn::Boring(stream) => stream.get_ref().at_record_boundary(),
            TlsConn::Reality(stream) => stream.at_record_boundary(),
        }
    }

    pub fn has_pending_plaintext(&mut self) -> bool {
        match self {
            TlsConn::Buffered(stream) => stream.has_plaintext(),
            TlsConn::Record(stream) => stream.has_pending_plaintext(),
            TlsConn::Boring(stream) => boring_backend::pending_plaintext(stream) > 0,
            TlsConn::Reality(stream) => stream.has_pending_plaintext(),
        }
    }

    pub fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        match self {
            TlsConn::Buffered(stream) => stream.drain_plaintext(out),
            TlsConn::Record(stream) => stream.drain_plaintext(out),
            TlsConn::Boring(stream) => boring_backend::drain_plaintext(stream, out),
            TlsConn::Reality(stream) => stream.drain_plaintext(out),
        }
    }
}

macro_rules! delegate {
    ($self:ident, $method:ident($($arg:expr),*)) => {
        match $self.get_mut() {
            TlsConn::Buffered(stream) => Pin::new(stream).$method($($arg),*),
            TlsConn::Record(stream) => Pin::new(&mut **stream).$method($($arg),*),
            TlsConn::Boring(stream) => Pin::new(&mut **stream).$method($($arg),*),
            TlsConn::Reality(stream) => Pin::new(&mut **stream).$method($($arg),*),
        }
    };
}

impl AsyncRead for TlsConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        delegate!(self, poll_read(cx, buf))
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        delegate!(self, poll_write(cx, data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, poll_shutdown(cx))
    }
}

impl Stream for TlsConn {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        match *self {
            TlsConn::Buffered(stream) => match stream.try_into_record() {
                Ok(Ok(stream)) => stream.into_split(),
                Ok(Err(err)) => failed_split(err),
                Err(stream) => split_with_lock(TlsConn::Buffered(stream)),
            },
            TlsConn::Record(stream) => {
                split_event("record", "native", "record-owner");
                stream.into_split()
            }
            TlsConn::Reality(stream) => {
                split_event("reality", "native", "record-owner");
                stream.into_split()
            }
            other => {
                split_event("boring", "fallback", "suite");
                split_with_lock(other)
            }
        }
    }
}
