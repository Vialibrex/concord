use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::{BoxStream, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::record::RecordStream;

/// A REALITY connection past its handshake, on the shared TLS 1.3 record layer.
pub struct RealityStream {
    inner: RecordStream,
    group: u16,
}

impl RealityStream {
    pub(crate) fn new(inner: RecordStream, group: u16) -> Self {
        Self { inner, group }
    }

    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.inner.alpn()
    }

    pub fn key_exchange_group(&self) -> u16 {
        self.group
    }

    pub fn raw_mut(&mut self) -> &mut BoxStream {
        self.inner.raw_mut()
    }

    pub fn at_record_boundary(&self) -> bool {
        self.inner.at_record_boundary()
    }

    pub fn has_pending_plaintext(&self) -> bool {
        self.inner.has_pending_plaintext()
    }

    pub fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        self.inner.drain_plaintext(out);
    }

    pub(crate) fn set_unaligned(&mut self) {
        self.inner.set_unaligned();
    }

    pub(crate) fn into_record(self) -> RecordStream {
        self.inner
    }
}

impl AsyncRead for RealityStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Stream for RealityStream {
    concord_common::stream_policy!(inner; forward: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);
}
