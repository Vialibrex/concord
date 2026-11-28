use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::BoxWrite;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::record_io::{ReadHalf, RecordIo};

use super::recv::Recv;
use super::send::Send;

/// The read half of a connection on the record layer.
pub struct TlsRead {
    pub(super) io: RecordIo<ReadHalf>,
    pub(super) recv: Recv,
}

impl TlsRead {
    /// The transport under the records; only meaningful at a record boundary.
    pub fn raw_mut(&mut self) -> &mut (dyn AsyncRead + std::marker::Send + Unpin + 'static) {
        self.io.get_mut().as_dyn()
    }

    pub fn at_record_boundary(&self) -> bool {
        self.io.at_record_boundary() && self.recv.at_boundary()
    }

    pub fn has_pending_plaintext(&self) -> bool {
        self.recv.has_plaintext()
    }

    pub fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        self.recv.drain_plaintext(out);
    }
}

impl AsyncRead for TlsRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.recv.poll_read(&mut this.io, cx, buf)
    }
}

/// The write half of a connection on the record layer.
pub struct TlsWrite {
    pub(super) io: BoxWrite,
    pub(super) send: Send,
}

impl TlsWrite {
    /// The transport under the records; flush first so no sealed record is left behind.
    pub fn raw_mut(&mut self) -> &mut BoxWrite {
        &mut self.io
    }
}

impl AsyncWrite for TlsWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.send.poll_write(&mut this.io, cx, &[data])
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.send.poll_write_vectored(&mut this.io, cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.send.poll_flush(&mut this.io, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.send.poll_shutdown(&mut this.io, cx)
    }
}
