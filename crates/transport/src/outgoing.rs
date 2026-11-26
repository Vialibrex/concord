use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::AsyncWrite;

pub(crate) struct Outgoing {
    buf: Vec<u8>,
    off: usize,
    inflight: Option<usize>,
}

impl Outgoing {
    pub(crate) fn new() -> Self {
        Outgoing {
            buf: Vec::new(),
            off: 0,
            inflight: None,
        }
    }

    pub(crate) fn queue_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn poll_drain<S: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while let Some(pending) = self.buf.get(self.off..) {
            if pending.is_empty() {
                break;
            }
            let n = ready!(Pin::new(&mut *inner).poll_write(cx, pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.off += n;
        }
        self.buf.clear();
        self.off = 0;
        Poll::Ready(Ok(()))
    }

    /// Sends what is queued; `Some(n)` is a record [`Self::poll_write_record`] accepted as
    /// `n` bytes that has only now left, which the caller reports for its pending write.
    pub(crate) fn poll_settle<S: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<usize>>> {
        ready!(self.poll_drain(inner, cx))?;
        Poll::Ready(Ok(self.inflight.take()))
    }

    /// Returns `Ready` only once the record has been handed to `inner`, so a
    /// caller that never flushes still sees its data leave.
    pub(crate) fn poll_write_record<S: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
        data: &[u8],
        max: usize,
        encode: impl FnOnce(&mut Vec<u8>, &[u8]),
    ) -> Poll<io::Result<usize>> {
        if let Some(done) = self.inflight {
            ready!(self.poll_drain(inner, cx))?;
            self.inflight = None;
            return Poll::Ready(Ok(done));
        }
        if !self.buf.is_empty() {
            ready!(self.poll_drain(inner, cx))?;
        }
        let take = data.len().min(max);
        let Some(chunk) = data.get(..take).filter(|chunk| !chunk.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        encode(&mut self.buf, chunk);
        self.inflight = Some(take);
        ready!(self.poll_drain(inner, cx))?;
        self.inflight = None;
        Poll::Ready(Ok(take))
    }
}
