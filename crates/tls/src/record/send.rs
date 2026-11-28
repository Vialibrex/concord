use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, ready};

use rustls::crypto::cipher::{MessageEncrypter, OutboundChunks, OutboundPlainMessage};
use rustls::{ContentType, HandshakeType, ProtocolVersion};
use tokio::io::AsyncWrite;

use super::keys::{Shared, tls_error};
use super::{
    ALERT_CLOSE_NOTIFY, KEY_UPDATE_NOT_REQUESTED, MAX_PLAINTEXT, MAX_WRITE, MAX_WRITE_SLICES,
};

pub(super) struct Send {
    pub(super) shared: Arc<Shared>,
    pub(super) encrypter: Box<dyn MessageEncrypter>,
    pub(super) seq: u64,
    pub(super) limit: u64,
    pub(super) tls13: bool,
    /// Records sealed for the transport, each in its own buffer; `sent` bytes of the
    /// first one it has taken.
    pub(super) out: VecDeque<Vec<u8>>,
    pub(super) sent: usize,
    pub(super) closed: bool,
}

impl Send {
    fn poll_drain<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while let Some(front) = self.out.front() {
            let first = front.get(self.sent..).unwrap_or_default();
            let n = if io.is_write_vectored() && self.out.len() > 1 {
                let mut slices = [IoSlice::new(&[]); MAX_WRITE_SLICES];
                let records =
                    std::iter::once(first).chain(self.out.iter().skip(1).map(Vec::as_slice));
                let mut used = 0;
                for (slot, record) in slices.iter_mut().zip(records) {
                    *slot = IoSlice::new(record);
                    used += 1;
                }
                ready!(
                    Pin::new(&mut *io)
                        .poll_write_vectored(cx, slices.get(..used).unwrap_or_default())
                )?
            } else {
                ready!(Pin::new(&mut *io).poll_write(cx, first))?
            };
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.advance(n);
        }
        self.sent = 0;
        Poll::Ready(Ok(()))
    }

    fn advance(&mut self, mut n: usize) {
        while let Some(front) = self.out.front() {
            let left = front.len() - self.sent;
            if n < left {
                self.sent += n;
                return;
            }
            n -= left;
            self.out.pop_front();
            self.sent = 0;
        }
    }

    fn seal(&mut self, typ: ContentType, payload: OutboundChunks<'_>) -> io::Result<()> {
        if self.seq >= self.limit {
            if !self.tls13 {
                return Err(io::Error::other(
                    "tls: record limit of the cipher suite reached",
                ));
            }
            self.rotate()?;
        }
        self.seal_now(typ, payload)
    }

    fn seal_now(&mut self, typ: ContentType, payload: OutboundChunks<'_>) -> io::Result<()> {
        let message = OutboundPlainMessage {
            typ,
            version: ProtocolVersion::TLSv1_2,
            payload,
        };
        let sealed = self
            .encrypter
            .encrypt(message, self.seq)
            .map_err(tls_error)?
            .encode();
        self.seq += 1;
        self.out.push_back(sealed);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        let key_update = [
            u8::from(HandshakeType::KeyUpdate),
            0,
            0,
            1,
            KEY_UPDATE_NOT_REQUESTED,
        ];
        self.seal_now(ContentType::Handshake, OutboundChunks::Single(&key_update))?;
        self.encrypter = self.shared.schedule().next_tx()?;
        self.seq = 0;
        Ok(())
    }

    fn answer_key_update(&mut self) -> io::Result<()> {
        if self.shared.answer_key_update.swap(false, Ordering::AcqRel) {
            self.rotate()?;
        }
        Ok(())
    }

    pub(super) fn poll_write<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        chunks: &[&[u8]],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tls: write after close_notify",
            )));
        }
        let total: usize = chunks.iter().map(|chunk| chunk.len()).sum();
        if total == 0 {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_drain(io, cx))?;
        self.answer_key_update()?;
        let accepted = total.min(MAX_WRITE);
        let mut start = 0;
        while start < accepted {
            let end = (start + MAX_PLAINTEXT).min(accepted);
            let payload = match chunks {
                [single] => OutboundChunks::Single(single.get(start..end).unwrap_or_default()),
                _ => OutboundChunks::Multiple { chunks, start, end },
            };
            self.seal(ContentType::ApplicationData, payload)?;
            start = end;
        }
        // The records are ours to deliver now; what the transport does not take yet goes
        // out before the next write or on flush.
        if let Poll::Ready(Err(err)) = self.poll_drain(io, cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(accepted))
    }

    pub(super) fn poll_write_vectored<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let chunks = collect_vectored(bufs);
        self.poll_write(io, cx, chunks.as_slice())
    }

    pub(super) fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(io, cx))?;
        self.answer_key_update()?;
        ready!(self.poll_drain(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    pub(super) fn poll_shutdown<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.closed {
            ready!(self.poll_drain(io, cx))?;
            self.answer_key_update()?;
            let alert = [1, ALERT_CLOSE_NOTIFY];
            self.seal(ContentType::Alert, OutboundChunks::Single(&alert))?;
            self.closed = true;
        }
        ready!(self.poll_drain(io, cx))?;
        match ready!(Pin::new(io).poll_shutdown(cx)) {
            Err(err) if err.kind() != io::ErrorKind::NotConnected => Poll::Ready(Err(err)),
            _ => Poll::Ready(Ok(())),
        }
    }
}

enum VectoredChunks<'a> {
    Stack {
        buf: [&'a [u8]; MAX_WRITE_SLICES],
        len: usize,
    },
    Heap(Vec<&'a [u8]>),
}

impl<'a> VectoredChunks<'a> {
    fn as_slice(&self) -> &[&'a [u8]] {
        match self {
            Self::Stack { buf, len } => buf.get(..*len).unwrap_or_default(),
            Self::Heap(vec) => vec,
        }
    }
}

fn collect_vectored<'a>(bufs: &'a [IoSlice<'a>]) -> VectoredChunks<'a> {
    let mut stack = [&[][..]; MAX_WRITE_SLICES];
    let mut len = 0;
    let mut total = 0usize;
    let mut heap: Option<Vec<&'a [u8]>> = None;
    for buf in bufs {
        let slice: &[u8] = buf;
        if slice.is_empty() {
            continue;
        }
        if let Some(vec) = &mut heap {
            vec.push(slice);
        } else if let Some(slot) = stack.get_mut(len) {
            *slot = slice;
            len += 1;
        } else {
            let mut vec = Vec::with_capacity(bufs.len());
            vec.extend_from_slice(&stack);
            vec.push(slice);
            heap = Some(vec);
        }
        total = total.saturating_add(slice.len());
        if total >= MAX_WRITE {
            break;
        }
    }
    match heap {
        Some(vec) => VectoredChunks::Heap(vec),
        None => VectoredChunks::Stack { buf: stack, len },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_vectored_uses_stack_up_to_eight_and_falls_back_to_heap_past_eight() {
        let empty = [IoSlice::new(&[]), IoSlice::new(&[])];
        let collected = collect_vectored(&empty);
        assert!(matches!(collected, VectoredChunks::Stack { len: 0, .. }));

        let small: Vec<Vec<u8>> = (0..MAX_WRITE_SLICES).map(|i| vec![i as u8; 16]).collect();
        let mut slices = Vec::new();
        for piece in &small {
            slices.push(IoSlice::new(&[]));
            slices.push(IoSlice::new(piece));
        }
        let collected = collect_vectored(&slices);
        assert!(matches!(
            collected,
            VectoredChunks::Stack {
                len: MAX_WRITE_SLICES,
                ..
            }
        ));
        assert_eq!(collected.as_slice().len(), MAX_WRITE_SLICES);

        let many: Vec<Vec<u8>> = (0..12u8).map(|i| vec![i; 32]).collect();
        let many_slices: Vec<IoSlice<'_>> = many.iter().map(|b| IoSlice::new(b)).collect();
        let collected = collect_vectored(&many_slices);
        assert!(matches!(collected, VectoredChunks::Heap(ref v) if v.len() == 12));

        let blocks: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; MAX_PLAINTEXT]).collect();
        let big_slices: Vec<IoSlice<'_>> = blocks.iter().map(|b| IoSlice::new(b)).collect();
        let collected = collect_vectored(&big_slices);
        assert!(matches!(collected, VectoredChunks::Stack { len: 7, .. }));
    }
}
