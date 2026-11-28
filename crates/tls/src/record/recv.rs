#[cfg(test)]
use std::cell::Cell;
use std::io::{self, IoSliceMut};
use std::ops::{Deref, DerefMut, Range};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll, ready};

use concord_common::stream_buffer::{COPY_BUFFER_SIZE, ReadBufferOptions, StreamBuffer};
use rustls::crypto::cipher::{InboundOpaqueMessage, MessageDecrypter};
use rustls::{ContentType, HandshakeType, ProtocolVersion};
use tokio::io::{AsyncRead, ReadBuf};

use crate::record_io::{RECORD_HEADER_LEN, RecordIo, Socket};

use super::keys::{Shared, invalid, tls_error};
use super::{
    ALERT_CLOSE_NOTIFY, ALERT_LEVEL_WARNING, ALERT_USER_CANCELED, KEY_UPDATE_NOT_REQUESTED,
    KEY_UPDATE_REQUESTED, MAX_CIPHERTEXT, MAX_HANDSHAKE_MESSAGE, MAX_PLAINTEXT,
    MAX_USELESS_RECORDS, MAX_WIRE_RECORD,
};

#[cfg(test)]
thread_local! {
    static RECORD_BUFFER_TAKES: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn record_buffer_takes() -> usize {
    RECORD_BUFFER_TAKES.with(Cell::get)
}

pub(super) enum RecordBuffer {
    Empty,
    Handshake(Vec<u8>),
    Pooled(StreamBuffer),
}

impl RecordBuffer {
    fn take() -> io::Result<Self> {
        #[cfg(test)]
        RECORD_BUFFER_TAKES.with(|count| count.set(count.get() + 1));
        let options = ReadBufferOptions::for_copy(Default::default(), Default::default())?;
        // Reserve enough tail to complete the last record without moving its ciphertext.
        let mut buffer = options.take_for_read(COPY_BUFFER_SIZE, MAX_WIRE_RECORD)?;
        // Recv's start/end delimit the received data within this initialized working slab.
        let space = buffer.spare_mut().len();
        buffer.advance(space)?;
        Ok(Self::Pooled(buffer))
    }

    fn grow(&mut self, need: usize) {
        if let Self::Handshake(buffer) = self
            && buffer.len() < need
        {
            buffer.resize(need, 0);
        }
    }
}

impl Deref for RecordBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Handshake(buffer) => buffer,
            Self::Pooled(buffer) => buffer.as_slice(),
        }
    }
}

impl DerefMut for RecordBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Empty => &mut [],
            Self::Handshake(buffer) => buffer,
            Self::Pooled(buffer) => buffer.as_mut_slice(),
        }
    }
}

pub(super) trait RecordReader: AsyncRead + Unpin {
    fn record_aligned(&self) -> bool;

    fn tcp(&self) -> Option<&tokio::net::TcpStream>;
}

impl<S: Socket + AsyncRead + Unpin> RecordReader for RecordIo<S> {
    fn record_aligned(&self) -> bool {
        self.is_aligned()
    }

    fn tcp(&self) -> Option<&tokio::net::TcpStream> {
        if self.is_aligned() {
            None
        } else {
            self.get_ref().socket()
        }
    }
}

pub(super) struct Recv {
    pub(super) shared: Arc<Shared>,
    pub(super) decrypter: Box<dyn MessageDecrypter>,
    pub(super) seq: u64,
    pub(super) tls13: bool,
    /// Plaintext rustls decrypted during the handshake.
    pub(super) early: Vec<u8>,
    /// Ciphertext from the transport, decrypted in place; `plain` is what the caller has
    /// not taken yet.
    pub(super) buf: RecordBuffer,
    pub(super) next: Option<(RecordBuffer, usize)>,
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) plain: Range<usize>,
    pub(super) handshake: Vec<u8>,
    pub(super) useless: u8,
    pub(super) closed: bool,
    pub(super) failed: Option<(io::ErrorKind, String)>,
    /// Only a server sends tickets after the handshake (RFC 8446 4.6.1).
    pub(super) peer_is_server: bool,
}

impl Recv {
    pub(super) fn poll_read<R: RecordReader>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        loop {
            if out.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !self.early.is_empty() {
                let take = self.early.len().min(out.remaining());
                out.put_slice(self.early.get(..take).unwrap_or_default());
                self.early.drain(..take);
                continue;
            }
            if !self.plain.is_empty() {
                let take = self.plain.len().min(out.remaining());
                let from = self.plain.start;
                out.put_slice(self.buf.get(from..from + take).unwrap_or_default());
                self.plain.start += take;
                self.release_empty_buffer();
                continue;
            }
            self.release_empty_buffer();
            let copied = out.filled().len() > before;
            if self.closed || (copied && self.failed.is_some()) {
                return Poll::Ready(Ok(()));
            }
            if let Some((kind, message)) = &self.failed {
                return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
            }
            // One read takes every record the transport has ready, so a
            // relay hands its peer large writes instead of one per record. An aligned
            // reader stops after a record: what follows may not be TLS (XTLS Vision).
            let step = match self.open_record() {
                Ok(true) => continue,
                Ok(false) if copied && io.record_aligned() => return Poll::Ready(Ok(())),
                Ok(false) => self.poll_fill(io, cx),
                Err(err) => Poll::Ready(Err(err)),
            };
            match step {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => {
                    self.failed = Some((err.kind(), err.to_string()));
                    return Poll::Ready(if copied { Ok(()) } else { Err(err) });
                }
                Poll::Pending if copied => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// The length of the record at `start`, once its header is in.
    fn record_len(&self) -> io::Result<Option<usize>> {
        let filled = self.buf.get(self.start..self.end).unwrap_or_default();
        let Some(&[typ, major, _, hi, lo]) = filled.get(..RECORD_HEADER_LEN) else {
            return Ok(None);
        };
        let body = usize::from(u16::from_be_bytes([hi, lo]));
        if !(20..=24).contains(&typ) || major != 3 || body > MAX_CIPHERTEXT {
            return Err(invalid("not a tls record"));
        }
        Ok(Some(RECORD_HEADER_LEN + body))
    }

    /// Decrypts one whole record if the buffer holds one.
    fn open_record(&mut self) -> io::Result<bool> {
        if self.end - self.start < RECORD_HEADER_LEN {
            return Ok(false);
        }
        let Some(len) = self.record_len()? else {
            return Ok(false);
        };
        if self.end - self.start < len {
            return Ok(false);
        }
        let header = self.start;
        self.start += len;
        let base = self.buf.as_ptr() as usize;
        let Some(record) = self.buf.get_mut(header..header + len) else {
            return Err(invalid("tls record overrun"));
        };
        let (head, body) = record.split_at_mut(RECORD_HEADER_LEN);
        let typ = ContentType::from(head.first().copied().unwrap_or_default());
        let version = ProtocolVersion::from(u16::from_be_bytes([
            head.get(1).copied().unwrap_or_default(),
            head.get(2).copied().unwrap_or_default(),
        ]));
        if typ != ContentType::ApplicationData && self.tls13 {
            return Err(invalid("tls: unencrypted record after the handshake"));
        }
        let message = InboundOpaqueMessage::new(typ, version, body);
        let plain = self
            .decrypter
            .decrypt(message, self.seq)
            .map_err(tls_error)?;
        self.seq += 1;
        if plain.payload.len() > MAX_PLAINTEXT {
            return Err(invalid("tls: record overflow"));
        }
        let offset = (plain.payload.as_ptr() as usize).saturating_sub(base);
        let range = offset..offset + plain.payload.len();
        match plain.typ {
            ContentType::ApplicationData => {
                if range.is_empty() {
                    self.ignore()?;
                } else {
                    self.useless = 0;
                }
                self.plain = range;
            }
            ContentType::Alert => match plain.payload {
                [_, ALERT_CLOSE_NOTIFY] => self.closed = true,
                [_, ALERT_USER_CANCELED] if self.tls13 => self.ignore()?,
                [ALERT_LEVEL_WARNING, _] if !self.tls13 => self.ignore()?,
                [_, description] => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("tls: peer sent alert {description}"),
                    ));
                }
                _ => return Err(invalid("tls: bad alert")),
            },
            ContentType::Handshake => {
                if !plain.payload.is_empty() {
                    self.useless = 0;
                }
                self.handshake.extend_from_slice(plain.payload);
                self.handle_handshake()?;
            }
            _ => return Err(invalid("tls: unexpected record type")),
        }
        Ok(true)
    }

    fn ignore(&mut self) -> io::Result<()> {
        self.useless += 1;
        if self.useless > MAX_USELESS_RECORDS {
            return Err(invalid("tls: too many ignored records"));
        }
        Ok(())
    }

    fn handle_handshake(&mut self) -> io::Result<()> {
        while let Some(&[typ, a, b, c]) = self.handshake.get(..4) {
            let len = usize::try_from(u32::from_be_bytes([0, a, b, c])).unwrap_or(usize::MAX);
            if len > MAX_HANDSHAKE_MESSAGE {
                return Err(invalid("tls: handshake message too long"));
            }
            let Some(body) = self.handshake.get(4..4 + len) else {
                return Ok(());
            };
            match (HandshakeType::from(typ), body) {
                // Resumption is off, so a ticket is of no use.
                (HandshakeType::NewSessionTicket, _) if self.tls13 && self.peer_is_server => {}
                (HandshakeType::KeyUpdate, &[request]) if self.tls13 => {
                    if self.handshake.len() != 4 + len {
                        return Err(invalid("tls: KeyUpdate not at a record boundary"));
                    }
                    if request == KEY_UPDATE_REQUESTED {
                        self.shared.answer_key_update.store(true, Ordering::Release);
                    } else if request != KEY_UPDATE_NOT_REQUESTED {
                        return Err(invalid("tls: bad KeyUpdate"));
                    }
                    self.decrypter = self.shared.schedule().next_rx()?;
                    self.seq = 0;
                }
                _ => return Err(invalid("tls: unexpected handshake message")),
            }
            self.handshake.drain(..4 + len);
        }
        Ok(())
    }

    fn poll_fill<R: RecordReader>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
            if matches!(self.buf, RecordBuffer::Empty) {
                self.buf = RecordBuffer::take()?;
            }
        }
        let record_end = self.record_len()?.map(|length| self.start + length);
        let pooled_unaligned = !io.record_aligned() && matches!(self.buf, RecordBuffer::Pooled(_));
        let limit = match record_end {
            Some(end) if pooled_unaligned && end <= COPY_BUFFER_SIZE => COPY_BUFFER_SIZE,
            Some(end) => end,
            None if pooled_unaligned && self.end < COPY_BUFFER_SIZE => COPY_BUFFER_SIZE,
            None if self.end > self.start => self.start + RECORD_HEADER_LEN,
            None => self.end + COPY_BUFFER_SIZE,
        };
        self.buf.grow(limit);
        if limit > self.buf.len() || limit <= self.end {
            return Poll::Ready(Err(invalid("tls: receive buffer full")));
        }
        let needs_next = record_end.is_some_and(|end| !pooled_unaligned || end > COPY_BUFFER_SIZE);
        if needs_next && let (Some(record_end), Some(tcp)) = (record_end, io.tcp()) {
            ready!(tcp.poll_read_ready(cx))?;
            let mut next = RecordBuffer::take()?;
            let first = self.buf.get_mut(self.end..record_end).unwrap_or_default();
            let missing = first.len();
            let following = next
                .get_mut(..COPY_BUFFER_SIZE)
                .ok_or_else(|| invalid("tls: short pooled receive block"))?;
            let mut slices = [IoSliceMut::new(first), IoSliceMut::new(following)];
            let n = loop {
                match tcp.try_read_vectored(&mut slices) {
                    Ok(n) => break n,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        ready!(tcp.poll_read_ready(cx))?;
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                }
            };
            self.end += n.min(missing);
            if n > missing {
                self.next = Some((next, n - missing));
            }
            return self.accept_read(n);
        }
        let space = self.buf.get_mut(self.end..limit).unwrap_or_default();
        let mut read = ReadBuf::new(space);
        match Pin::new(io).poll_read(cx, &mut read) {
            Poll::Pending => {
                self.release_empty_buffer();
                return Poll::Pending;
            }
            Poll::Ready(result) => result?,
        }
        let n = read.filled().len();
        self.end += n;
        self.accept_read(n)
    }

    fn accept_read(&mut self, n: usize) -> Poll<io::Result<()>> {
        if n == 0 {
            // Go's crypto/tls (conn.go readRecordOrCCS) accepts an EOF without close_notify
            // as a clean end only at a record boundary, because popular sites close that way;
            // mihomo peers behave the same.
            if self.end == 0 && self.handshake.is_empty() {
                self.closed = true;
                return Poll::Ready(Ok(()));
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tls: transport closed inside a record or handshake message",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn release_empty_buffer(&mut self) {
        if self.start == self.end && self.plain.is_empty() {
            self.start = 0;
            if let Some((buffer, end)) = self.next.take() {
                self.buf = buffer;
                self.end = end;
            } else {
                self.buf = RecordBuffer::Empty;
                self.end = 0;
            }
        }
    }

    pub(super) fn at_boundary(&self) -> bool {
        self.start == self.end && self.next.is_none() && self.handshake.is_empty()
    }

    pub(super) fn has_plaintext(&self) -> bool {
        !self.early.is_empty() || !self.plain.is_empty()
    }

    pub(super) fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.early);
        out.extend_from_slice(self.buf.get(self.plain.clone()).unwrap_or_default());
        self.plain = 0..0;
    }
}
