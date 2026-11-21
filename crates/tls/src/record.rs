use std::collections::VecDeque;
use std::io::{self, IoSlice, IoSliceMut};
use std::ops::{Deref, DerefMut, Range};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use aws_lc_rs::aead;
use concord_common::stream_buffer::{COPY_BUFFER_SIZE, ReadBufferOptions, StreamBuffer};
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxStream, BoxWrite};
use rustls::client::ClientConnectionData;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, OutboundChunks,
    OutboundPlainMessage,
};
use rustls::kernel::KernelConnection;
use rustls::{
    ConnectionTrafficSecrets, ContentType, ExtractedSecrets, HandshakeType, ProtocolVersion,
    SupportedCipherSuite, Tls12CipherSuite,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ciphers::Tls12GcmSeal;
use crate::record_io::{RECORD_HEADER_LEN, ReadHalf, RecordIo, Socket};

const MAX_PLAINTEXT: usize = 16 * 1024;
/// RFC 5246 6.2.3 lets a TLS 1.2 record grow by 2048 bytes; TLS 1.3 by 256.
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 2048;
const MAX_WIRE_RECORD: usize = RECORD_HEADER_LEN + MAX_CIPHERTEXT;
/// Linux `UIO_FASTIOV`: a `writev` of up to this many slices imports them on the stack.
const MAX_WRITE_SLICES: usize = 8;
/// Records one write seals, so they and a KeyUpdate answer leave in one `writev`.
const MAX_WRITE: usize = (MAX_WRITE_SLICES - 1) * MAX_PLAINTEXT;
const MAX_HANDSHAKE_MESSAGE: usize = 65_536;
const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_USER_CANCELED: u8 = 90;
const ALERT_LEVEL_WARNING: u8 = 1;
/// Go's `maxUselessRecords`: dropped alerts and empty records in a row before the read fails.
const MAX_USELESS_RECORDS: u8 = 16;
const KEY_UPDATE_NOT_REQUESTED: u8 = 0;
const KEY_UPDATE_REQUESTED: u8 = 1;

fn tls_error(err: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn key_iv(secrets: ConnectionTrafficSecrets) -> io::Result<(AeadKey, Iv)> {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => Ok((key, iv)),
        _ => Err(invalid("tls: cipher suite has no record layer")),
    }
}

/// ConnectionTrafficSecrets joins TLS 1.2's fixed IV and explicit nonce part; the suite's
/// key block shape splits them again.
fn tls12_iv(suite: &Tls12CipherSuite, iv: &Iv) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let shape = suite.aead_alg.key_block_shape();
    let iv = iv.as_ref();
    let fixed = iv.get(..shape.fixed_iv_len);
    let explicit = iv.get(shape.fixed_iv_len..shape.fixed_iv_len + shape.explicit_nonce_len);
    match (fixed, explicit) {
        (Some(fixed), Some(explicit)) => Ok((fixed.to_vec(), explicit.to_vec())),
        _ => Err(invalid("tls: short iv")),
    }
}

/// The suite's own AEAD, as rustls builds it for itself.
fn encrypter(
    suite: SupportedCipherSuite,
    secrets: ConnectionTrafficSecrets,
    seq: u64,
) -> io::Result<Box<dyn MessageEncrypter>> {
    let gcm: Option<&'static aead::Algorithm> = match &secrets {
        ConnectionTrafficSecrets::Aes128Gcm { .. } => Some(&aead::AES_128_GCM),
        ConnectionTrafficSecrets::Aes256Gcm { .. } => Some(&aead::AES_256_GCM),
        _ => None,
    };
    let (key, iv) = key_iv(secrets)?;
    Ok(match (suite, gcm) {
        (SupportedCipherSuite::Tls13(_), Some(algorithm)) if seq != 0 => {
            crate::ciphers::tls13_sealer(algorithm, key.as_ref(), iv)?
        }
        (SupportedCipherSuite::Tls13(suite), _) => suite.aead_alg.encrypter(key, iv),
        (SupportedCipherSuite::Tls12(_), Some(algorithm)) => {
            Box::new(Tls12GcmSeal::new(algorithm, key.as_ref(), iv.as_ref())?)
        }
        (SupportedCipherSuite::Tls12(suite), None) => {
            let (fixed, explicit) = tls12_iv(suite, &iv)?;
            suite.aead_alg.encrypter(key, &fixed, &explicit)
        }
    })
}

#[cfg(test)]
pub(crate) fn test_encrypter(
    suite: SupportedCipherSuite,
    secrets: ConnectionTrafficSecrets,
    seq: u64,
) -> io::Result<Box<dyn MessageEncrypter>> {
    encrypter(suite, secrets, seq)
}

fn decrypter(
    suite: SupportedCipherSuite,
    secrets: ConnectionTrafficSecrets,
) -> io::Result<Box<dyn MessageDecrypter>> {
    let (key, iv) = key_iv(secrets)?;
    Ok(match suite {
        SupportedCipherSuite::Tls13(suite) => suite.aead_alg.decrypter(key, iv),
        SupportedCipherSuite::Tls12(suite) => {
            let (fixed, _) = tls12_iv(suite, &iv)?;
            suite.aead_alg.decrypter(key, &fixed)
        }
    })
}

/// Derives the next traffic key of one direction for a TLS 1.3 KeyUpdate; sequence numbers
/// restart at zero.
pub(crate) trait KeySchedule: std::marker::Send {
    fn next_tx(&mut self) -> io::Result<Box<dyn MessageEncrypter>>;
    fn next_rx(&mut self) -> io::Result<Box<dyn MessageDecrypter>>;
}

struct RustlsSchedule {
    kernel: KernelConnection<ClientConnectionData>,
    suite: SupportedCipherSuite,
}

impl KeySchedule for RustlsSchedule {
    fn next_tx(&mut self) -> io::Result<Box<dyn MessageEncrypter>> {
        let (_, secrets) = self.kernel.update_tx_secret().map_err(tls_error)?;
        encrypter(self.suite, secrets, 0)
    }

    fn next_rx(&mut self) -> io::Result<Box<dyn MessageDecrypter>> {
        let (_, secrets) = self.kernel.update_rx_secret().map_err(tls_error)?;
        decrypter(self.suite, secrets)
    }
}

/// Each direction's cipher and next sequence number at transport handoff.
pub(crate) struct Keys {
    pub(crate) tls13: bool,
    /// Records one key may seal before it must be replaced.
    pub(crate) limit: u64,
    pub(crate) tx: (u64, Box<dyn MessageEncrypter>),
    pub(crate) rx: (u64, Box<dyn MessageDecrypter>),
    pub(crate) schedule: Box<dyn KeySchedule>,
}

impl Keys {
    pub(crate) fn from_rustls(
        secrets: ExtractedSecrets,
        kernel: KernelConnection<ClientConnectionData>,
    ) -> io::Result<Self> {
        let suite = kernel.negotiated_cipher_suite();
        let limit = match suite {
            SupportedCipherSuite::Tls13(suite) => suite.common.confidentiality_limit,
            SupportedCipherSuite::Tls12(suite) => suite.common.confidentiality_limit,
        };
        let (tx_seq, tx) = secrets.tx;
        let (rx_seq, rx) = secrets.rx;
        Ok(Keys {
            tls13: kernel.protocol_version() == ProtocolVersion::TLSv1_3,
            limit,
            tx: (tx_seq, encrypter(suite, tx, tx_seq)?),
            rx: (rx_seq, decrypter(suite, rx)?),
            schedule: Box::new(RustlsSchedule { kernel, suite }),
        })
    }
}

/// What both directions share. The key schedule is touched only on a KeyUpdate.
struct Shared {
    schedule: Mutex<Box<dyn KeySchedule>>,
    /// The peer asked for a KeyUpdate; RFC 8446 4.6.3 wants ours before our next record.
    answer_key_update: AtomicBool,
}

impl Shared {
    fn schedule(&self) -> std::sync::MutexGuard<'_, Box<dyn KeySchedule>> {
        lock(&self.schedule)
    }
}

enum RecordBuffer {
    Empty,
    Handshake(Vec<u8>),
    Pooled(StreamBuffer),
}

impl RecordBuffer {
    fn take() -> io::Result<Self> {
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

trait RecordReader: AsyncRead + Unpin {
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

struct Recv {
    shared: Arc<Shared>,
    decrypter: Box<dyn MessageDecrypter>,
    seq: u64,
    tls13: bool,
    /// Plaintext rustls decrypted during the handshake.
    early: Vec<u8>,
    /// Ciphertext from the transport, decrypted in place; `plain` is what the caller has
    /// not taken yet.
    buf: RecordBuffer,
    next: Option<(RecordBuffer, usize)>,
    start: usize,
    end: usize,
    plain: Range<usize>,
    handshake: Vec<u8>,
    useless: u8,
    closed: bool,
    failed: Option<(io::ErrorKind, String)>,
}

impl Recv {
    fn poll_read<R: RecordReader>(
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
                (HandshakeType::NewSessionTicket, _) if self.tls13 => {}
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
        let limit = record_end.unwrap_or_else(|| {
            if self.end > self.start {
                self.start + RECORD_HEADER_LEN
            } else {
                self.end + COPY_BUFFER_SIZE
            }
        });
        self.buf.grow(limit);
        if limit > self.buf.len() || limit <= self.end {
            return Poll::Ready(Err(invalid("tls: receive buffer full")));
        }
        if let (Some(record_end), Some(tcp)) = (record_end, io.tcp()) {
            let mut next = RecordBuffer::take()?;
            let first = self.buf.get_mut(self.end..record_end).unwrap_or_default();
            let missing = first.len();
            let following = next
                .get_mut(..COPY_BUFFER_SIZE)
                .ok_or_else(|| invalid("tls: short pooled receive block"))?;
            let mut slices = [IoSliceMut::new(first), IoSliceMut::new(following)];
            let n = loop {
                ready!(tcp.poll_read_ready(cx))?;
                match tcp.try_read_vectored(&mut slices) {
                    Ok(n) => break n,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
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

    fn at_boundary(&self) -> bool {
        self.start == self.end && self.next.is_none() && self.handshake.is_empty()
    }

    fn has_plaintext(&self) -> bool {
        !self.early.is_empty() || !self.plain.is_empty()
    }

    fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.early);
        out.extend_from_slice(self.buf.get(self.plain.clone()).unwrap_or_default());
        self.plain = 0..0;
    }
}

struct Send {
    shared: Arc<Shared>,
    encrypter: Box<dyn MessageEncrypter>,
    seq: u64,
    limit: u64,
    tls13: bool,
    /// Records sealed for the transport, each in its own buffer; `sent` bytes of the
    /// first one it has taken.
    out: VecDeque<Vec<u8>>,
    sent: usize,
    closed: bool,
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

    fn poll_write<W: AsyncWrite + Unpin>(
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

    fn poll_flush<W: AsyncWrite + Unpin>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(io, cx))?;
        self.answer_key_update()?;
        ready!(self.poll_drain(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin>(
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

fn vectored<'a>(bufs: &'a [IoSlice<'a>]) -> Vec<&'a [u8]> {
    bufs.iter()
        .map(|buf| &**buf)
        .filter(|buf| !buf.is_empty())
        .collect()
}

/// A TLS client connection past its handshake. The handshake library keeps the key
/// schedule; each direction seals or opens its own records with its own cipher and sequence
/// number, so the halves of a split share nothing on the data path, as Go's `in` and `out`
/// halfConns.
pub struct RecordStream {
    io: RecordIo<BoxStream>,
    recv: Recv,
    send: Send,
    alpn: Option<Vec<u8>>,
}

impl RecordStream {
    /// `leftover` is what the handshake read past its last record; `early` is plaintext it
    /// already decrypted.
    pub(crate) fn new(
        io: RecordIo<BoxStream>,
        keys: Keys,
        alpn: Option<Vec<u8>>,
        leftover: Vec<u8>,
        early: Vec<u8>,
    ) -> Self {
        let Keys {
            tls13,
            limit,
            tx: (tx_seq, encrypter),
            rx: (rx_seq, decrypter),
            schedule,
        } = keys;
        let shared = Arc::new(Shared {
            schedule: Mutex::new(schedule),
            answer_key_update: AtomicBool::new(false),
        });
        let end = leftover.len();
        let recv = Recv {
            shared: shared.clone(),
            decrypter,
            seq: rx_seq,
            tls13,
            early,
            buf: RecordBuffer::Handshake(leftover),
            next: None,
            start: 0,
            end,
            plain: 0..0,
            handshake: Vec::new(),
            useless: 0,
            closed: false,
            failed: None,
        };
        let send = Send {
            shared,
            encrypter,
            seq: tx_seq,
            limit,
            tls13,
            out: VecDeque::new(),
            sent: 0,
            closed: false,
        };
        RecordStream {
            io,
            recv,
            send,
            alpn,
        }
    }

    pub(crate) fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    pub(crate) fn is_tls13(&self) -> bool {
        self.send.tls13
    }

    pub(crate) fn set_unaligned(&mut self) {
        self.io.set_unaligned();
    }

    pub(crate) fn raw_mut(&mut self) -> &mut BoxStream {
        self.io.get_mut()
    }

    pub(crate) fn at_record_boundary(&self) -> bool {
        self.io.at_record_boundary() && self.recv.at_boundary()
    }

    pub(crate) fn has_pending_plaintext(&self) -> bool {
        self.recv.has_plaintext()
    }

    pub(crate) fn drain_plaintext(&mut self, out: &mut Vec<u8>) {
        self.recv.drain_plaintext(out);
    }

    pub(crate) fn into_halves(self) -> (TlsRead, TlsWrite) {
        let (read, write) = self.io.into_split();
        let reader = TlsRead {
            io: read,
            recv: self.recv,
        };
        let writer = TlsWrite {
            io: write,
            send: self.send,
        };
        (reader, writer)
    }

    pub(crate) fn into_split(self) -> (BoxRead, BoxWrite) {
        let (read, write) = self.into_halves();
        (Box::new(read), Box::new(write))
    }
}

impl concord_common::Stream for RecordStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        RecordStream::into_split(*self)
    }
}

impl AsyncRead for RecordStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.recv.poll_read(&mut this.io, cx, buf)
    }
}

impl AsyncWrite for RecordStream {
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
        this.send.poll_write(&mut this.io, cx, &vectored(bufs))
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

/// The read half of a connection on the record layer.
pub struct TlsRead {
    io: RecordIo<ReadHalf>,
    recv: Recv,
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
    io: BoxWrite,
    send: Send,
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
        this.send.poll_write(&mut this.io, cx, &vectored(bufs))
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
