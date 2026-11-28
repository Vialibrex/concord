mod halves;
mod keys;
mod recv;
mod send;

use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use concord_common::{BoxRead, BoxStream, BoxWrite};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::record_io::{RECORD_HEADER_LEN, RecordIo};

pub use halves::{TlsRead, TlsWrite};
#[cfg(test)]
pub(crate) use keys::test_encrypter;
pub(crate) use keys::{KeySchedule, Keys};
#[cfg(test)]
pub(crate) use recv::record_buffer_takes;

use keys::Shared;
use recv::{RecordBuffer, Recv};
use send::Send;

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
            tcp, peer_addr, needs_handshake, direct, into_tcp);

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
