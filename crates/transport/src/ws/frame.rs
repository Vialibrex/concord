use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Wake, Waker, ready};

use concord_common::sync::lock;
use concord_common::{BoxRead, BoxWrite, Stream};
use futures_util::task::AtomicWaker;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::http1::invalid;

const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;
const MAX_CONTROL: usize = 125;

pub(crate) fn apply_mask(key: [u8; 4], offset: usize, data: &mut [u8]) {
    let mut rotated = key;
    rotated.rotate_left(offset & 3);
    let wide = u64::from_ne_bytes([
        rotated[0], rotated[1], rotated[2], rotated[3], rotated[0], rotated[1], rotated[2],
        rotated[3],
    ]);
    let (chunks, rest) = data.as_chunks_mut::<8>();
    for chunk in chunks {
        *chunk = (u64::from_ne_bytes(*chunk) ^ wide).to_ne_bytes();
    }
    for (byte, k) in rest.iter_mut().zip(rotated.iter().cycle()) {
        *byte ^= k;
    }
}

pub(crate) fn encode_frame(out: &mut Vec<u8>, opcode: u8, payload: &[u8], client: bool) {
    out.push(0x80 | opcode);
    let mask_bit = if client { 0x80 } else { 0 };
    let len = payload.len();
    if len < 126 {
        out.push(mask_bit | len as u8);
    } else if len < 65536 {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if client {
        let key: [u8; 4] = rand::random();
        out.extend_from_slice(&key);
        let start = out.len();
        out.extend_from_slice(payload);
        if let Some(body) = out.get_mut(start..) {
            apply_mask(key, 0, body);
        }
    } else {
        out.extend_from_slice(payload);
    }
}

enum Read {
    Head {
        buf: [u8; 14],
        have: usize,
    },
    Data {
        left: u64,
        mask: Option<[u8; 4]>,
        pos: usize,
    },
    Control {
        op: u8,
        left: usize,
        mask: Option<[u8; 4]>,
        payload: Vec<u8>,
    },
    Skip {
        left: u64,
    },
    Eof,
}

impl Read {
    fn head() -> Read {
        Read::Head {
            buf: [0; 14],
            have: 0,
        }
    }
}

enum Step {
    Filled,
    Ping(Vec<u8>),
    Close(Vec<u8>),
}

/// Reads until data fills `out`, the stream ends, or a control frame that needs an answer
/// completes.
fn poll_step<R: AsyncRead + Unpin + ?Sized>(
    state: &mut Read,
    io: &mut R,
    cx: &mut Context<'_>,
    out: &mut ReadBuf<'_>,
) -> Poll<io::Result<Step>> {
    loop {
        match state {
            Read::Eof => return Poll::Ready(Ok(Step::Filled)),
            Read::Head { buf, have } => {
                let need = if *have < 2 { 2 } else { header_len(buf) };
                if *have >= need {
                    let (op, left, mask) = parse_head(buf, need)?;
                    *state = match op {
                        0x0..=0x2 => Read::Data { left, mask, pos: 0 },
                        OP_CLOSE | OP_PING | OP_PONG => {
                            if left > MAX_CONTROL as u64 {
                                return Poll::Ready(Err(invalid("oversized control frame")));
                            }
                            Read::Control {
                                op,
                                left: left as usize,
                                mask,
                                payload: Vec::new(),
                            }
                        }
                        _ => Read::Skip { left },
                    };
                    continue;
                }
                let Some(window) = buf.get_mut(*have..need) else {
                    return Poll::Ready(Err(invalid("frame header overflow")));
                };
                let mut window = ReadBuf::new(window);
                ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                let got = window.filled().len();
                if got == 0 {
                    if *have == 0 {
                        *state = Read::Eof;
                        return Poll::Ready(Ok(Step::Filled));
                    }
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                *have += got;
            }
            Read::Data { left, mask, pos } => {
                if *left == 0 {
                    *state = Read::head();
                    continue;
                }
                let take = usize::try_from(*left)
                    .unwrap_or(usize::MAX)
                    .min(out.remaining());
                if take == 0 {
                    return Poll::Ready(Ok(Step::Filled));
                }
                let target = out.initialize_unfilled_to(take);
                let mut window = ReadBuf::new(target);
                ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                let got = window.filled().len();
                if got == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                if let Some(key) = *mask {
                    apply_mask(key, *pos, window.filled_mut());
                }
                out.advance(got);
                *pos += got;
                *left -= got as u64;
                return Poll::Ready(Ok(Step::Filled));
            }
            Read::Skip { left } => {
                if *left == 0 {
                    *state = Read::head();
                    continue;
                }
                let mut sink = [0u8; 1024];
                let take = usize::try_from(*left).unwrap_or(usize::MAX).min(sink.len());
                let Some(window) = sink.get_mut(..take) else {
                    return Poll::Ready(Err(invalid("skip window")));
                };
                let mut window = ReadBuf::new(window);
                ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                let got = window.filled().len();
                if got == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                *left -= got as u64;
            }
            Read::Control {
                op,
                left,
                mask,
                payload,
            } => {
                if *left > 0 {
                    let mut tmp = [0u8; MAX_CONTROL];
                    let Some(window) = tmp.get_mut(..*left) else {
                        return Poll::Ready(Err(invalid("control window")));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let mut chunk = window.filled().to_vec();
                    if let Some(key) = mask {
                        apply_mask(*key, payload.len(), &mut chunk);
                    }
                    payload.extend_from_slice(&chunk);
                    *left -= got;
                    continue;
                }
                let op = *op;
                let payload = std::mem::take(payload);
                *state = Read::head();
                match op {
                    OP_PING => return Poll::Ready(Ok(Step::Ping(payload))),
                    OP_CLOSE => {
                        *state = Read::Eof;
                        return Poll::Ready(Ok(Step::Close(payload)));
                    }
                    _ => {}
                }
            }
        }
    }
}

fn header_len(first_two: &[u8]) -> usize {
    let second = first_two.get(1).copied().unwrap_or(0);
    let extra = match second & 0x7F {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let mask = if second & 0x80 != 0 { 4 } else { 0 };
    2 + extra + mask
}

fn drain<W: AsyncWrite + Unpin + ?Sized>(
    io: &mut W,
    buf: &mut Vec<u8>,
    off: &mut usize,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while let Some(pending) = buf.get(*off..) {
        if pending.is_empty() {
            break;
        }
        let n = ready!(Pin::new(&mut *io).poll_write(cx, pending))?;
        if n == 0 {
            return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
        }
        *off += n;
    }
    buf.clear();
    *off = 0;
    Poll::Ready(Ok(()))
}

/// Everything the write direction owns. Replies queued while reading (pong, close) go out
/// only between data frames; mid-frame, the writer finishes them.
struct WriteSide {
    out: Vec<u8>,
    out_off: usize,
    ctrl: Vec<u8>,
    ctrl_off: usize,
    inflight: Option<usize>,
    close_sent: bool,
    client: bool,
}

impl WriteSide {
    fn new(client: bool) -> Self {
        WriteSide {
            out: Vec::new(),
            out_off: 0,
            ctrl: Vec::new(),
            ctrl_off: 0,
            inflight: None,
            close_sent: false,
            client,
        }
    }

    fn poll_drain<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        drain(io, &mut self.out, &mut self.out_off, cx)
    }

    fn poll_drain_ctrl<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        drain(io, &mut self.ctrl, &mut self.ctrl_off, cx)
    }

    /// Sends queued replies if no data frame is half written; true once nothing is left to
    /// send from the reading side's point of view.
    fn pump_ctrl<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> bool {
        if self.out.is_empty() && self.poll_drain_ctrl(io, cx).is_ready() {
            self.ctrl.clear();
            self.ctrl_off = 0;
            return true;
        }
        false
    }

    fn has_ctrl(&self) -> bool {
        !self.ctrl.is_empty()
    }

    fn queue_control(&mut self, opcode: u8, payload: &[u8]) {
        if opcode == OP_CLOSE {
            if self.close_sent {
                return;
            }
            self.close_sent = true;
        }
        encode_frame(&mut self.ctrl, opcode, payload, self.client);
    }

    fn queue_reply(&mut self, step: Step) {
        match step {
            Step::Ping(payload) => self.queue_control(OP_PONG, &payload),
            Step::Close(payload) => self.queue_control(OP_CLOSE, &payload),
            Step::Filled => {}
        }
    }

    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.close_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(done) = self.inflight {
            ready!(self.poll_drain(io, cx))?;
            self.inflight = None;
            return Poll::Ready(Ok(done));
        }
        ready!(self.poll_drain_ctrl(io, cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        encode_frame(&mut self.out, OP_BINARY, data, self.client);
        self.inflight = Some(data.len());
        ready!(self.poll_drain(io, cx))?;
        self.inflight = None;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(io, cx))?;
        ready!(self.poll_drain_ctrl(io, cx))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(io, cx))?;
        self.queue_control(OP_CLOSE, &1000u16.to_be_bytes());
        ready!(self.poll_drain_ctrl(io, cx))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

pub(crate) struct WsStream<S> {
    inner: S,
    read: Read,
    write: WriteSide,
}

impl<S> WsStream<S> {
    pub fn new(inner: S, client: bool) -> Self {
        WsStream {
            inner,
            read: Read::head(),
            write: WriteSide::new(client),
        }
    }
}

fn parse_head(buf: &[u8; 14], need: usize) -> io::Result<(u8, u64, Option<[u8; 4]>)> {
    let op = buf[0] & 0x0F;
    let second = buf[1];
    let len7 = u64::from(second & 0x7F);
    let (len, mut cursor) = match len7 {
        126 => (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4),
        127 => {
            let mut raw = [0u8; 8];
            raw.copy_from_slice(buf.get(2..10).ok_or_else(|| invalid("frame header"))?);
            let len = u64::from_be_bytes(raw);
            if len >> 63 != 0 {
                return Err(invalid("frame length has the high bit set"));
            }
            (len, 10)
        }
        n => (n, 2),
    };
    let mask = if second & 0x80 != 0 {
        let mut key = [0u8; 4];
        key.copy_from_slice(
            buf.get(cursor..cursor + 4)
                .ok_or_else(|| invalid("frame mask"))?,
        );
        cursor += 4;
        Some(key)
    } else {
        None
    };
    debug_assert_eq!(cursor, need);
    Ok((op, len, mask))
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            this.write.pump_ctrl(&mut this.inner, cx);
            match ready!(poll_step(&mut this.read, &mut this.inner, cx, buf))? {
                Step::Filled => return Poll::Ready(Ok(())),
                step => this.write.queue_reply(step),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write.poll_write(&mut this.inner, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write.poll_flush(&mut this.inner, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.write.poll_shutdown(&mut this.inner, cx)
    }
}

struct Locked {
    io: BoxWrite,
    side: WriteSide,
}

/// The write side is behind a mutex because the read half must be able to send a pong or a
/// close echo itself when the writer is idle. The write half takes it per poll, the read
/// half only when a control frame arrives or while a reply is still queued.
struct Shared {
    locked: Mutex<Locked>,
    read: AtomicWaker,
    write: AtomicWaker,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Locked> {
        lock(&self.locked)
    }
}

/// Wakes both halves, for a send the reader started on a socket the writer may also wait on.
impl Wake for Shared {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.read.wake();
        self.write.wake();
    }
}

struct WsRead {
    io: BoxRead,
    state: Read,
    shared: Arc<Shared>,
    reply_pending: bool,
}

impl WsRead {
    fn send_replies(&mut self, cx: &mut Context<'_>) {
        self.shared.read.register(cx.waker());
        let waker = Waker::from(self.shared.clone());
        let mut both = Context::from_waker(&waker);
        let mut locked = self.shared.lock();
        let Locked { io, side } = &mut *locked;
        self.reply_pending = !side.pump_ctrl(io, &mut both);
    }
}

impl AsyncRead for WsRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.reply_pending {
                this.send_replies(cx);
            }
            match ready!(poll_step(&mut this.state, &mut this.io, cx, buf))? {
                Step::Filled => return Poll::Ready(Ok(())),
                step => {
                    this.shared.lock().side.queue_reply(step);
                    this.reply_pending = true;
                    this.send_replies(cx);
                }
            }
        }
    }
}

struct WsWrite {
    shared: Arc<Shared>,
}

impl WsWrite {
    fn with<T>(
        &self,
        cx: &mut Context<'_>,
        f: impl FnOnce(&mut BoxWrite, &mut WriteSide, &mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        let mut locked = self.shared.lock();
        let Locked { io, side } = &mut *locked;
        if !side.has_ctrl() {
            let polled = f(io, side, cx);
            if polled.is_pending() {
                self.shared.write.register(cx.waker());
            }
            return polled;
        }
        // The socket keeps one waker, so while a reply the read half queued is waiting, both
        // halves must hear the socket, and the read half must hear when a data frame ends.
        self.shared.write.register(cx.waker());
        let waker = Waker::from(self.shared.clone());
        let polled = f(io, side, &mut Context::from_waker(&waker));
        if polled.is_ready() && side.has_ctrl() {
            self.shared.read.wake();
        }
        polled
    }
}

impl AsyncWrite for WsWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with(cx, |io, side, cx| side.poll_write(io, cx, data))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with(cx, |io, side, cx| side.poll_flush(io, cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with(cx, |io, side, cx| side.poll_shutdown(io, cx))
    }
}

impl<S: Stream> Stream for WsStream<S> {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let WsStream { inner, read, write } = *self;
        let (io_read, io_write) = Box::new(inner).into_split();
        let shared = Arc::new(Shared {
            locked: Mutex::new(Locked {
                io: io_write,
                side: write,
            }),
            read: AtomicWaker::new(),
            write: AtomicWaker::new(),
        });
        (
            Box::new(WsRead {
                io: io_read,
                state: read,
                shared: shared.clone(),
                reply_pending: false,
            }),
            Box::new(WsWrite { shared }),
        )
    }
}

#[cfg(test)]
mod tests {
    use concord_common::BoxStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    #[test]
    fn mask_is_an_involution_for_every_offset() {
        let key = [0x11, 0x22, 0x33, 0x44];
        let original: Vec<u8> = (0..37u8).collect();
        for offset in 0..8 {
            let mut data = original.clone();
            apply_mask(key, offset, &mut data);
            assert_ne!(data, original);
            apply_mask(key, offset, &mut data);
            assert_eq!(data, original);
        }
    }

    #[test]
    fn mask_matches_the_rfc_definition() {
        let key = [1, 2, 3, 4];
        for len in 0..32 {
            for offset in 0..4 {
                let mut data = vec![0u8; len];
                apply_mask(key, offset, &mut data);
                let expect: Vec<u8> = (0..len).map(|i| key[(i + offset) % 4]).collect();
                assert_eq!(data, expect, "len {len} offset {offset}");
            }
        }
    }

    #[tokio::test]
    async fn payloads_round_trip_across_frame_sizes() {
        let (a, b) = duplex(1 << 16);
        let mut client = WsStream::new(a, true);
        let mut server = WsStream::new(b, false);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, payload);
    }

    async fn read_one_masked_frame(raw: &mut DuplexStream, payload: &[u8]) {
        let mut head = [0u8; 14];
        raw.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x80 | OP_BINARY);
        assert_eq!(head[1], 0x80 | 127);
        let len = u64::from_be_bytes(head[2..10].try_into().unwrap());
        assert_eq!(len, payload.len() as u64);
        let mut body = vec![0u8; payload.len()];
        raw.read_exact(&mut body).await.unwrap();
        apply_mask([head[10], head[11], head[12], head[13]], 0, &mut body);
        assert_eq!(body, payload);
    }

    #[tokio::test]
    async fn a_write_larger_than_a_relay_buffer_is_one_message() {
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let (a, mut raw) = duplex(1 << 18);
        let mut whole = WsStream::new(a, true);
        assert_eq!(whole.write(&payload).await.unwrap(), payload.len());
        read_one_masked_frame(&mut raw, &payload).await;

        let (a, mut raw) = duplex(1 << 18);
        let (_read, mut write) = (Box::new(WsStream::new(a, true)) as BoxStream).into_split();
        assert_eq!(write.write(&payload).await.unwrap(), payload.len());
        read_one_masked_frame(&mut raw, &payload).await;
    }

    #[tokio::test]
    async fn ping_is_answered_with_a_pong_and_data_continues() {
        let (a, mut raw) = duplex(4096);
        let mut client = WsStream::new(a, true);
        let mut ping = Vec::new();
        encode_frame(&mut ping, OP_PING, b"hi", false);
        encode_frame(&mut ping, OP_BINARY, b"data", false);
        raw.write_all(&ping).await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"data");
        client.flush().await.unwrap();
        let mut reply = [0u8; 8];
        raw.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x80 | OP_PONG);
        assert_eq!(reply[1], 0x80 | 2);
        let key = [reply[2], reply[3], reply[4], reply[5]];
        let mut body = [reply[6], reply[7]];
        apply_mask(key, 0, &mut body);
        assert_eq!(&body, b"hi");
    }

    #[tokio::test]
    async fn close_frame_ends_the_stream_and_is_answered() {
        let (a, mut raw) = duplex(4096);
        let mut client = WsStream::new(a, true);
        let mut close = Vec::new();
        encode_frame(&mut close, OP_CLOSE, &1000u16.to_be_bytes(), false);
        raw.write_all(&close).await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty());
        client.flush().await.unwrap();
        let mut reply = [0u8; 8];
        raw.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x80 | OP_CLOSE);
    }

    #[tokio::test]
    async fn split_halves_answer_a_ping_while_the_writer_is_idle() {
        let (a, mut raw) = duplex(4096);
        let (mut read, _write) = (Box::new(WsStream::new(a, true)) as BoxStream).into_split();
        let mut ping = Vec::new();
        encode_frame(&mut ping, OP_PING, b"hi", false);
        encode_frame(&mut ping, OP_BINARY, b"data", false);
        raw.write_all(&ping).await.unwrap();
        let mut buf = [0u8; 4];
        read.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"data");
        let mut reply = [0u8; 8];
        raw.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x80 | OP_PONG);
        let key = [reply[2], reply[3], reply[4], reply[5]];
        let mut body = [reply[6], reply[7]];
        apply_mask(key, 0, &mut body);
        assert_eq!(&body, b"hi");
    }

    #[tokio::test]
    async fn a_pong_queued_mid_frame_leaves_once_the_writer_ends_that_frame() {
        let (a, mut raw) = duplex(64);
        let (mut read, mut write) = (Box::new(WsStream::new(a, true)) as BoxStream).into_split();
        let writer = tokio::spawn(async move {
            write.write_all(&[7; 1000]).await.unwrap();
            write
        });
        tokio::task::yield_now().await;
        let mut ping = Vec::new();
        encode_frame(&mut ping, OP_PING, b"hi", false);
        raw.write_all(&ping).await.unwrap();
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 1];
            let _ = read.read(&mut buf).await;
        });
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        let mut frame = vec![0u8; 8 + 1000];
        raw.read_exact(&mut frame).await.unwrap();
        assert_eq!(frame[0], 0x80 | OP_BINARY);
        let _write = writer.await.unwrap();
        let mut reply = [0u8; 8];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            raw.read_exact(&mut reply),
        )
        .await
        .expect("the pong waited for the next inbound frame")
        .unwrap();
        assert_eq!(reply[0], 0x80 | OP_PONG);
        reader.abort();
    }

    #[tokio::test]
    async fn split_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let (a, b) = duplex(1 << 10);
        let (mut cr, mut cw) = (Box::new(WsStream::new(a, true)) as BoxStream).into_split();
        let (mut sr, mut sw) = (Box::new(WsStream::new(b, false)) as BoxStream).into_split();
        let up: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let down: Vec<u8> = (0..90_000u32).map(|i| (i % 241) as u8).collect();
        let (up_c, down_s) = (up.clone(), down.clone());
        let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let c_write = tokio::spawn(async move {
            cw.write_all(&up_c).await.unwrap();
            cw.flush().await.unwrap();
            sent_tx.send(()).unwrap();
            read_rx.await.unwrap();
            cw.shutdown().await.unwrap();
        });
        let s_write = tokio::spawn(async move {
            sw.write_all(&down_s).await.unwrap();
            sent_rx.await.unwrap();
            sw.shutdown().await.unwrap();
        });
        let c_read = tokio::spawn(async move {
            let mut got = Vec::new();
            cr.read_to_end(&mut got).await.unwrap();
            read_tx.send(()).unwrap();
            got
        });
        let mut got_up = Vec::new();
        sr.read_to_end(&mut got_up).await.unwrap();
        assert_eq!(got_up, up);
        assert_eq!(c_read.await.unwrap(), down);
        c_write.await.unwrap();
        s_write.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_frames_error_without_panicking() {
        let (a, mut raw) = duplex(4096);
        let mut client = WsStream::new(a, true);
        let mut bad = vec![0x80 | OP_PING, 126, 0x01, 0x00];
        bad.extend_from_slice(&[0u8; 256]);
        raw.write_all(&bad).await.unwrap();
        let mut buf = [0u8; 8];
        assert!(client.read(&mut buf).await.is_err());

        let (a, mut raw) = duplex(4096);
        let mut client = WsStream::new(a, true);
        raw.write_all(&[0x82, 127, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
            .await
            .unwrap();
        assert!(client.read(&mut buf).await.is_err());

        let (a, mut raw) = duplex(4096);
        let mut client = WsStream::new(a, true);
        raw.write_all(&[0x82, 10, b'a', b'b']).await.unwrap();
        drop(raw);
        let mut got = Vec::new();
        assert!(client.read_to_end(&mut got).await.is_err());
    }

    #[tokio::test]
    async fn masked_server_frames_are_unmasked() {
        let (a, mut raw) = duplex(4096);
        let mut client = WsStream::new(a, true);
        let mut frame = Vec::new();
        encode_frame(&mut frame, OP_BINARY, b"hello masked", true);
        raw.write_all(&frame).await.unwrap();
        let mut buf = [0u8; 12];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello masked");
    }
}
