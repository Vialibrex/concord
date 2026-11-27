use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::layered::{Layered, ReadLayer, WriteLayer, poll_drain};
use concord_common::stream_buffer::{self, BufferRequirements, OwnedDrain, StreamBuffer};
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::http1::invalid;

const FRONT_HEADROOM: usize = 6 + 10;

fn wire_message_len(payload_len: usize) -> Option<u32> {
    let var_len = uvarint_len(payload_len as u64);
    1usize
        .checked_add(var_len)?
        .checked_add(payload_len)
        .and_then(|total| u32::try_from(total).ok())
}

enum Read {
    Header {
        buf: [u8; 5],
        have: usize,
    },
    Tag {
        msg_len: u64,
    },
    Varint {
        msg_len: u64,
        value: u64,
        shift: u32,
        used: u64,
    },
    Payload {
        left: u64,
        trailing: u64,
    },
    Skip {
        left: u64,
    },
}

impl Read {
    fn header() -> Read {
        Read::Header {
            buf: [0; 5],
            have: 0,
        }
    }
}

pub(crate) fn uvarint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

pub(crate) fn put_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7F) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(crate) fn encode_message(out: &mut Vec<u8>, data: &[u8]) {
    let var_len = uvarint_len(data.len() as u64);
    out.push(0x00);
    out.extend_from_slice(&((1 + var_len + data.len()) as u32).to_be_bytes());
    out.push(0x0A);
    put_uvarint(out, data.len() as u64);
    out.extend_from_slice(data);
}

struct GunWrite {
    out: Vec<u8>,
    out_off: usize,
    inflight: Option<usize>,
    owned: OwnedDrain,
}

impl GunWrite {
    fn poll_message<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(done) = self.inflight {
            ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
            self.inflight = None;
            return Poll::Ready(Ok(done));
        }
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        let max_payload = usize::try_from(u32::MAX - 6).unwrap_or(usize::MAX);
        let take = data.len().min(max_payload);
        let Some(chunk) = data.get(..take).filter(|c| !c.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        encode_message(&mut self.out, chunk);
        self.inflight = Some(take);
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        self.inflight = None;
        Poll::Ready(Ok(take))
    }
}

/// gun's framing: each chunk is one gRPC message holding a protobuf message with a
/// single `bytes` field.
pub(crate) fn gun_framed<S: Stream>(inner: S) -> BoxStream {
    let write = GunWrite {
        out: Vec::new(),
        out_off: 0,
        inflight: None,
        owned: OwnedDrain::default(),
    };
    Box::new(GunStream {
        io: inner,
        read: Read::header(),
        write,
    })
}

/// The unsplit stream, which can pass an owned message to the stream under it. Its halves
/// are `Layered`'s and write plain bytes.
struct GunStream<S> {
    io: S,
    read: Read,
    write: GunWrite,
}

impl<S: Stream> AsyncRead for GunStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ReadLayer::poll_read(&mut this.read, &mut this.io, cx, buf)
    }
}

impl<S: Stream> AsyncWrite for GunStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_owned(cx))?;
        this.write.poll_message(&mut this.io, cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_owned(cx))?;
        ready!(poll_drain(
            &mut this.io,
            cx,
            &mut this.write.out,
            &mut this.write.out_off
        ))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_owned(cx))?;
        ready!(poll_drain(
            &mut this.io,
            cx,
            &mut this.write.out,
            &mut this.write.out_off
        ))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

impl<S: Stream> GunStream<S> {
    fn poll_owned(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.write
            .owned
            .poll_drain(|buffer| self.io.poll_write_buffer(cx, buffer))
    }
}

impl<S: Stream> Stream for GunStream<S> {
    concord_common::stream_policy!(io;
        own: into_split, write_requirements, poll_write_buffer;
        default: read_requirements, poll_read_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn write_requirements(&self) -> BufferRequirements {
        // gun.Conn advertises 6 + binary.MaxVarintLen64 bytes and no writer MTU.
        BufferRequirements {
            front: FRONT_HEADROOM,
            ..BufferRequirements::default()
        }
        .compose_writer(self.io.write_requirements())
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_owned(cx))?;
        if self.write.inflight.is_some() {
            return stream_buffer::poll_write_buffer(self, cx, buffer);
        }
        ready!(poll_drain(
            &mut self.io,
            cx,
            &mut self.write.out,
            &mut self.write.out_off
        ))?;
        let length = buffer.len();
        let requirements = self.write_requirements();
        let Some(msg_len) = wire_message_len(length) else {
            return stream_buffer::poll_write_buffer(self, cx, buffer);
        };
        if length == 0
            || buffer.headroom() < requirements.front
            || buffer.tailroom() < requirements.rear
        {
            return stream_buffer::poll_write_buffer(self, cx, buffer);
        }
        let var_len = uvarint_len(length as u64);
        let head = buffer.prepend(6 + var_len)?;
        let (prefix, varint) = head
            .split_at_mut_checked(6)
            .ok_or_else(|| invalid("short gRPC header"))?;
        let [a, b, c, d] = msg_len.to_be_bytes();
        prefix.copy_from_slice(&[0, a, b, c, d, 0x0A]);
        let mut value = length as u64;
        for byte in varint {
            *byte = value as u8 & 0x7F;
            value >>= 7;
            if value != 0 {
                *byte |= 0x80;
            }
        }
        self.write.owned.start(buffer);
        if let Poll::Ready(Err(error)) = self.poll_owned(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(length))
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let GunStream { io, read, write } = *self;
        Box::new(Layered::new(io, read, write)).into_split()
    }
}

impl ReadLayer for Read {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut *self {
                Read::Header { buf: head, have } => {
                    let Some(window) = head.get_mut(*have..) else {
                        return Poll::Ready(Err(invalid("gRPC header overflow")));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        if *have == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *have += got;
                    if *have == head.len() {
                        if head[0] != 0 {
                            return Poll::Ready(Err(invalid("compressed gRPC message")));
                        }
                        let msg_len =
                            u64::from(u32::from_be_bytes([head[1], head[2], head[3], head[4]]));
                        *self = if msg_len == 0 {
                            Read::header()
                        } else {
                            Read::Tag { msg_len }
                        };
                    }
                }
                Read::Tag { msg_len } => {
                    let mut byte = [0u8; 1];
                    let mut window = ReadBuf::new(&mut byte);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    if window.filled().is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    if byte[0] != 0x0A {
                        return Poll::Ready(Err(invalid(
                            "unexpected protobuf tag in gRPC message",
                        )));
                    }
                    *self = Read::Varint {
                        msg_len: *msg_len - 1,
                        value: 0,
                        shift: 0,
                        used: 1,
                    };
                }
                Read::Varint {
                    msg_len,
                    value,
                    shift,
                    used,
                } => {
                    let mut byte = [0u8; 1];
                    let mut window = ReadBuf::new(&mut byte);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    if window.filled().is_empty() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    if *shift >= 63 {
                        return Poll::Ready(Err(invalid("invalid length")));
                    }
                    *value |= u64::from(byte[0] & 0x7F) << *shift;
                    *shift += 7;
                    *used += 1;
                    if byte[0] & 0x80 == 0 {
                        let consumed = *used;
                        let total = *msg_len + 1;
                        if consumed > total || *value > total - consumed {
                            return Poll::Ready(Err(invalid("invalid length")));
                        }
                        *self = Read::Payload {
                            left: *value,
                            trailing: total - consumed - *value,
                        };
                    }
                }
                Read::Payload { left, trailing } => {
                    if *left == 0 {
                        *self = if *trailing == 0 {
                            Read::header()
                        } else {
                            Read::Skip { left: *trailing }
                        };
                        continue;
                    }
                    let take = usize::try_from(*left)
                        .unwrap_or(usize::MAX)
                        .min(buf.remaining());
                    if take == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let target = buf.initialize_unfilled_to(take);
                    let mut window = ReadBuf::new(target);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    buf.advance(got);
                    *left -= got as u64;
                    return Poll::Ready(Ok(()));
                }
                Read::Skip { left } => {
                    let mut sink = [0u8; 512];
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
                    if *left == 0 {
                        *self = Read::header();
                    }
                }
            }
        }
    }
}

impl WriteLayer for GunWrite {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_owned_plain(io, cx))?;
        self.poll_message(io, cx, data)
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_owned_plain(io, cx))?;
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_owned_plain(io, cx))?;
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

impl GunWrite {
    fn poll_owned_plain<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.owned
            .poll_drain(|buffer| stream_buffer::poll_write_buffer(&mut *io, cx, buffer))
    }
}

#[cfg(test)]
mod tests {
    use concord_common::stream_buffer::ReadBufferOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn message_layout_matches_gun() {
        let mut out = Vec::new();
        encode_message(&mut out, b"abc");
        assert_eq!(out, [0, 0, 0, 0, 5, 0x0A, 3, b'a', b'b', b'c']);
        let mut big = Vec::new();
        encode_message(&mut big, &vec![7u8; 300]);
        assert_eq!(&big[..8], &[0, 0, 0, 1, 47, 0x0A, 0xAC, 0x02]);
        assert_eq!(big.len(), 5 + 1 + 2 + 300);
        assert_eq!(u32::from_be_bytes([big[1], big[2], big[3], big[4]]), 303);
    }

    #[test]
    fn varint_lengths_match_go() {
        for (value, len) in [
            (0u64, 1),
            (127, 1),
            (128, 2),
            (16383, 2),
            (16384, 3),
            (u32::MAX as u64, 5),
        ] {
            assert_eq!(uvarint_len(value), len);
            let mut out = Vec::new();
            put_uvarint(&mut out, value);
            assert_eq!(out.len(), len);
        }
    }

    #[tokio::test]
    async fn round_trips_a_stream_larger_than_a_message() {
        let (a, b) = duplex(1 << 16);
        let mut near = gun_framed(a);
        let mut far = gun_framed(b);
        let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 249) as u8).collect();
        let sent = payload.clone();
        let writer = tokio::spawn(async move {
            near.write_all(&sent).await.unwrap();
            near.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        far.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, payload);
    }

    fn owned(sender: &BoxStream, payload: &[u8]) -> StreamBuffer {
        let options =
            ReadBufferOptions::for_copy(Default::default(), sender.write_requirements()).unwrap();
        let mut buffer = options.take_for_read(payload.len(), 0).unwrap();
        buffer.spare_mut()[..payload.len()].copy_from_slice(payload);
        buffer.advance(payload.len()).unwrap();
        buffer
    }

    #[tokio::test]
    async fn owned_messages_survive_partial_writes_then_scalar_data_and_close() {
        for length in [1, 127, 128, 15_000, 32 * 1024 - FRONT_HEADROOM, 64 * 1024] {
            let payload: Vec<_> = (0..length).map(|n| (n % 239) as u8).collect();
            let (near, mut far) = duplex(7);
            let mut sender = gun_framed(near);
            let mut buffer = owned(&sender, &payload);
            let mut expected = Vec::new();
            encode_message(&mut expected, &payload);
            encode_message(&mut expected, b"tail");
            let writer = async {
                let accepted = std::future::poll_fn(|cx| sender.poll_write_buffer(cx, &mut buffer))
                    .await
                    .unwrap();
                assert_eq!(accepted, length);
                assert!(buffer.is_empty());
                sender.write_all(b"tail").await.unwrap();
                sender.shutdown().await.unwrap();
            };
            let reader = async {
                let mut wire = Vec::new();
                far.read_to_end(&mut wire).await.unwrap();
                wire
            };
            let ((), wire) = tokio::join!(writer, reader);
            assert_eq!(wire, expected);
        }
    }

    #[tokio::test]
    async fn large_owned_and_streaming_messages_round_trip_as_single_frames() {
        for length in [48 * 1024usize, 1 << 20] {
            let payload: Vec<_> = (0..length).map(|n| ((n * 29) % 251) as u8).collect();
            let (near, far) = duplex(1 << 16);
            let mut sender = gun_framed(near);
            let mut receiver = gun_framed(far);
            let mut buffer = owned(&sender, &payload);
            let mut expected = Vec::new();
            encode_message(&mut expected, &payload);
            assert_eq!(
                u32::from_be_bytes([expected[1], expected[2], expected[3], expected[4]]) as usize,
                1 + uvarint_len(length as u64) + length
            );
            let writer = async {
                let accepted = std::future::poll_fn(|cx| sender.poll_write_buffer(cx, &mut buffer))
                    .await
                    .unwrap();
                assert_eq!(accepted, length);
                assert!(buffer.is_empty());
                sender.shutdown().await.unwrap();
            };
            // Read with a small 4 KiB caller buffer to verify streaming decode without
            // pre-allocating by declared message length.
            let reader = async {
                let mut got = Vec::with_capacity(length);
                let mut chunk = [0u8; 4096];
                loop {
                    let n = receiver.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&chunk[..n]);
                }
                got
            };
            let ((), got) = tokio::join!(writer, reader);
            assert_eq!(got, payload);
        }
    }

    #[tokio::test]
    async fn insufficient_headroom_keeps_the_scalar_fallback_across_pending() {
        let (near, mut far) = duplex(2);
        let mut sender = gun_framed(near);
        let mut buffer = ReadBufferOptions::for_copy(Default::default(), Default::default())
            .unwrap()
            .take();
        buffer.spare_mut()[..8].copy_from_slice(b"fallback");
        buffer.advance(8).unwrap();
        let writer = async {
            assert_eq!(
                std::future::poll_fn(|cx| sender.poll_write_buffer(cx, &mut buffer))
                    .await
                    .unwrap(),
                8
            );
            assert!(buffer.is_empty());
            sender.shutdown().await.unwrap();
        };
        let reader = async {
            let mut bytes = Vec::new();
            far.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let ((), wire) = tokio::join!(writer, reader);
        let mut expected = Vec::new();
        encode_message(&mut expected, b"fallback");
        assert_eq!(wire, expected);
    }

    #[tokio::test]
    async fn the_write_half_finishes_an_owned_message_accepted_before_the_split() {
        let payload: Vec<_> = (0..300).map(|n| (n % 239) as u8).collect();
        let (near, mut far) = duplex(7);
        let mut sender = gun_framed(near);
        let mut buffer = owned(&sender, &payload);
        let accepted = std::future::poll_fn(|cx| sender.poll_write_buffer(cx, &mut buffer))
            .await
            .unwrap();
        assert_eq!(accepted, payload.len());
        let (_read, mut write) = sender.into_split();
        let writer = async {
            write.write_all(b"tail").await.unwrap();
            write.shutdown().await.unwrap();
        };
        let reader = async {
            let mut wire = Vec::new();
            far.read_to_end(&mut wire).await.unwrap();
            wire
        };
        let ((), wire) = tokio::join!(writer, reader);
        let mut expected = Vec::new();
        encode_message(&mut expected, &payload);
        encode_message(&mut expected, b"tail");
        assert_eq!(wire, expected);
    }

    #[tokio::test]
    async fn reads_one_byte_at_a_time_and_skips_empty_messages_and_extra_fields() {
        let mut wire = Vec::new();
        encode_message(&mut wire, b"");
        wire.extend_from_slice(&[0, 0, 0, 0, 0]);
        // a message with the payload field followed by an unknown field (tag 0x10, value 1)
        wire.extend_from_slice(&[0, 0, 0, 0, 6, 0x0A, 2, b'h', b'i', 0x10, 1]);
        encode_message(&mut wire, b"!");
        let (a, mut b) = duplex(64);
        let mut reader = gun_framed(a);
        b.write_all(&wire).await.unwrap();
        drop(b);
        let mut got = Vec::new();
        let mut one = [0u8; 1];
        loop {
            let n = reader.read(&mut one).await.unwrap();
            if n == 0 {
                break;
            }
            got.push(one[0]);
        }
        assert_eq!(got, b"hi!");
    }

    #[tokio::test]
    async fn malformed_messages_are_errors() {
        for wire in [
            vec![1u8, 0, 0, 0, 3, 0x0A, 1, b'a'],
            vec![0, 0, 0, 0, 3, 0x12, 1, b'a'],
            vec![0, 0, 0, 0, 3, 0x0A, 9, b'a'],
            vec![
                0, 0, 0, 0, 12, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01,
            ],
            vec![0, 0, 0, 0, 9, 0x0A, 3, b'a'],
        ] {
            let (a, mut b) = duplex(64);
            let mut reader = gun_framed(a);
            b.write_all(&wire).await.unwrap();
            drop(b);
            let mut got = Vec::new();
            assert!(reader.read_to_end(&mut got).await.is_err(), "{wire:?}");
        }
    }

    #[tokio::test]
    async fn the_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let (a, b) = duplex(1 << 16);
        let (mut read, mut write) = gun_framed(a).into_split();
        let (mut far_read, mut far_write) = gun_framed(b).into_split();
        let writer = tokio::spawn(async move {
            write.write_all(b"ping").await.unwrap();
            write.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        let mut got = Vec::new();
        far_read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");
        writer.await.unwrap();
        far_write.write_all(b"pong").await.unwrap();
        far_write.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"pong");
    }
}
