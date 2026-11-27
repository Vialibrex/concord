#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, duplex};

use super::*;

fn frame(payload: &[u8], padding: u8) -> Vec<u8> {
    let mut out = u16::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
    out.push(padding);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0, usize::from(padding)));
    out
}

fn stream_of_frames() -> (Vec<u8>, Vec<u8>) {
    let mut wire = Vec::new();
    let mut plain = Vec::new();
    for i in 0..FRAMES {
        let payload: Vec<u8> = (0..i * 7).map(|b| b as u8).collect();
        wire.extend(frame(&payload, (i * 31) as u8));
        plain.extend(payload);
    }
    wire.extend_from_slice(b"after the padded frames");
    plain.extend_from_slice(b"after the padded frames");
    (wire, plain)
}

#[test]
fn strips_the_first_frames_whatever_the_chunking() {
    let (wire, plain) = stream_of_frames();
    for chunk in [1, 2, 3, 5, 64, wire.len()] {
        let mut unpad = Unpad::default();
        let mut got = Vec::new();
        for piece in wire.chunks(chunk) {
            let mut piece = piece.to_vec();
            let n = unpad.strip(&mut piece);
            got.extend_from_slice(&piece[..n]);
        }
        assert_eq!(got, plain, "chunk {chunk}");
        assert!(unpad.done());
    }
}

#[test]
fn an_empty_unpadded_frame_counts() {
    let mut wire = frame(&[], 0);
    wire.extend(frame(b"x", 0));
    let mut unpad = Unpad::default();
    assert_eq!(unpad.strip(&mut wire), 1);
    assert_eq!(unpad.frames, 2);
}

#[tokio::test]
async fn padded_stream_round_trips_through_its_own_reader() {
    let (client, server) = duplex(1 << 20);
    let mut client = PaddingType::Variant1.wrap(Box::new(client));
    let mut server = PaddingType::Variant1.wrap(Box::new(server));
    let sizes = [1, 50, 99, 100, 150, 500, 1023, 70_000, 3, 9, 2000];
    let mut sent = Vec::new();
    for (i, size) in sizes.iter().enumerate() {
        let chunk: Vec<u8> = (0..*size).map(|b| (b + i) as u8).collect();
        client.write_all(&chunk).await.unwrap();
        sent.extend(chunk);
    }
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, sent);
}

#[tokio::test]
async fn short_writes_are_padded_to_at_least_a_full_padding() {
    let (client, mut server) = duplex(1 << 20);
    let mut client = PaddingType::Variant1.wrap(Box::new(client));
    client.write_all(&[7; 40]).await.unwrap();
    let mut head = [0; 3];
    server.read_exact(&mut head).await.unwrap();
    assert_eq!(u16::from_be_bytes([head[0], head[1]]), 40);
    assert!(usize::from(head[2]) >= MAX_PADDING - 40);
}

#[derive(Default)]
struct Recorder {
    writes: Vec<usize>,
    bytes: Vec<u8>,
}

impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.writes.push(data.len());
        this.bytes.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn mid_sized_frames_go_out_in_small_writes_and_later_writes_pass_through() {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut pad = Pad::default();
    let mut sink = Recorder::default();
    let data = [1u8; 500];
    assert!(matches!(
        pad.poll_write(&mut sink, &mut cx, &data),
        Poll::Ready(Ok(500))
    ));
    assert!(sink.writes.len() > 1);
    assert!(
        sink.writes
            .iter()
            .all(|&n| (SPLIT_CHUNK_MIN..=SPLIT_CHUNK_MAX).contains(&n)
                || n == *sink.writes.last().unwrap())
    );
    for _ in 1..FRAMES {
        assert!(matches!(
            pad.poll_write(&mut sink, &mut cx, &[2; 10]),
            Poll::Ready(Ok(10))
        ));
    }
    let before = sink.writes.len();
    assert!(matches!(
        pad.poll_write(&mut sink, &mut cx, &[3; 10]),
        Poll::Ready(Ok(10))
    ));
    assert_eq!(sink.writes[before..], [10]);
    assert_eq!(sink.bytes[sink.bytes.len() - 10..], [3; 10]);
}

#[test]
fn padding_types_parse_the_reply_values() {
    assert_eq!(PaddingType::parse("0"), Some(PaddingType::None));
    assert_eq!(PaddingType::parse("1"), Some(PaddingType::Variant1));
    assert_eq!(PaddingType::parse("2"), None);
}
