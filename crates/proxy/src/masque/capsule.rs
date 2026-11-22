use std::io;

use bytes::Bytes;
use quinn_proto::VarInt;
use quinn_proto::coding::Codec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) async fn varint(read: &mut (impl AsyncRead + Unpin)) -> io::Result<u64> {
    let first = read.read_u8().await?;
    let size = 1usize << (first >> 6);
    let mut raw = [first, 0, 0, 0, 0, 0, 0, 0];
    let encoded = raw.get_mut(..size).unwrap_or_default();
    if let Some(rest) = encoded.get_mut(1..) {
        read.read_exact(rest).await?;
    }
    VarInt::decode(&mut &*encoded)
        .map(VarInt::into_inner)
        .map_err(io::Error::other)
}

pub(super) async fn skip(read: &mut (impl AsyncRead + Unpin), length: u64) -> io::Result<()> {
    let copied = tokio::io::copy(&mut read.take(length), &mut tokio::io::sink()).await?;
    if copied != length {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

pub(super) fn encode(kind: u32, payload: &mut bytes::BytesMut) -> io::Result<()> {
    let mut raw = [0; 16];
    let mut room = raw.as_mut_slice();
    VarInt::from_u32(kind).encode(&mut room);
    VarInt::from_u64(payload.len() as u64)
        .map_err(io::Error::other)?
        .encode(&mut room);
    let used = 16 - room.len();
    prepend(payload, raw.get(..used).unwrap_or_default());
    Ok(())
}

pub(super) async fn send(
    write: &mut (impl AsyncWrite + Unpin),
    kind: u32,
    payload: &[u8],
) -> io::Result<()> {
    let mut raw = [0; 16];
    let mut room = raw.as_mut_slice();
    VarInt::from_u32(kind).encode(&mut room);
    VarInt::from_u64(payload.len() as u64)
        .map_err(io::Error::other)?
        .encode(&mut room);
    let used = 16 - room.len();
    write.write_all(raw.get(..used).unwrap_or_default()).await?;
    write.write_all(payload).await?;
    write.flush().await
}

pub(super) fn routes() -> Bytes {
    let mut body = Vec::new();
    body.push(4);
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&[255; 4]);
    body.push(0);
    body.push(6);
    body.extend_from_slice(&[0; 16]);
    body.extend_from_slice(&[255; 16]);
    body.push(0);
    body.into()
}

pub(super) fn prepend(buf: &mut bytes::BytesMut, head: &[u8]) {
    let len = buf.len();
    buf.resize(len + head.len(), 0);
    buf.copy_within(..len, head.len());
    let (front, _) = buf.split_at_mut(head.len());
    front.copy_from_slice(head);
}

pub(super) fn decrement_hop(packet: &mut [u8]) -> bool {
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            let Some(header) = packet.first_chunk_mut::<20>() else {
                return false;
            };
            if header[8] <= 1 {
                return false;
            }
            header[8] -= 1;
            header[10..12].fill(0);
            let mut sum: u32 = header
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&word| u32::from(u16::from_be_bytes(word)))
                .sum();
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            header[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            true
        }
        Some(6) => match packet.first_chunk_mut::<40>() {
            Some(header) if header[7] > 1 => {
                header[7] -= 1;
                true
            }
            _ => false,
        },
        _ => false,
    }
}
