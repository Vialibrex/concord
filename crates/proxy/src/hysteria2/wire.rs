use std::io;

use bytes::Bytes;
use concord_quic::Fragment;
use rand::RngExt;
#[cfg(feature = "server")]
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::util::invalid_data;

pub(crate) const FRAME_TCP_REQUEST: u64 = 0x401;
pub(crate) const MAX_MESSAGE: u64 = 2048;
pub(crate) const MAX_PADDING: u64 = 4096;
pub(crate) const MAX_UDP: usize = 4096;
pub(crate) const MAX_RESPONSE_HEAD: usize = 1 + 8 + MAX_MESSAGE as usize + 8 + MAX_PADDING as usize;

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub(crate) fn padding(min: usize, max: usize) -> String {
    let mut rng = rand::rng();
    let len = rng.random_range(min..max);
    (0..len)
        .map(|_| {
            let pick = rng.random_range(0..PADDING_CHARS.len());
            char::from(PADDING_CHARS.get(pick).copied().unwrap_or(b'a'))
        })
        .collect()
}

pub(crate) fn varint_len(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

pub(crate) fn put_varint(out: &mut Vec<u8>, value: u64) {
    match varint_len(value) {
        1 => out.push(value as u8),
        2 => out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Reads one varint, or `None` when `input` ends inside it.
pub(crate) fn get_varint(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    let bytes = input.get(..len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in bytes.iter().skip(1) {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

pub(crate) fn tcp_request(addr: &str) -> Vec<u8> {
    let pad = padding(64, 512);
    let mut out = Vec::with_capacity(addr.len() + pad.len() + 16);
    put_varint(&mut out, FRAME_TCP_REQUEST);
    put_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    put_varint(&mut out, pad.len() as u64);
    out.extend_from_slice(pad.as_bytes());
    out
}

/// One varint and the bytes it took, read no further than its end; `None` when the stream
/// ends first.
#[cfg(feature = "server")]
pub(crate) async fn read_varint<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> io::Result<Option<(u64, Vec<u8>)>> {
    let mut first = [0u8; 1];
    if recv.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let [byte] = first;
    let mut raw = vec![byte];
    raw.resize(1 << (byte >> 6), 0);
    match recv.read_exact(raw.get_mut(1..).unwrap_or_default()).await {
        Ok(_) => Ok(get_varint(&raw).map(|(value, _)| (value, raw))),
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(err) => Err(err),
    }
}

#[cfg(feature = "server")]
async fn varint_value<R: AsyncRead + Unpin>(recv: &mut R) -> io::Result<u64> {
    read_varint(recv)
        .await?
        .map(|(value, _)| value)
        .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
}

/// The rest of a TCP request after its frame type: the address it names
/// (sing-quic's `ReadTCPRequest`).
#[cfg(feature = "server")]
pub(crate) async fn read_tcp_request<R: AsyncRead + Unpin>(recv: &mut R) -> io::Result<String> {
    let addr_len = varint_value(recv).await?;
    if addr_len == 0 || addr_len > MAX_MESSAGE {
        return Err(invalid_data("invalid address length"));
    }
    let mut addr = vec![0u8; addr_len as usize];
    recv.read_exact(&mut addr).await?;
    let padding = varint_value(recv).await?;
    if padding > MAX_PADDING {
        return Err(invalid_data("invalid padding length"));
    }
    let skipped = tokio::io::copy(&mut (&mut *recv).take(padding), &mut tokio::io::sink()).await?;
    if skipped < padding {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(String::from_utf8_lossy(&addr).into_owned())
}

/// The server's answer to a TCP request it took. mihomo never answers with a refusal: a
/// target that cannot be reached closes the stream instead.
#[cfg(feature = "server")]
pub(crate) fn tcp_response() -> Vec<u8> {
    let pad = padding(128, 1024);
    let mut out = Vec::with_capacity(pad.len() + 4);
    out.push(0);
    put_varint(&mut out, 0);
    put_varint(&mut out, pad.len() as u64);
    out.extend_from_slice(pad.as_bytes());
    out
}

pub(crate) enum Response {
    Ok,
    Refused(String),
}

/// Parses the server's TCP response from the front of `input`.
/// `Ok(None)` means more bytes are needed.
pub(crate) fn parse_tcp_response(input: &[u8]) -> io::Result<Option<(Response, usize)>> {
    let Some((&status, rest)) = input.split_first() else {
        return Ok(None);
    };
    let Some((message_len, used)) = get_varint(rest) else {
        return Ok(None);
    };
    if message_len > MAX_MESSAGE {
        return Err(invalid_data("invalid message length"));
    }
    let message_len = message_len as usize;
    let message_start = 1 + used;
    let Some(message) = input.get(message_start..message_start + message_len) else {
        return Ok(None);
    };
    let after = message_start + message_len;
    let Some((padding_len, used)) = input.get(after..).and_then(get_varint) else {
        return Ok(None);
    };
    if padding_len > MAX_PADDING {
        return Err(invalid_data("invalid padding length"));
    }
    let end = after + used + padding_len as usize;
    if input.len() < end {
        return Ok(None);
    }
    let response = if status == 0 {
        Response::Ok
    } else {
        Response::Refused(String::from_utf8_lossy(message).into_owned())
    };
    Ok(Some((response, end)))
}

pub(crate) struct UdpHeader<'a> {
    pub(crate) session: u32,
    pub(crate) packet: u16,
    pub(crate) fragment: u8,
    pub(crate) fragments: u8,
    pub(crate) addr: &'a str,
}

pub(crate) fn udp_header_len(addr: &str) -> usize {
    8 + varint_len(addr.len() as u64) + addr.len()
}

pub(crate) fn put_udp_header(out: &mut Vec<u8>, header: &UdpHeader<'_>) {
    out.extend_from_slice(&header.session.to_be_bytes());
    out.extend_from_slice(&header.packet.to_be_bytes());
    out.push(header.fragment);
    out.push(header.fragments);
    put_varint(out, header.addr.len() as u64);
    out.extend_from_slice(header.addr.as_bytes());
}

pub(crate) struct UdpMessage {
    pub(crate) session: u32,
    pub(crate) packet: u16,
    pub(crate) fragment: u8,
    pub(crate) fragments: u8,
    pub(crate) addr: String,
    pub(crate) data: Bytes,
}

pub(crate) fn parse_udp(datagram: &Bytes) -> io::Result<UdpMessage> {
    let head = datagram
        .get(..8)
        .ok_or_else(|| invalid_data("short udp message"))?;
    let (session, packet, fragment, fragments) = match head {
        [a, b, c, d, e, f, g, h] => (
            u32::from_be_bytes([*a, *b, *c, *d]),
            u16::from_be_bytes([*e, *f]),
            *g,
            *h,
        ),
        _ => return Err(invalid_data("short udp message")),
    };
    let rest = datagram.get(8..).unwrap_or_default();
    let (addr_len, used) = get_varint(rest).ok_or_else(|| invalid_data("short udp message"))?;
    if addr_len == 0 || addr_len > MAX_MESSAGE {
        return Err(invalid_data("invalid address length"));
    }
    let start = 8 + used;
    let end = start + addr_len as usize;
    let addr = datagram
        .get(start..end)
        .ok_or_else(|| invalid_data("short udp message"))?;
    Ok(UdpMessage {
        session,
        packet,
        fragment,
        fragments,
        addr: String::from_utf8_lossy(addr).into_owned(),
        data: datagram.slice(end..),
    })
}

impl UdpMessage {
    pub(crate) fn into_fragment(self) -> Fragment<String> {
        Fragment {
            packet: self.packet,
            index: self.fragment,
            total: self.fragments,
            addr: Some(self.addr),
            data: self.data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn the_server_reads_the_request_and_answers_what_the_client_parses() {
        let mut wire = tcp_request("example.com:443");
        wire.extend_from_slice(b"data");
        let mut recv = wire.as_slice();
        assert_eq!(
            read_varint(&mut recv)
                .await
                .unwrap()
                .map(|(value, _)| value),
            Some(FRAME_TCP_REQUEST)
        );
        assert_eq!(
            read_tcp_request(&mut recv).await.unwrap(),
            "example.com:443"
        );
        assert_eq!(recv, b"data");

        let mut answer = tcp_response();
        let head = answer.len();
        answer.extend_from_slice(b"reply");
        let Some((Response::Ok, used)) = parse_tcp_response(&answer).unwrap() else {
            panic!("not a success");
        };
        assert_eq!(used, head);
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn a_varint_cut_short_reads_as_the_end() {
        assert!(
            read_varint(&mut [0x44u8].as_slice())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            read_varint(&mut [0u8; 0].as_slice())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn varints_round_trip_at_every_width() {
        for value in [0u64, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(out.len(), varint_len(value));
            assert_eq!(get_varint(&out), Some((value, out.len())));
        }
        assert_eq!(get_varint(&[0x44, 0x01]), Some((0x401, 2)));
        assert_eq!(get_varint(&[0x44]), None);
    }

    #[test]
    fn a_tcp_request_starts_with_the_frame_type_and_address() {
        let request = tcp_request("example.com:443");
        assert_eq!(&request[..2], &[0x44, 0x01]);
        assert_eq!(request[2], 15);
        assert_eq!(&request[3..18], b"example.com:443");
        let (pad, used) = get_varint(&request[18..]).unwrap();
        assert_eq!(request.len(), 18 + used + pad as usize);
        assert!((64..512).contains(&(pad as usize)));
    }

    #[test]
    fn a_tcp_response_waits_for_its_padding() {
        let mut wire = vec![0u8, 0, 5];
        assert!(parse_tcp_response(&wire).unwrap().is_none());
        wire.extend_from_slice(b"12345");
        let Some((Response::Ok, used)) = parse_tcp_response(&wire).unwrap() else {
            panic!("expected a complete response");
        };
        assert_eq!(used, wire.len());
    }

    #[test]
    fn a_refusal_carries_the_server_message() {
        let mut wire = vec![1u8, 4];
        wire.extend_from_slice(b"nope");
        wire.push(0);
        let Some((Response::Refused(message), _)) = parse_tcp_response(&wire).unwrap() else {
            panic!("expected a refusal");
        };
        assert_eq!(message, "nope");
    }

    #[test]
    fn an_oversized_message_is_rejected() {
        let mut wire = vec![0u8];
        put_varint(&mut wire, MAX_MESSAGE + 1);
        assert!(parse_tcp_response(&wire).is_err());
    }

    #[test]
    fn udp_messages_round_trip() {
        let mut wire = Vec::new();
        put_udp_header(
            &mut wire,
            &UdpHeader {
                session: 7,
                packet: 9,
                fragment: 1,
                fragments: 3,
                addr: "1.1.1.1:53",
            },
        );
        assert_eq!(wire.len(), udp_header_len("1.1.1.1:53"));
        wire.extend_from_slice(b"data");
        let parsed = parse_udp(&Bytes::from(wire)).unwrap();
        assert_eq!(
            (
                parsed.session,
                parsed.packet,
                parsed.fragment,
                parsed.fragments
            ),
            (7, 9, 1, 3)
        );
        assert_eq!(parsed.addr, "1.1.1.1:53");
        assert_eq!(&parsed.data[..], b"data");
    }

    #[test]
    fn a_truncated_udp_message_is_an_error() {
        assert!(parse_udp(&Bytes::from_static(&[0, 0, 0, 1, 0, 2, 0])).is_err());
        assert!(parse_udp(&Bytes::from_static(&[0, 0, 0, 1, 0, 2, 0, 1, 0])).is_err());
    }
}
