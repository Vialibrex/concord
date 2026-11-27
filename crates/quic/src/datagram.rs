use std::sync::Arc;

use quinn_proto::ConnectError;
use quinn_proto::ConnectionId;
use quinn_proto::Side;
use quinn_proto::crypto::{ClientConfig, Keys, ServerConfig, Session, UnsupportedVersion};
use quinn_proto::transport_parameters::TransportParameters;

const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

fn read_varint(input: &[u8]) -> Option<(u64, &[u8])> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    let (head, rest) = input.split_at_checked(len)?;
    let value = head.iter().enumerate().fold(0u64, |acc, (i, byte)| {
        let byte = if i == 0 { byte & 0x3f } else { *byte };
        (acc << 8) | u64::from(byte)
    });
    Some((value, rest))
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=63 => out.push(value as u8),
        64..=16_383 => out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        16_384..=1_073_741_823 => {
            out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes())
        }
        _ => out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// Rewrites `max_datagram_frame_size` in an encoded transport parameter list.
fn cap_frame(raw: &[u8], frame: u64) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len() + 2);
    let mut rest = raw;
    while !rest.is_empty() {
        let (id, after_id) = read_varint(rest)?;
        let (len, after_len) = read_varint(after_id)?;
        let (value, next) = after_len.split_at_checked(usize::try_from(len).ok()?)?;
        write_varint(&mut out, id);
        if id == MAX_DATAGRAM_FRAME_SIZE {
            let mut replacement = Vec::new();
            write_varint(&mut replacement, frame);
            write_varint(&mut out, replacement.len() as u64);
            out.extend_from_slice(&replacement);
        } else {
            write_varint(&mut out, len);
            out.extend_from_slice(value);
        }
        rest = next;
    }
    Some(out)
}

/// quinn derives the `max_datagram_frame_size` it advertises from the size of
/// its datagram receive buffer, so the two cannot differ. This advertises
/// `frame` while the buffer stays large.
pub struct CappedFrame<C: ?Sized> {
    inner: Arc<C>,
    frame: u64,
}

impl<C: ?Sized> CappedFrame<C> {
    pub fn new(inner: Arc<C>, frame: u64) -> Self {
        CappedFrame { inner, frame }
    }

    /// Read back as the client reads them, which admits the parameters only a server sends.
    fn capped(&self, params: &TransportParameters) -> Option<TransportParameters> {
        let mut raw = Vec::new();
        params.write(&mut raw);
        cap_frame(&raw, self.frame)
            .and_then(|bytes| TransportParameters::read(Side::Client, &mut bytes.as_slice()).ok())
    }
}

impl<C: ClientConfig + ?Sized> ClientConfig for CappedFrame<C> {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let capped = self.capped(params);
        self.inner
            .clone()
            .start_session(version, server_name, capped.as_ref().unwrap_or(params))
    }
}

impl<C: ServerConfig + ?Sized> ServerConfig for CappedFrame<C> {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        self.inner.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        let capped = self.capped(params);
        self.inner
            .clone()
            .start_session(version, capped.as_ref().unwrap_or(params))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_every_width() {
        for value in [0, 63, 64, 16_383, 16_384, 1_073_741_823, 1_073_741_824] {
            let mut out = Vec::new();
            write_varint(&mut out, value);
            assert_eq!(read_varint(&out), Some((value, &[][..])));
        }
    }

    #[test]
    fn only_the_datagram_parameter_changes() {
        let mut raw = Vec::new();
        for (id, value) in [
            (0x04u64, 7u64),
            (MAX_DATAGRAM_FRAME_SIZE, 65_535),
            (0x09, 3),
        ] {
            let mut body = Vec::new();
            write_varint(&mut body, value);
            write_varint(&mut raw, id);
            write_varint(&mut raw, body.len() as u64);
            raw.extend_from_slice(&body);
        }
        let capped = cap_frame(&raw, 1200).unwrap();
        let mut rest = capped.as_slice();
        let mut seen = Vec::new();
        while !rest.is_empty() {
            let (id, after) = read_varint(rest).unwrap();
            let (len, after) = read_varint(after).unwrap();
            let (value, next) = after.split_at(len as usize);
            seen.push((id, read_varint(value).unwrap().0));
            rest = next;
        }
        assert_eq!(
            seen,
            [(0x04, 7), (MAX_DATAGRAM_FRAME_SIZE, 1200), (0x09, 3)]
        );
    }

    #[test]
    fn a_truncated_list_is_refused() {
        assert!(cap_frame(&[0x20, 0x04, 1], 1200).is_none());
    }
}
