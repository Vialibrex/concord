use std::io;

use concord_common::{Address, PacketBuf};

use super::meta::invalid;
use crate::addr_codec::{MAX_ADDR_LEN, SOCKS};
use crate::dgram::{Decoded, Decoder, Encoder};

const START: u8 = 0x00;
const END: u8 = 0xff;

pub(super) struct Frames;

impl Encoder for Frames {
    fn headroom(&self) -> usize {
        MAX_ADDR_LEN + 6
    }

    fn encode(&self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        let addr_len = SOCKS.len(dst);
        SOCKS.write_into(dst, pkt.prepend(addr_len))?;
        pkt.prepend(3).fill(0);
        let len = u16::try_from(pkt.len()).map_err(|_| invalid("datagram too long"))?;
        let head = pkt.prepend(3);
        if let Some(first) = head.first_mut() {
            *first = START;
        }
        if let Some(size) = head.get_mut(1..3) {
            size.copy_from_slice(&len.to_be_bytes());
        }
        pkt.extend_from_slice(&[END]);
        Ok(())
    }
}

impl Decoder for Frames {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
        let Some(&[start, hi, lo]) = input.get(..3) else {
            return Ok(Decoded::NeedMore);
        };
        if start != START {
            return Err(invalid("packet prefix is not 0x00"));
        }
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        let Some(frame) = input.get(3..3 + len + 1) else {
            return Ok(Decoded::NeedMore);
        };
        let consumed = 3 + len + 1;
        if frame.last() != Some(&END) {
            return Err(invalid("packet suffix is not 0xff"));
        }
        let body = frame.get(..len).unwrap_or_default();
        if body.len() < 4 || body.get(..3) != Some(&[0, 0, 0]) {
            return Err(invalid("invalid UDP header"));
        }
        let rest = body.get(3..).unwrap_or_default();
        let Some((addr, used)) = SOCKS.parse(rest)? else {
            return Err(invalid("truncated UDP header"));
        };
        Ok(Decoded::Packet {
            addr: Some(addr),
            payload: 3 + 3 + used..3 + len,
            consumed,
        })
    }
}
