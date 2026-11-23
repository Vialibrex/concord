use std::io;
use std::net::SocketAddr;

use concord_common::Address;
use concord_netstack::wire::{
    L4Checksum, UDP_HEADER, build_udp, fragment_count, ip_header_len, write_fragment,
};

use super::pool::Slot;

pub(super) struct ReplyPacket<'a> {
    from: SocketAddr,
    local: SocketAddr,
    payload: &'a [u8],
}

impl<'a> ReplyPacket<'a> {
    pub fn new(payload: &'a [u8], from: &Address, local: SocketAddr) -> io::Result<Self> {
        let Address::Socket(from) = *from else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a reply needs an IP source address",
            ));
        };
        Ok(Self {
            from,
            local,
            payload,
        })
    }

    pub fn len(&self) -> usize {
        ip_header_len(self.local.ip()) + UDP_HEADER + self.payload.len()
    }

    fn build(&self, buf: &mut [u8], checksum: L4Checksum) -> io::Result<usize> {
        build_udp(buf, self.from, self.local, self.payload, checksum)
            .map_err(|_| io::ErrorKind::InvalidInput.into())
    }

    pub fn write(&self, slot: &mut Slot, checksum: L4Checksum) -> io::Result<()> {
        slot.len = self.build(&mut slot.buf, checksum)?;
        Ok(())
    }

    pub fn fragments(&self, mtu: usize) -> io::Result<Option<Fragments>> {
        let mut whole = vec![0; self.len()];
        let len = self.build(&mut whole, L4Checksum::Full)?;
        whole.truncate(len);
        Ok(fragment_count(&whole, mtu).map(|count| Fragments { whole, mtu, count }))
    }
}

pub(super) struct Fragments {
    whole: Vec<u8>,
    mtu: usize,
    pub count: usize,
}

impl Fragments {
    pub fn write(&self, slots: &mut [Slot], ident: u32) -> io::Result<()> {
        for (index, slot) in slots.iter_mut().enumerate() {
            slot.len = write_fragment(&self.whole, self.mtu, ident, index, &mut slot.buf)
                .ok_or(io::ErrorKind::InvalidInput)?;
        }
        Ok(())
    }
}
