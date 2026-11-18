use std::io;
use std::ops::Range;

use concord_common::{Address, PacketBuf};

mod relay;
mod stream;

pub(crate) use self::relay::{UdpRelay, Watch};
pub(crate) use self::stream::StreamSession;

pub(crate) enum Decoded {
    NeedMore,
    Skip(usize),
    Packet {
        /// `None` is the session's fixed remote.
        addr: Option<Address>,
        payload: Range<usize>,
        consumed: usize,
    },
}

/// Frames one datagram in front of its payload, in place.
pub(crate) trait Encoder: Send + 'static {
    fn headroom(&self) -> usize;
    fn encode(&self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()>;

    /// Appends the framed datagram to `out`; a protocol that splits one overrides this.
    fn encode_into(&self, pkt: &mut PacketBuf, dst: &Address, out: &mut Vec<u8>) -> io::Result<()> {
        self.encode(pkt, dst)?;
        out.extend_from_slice(pkt.as_slice());
        Ok(())
    }
}

pub(crate) trait Decoder: Send + 'static {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded>;
}

/// Unframes one whole datagram from a datagram carrier.
pub(crate) trait Opener: Send + Sync + 'static {
    /// Strips the framing and returns where the packet came from.
    fn open(&self, pkt: &mut PacketBuf) -> io::Result<Address>;
}
