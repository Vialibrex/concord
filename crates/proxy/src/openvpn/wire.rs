use std::io;

pub(super) const HARD_RESET_SERVER_V1: u8 = 2;
pub(super) const SOFT_RESET: u8 = 3;
pub(super) const CONTROL: u8 = 4;
pub(super) const ACK: u8 = 5;
pub(super) const DATA_V1: u8 = 6;
pub(super) const HARD_RESET_CLIENT_V2: u8 = 7;
pub(super) const HARD_RESET_SERVER_V2: u8 = 8;
pub(super) const DATA_V2: u8 = 9;
pub(super) const HARD_RESET_CLIENT_V3: u8 = 10;

pub(super) const KEY_ID_MASK: u8 = 0x07;
pub(super) const HEADER_LEN: usize = 1 + SESSION_LEN;
pub(super) const SESSION_LEN: usize = 8;
pub(super) const ACK_CAPACITY: usize = 8;

pub(super) type SessionId = [u8; SESSION_LEN];

pub(super) const PING: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

pub(super) fn opcode(first: u8) -> u8 {
    first >> 3
}

pub(super) fn key_id(first: u8) -> u8 {
    first & KEY_ID_MASK
}

pub(super) fn is_control(op: u8) -> bool {
    matches!(op, 1..=5 | 7 | 8 | 10 | 11)
}

pub(super) fn is_data(op: u8) -> bool {
    matches!(op, DATA_V1 | DATA_V2)
}

/// mihomo's `NextKeyID`: 0 is only the first epoch, so 7 wraps to 1.
pub(super) fn next_key_id(current: u8) -> u8 {
    match (current + 1) & KEY_ID_MASK {
        0 => 1,
        next => next,
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ControlPacket {
    pub(super) op: u8,
    pub(super) key_id: u8,
    pub(super) session: SessionId,
    pub(super) acks: Vec<u32>,
    pub(super) ack_session: SessionId,
    pub(super) message_id: u32,
    pub(super) payload: Vec<u8>,
}

impl ControlPacket {
    pub(super) fn carries_message(&self) -> bool {
        self.op != ACK
    }

    pub(super) fn header(&self) -> [u8; HEADER_LEN] {
        let mut header = [0; HEADER_LEN];
        header[0] = (self.op << 3) | (self.key_id & KEY_ID_MASK);
        header[1..].copy_from_slice(&self.session);
        header
    }

    /// Everything after the header: what tls-auth and tls-crypt protect.
    pub(super) fn plain(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.acks.len() * 4 + 12 + self.payload.len());
        out.push(u8::try_from(self.acks.len()).unwrap_or(0));
        for ack in &self.acks {
            out.extend_from_slice(&ack.to_be_bytes());
        }
        if !self.acks.is_empty() {
            out.extend_from_slice(&self.ack_session);
        }
        if self.carries_message() {
            out.extend_from_slice(&self.message_id.to_be_bytes());
            out.extend_from_slice(&self.payload);
        }
        out
    }

    pub(super) fn decode(header: &[u8], plain: &[u8]) -> io::Result<ControlPacket> {
        let (&first, session) = header
            .split_first()
            .filter(|(_, session)| session.len() == SESSION_LEN)
            .ok_or_else(|| malformed("control header"))?;
        let op = opcode(first);
        if !is_control(op) {
            return Err(malformed("control opcode"));
        }
        let mut reader = Reader(plain);
        let count = usize::from(reader.u8()?);
        if count > ACK_CAPACITY {
            return Err(malformed("control ACK count"));
        }
        let mut acks = Vec::with_capacity(count);
        for _ in 0..count {
            acks.push(reader.u32()?);
        }
        let mut ack_session = SessionId::default();
        if count > 0 {
            ack_session.copy_from_slice(reader.take(SESSION_LEN)?);
        }
        let mut packet = ControlPacket {
            op,
            key_id: key_id(first),
            session: session.try_into().map_err(|_| malformed("session"))?,
            acks,
            ack_session,
            ..ControlPacket::default()
        };
        if packet.carries_message() {
            packet.message_id = reader.u32()?;
            packet.payload = reader.0.to_vec();
        } else if !reader.0.is_empty() {
            return Err(malformed("ACK packet with a payload"));
        }
        Ok(packet)
    }
}

pub(super) fn malformed(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("malformed OpenVPN {what}"),
    )
}

pub(super) struct Reader<'a>(pub(super) &'a [u8]);

impl<'a> Reader<'a> {
    pub(super) fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let (head, rest) = self
            .0
            .split_at_checked(len)
            .ok_or_else(|| malformed("packet length"))?;
        self.0 = rest;
        Ok(head)
    }

    pub(super) fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or_else(|| malformed("packet length"))?;
        self.0 = rest;
        Ok(*head)
    }

    pub(super) fn u8(&mut self) -> io::Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}
