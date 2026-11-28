use crate::frame::{self, Error, Head, Kind, Reason, StreamId};

use bytes::BufMut;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Reset {
    stream_id: StreamId,
    error_code: Reason,
    // Concord: padding of an empty END_STREAM DATA frame written just ahead of this reset.
    padded_end: u8,
}

impl Reset {
    pub fn new(stream_id: StreamId, error: Reason) -> Reset {
        Reset {
            stream_id,
            error_code: error,
            padded_end: 0,
        }
    }

    // Concord: `padding` counts the pad-length octet, as Chromium's
    // `SpdySession::EnqueueResetStreamFrame` writes it.
    pub(crate) fn set_padded_end(&mut self, padding: u8) {
        self.padded_end = padding;
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn reason(&self) -> Reason {
        self.error_code
    }

    pub fn load(head: Head, payload: &[u8]) -> Result<Reset, Error> {
        if payload.len() != 4 {
            return Err(Error::InvalidPayloadLength);
        }

        let error_code = unpack_octets_4!(payload, 0, u32);

        Ok(Reset {
            stream_id: head.stream_id(),
            error_code: error_code.into(),
            padded_end: 0,
        })
    }

    pub fn encode<B: BufMut>(&self, dst: &mut B) {
        tracing::trace!(
            "encoding RESET; id={:?} code={:?}",
            self.stream_id,
            self.error_code
        );
        // Concord: Chromium's padded empty END_STREAM DATA ahead of the reset.
        if self.padded_end > 0 {
            const END_STREAM_PADDED: u8 = 0x1 | 0x8;
            let pad = usize::from(self.padded_end);
            Head::new(Kind::Data, END_STREAM_PADDED, self.stream_id).encode(pad, dst);
            dst.put_u8(self.padded_end - 1);
            dst.put_bytes(0, pad - 1);
        }
        let head = Head::new(Kind::Reset, 0, self.stream_id);
        head.encode(4, dst);
        dst.put_u32(self.error_code.into());
    }
}

impl<B> From<Reset> for frame::Frame<B> {
    fn from(src: Reset) -> Self {
        frame::Frame::Reset(src)
    }
}
