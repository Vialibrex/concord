//! Go's `gzipReader` (`transport.go:3117-3211`), which unpacks an answer the
//! transport asked gzip for: every member in turn, each with its CRC and length checked.

use std::io::{self, Write};

use bytes::Bytes;
use flate2::write::MultiGzDecoder;

pub(super) struct Gunzip {
    decoder: MultiGzDecoder<Vec<u8>>,
    fed: bool,
}

impl Gunzip {
    pub(super) fn new() -> Self {
        Gunzip {
            decoder: MultiGzDecoder::new(Vec::new()),
            fed: false,
        }
    }

    /// How much of `input` one step took and what it unpacked: no more than flate2's 32 KiB
    /// buffer and miniz_oxide's 32 KiB dictionary hold, so a small body never unpacks into
    /// memory all at once.
    pub(super) fn write(&mut self, input: &[u8]) -> io::Result<(usize, Bytes)> {
        self.fed |= !input.is_empty();
        let taken = self.decoder.write(input)?;
        if taken == 0 && !input.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "gzip took nothing",
            ));
        }
        self.decoder.flush()?;
        Ok((taken, self.take()))
    }

    /// The rest once the body has ended. A body with no bytes at all unpacks to nothing, as
    /// Go's reader meets `io.EOF` before a header and the copy takes that for the end.
    pub(super) fn finish(mut self) -> io::Result<Bytes> {
        if !self.fed {
            return Ok(Bytes::new());
        }
        self.decoder.try_finish()?;
        Ok(self.take())
    }

    fn take(&mut self) -> Bytes {
        Bytes::from(std::mem::take(self.decoder.get_mut()))
    }
}

#[cfg(test)]
mod tests {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    fn packed(text: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(text).unwrap();
        encoder.finish().unwrap()
    }

    fn unpack(body: &[u8], step: usize) -> io::Result<(Vec<u8>, usize)> {
        let mut gunzip = Gunzip::new();
        let mut got = Vec::new();
        let mut largest = 0;
        for piece in body.chunks(step) {
            let mut rest = piece;
            while !rest.is_empty() {
                let (taken, out) = gunzip.write(rest)?;
                largest = largest.max(out.len());
                got.extend_from_slice(&out);
                rest = rest.get(taken..).unwrap_or_default();
            }
        }
        got.extend_from_slice(&gunzip.finish()?);
        Ok((got, largest))
    }

    #[test]
    fn members_unpack_one_after_another_however_the_body_is_cut() {
        let mut body = packed(b"first, ");
        body.extend(packed(b"second"));
        for step in [1, 7, body.len()] {
            assert_eq!(unpack(&body, step).unwrap().0, b"first, second");
        }
    }

    #[test]
    fn an_empty_body_unpacks_to_nothing() {
        assert_eq!(unpack(b"", 1).unwrap().0, b"");
    }

    #[test]
    fn a_body_cut_short_with_a_wrong_crc_or_with_bytes_after_it_fails() {
        let body = packed(b"some text to pack");
        assert!(unpack(&body[..body.len() - 3], 4).is_err());
        let mut crc = body.clone();
        let at = crc.len() - 8;
        crc[at] ^= 1;
        assert!(unpack(&crc, 4).is_err());
        let mut after = body;
        after.extend_from_slice(b"tail");
        assert!(unpack(&after, 4).is_err());
        assert!(unpack(b"not gzip at all", 4).is_err());
    }

    #[test]
    fn a_body_that_unpacks_large_comes_out_two_windows_at_a_time() {
        let text = vec![0u8; 4 << 20];
        let body = packed(&text);
        let (got, largest) = unpack(&body, body.len()).unwrap();
        assert_eq!(got.len(), text.len());
        assert!(largest <= 65 * 1024, "{largest}");
    }
}
