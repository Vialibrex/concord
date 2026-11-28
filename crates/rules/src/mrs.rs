//! The `.mrs` container: a zstd stream holding a header and a domain or IP-CIDR set.

use std::io::Read;

use concord_common::cidr::IpCidrSet;
use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, compress_to_vec};

use crate::cidr_set;
use crate::domain_set::DomainSet;
use crate::error::FormatError;

pub const MAGIC: [u8; 4] = [b'M', b'R', b'S', 1];

/// The two behaviors an `.mrs` file can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MrsBehavior {
    Domain,
    IpCidr,
}

impl MrsBehavior {
    fn byte(self) -> u8 {
        match self {
            MrsBehavior::Domain => 0,
            MrsBehavior::IpCidr => 1,
        }
    }
}

#[derive(Debug)]
pub enum MrsPayload {
    Domain(DomainSet),
    IpCidr(IpCidrSet),
}

#[derive(Debug)]
pub struct Mrs {
    pub count: u64,
    pub payload: MrsPayload,
}

pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, at: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }

    pub(crate) fn position(&self) -> usize {
        self.at
    }

    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a [u8], FormatError> {
        let end = self
            .at
            .checked_add(len)
            .ok_or_else(|| FormatError::new("unexpected EOF"))?;
        let out = self
            .buf
            .get(self.at..end)
            .ok_or_else(|| FormatError::new("unexpected EOF"))?;
        self.at = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.bytes(1)?.first().copied().unwrap_or(0))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, FormatError> {
        let raw: [u8; 8] = self
            .bytes(8)?
            .try_into()
            .map_err(|_| FormatError::new("unexpected EOF"))?;
        Ok(u64::from_be_bytes(raw))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, FormatError> {
        Ok(self.u64()? as i64)
    }

    pub(crate) fn array16(&mut self) -> Result<[u8; 16], FormatError> {
        self.bytes(16)?
            .try_into()
            .map_err(|_| FormatError::new("unexpected EOF"))
    }
}

pub fn is_zstd(buf: &[u8]) -> bool {
    buf.starts_with(&[0x28, 0xB5, 0x2F, 0xFD])
}

fn inflate(buf: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut decoder =
        StreamingDecoder::new(buf).map_err(|err| FormatError::new(err.to_string()))?;
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|err| FormatError::new(err.to_string()))?;
    Ok(out)
}

/// Reads an `.mrs` file whose header must declare `expected`.
pub fn decode(buf: &[u8], expected: MrsBehavior) -> Result<Mrs, FormatError> {
    let raw = inflate(buf)?;
    let mut cur = Cursor::new(&raw);
    if cur.bytes(4)? != MAGIC {
        return Err(FormatError::new("invalid MrsMagic bytes"));
    }
    if cur.u8()? != expected.byte() {
        return Err(FormatError::new("invalid behavior"));
    }
    let count = cur.i64()?;
    let extra = cur.i64()?;
    if extra < 0 {
        return Err(FormatError::new("length is invalid"));
    }
    cur.bytes(usize::try_from(extra).map_err(|_| FormatError::new("length is invalid"))?)?;
    let body = raw
        .get(cur.position()..)
        .ok_or_else(|| FormatError::new("unexpected EOF"))?;
    let payload = match expected {
        MrsBehavior::Domain => MrsPayload::Domain(DomainSet::read_bin(body)?.0),
        MrsBehavior::IpCidr => MrsPayload::IpCidr(cidr_set::read_bin(body)?.0),
    };
    Ok(Mrs {
        count: u64::try_from(count).unwrap_or(0),
        payload,
    })
}

pub fn encode(count: u64, payload: &MrsPayload) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&MAGIC);
    let behavior = match payload {
        MrsPayload::Domain(_) => MrsBehavior::Domain,
        MrsPayload::IpCidr(_) => MrsBehavior::IpCidr,
    };
    raw.push(behavior.byte());
    raw.extend_from_slice(&(count as i64).to_be_bytes());
    raw.extend_from_slice(&0i64.to_be_bytes());
    match payload {
        MrsPayload::Domain(set) => set.write_bin(&mut raw),
        MrsPayload::IpCidr(set) => cidr_set::write_bin(set, &mut raw),
    }
    compress_to_vec(raw.as_slice(), CompressionLevel::Fastest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_set::DomainSetBuilder;

    #[test]
    fn domain_file_round_trips() {
        let mut builder = DomainSetBuilder::new();
        builder.insert("+.example.com").unwrap();
        builder.insert("exact.org").unwrap();
        let set = builder.build().unwrap();
        let bytes = encode(2, &MrsPayload::Domain(set));
        assert!(is_zstd(&bytes));
        let read = decode(&bytes, MrsBehavior::Domain).unwrap();
        assert_eq!(read.count, 2);
        let MrsPayload::Domain(set) = read.payload else {
            panic!("not a domain set");
        };
        assert!(set.has("www.example.com") && set.has("exact.org"));
        assert!(!set.has("www.exact.org"));
    }

    #[test]
    fn ip_file_round_trips() {
        let mut set = IpCidrSet::new();
        assert!(set.add_str("10.0.0.0/8"));
        assert!(set.add_str("2001:db8::/32"));
        set.merge();
        let bytes = encode(2, &MrsPayload::IpCidr(set));
        let read = decode(&bytes, MrsBehavior::IpCidr).unwrap();
        let MrsPayload::IpCidr(set) = read.payload else {
            panic!("not an ip set");
        };
        assert!(set.contains("10.1.2.3".parse().unwrap()));
        assert!(set.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn behavior_mismatch_and_garbage_are_errors() {
        let mut set = IpCidrSet::new();
        set.add_str("10.0.0.0/8");
        set.merge();
        let bytes = encode(1, &MrsPayload::IpCidr(set));
        assert_eq!(
            decode(&bytes, MrsBehavior::Domain).unwrap_err().to_string(),
            "invalid behavior"
        );
        assert!(decode(b"(\xb5/\xfdgarbage", MrsBehavior::Domain).is_err());
        assert!(decode(b"", MrsBehavior::Domain).is_err());
    }
}
