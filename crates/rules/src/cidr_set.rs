//! `.mrs` binary codec for [`IpCidrSet`].

use std::net::{Ipv4Addr, Ipv6Addr};

use concord_common::cidr::IpCidrSet;

use crate::error::FormatError;

pub fn write_bin(set: &IpCidrSet, out: &mut Vec<u8>) {
    out.push(1);
    out.extend_from_slice(&(set.range_count() as i64).to_be_bytes());
    for &(from, to) in set.v4_ranges() {
        out.extend_from_slice(&Ipv4Addr::from(from).to_ipv6_mapped().octets());
        out.extend_from_slice(&Ipv4Addr::from(to).to_ipv6_mapped().octets());
    }
    for &(from, to) in set.v6_ranges() {
        out.extend_from_slice(&from.to_be_bytes());
        out.extend_from_slice(&to.to_be_bytes());
    }
}

/// Reads the payload that follows the `.mrs` header; returns the set and the bytes consumed.
pub fn read_bin(buf: &[u8]) -> Result<(IpCidrSet, usize), FormatError> {
    let mut cur = crate::mrs::Cursor::new(buf);
    if cur.u8()? != 1 {
        return Err(FormatError::new("version is invalid"));
    }
    let count = cur.i64()?;
    if count < 1 {
        return Err(FormatError::new("length is invalid"));
    }
    let count = usize::try_from(count).map_err(|_| FormatError::new("length is invalid"))?;
    if count > cur.remaining() / 32 {
        return Err(FormatError::new("unexpected end of data"));
    }
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for _ in 0..count {
        let from = Ipv6Addr::from(cur.array16()?);
        let to = Ipv6Addr::from(cur.array16()?);
        match (from.to_ipv4_mapped(), to.to_ipv4_mapped()) {
            (Some(from), Some(to)) => {
                let (from, to) = (u32::from(from), u32::from(to));
                if from > to {
                    return Err(FormatError::new("invalid ip range"));
                }
                v4.push((from, to));
            }
            (None, None) => {
                let (from, to) = (u128::from(from), u128::from(to));
                if from > to {
                    return Err(FormatError::new("invalid ip range"));
                }
                v6.push((from, to));
            }
            _ => return Err(FormatError::new("invalid ip range")),
        }
    }
    Ok((IpCidrSet::from_ranges(v4, v6), cur.position()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(entries: &[&str]) -> IpCidrSet {
        let mut set = IpCidrSet::new();
        for entry in entries {
            assert!(set.add_str(entry), "{entry}");
        }
        set.merge();
        set
    }

    #[test]
    fn bin_round_trips() {
        let original = set(&["10.0.0.0/8", "1.2.3.4/32", "2001:db8::/32"]);
        let mut buf = Vec::new();
        write_bin(&original, &mut buf);
        let (read, used) = read_bin(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(read, original);
    }

    #[test]
    fn truncated_bin_is_an_error_not_a_panic() {
        let original = set(&["10.0.0.0/8"]);
        let mut buf = Vec::new();
        write_bin(&original, &mut buf);
        for cut in 0..buf.len() {
            assert!(read_bin(buf.get(..cut).unwrap()).is_err());
        }
    }

    #[test]
    fn read_bin_sorts_and_merges_unsorted_or_overlapping_ranges() {
        let mut buf = Vec::new();
        buf.push(1);
        buf.extend_from_slice(&3i64.to_be_bytes());
        for (from, to) in [
            (Ipv4Addr::new(10, 0, 1, 0), Ipv4Addr::new(10, 0, 1, 255)),
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 255)),
            (Ipv4Addr::new(10, 0, 0, 128), Ipv4Addr::new(10, 0, 1, 10)),
        ] {
            buf.extend_from_slice(&from.to_ipv6_mapped().octets());
            buf.extend_from_slice(&to.to_ipv6_mapped().octets());
        }
        let (read, used) = read_bin(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(read.range_count(), 1);
        assert_eq!(read, set(&["10.0.0.0/23"]));
    }
}
