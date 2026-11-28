//! A set of IP ranges with the merge semantics of mihomo's `IpCidrSet`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Go's `netip.ParsePrefix`: `addr/bits`, decimal bits without sign or leading zero.
pub fn parse_prefix(text: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = text.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    if bits.is_empty()
        || !bits.bytes().all(|b| b.is_ascii_digit())
        || (bits.len() > 1 && bits.starts_with('0'))
    {
        return None;
    }
    let bits: u8 = bits.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((addr, bits))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IpCidrSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn mask_v4(bits: u8) -> u32 {
    match bits {
        0 => 0,
        b => u32::MAX << (32 - u32::from(b.min(32))),
    }
}

fn mask_v6(bits: u8) -> u128 {
    match bits {
        0 => 0,
        b => u128::MAX << (128 - u32::from(b.min(128))),
    }
}

impl IpCidrSet {
    pub fn new() -> Self {
        IpCidrSet::default()
    }

    pub fn from_ranges(v4: Vec<(u32, u32)>, v6: Vec<(u128, u128)>) -> Self {
        let mut set = IpCidrSet { v4, v6 };
        set.merge();
        set
    }

    pub fn v4_ranges(&self) -> &[(u32, u32)] {
        &self.v4
    }

    pub fn v6_ranges(&self) -> &[(u128, u128)] {
        &self.v6
    }

    pub fn add_prefix(&mut self, ip: IpAddr, bits: u8) {
        match ip {
            IpAddr::V4(ip) => {
                let mask = mask_v4(bits);
                let start = u32::from(ip) & mask;
                self.v4.push((start, start | !mask));
            }
            IpAddr::V6(ip) => {
                let mask = mask_v6(bits);
                let start = u128::from(ip) & mask;
                self.v6.push((start, start | !mask));
            }
        }
    }

    pub fn add_str(&mut self, text: &str) -> bool {
        match parse_prefix(text) {
            Some((ip, bits)) => {
                self.add_prefix(ip, bits);
                true
            }
            None => false,
        }
    }

    /// Sorts and coalesces overlapping and adjacent ranges.
    pub fn merge(&mut self) {
        merge_ranges(&mut self.v4, u32::MAX);
        merge_ranges(&mut self.v6, u128::MAX);
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => range_contains(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => range_contains(&self.v6, u128::from(ip)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn range_count(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

impl FromIterator<(IpAddr, u8)> for IpCidrSet {
    fn from_iter<T: IntoIterator<Item = (IpAddr, u8)>>(iter: T) -> Self {
        let mut set = IpCidrSet::new();
        set.extend(iter);
        set
    }
}

impl Extend<(IpAddr, u8)> for IpCidrSet {
    fn extend<T: IntoIterator<Item = (IpAddr, u8)>>(&mut self, iter: T) {
        for (ip, bits) in iter {
            self.add_prefix(ip, bits);
        }
        self.merge();
    }
}

impl IpCidrSet {
    /// The minimal prefix cover of every range, ascending, IPv4 first.
    pub fn prefixes(&self) -> Vec<(IpAddr, u8)> {
        let mut out = Vec::new();
        for &(from, to) in &self.v4 {
            let mut start = u64::from(from);
            let end = u64::from(to);
            while start <= end {
                let align = if start == 0 {
                    32
                } else {
                    start.trailing_zeros().min(32)
                };
                let span = 64 - (end - start + 1).leading_zeros() - 1;
                let size = align.min(span);
                out.push((IpAddr::V4(Ipv4Addr::from(start as u32)), (32 - size) as u8));
                start += 1u64 << size;
            }
        }
        for &(from, to) in &self.v6 {
            let mut start = from;
            loop {
                let align = if start == 0 {
                    128
                } else {
                    start.trailing_zeros().min(128)
                };
                let remaining = to - start;
                let span = if remaining == u128::MAX {
                    128
                } else {
                    127 - (remaining + 1).leading_zeros()
                };
                let size = align.min(span);
                out.push((IpAddr::V6(Ipv6Addr::from(start)), (128 - size) as u8));
                let step = if size == 128 {
                    u128::MAX
                } else {
                    (1u128 << size) - 1
                };
                match start.checked_add(step) {
                    Some(last) if last < to => start = last + 1,
                    _ => break,
                }
            }
        }
        out
    }
}

fn merge_ranges<T: Copy + Ord + Bounded>(ranges: &mut Vec<(T, T)>, max: T) {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for &(from, to) in ranges.iter() {
        match out.last_mut() {
            Some(last) if last.1 == max || last.1.next() >= from => {
                if to > last.1 {
                    last.1 = to;
                }
            }
            _ => out.push((from, to)),
        }
    }
    *ranges = out;
}

trait Bounded {
    fn next(self) -> Self;
}

impl Bounded for u32 {
    fn next(self) -> Self {
        self.saturating_add(1)
    }
}

impl Bounded for u128 {
    fn next(self) -> Self {
        self.saturating_add(1)
    }
}

fn range_contains<T: Copy + Ord>(ranges: &[(T, T)], value: T) -> bool {
    let at = ranges.partition_point(|r| r.0 <= value);
    at.checked_sub(1)
        .and_then(|i| ranges.get(i))
        .is_some_and(|r| value <= r.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn set(entries: &[&str]) -> IpCidrSet {
        let mut set = IpCidrSet::new();
        for entry in entries {
            assert!(set.add_str(entry), "{entry}");
        }
        set.merge();
        set
    }

    #[test]
    fn parse_prefix_is_as_strict_as_go() {
        assert!(parse_prefix("10.0.0.0/8").is_some());
        assert!(parse_prefix("2001:db8::/32").is_some());
        assert!(parse_prefix("10.0.0.0/08").is_none());
        assert!(parse_prefix("10.0.0.0/+8").is_none());
        assert!(parse_prefix("10.0.0.0/33").is_none());
        assert!(parse_prefix("10.0.0.0").is_none());
        assert!(parse_prefix("fe80::1%eth0/64").is_none());
    }

    #[test]
    fn contains_follows_merged_ranges() {
        let set = set(&[
            "10.0.0.0/8",
            "192.168.0.0/16",
            "2001:db8::/32",
            "10.1.0.0/16",
        ]);
        assert!(set.contains(ip("10.255.255.255")));
        assert!(set.contains(ip("192.168.3.4")));
        assert!(!set.contains(ip("11.0.0.0")));
        assert!(set.contains(ip("2001:db8:1::1")));
        assert!(!set.contains(ip("2001:db9::1")));
        assert_eq!(set.range_count(), 3);
    }

    #[test]
    fn adjacent_ranges_coalesce() {
        let set = set(&["10.0.0.0/25", "10.0.0.128/25"]);
        assert_eq!(set.prefixes(), vec![(ip("10.0.0.0"), 24)]);
    }

    #[test]
    fn prefixes_cover_an_unaligned_range() {
        let set = IpCidrSet::from_ranges(
            vec![(
                u32::from(Ipv4Addr::new(10, 0, 0, 1)),
                u32::from(Ipv4Addr::new(10, 0, 0, 6)),
            )],
            Vec::new(),
        );
        let prefixes = set.prefixes();
        assert_eq!(
            prefixes,
            vec![
                (ip("10.0.0.1"), 32),
                (ip("10.0.0.2"), 31),
                (ip("10.0.0.4"), 31),
                (ip("10.0.0.6"), 32)
            ]
        );
    }

    #[test]
    fn everything_is_one_prefix() {
        let set = set(&["0.0.0.0/0", "::/0"]);
        assert_eq!(set.prefixes(), vec![(ip("0.0.0.0"), 0), (ip("::"), 0)]);
        assert!(set.contains(ip("8.8.8.8")));
    }
}
