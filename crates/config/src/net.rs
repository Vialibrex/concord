use std::fmt;
use std::net::IpAddr;

use crate::error::{ConfigError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpCidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpCidr {
    pub fn parse(text: &str) -> Option<IpCidr> {
        concord_common::cidr::parse_prefix(text).map(|(addr, prefix)| IpCidr { addr, prefix })
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn covers_everything(&self) -> bool {
        self.prefix == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                mask_v4(u32::from(net), self.prefix) == mask_v4(u32::from(ip), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                mask_v6(u128::from(net), self.prefix) == mask_v6(u128::from(ip), self.prefix)
            }
            _ => false,
        }
    }
}

fn mask_v4(bits: u32, prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        p => bits & (u32::MAX << (32 - u32::from(p.min(32)))),
    }
}

fn mask_v6(bits: u128, prefix: u8) -> u128 {
    match prefix {
        0 => 0,
        p => bits & (u128::MAX << (128 - u32::from(p.min(128)))),
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

pub fn parse_cidr(text: &str) -> Result<IpCidr> {
    IpCidr::parse(text.trim())
        .ok_or_else(|| ConfigError::new(format!("netip.ParsePrefix(\"{text}\"): invalid prefix")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

pub fn parse_unsigned_ranges(text: &str, max: u64) -> Result<Vec<(u64, u64)>> {
    let text = text.trim();
    if text.is_empty() || text == "*" {
        return Ok(Vec::new());
    }
    let normalized = text.replace(',', "/");
    let parts: Vec<&str> = normalized.split('/').collect();
    if parts.len() > 28 {
        return Err(ConfigError::new(
            "intRanges error, too many ranges to use, maximum support 28 ranges",
        ));
    }
    let mut ranges = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (start, end) = match part.split_once('-') {
            Some((a, b)) => (parse_bounded(a, max)?, parse_bounded(b, max)?),
            None => {
                let n = parse_bounded(part, max)?;
                (n, n)
            }
        };
        ranges.push((start.min(end), start.max(end)));
    }
    Ok(ranges)
}

fn parse_bounded(text: &str, max: u64) -> Result<u64> {
    let text = text.trim_matches(['[', ']', ' ']);
    let value: u64 = (!text.starts_with('+'))
        .then(|| text.parse().ok())
        .flatten()
        .ok_or_else(|| ConfigError::new(format!("intRanges error, can't parse {text:?}")))?;
    if value > max {
        return Err(ConfigError::new(format!(
            "intRanges error, {value} is out of range"
        )));
    }
    Ok(value)
}

pub fn parse_port_ranges(text: &str) -> Result<Vec<PortRange>> {
    Ok(parse_unsigned_ranges(text, u64::from(u16::MAX))?
        .into_iter()
        .filter_map(|(start, end)| {
            Some(PortRange {
                start: u16::try_from(start).ok()?,
                end: u16::try_from(end).ok()?,
            })
        })
        .collect())
}

pub fn is_ip(text: &str) -> bool {
    text.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_follow_go_int_ranges() {
        assert_eq!(parse_unsigned_ranges("443-80", 65535).unwrap(), [(80, 443)]);
        assert_eq!(parse_unsigned_ranges("[80]", 65535).unwrap(), [(80, 80)]);
        assert_eq!(
            parse_unsigned_ranges("[ 80 ]-[443]", 65535).unwrap(),
            [(80, 443)]
        );
        assert!(parse_unsigned_ranges("+5", 65535).is_err());
        assert!(parse_unsigned_ranges("1-+5", 65535).is_err());
        assert!(parse_unsigned_ranges("1-2-3", 65535).is_err());
        assert!(parse_unsigned_ranges("70000", 65535).is_err());
    }

    #[test]
    fn cidr_is_as_strict_as_go_parse_prefix() {
        assert!(IpCidr::parse("10.0.0.0/8").is_some());
        assert!(IpCidr::parse("10.0.0.0/0").is_some());
        assert!(IpCidr::parse("10.0.0.0/08").is_none());
        assert!(IpCidr::parse("10.0.0.0/+8").is_none());
        assert!(IpCidr::parse("10.0.0.0/").is_none());
        assert!(IpCidr::parse("10.0.0.0/33").is_none());
    }
}
