use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use crate::route::Os;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (len <= max).then_some(Prefix { addr, len })
    }

    pub fn host(addr: IpAddr) -> Self {
        Prefix {
            addr,
            len: if addr.is_ipv4() { 32 } else { 128 },
        }
    }

    /// Reads `a.b.c.d/len`, `v6/len`, and a bare address as a host prefix.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        match text.split_once('/') {
            Some((addr, len)) => Prefix::new(addr.parse().ok()?, len.parse().ok()?),
            None => Some(Prefix::host(text.parse().ok()?)),
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    #[allow(
        clippy::len_without_is_empty,
        reason = "a prefix length is not a collection size"
    )]
    pub fn len(&self) -> u8 {
        self.len
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn max_len(&self) -> u8 {
        if self.addr.is_ipv4() { 32 } else { 128 }
    }

    pub fn masked(&self) -> Prefix {
        let (start, _) = self.range();
        Prefix {
            addr: from_bits(self.addr.is_ipv4(), start),
            len: self.len,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        let (start, end) = self.range();
        let bits = to_bits(ip);
        bits >= start && bits <= end
    }

    pub(crate) fn range(&self) -> (u128, u128) {
        let width = u32::from(self.max_len());
        let host_bits = width - u32::from(self.len);
        let mask = if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        let start = to_bits(self.addr) & !mask;
        (start, start | mask)
    }

    /// The address after the interface address, where the DNS hijack listens
    /// and the gateway of the route table points.
    pub fn next_host(&self) -> Option<IpAddr> {
        let bits = to_bits(self.addr).checked_add(1)?;
        let (_, end) = self.range();
        (bits <= end).then(|| from_bits(self.addr.is_ipv4(), bits))
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

pub(crate) fn to_bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

pub(crate) fn from_bits(v4: bool, bits: u128) -> IpAddr {
    if v4 {
        IpAddr::V4(Ipv4Addr::from(bits as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(bits))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdRange {
    pub start: u32,
    pub end: u32,
}

impl IdRange {
    pub fn single(id: u32) -> Self {
        IdRange { start: id, end: id }
    }

    /// Reads the `start:end` spelling of `*-uid-range` and `*-port-range`.
    pub fn parse(text: &str) -> Option<Self> {
        let (start, end) = text.split_once(':')?;
        let range = IdRange {
            start: start.trim().parse().ok()?,
            end: end.trim().parse().ok()?,
        };
        (range.start <= range.end).then_some(range)
    }
}

#[derive(Clone, Debug)]
pub struct TunOptions {
    pub device: Option<String>,
    pub mtu: u32,
    pub inet4_address: Vec<Prefix>,
    pub inet6_address: Vec<Prefix>,
    pub auto_route: bool,
    pub strict_route: bool,
    pub route_address: Vec<Prefix>,
    pub route_exclude_address: Vec<Prefix>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<IdRange>,
    pub exclude_uid: Vec<IdRange>,
    pub exclude_src_port: Vec<IdRange>,
    pub exclude_dst_port: Vec<IdRange>,
    pub dns_hijack: Vec<String>,
    pub udp_timeout: Duration,
    pub disable_icmp_forwarding: bool,
    pub inbound_name: String,
    pub iproute2_table_index: u32,
    pub iproute2_rule_index: u32,
    pub max_tcp_flows: usize,
    /// Absolute path of `wintun.dll`; the default is the copy compiled into the core.
    pub wintun_path: Option<PathBuf>,
}

pub(crate) const UDP_TIMEOUT: Duration = Duration::from_secs(300);

impl Default for TunOptions {
    fn default() -> Self {
        TunOptions {
            device: None,
            mtu: 9000,
            inet4_address: Vec::new(),
            inet6_address: Vec::new(),
            auto_route: false,
            strict_route: false,
            route_address: Vec::new(),
            route_exclude_address: Vec::new(),
            include_interface: Vec::new(),
            exclude_interface: Vec::new(),
            include_uid: Vec::new(),
            exclude_uid: Vec::new(),
            exclude_src_port: Vec::new(),
            exclude_dst_port: Vec::new(),
            dns_hijack: Vec::new(),
            udp_timeout: UDP_TIMEOUT,
            disable_icmp_forwarding: false,
            inbound_name: "DEFAULT-TUN".to_owned(),
            iproute2_table_index: 2022,
            iproute2_rule_index: 9000,
            max_tcp_flows: concord_netstack::StackConfig::default().max_connections,
            wintun_path: None,
        }
    }
}

impl TunOptions {
    pub(crate) fn effective_mtu(&self) -> usize {
        (self.mtu as usize).clamp(576, 65_535)
    }

    /// A macOS utun is named by its kernel unit, so any other name is left for the kernel to pick,
    /// as mihomo picks one itself.
    pub(crate) fn device_name(&self, os: Os) -> Option<&str> {
        let name = self.device.as_deref().filter(|name| !name.is_empty())?;
        let named_by_unit = name.strip_prefix("utun").is_some_and(|unit| {
            !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit())
        });
        (os != Os::MacOs || named_by_unit).then_some(name)
    }

    pub(crate) fn inet4_broadcast(&self) -> Option<IpAddr> {
        let prefix = self
            .inet4_address
            .first()
            .filter(|prefix| prefix.len() < 31)?;
        Some(from_bits(true, prefix.range().1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_mask() {
        let p = Prefix::parse("198.18.0.1/30").unwrap();
        assert_eq!(p.masked().to_string(), "198.18.0.0/30");
        assert_eq!(p.next_host(), Some("198.18.0.2".parse().unwrap()));
        assert!(p.contains("198.18.0.3".parse().unwrap()));
        assert!(!p.contains("198.18.0.4".parse().unwrap()));
        assert!(!p.contains("::1".parse().unwrap()));
        assert_eq!(Prefix::parse("10.0.0.1").unwrap().len(), 32);
        assert!(Prefix::parse("10.0.0.1/33").is_none());
        assert!(Prefix::parse("nope").is_none());
    }

    #[test]
    fn macos_leaves_a_name_that_is_not_a_utun_unit_to_the_kernel() {
        let named = |device: &str| TunOptions {
            device: Some(device.to_owned()),
            ..TunOptions::default()
        };
        for name in ["FlClash", "utun", "utunX", "Meta", "utun-1"] {
            assert_eq!(named(name).device_name(Os::MacOs), None, "{name}");
            assert_eq!(named(name).device_name(Os::Linux), Some(name), "{name}");
        }
        assert_eq!(named("utun7").device_name(Os::MacOs), Some("utun7"));
        assert_eq!(named("").device_name(Os::Windows), None);
        assert_eq!(TunOptions::default().device_name(Os::MacOs), None);
    }

    #[test]
    fn host_prefix_has_no_next_host_past_the_end() {
        let p = Prefix::parse("fdfe:dcba:9876::1/126").unwrap();
        assert_eq!(p.next_host(), Some("fdfe:dcba:9876::2".parse().unwrap()));
        let last = Prefix::parse("255.255.255.255/32").unwrap();
        assert_eq!(last.next_host(), None);
    }

    #[test]
    fn broadcast_is_the_last_address_of_a_wide_enough_ipv4_prefix() {
        let with = |text: &str| TunOptions {
            inet4_address: Prefix::parse(text).into_iter().collect(),
            ..TunOptions::default()
        };
        assert_eq!(
            with("198.18.0.1/30").inet4_broadcast(),
            Some("198.18.0.3".parse().unwrap())
        );
        assert_eq!(with("198.18.0.1/31").inet4_broadcast(), None);
        assert_eq!(with("198.18.0.1/32").inet4_broadcast(), None);
        assert_eq!(TunOptions::default().inet4_broadcast(), None);
    }

    #[test]
    fn id_range_parses_colon_spelling() {
        assert_eq!(
            IdRange::parse("1000:2000"),
            Some(IdRange {
                start: 1000,
                end: 2000
            })
        );
        assert_eq!(IdRange::parse("2000:1000"), None);
        assert_eq!(IdRange::parse("1000"), None);
    }
}
