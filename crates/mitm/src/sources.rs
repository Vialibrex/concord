//! Surge's `client-source-address`: the clients whose connections are decrypted.

use std::net::IpAddr;

use concord_common::cidr::IpCidrSet;
use concord_config::mitm::SourceEntryDef;

use crate::view::SourceEntryView;

/// Every client while it names none, as Surge leaves MITM on for all clients without the key;
/// an entry with `-` leaves its clients out whatever else names them.
#[derive(Debug, Default)]
pub(crate) struct SourceList {
    include: IpCidrSet,
    exclude: IpCidrSet,
}

impl SourceList {
    pub(crate) fn add(&mut self, entries: &[SourceEntryDef]) -> Vec<SourceEntryView> {
        self.include.extend(
            entries
                .iter()
                .filter(|entry| !entry.exclude)
                .map(|entry| (entry.network.ip(), entry.network.prefix())),
        );
        self.exclude.extend(
            entries
                .iter()
                .filter(|entry| entry.exclude)
                .map(|entry| (entry.network.ip(), entry.network.prefix())),
        );
        entries
            .iter()
            .map(|entry| SourceEntryView {
                network: entry.network.to_string(),
                exclude: entry.exclude,
            })
            .collect()
    }

    /// The entries before a bad one stay added, and come back with its error.
    #[cfg(test)]
    pub(crate) fn add_line(
        &mut self,
        line: &str,
    ) -> (
        Vec<SourceEntryView>,
        Result<(), concord_config::mitm::LineError>,
    ) {
        let (entries, error) = concord_config::mitm::parse_source_line(line);
        (self.add(&entries), error.map_or(Ok(()), Err))
    }

    pub(crate) fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        !self.exclude.contains(ip) && (self.include.is_empty() || self.include.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(lines: &[&str]) -> SourceList {
        let mut list = SourceList::default();
        for line in lines {
            list.add_line(line).1.unwrap();
        }
        list
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn follows_surge_semantics() {
        assert!(list(&[]).allows(ip("10.0.0.1")));
        let surge = list(&["-192.168.1.2, 0.0.0.0/0"]);
        assert!(surge.allows(ip("192.168.1.3")));
        assert!(!surge.allows(ip("192.168.1.2")));
        assert!(!surge.allows(ip("::ffff:192.168.1.2")));
        assert!(!surge.allows(ip("2001:db8::1")), "only IPv4 is named");
        let skipped = list(&["-192.168.4.50", "-192.168.4.51"]);
        assert!(skipped.allows(ip("192.168.4.52")));
        assert!(!skipped.allows(ip("192.168.4.51")));
        let mut bad = SourceList::default();
        assert!(bad.add_line("192.168.1.0/24, lan").1.is_err());
    }

    #[test]
    fn source_list_agrees_with_linear_scan_and_preserves_views() {
        let probes: Vec<IpAddr> = [
            "0.0.0.0",
            "10.0.0.1",
            "192.168.1.1",
            "192.168.1.2",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:192.168.1.1",
            "::ffff:192.168.1.2",
            "2001:db8::1",
            "2001:db8::2",
        ]
        .into_iter()
        .map(ip)
        .collect();

        let cases: &[&[&str]] = &[
            &[],
            &["-192.168.1.2/32", "-2001:db8::1/128"],
            &["0.0.0.0/0", "-192.168.1.2/32"],
            &["::/0", "-2001:db8::1/128"],
            &["192.168.1.0/24, 192.168.1.1/32, -192.168.1.2, 2001:db8::/32"],
            &["-192.168.1.0/24", "192.168.1.1/32", "0.0.0.0/0", "::/0"],
        ];

        for lines in cases {
            let mut sources = SourceList::default();
            let mut raw_include = Vec::new();
            let mut raw_exclude = Vec::new();
            for line in *lines {
                let (entries, err) = concord_config::mitm::parse_source_line(line);
                assert!(err.is_none());
                let expected_views: Vec<SourceEntryView> = entries
                    .iter()
                    .map(|e| SourceEntryView {
                        network: e.network.to_string(),
                        exclude: e.exclude,
                    })
                    .collect();
                let views = sources.add(&entries);
                assert_eq!(views, expected_views);
                for entry in entries {
                    if entry.exclude {
                        raw_exclude.push(entry.network);
                    } else {
                        raw_include.push(entry.network);
                    }
                }
            }
            for &addr in &probes {
                let canonical = addr.to_canonical();
                let linear = !raw_exclude.iter().any(|net| net.contains(canonical))
                    && (raw_include.is_empty()
                        || raw_include.iter().any(|net| net.contains(canonical)));
                assert_eq!(sources.allows(addr), linear, "case={lines:?} ip={addr}");
            }
        }
    }
}
