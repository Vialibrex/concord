use std::net::IpAddr;

use concord_config::mitm::{
    HostEntryDef, IP_ADDRESS, IPV4_ADDRESS, IPV6_ADDRESS, Items, RejectedItem, SIMPLE_HOSTNAME,
    parse_host_line,
};

use crate::view::{HostEntryView, HostsView, LineView};

const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;

/// Surge's `[MITM] hostname`: entries match in order, so an exclusion has to
/// come before the wider entry it carves out of.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostList(Vec<HostEntryDef>);

impl HostList {
    pub fn parse(lines: &[String]) -> (HostList, Vec<String>) {
        let mut list = HostList::default();
        let mut errors = Vec::new();
        for line in lines {
            let (entries, rejected) = parse_host_line(line);
            list.0.extend(entries);
            errors.extend(
                rejected
                    .iter()
                    .map(|item| format!("hostname {}", item.error())),
            );
        }
        (list, errors)
    }

    /// A bare entry covers 443, and 80, which Surge's HTTP engine rewrites without an entry.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        self.find(host, port, false)
    }

    /// Widens a bare entry to any port, as Surge does for a connection whose server
    /// name was read from its first bytes.
    pub fn matches_sniffed(&self, host: &str, port: u16) -> bool {
        self.find(host, port, true)
    }

    /// Whether the first entry that covers `host` on `port` carves it out.
    pub fn excludes(&self, host: &str, port: u16) -> bool {
        self.first(host, port, false)
            .is_some_and(|entry| entry.exclude)
    }

    pub fn includes_any(&self) -> bool {
        self.0.iter().any(|entry| !entry.exclude)
    }

    fn find(&self, host: &str, port: u16, sniffed: bool) -> bool {
        self.first(host, port, sniffed)
            .is_some_and(|entry| !entry.exclude)
    }

    fn first(&self, host: &str, port: u16, sniffed: bool) -> Option<&HostEntryDef> {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        self.0
            .iter()
            .find(|entry| covers(entry, port, sniffed) && names(&entry.pattern, &host))
    }

    pub(crate) fn extend(&mut self, other: HostList) {
        self.0.extend(other.0);
    }

    /// Takes out the entries written exactly as one of `disabled`'s, not those it covers.
    pub(crate) fn remove(&mut self, disabled: &HostList) {
        self.0.retain(|entry| !disabled.0.contains(entry));
    }
}

fn covers(entry: &HostEntryDef, port: u16, sniffed: bool) -> bool {
    if entry.bare {
        return entry.exclude || sniffed || port == HTTPS_PORT || port == HTTP_PORT;
    }
    entry.port == 0 || entry.port == port
}

/// Each item of a hostname line in the order written, a bad one with why; `None` for a line
/// without items.
pub(crate) fn hosts_view(read: &Items<HostEntryDef>) -> Option<LineView> {
    let mut good = read.items.iter().map(|entry| HostEntryView {
        host: entry.pattern.clone(),
        port: (!entry.bare).then_some(entry.port),
        exclude: entry.exclude,
        reason: None,
    });
    let mut bad = read.rejected.iter().peekable();
    let mut entries = Vec::with_capacity(read.items.len() + read.rejected.len());
    for at in 0..read.items.len() + read.rejected.len() {
        let entry = match bad.next_if(|item| item.at == at) {
            Some(item) => rejected_view(item),
            None => match good.next() {
                Some(entry) => entry,
                None => break,
            },
        };
        entries.push(entry);
    }
    (!entries.is_empty()).then_some(LineView::Hosts(HostsView { entries }))
}

fn rejected_view(item: &RejectedItem) -> HostEntryView {
    let host = item.item.strip_prefix('-');
    HostEntryView {
        host: host.unwrap_or(&item.item).to_string(),
        port: None,
        exclude: host.is_some(),
        reason: Some(item.reason.message.clone()),
    }
}

impl From<Vec<HostEntryDef>> for HostList {
    fn from(entries: Vec<HostEntryDef>) -> HostList {
        HostList(entries)
    }
}

/// Whether an entry's pattern, a glob or one of Surge's tokens, stands for `host`.
fn names(pattern: &str, host: &str) -> bool {
    if !pattern.starts_with('<') {
        return glob(pattern, host);
    }
    let ip = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok();
    match pattern {
        IP_ADDRESS => ip.is_some(),
        IPV4_ADDRESS => ip.is_some_and(|ip| ip.is_ipv4()),
        IPV6_ADDRESS => ip.is_some_and(|ip| ip.is_ipv6()),
        SIMPLE_HOSTNAME => ip.is_none() && !host.contains('.'),
        _ => false,
    }
}

/// `*` and `?` over bytes; the name is already lower-case.
pub(crate) fn glob(pattern: &str, name: &str) -> bool {
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    let (mut p, mut n) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'?') => {
                p += 1;
                n += 1;
            }
            Some(b'*') => {
                star = Some(p);
                mark = n;
                p += 1;
            }
            Some(&c) if c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                Some(at) => {
                    p = at + 1;
                    mark += 1;
                    n = mark;
                }
                None => return false,
            },
        }
    }
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn follows_surge_semantics() {
        let (list, errors) = HostList::parse(&lines(&[
            "-skip.example.com",
            "*.example.com, api.other.test:8443",
            "all.ports.test:0",
            "[2001:db8::1]:443",
            "10.0.0.?",
        ]));
        assert!(errors.is_empty(), "{errors:?}");
        let cases = [
            ("a.example.com", 443, true),
            ("A.Example.COM.", 443, true),
            ("a.b.example.com", 443, true),
            ("example.com", 443, false),
            ("a.example.com", 80, true),
            ("a.example.com", 8443, false),
            ("skip.example.com", 443, false),
            ("skip.example.com", 80, false),
            ("api.other.test", 8443, true),
            ("api.other.test", 443, false),
            ("all.ports.test", 22, true),
            ("2001:db8::1", 443, true),
            ("10.0.0.7", 443, true),
            ("10.0.0.17", 443, false),
            ("", 443, false),
        ];
        for (host, port, want) in cases {
            assert_eq!(list.matches(host, port), want, "{host}:{port}");
        }
    }

    #[test]
    fn tokens_stand_for_kinds_of_host() {
        let (list, errors) = HostList::parse(&lines(&["-<ip-address>, *"]));
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!list.matches("203.0.113.9", 443));
        assert!(!list.matches("2001:db8::1", 443));
        assert!(list.matches("a.example.com", 443));
        let cases = [
            ("<IPv4-Address>", "203.0.113.9", true),
            ("<ipv4-address>", "2001:db8::1", false),
            ("<ipv6-address>", "[2001:db8::1]", true),
            ("<ipv6-address>", "203.0.113.9", false),
            ("<simple-hostname>", "printer", true),
            ("<simple-hostname>", "a.example.com", false),
            ("<simple-hostname>", "203.0.113.9", false),
        ];
        for (token, host, want) in cases {
            let (list, errors) = HostList::parse(&lines(&[token]));
            assert!(errors.is_empty(), "{errors:?}");
            assert_eq!(list.matches(host, 443), want, "{token} {host}");
        }
        let (_, errors) = HostList::parse(&lines(&["<any-host>"]));
        assert_eq!(errors.len(), 1, "{errors:?}");
    }

    #[test]
    fn order_decides() {
        let (list, _) = HostList::parse(&lines(&["*", "-a.test"]));
        assert!(list.matches("a.test", 443));
    }

    #[test]
    fn sniffed_widens_bare_entries() {
        let (list, _) = HostList::parse(&lines(&["a.test"]));
        assert!(!list.matches("a.test", 8080));
        assert!(list.matches_sniffed("a.test", 8080));
    }

    #[test]
    fn reports_bad_entries() {
        let (list, errors) = HostList::parse(&lines(&[
            "good.test",
            "bad host.test",
            "x.test:99999",
            "<ip-address>:443",
            "[::1",
        ]));
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(list.matches("good.test", 443));
        assert_eq!(
            errors.first().map(String::as_str),
            Some("hostname \"bad host.test\": unsupported character U+0020")
        );
    }

    #[test]
    fn glob_cases() {
        let cases = [
            ("*", "anything.at.all", true),
            ("*.a.test", "x.a.test", true),
            ("*.a.test", "a.test", false),
            ("a*c", "abbbc", true),
            ("a*c", "abbbd", false),
            ("?.a.test", "x.a.test", true),
            ("?.a.test", "xy.a.test", false),
            ("*x*y*", "1x2y3", true),
        ];
        for (pattern, name, want) in cases {
            assert_eq!(glob(pattern, name), want, "{pattern} {name}");
        }
    }
}
