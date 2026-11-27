use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use concord_config::mitm::{
    HostEntryDef, IP_ADDRESS, IPV4_ADDRESS, IPV6_ADDRESS, Items, RejectedItem, SIMPLE_HOSTNAME,
    parse_host_line,
};

use crate::view::{HostEntryView, HostsView, LineView};

const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;
/// RFC 1035 §2.3.4 caps a DNS domain name at 253 wire-text bytes; longer inputs heap-allocate.
const MAX_DNS_NAME_LEN: usize = 253;

/// Surge's `[MITM] hostname`: entries match in order, so an exclusion has to
/// come before the wider entry it carves out of.
#[derive(Debug, Default)]
pub struct HostList {
    entries: Vec<HostEntryDef>,
    index: OnceLock<Arc<HostIndex>>,
}

impl Clone for HostList {
    fn clone(&self) -> Self {
        let index = OnceLock::new();
        if let Some(compiled) = self.index.get() {
            let _ = index.set(Arc::clone(compiled));
        }
        HostList {
            entries: self.entries.clone(),
            index,
        }
    }
}

impl PartialEq for HostList {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for HostList {}

#[derive(Clone, Copy, Debug)]
struct RuleMeta {
    pos: u32,
    port: u16,
    bare: bool,
    exclude: bool,
}

impl RuleMeta {
    fn covers(self, port: u16, sniffed: bool) -> bool {
        if self.bare {
            return self.exclude || sniffed || port == HTTPS_PORT || port == HTTP_PORT;
        }
        self.port == 0 || self.port == port
    }

    fn covers_all(self) -> bool {
        (self.bare && self.exclude) || (!self.bare && self.port == 0)
    }

    fn shadows(self, next: RuleMeta) -> bool {
        if self.covers_all() {
            return true;
        }
        if self.bare {
            return (next.bare && !next.exclude)
                || (!next.bare && (next.port == HTTP_PORT || next.port == HTTPS_PORT));
        }
        !next.bare && next.port == self.port
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    IpAddress,
    Ipv4Address,
    Ipv6Address,
    SimpleHostname,
}

#[derive(Clone, Copy, Debug)]
struct TokenRule {
    meta: RuleMeta,
    kind: TokenKind,
}

#[derive(Debug)]
struct CompiledGlob {
    meta: RuleMeta,
    pattern: Box<str>,
}

#[derive(Debug, Default)]
struct GlobBucket {
    by_suffix: HashMap<Box<str>, Vec<CompiledGlob>>,
    unanchored: Vec<CompiledGlob>,
}

impl GlobBucket {
    fn push(&mut self, glob: CompiledGlob) {
        if let Some(suffix) = fixed_glob_suffix(&glob.pattern) {
            self.by_suffix
                .entry(Box::from(suffix))
                .or_default()
                .push(glob);
        } else {
            self.unanchored.push(glob);
        }
    }

    fn check_unanchored(
        &self,
        host: &str,
        port: u16,
        sniffed: bool,
        best: &mut Option<(u32, bool)>,
    ) {
        let limit = best_pos(*best);
        for rule in &self.unanchored {
            if rule.meta.pos >= limit {
                break;
            }
            if rule.meta.covers(port, sniffed) && glob(&rule.pattern, host) {
                update_best(best, rule.meta);
                break;
            }
        }
    }

    fn check_suffix(
        &self,
        suffix: &str,
        host: &str,
        port: u16,
        sniffed: bool,
        best: &mut Option<(u32, bool)>,
    ) {
        let Some(rules) = self.by_suffix.get(suffix) else {
            return;
        };
        let limit = best_pos(*best);
        for rule in rules {
            if rule.meta.pos >= limit {
                break;
            }
            if rule.meta.covers(port, sniffed) && glob(&rule.pattern, host) {
                update_best(best, rule.meta);
                break;
            }
        }
    }
}

#[derive(Debug, Default)]
struct HostIndex {
    includes_any: bool,
    any_port_include: bool,
    bare_include: bool,
    include_ports: Vec<u16>,
    any_port_exclude: bool,
    exclude_ports: Vec<u16>,
    any_host: Vec<RuleMeta>,
    exact: HashMap<Box<str>, Vec<RuleMeta>>,
    suffix: HashMap<Box<str>, Vec<RuleMeta>>,
    any_port_globs: GlobBucket,
    fixed_port_globs: HashMap<u16, GlobBucket>,
    tokens: Vec<TokenRule>,
}

impl HostIndex {
    fn build(entries: &[HostEntryDef]) -> HostIndex {
        let mut idx = HostIndex::default();
        for (i, entry) in entries.iter().enumerate() {
            let meta = RuleMeta {
                pos: u32::try_from(i).unwrap_or(u32::MAX),
                port: entry.port,
                bare: entry.bare,
                exclude: entry.exclude,
            };
            idx.record_coverage(meta);
            idx.insert_entry(&entry.pattern, meta);
        }
        idx.include_ports.sort_unstable();
        idx.include_ports.dedup();
        idx.exclude_ports.sort_unstable();
        idx.exclude_ports.dedup();
        idx
    }

    fn record_coverage(&mut self, meta: RuleMeta) {
        if !meta.exclude {
            self.includes_any = true;
            if meta.bare {
                self.bare_include = true;
            } else if meta.port == 0 {
                self.any_port_include = true;
            } else {
                self.include_ports.push(meta.port);
            }
        } else if meta.bare || meta.port == 0 {
            self.any_port_exclude = true;
        } else {
            self.exclude_ports.push(meta.port);
        }
    }

    fn insert_entry(&mut self, pattern: &str, meta: RuleMeta) {
        if pattern.starts_with('<') {
            if let Some(kind) = parse_token_kind(pattern) {
                let shadowed = self
                    .tokens
                    .iter()
                    .any(|prev| prev.kind == kind && prev.meta.shadows(meta));
                if !shadowed {
                    self.tokens.push(TokenRule { meta, kind });
                }
            }
            return;
        }
        if pattern.is_empty() {
            return;
        }
        if !pattern.contains(['*', '?']) {
            let slot = self.exact.entry(Box::from(pattern)).or_default();
            push_rule(slot, meta);
            return;
        }
        if pattern.bytes().all(|b| b == b'*') {
            push_rule(&mut self.any_host, meta);
            return;
        }
        if let Some(rest) = pattern.strip_prefix("*.")
            && !rest.contains(['*', '?'])
        {
            let slot = self.suffix.entry(Box::from(rest)).or_default();
            push_rule(slot, meta);
            return;
        }
        let compiled = CompiledGlob {
            meta,
            pattern: Box::from(pattern),
        };
        if !meta.bare && meta.port != 0 {
            self.fixed_port_globs
                .entry(meta.port)
                .or_default()
                .push(compiled);
        } else {
            self.any_port_globs.push(compiled);
        }
    }

    fn can_include_port(&self, port: u16, sniffed: bool) -> bool {
        self.includes_any
            && (self.any_port_include
                || (self.bare_include && (sniffed || port == HTTPS_PORT || port == HTTP_PORT))
                || self.include_ports.binary_search(&port).is_ok())
    }

    fn can_exclude_port(&self, port: u16) -> bool {
        self.any_port_exclude || self.exclude_ports.binary_search(&port).is_ok()
    }

    fn first_exclude(&self, host: &str, port: u16, sniffed: bool) -> Option<bool> {
        let stripped = host.strip_suffix('.').unwrap_or(host);
        if stripped.is_empty() {
            return None;
        }
        if !stripped.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.first_exclude_lower(stripped, port, sniffed);
        }
        if stripped.len() <= MAX_DNS_NAME_LEN {
            let mut buf = [0u8; MAX_DNS_NAME_LEN];
            for (dst, &src) in buf.iter_mut().zip(stripped.as_bytes()) {
                *dst = src.to_ascii_lowercase();
            }
            if let Ok(lower) = std::str::from_utf8(&buf[..stripped.len()]) {
                return self.first_exclude_lower(lower, port, sniffed);
            }
        }
        let lower = stripped.to_ascii_lowercase();
        self.first_exclude_lower(&lower, port, sniffed)
    }

    fn first_exclude_lower(&self, host: &str, port: u16, sniffed: bool) -> Option<bool> {
        let mut best: Option<(u32, bool)> = None;
        check_rules(&self.any_host, port, sniffed, &mut best);
        if let Some(rules) = self.exact.get(host) {
            check_rules(rules, port, sniffed, &mut best);
        }
        let port_bucket = self.fixed_port_globs.get(&port);
        let check_dots = !self.suffix.is_empty()
            || !self.any_port_globs.by_suffix.is_empty()
            || port_bucket.is_some_and(|bucket| !bucket.by_suffix.is_empty());
        if check_dots {
            for (dot, &byte) in host.as_bytes().iter().enumerate() {
                if byte != b'.' {
                    continue;
                }
                let tail = &host[dot + 1..];
                if let Some(rules) = self.suffix.get(tail) {
                    check_rules(rules, port, sniffed, &mut best);
                }
                if !self.any_port_globs.by_suffix.is_empty() {
                    self.any_port_globs
                        .check_suffix(tail, host, port, sniffed, &mut best);
                }
                if let Some(bucket) = port_bucket
                    && !bucket.by_suffix.is_empty()
                {
                    bucket.check_suffix(tail, host, port, sniffed, &mut best);
                }
            }
        }
        if !self.any_port_globs.unanchored.is_empty() {
            self.any_port_globs
                .check_unanchored(host, port, sniffed, &mut best);
        }
        if let Some(bucket) = port_bucket
            && !bucket.unanchored.is_empty()
        {
            bucket.check_unanchored(host, port, sniffed, &mut best);
        }
        self.check_tokens(host, port, sniffed, &mut best);
        best.map(|(_, exclude)| exclude)
    }

    fn check_tokens(&self, host: &str, port: u16, sniffed: bool, best: &mut Option<(u32, bool)>) {
        let limit = best_pos(*best);
        let Some(first) = self.tokens.first() else {
            return;
        };
        if first.meta.pos >= limit {
            return;
        }
        let ip = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok();
        let simple = ip.is_none() && !host.contains('.');
        for rule in &self.tokens {
            if rule.meta.pos >= limit {
                break;
            }
            if !rule.meta.covers(port, sniffed) {
                continue;
            }
            let matched = match rule.kind {
                TokenKind::IpAddress => ip.is_some(),
                TokenKind::Ipv4Address => ip.is_some_and(|ip| ip.is_ipv4()),
                TokenKind::Ipv6Address => ip.is_some_and(|ip| ip.is_ipv6()),
                TokenKind::SimpleHostname => simple,
            };
            if matched {
                update_best(best, rule.meta);
                break;
            }
        }
    }
}

fn best_pos(best: Option<(u32, bool)>) -> u32 {
    best.map_or(u32::MAX, |(pos, _)| pos)
}

fn update_best(best: &mut Option<(u32, bool)>, meta: RuleMeta) {
    if best.is_none_or(|(pos, _)| meta.pos < pos) {
        *best = Some((meta.pos, meta.exclude));
    }
}

fn push_rule(list: &mut Vec<RuleMeta>, next: RuleMeta) {
    if list.iter().any(|prev| prev.shadows(next)) {
        return;
    }
    list.push(next);
}

fn check_rules(rules: &[RuleMeta], port: u16, sniffed: bool, best: &mut Option<(u32, bool)>) {
    let limit = best_pos(*best);
    for &rule in rules {
        if rule.pos >= limit {
            break;
        }
        if rule.covers(port, sniffed) {
            update_best(best, rule);
            break;
        }
    }
}

fn parse_token_kind(pattern: &str) -> Option<TokenKind> {
    match pattern {
        IP_ADDRESS => Some(TokenKind::IpAddress),
        IPV4_ADDRESS => Some(TokenKind::Ipv4Address),
        IPV6_ADDRESS => Some(TokenKind::Ipv6Address),
        SIMPLE_HOSTNAME => Some(TokenKind::SimpleHostname),
        _ => None,
    }
}

fn fixed_glob_suffix(pattern: &str) -> Option<&str> {
    let last_wild = pattern.rfind(['*', '?'])?;
    let tail = &pattern[last_wild + 1..];
    let dot = tail.find('.')?;
    Some(&tail[dot + 1..])
}

impl HostList {
    pub fn parse(lines: &[String]) -> (HostList, Vec<String>) {
        let mut list = HostList::default();
        let mut errors = Vec::new();
        for line in lines {
            let (entries, rejected) = parse_host_line(line);
            list.entries.extend(entries);
            errors.extend(
                rejected
                    .iter()
                    .map(|item| format!("hostname {}", item.error())),
            );
        }
        list.index();
        (list, errors)
    }

    /// Precomputes the lookup index so queries never build it on the hot path.
    pub(crate) fn index(&self) {
        let _ = self.compiled();
    }

    fn compiled(&self) -> &HostIndex {
        self.index
            .get_or_init(|| Arc::new(HostIndex::build(&self.entries)))
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
        let idx = self.compiled();
        if !idx.can_exclude_port(port) {
            return false;
        }
        idx.first_exclude(host, port, false) == Some(true)
    }

    pub fn includes_any(&self) -> bool {
        self.compiled().includes_any
    }

    fn find(&self, host: &str, port: u16, sniffed: bool) -> bool {
        let idx = self.compiled();
        if !idx.can_include_port(port, sniffed) {
            return false;
        }
        idx.first_exclude(host, port, sniffed) == Some(false)
    }

    #[cfg(test)]
    pub(crate) fn extend(&mut self, other: HostList) {
        if !other.entries.is_empty() {
            self.entries.extend(other.entries);
            self.index = OnceLock::new();
        }
    }

    pub(crate) fn extend_entries(&mut self, entries: &[HostEntryDef]) {
        if !entries.is_empty() {
            self.entries.extend_from_slice(entries);
            self.index = OnceLock::new();
        }
    }

    /// Takes out the entries written exactly as one of `disabled`'s, not those it covers.
    #[cfg(test)]
    pub(crate) fn remove(&mut self, disabled: &HostList) {
        self.remove_entries(&disabled.entries);
    }

    pub(crate) fn remove_entries(&mut self, disabled: &[HostEntryDef]) {
        if disabled.is_empty() {
            return;
        }
        let drop: HashSet<(&str, bool, bool, u16)> = disabled
            .iter()
            .map(|e| (e.pattern.as_str(), e.exclude, e.bare, e.port))
            .collect();
        self.entries
            .retain(|e| !drop.contains(&(e.pattern.as_str(), e.exclude, e.bare, e.port)));
        self.index = OnceLock::new();
    }
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
        HostList {
            entries,
            index: OnceLock::new(),
        }
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

    fn linear_covers(entry: &HostEntryDef, port: u16, sniffed: bool) -> bool {
        if entry.bare {
            return entry.exclude || sniffed || port == HTTPS_PORT || port == HTTP_PORT;
        }
        entry.port == 0 || entry.port == port
    }

    fn linear_names(pattern: &str, host: &str) -> bool {
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

    fn linear_first<'a>(
        entries: &'a [HostEntryDef],
        host: &str,
        port: u16,
        sniffed: bool,
    ) -> Option<&'a HostEntryDef> {
        let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        entries.iter().find(|entry| {
            linear_covers(entry, port, sniffed) && linear_names(&entry.pattern, &host)
        })
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[(self.next() as usize) % items.len()]
        }
    }

    #[test]
    fn same_name_multi_port_and_wildcard_precedence() {
        let (list, errors) = HostList::parse(&lines(&["-api.a.test:8443,api.a.test:0,-*.a.test"]));
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!list.matches("API.A.TEST.", 8443));
        assert!(list.excludes("API.A.TEST.", 8443));
        assert!(list.matches("API.A.TEST.", 443));
        assert!(!list.excludes("API.A.TEST.", 443));

        let (swapped, errors) =
            HostList::parse(&lines(&["api.a.test:0,-api.a.test:8443,-*.a.test"]));
        assert!(errors.is_empty(), "{errors:?}");
        assert!(swapped.matches("API.A.TEST.", 8443));
        assert!(!swapped.excludes("API.A.TEST.", 8443));

        let (wide_first, _) = HostList::parse(&lines(&["*.a.test,-x.a.test"]));
        assert!(wide_first.matches("x.a.test", 443));
        assert!(!wide_first.excludes("x.a.test", 443));
        let (excl_first, _) = HostList::parse(&lines(&["-x.a.test,*.a.test"]));
        assert!(!excl_first.matches("x.a.test", 443));
        assert!(excl_first.excludes("x.a.test", 443));
        assert!(excl_first.matches("a.b.a.test", 443));
        assert!(!excl_first.matches("a.test", 443));

        let (bare, _) = HostList::parse(&lines(&["-neg.a.test,pos.a.test"]));
        assert!(!bare.matches("pos.a.test", 8443));
        assert!(bare.matches_sniffed("pos.a.test", 8443));
        assert!(bare.excludes("neg.a.test", 8443));
        assert!(!bare.matches_sniffed("neg.a.test", 8443));

        let (_, errs) = HostList::parse(&lines(&["<all>"]));
        assert_eq!(errs.len(), 1, "<all> must still parse as unknown token");
    }

    #[test]
    fn indexed_matches_linear_on_port_shadowing_and_remove() {
        let (mut list, errors) = HostList::parse(&lines(&[
            "-api.a.test:443",
            "api.a.test",
            "-api.a.test:8443",
            "*.sub.a.test",
            "-skip.sub.a.test",
            "m1*.a.test:8443",
            "m1*.a.test",
            "exact.a.test:0",
            "-exact.a.test",
            "**.deep.a.test",
        ]));
        assert!(errors.is_empty(), "{errors:?}");
        let check = |list: &HostList| {
            let hosts = [
                "api.a.test",
                "API.A.TEST.",
                "skip.sub.a.test",
                "x.sub.a.test",
                ".sub.a.test",
                "sub.a.test",
                "m10.a.test",
                "exact.a.test",
                "x.y.deep.a.test",
            ];
            for host in hosts {
                for port in [0, 53, 80, 443, 8080, 8443] {
                    let want_m =
                        linear_first(&list.entries, host, port, false).is_some_and(|e| !e.exclude);
                    let want_s =
                        linear_first(&list.entries, host, port, true).is_some_and(|e| !e.exclude);
                    let want_e =
                        linear_first(&list.entries, host, port, false).is_some_and(|e| e.exclude);
                    assert_eq!(list.matches(host, port), want_m, "matches {host}:{port}");
                    assert_eq!(
                        list.matches_sniffed(host, port),
                        want_s,
                        "sniffed {host}:{port}"
                    );
                    assert_eq!(list.excludes(host, port), want_e, "excludes {host}:{port}");
                }
            }
            assert_eq!(list.includes_any(), list.entries.iter().any(|e| !e.exclude));
        };
        check(&list);

        // Removing an exact entry invalidates and updates the index accurately.
        let (disabled, _) = HostList::parse(&lines(&["-api.a.test:443", "exact.a.test:0"]));
        list.remove(&disabled);
        check(&list);

        // Extending appends after existing entries and updates the index.
        let (more, _) = HostList::parse(&lines(&["-m1*.a.test:8443", "new.a.test:53"]));
        list.extend(more);
        check(&list);
    }

    #[test]
    fn differential_random_tables_match_linear_oracle() {
        let patterns = [
            "api.a.test",
            "feed.a.test",
            "skip.a.test",
            "a.b.example.com",
            "*.a.test",
            "*.sub.a.test",
            "*.example.com",
            "*.com",
            "*",
            "**",
            "m1*.a.test",
            "a*b.example.com",
            "?.a.test",
            "10.0.0.?",
            "*cdn*",
            "api.*.test",
            "**.a.test",
            "203.0.113.9",
            "2001:db8::1",
            "printer",
            IP_ADDRESS,
            IPV4_ADDRESS,
            IPV6_ADDRESS,
            SIMPLE_HOSTNAME,
            "<unknown-token>",
            "",
        ];
        let ports: [(bool, u16); 7] = [
            (true, 0),
            (false, 0),
            (false, 53),
            (false, 80),
            (false, 443),
            (false, 8080),
            (false, 8443),
        ];
        let long_host = format!("{}.a.test", "A".repeat(260));
        let query_hosts = [
            "",
            ".",
            "api.a.test",
            "API.A.TEST.",
            "api.a.test..",
            "feed.a.test",
            "skip.a.test",
            "x.a.test",
            ".a.test",
            "a..a.test",
            "x.sub.a.test",
            "sub.a.test",
            "m123.a.test",
            "m2.a.test",
            "axxxb.example.com",
            "a.b.example.com",
            "example.com",
            "mycdn.example.org",
            "api.foo.test",
            "10.0.0.7",
            "10.0.0.17",
            "203.0.113.9",
            "2001:db8::1",
            "[2001:db8::1]",
            "PRINTER",
            "printer.",
            "localhost",
            long_host.as_str(),
        ];
        let query_ports = [0u16, 53, 80, 443, 8080, 8443];

        let mut rng = Rng(0x5EED_C0DE_1234_5678);
        for trial in 0..80 {
            let count = (rng.next() as usize) % 90;
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let pattern = (*rng.pick(&patterns)).to_string();
                let exclude = (rng.next() & 1) == 1;
                let (bare, port) = *rng.pick(&ports);
                entries.push(HostEntryDef {
                    pattern,
                    exclude,
                    bare,
                    port,
                });
            }
            let list = HostList::from(entries.clone());
            list.index();
            assert_eq!(
                list.includes_any(),
                entries.iter().any(|e| !e.exclude),
                "trial {trial} includes_any"
            );
            for &host in &query_hosts {
                for &port in &query_ports {
                    let want_m =
                        linear_first(&entries, host, port, false).is_some_and(|e| !e.exclude);
                    let want_s =
                        linear_first(&entries, host, port, true).is_some_and(|e| !e.exclude);
                    let want_e =
                        linear_first(&entries, host, port, false).is_some_and(|e| e.exclude);
                    assert_eq!(
                        list.matches(host, port),
                        want_m,
                        "trial {trial} matches({host:?}, {port})"
                    );
                    assert_eq!(
                        list.matches_sniffed(host, port),
                        want_s,
                        "trial {trial} matches_sniffed({host:?}, {port})"
                    );
                    assert_eq!(
                        list.excludes(host, port),
                        want_e,
                        "trial {trial} excludes({host:?}, {port})"
                    );
                }
            }
        }
    }
}
