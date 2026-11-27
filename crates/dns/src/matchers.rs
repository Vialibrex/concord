use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;

use concord_config::net::IpCidr;
use concord_config::rule::{Cond, RuleDef};
use concord_rules::cidr_set::IpCidrSet;

use crate::trie::DomainSet;
use crate::{DnsError, DomainMatch, GeoIpLookup, IpMatch, RuleEnv};

pub struct CidrSet {
    set: IpCidrSet,
}

impl CidrSet {
    pub fn new(items: Vec<IpCidr>) -> Self {
        let mut set = IpCidrSet::new();
        for cidr in items {
            set.add_prefix(cidr.addr, cidr.prefix);
        }
        set.merge();
        CidrSet { set }
    }

    #[cfg(test)]
    fn range_count(&self) -> usize {
        self.set.range_count()
    }
}

impl IpMatch for CidrSet {
    fn matches(&self, ip: IpAddr) -> bool {
        self.set.contains(ip)
    }
}

fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            let first = v6.segments().first().copied().unwrap_or(0);
            (first & 0xfe00) == 0xfc00
                || v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || (first & 0xffc0) == 0xfe80
        }
    }
}

/// `fallback-filter.geoip`: true for an address outside `code`, which is the
/// answer that should not be trusted from the main servers.
pub struct GeoFallback {
    lookup: Arc<dyn GeoIpLookup>,
    code: String,
}

impl GeoFallback {
    pub fn new(lookup: Arc<dyn GeoIpLookup>, code: &str) -> Self {
        GeoFallback {
            lookup,
            code: code.to_ascii_lowercase(),
        }
    }
}

impl IpMatch for GeoFallback {
    fn matches(&self, ip: IpAddr) -> bool {
        if is_lan(ip) {
            return false;
        }
        if self.code == "lan" {
            return true;
        }
        !self
            .lookup
            .country_codes(ip)
            .iter()
            .any(|code| code.eq_ignore_ascii_case(&self.code))
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some(p);
                mark = t;
                p += 1;
            }
            Some(&c) if c == b'?' || Some(&c) == text.get(t) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some(s) => {
                    p = s + 1;
                    mark += 1;
                    t = mark;
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .is_some_and(|rest| rest.iter().all(|c| *c == b'*'))
}

enum DomainCond {
    Exact(String),
    Suffix(String),
    Keyword(String),
    Regex(regex::Regex),
    Wildcard(String),
    Set(Arc<dyn DomainMatch>),
    Any,
}

impl DomainCond {
    fn matches(&self, host: &str) -> bool {
        match self {
            DomainCond::Exact(domain) => host == domain,
            DomainCond::Suffix(suffix) => {
                host == suffix
                    || host
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|head| head.ends_with('.'))
            }
            DomainCond::Keyword(word) => host.contains(word.as_str()),
            DomainCond::Regex(re) => re.is_match(host),
            DomainCond::Wildcard(pattern) => wildcard_match(pattern, host),
            DomainCond::Set(set) => set.matches(host),
            DomainCond::Any => true,
        }
    }
}

/// One line of `fake-ip-filter` in `rule` mode.
pub struct FilterRule {
    cond: DomainCond,
    real_ip: bool,
}

impl FilterRule {
    pub fn compile(def: &RuleDef, env: &dyn RuleEnv) -> Result<Self, DnsError> {
        let cond = match &def.cond {
            Cond::Domain(domain) => DomainCond::Exact(domain.to_lowercase()),
            Cond::DomainSuffix(suffix) => DomainCond::Suffix(suffix.to_lowercase()),
            Cond::DomainKeyword(word) => DomainCond::Keyword(word.to_lowercase()),
            Cond::DomainRegex(pattern) => DomainCond::Regex(
                regex::Regex::new(pattern)
                    .map_err(|err| DnsError::config(format!("{}: {err}", def.text)))?,
            ),
            Cond::DomainWildcard(pattern) => DomainCond::Wildcard(pattern.to_lowercase()),
            Cond::GeoSite(name) => DomainCond::Set(
                env.geosite(name)
                    .map_err(|err| DnsError::rule(format!("{}: {err}", def.text), err))?,
            ),
            Cond::RuleSet(name) => DomainCond::Set(
                env.domain_rule_set(name)
                    .map_err(|err| DnsError::rule(format!("{}: {err}", def.text), err))?,
            ),
            Cond::Match => DomainCond::Any,
            other => {
                return Err(DnsError::config(format!(
                    "fake-ip-filter: rule type '{}' not supported",
                    other.type_name()
                )));
            }
        };
        Ok(FilterRule {
            cond,
            real_ip: def.target.eq_ignore_ascii_case("real-ip"),
        })
    }
}

fn split_names(rest: &str) -> impl Iterator<Item = &str> {
    rest.split(',')
}

/// Splits `geosite:a,b`, `rule-set:a,b` and domain patterns the way
/// `parseDomain` does.
pub fn domain_matchers(
    entries: &[String],
    what: &str,
    env: &dyn RuleEnv,
) -> Result<Vec<Arc<dyn DomainMatch>>, DnsError> {
    let mut out: Vec<Arc<dyn DomainMatch>> = Vec::new();
    let mut set = DomainSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let lower = entry.to_lowercase();
        let named = |prefix: &str| {
            lower
                .starts_with(prefix)
                .then(|| entry.get(prefix.len()..).unwrap_or_default())
        };
        if let Some(rest) = named("geosite:") {
            for name in split_names(rest) {
                out.push(env.geosite(name).map_err(|err| {
                    DnsError::rule(format!("{what}[{index}] {entry:?}: {err}"), err)
                })?);
            }
        } else if let Some(rest) = named("rule-set:") {
            for name in split_names(rest) {
                out.push(env.domain_rule_set(name).map_err(|err| {
                    DnsError::rule(format!("{what}[{index}] {entry:?}: {err}"), err)
                })?);
            }
        } else {
            set.insert(entry)
                .map_err(|err| DnsError::config(format!("{what}[{index}]: {err}")))?;
        }
    }
    if !set.is_empty() {
        out.push(Arc::new(set));
    }
    Ok(out)
}

/// `geoip:` of `skip-src-address`/`skip-dst-address`: the plain GEOIP rule, so
/// `lan` is the private ranges and anything else is a country-code hit.
struct GeoIpIs {
    lookup: Arc<dyn GeoIpLookup>,
    code: String,
}

impl IpMatch for GeoIpIs {
    fn matches(&self, ip: IpAddr) -> bool {
        if self.code == "lan" {
            return is_lan(ip);
        }
        self.lookup
            .country_codes(ip)
            .iter()
            .any(|code| code.eq_ignore_ascii_case(&self.code))
    }
}

/// Builds the matchers `parseIPCIDR` does: one per `geoip:` code and per
/// `rule-set:` name, then one for all the plain CIDRs.
pub fn ip_matchers(
    cidrs: Vec<IpCidr>,
    geoip: &[String],
    rule_sets: &[String],
    env: &dyn RuleEnv,
) -> Result<Vec<Arc<dyn IpMatch>>, DnsError> {
    let mut out: Vec<Arc<dyn IpMatch>> = Vec::new();
    for code in geoip {
        let code = code.to_ascii_lowercase();
        let lookup = if code == "lan" {
            Arc::new(NoCountry) as Arc<dyn GeoIpLookup>
        } else {
            env.geoip()
                .map_err(|err| DnsError::rule(err.to_string(), err))?
        };
        out.push(Arc::new(GeoIpIs { lookup, code }));
    }
    for name in rule_sets {
        out.push(
            env.ip_rule_set(name)
                .map_err(|err| DnsError::rule(err.to_string(), err))?,
        );
    }
    if !cidrs.is_empty() {
        out.push(Arc::new(CidrSet::new(cidrs)));
    }
    Ok(out)
}

struct NoCountry;

impl GeoIpLookup for NoCountry {
    fn country_codes(&self, _: IpAddr) -> Vec<String> {
        Vec::new()
    }
}

pub enum Skipper {
    Rules(Vec<FilterRule>),
    Hosts {
        matchers: Vec<Arc<dyn DomainMatch>>,
        whitelist: bool,
    },
}

fn normalize_host(domain: &str) -> Cow<'_, str> {
    if domain
        .bytes()
        .any(|b| b.is_ascii_uppercase() || !b.is_ascii())
    {
        Cow::Owned(domain.to_lowercase())
    } else {
        Cow::Borrowed(domain)
    }
}

impl Skipper {
    pub fn should_skip(&self, domain: &str) -> bool {
        match self {
            Skipper::Rules(rules) if !rules.is_empty() => {
                let host = normalize_host(domain);
                rules
                    .iter()
                    .find(|rule| rule.cond.matches(&host))
                    .is_some_and(|rule| rule.real_ip)
            }
            Skipper::Rules(_) => false,
            Skipper::Hosts {
                matchers,
                whitelist,
            } => {
                let hit = matchers.iter().any(|matcher| matcher.matches(domain));
                hit != *whitelist
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleError;

    #[test]
    fn wildcard_follows_the_go_table() {
        for (text, pattern, want) in [
            ("", "", true),
            ("", "*", true),
            ("", "?", false),
            ("a", "?*", true),
            ("abc.edf.hjg", "abc.*.hjg", true),
            ("abc.edf.hjg", "abc*hjq", false),
            ("abc.edf.hjg", "a*g", true),
            ("abc.edf.hjg", "ab??.edf.hjg", false),
            ("abc.edf.hjg", "?b?.edf.hjg", true),
            (
                "do not match a string with extra and a *",
                "do not match a string * with more",
                false,
            ),
        ] {
            assert_eq!(
                wildcard_match(pattern, text),
                want,
                "{pattern:?} vs {text:?}"
            );
        }
    }

    struct Codes;

    impl GeoIpLookup for Codes {
        fn country_codes(&self, ip: IpAddr) -> Vec<String> {
            if ip == "1.2.3.4".parse::<IpAddr>().unwrap() {
                vec!["cn".into()]
            } else {
                Vec::new()
            }
        }
    }

    struct Env;

    impl RuleEnv for Env {
        fn geosite(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError> {
            Err(name.into())
        }

        fn domain_rule_set(&self, name: &str) -> Result<Arc<dyn DomainMatch>, RuleError> {
            Err(name.into())
        }

        fn geoip(&self) -> Result<Arc<dyn GeoIpLookup>, RuleError> {
            Ok(Arc::new(Codes))
        }

        fn ip_rule_set(&self, name: &str) -> Result<Arc<dyn IpMatch>, RuleError> {
            Err(format!("not found rule-set: {name}").into())
        }
    }

    #[test]
    fn ip_matchers_build_geoip_lan_and_cidrs() {
        let cidr = IpCidr {
            addr: "9.9.9.0".parse().unwrap(),
            prefix: 24,
        };
        let matchers = ip_matchers(vec![cidr], &["CN".into(), "lan".into()], &[], &Env).unwrap();
        assert_eq!(matchers.len(), 3);
        let hit = |ip: &str| {
            let ip: IpAddr = ip.parse().unwrap();
            matchers.iter().any(|m| m.matches(ip))
        };
        assert!(hit("1.2.3.4"));
        assert!(hit("192.168.1.1"));
        assert!(hit("9.9.9.9"));
        assert!(!hit("8.8.8.8"));
        assert!(ip_matchers(Vec::new(), &[], &["nope".into()], &Env).is_err());
    }

    #[test]
    fn suffix_needs_a_label_boundary() {
        let cond = DomainCond::Suffix("example.com".into());
        assert!(cond.matches("example.com"));
        assert!(cond.matches("a.example.com"));
        assert!(!cond.matches("badexample.com"));
    }

    #[test]
    fn cidr_set_coalesces_ranges_and_matches_boundaries() {
        let cidrs = [
            "10.0.0.0/25",
            "10.0.0.128/25",
            "10.0.0.64/26",
            "2001:db8::/33",
            "2001:db8:8000::/33",
        ]
        .into_iter()
        .map(|text| IpCidr::parse(text).unwrap())
        .collect();
        let set = CidrSet::new(cidrs);
        assert_eq!(set.range_count(), 2);
        for hit in [
            "10.0.0.0",
            "10.0.0.127",
            "10.0.0.255",
            "2001:db8::1",
            "2001:db8:ffff::1",
        ] {
            assert!(set.matches(hit.parse().unwrap()), "expected hit for {hit}");
        }
        for miss in [
            "9.255.255.255",
            "10.0.1.0",
            "2001:db7:ffff::1",
            "2001:db9::",
        ] {
            assert!(
                !set.matches(miss.parse().unwrap()),
                "expected miss for {miss}"
            );
        }

        let uncanonical = CidrSet::new(vec![IpCidr {
            addr: "192.168.1.99".parse().unwrap(),
            prefix: 24,
        }]);
        assert!(uncanonical.matches("192.168.1.1".parse().unwrap()));
        assert!(!uncanonical.matches("192.168.2.1".parse().unwrap()));
    }

    struct RecordingMatcher {
        seen: std::sync::Mutex<Vec<(usize, String)>>,
    }

    impl RecordingMatcher {
        fn new() -> Self {
            RecordingMatcher {
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl DomainMatch for RecordingMatcher {
        fn matches(&self, domain: &str) -> bool {
            concord_common::sync::lock(&self.seen).push((domain.as_ptr() as usize, domain.into()));
            false
        }
    }

    #[test]
    fn skipper_rules_borrow_lowercase_host_and_match_mixed_case() {
        let recorder = Arc::new(RecordingMatcher::new());
        let rules = vec![
            FilterRule {
                cond: DomainCond::Set(Arc::clone(&recorder) as Arc<dyn DomainMatch>),
                real_ip: false,
            },
            FilterRule {
                cond: DomainCond::Set(Arc::clone(&recorder) as Arc<dyn DomainMatch>),
                real_ip: false,
            },
            FilterRule {
                cond: DomainCond::Set(Arc::clone(&recorder) as Arc<dyn DomainMatch>),
                real_ip: false,
            },
            FilterRule {
                cond: DomainCond::Exact("sub.example.com".into()),
                real_ip: true,
            },
            FilterRule {
                cond: DomainCond::Exact("fake.example.com".into()),
                real_ip: false,
            },
            FilterRule {
                cond: DomainCond::Suffix("example.com".into()),
                real_ip: true,
            },
        ];
        let skipper = Skipper::Rules(rules);

        let lower = "sub.example.com";
        assert!(skipper.should_skip(lower));
        let seen = std::mem::take(&mut *concord_common::sync::lock(&recorder.seen));
        assert_eq!(seen.len(), 3);
        for (ptr, host) in seen {
            assert_eq!(host, "sub.example.com");
            assert_eq!(ptr, lower.as_ptr() as usize);
        }

        assert!(skipper.should_skip("SUB.Example.COM"));
        let seen = std::mem::take(&mut *concord_common::sync::lock(&recorder.seen));
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|(_, host)| host == "sub.example.com"));

        assert!(!skipper.should_skip("FAKE.Example.COM"));
        assert!(skipper.should_skip("Other.Example.COM"));
    }
}
