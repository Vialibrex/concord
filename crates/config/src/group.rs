use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use serde_json::Value;

use crate::Map;
use crate::error::{ConfigError, Result};
use crate::filter;
use crate::lenient::{Fields, Ignored};
use crate::net::parse_unsigned_ranges;
use crate::proxy::ProxyDef;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GroupKind {
    #[default]
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    Smart,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupKind::Select => "select",
            GroupKind::UrlTest => "url-test",
            GroupKind::Fallback => "fallback",
            GroupKind::LoadBalance => "load-balance",
            GroupKind::Smart => "smart",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            GroupKind::Select => "Selector",
            GroupKind::UrlTest => "URLTest",
            GroupKind::Fallback => "Fallback",
            GroupKind::LoadBalance => "LoadBalance",
            GroupKind::Smart => "Smart",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LbStrategy {
    #[default]
    ConsistentHashing,
    RoundRobin,
    StickySessions,
}

/// A `policy-priority` entry; a pattern is a regex when it compiles and a substring otherwise.
#[derive(Clone, Debug)]
pub struct PriorityRule {
    pub pattern: String,
    pub factor: f64,
}

impl PartialEq for PriorityRule {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.factor.to_bits() == other.factor.to_bits()
    }
}

impl Eq for PriorityRule {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupDef {
    pub name: String,
    pub kind: GroupKind,
    pub proxies: Vec<String>,
    pub use_providers: Vec<String>,
    pub use_position: IndexMap<String, i32>,
    pub url: String,
    /// Only a nonempty YAML string overrides the runtime's test URL.
    pub explicit_url: Option<String>,
    pub interval: u32,
    /// Kept before group defaults; base-0 strings and floats are not decimal zero here.
    pub interval_is_zero: bool,
    pub timeout: u32,
    pub max_failed_times: u32,
    pub empty_fallback: String,
    pub explicit_empty_fallback: bool,
    pub lazy: bool,
    pub disable_udp: bool,
    pub filter: String,
    pub exclude_filter: String,
    pub exclude_type: String,
    pub expected_status: String,
    pub include_all: bool,
    pub include_all_proxies: bool,
    pub include_all_providers: bool,
    pub hidden: bool,
    pub icon: String,
    pub tolerance: u16,
    pub policy_priority: Vec<PriorityRule>,
    pub default_selected: String,
    pub strategy: LbStrategy,
    pub hash_key: String,
    /// Keys a group does not have, which mihomo logs and drops.
    pub ignored: Vec<Ignored>,
    pub builtin_global: bool,
}

fn format_error() -> ConfigError {
    ConfigError::new("format error")
}

fn interval_is_zero(map: &Map) -> bool {
    match map.get("interval") {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.trim().parse::<u64>().is_ok_and(|n| n == 0),
        Some(value) => value.as_u64() == Some(0),
    }
}

fn explicit_text<'a>(map: &'a Map, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

fn last_unescaped_colon(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().rev().find_map(|(i, &b)| {
        let escapes = bytes
            .get(..i)?
            .iter()
            .rev()
            .take_while(|&&b| b == b'\\')
            .count();
        (b == b':' && escapes % 2 == 0).then_some(i)
    })
}

fn unescape(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        let escaped = if c == '\\' { chars.next() } else { None };
        out.push(escaped.unwrap_or(c));
    }
    out
}

fn parse_policy_priority(text: &str, f: &mut Fields<'_>) -> Vec<PriorityRule> {
    let mut rules = Vec::new();
    for pair in text.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let split = last_unescaped_colon(pair).filter(|&i| i > 0 && i + 1 < pair.len());
        let Some(idx) = split else {
            f.warn(
                "policy-priority",
                &format!("`{pair}` is skipped: it must be `pattern:factor`"),
            );
            continue;
        };
        let (pattern, factor) = (pair[..idx].trim(), pair[idx + 1..].trim());
        match factor.parse::<f64>() {
            Ok(factor) if factor.is_finite() && factor > 0.0 => rules.push(PriorityRule {
                pattern: unescape(pattern),
                factor,
            }),
            _ => f.warn(
                "policy-priority",
                &format!("`{pair}` is skipped: the factor must be a positive number"),
            ),
        }
    }
    rules
}

fn read_smart(def: &mut GroupDef, f: &mut Fields<'_>) -> Result<()> {
    def.tolerance = u16::try_from(f.u32("tolerance")?).unwrap_or(u16::MAX);
    def.policy_priority = parse_policy_priority(&f.string("policy-priority")?, f);
    for (key, why) in [
        ("uselightgbm", "this core does not use a LightGBM model"),
        ("collectdata", "this core does not collect training data"),
        ("sample-rate", "this core does not collect training data"),
        ("prefer-asn", "this core does not key nodes by ASN"),
    ] {
        f.ignore_switch(key, why);
    }
    Ok(())
}

pub fn parse_group(map: &Map) -> Result<GroupDef> {
    let mut f = Fields::new(map, "", false);
    let name = f.string("name").map_err(|_| format_error())?;
    let type_name = f.string("type").map_err(|_| format_error())?;
    if name.is_empty() || type_name.is_empty() {
        return Err(format_error());
    }
    let decode =
        |err: ConfigError| ConfigError::new(format!("format error: {name}: {}", err.message));
    let include_all = f.boolean("include-all").map_err(decode)?;
    let mut use_position = IndexMap::new();
    if let Some(positions) = f.object("use-position").map_err(decode)? {
        for (provider, value) in positions {
            let index = crate::lenient::to_i128(value)
                .and_then(|n| i32::try_from(n).ok())
                .ok_or_else(|| {
                    ConfigError::new(format!(
                        "format error: {name}: use-position.{provider} is not an int"
                    ))
                })?;
            use_position.insert(provider.clone(), index);
        }
    }
    let mut def = GroupDef {
        name: name.clone(),
        proxies: f.strings("proxies").map_err(decode)?,
        use_providers: f.strings("use").map_err(decode)?,
        use_position,
        url: f.string("url").map_err(decode)?,
        explicit_url: explicit_text(map, "url").map(str::to_string),
        interval: f.u32("interval").map_err(decode)?,
        interval_is_zero: interval_is_zero(map),
        timeout: f.u32("timeout").map_err(decode)?,
        max_failed_times: f.u32("max-failed-times").map_err(decode)?,
        empty_fallback: f.string("empty-fallback").map_err(decode)?,
        explicit_empty_fallback: explicit_text(map, "empty-fallback").is_some(),
        lazy: f.opt_bool("lazy").map_err(decode)?.unwrap_or(true),
        disable_udp: f.boolean("disable-udp").map_err(decode)?,
        filter: f.string("filter").map_err(decode)?,
        exclude_filter: f.string("exclude-filter").map_err(decode)?,
        exclude_type: f.string("exclude-type").map_err(decode)?,
        expected_status: f.string("expected-status").map_err(decode)?,
        include_all,
        include_all_proxies: include_all || f.boolean("include-all-proxies").map_err(decode)?,
        include_all_providers: include_all || f.boolean("include-all-providers").map_err(decode)?,
        hidden: f.boolean("hidden").map_err(decode)?,
        icon: f.string("icon").map_err(decode)?,
        ..GroupDef::default()
    };
    def.kind = match type_name.as_str() {
        "select" => GroupKind::Select,
        "url-test" => GroupKind::UrlTest,
        "fallback" => GroupKind::Fallback,
        "load-balance" => GroupKind::LoadBalance,
        "smart" => GroupKind::Smart,
        "relay" => {
            return Err(ConfigError::new(format!(
                "unsupported type: The group [{name}] with relay type was removed, please using dialer-proxy instead"
            )));
        }
        other => return Err(ConfigError::new(format!("unsupported type: {other}"))),
    };
    match def.kind {
        GroupKind::UrlTest => {
            def.tolerance = u16::try_from(f.u32("tolerance")?).unwrap_or(u16::MAX);
        }
        GroupKind::Smart => read_smart(&mut def, &mut f)?,
        GroupKind::Select => def.default_selected = f.string("default-selected")?,
        GroupKind::LoadBalance => {
            let strategy = f.string("strategy")?;
            def.hash_key = f.string("hash-key")?;
            def.strategy = match strategy.as_str() {
                "" | "consistent-hashing" => LbStrategy::ConsistentHashing,
                "round-robin" => {
                    if !def.hash_key.is_empty() {
                        return Err(ConfigError::new(format!(
                            "{name}: unsupported hash-key: round-robin does not hash"
                        )));
                    }
                    LbStrategy::RoundRobin
                }
                "sticky-sessions" => LbStrategy::StickySessions,
                other => {
                    return Err(ConfigError::new(format!("unsupported strategy: {other}")));
                }
            };
            if !matches!(def.hash_key.as_str(), "" | "in-user") {
                return Err(ConfigError::new(format!(
                    "unsupported hash-key: {}",
                    def.hash_key
                )));
            }
        }
        GroupKind::Fallback => {}
    }
    for (key, text) in [
        ("filter", &def.filter),
        ("exclude-filter", &def.exclude_filter),
    ] {
        if !text.is_empty() {
            filter::validate(text)
                .map_err(|err| ConfigError::new(format!("{name}: {key}: {}", err.message)))?;
        }
    }
    parse_unsigned_ranges(&def.expected_status, u64::from(u16::MAX))
        .map_err(|err| ConfigError::new(format!("{name}: {}", err.message)))?;
    def.expected_status = match def.expected_status.trim() {
        "" => "*".to_string(),
        text => text.to_string(),
    };
    for key in ["routing-mark", "interface-name", "dialer-proxy"] {
        f.ignore(key, "a group does not dial, so set it on the nodes");
    }
    def.ignored = f.take_ignored();
    Ok(def)
}

impl GroupDef {
    pub(crate) fn global(proxies: &[ProxyDef], groups: &[GroupDef], url: &str) -> Self {
        let mut members = vec!["DIRECT".to_string(), "REJECT".to_string()];
        members.extend(proxies.iter().map(|p| p.name.clone()));
        members.extend(groups.iter().map(|g| g.name.clone()));
        GroupDef {
            name: "GLOBAL".to_string(),
            proxies: members,
            url: url.to_string(),
            interval_is_zero: true,
            empty_fallback: "COMPATIBLE".to_string(),
            lazy: true,
            expected_status: "*".to_string(),
            builtin_global: true,
            ..GroupDef::default()
        }
    }

    /// Adds the nodes `include-all` takes and returns the set-aside ones it matched, which mihomo would hold.
    pub fn take_all_proxies(
        &mut self,
        sorted: &[&str],
        set_aside: &HashSet<String>,
    ) -> Result<Vec<String>> {
        let filter = (!self.filter.is_empty())
            .then(|| filter::CompiledFilter::compile(&self.filter))
            .transpose()?;
        let matches = |name: &str| filter.as_ref().is_none_or(|f| f.is_match(name));
        let taken = sorted.iter().filter(|name| matches(name));
        self.proxies.extend(taken.map(|name| (*name).to_string()));
        let mut aside: Vec<String> = set_aside
            .iter()
            .filter(|name| matches(name))
            .cloned()
            .collect();
        aside.sort_unstable();
        Ok(aside)
    }
}

pub fn find_group_cycle(groups: &[GroupDef]) -> Option<Vec<String>> {
    let index: HashMap<&str, &GroupDef> = groups.iter().map(|g| (g.name.as_str(), g)).collect();
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Visiting,
        Done,
    }
    let mut marks: HashMap<&str, Mark> = HashMap::new();
    for start in groups {
        if marks.contains_key(start.name.as_str()) {
            continue;
        }
        let mut stack: Vec<(&str, usize)> = vec![(start.name.as_str(), 0)];
        marks.insert(start.name.as_str(), Mark::Visiting);
        while let Some((current, child_index)) = stack.pop() {
            let children: Vec<&str> = index
                .get(current)
                .map(|g| {
                    g.proxies
                        .iter()
                        .map(String::as_str)
                        .filter(|p| index.contains_key(p))
                        .collect()
                })
                .unwrap_or_default();
            if let Some(&next) = children.get(child_index) {
                stack.push((current, child_index + 1));
                match marks.get(next) {
                    Some(Mark::Visiting) => {
                        let mut cycle: Vec<String> =
                            stack.iter().map(|(name, _)| (*name).to_string()).collect();
                        let from = cycle.iter().position(|name| name == next).unwrap_or(0);
                        cycle.drain(..from);
                        let mut seen = HashSet::new();
                        cycle.retain(|name| seen.insert(name.clone()));
                        return Some(cycle);
                    }
                    Some(Mark::Done) => {}
                    None => {
                        marks.insert(next, Mark::Visiting);
                        stack.push((next, 0));
                    }
                }
            } else {
                marks.insert(current, Mark::Done);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn group(value: serde_json::Value) -> Result<GroupDef> {
        match value {
            serde_json::Value::Object(map) => parse_group(&map),
            _ => Err(ConfigError::new("not a map")),
        }
    }

    #[test]
    fn a_select_group_reads_its_options() {
        let def = group(json!({
            "name": "Proxy", "type": "select", "proxies": ["a", "b"], "use": "p1",
            "include-all": true, "filter": "hk`jp", "default-selected": "b", "hidden": "true",
            "use-position": {"p1": 2}
        }))
        .unwrap();
        assert_eq!(def.kind, GroupKind::Select);
        assert_eq!(def.proxies, ["a", "b"]);
        assert_eq!(def.use_providers, ["p1"]);
        assert!(def.include_all_proxies && def.include_all_providers && def.hidden && def.lazy);
        assert_eq!(def.default_selected, "b");
        assert_eq!(def.use_position.get("p1"), Some(&2));
        assert_eq!(def.expected_status, "*");
    }

    #[test]
    fn type_specific_options() {
        let def = group(json!({"name": "t", "type": "url-test", "proxies": ["a"], "tolerance": "50", "lazy": false})).unwrap();
        assert_eq!((def.tolerance, def.lazy), (50, false));
        let def = group(json!({"name": "l", "type": "load-balance", "proxies": ["a"], "strategy": "sticky-sessions", "hash-key": "in-user"})).unwrap();
        assert_eq!(def.strategy, LbStrategy::StickySessions);
        assert!(group(json!({"name": "l", "type": "load-balance", "strategy": "round-robin", "hash-key": "in-user"})).is_err());
        assert!(group(json!({"name": "l", "type": "load-balance", "strategy": "random"})).is_err());
    }

    #[test]
    fn relay_and_unknown_types_are_rejected() {
        let err = group(json!({"name": "r", "type": "relay", "proxies": ["a"]})).unwrap_err();
        assert!(err.message.contains("relay type was removed"), "{err}");
        assert!(group(json!({"name": "r", "type": "magic"})).is_err());
        assert_eq!(
            group(json!({"type": "select"})).unwrap_err().message,
            "format error"
        );
    }

    #[test]
    fn a_field_that_does_not_decode_names_the_group_and_the_key() {
        let message = |value| group(value).unwrap_err().message;
        assert_eq!(
            message(json!({"name": "g", "type": "select", "interval": "abc"})),
            "format error: g: 'interval' expected type 'uint32', got unconvertible type 'string'"
        );
        assert_eq!(
            message(json!({"name": "g", "type": "select", "use-position": {"p": "x"}})),
            "format error: g: use-position.p is not an int"
        );
        assert!(
            message(json!({"name": "g", "type": "select", "exclude-filter": "(abc"}))
                .starts_with("g: exclude-filter: ")
        );
    }

    #[test]
    fn bad_filters_and_statuses_are_rejected() {
        assert!(group(json!({"name": "g", "type": "select", "filter": "(abc"})).is_err());
        assert!(group(json!({"name": "g", "type": "select", "expected-status": "20x"})).is_err());
        assert!(
            group(json!({"name": "g", "type": "select", "expected-status": "200/302"})).is_ok()
        );
    }

    #[test]
    fn group_cycles_are_found() {
        let defs: Vec<GroupDef> = [
            json!({"name": "a", "type": "select", "proxies": ["b"]}),
            json!({"name": "b", "type": "select", "proxies": ["c", "DIRECT"]}),
            json!({"name": "c", "type": "select", "proxies": ["a"]}),
        ]
        .into_iter()
        .map(|v| group(v).unwrap())
        .collect();
        let cycle = find_group_cycle(&defs).unwrap();
        assert_eq!(cycle.len(), 3);
        assert!(find_group_cycle(&defs[..2]).is_none());
    }

    fn smart(priority: &str) -> GroupDef {
        group(json!({"name": "s", "type": "smart", "proxies": ["a"], "tolerance": 30, "policy-priority": priority})).unwrap()
    }

    fn rules(def: &GroupDef) -> Vec<(&str, f64)> {
        def.policy_priority
            .iter()
            .map(|rule| (rule.pattern.as_str(), rule.factor))
            .collect()
    }

    #[test]
    fn a_smart_group_reads_tolerance_and_priority_rules_in_order() {
        let def = smart("hk:1.5; (?i)jp.*:0.5 ;; sg:2");
        assert_eq!(def.kind, GroupKind::Smart);
        assert_eq!(
            (def.kind.as_str(), def.kind.display_name()),
            ("smart", "Smart")
        );
        assert_eq!(def.tolerance, 30);
        assert_eq!(rules(&def), [("hk", 1.5), ("(?i)jp.*", 0.5), ("sg", 2.0)]);
        assert!(def.ignored.is_empty(), "{:?}", def.ignored);
        assert!(
            group(json!({"name": "s", "type": "smart"}))
                .unwrap()
                .policy_priority
                .is_empty()
        );
    }

    #[test]
    fn a_priority_pair_splits_at_the_last_unescaped_colon() {
        let def = smart(r"a\:b:1.5;x:y:2;c\\:3;d\:e");
        assert_eq!(rules(&def), [("a:b", 1.5), ("x:y", 2.0), (r"c\", 3.0)]);
        assert_eq!(def.ignored.len(), 1, "{:?}", def.ignored);
    }

    #[test]
    fn an_invalid_priority_pair_is_skipped_with_a_warning() {
        let def = smart("nocolon;:2;hk:;jp:abc;sg:0;tw:-1;us:inf;ok:3");
        assert_eq!(rules(&def), [("ok", 3.0)]);
        assert_eq!(def.ignored.len(), 7, "{:?}", def.ignored);
        assert!(
            def.ignored
                .iter()
                .all(|w| w.code == "not_applied" && w.key == "policy-priority")
        );
    }

    #[test]
    fn smart_model_keys_warn_only_when_they_ask_for_something() {
        let warned = |options: serde_json::Value| {
            let mut value = json!({"name": "s", "type": "smart", "proxies": ["a"]});
            value
                .as_object_mut()
                .unwrap()
                .extend(options.as_object().unwrap().clone());
            group(value)
                .unwrap()
                .ignored
                .iter()
                .map(|w| w.key.clone())
                .collect::<Vec<_>>()
        };
        assert!(warned(json!({"uselightgbm": false, "collectdata": false})).is_empty());
        assert_eq!(warned(json!({"uselightgbm": true})), ["uselightgbm"]);
        assert_eq!(
            warned(json!({"collectdata": true, "sample-rate": 0.5, "prefer-asn": true})),
            ["collectdata", "sample-rate", "prefer-asn"]
        );
    }
}
