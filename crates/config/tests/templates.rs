//! Profiles keep the maps their aliases copy under keys of their own, such as `rule-anchor:` with
//! `ip: &ip {...}` under it. mihomo ignores such keys once the aliases are expanded, so they are
//! neither reported nor kept, whichever way the profile reaches the core: read on its own (`-t`,
//! `config.read`, `profile.inspect`), as the base of an overlay the host built from it, or as
//! the whole config a host wrote back after running a script over what `config.read` gave it.

use concord_config::{
    LoadOptions, RawConfig, load_raw, merge_document, parse_raw, parse_raw_str, profile_base,
};
use serde_json::Value;

/// The load's report carries the raw config's.
fn warned(raw: &RawConfig) -> Vec<String> {
    let profile = load_raw(raw.clone(), &LoadOptions::default()).unwrap();
    profile
        .report
        .warnings
        .iter()
        .map(|w| w.path.clone())
        .collect()
}

/// Each way in: what it warns about and the config it keeps.
fn every_path(text: &str) -> Vec<(&'static str, Vec<String>, Value)> {
    let direct = parse_raw(text.as_bytes()).unwrap();

    let base = profile_base(text.as_bytes(), None).unwrap();
    let mut overlay = base.config.as_object().cloned().unwrap();
    overlay.remove("rule");
    overlay.insert("rules".into(), Value::Array(Vec::new()));
    let merged = merge_document(text.as_bytes(), &Value::Object(overlay).to_string(), None);
    let applied = RawConfig::from_document(merged.unwrap()).unwrap();

    let mut read = direct.to_json();
    let read_map = read.as_object_mut().unwrap();
    let rules = read_map.remove("rule").unwrap();
    read_map.insert("rules".into(), rules);
    let whole = parse_raw_str(&read.to_string()).unwrap();

    vec![
        ("profile", warned(&direct), direct.to_json()),
        ("inspect", Vec::new(), base.config),
        ("overlay", warned(&applied), applied.to_json()),
        ("script", warned(&whole), whole.to_json()),
    ]
}

fn assert_dropped(text: &str, templates: &[&str]) {
    for (way, warned, config) in every_path(text) {
        assert_eq!(warned, Vec::<String>::new(), "{way} warns");
        for template in templates {
            let mut at = &config;
            let mut kept = true;
            for part in template.split('.') {
                match at.get(part) {
                    Some(next) => at = next,
                    None => kept = false,
                }
            }
            assert!(!kept, "{way} keeps {template}");
        }
    }
}

#[test]
fn a_key_holding_anchored_maps_is_a_template() {
    let text = "rule-anchor:\n  ip: &ip {type: http, interval: 86400, behavior: ipcidr, format: mrs}\n  \
                domain: &domain {type: http, interval: 86400, behavior: domain, format: mrs}\n\
                rule-providers:\n  cn: {<<: *domain, url: 'https://x/cn.mrs'}\n  \
                cnip: {<<: *ip, url: 'https://x/cnip.mrs'}\nrules:\n  - RULE-SET,cn,DIRECT\n  - MATCH,DIRECT\n";
    assert_dropped(text, &["rule-anchor"]);
    let config = parse_raw(text.as_bytes()).unwrap().to_json();
    assert_eq!(config["rule-providers"]["cnip"]["behavior"], "ipcidr");
}

#[test]
fn an_anchored_key_is_a_template() {
    assert_dropped(
        "proxy-provider-anchor: &pp {type: http, interval: 3600, health-check: {enable: true, url: 'https://x/t'}}\n\
         proxy-providers:\n  a:\n    <<: *pp\n    url: https://x/a\n",
        &["proxy-provider-anchor"],
    );
}

#[test]
fn a_template_may_build_on_another_inside_it() {
    assert_dropped(
        "proxy-provider-anchor:\n  check: &check {enable: true, url: 'https://x/t', interval: 300}\n  \
         base: &base {type: http, interval: 3600, health-check: *check}\n  \
         lazy: &lazy {<<: *base, health-check: {<<: *check, lazy: true}}\n\
         proxy-providers:\n  a: {<<: *lazy, url: 'https://x/a'}\n",
        &["proxy-provider-anchor"],
    );
}

#[test]
fn a_list_of_anchored_items_is_a_template() {
    assert_dropped(
        "proxy-provider-anchor:\n  - &pp {type: http, interval: 3600}\nproxy-providers:\n  a: {<<: *pp, url: 'https://x/a'}\n",
        &["proxy-provider-anchor"],
    );
}

#[test]
fn anchored_lists_and_scalars_are_templates() {
    assert_dropped(
        "names: &names [a, b]\nhk: &hk '(?i)港|HK'\nfilters:\n  jp: &jp '(?i)日本|JP'\n\
         proxies:\n  - {name: a, type: direct}\n  - {name: b, type: direct}\n\
         proxy-groups:\n  - {name: g, type: select, proxies: *names, filter: *hk}\n  \
         - {name: j, type: select, proxies: [a], filter: *jp}\n",
        &["names", "hk", "filters"],
    );
}

#[test]
fn an_anchor_deep_under_a_key_makes_it_a_template() {
    assert_dropped(
        "templates:\n  providers:\n    http: &http {type: http, interval: 3600}\n\
         proxy-providers:\n  a: {<<: *http, url: 'https://x/a'}\n",
        &["templates"],
    );
}

#[test]
fn a_section_key_holding_an_anchor_is_a_template() {
    let text = "dns:\n  enable: true\n  cn-dns: &cn [223.5.5.5]\n  nameserver: *cn\n  \
                fallback-filter:\n    hold: &geo [CN]\n    geoip-code: CN\n\
                sniffer:\n  enable: true\n  ports: &ports [80, 443]\n  sniff:\n    TLS: {ports: *ports}\n";
    assert_dropped(
        text,
        &["dns.cn-dns", "dns.fallback-filter.hold", "sniffer.ports"],
    );
    let config = parse_raw(text.as_bytes()).unwrap().to_json();
    assert_eq!(
        config["dns"]["nameserver"],
        serde_json::json!(["223.5.5.5"])
    );
    assert_eq!(
        config["sniffer"]["sniff"]["TLS"]["ports"],
        serde_json::json!(["80", "443"])
    );
}

#[test]
fn a_known_key_that_holds_an_anchor_is_read_as_usual() {
    let text = "dns: &dns {enable: true, ipv6: true}\n\
                proxy-providers:\n  a: &a {type: http, url: 'https://x/a', interval: 3600}\n  \
                b: {<<: *a, url: 'https://x/b'}\n";
    for (way, warned, config) in every_path(text) {
        assert_eq!(warned, Vec::<String>::new(), "{way} warns");
        assert_eq!(config["dns"]["ipv6"], true, "{way}");
        assert_eq!(config["proxy-providers"]["b"]["interval"], 3600, "{way}");
        assert_eq!(
            config["proxy-providers"]["a"]["url"], "https://x/a",
            "{way}"
        );
    }
}

#[test]
fn a_key_that_only_uses_a_template_is_unknown() {
    let text = "base: &base {type: http, interval: 3600}\ncopy: *base\nmerged: {<<: *base, url: 'https://x'}\n";
    for (way, mut warned, config) in every_path(text) {
        warned.sort_unstable();
        if way == "inspect" {
            assert!(config.get("copy").is_some() && config.get("merged").is_some());
            continue;
        }
        assert_eq!(warned, ["copy", "merged"], "{way}");
        assert!(config.get("base").is_none(), "{way}");
    }
}

#[test]
fn an_overlay_written_as_yaml_keeps_its_templates_out() {
    let profile = "proxies:\n  - {name: a, type: direct}\n";
    let overlay = "rule-anchor:\n  domain: &domain {type: http, behavior: domain, interval: 86400}\n\
                   rule-providers:\n  cn: {<<: *domain, url: 'https://x/cn.yaml'}\n";
    let merged = merge_document(profile.as_bytes(), overlay, None).unwrap();
    let raw = RawConfig::from_document(merged).unwrap();
    assert_eq!(warned(&raw), Vec::<String>::new());
    assert!(raw.to_json().get("rule-anchor").is_none());
    assert_eq!(raw.to_json()["rule-providers"]["cn"]["behavior"], "domain");
}
