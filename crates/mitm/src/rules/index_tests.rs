use super::*;
use crate::rules::parse_url_rewrite;

const PATTERNS: [&str; 17] = [
    r"^http:\/\/launch\.cloud\.a\.test\/Article\/LaunchLogo",
    r"^https?:\/\/(h3\.)?open\.b\.test\/feed\/adshow\?",
    r"^https:\/\/api\.c\.test\/2\/timeline\/(home(?>_hot|_topic)?|unread_hot)\?",
    r"^https://example\.com:8443/ads/\d+",
    r"^https?://ad\.example\.com/banner\?id=\w+",
    r"(?i)^https://cdn\.ads\.test/",
    r"(?i)^https://www\.example\.org/promotions/summer-sale/banner",
    r"^\w+://tracker\.test/",
    r"/collect\?",
    r"^https://a\.test/(?=x)",
    r"^https://a\.test/x\d+$",
    r"^https?://(www\.)?video\.test/(ad|pre)roll",
    r"^https://API\.Mixed\.test/v1",
    r"^",
    r"^https?:\/\/[\w-]+\.maps\.test\/ws\/(boss|shield)\/",
    r"^https?://[^/]+/(api|v2)/promo(tion)?s?/",
    r"(?i)/ADS/",
];

const URLS: [&str; 27] = [
    "http://launch.cloud.a.test/Article/LaunchLogo?x=1",
    "https://launch.cloud.a.test/Article/LaunchLogo",
    "https://h3.open.b.test/feed/adshow?a=1",
    "http://open.b.test/feed/adshow?a=1",
    "https://api.c.test/2/timeline/home_hot?gsid=1",
    "https://api.c.test/2/timeline/unread_hot?from=1",
    "https://example.com:8443/ads/12",
    "https://example.com/ads/12",
    "https://ad.example.com/banner?id=abc",
    "HTTPS://CDN.ADS.TEST/x.js",
    "https://Cdn.Ads.Test/x.js",
    "https://WWW.EXAMPLE.ORG/PROMOTIONS/SUMMER-SALE/BANNER.png",
    "ws://tracker.test/x",
    "https://site.test/collect?v=1",
    "https://a.test/xyz",
    "https://a.test/x12",
    "https://video.test/preroll.mp4",
    "http://www.video.test/adroll",
    "https://api.mixed.test/v1",
    "https://API.Mixed.test/v1/list",
    "https://www.unrelated.test/index.html",
    "",
    "https://m5.maps.test/ws/boss/order",
    "https://m5.maps.test/ws/other/x",
    "https://shop.test/api/promotions/1",
    "https://shop.test/v2/promo/1?x=/ads/",
    "https://cdn.test/Ads/x.png",
];

fn rules_of(patterns: &[&str]) -> Rules {
    let mut rules = Rules::default();
    for pattern in patterns {
        let line = format!("{pattern} _ reject");
        rules
            .url_rewrites
            .push(parse_url_rewrite(&line).unwrap_or_else(|err| panic!("{line}: {err}")));
    }
    rules
}

fn naive(rules: &Rules, url: &str) -> Vec<*const super::super::UrlRewrite> {
    rules
        .url_rewrites
        .iter()
        .filter(|rule| rule.pattern.is_match(url))
        .map(std::ptr::from_ref)
        .collect()
}

fn indexed(rules: &Rules, url: &str) -> Vec<*const super::super::UrlRewrite> {
    rules
        .url_rewrite_candidates(url)
        .filter(|rule| rule.pattern.is_match(url))
        .map(std::ptr::from_ref)
        .collect()
}

#[test]
fn the_index_finds_the_rules_a_full_scan_finds_in_the_same_order() {
    let rules = rules_of(&PATTERNS);
    for url in URLS {
        assert_eq!(indexed(&rules, url), naive(&rules, url), "{url}");
    }
    let hits: usize = URLS.iter().map(|url| naive(&rules, url).len()).sum();
    assert!(hits > URLS.len(), "the corpus has to hit");
}

#[test]
fn a_prefix_only_makes_a_candidate_and_the_pattern_decides() {
    let rules = rules_of(&[r"^https://a\.test/x\d+$"]);
    assert!(rules.index_of_url_rewrites().always().is_empty());
    assert_eq!(
        rules.url_rewrite_candidates("https://a.test/xyz").count(),
        1
    );
    assert!(
        rules
            .rewrite_url("https://a.test/xyz", &crate::heads::Heads::new(None, None))
            .is_none()
    );
    assert!(
        rules
            .rewrite_url("https://a.test/x12", &crate::heads::Heads::new(None, None))
            .is_some()
    );
    assert_eq!(
        rules.url_rewrite_candidates("https://b.test/x12").count(),
        0
    );
}

#[test]
fn patterns_without_a_literal_to_look_up_are_always_tried() {
    let cases = [
        (r"^", "an empty prefix"),
        (r"^.+", "no literal at all"),
        (r"^\w+\d*$", "only classes"),
    ];
    for (pattern, why) in cases {
        let rules = rules_of(&[pattern]);
        assert_eq!(rules.index_of_url_rewrites().always(), [0], "{why}");
    }
}

#[test]
fn a_literal_anywhere_in_the_pattern_looks_it_up() {
    let cases = [
        (
            r"^\w+://tracker\.test/",
            "ws://tracker.test/x",
            "wss://other.test/",
        ),
        (
            r"/collect\?",
            "https://site.test/collect?v=1",
            "https://site.test/collect",
        ),
        (
            r"^https?:\/\/[\w-]+\.maps\.test\/ws\/",
            "https://m5.maps.test/ws/x",
            "https://www.example.com/ws/x",
        ),
    ];
    for (pattern, hit, miss) in cases {
        let rules = rules_of(&[pattern]);
        assert!(
            rules.index_of_url_rewrites().always().is_empty(),
            "{pattern}"
        );
        assert_eq!(
            rules.url_rewrite_candidates(hit).count(),
            1,
            "{pattern} {hit}"
        );
        assert_eq!(
            rules.url_rewrite_candidates(miss).count(),
            0,
            "{pattern} {miss}"
        );
    }
}

#[test]
fn a_case_insensitive_pattern_is_found_in_any_case() {
    for pattern in [
        r"(?i)^https://cdn\.ads\.test/",
        r"(?i)^https://www\.example\.org/promotions/summer-sale/banner",
    ] {
        let rules = rules_of(&[pattern]);
        for url in [
            "https://cdn.ads.test/a",
            "HTTPS://CDN.ADS.TEST/a",
            "hTtPs://cDn.AdS.tEsT/a",
            "https://WWW.EXAMPLE.ORG/PROMOTIONS/SUMMER-SALE/BANNER",
            "https://www.Example.org/promotions/Summer-Sale/banner",
        ] {
            assert_eq!(indexed(&rules, url), naive(&rules, url), "{pattern} {url}");
        }
    }
}

#[test]
fn only_case_insensitive_patterns_go_to_the_folded_automaton() {
    let patterns = [
        r"^https://API\.Mixed\.test/v1",
        r"(?i)^https://www\.example\.org/promotions/summer-sale/banner",
        r"(?i)^https://cdn\.ads\.test/",
        r"/collect\?",
        r"(?i)/ad",
        r"^https://(?i:Shop)\.test/cart",
        r"(?-i)^https://\(?inner\.test/",
        r"(?P<x>a)\.test/(?m)line",
    ];
    let rules = rules_of(&patterns);
    let index = rules.index_of_url_rewrites();
    assert_eq!(index.literal_owners(false), [0, 3, 7]);
    assert_eq!(index.literal_owners(true), [1, 2, 4, 5, 6]);
    for url in [
        "https://API.Mixed.test/v1",
        "https://api.mixed.test/v1",
        "HTTPS://WWW.EXAMPLE.ORG/PROMOTIONS/SUMMER-SALE/BANNER",
        "https://Cdn.Ads.Test/x",
        "https://x.test/collect?a=1",
        "https://x.test/COLLECT?a=1",
        "https://x.test/AD",
        "https://x.test/aD",
        "https://sHoP.test/cart",
        "https://shop.test/CART",
        "https://(inner.test/",
        "https://inner.test/",
        "a.test/line",
    ] {
        assert_eq!(indexed(&rules, url), naive(&rules, url), "{url}");
    }
}

#[test]
fn a_url_builds_only_the_patterns_it_may_match() {
    let patterns: Vec<String> = (0..1000)
        .map(|n| format!(r"^https?://ad{n}\.example\.com/banner"))
        .collect();
    let rules = rules_of(&patterns.iter().map(String::as_str).collect::<Vec<_>>());
    let built = |rules: &Rules| {
        rules
            .url_rewrites
            .iter()
            .filter(|rule| rule.pattern.is_built())
            .count()
    };
    let heads = crate::heads::Heads::new(None, None);
    for n in 0..200 {
        assert!(
            rules
                .rewrite_url(&format!("https://www.site{n}.test/page?q={n}"), &heads)
                .is_none()
        );
    }
    assert_eq!(built(&rules), 0);
    assert!(
        rules
            .rewrite_url("https://ad7.example.com/banner", &heads)
            .is_some()
    );
    assert_eq!(built(&rules), 1);
}

#[test]
fn relaxing_a_pattern_keeps_every_match() {
    let cases = [
        (r"^a(?>b|c)d", r"^a(?:b|c)d"),
        (r"^a(?!x|y\))b", r"^ab"),
        (r"^a(?<=a)b(?<!c)", r"^ab"),
        (r"^(\w)x\1", r"^(\w)x(?s:.*)"),
        (r"^(?<n>\w)\k<n>", r"^(?<n>\w)(?s:.*)"),
        (r"^[(?!]x", r"^[(?!]x"),
        (r"^a\(?!b", r"^a\(?!b"),
    ];
    for (source, relaxed) in cases {
        assert_eq!(super::relax(source), relaxed, "{source}");
    }
}

#[test]
fn unicode_case_folding_and_regex_set_match_linear_oracle() {
    let patterns = [
        // Unicode Kelvin sign (K U+212A) and long s (ſ U+017F) with scoped flags.
        r"(?i:kelvin)/Case",
        r"(?i)s",
        r"(?i)^https?://api\.mod-alpha\.example\.com/v1/feed",
        r"(?i)^https?://static\.example\.com/ads/splash",
        r"^https://a\.test/(foo|)",
        r"^https://a\.test/(foo|bar)/x",
        r"^https://a\.test/aa/aa",
        r"^https?://[^/]+/\d+/\w+$",
        r"(?i)^https?://[^/]+/[a-z]+\d+$",
        r"^\p{Greek}+$",
        r"^https?://(?=\w+\.a\.test/)[^/]+/v1$",
        r"^https?://(\w+)\.a\.test/\1$",
        r"^https?:\/\/res\.a\.test\/ad.\cnews\/",
        r"^https?://.+",
    ];
    let urls = [
        "https://x.test/\u{212A}ELVIN/Case",
        "https://x.test/\u{212A}elvin/case",
        "https://x.test/kelvin/Case",
        "https://x.test/kelvin/case",
        "https://x.test/\u{017F}",
        "https://x.test/S",
        "https://x.test/z",
        "HTTPS://API.MOD-ALPHA.EXAMPLE.COM/V1/FEED",
        "https://\u{017F}tatic.example.com/ad\u{017F}/\u{017F}pla\u{017F}h",
        "https://a.test/",
        "https://a.test/foo",
        "https://a.test/foo/x",
        "https://a.test/bar/x",
        "https://a.test/aa/aa",
        "https://any.example.org/123/abc",
        "https://any.example.org/AbC99",
        "https://any.example.org/nomatch!",
        "αβγ",
        "https://ok.a.test/v1",
        "https://dup.a.test/dup",
        "https://dup.a.test/other",
        "https://res.a.test/ad.\u{000E}ews/",
        "https://res.a.test/ad.news/",
        "http://other.example.net/plain",
        "",
    ];
    let rules = rules_of(&patterns);
    for url in urls {
        assert_eq!(indexed(&rules, url), naive(&rules, url), "{url}");
    }
    let idx = rules.index_of_url_rewrites();
    assert!(
        !idx.regex_set_owners().is_empty(),
        "pure no-literal patterns should be indexed by RegexSet"
    );
    let fancy_only = rules_of(&[r"^(\w+)\1$", r"^(?=\d)\w+$", r"^\d+$"]);
    let fidx = fancy_only.index_of_url_rewrites();
    assert_eq!(fidx.always_fancy(), &[0, 1]);
    assert_eq!(fidx.regex_set_owners(), &[2]);
    for url in ["abab", "ab", "1abc", "abc", "12345", ""] {
        assert_eq!(indexed(&fancy_only, url), naive(&fancy_only, url), "{url}");
    }
}

#[test]
fn non_http_scripts_are_excluded_from_http_indexes_and_hooks_take_first() {
    use crate::script::testkit::{host_with, sync_program};
    use crate::script::{Script, ScriptKind, ScriptResult, compile_script};
    let dir = tempfile::tempdir().unwrap();
    let host = host_with(
        dir.path(),
        vec![("a", sync_program(|_| Ok(ScriptResult::default())))],
    );
    let make = |line: &str| -> std::sync::Arc<Script> {
        let def = concord_config::mitm::parse_script(line).unwrap();
        std::sync::Arc::new(compile_script(&def, dir.path(), &host, &mut None).unwrap())
    };
    let mut rules = Rules::default();
    rules.scripts.push(make(
        r#"c1 = type=cron,cronexp="0 8 * * *",script-path=a.js"#,
    ));
    rules.scripts.push(make(
        r"e1 = type=event,event-name=network-changed,script-path=a.js",
    ));
    rules
        .scripts
        .push(make(r"dup = type=rule,script-path=a.js,argument=first"));
    rules
        .scripts
        .push(make(r"dup = type=rule,script-path=a.js,argument=second"));
    rules
        .scripts
        .push(make(r"g1 = type=generic,script-path=a.js"));
    rules.index();

    let scan = rules.scan_request("https://example.com/anything");
    assert!(scan.scripts.is_empty());
    let plan = rules.prepare_response("https://example.com/anything");
    assert!(plan.scripts.is_empty());
    let found = rules.script_by_name(ScriptKind::Rule, "dup").unwrap();
    assert_eq!(
        found.argument.as_ref().and_then(|v| v.as_str()),
        Some("first"),
        "duplicate hook names must pick the first definition"
    );
}
