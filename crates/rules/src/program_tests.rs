use concord_common::Network;
use indexmap::IndexMap;

use crate::geo::GeoFile;
use crate::geo::dat::testing::site;
use crate::geo::test_mmdb::{Value, build};
use crate::testkit::{Flow, Kit, defs, drive};
use crate::{Behavior, CompileError, Cond, Demands, RouteProgram, RuleDef, RuleSet};

const MERGES: [usize; 2] = [2, 1000];

fn accepted(kit: &Kit, program: &RouteProgram, flow: &Flow) -> Option<(usize, String)> {
    drive(program, &kit.geo, flow, true).accepted
}

fn pick(index: usize, target: &str) -> Option<(usize, String)> {
    Some((index, target.to_string()))
}

fn resolving(host: &'static str, ip: &str) -> Flow {
    Flow {
        resolves_to: Some(ip.parse().unwrap()),
        ..Flow::domain(host)
    }
}

fn udp(host: &'static str) -> Flow {
    Flow {
        network: Network::Udp,
        ..Flow::domain(host)
    }
}

fn fill(kit: &Kit, name: &str, behavior: Behavior, entries: &[&str]) {
    let handle = kit.sets.declare(name, behavior);
    let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
    handle.store(RuleSet::from_entries(behavior, &entries, &kit.env(8)).set);
}

fn compile_err(kit: &Kit, lines: &[&str], subs: &[(&str, &[&str])]) -> CompileError {
    let sub_rules = subs
        .iter()
        .map(|(name, lines)| (name.to_string(), defs(lines)))
        .collect();
    match RouteProgram::compile(&defs(lines), &sub_rules, &kit.env(8)) {
        Ok(_) => panic!("compiled"),
        Err(err) => err,
    }
}

#[test]
fn first_match_keeps_rule_order_across_runs_and_kinds() {
    let kit = Kit::new();
    let lines = [
        "DOMAIN-SUFFIX,a.com,P0",
        "DOMAIN,x.a.com,P1",
        "DOMAIN-KEYWORD,zzz,P2",
        "NETWORK,udp,P3",
        "DOMAIN-SUFFIX,b.com,P4",
        "DOMAIN-SUFFIX,a.com,P5",
        "DOMAIN-WILDCARD,*.c.com,P6",
        "MATCH,P7",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.a.com")),
            pick(0, "P0")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("zzz.b.com")),
            pick(2, "P2")
        );
        assert_eq!(accepted(&kit, &program, &udp("q.b.com")), pick(3, "P3"));
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("q.b.com")),
            pick(4, "P4")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("q.c.com")),
            pick(6, "P6")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("other.org")),
            pick(7, "P7")
        );
        let all = drive(&program, &kit.geo, &Flow::domain("x.a.com"), false);
        let order: Vec<usize> = all.candidates.iter().map(|c| c.0).collect();
        assert_eq!(order, [0, 1, 5, 7], "merge {merge}");
    }
}

#[test]
fn skip_continues_inside_a_merged_run() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "DOMAIN-SUFFIX,a.com,PASS",
            "DOMAIN-KEYWORD,a.c,PASS",
            "DOMAIN,www.a.com,PASS",
            "DOMAIN-SUFFIX,a.com,FINAL",
        ],
        2,
    );
    let trace = drive(&program, &kit.geo, &Flow::domain("www.a.com"), true);
    let order: Vec<usize> = trace.candidates.iter().map(|c| c.0).collect();
    assert_eq!(order, [0, 1, 2, 3]);
    assert_eq!(trace.accepted, pick(3, "FINAL"));
}

#[test]
fn the_destination_is_resolved_once_and_only_when_needed() {
    let kit = Kit::new();
    let lines = [
        "DOMAIN-SUFFIX,x.com,X",
        "IP-CIDR,10.0.0.0/8,TEN",
        "IP-CIDR,20.0.0.0/8,TWENTY",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        let flow = resolving("y.net", "20.1.1.1");
        let trace = drive(&program, &kit.geo, &flow, true);
        assert_eq!(trace.accepted, pick(2, "TWENTY"));
        assert_eq!(trace.ip_lookups, 1);

        let trace = drive(&program, &kit.geo, &Flow::domain("a.x.com"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "X"), 0));

        let trace = drive(&program, &kit.geo, &Flow::domain("unresolvable.net"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (None, 1));

        let trace = drive(&program, &kit.geo, &Flow::ip("10.9.9.9"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(1, "TEN"), 0));
    }
}

#[test]
fn no_resolve_never_asks_for_the_address() {
    let kit = Kit::new();
    for merge in MERGES {
        let program = kit.compile(&["IP-CIDR,10.0.0.0/8,TEN,no-resolve"], merge);
        let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (None, 0));
        let trace = drive(&program, &kit.geo, &Flow::ip("10.1.1.1"), true);
        assert_eq!(trace.accepted, pick(0, "TEN"));
        assert!(!program.demands().resolve_ip && program.demands().ip);
    }
}

#[test]
fn a_no_resolve_rule_after_a_resolving_one_sees_the_address() {
    let kit = Kit::new();
    for merge in MERGES {
        let program = kit.compile(
            &["IP-CIDR,20.0.0.0/8,A", "IP-CIDR,10.0.0.0/8,B,no-resolve"],
            merge,
        );
        let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(1, "B"), 1));
    }
}

#[test]
fn source_rules_use_the_client_address() {
    let kit = Kit::new();
    for merge in MERGES {
        let program = kit.compile(
            &[
                "SRC-IP-CIDR,192.168.1.0/24,LAN",
                "IP-CIDR,192.168.1.0/24,DST,src",
                "MATCH,X",
            ],
            merge,
        );
        let trace = drive(&program, &kit.geo, &Flow::domain("a.net"), false);
        assert_eq!(trace.ip_lookups, 0);
        assert_eq!(
            trace.candidates.iter().map(|c| c.0).collect::<Vec<_>>(),
            [0, 1, 2]
        );
    }
}

#[test]
fn processes_are_looked_up_on_demand() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "DOMAIN,a.com,A",
            "PROCESS-NAME,curl,CURL",
            "UID,1000-1010,USER",
            "MATCH,M",
        ],
        8,
    );
    let trace = drive(&program, &kit.geo, &Flow::domain("a.com"), true);
    assert_eq!((trace.accepted, trace.process_lookups), (pick(0, "A"), 0));

    let mut flow = Flow::domain("b.com");
    flow.process = Some(("curl", "/usr/bin/curl", 501));
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!(
        (trace.accepted, trace.process_lookups),
        (pick(1, "CURL"), 1)
    );

    flow.process = Some(("wget", "/usr/bin/wget", 1005));
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!(
        (trace.accepted, trace.process_lookups),
        (pick(2, "USER"), 1)
    );

    flow.process = Some(("wget", "/usr/bin/wget", 0));
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!(trace.accepted, pick(3, "M"));

    flow.process = None;
    let trace = drive(&program, &kit.geo, &flow, true);
    assert_eq!((trace.accepted, trace.process_lookups), (pick(3, "M"), 1));
    assert!(program.demands().process);
}

#[test]
fn process_matching_folds_case_and_supports_wildcards() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "PROCESS-NAME,Chrome.EXE,A",
            "PROCESS-PATH-WILDCARD,/opt/*/bin/tool,B",
            "PROCESS-NAME-REGEX,^fire,C",
        ],
        8,
    );
    let mut flow = Flow::domain("a.com");
    flow.process = Some(("chrome.exe", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(0, "A"));
    flow.process = Some(("t", "/OPT/app/bin/tool", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(1, "B"));
    flow.process = Some(("firefox", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(2, "C"));
}

#[test]
fn process_wildcards_lowercase_like_go() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "PROCESS-NAME-WILDCARD,\u{e9}t\u{e9}*,A",
            "PROCESS-NAME-WILDCARD,\u{3c3}*,B",
        ],
        8,
    );
    let mut flow = Flow::domain("a.com");
    flow.process = Some(("\u{c9}T\u{c9}.exe", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(0, "A"));
    flow.process = Some(("\u{3a3}\u{3a3}", "/x", 1));
    assert_eq!(accepted(&kit, &program, &flow), pick(1, "B"));
}

#[test]
fn sub_rule_lists_pass_or_fall_through() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[
        ("one", &["DOMAIN,x.a.com,PASS", "DOMAIN-KEYWORD,x,KEYWORD"]),
        (
            "two",
            &["DOMAIN,x.a.com,PASS-RULE", "DOMAIN-KEYWORD,x,KEYWORD"],
        ),
    ];
    for merge in MERGES {
        let program = kit.compile_with(
            &[
                "SUB-RULE,(DOMAIN-SUFFIX,a.com),one",
                "SUB-RULE,(NETWORK,tcp),two",
                "MATCH,Z",
            ],
            subs,
            merge,
        );
        let flow = Flow::domain("x.a.com");
        assert_eq!(accepted(&kit, &program, &flow), pick(1, "KEYWORD"));
        let all = drive(&program, &kit.geo, &flow, false);
        assert_eq!(
            all.candidates,
            [
                (0, "PASS".to_string()),
                (1, "PASS-RULE".to_string()),
                (1, "KEYWORD".to_string()),
                (2, "Z".to_string()),
            ]
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("next.org")),
            pick(1, "KEYWORD")
        );
        assert_eq!(accepted(&kit, &program, &udp("other.org")), pick(2, "Z"));
    }
}

#[test]
fn nested_sub_rules_report_the_outermost_rule() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[
        (
            "outer",
            &[
                "DOMAIN,skip.com,A",
                "SUB-RULE,(DOMAIN-SUFFIX,a.com),inner",
                "MATCH,OUTER",
            ],
        ),
        (
            "inner",
            &["DOMAIN,x.a.com,PASS-RULE", "DOMAIN-SUFFIX,a.com,INNER"],
        ),
    ];
    let program = kit.compile_with(&["SUB-RULE,(NETWORK,tcp),outer", "MATCH,Z"], subs, 8);
    let trace = drive(&program, &kit.geo, &Flow::domain("x.a.com"), false);
    assert_eq!(
        trace.candidates,
        [
            (0, "PASS-RULE".to_string()),
            (0, "INNER".to_string()),
            (1, "Z".to_string()),
        ]
    );
    assert_eq!(
        accepted(&kit, &program, &Flow::domain("b.org")),
        pick(0, "OUTER")
    );
    let info = program.rule_at(crate::RuleRef(0, 0));
    assert_eq!(info.type_name, "SubRules");
}

#[test]
fn nested_sub_rule_without_a_hit_lets_the_enclosing_list_go_on() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[
        (
            "outer",
            &["SUB-RULE,(DOMAIN-SUFFIX,a.com),inner", "MATCH,OUTER"],
        ),
        ("inner", &["DOMAIN,x.a.com,PASS-RULE"]),
    ];
    let program = kit.compile_with(&["SUB-RULE,(NETWORK,tcp),outer", "MATCH,Z"], subs, 8);
    let trace = drive(&program, &kit.geo, &Flow::domain("x.a.com"), false);
    assert_eq!(
        trace.candidates,
        [
            (0, "PASS-RULE".to_string()),
            (0, "OUTER".to_string()),
            (1, "Z".to_string()),
        ]
    );
}

#[test]
fn a_top_level_sub_rule_aimed_at_a_proxy_never_matches() {
    let kit = Kit::new();
    let subs: &[(&str, &[&str])] = &[("one", &["MATCH,ONE"])];
    for merge in MERGES {
        let program = kit.compile_with(
            &[
                "SUB-RULE,(NETWORK,tcp),DIRECT",
                "SUB-RULE,(NETWORK,tcp),one",
                "MATCH,Z",
            ],
            subs,
            merge,
        );
        let flow = Flow::domain("x.a.com");
        assert_eq!(accepted(&kit, &program, &flow), pick(1, "ONE"));
        let trace = drive(&program, &kit.geo, &flow, false);
        assert_eq!(
            trace.candidates,
            [(1, "ONE".to_string()), (2, "Z".to_string())]
        );
    }
    let nested = IndexMap::from([("one".to_string(), defs(&["SUB-RULE,(NETWORK,tcp),DIRECT"]))]);
    let refused = RouteProgram::compile(&defs(&["MATCH,Z"]), &nested, &kit.env(8));
    assert!(matches!(refused, Err(CompileError::UnknownSubRule { .. })));
}

#[test]
fn logic_rules_combine_conditions() {
    let kit = Kit::new();
    let lines = [
        "AND,((DOMAIN-SUFFIX,a.com),(NETWORK,udp)),UDP-A",
        "OR,((DOMAIN,b.com),(DST-PORT,8443)),B-OR-PORT",
        "NOT,((DOMAIN-SUFFIX,c.com)),NOT-C",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        assert_eq!(accepted(&kit, &program, &udp("x.a.com")), pick(0, "UDP-A"));
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.a.com")),
            pick(2, "NOT-C")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("b.com")),
            pick(1, "B-OR-PORT")
        );
        let mut flow = Flow::domain("z.c.com");
        assert_eq!(accepted(&kit, &program, &flow), None);
        flow.dst_port = 8443;
        assert_eq!(accepted(&kit, &program, &flow), pick(1, "B-OR-PORT"));
    }
}

#[test]
fn logic_children_honour_their_own_flags() {
    let kit = Kit::new();
    let quiet = kit.compile(
        &["AND,((IP-CIDR,10.0.0.0/8,no-resolve),(DOMAIN,a.com)),Q"],
        8,
    );
    let trace = drive(&quiet, &kit.geo, &resolving("a.com", "10.1.1.1"), true);
    assert_eq!((trace.accepted, trace.ip_lookups), (None, 0));
    assert!(!quiet.demands().resolve_ip);

    let loud = kit.compile(&["AND,((IP-CIDR,10.0.0.0/8),(DOMAIN,a.com)),L"], 8);
    let trace = drive(&loud, &kit.geo, &resolving("a.com", "10.1.1.1"), true);
    assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "L"), 1));
    assert!(loud.demands().resolve_ip);

    let source = kit.compile(&["AND,((IP-CIDR,192.168.1.0/24,src),(DOMAIN,a.com)),S"], 8);
    let trace = drive(&source, &kit.geo, &Flow::domain("a.com"), true);
    assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "S"), 0));
}

#[test]
fn rule_sets_follow_updates_without_recompiling() {
    let kit = Kit::new();
    fill(&kit, "dom", Behavior::Domain, &["+.a.com"]);
    fill(&kit, "ips", Behavior::IpCidr, &["10.0.0.0/8"]);
    fill(
        &kit,
        "cls",
        Behavior::Classical,
        &["DOMAIN-KEYWORD,kw", "IP-CIDR,30.0.0.0/8,no-resolve"],
    );
    for merge in MERGES {
        let program = kit.compile(
            &["RULE-SET,dom,D", "RULE-SET,ips,I", "RULE-SET,cls,C"],
            merge,
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.a.com")),
            pick(0, "D")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("kw.org")),
            pick(2, "C")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::ip("10.2.2.2")),
            pick(1, "I")
        );
        assert_eq!(
            accepted(&kit, &program, &Flow::ip("30.2.2.2")),
            pick(2, "C")
        );
        let trace = drive(&program, &kit.geo, &resolving("q.org", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(1, "I"), 1));

        fill(&kit, "dom", Behavior::Domain, &["+.b.com"]);
        assert_eq!(accepted(&kit, &program, &Flow::domain("x.a.com")), None);
        assert_eq!(
            accepted(&kit, &program, &Flow::domain("x.b.com")),
            pick(0, "D")
        );
        fill(&kit, "dom", Behavior::Domain, &["+.a.com"]);
    }
}

#[test]
fn rule_set_modifiers() {
    let kit = Kit::new();
    fill(
        &kit,
        "ips",
        Behavior::IpCidr,
        &["10.0.0.0/8", "192.168.1.0/24"],
    );
    let program = kit.compile(
        &["RULE-SET,ips,SRC,src", "RULE-SET,ips,QUIET,no-resolve"],
        8,
    );
    let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), false);
    assert_eq!(trace.ip_lookups, 0);
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|c| c.1.as_str())
            .collect::<Vec<_>>(),
        ["SRC"]
    );
    let trace = drive(&program, &kit.geo, &Flow::ip("10.1.1.1"), false);
    assert_eq!(
        trace
            .candidates
            .iter()
            .map(|c| c.1.as_str())
            .collect::<Vec<_>>(),
        ["SRC", "QUIET"]
    );
}

#[test]
fn a_no_resolve_check_before_the_lookup_stays_unanswered() {
    let kit = Kit::new();
    fill(
        &kit,
        "cls",
        Behavior::Classical,
        &["IP-CIDR,10.0.0.0/8,no-resolve", "IP-CIDR,99.0.0.0/8"],
    );
    for merge in MERGES {
        let program = kit.compile(&["RULE-SET,cls,C"], merge);
        let trace = drive(&program, &kit.geo, &resolving("a.net", "10.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (None, 1));
        let trace = drive(&program, &kit.geo, &resolving("a.net", "99.1.1.1"), true);
        assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "C"), 1));
        let trace = drive(&program, &kit.geo, &Flow::ip("10.1.1.1"), true);
        assert_eq!(trace.accepted, pick(0, "C"));
    }
}

#[test]
fn geoip_lan_needs_no_database() {
    let kit = Kit::new();
    let program = kit.compile(&["GEOIP,LAN,L", "MATCH,W"], 8);
    let trace = drive(
        &program,
        &kit.geo,
        &resolving("home.test", "192.168.0.9"),
        true,
    );
    assert_eq!((trace.accepted, trace.ip_lookups), (pick(0, "L"), 1));
    assert_eq!(
        accepted(&kit, &program, &resolving("far.test", "8.8.8.8")),
        pick(1, "W")
    );
}

#[test]
fn geoip_reads_the_mmdb_or_the_dat() {
    let kit = Kit::new();
    let line = ["GEOIP,CN,CN", "MATCH,W"];
    let missing = compile_err(&kit, &line, &[]);
    assert_eq!(missing.missing_geo_file(), Some(GeoFile::Mmdb));
    assert!(matches!(missing, CompileError::Geo { .. }));

    let country = Value::map(vec![(
        "country",
        Value::map(vec![("iso_code", Value::s("CN"))]),
    )]);
    std::fs::write(
        kit.dir.path().join("geoip.metadb"),
        build("GeoLite2-Country", &[("1.0.0.0", 8, country)]),
    )
    .unwrap();
    let program = kit.compile(&line, 8);
    assert_eq!(
        accepted(&kit, &program, &Flow::ip("1.2.3.4")),
        pick(0, "CN")
    );
    assert_eq!(accepted(&kit, &program, &Flow::ip("9.2.3.4")), pick(1, "W"));
}

fn write_geoip(kit: &Kit, entries: &[(&str, u8, &str)]) {
    let rows: Vec<_> = entries
        .iter()
        .map(|(net, bits, code)| {
            let country = Value::map(vec![(
                "country",
                Value::map(vec![("iso_code", Value::s(code))]),
            )]);
            (*net, *bits, country)
        })
        .collect();
    std::fs::write(
        kit.dir.path().join("geoip.metadb"),
        build("GeoLite2-Country", &rows),
    )
    .unwrap();
}

fn write_asn(kit: &Kit) {
    let record = Value::map(vec![
        ("autonomous_system_number", Value::U32(13335)),
        (
            "autonomous_system_organization",
            Value::s("Cloudflare, Inc."),
        ),
    ]);
    std::fs::write(
        kit.dir.path().join("ASN.mmdb"),
        build("GeoLite2-ASN", &[("1.1.1.0", 24, record)]),
    )
    .unwrap();
}

fn observed(kit: &Kit, lines: &[&str], flow: &Flow) -> crate::Observed {
    drive(&kit.compile(lines, 8), &kit.geo, flow, false).observed
}

#[test]
fn geoip_rules_leave_the_codes_they_looked_up() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN"), ("192.168.0.0", 16, "XX")]);
    let seen = observed(
        &kit,
        &["GEOIP,US,A", "SRC-GEOIP,XX,B", "GEOIP,LAN,C", "MATCH,W"],
        &Flow::ip("1.2.3.4"),
    );
    assert_eq!(seen.dst_geoip, Some(vec!["cn".to_string()]));
    assert_eq!(seen.src_geoip, Some(vec!["xx".to_string()]));
    assert_eq!((seen.src_asn.as_str(), seen.dst_asn.as_str()), ("", ""));

    let seen = observed(&kit, &["GEOIP,US,A", "MATCH,W"], &Flow::ip("9.9.9.9"));
    assert_eq!(seen.dst_geoip, Some(Vec::new()));
    assert_eq!(seen.src_geoip, None);
}

#[test]
fn lan_geoip_and_unresolved_destinations_leave_nothing() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN")]);
    let seen = observed(&kit, &["GEOIP,LAN,A", "MATCH,W"], &Flow::ip("1.2.3.4"));
    assert_eq!(seen, crate::Observed::default());
    let seen = observed(
        &kit,
        &["GEOIP,CN,A,no-resolve", "MATCH,W"],
        &Flow::domain("a.test"),
    );
    assert_eq!(seen, crate::Observed::default());
}

#[test]
fn a_rule_set_with_a_source_swaps_where_the_codes_land() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN"), ("192.168.0.0", 16, "XX")]);
    fill(&kit, "inner", Behavior::Classical, &["GEOIP,CN,no-resolve"]);
    let seen = observed(
        &kit,
        &["SRC-IP-CIDR,192.168.0.0/16,A", "MATCH,W"],
        &Flow::ip("1.2.3.4"),
    );
    assert_eq!(seen, crate::Observed::default());
    let seen = observed(
        &kit,
        &["RULE-SET,inner,A,src", "MATCH,W"],
        &Flow::ip("1.2.3.4"),
    );
    assert_eq!(seen.src_geoip, Some(vec!["xx".to_string()]));
    assert_eq!(seen.dst_geoip, None);
}

#[test]
fn a_negated_geoip_matches_every_other_country() {
    let kit = Kit::new();
    write_geoip(&kit, &[("1.0.0.0", 8, "CN"), ("8.0.0.0", 8, "US")]);
    let program = kit.compile(&["GEOIP,!cn,A", "MATCH,W"], 8);
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.2.3.4")), pick(1, "W"));
    assert_eq!(accepted(&kit, &program, &Flow::ip("8.2.3.4")), pick(0, "A"));
    assert_eq!(accepted(&kit, &program, &Flow::ip("9.2.3.4")), pick(0, "A"));
}

#[test]
fn asn_rules_leave_the_number_and_the_organisation() {
    let kit = Kit::new();
    write_asn(&kit);
    let lines = ["IP-ASN,1,A", "MATCH,W"];
    let seen = observed(&kit, &lines, &Flow::ip("1.1.1.1"));
    assert_eq!(seen.dst_asn, "13335 Cloudflare, Inc.");
    let program = kit.compile(&["IP-ASN,13335,A", "MATCH,W"], 8);
    assert_eq!(
        drive(&program, &kit.geo, &Flow::ip("1.1.1.1"), true).accepted,
        pick(0, "A")
    );
    let seen = observed(&kit, &["SRC-IP-ASN,1,A", "MATCH,W"], &Flow::ip("1.1.1.1"));
    assert_eq!(seen.src_asn, "0 ");
    assert_eq!(seen.dst_asn, "");
}

#[test]
fn asn_rules_wait_for_a_missing_database_without_a_recompile() {
    let kit = Kit::new();
    let program = kit.compile(&["IP-ASN,13335,A", "MATCH,W"], 8);
    assert_eq!(program.deferred_geo(), [GeoFile::Asn]);
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.1.1.1")), pick(1, "W"));
    write_asn(&kit);
    kit.geo.reload(GeoFile::Asn).unwrap();
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.1.1.1")), pick(0, "A"));
    assert!(
        kit.compile(&["IP-ASN,13335,A"], 8)
            .deferred_geo()
            .is_empty()
    );
}

#[test]
fn logic_rules_do_not_turn_a_missing_asn_database_into_a_match() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "NOT,((IP-ASN,13335)),N",
            "NOT,((OR,((IP-ASN,13335),(DOMAIN,never.test)))),O",
            "NOT,((AND,((IP-ASN,13335),(DOMAIN,never.test)))),A",
            "MATCH,W",
        ],
        8,
    );
    assert_eq!(accepted(&kit, &program, &Flow::ip("8.8.8.8")), pick(2, "A"));
    write_asn(&kit);
    kit.geo.reload(GeoFile::Asn).unwrap();
    assert_eq!(accepted(&kit, &program, &Flow::ip("8.8.8.8")), pick(0, "N"));
    assert_eq!(accepted(&kit, &program, &Flow::ip("1.1.1.1")), pick(2, "A"));
}

#[test]
fn geosite_reads_the_dat() {
    let kit = Kit::new();
    let line = ["GEOSITE,cn,CN", "MATCH,W"];
    assert_eq!(
        compile_err(&kit, &line, &[]).missing_geo_file(),
        Some(GeoFile::GeoSite)
    );
    std::fs::write(
        kit.dir.path().join("GeoSite.dat"),
        site("cn", &[(2, "baidu.com", &[])]),
    )
    .unwrap();
    let program = kit.compile(&line, 8);
    assert_eq!(
        accepted(&kit, &program, &Flow::domain("www.baidu.com")),
        pick(0, "CN")
    );
    assert_eq!(
        accepted(&kit, &program, &Flow::domain("google.com")),
        pick(1, "W")
    );
    assert!(program.demands().domain && !program.demands().ip);
}

#[test]
fn compile_errors_read_like_mihomo() {
    let kit = Kit::new();
    let err = compile_err(&kit, &["RULE-SET,nope,X"], &[]);
    assert!(matches!(err, CompileError::UnknownRuleSet { .. }), "{err}");
    assert_eq!(
        err.to_string(),
        "rules[0] [RULE-SET,nope,X] error: rule set [nope] not found"
    );

    let err = compile_err(
        &kit,
        &["SUB-RULE,(DOMAIN,a.com),a"],
        &[
            ("a", &["SUB-RULE,(DOMAIN,a.com),b"]),
            ("b", &["SUB-RULE,(DOMAIN,a.com),a"]),
        ],
    );
    assert!(matches!(err, CompileError::SubRuleCycle(_)), "{err}");

    let bad = RuleDef {
        cond: Cond::DomainRegex("(".into()),
        target: "X".into(),
        no_resolve: false,
        src: false,
        extended: false,
        text: "DOMAIN-REGEX,(,X".into(),
    };
    let err = RouteProgram::compile(&[bad], &Default::default(), &kit.env(8))
        .err()
        .unwrap();
    assert!(matches!(err, CompileError::Invalid { .. }), "{err}");

    let mut env = kit.env(8);
    env.known_target = Some(Box::new(|name| name == "DIRECT"));
    let rules = defs(&["DOMAIN,a.com,DIRECT", "DOMAIN,b.com,GHOST"]);
    let err = RouteProgram::compile(&rules, &Default::default(), &env)
        .err()
        .unwrap();
    assert!(
        matches!(err, CompileError::UnknownTarget { index: 1, .. }),
        "{err}"
    );
    let sub = defs(&["SUB-RULE,(DOMAIN,a.com),missing"]);
    let err = RouteProgram::compile(&sub, &Default::default(), &env)
        .err()
        .unwrap();
    assert!(matches!(err, CompileError::UnknownSubRule { .. }), "{err}");
}

#[test]
fn demands_and_rule_info() {
    let kit = Kit::new();
    let program = kit.compile(&["DOMAIN-SUFFIX,a.com,A", "NETWORK,udp,B"], 8);
    assert_eq!(
        program.demands(),
        Demands {
            domain: true,
            ..Demands::default()
        }
    );
    let program = kit.compile(
        &[
            "IP-CIDR,10.0.0.0/8,A",
            "PROCESS-NAME,x,B",
            "GEOIP,LAN,C,no-resolve",
        ],
        8,
    );
    assert_eq!(
        program.demands(),
        Demands {
            domain: false,
            ip: true,
            resolve_ip: true,
            process: true,
            http: false,
        }
    );
    assert_eq!(program.len(), 3);
    let info = program.rule_at(crate::RuleRef(0, 0));
    assert_eq!((info.type_name, info.payload), ("IPCIDR", "10.0.0.0/8"));
    let info = program.rule_at(crate::RuleRef(1, 0));
    assert_eq!((info.type_name, info.payload), ("ProcessName", "x"));
    assert!(program.memory_estimate() > 0);

    fill(&kit, "ips", Behavior::IpCidr, &["10.0.0.0/8"]);
    let program = kit.compile(&["RULE-SET,ips,A"], 8);
    assert!(program.demands().resolve_ip);
    let program = kit.compile(&["RULE-SET,ips,A,no-resolve"], 8);
    assert!(program.demands().ip && !program.demands().resolve_ip);
}

#[test]
fn inbound_conditions() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "IN-TYPE,SOCKS,S",
            "IN-NAME,special,N",
            "IN-USER,alice,U",
            "IN-PORT,9000-9100,P",
            "SRC-PORT,50000,SP",
        ],
        8,
    );
    let mut flow = Flow::domain("a.com");
    assert_eq!(accepted(&kit, &program, &flow), pick(4, "SP"));
    flow.kind = concord_common::InboundKind::Socks5;
    assert_eq!(accepted(&kit, &program, &flow), pick(0, "S"));
    flow.kind = concord_common::InboundKind::Http;
    flow.inbound_name = "special";
    assert_eq!(accepted(&kit, &program, &flow), pick(1, "N"));
    flow.inbound_name = "in";
    flow.user = Some("alice");
    assert_eq!(accepted(&kit, &program, &flow), pick(2, "U"));
    flow.user = None;
    flow.in_port = 9050;
    assert_eq!(accepted(&kit, &program, &flow), pick(3, "P"));
}

#[test]
fn in_type_matches_every_inbound_kind_by_its_rule_name() {
    use concord_common::InboundKind;
    let kit = Kit::new();
    for kind in InboundKind::ALL {
        let rule = format!("IN-TYPE,{},HIT", kind.rule_name().to_lowercase());
        let program = kit.compile(&[rule.as_str(), "MATCH,MISS"], 8);
        let mut flow = Flow::domain("a.com");
        for other in InboundKind::ALL {
            flow.kind = other;
            let want = if other == kind {
                pick(0, "HIT")
            } else {
                pick(1, "MISS")
            };
            assert_eq!(
                accepted(&kit, &program, &flow),
                want,
                "{kind:?} against {other:?}"
            );
        }
    }
}

#[test]
fn rematch_restarts_a_named_list_and_keeps_its_rule_identity() {
    use crate::{MatchCtx, Step};
    use concord_common::RouteState;
    let kit = Kit::new();
    let program = kit.compile_with(
        &["REMATCH-NAME,Next,MAIN", "MATCH,FALLBACK"],
        &[
            ("inner", &["REMATCH-NAME,Next/Other,SUB", "MATCH,MISS"]),
            ("outer", &["SUB-RULE,(NETWORK,tcp),inner"]),
        ],
        8,
    );
    let meta = Flow::domain("example.com").meta();
    let mut state = RouteState::seed(&meta.dst);
    let ctx = MatchCtx::new(&kit.geo);
    let mut run = program.start();
    assert!(matches!(
        run.step(&meta, &state, &ctx),
        Step::Candidate {
            target: "FALLBACK",
            ..
        }
    ));
    state.rematch_name = Some("next".into());
    run.restart(Some("inner"));
    assert!(matches!(
        run.step(&meta, &state, &ctx),
        Step::Candidate { target: "MISS", .. }
    ));
    state.rematch_name = Some("Next".into());
    run.restart(Some("inner"));
    let Step::Candidate { target, rule } = run.step(&meta, &state, &ctx) else {
        panic!("no sub-rule candidate")
    };
    assert_eq!(target, "SUB");
    assert_eq!(program.rule_at(rule).type_name, "RematchName");
    assert_eq!(program.rule_at(rule).payload, "Next/Other");
    run.restart(Some("outer"));
    let Step::Candidate { target, rule } = run.step(&meta, &state, &ctx) else {
        panic!("no nested candidate")
    };
    assert_eq!(target, "SUB");
    assert_eq!(program.rule_at(rule).type_name, "SubRules");
    for name in [None, Some(""), Some("unknown")] {
        run.restart(name);
        let Step::Candidate { target, rule } = run.step(&meta, &state, &ctx) else {
            panic!("no main candidate")
        };
        assert_eq!(target, "MAIN");
        assert_eq!(program.rule_at(rule).payload, "Next");
    }
}

#[test]
fn a_rule_has_a_main_position_only_when_matching_started_in_the_main_list() {
    use crate::{MatchCtx, Step};
    use concord_common::RouteState;
    let kit = Kit::new();
    let program = kit.compile_with(
        &[
            "DOMAIN,skip.com,A",
            "SUB-RULE,(NETWORK,tcp),outer",
            "MATCH,Z",
        ],
        &[("outer", &["DOMAIN-SUFFIX,a.com,OUTER"])],
        8,
    );
    let ctx = MatchCtx::new(&kit.geo);
    let first = |host: &'static str, list: Option<&str>| {
        let meta = Flow::domain(host).meta();
        let state = RouteState::seed(&meta.dst);
        let mut run = program.start();
        run.restart(list);
        match run.step(&meta, &state, &ctx) {
            Step::Candidate { target, rule } => (target.to_string(), rule.main_index()),
            step => panic!("no candidate: {step:?}"),
        }
    };
    assert_eq!(first("x.a.com", None), ("OUTER".to_string(), Some(1)));
    assert_eq!(first("b.org", None), ("Z".to_string(), Some(2)));
    assert_eq!(first("x.a.com", Some("outer")), ("OUTER".to_string(), None));
}

fn request(host: &'static str, url: &'static str, agent: Option<&'static str>) -> Flow {
    Flow {
        http: Some((url, agent)),
        ..Flow::domain(host)
    }
}

#[test]
fn http_rules_wait_for_the_request_and_match_it_in_list_order() {
    let kit = Kit::new();
    let lines = [
        r"URL-REGEX,^https://a\.test/ok,DIRECT",
        "DOMAIN,a.test,REJECT",
        "USER-AGENT,Foo*,NODE",
        "MATCH,PROXY",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        let connection = drive(&program, &kit.geo, &Flow::domain("a.test"), true);
        assert_eq!(connection.accepted, pick(1, "REJECT"));
        assert!(connection.http_pending);
        let allowed = request("a.test", "https://a.test/ok?x=1", None);
        assert_eq!(accepted(&kit, &program, &allowed), pick(0, "DIRECT"));
        let other = request("a.test", "https://a.test/ad", Some("Foo/1"));
        assert_eq!(accepted(&kit, &program, &other), pick(1, "REJECT"));
        let agent = request("b.test", "https://b.test/", Some("Foo/1"));
        assert_eq!(accepted(&kit, &program, &agent), pick(2, "NODE"));
        let no_agent = request("b.test", "https://b.test/", None);
        assert_eq!(accepted(&kit, &program, &no_agent), pick(3, "PROXY"));
    }
}

#[test]
fn a_rule_decided_without_the_request_is_not_pending() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "AND,((DOMAIN,x.test),(URL-REGEX,/ad)),REJECT",
            "DOMAIN-SUFFIX,test,PROXY",
        ],
        8,
    );
    let other = drive(&program, &kit.geo, &Flow::domain("y.test"), true);
    assert_eq!(other.accepted, pick(1, "PROXY"));
    assert!(!other.http_pending);
    let listed = drive(&program, &kit.geo, &Flow::domain("x.test"), true);
    assert_eq!(listed.accepted, pick(1, "PROXY"));
    assert!(listed.http_pending);
    let program = kit.compile(&["DOMAIN,a.test,DIRECT", "URL-REGEX,/ad,REJECT"], 8);
    let decided = drive(&program, &kit.geo, &Flow::domain("a.test"), true);
    assert_eq!(decided.accepted, pick(0, "DIRECT"));
    assert!(!decided.http_pending);
}

#[test]
fn logic_over_an_unread_request_stays_undecided() {
    let kit = Kit::new();
    let program = kit.compile(
        &[
            "NOT,((URL-REGEX,/keep)),REJECT",
            "OR,((DOMAIN,a.test),(USER-AGENT,Bot*)),A",
            r#"AND,((URL-REGEX,"^http:\/\/(a|b)\.test\/d\?"),(USER-AGENT,"Ali*")),B"#,
            "MATCH,PROXY",
        ],
        8,
    );
    let unread = drive(&program, &kit.geo, &Flow::domain("b.test"), true);
    assert_eq!(unread.accepted, pick(3, "PROXY"));
    assert!(unread.http_pending);
    assert_eq!(
        accepted(&kit, &program, &Flow::domain("a.test")),
        pick(1, "A")
    );
    let kept = request("b.test", "http://b.test/keep", Some("Ali/2"));
    assert_eq!(accepted(&kit, &program, &kept), pick(3, "PROXY"));
    let dropped = request("b.test", "http://b.test/x", None);
    assert_eq!(accepted(&kit, &program, &dropped), pick(0, "REJECT"));
    let both = request("b.test", "http://b.test/d?dn=x/keep", Some("Ali/2"));
    assert_eq!(accepted(&kit, &program, &both), pick(2, "B"));
}

#[test]
fn http_rules_in_a_classical_set_wait_for_the_request() {
    let kit = Kit::new();
    fill(
        &kit,
        "http",
        Behavior::Classical,
        &[r#"URL-REGEX,"^https://a\.test/(x|y),z""#, "USER-AGENT,Bot*"],
    );
    let program = kit.compile(&["RULE-SET,http,REJECT", "MATCH,PROXY"], 8);
    assert!(program.demands().http);
    let unread = drive(&program, &kit.geo, &Flow::domain("a.test"), true);
    assert_eq!(unread.accepted, pick(1, "PROXY"));
    assert!(unread.http_pending);
    let hit = request("a.test", "https://a.test/y,z", None);
    assert_eq!(accepted(&kit, &program, &hit), pick(0, "REJECT"));
    let bot = request("a.test", "https://a.test/", Some("Bot"));
    assert_eq!(accepted(&kit, &program, &bot), pick(0, "REJECT"));
}

#[test]
fn user_agent_reads_the_proxy_connect_while_no_request_is_read() {
    let kit = Kit::new();
    let lines = [
        "USER-AGENT,Foo*,NODE",
        "URL-REGEX,/ad,REJECT",
        "MATCH,PROXY",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        let connect = |agent| Flow {
            kind: concord_common::InboundKind::Https,
            connect_agent: Some(agent),
            ..Flow::domain("a.test")
        };
        let matched = drive(&program, &kit.geo, &connect("Foo/1"), true);
        assert_eq!(matched.accepted, pick(0, "NODE"));
        assert!(!matched.http_pending);
        let other = drive(&program, &kit.geo, &connect("Bar/1"), true);
        assert_eq!(other.accepted, pick(2, "PROXY"));
        assert!(
            other.http_pending,
            "the URL-REGEX still waits for the request"
        );
        let read = Flow {
            http: Some(("https://a.test/", Some("Bar/2"))),
            ..connect("Foo/1")
        };
        assert_eq!(
            accepted(&kit, &program, &read),
            pick(2, "PROXY"),
            "a request read speaks for itself"
        );
    }
}

#[test]
fn extended_matching_also_tries_the_dialed_name_and_the_host_header() {
    let kit = Kit::new();
    let lines = [
        "DOMAIN-SUFFIX,ads.test,REJECT,extended-matching",
        "DOMAIN,track.test,REJECT,extended-matching",
        "DOMAIN-SUFFIX,plain.test,REJECT",
        "MATCH,DIRECT",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        let sniffed_over = |dialed, sniffed| Flow {
            sniffed: Some(sniffed),
            ..Flow::domain(dialed)
        };
        let fronted = |url| Flow {
            http: Some((url, None)),
            ..Flow::ip("203.0.113.9")
        };
        assert_eq!(
            accepted(&kit, &program, &sniffed_over("x.ads.test", "cdn.test")),
            pick(0, "REJECT"),
            "merge {merge}"
        );
        assert_eq!(
            accepted(&kit, &program, &fronted("https://track.test/p")),
            pick(1, "REJECT"),
            "merge {merge}"
        );
        assert_eq!(
            accepted(&kit, &program, &sniffed_over("x.plain.test", "cdn.test")),
            pick(3, "DIRECT"),
            "merge {merge}: a rule without the flag sees the sniffed name only"
        );
    }
}

#[test]
fn a_script_rule_asks_once_per_run_and_resolves_first_when_told() {
    let kit = Kit::new();
    let lines = [
        "SCRIPT,ads,REJECT",
        "AND,((DOMAIN,a.test),(SCRIPT,ads)),DIRECT",
        "SCRIPT,geo,PROXY,requires-resolve",
        "MATCH,DIRECT",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        let flow = |scripts| Flow {
            scripts,
            resolves_to: Some("203.0.113.9".parse().unwrap()),
            ..Flow::domain("a.test")
        };
        let trace = drive(&program, &kit.geo, &flow(&["ads"]), true);
        assert_eq!(trace.accepted, pick(0, "REJECT"), "merge {merge}");
        assert_eq!((trace.scripts.len(), trace.ip_lookups), (1, 0));

        let trace = drive(&program, &kit.geo, &flow(&["geo"]), true);
        assert_eq!(trace.accepted, pick(2, "PROXY"), "merge {merge}");
        assert_eq!(
            trace.scripts,
            ["ads", "geo"],
            "ads is asked once for two rules"
        );
        assert_eq!(trace.ip_lookups, 1);

        let trace = drive(&program, &kit.geo, &flow(&[]), true);
        assert_eq!(trace.accepted, pick(3, "DIRECT"), "merge {merge}");
    }
}

#[test]
fn a_rule_set_leaves_out_its_script_rules() {
    let kit = Kit::new();
    let entries: Vec<String> = [
        "SCRIPT,ads",
        "AND,((SCRIPT,ads),(DOMAIN,a.test))",
        "DOMAIN,b.test",
    ]
    .iter()
    .map(|entry| entry.to_string())
    .collect();
    let built = RuleSet::from_entries(Behavior::Classical, &entries, &kit.env(8));
    assert_eq!(built.warnings.len(), 2, "{:?}", built.warnings);
    assert!(
        built
            .warnings
            .iter()
            .all(|warning| warning.contains("SCRIPT"))
    );
}

fn classical(kit: &Kit, entries: &[&str]) -> RuleSet {
    let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
    RuleSet::from_entries(Behavior::Classical, &entries, &kit.env(8)).set
}

#[test]
fn whether_a_program_reads_http_follows_its_classical_sets_as_they_change() {
    let kit = Kit::new();
    let first = kit.sets.declare("first", Behavior::Classical);
    let second = kit.sets.declare("second", Behavior::Classical);
    let staged = kit.sets.declare("staged", Behavior::Classical);
    fill(&kit, "domains", Behavior::Domain, &["a.test"]);
    fill(&kit, "ips", Behavior::IpCidr, &["10.0.0.0/8"]);
    let program = kit.compile(
        &[
            "RULE-SET,first,A",
            "RULE-SET,first,B,src",
            "RULE-SET,second,C,no-resolve",
            "RULE-SET,domains,D",
            "RULE-SET,ips,E",
            "MATCH,F",
        ],
        8,
    );
    let other = kit.compile(&["RULE-SET,first,X", "MATCH,Y"], 8);
    let check = |want: bool| {
        for program in [&program, &other] {
            assert_eq!(program.reads_http(), program.demands().http);
        }
        assert_eq!(program.reads_http(), want);
    };
    check(false);

    assert!(first.store(classical(&kit, &[r"URL-REGEX,^https://a\.test/"])));
    check(true);
    assert!(other.reads_http());
    assert!(second.store(classical(&kit, &["USER-AGENT,Bot*"])));
    check(true);
    assert!(first.store(classical(&kit, &["DOMAIN,a.test"])));
    check(true);
    assert!(!other.reads_http());
    assert!(second.store(classical(&kit, &[])));
    check(false);

    assert!(staged.store(classical(&kit, &[r"URL-REGEX,/ad"])));
    assert!(first.take_from(&staged));
    check(true);
    assert!(staged.store(classical(&kit, &[])));
    assert!(first.take_from(&staged));
    check(false);

    assert!(!first.store(RuleSet::empty(Behavior::Domain)));
    assert!(!first.take_from(&kit.sets.declare("domains", Behavior::Domain)));
    check(false);
}

#[test]
fn a_program_with_its_own_http_rule_reads_http_whatever_its_sets_hold() {
    let kit = Kit::new();
    fill(&kit, "empty", Behavior::Classical, &[]);
    let program = kit.compile(&["RULE-SET,empty,A", "URL-REGEX,/ad,B"], 8);
    assert!(program.reads_http());
    assert_eq!(program.reads_http(), program.demands().http);
}

fn url_runs(program: &RouteProgram) -> Vec<usize> {
    program
        .progs
        .iter()
        .map(|prog| prog.url_runs.len())
        .collect()
}

#[test]
fn a_url_run_offers_each_matching_rule_in_list_order() {
    let kit = Kit::new();
    let lines = [
        r"URL-REGEX,^https://a\.test/,PASS",
        r"URL-REGEX,/(\w)\1/,A",
        "URL-REGEX,/never,B",
        "URL-REGEX,(?<=/)ad,C",
        "URL-REGEX,(?i)/AD,D",
        "DOMAIN,a.test,E",
        "MATCH,F",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        assert_eq!(url_runs(&program)[0], usize::from(merge == 2));
        let flow = request("a.test", "https://a.test/ad", None);
        let all = drive(&program, &kit.geo, &flow, false);
        let want: Vec<(usize, String)> = [(0, "PASS"), (3, "C"), (4, "D"), (5, "E"), (6, "F")]
            .map(|(index, target)| (index, target.to_string()))
            .into();
        assert_eq!(all.candidates, want, "merge {merge}");
        assert_eq!(accepted(&kit, &program, &flow), pick(3, "C"));
        let twice = request("a.test", "https://a.test/xx/", None);
        assert_eq!(accepted(&kit, &program, &twice), pick(1, "A"));
        let other = request("b.test", "https://b.test/AD", None);
        assert_eq!(accepted(&kit, &program, &other), pick(4, "D"));
        assert!(!drive(&program, &kit.geo, &other, true).http_pending);
    }
}

#[test]
fn a_url_run_in_a_sub_rule_list_passes_on_to_the_list_after_it() {
    let kit = Kit::new();
    let inner: &[&str] = &[
        "URL-REGEX,/ad,PASS-RULE",
        "URL-REGEX,/ad,PASS",
        "URL-REGEX,(?<!x)/ad,IN",
        "URL-REGEX,/ad,LATE",
    ];
    for merge in MERGES {
        let program = kit.compile_with(
            &[
                "SUB-RULE,(DOMAIN,a.test),inner",
                "URL-REGEX,/ad,OUT",
                "MATCH,F",
            ],
            &[("inner", inner)],
            merge,
        );
        assert_eq!(url_runs(&program)[1], usize::from(merge == 2));
        let flow = request("a.test", "https://a.test/ad", None);
        let all = drive(&program, &kit.geo, &flow, false);
        let want: Vec<(usize, String)> = [(0, "PASS-RULE"), (0, "PASS"), (1, "OUT"), (2, "F")]
            .map(|(index, target)| (index, target.to_string()))
            .into();
        assert_eq!(all.candidates, want, "merge {merge}");
    }
}

#[test]
fn a_url_run_waits_for_the_request_only_when_reached_undecided() {
    let kit = Kit::new();
    let lines = [
        "DOMAIN,a.test,A",
        "URL-REGEX,/one,B",
        "URL-REGEX,/two,C",
        r"URL-REGEX,/(\w)\1$,D",
        "MATCH,F",
    ];
    for merge in MERGES {
        let program = kit.compile(&lines, merge);
        assert!(program.reads_http());
        let decided = drive(&program, &kit.geo, &Flow::domain("a.test"), true);
        assert_eq!(decided.accepted, pick(0, "A"));
        assert!(!decided.http_pending);
        let unread = drive(&program, &kit.geo, &Flow::domain("b.test"), true);
        assert_eq!(unread.accepted, pick(4, "F"));
        assert!(unread.http_pending);
        let none = drive(
            &program,
            &kit.geo,
            &request("b.test", "https://b.test/x", None),
            true,
        );
        assert_eq!(none.accepted, pick(4, "F"));
        assert!(!none.http_pending);
        let both = request("b.test", "https://b.test/two/ll", None);
        assert_eq!(accepted(&kit, &program, &both), pick(2, "C"));
        let fancy = request("b.test", "https://b.test/ll", None);
        assert_eq!(accepted(&kit, &program, &fancy), pick(3, "D"));
    }
}

#[test]
fn url_rules_in_a_classical_set_match_as_a_run() {
    let kit = Kit::new();
    let mut entries = vec![r"URL-REGEX,(?<=/)deep"];
    entries.extend(["URL-REGEX,/x"; 9]);
    entries.push("URL-REGEX,/ad");
    fill(&kit, "urls", Behavior::Classical, &entries);
    let program = kit.compile(&["RULE-SET,urls,REJECT", "MATCH,PROXY"], 8);
    let unread = drive(&program, &kit.geo, &Flow::domain("a.test"), true);
    assert_eq!(unread.accepted, pick(1, "PROXY"));
    assert!(unread.http_pending);
    for (url, want) in [
        ("https://a.test/ad", pick(0, "REJECT")),
        ("https://a.test/deep", pick(0, "REJECT")),
        ("https://a.test/y", pick(1, "PROXY")),
    ] {
        let flow = request("a.test", url, None);
        assert_eq!(accepted(&kit, &program, &flow), want, "{url}");
    }
}

#[test]
fn a_url_run_rejects_a_bad_pattern_as_a_lone_rule_does() {
    let kit = Kit::new();
    let mut rules = defs(&["URL-REGEX,/a,A", "URL-REGEX,/b,B", "URL-REGEX,/c,C"]);
    rules[1].cond = Cond::UrlRegex("/(".into());
    let errors = [1, 1000].map(|merge| {
        let err = RouteProgram::compile(&rules, &IndexMap::new(), &kit.env(merge))
            .err()
            .unwrap();
        assert!(
            matches!(&err, CompileError::Invalid { index: 1, .. }),
            "{err}"
        );
        err.to_string()
    });
    assert_eq!(errors[0], errors[1]);
}

#[test]
fn a_broken_url_run_matches_lone_rule_demands_and_error_order() {
    let kit = Kit::new();
    let oversized = r"(?:\w{500}){500}";
    assert!(concord_config::mitm::check_pattern(oversized).is_ok());

    for bad_at in [0usize, 7] {
        let mut entries: Vec<String> = (0..8).map(|_| "URL-REGEX,/ok".to_string()).collect();
        entries[bad_at] = format!("URL-REGEX,{oversized}");
        let merged = RuleSet::from_entries(Behavior::Classical, &entries, &kit.env(8));
        let lone = RuleSet::from_entries(Behavior::Classical, &entries, &kit.env(1000));
        assert_eq!(
            merged.set.demands().http,
            lone.set.demands().http,
            "classical bad_at={bad_at}"
        );
        assert!(merged.set.demands().http, "classical bad_at={bad_at}");
    }

    let env_known = |merge: usize| {
        let mut env = kit.env(merge);
        env.known_target = Some(Box::new(|target| target == "A"));
        env
    };
    let bad_rule = format!("URL-REGEX,{oversized},A");
    let cases: [&[&str]; 2] = [
        &[bad_rule.as_str(), "URL-REGEX,/ok,UNKNOWN"],
        &[bad_rule.as_str(), "DOMAIN,a.test,UNKNOWN"],
    ];
    for lines in cases {
        let rules = defs(lines);
        let merged = RouteProgram::compile(&rules, &IndexMap::new(), &env_known(8))
            .err()
            .unwrap();
        let lone = RouteProgram::compile(&rules, &IndexMap::new(), &env_known(1))
            .err()
            .unwrap();
        assert!(
            matches!(&merged, CompileError::Invalid { index: 0, .. }),
            "{merged}"
        );
        assert_eq!(merged.to_string(), lone.to_string());
    }

    let sub_lines = defs(&[bad_rule.as_str(), "URL-REGEX,/ok,UNKNOWN"]);
    let sub_rules = IndexMap::from([("inner".to_string(), sub_lines)]);
    let main_rules = defs(&["SUB-RULE,(DOMAIN,a.test),inner"]);
    let merged = RouteProgram::compile(&main_rules, &sub_rules, &env_known(8))
        .err()
        .unwrap();
    let lone = RouteProgram::compile(&main_rules, &sub_rules, &env_known(1))
        .err()
        .unwrap();
    assert!(
        matches!(
            &merged,
            CompileError::Invalid {
                section,
                index: 0,
                ..
            } if section == "sub-rules[inner]"
        ),
        "{merged}"
    );
    assert_eq!(merged.to_string(), lone.to_string());
}

#[test]
fn program_url_set_scans_once_and_preserves_order_across_main_and_sub_rules() {
    let kit = Kit::new();
    let main = [
        "DOMAIN,early.a.test,EARLY",
        r"URL-REGEX,^https://a\.test/,PASS",
        "DOMAIN,d1.a.test,D1",
        r"URL-REGEX,/(\w)\1/,FANCY",
        "DOMAIN,d2.a.test,D2",
        "SUB-RULE,(URL-REGEX,/sub),inner",
        "DOMAIN,d3.a.test,D3",
        "URL-REGEX,(?i)/AD,HIT",
        "MATCH,FINAL",
    ];
    let inner: &[&str] = &[
        "DOMAIN,sub-only.a.test,S0",
        "URL-REGEX,/sub/pass-rule,PASS-RULE",
        "DOMAIN,sub-mid.a.test,S1",
        "URL-REGEX,(?<!x)/sub/pass-rule,SUB-FANCY",
        "DOMAIN,sub-end.a.test,S2",
        "URL-REGEX,/sub/end,SUB-END",
    ];
    let program = kit.compile_with(&main, &[("inner", inner)], 8);
    assert!(program.url_set.is_set());

    let early = drive(
        &program,
        &kit.geo,
        &request("early.a.test", "https://early.a.test/ad", None),
        true,
    );
    assert_eq!(early.accepted, pick(0, "EARLY"));
    assert_eq!(program.url_set.scans(), 0);

    let unread = drive(&program, &kit.geo, &Flow::domain("a.test"), true);
    assert_eq!(unread.accepted, pick(8, "FINAL"));
    assert!(unread.http_pending);
    assert_eq!(program.url_set.scans(), 0);

    let flow = request("a.test", "https://a.test/sub/pass-rule/AD", None);
    let all = drive(&program, &kit.geo, &flow, false);
    let want: Vec<(usize, String)> = [
        (1, "PASS"),
        (5, "PASS-RULE"),
        (5, "SUB-FANCY"),
        (7, "HIT"),
        (8, "FINAL"),
    ]
    .map(|(i, t)| (i, t.to_string()))
    .into();
    assert_eq!(all.candidates, want);
    assert_eq!(program.url_set.scans(), 1);
    assert!(!all.http_pending);

    let fancy = request("a.test", "https://a.test/xx/AD", None);
    assert_eq!(accepted(&kit, &program, &fancy), pick(3, "FANCY"));
    assert_eq!(program.url_set.scans(), 2);

    let meta = Flow::domain("a.test").meta();
    let ctx = crate::MatchCtx::new(&kit.geo);
    let mut state = concord_common::RouteState::seed(&meta.dst);
    state.http = Some(std::sync::Arc::new(concord_common::HttpFacts {
        url: "https://a.test/sub/end".into(),
        host: "a.test".into(),
        user_agent: None,
    }));
    let mut run = program.start();
    assert!(!run.has_url_hits());
    let first = run.step(&meta, &state, &ctx);
    assert!(matches!(
        first,
        crate::Step::Candidate { target: "PASS", .. }
    ));
    assert!(run.has_url_hits());
    run.skip();
    let second = run.step(&meta, &state, &ctx);
    assert!(matches!(
        second,
        crate::Step::Candidate {
            target: "SUB-END",
            ..
        }
    ));
    let scans_before_swap = program.url_set.scans();
    state.http = Some(std::sync::Arc::new(concord_common::HttpFacts {
        url: "https://a.test/AD".into(),
        host: "a.test".into(),
        user_agent: None,
    }));
    run.skip();
    let third = run.step(&meta, &state, &ctx);
    assert!(matches!(
        third,
        crate::Step::Candidate { target: "HIT", .. }
    ));
    assert_eq!(program.url_set.scans(), scans_before_swap + 1);
    run.restart(None);
    assert!(!run.has_url_hits());
}

#[test]
fn program_url_set_handles_logic_rules_single_leaf_and_classical_sets() {
    let kit = Kit::new();
    fill(
        &kit,
        "set_a",
        Behavior::Classical,
        &[
            "DOMAIN,nope.a.test",
            "URL-REGEX,/set-hit",
            "DOMAIN,nope2.a.test",
            "URL-REGEX,/set-two",
        ],
    );
    let program = kit.compile(
        &[
            "NOT,((URL-REGEX,/blocked)),NOT-BLOCKED",
            "AND,((DOMAIN,a.test),(URL-REGEX,/blocked)),AND-HIT",
            "OR,((URL-REGEX,/or1),(URL-REGEX,/or2)),OR-HIT",
            "RULE-SET,set_a,SET",
            "MATCH,FINAL",
        ],
        8,
    );
    assert!(program.url_set.is_set());

    let no_http = drive(&program, &kit.geo, &Flow::domain("a.test"), true);
    assert_eq!(no_http.accepted, pick(4, "FINAL"));
    assert!(no_http.http_pending);
    assert_eq!(program.url_set.scans(), 0);

    let allowed = request("a.test", "https://a.test/ok", None);
    assert_eq!(accepted(&kit, &program, &allowed), pick(0, "NOT-BLOCKED"));

    let blocked = request("a.test", "https://a.test/blocked", None);
    assert_eq!(accepted(&kit, &program, &blocked), pick(1, "AND-HIT"));

    let from_set = request("b.test", "https://b.test/blocked/set-two", None);
    assert_eq!(accepted(&kit, &program, &from_set), pick(3, "SET"));

    // Classical set URL leaves must never index the outer program's UrlSet slots:
    // outer slots are 0=/outer0, 1=/outer1; set_a has /set-hit, /set-two.
    let isolated = kit.compile(
        &[
            "AND,((DOMAIN,a.test),(URL-REGEX,/outer0)),OUTER0",
            "AND,((DOMAIN,a.test),(URL-REGEX,/outer1)),OUTER1",
            "RULE-SET,set_a,SET",
            "MATCH,FINAL",
        ],
        8,
    );
    assert!(isolated.url_set.is_set());
    let set_only = request("b.test", "https://b.test/set-two", None);
    assert_eq!(accepted(&kit, &isolated, &set_only), pick(2, "SET"));
    let outer_slot_only = request("b.test", "https://b.test/outer0", None);
    assert_eq!(
        accepted(&kit, &isolated, &outer_slot_only),
        pick(3, "FINAL")
    );

    let single = kit.compile(&["DOMAIN,x.a.test,X", "URL-REGEX,/one,ONE", "MATCH,F"], 8);
    assert!(!single.url_set.is_set());
    assert_eq!(
        accepted(
            &kit,
            &single,
            &request("a.test", "https://a.test/one", None)
        ),
        pick(1, "ONE")
    );
}

#[test]
fn url_set_fallback_matches_when_regex_set_cannot_be_built() {
    let re0 = fancy_regex::Regex::new("/alpha").unwrap();
    let re1 = fancy_regex::Regex::new("/beta").unwrap();
    let set = crate::runs::UrlSet::build(vec!["(".into(), "(".into()], vec![re0, re1]);
    assert!(!set.is_set());
    let mut cache = None;
    let http = std::sync::Arc::new(concord_common::HttpFacts {
        url: "https://a.test/beta".into(),
        host: "a.test".into(),
        user_agent: None,
    });
    assert!(!set.matches(0, &http, &mut cache));
    assert!(set.matches(1, &http, &mut cache));
}

#[test]
fn chunked_url_set_scans_buckets_lazily_and_handles_oversized_single_pattern() {
    let patterns = [
        r"^https?://([a-z0-9-]+\.)*b0\.example\.com/p0",
        r"/api/v\d+/bucket0/item1",
        r"^https?://([a-z0-9-]+\.)*b1\.example\.com/p2",
        r"/api/v\d+/bucket1/item3",
        r"^https?://([a-z0-9-]+\.)*b2\.example\.com/p4",
        r"/api/v\d+/bucket2/item5",
        r"/shared/both",
    ];
    let sources: Vec<String> = patterns
        .iter()
        .map(|p| concord_config::mitm::delegatable_regex(p).unwrap())
        .collect();
    let regexes: Vec<fancy_regex::Regex> = patterns
        .iter()
        .map(|p| fancy_regex::Regex::new(p).unwrap())
        .collect();

    // Small NFA cap forces multiple buckets while still fitting individual patterns.
    let set = crate::runs::UrlSet::build_with_limit(sources.clone(), regexes.clone(), 4096);
    assert!(set.is_set());
    assert!(
        set.bucket_count() >= 3,
        "expected >= 3 buckets, got {}",
        set.bucket_count()
    );

    let make_http = |url: &str| {
        std::sync::Arc::new(concord_common::HttpFacts {
            url: url.into(),
            host: "b0.example.com".into(),
            user_agent: None,
        })
    };

    // Hit in bucket 0 scans only bucket 0 (1 scan, not all buckets).
    let mut cache = None;
    let hit0 = make_http("https://b0.example.com/p0");
    assert!(set.matches(0, &hit0, &mut cache));
    assert_eq!(set.scans(), 1);
    assert!(!set.matches(1, &hit0, &mut cache));
    assert_eq!(set.scans(), 1);

    let mut cache = None;
    let scans_before_last = set.scans();
    let hit_last = make_http("https://x.test/shared/both");
    assert!(!set.matches(0, &hit_last, &mut cache));
    assert_eq!(set.scans(), scans_before_last + 1);
    assert!(set.matches(6, &hit_last, &mut cache));
    assert_eq!(set.scans(), scans_before_last + 2);

    let mut cache = None;
    let scans_before = set.scans();
    let hit_both = make_http("https://b0.example.com/p0/shared/both");
    assert!(set.matches(0, &hit_both, &mut cache));
    assert_eq!(set.scans(), scans_before + 1);
    assert!(set.matches(6, &hit_both, &mut cache));
    assert_eq!(set.scans(), scans_before + 2);
    assert!(set.matches(0, &hit_both, &mut cache));
    assert_eq!(set.scans(), scans_before + 2);

    let mixed = [r"/alpha/", r"/api/v\d+/big", r"/beta/", r"/gamma/"];
    let m_src: Vec<String> = mixed
        .iter()
        .map(|p| concord_config::mitm::delegatable_regex(p).unwrap())
        .collect();
    let m_re: Vec<fancy_regex::Regex> = mixed
        .iter()
        .map(|p| fancy_regex::Regex::new(p).unwrap())
        .collect();
    let degraded = crate::runs::UrlSet::build_with_limit(m_src, m_re, 1024);
    assert!(degraded.is_set());
    assert!(
        degraded.fancy_bucket_count() >= 1,
        "expected oversized Unicode pattern to degrade to Fancy"
    );
    let mut cache = None;
    assert!(degraded.matches(0, &make_http("https://x.test/alpha/"), &mut cache));
    assert!(degraded.matches(1, &make_http("https://x.test/api/v9/big"), &mut cache));
    assert!(!degraded.matches(1, &make_http("https://x.test/api/nope"), &mut cache));
    assert!(degraded.matches(3, &make_http("https://x.test/gamma/"), &mut cache));
}

#[test]
fn chunked_url_set_recovers_step_after_heavy_prefix() {
    let mut sources = Vec::new();
    let mut regexes = Vec::new();
    for i in 0..8 {
        let pat = format!("/heavy/segment_alpha_beta_gamma_delta_epsilon_{i}/");
        sources.push(concord_config::mitm::delegatable_regex(&pat).unwrap());
        regexes.push(fancy_regex::Regex::new(&pat).unwrap());
    }
    for i in 0..80 {
        let pat = format!("/p{i}/");
        sources.push(concord_config::mitm::delegatable_regex(&pat).unwrap());
        regexes.push(fancy_regex::Regex::new(&pat).unwrap());
    }
    // Long ASCII prefix fits in small Set buckets (no Fancy degradation) and pulls step down,
    // while the 80 short ASCII patterns must recover step upward rather than staying pinned.
    let set = crate::runs::UrlSet::build_with_limit(sources, regexes, 4096);
    assert!(set.is_set());
    assert_eq!(
        set.fancy_bucket_count(),
        0,
        "prefix must fit in Set buckets so step actually shrinks"
    );
    assert!(
        set.bucket_count() < 20,
        "expected step recovery on light suffix, got {} buckets",
        set.bucket_count()
    );
}

#[test]
fn single_set_fast_path_keeps_n1000_and_within_limit_unchunked() {
    let make = |n: usize| {
        let mut sources = Vec::with_capacity(n);
        let mut regexes = Vec::with_capacity(n);
        let mut items = Vec::with_capacity(n);
        for i in 0..n {
            let pat = format!("/api/item{i}/");
            let cooked = concord_config::mitm::delegatable_regex(&pat).unwrap();
            let re = fancy_regex::Regex::new(&pat).unwrap();
            sources.push(cooked);
            regexes.push(re.clone());
            items.push((i as u32, re));
        }
        (sources, regexes, items)
    };

    // Synthetic fast-path check: 16 patterns exceed bucket=2 KiB yet fit inside single=16 KiB.
    let (s_fit, r_fit, i_fit) = make(16);
    let fit_set = crate::runs::UrlSet::build_with_limits(s_fit.clone(), r_fit.clone(), 16384, 2048);
    assert_eq!(fit_set.bucket_count(), 1);
    let fit_run = crate::runs::UrlRun::build_with_limits(0, 16, i_fit, Some(16384), 2048);
    assert_eq!(fit_run.bucket_count(), 1);

    let (s_big, r_big, i_big) = make(60);
    let big_set = crate::runs::UrlSet::build_with_limits(s_big, r_big, 16384, 2048);
    assert!(big_set.bucket_count() >= 2);
    let big_run = crate::runs::UrlRun::build_with_limits(0, 60, i_big, Some(16384), 2048);
    assert!(big_run.bucket_count() >= 2);

    let mut prod_sources = Vec::new();
    let mut prod_regexes = Vec::new();
    let mut prod_items = Vec::new();
    for i in 0..1000usize {
        let pat = match i % 5 {
            0 => format!(r"^https?://([a-z0-9-]+\.)*ads{i}\.example\.com/"),
            1 => format!(r"/api/v\d+/track{i}\?"),
            2 => format!(r"(?i)\.example{i}\.net/.*\.(gif|png)$"),
            3 => format!(r"^https://cdn{i}\.test/(?!static/)"),
            _ => format!(r"/collect{i}/"),
        };
        let re = fancy_regex::Regex::new(&pat).unwrap();
        if let Some(cooked) = concord_config::mitm::delegatable_regex(&pat) {
            prod_sources.push(cooked);
            prod_regexes.push(re.clone());
        }
        prod_items.push((i as u32, re));
    }
    let prod_set = crate::runs::UrlSet::build(prod_sources, prod_regexes);
    assert_eq!(
        prod_set.bucket_count(),
        1,
        "n=1000 UrlSet must stay single-bucket"
    );
    let prod_run = crate::runs::UrlRun::build(0, 1000, prod_items);
    assert_eq!(
        prod_run.bucket_count(),
        1,
        "n=1000 UrlRun must stay single-bucket"
    );
}

#[test]
fn chunked_url_run_preserves_rule_order_across_buckets_and_fancy() {
    let entries: &[(u32, &str)] = &[
        (0, r"^https?://([a-z0-9-]+\.)*b0\.example\.com/hit"),
        (1, r"/api/v\d+/b0/one"),
        (2, r"^https?://([a-z0-9-]+\.)*b1\.example\.com/hit"),
        (3, r"/fancy/(?!skip)"),
        (4, r"/api/v\d+/b1/two"),
        (5, r"^https?://([a-z0-9-]+\.)*b2\.example\.com/hit"),
        (6, r"/api/v\d+/b2/three"),
        (7, r"/shared/tail"),
    ];
    let items: Vec<(u32, fancy_regex::Regex)> = entries
        .iter()
        .map(|(idx, pat)| (*idx, fancy_regex::Regex::new(pat).unwrap()))
        .collect();
    let run = crate::runs::UrlRun::build_with_limit(0, 8, items, 4096);
    assert!(
        run.bucket_count() >= 3,
        "expected >= 3 UrlRun buckets, got {}",
        run.bucket_count()
    );

    // Hit only in last bucket.
    assert_eq!(run.next_from("https://x.test/shared/tail", 0), Some(7));
    // Hit only in bucket 0.
    assert_eq!(run.next_from("https://b0.example.com/hit", 0), Some(0));
    // Simultaneous hits in bucket 0 (0), intervening fancy (3), and last bucket (7):
    // early-stop across buckets must return strictly increasing rule indices.
    let multi = "https://b0.example.com/hit/fancy/ok/shared/tail";
    assert_eq!(run.next_from(multi, 0), Some(0));
    assert_eq!(run.next_from(multi, 1), Some(3));
    assert_eq!(run.next_from(multi, 4), Some(7));
    assert_eq!(run.next_from(multi, 8), None);
}
