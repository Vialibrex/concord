use std::sync::atomic::Ordering;
use std::time::Duration;

use super::*;
use crate::group::{set_fastest_mid_scan, take_url_test_scans};
use crate::health::{StatusRanges, take_lock_calls};
use crate::outbounds::take_refresh_visits;
use crate::priority::take_match_calls;
use crate::smart::{set_candidates_mid_scan, take_align_scans, take_row_allocs, take_table_builds};

#[tokio::test(start_paused = true)]
async fn static_covers_preserves_max_timeout_extra_urls_and_3000_node_lookup() {
    let mut yaml = String::from("proxies:\n");
    for i in 0..3000 {
        yaml.push_str(&format!("  - {{name: n{i}, type: direct}}\n"));
    }
    yaml.push_str("proxy-providers:\n  p:\n    type: inline\n    health-check:\n      enable: true\n      url: 'http://prov.test/204'\n      timeout: 7000\n    payload:\n      - {name: prov-a, type: direct}\n      - {name: ghost-ts, type: easytier}\n");
    yaml.push_str("proxy-groups:\n  - name: g_short\n    type: url-test\n    url: 'http://probe.test/generate_204'\n    timeout: 3000\n    proxies:\n");
    for i in 0..3000 {
        yaml.push_str(&format!("      - n{i}\n"));
    }
    yaml.push_str("  - name: g_long\n    type: url-test\n    url: 'http://probe.test/generate_204'\n    timeout: 9000\n    proxies: [n0, n2999]\n");
    yaml.push_str("  - name: g_extra\n    type: url-test\n    url: 'http://extra.test/204'\n    timeout: 8000\n    filter: 'nomatch'\n    use: [p]\n");

    let rig = Rig::new(&yaml);
    let checks = rig.out.checks();
    let short = checks.iter().find(|c| c.id() == "group:g_short").unwrap();
    for i in 0..3000 {
        assert!(short.covers(&format!("n{i}")));
    }
    assert!(!short.covers("unknown"));
    assert!(!short.covers("ghost-ts"));

    rig.book.get("n2999").set_delay(6000);
    let hit = rig
        .out
        .test_delay("n2999", TEST_URL, Duration::from_secs(2))
        .await;
    assert_eq!(hit.value, 6000);

    rig.book.get("n1").set_delay(4000);
    let capped = rig
        .out
        .test_delay("n1", TEST_URL, Duration::from_secs(10))
        .await;
    assert_eq!(capped.value, -1);

    // Provider extra URL timeout applies regardless of the extra's name filter.
    rig.book.get("prov-a").set_delay(5000);
    let extra = rig
        .out
        .test_delay("prov-a", "http://extra.test/204", Duration::from_secs(2))
        .await;
    assert_eq!(extra.value, 5000);

    let before_events = rig.events.delays().len();
    let missing = rig
        .out
        .test_delay("missing", TEST_URL, Duration::from_secs(2))
        .await;
    assert_eq!(missing.value, -2);
    assert_eq!(rig.events.delays().len(), before_events);
}

#[tokio::test(start_paused = true)]
async fn smart_priority_factors_are_precomputed_once_per_member_snapshot() {
    let mut yaml = String::from("proxies:\n");
    for i in 0..500 {
        yaml.push_str(&format!("  - {{name: node-{i}, type: direct}}\n"));
    }
    yaml.push_str(&format!(
        "proxy-groups:\n  - name: s1\n    type: smart\n    url: '{TEST_URL}'\n    policy-priority: '^node-1$:3;[invalid:2;^node-2$:0.5;^node-3$:1.5;^node-4$:4'\n    proxies:\n"
    ));
    for i in 0..500 {
        yaml.push_str(&format!("      - node-{i}\n"));
    }
    yaml.push_str(&format!(
        "  - name: s_empty\n    type: smart\n    url: '{TEST_URL}'\n    proxies: [node-0, node-1]\n"
    ));

    let _ = take_match_calls();
    let rig = Rig::new(&yaml);
    let build_matches = take_match_calls();
    assert!(
        build_matches > 0 && build_matches <= 500 * 5,
        "expected at most N*R matches on build, got {build_matches}"
    );

    let _ = take_table_builds();
    for round in 0..20 {
        let node = rig.out.node("node-0").unwrap();
        node.health().record(TEST_URL, 50 + round, false, true);
        let _ = rig.leaf_at("s1", &format!("site{round}.org"));
    }
    assert_eq!(
        take_match_calls(),
        0,
        "health table rebuilds must not re-run priority regexes"
    );
    assert_eq!(take_table_builds(), 20);

    let _ = take_lock_calls();
    for i in 0..50 {
        let _ = rig.leaf_at("s1", &format!("warm{i}.org"));
    }
    assert_eq!(take_table_builds(), 0);
    assert_eq!(take_lock_calls(), 0);

    let _ = take_match_calls();
    let _ = rig.leaf("s_empty");
    assert_eq!(take_match_calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn smart_factors_cover_overlap_invalid_regex_reorder_provider_swap_and_base_score_bits() {
    let rig = Rig::new(&format!(
        "proxy-providers:
  p:
    type: http
    url: 'http://provider.test/p.yaml'
    path: 'p.yaml'
    payload:
      - {{name: 'hk-1', type: direct}}
      - {{name: '[HK] sub', type: direct}}
      - {{name: 'us-1', type: direct}}
proxy-groups:
  - name: s
    type: smart
    url: '{TEST_URL}'
    policy-priority: '^hk:2;^hk-1$:5;[HK:4;^us-:0.5'
    use: [p]
"
    ));

    let check_bits = |rig: &Rig, delays: &[(&str, Option<u16>, f64)]| {
        for &(name, delay, _) in delays {
            if let Some(ms) = delay {
                rig.out
                    .node(name)
                    .unwrap()
                    .health()
                    .record(TEST_URL, ms, false, true);
            }
        }
        let group = rig.out.group("s").unwrap();
        let members = group.members();
        let view = group.smart().unwrap().candidates(&group, &members);
        assert_eq!(view.len(), delays.len());
        for (idx, &(name, delay, factor)) in delays.iter().enumerate() {
            assert_eq!(view.name(idx).map(|n| &**n), Some(name));
            let expected = delay.map(|d| (f64::from(d) / factor).to_bits());
            assert_eq!(
                view.base_score(idx).map(f64::to_bits),
                expected,
                "base_score bit mismatch for {name}"
            );
        }
    };

    // Overlapping `^hk:2` beats `^hk-1$:5`; invalid regex `[HK` matches as substring.
    check_bits(
        &rig,
        &[
            ("hk-1", Some(100), 2.0),
            ("[HK] sub", Some(120), 4.0),
            ("us-1", Some(75), 0.5),
        ],
    );
    assert_eq!(rig.leaf("s"), "[HK] sub");

    let prov = rig.out.provider("p").unwrap();
    prov.side_load(
        b"proxies:
  - {name: 'us-1', type: direct}
  - {name: 'plain', type: direct}
  - {name: 'hk-1', type: direct}
",
    )
    .await
    .unwrap();
    check_bits(
        &rig,
        &[
            ("us-1", Some(90), 0.5),
            ("plain", Some(80), 1.0),
            ("hk-1", Some(100), 2.0),
        ],
    );
    assert_eq!(rig.leaf_at("s", "reloaded.org"), "hk-1");
}

#[tokio::test(start_paused = true)]
async fn smart_attempt_budget_prechecks_without_building_candidates_or_locking_health() {
    let mut yaml = String::from("proxies:\n");
    for i in 0..300 {
        yaml.push_str(&format!("  - {{name: p{i}, type: direct}}\n"));
    }
    yaml.push_str(&format!(
        "proxy-providers:
  q:
    type: inline
    payload:
      - {{name: ts, type: easytier}}
proxy-groups:
  - name: bad
    type: select
    use: [q]
  - name: s
    type: smart
    url: '{TEST_URL}'
    policy-priority: '^p0$:2;^p1$:0.5'
    proxies: [bad, PASS, p0, p1]
  - name: o
    type: select
    proxies: [s]
"
    ));

    let rig = Rig::new(&yaml);
    let chain_p0: Vec<Arc<str>> = vec![Arc::from("p0"), Arc::from("s"), Arc::from("o")];
    rig.out
        .smart_dial_succeeded(&chain_p0, Duration::from_millis(200));

    rig.out.group("s").unwrap().health_watch().notify();
    let _ = take_table_builds();
    let _ = take_lock_calls();
    let _ = take_match_calls();

    // `bad` is quarantined (Rejected) and `PASS` is non-routable, so walk skips both to `p1`.
    let budget = rig.out.smart_attempt_budget(
        &chain_p0,
        &Rig::flow("example.com"),
        None,
        &[Arc::from("p0")],
    );
    assert_eq!(budget, Some(Duration::from_secs(1)));
    assert_eq!(take_table_builds(), 0);
    assert_eq!(take_lock_calls(), 0);
    assert_eq!(take_match_calls(), 0);

    let none = rig.out.smart_attempt_budget(
        &chain_p0,
        &Rig::flow("example.com"),
        None,
        &[Arc::from("p0"), Arc::from("p1")],
    );
    assert_eq!(none, None);
    assert_eq!(take_table_builds(), 0);
    assert_eq!(take_lock_calls(), 0);

    let (resolved, chosen) = rig
        .out
        .smart_retry(
            &chain_p0,
            &Rig::flow("example.com"),
            None,
            &[Arc::from("p0")],
        )
        .expect("p1 is routable");
    assert_eq!(&*chosen, "p1");
    let Resolved::Route {
        chain,
        provider_chain,
        ..
    } = resolved
    else {
        panic!("expected Route");
    };
    assert_eq!(
        chain.iter().map(|n| &**n).collect::<Vec<_>>(),
        ["p1", "s", "o"]
    );
    assert_eq!(provider_chain.len(), 3);
    assert_eq!(take_table_builds(), 1);
}

#[tokio::test(start_paused = true)]
async fn smart_different_groups_same_node_name_keep_distinct_factors_and_status_code_semantics() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
proxy-groups:
  - {{name: prefer_a, type: smart, proxies: [a, b], url: '{TEST_URL}', policy-priority: '^a$:4'}}
  - {{name: prefer_b, type: smart, proxies: [a, b], url: '{TEST_URL}', policy-priority: '^b$:4'}}
"
    ));
    rig.book.get("a").set_delay(120);
    rig.book.get("b").set_delay(100);
    assert_eq!(rig.test("a").await, 120);
    assert_eq!(rig.test("b").await, 100);
    assert_eq!(rig.leaf("prefer_a"), "a");
    assert_eq!(rig.leaf("prefer_b"), "b");

    rig.book.get("a").status.store(500, Ordering::SeqCst);
    let node = rig.out.node("a").unwrap();
    let expected = StatusRanges::parse("200-299").unwrap();
    rig.out
        .url_test_node(&node, TEST_URL, &expected, Duration::from_secs(5))
        .await;
    assert!(!node.health().alive_for(TEST_URL));
    assert!(node.health().alive_for("http://other.test/"));
}

#[tokio::test(start_paused = true)]
async fn unrelated_group_records_cause_zero_rescans_and_zero_hot_row_allocs() {
    let mut yaml = String::from("proxies:\n");
    for i in 0..300 {
        yaml.push_str(&format!("  - {{name: hot-{i}, type: direct}}\n"));
    }
    for i in 0..100 {
        yaml.push_str(&format!("  - {{name: other-{i}, type: direct}}\n"));
    }
    yaml.push_str(&format!(
        "proxy-groups:\n  - name: u_hot\n    type: url-test\n    url: '{TEST_URL}'\n    proxies:\n"
    ));
    for i in 0..300 {
        yaml.push_str(&format!("      - hot-{i}\n"));
    }
    yaml.push_str(&format!(
        "  - name: s_hot\n    type: smart\n    url: '{TEST_URL}'\n    proxies:\n"
    ));
    for i in 0..300 {
        yaml.push_str(&format!("      - hot-{i}\n"));
    }
    yaml.push_str(&format!(
        "  - name: u_other\n    type: url-test\n    url: '{TEST_URL}'\n    proxies:\n"
    ));
    for i in 0..100 {
        yaml.push_str(&format!("      - other-{i}\n"));
    }

    let rig = Rig::new(&yaml);
    let _ = rig.leaf("u_hot");
    let _ = rig.leaf_at("s_hot", "sticky.org");
    let _ = rig.leaf_at("s_hot", "sticky.org");

    let _ = take_url_test_scans();
    let _ = take_table_builds();
    let _ = take_row_allocs();
    let _ = take_align_scans();

    let mut pick_health_locks = 0usize;
    for i in 0..100 {
        let other = rig.out.node(&format!("other-{i}")).unwrap();
        other.health().record(TEST_URL, 20 + i as u16, false, true);

        let _ = take_lock_calls();
        assert_eq!(rig.leaf("u_hot"), "hot-0");
        assert_eq!(rig.leaf_at("s_hot", "sticky.org"), "hot-0");
        assert_eq!(rig.leaf_at("s_hot", &format!("new-{i}.org")), "hot-0");
        pick_health_locks += take_lock_calls();
    }
    assert_eq!(take_url_test_scans(), 0);
    assert_eq!(take_table_builds(), 0);
    assert_eq!(pick_health_locks, 0);
    assert_eq!(take_row_allocs(), 0);
    assert_eq!(take_align_scans(), 0);

    let hot5 = rig.out.node("hot-5").unwrap();
    hot5.health().record(TEST_URL, 15, false, true);
    assert_eq!(rig.leaf("u_hot"), "hot-5");
    assert_eq!(rig.leaf_at("s_hot", "brand-new.org"), "hot-5");
    assert_eq!(take_url_test_scans(), 1);
    assert_eq!(take_table_builds(), 1);
}

#[tokio::test(start_paused = true)]
async fn per_group_invalidation_covers_global_fallback_window_rollout_and_same_name_replacement() {
    let url_a = "http://a.test/204";
    let url_b = "http://b.test/204";
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
proxy-providers:
  p:
    type: http
    url: 'http://provider.test/p.yaml'
    path: 'p.yaml'
    payload:
      - {{name: x, type: direct}}
      - {{name: y, type: direct}}
proxy-groups:
  - {{name: u, type: url-test, proxies: [a, b], url: '{url_a}', tolerance: 20}}
  - {{name: s, type: smart, proxies: [a, b], url: '{url_a}'}}
  - {{name: up, type: url-test, use: [p], url: '{url_a}'}}
  - {{name: sp, type: smart, use: [p], url: '{url_a}'}}
"
    ));

    let node_a = rig.out.node("a").unwrap();
    let node_b = rig.out.node("b").unwrap();
    node_b.health().record(url_a, 100, false, true);
    assert_eq!(rig.leaf("u"), "b");
    node_a.health().record(url_a, 50, false, true);
    assert_eq!(rig.leaf("u"), "a");
    node_b.health().record(url_a, 50, false, true);
    node_a.health().record(url_a, 70, false, true);
    assert_eq!(rig.leaf("u"), "a");
    node_a.health().record(url_a, 71, false, true);
    assert_eq!(rig.leaf("u"), "b");

    let node_x = rig.out.node("x").unwrap();
    let node_y = rig.out.node("y").unwrap();
    node_y.health().record(url_a, 200, false, true);
    rig.store.set("up", "x");
    assert_eq!(rig.leaf("up"), "x");
    node_x.health().record(url_b, 0, true, false);
    assert!(!node_x.health().alive_for(url_a));
    assert_eq!(rig.leaf("up"), "y");
    node_x.health().record(url_b, 10, false, true);
    assert!(node_x.health().alive_for(url_a));
    assert_eq!(rig.leaf("up"), "x");
    rig.store.remove("up");

    for _ in 0..3 {
        node_b.health().record(url_a, 20, false, true);
    }
    assert_eq!(rig.leaf_at("s", "w1.org"), "b");
    for _ in 0..10 {
        node_b.health().record(url_a, 0, true, false);
    }
    assert_eq!(node_b.health().median_delay_for(url_a), None);
    assert_eq!(rig.leaf_at("s", "w2.org"), "a");

    let up = rig.out.group("up").unwrap();
    let sp = rig.out.group("sp").unwrap();
    let _ = rig.leaf_at("sp", "warm-before.org");
    let old_up_members = up.members();
    let old_sp_members = sp.members();
    let old_x = rig.out.node("x").unwrap();

    let prov = rig.out.provider("p").unwrap();
    prov.side_load(b"proxies:\n  - {name: x, type: direct}\n  - {name: y, type: direct}\n")
        .await
        .unwrap();
    let new_x = rig.out.node("x").unwrap();
    assert!(!old_x.same(&new_x));
    new_x.health().record(url_a, 30, false, true);
    assert_eq!(rig.leaf("up"), "x");
    let _ = take_align_scans();
    assert_eq!(rig.leaf_at("sp", "after-reload.org"), "x");
    assert_eq!(take_align_scans(), 1);
    assert_eq!(rig.leaf_at("sp", "claimed-second.org"), "x");
    assert_eq!(take_align_scans(), 0);

    let new_up_members = up.members();
    let new_sp_members = sp.members();
    let _ = up.url_test_pick_with(&old_up_members, 0);
    let _ = sp.smart().unwrap().candidates(&sp, &old_sp_members);
    let _ = take_url_test_scans();
    let _ = take_table_builds();
    assert_eq!(
        up.url_test_pick_with(&new_up_members, 0).name().as_ref(),
        "x"
    );
    let _ = sp.smart().unwrap().candidates(&sp, &new_sp_members);
    assert_eq!(take_url_test_scans(), 0);
    assert_eq!(take_table_builds(), 0);

    drop(old_up_members);
    drop(old_sp_members);
    let _ = take_url_test_scans();
    let _ = take_table_builds();
    old_x.health().record(url_a, 5, false, true);
    assert_eq!(rig.leaf("up"), "x");
    assert_eq!(rig.leaf_at("sp", "still-cached.org"), "x");
    assert_eq!(take_url_test_scans(), 0);
    assert_eq!(take_table_builds(), 0);
}

#[test]
fn concurrent_records_and_picks_always_converge_to_final_health_state() {
    let rig = Arc::new(Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
proxy-groups:
  - {{name: u, type: url-test, proxies: [a, b], url: '{TEST_URL}'}}
  - {{name: s, type: smart, proxies: [a, b], url: '{TEST_URL}'}}
"
    )));
    let a = rig.out.node("a").unwrap();
    let b = rig.out.node("b").unwrap();

    std::thread::scope(|scope| {
        for tid in 0..4 {
            let rig = Arc::clone(&rig);
            scope.spawn(move || {
                for i in 0..200 {
                    let _ = rig.leaf("u");
                    let _ = rig.leaf_at("s", &format!("t{tid}-{i}.org"));
                }
            });
        }
        scope.spawn(|| {
            for round in 1..=200u16 {
                a.health().record(TEST_URL, 200 - (round % 50), false, true);
                b.health().record(TEST_URL, 50 + (round % 50), false, true);
            }
            for _ in 0..10 {
                a.health().record(TEST_URL, 10, false, true);
                b.health().record(TEST_URL, 500, false, true);
            }
        });
    });

    assert_eq!(rig.leaf("u"), "a");
    assert_eq!(rig.leaf_at("s", "final-check.org"), "a");
}

#[tokio::test(start_paused = true)]
async fn mid_scan_record_tags_pre_scan_epoch_and_forces_next_pick_to_rescan() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: ua, type: direct}}
  - {{name: ub, type: direct}}
  - {{name: sa, type: direct}}
  - {{name: sb, type: direct}}
proxy-groups:
  - {{name: u, type: url-test, proxies: [ua, ub], url: '{TEST_URL}', tolerance: 0}}
  - {{name: s, type: smart, proxies: [sa, sb], url: '{TEST_URL}', tolerance: 0}}
"
    ));

    let ua = rig.out.node("ua").unwrap();
    let ub = rig.out.node("ub").unwrap();
    ua.health().record(TEST_URL, 50, false, true);
    ub.health().record(TEST_URL, 100, false, true);
    let ua_hook = ua.clone();
    set_fastest_mid_scan(move || {
        ua_hook.health().record(TEST_URL, 0, true, false);
    });
    assert_eq!(rig.leaf("u"), "ua");
    let _ = take_url_test_scans();
    assert_eq!(rig.leaf("u"), "ub");
    assert_eq!(take_url_test_scans(), 1);

    let sa = rig.out.node("sa").unwrap();
    let sb = rig.out.node("sb").unwrap();
    sa.health().record(TEST_URL, 50, false, true);
    sb.health().record(TEST_URL, 100, false, true);
    let sa_hook = sa.clone();
    set_candidates_mid_scan(move || {
        for _ in 0..10 {
            sa_hook.health().record(TEST_URL, 0, true, false);
        }
    });
    assert_eq!(rig.leaf_at("s", "mid-1.org"), "sa");
    let _ = take_table_builds();
    assert_eq!(rig.leaf_at("s", "mid-2.org"), "sb");
    assert_eq!(take_table_builds(), 1);
}

#[tokio::test(start_paused = true)]
async fn record_between_no_and_yes_resolve_is_visible_on_yes() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
proxy-groups:
  - {{name: u, type: url-test, proxies: [a, b], url: '{TEST_URL}', tolerance: 0}}
  - {{name: s, type: smart, proxies: [a, b], url: '{TEST_URL}', tolerance: 0}}
"
    ));

    let a = rig.out.node("a").unwrap();
    let b = rig.out.node("b").unwrap();
    a.health().record(TEST_URL, 50, false, true);
    b.health().record(TEST_URL, 100, false, true);

    let u = rig.out.group("u").unwrap();
    let s = rig.out.group("s").unwrap();
    let flow = Rig::flow("ny.org");
    assert_eq!(u.pick(&flow, None, Touch::No).name(), "a");
    assert_eq!(s.pick(&flow, Some("ny.org"), Touch::No).name(), "a");

    for _ in 0..3 {
        b.health().record(TEST_URL, 10, false, true);
    }
    assert_eq!(u.pick(&flow, None, Touch::Yes).name(), "b");
    assert_eq!(s.pick(&flow, Some("ny.org"), Touch::Yes).name(), "b");
}

#[tokio::test(start_paused = true)]
async fn dirty_refresh_skips_unrelated_non_smart_groups_and_batches_route_moved() {
    let mut yaml = String::from("proxies:\n");
    for i in 0..10 {
        yaml.push_str(&format!("  - {{name: u{i}-a, type: direct}}\n"));
        yaml.push_str(&format!("  - {{name: u{i}-b, type: direct}}\n"));
    }
    for i in 0..5 {
        yaml.push_str(&format!("  - {{name: f{i}-a, type: direct}}\n"));
        yaml.push_str(&format!("  - {{name: f{i}-b, type: direct}}\n"));
    }
    for i in 0..4 {
        yaml.push_str(&format!("  - {{name: sel{i}-a, type: direct}}\n"));
        yaml.push_str(&format!("  - {{name: sel{i}-b, type: direct}}\n"));
    }
    yaml.push_str("  - {name: s0-a, type: direct}\n  - {name: s0-b, type: direct}\n");
    yaml.push_str("proxy-groups:\n");
    for i in 0..10 {
        yaml.push_str(&format!(
            "  - {{name: u{i}, type: url-test, proxies: [u{i}-a, u{i}-b], url: '{TEST_URL}'}}\n"
        ));
    }
    for i in 0..5 {
        yaml.push_str(&format!(
            "  - {{name: f{i}, type: fallback, proxies: [f{i}-a, f{i}-b], url: '{TEST_URL}'}}\n"
        ));
    }
    for i in 0..4 {
        yaml.push_str(&format!(
            "  - {{name: sel{i}, type: select, proxies: [sel{i}-a, sel{i}-b]}}\n"
        ));
    }
    yaml.push_str(&format!(
        "  - {{name: s0, type: smart, proxies: [s0-a, s0-b], url: '{TEST_URL}'}}\n"
    ));

    let rig = Rig::new(&yaml);
    let _ = take_refresh_visits();
    let moved_before = rig.moved.count();

    rig.out
        .node("u0-b")
        .unwrap()
        .health()
        .record(TEST_URL, 25, false, true);
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 2);
    assert_eq!(rig.moved.count(), moved_before + 1);

    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 1);
    assert_eq!(rig.moved.count(), moved_before + 1);

    rig.out
        .node("u1-b")
        .unwrap()
        .health()
        .record(TEST_URL, 20, false, true);
    rig.out
        .node("f0-a")
        .unwrap()
        .health()
        .record(TEST_URL, 0, true, false);
    rig.out
        .node("f0-b")
        .unwrap()
        .health()
        .record(TEST_URL, 30, false, true);
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 3);
    assert_eq!(rig.moved.count(), moved_before + 2);

    rig.out.refresh_picks();
    assert_eq!(take_refresh_visits(), 21);
    assert_eq!(rig.moved.count(), moved_before + 2);
}

#[tokio::test(start_paused = true)]
async fn dirty_refresh_handles_oscillation_provider_reload_probing_and_smart_decay() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
  - {{name: fa, type: direct}}
  - {{name: fb, type: direct}}
  - {{name: sa, type: direct}}
  - {{name: sb, type: direct}}
proxy-providers:
  p:
    type: http
    url: 'http://provider.test/p.yaml'
    path: 'p.yaml'
    payload:
      - {{name: x, type: direct}}
      - {{name: y, type: direct}}
proxy-groups:
  - {{name: u, type: url-test, proxies: [a, b], url: '{TEST_URL}'}}
  - {{name: f, type: fallback, proxies: [fa, fb], url: '{TEST_URL}'}}
  - {{name: sel, type: select, proxies: [a, b]}}
  - {{name: up, type: url-test, use: [p], url: '{TEST_URL}'}}
  - {{name: s, type: smart, proxies: [sa, sb], url: '{TEST_URL}', tolerance: 0}}
"
    ));

    let a = rig.out.node("a").unwrap();
    let b = rig.out.node("b").unwrap();
    let sa = rig.out.node("sa").unwrap();
    let sb = rig.out.node("sb").unwrap();
    a.health().record(TEST_URL, 50, false, true);
    b.health().record(TEST_URL, 100, false, true);
    sa.health().record(TEST_URL, 20, false, true);
    sb.health().record(TEST_URL, 60, false, true);
    rig.out.refresh_dirty_picks();

    let moved_before = rig.moved.count();
    let _ = take_refresh_visits();
    b.health().record(TEST_URL, 10, false, true);
    b.health().record(TEST_URL, 100, false, true);
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 2);
    assert_eq!(rig.moved.count(), moved_before);

    let prov = rig.out.provider("p").unwrap();
    prov.side_load(b"proxies:\n  - {name: x, type: direct}\n  - {name: y, type: direct}\n")
        .await
        .unwrap();
    assert_eq!(rig.moved.count(), moved_before + 1);
    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 2);
    assert_eq!(rig.moved.count(), moved_before + 1);

    prov.side_load(b"proxies:\n  - {name: y, type: direct}\n  - {name: x, type: direct}\n")
        .await
        .unwrap();
    assert_eq!(rig.moved.count(), moved_before + 2);
    let _ = rig.out.group("up").unwrap().members();
    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 2);
    assert_eq!(rig.moved.count(), moved_before + 3);

    let moved_sel = rig.moved.count();
    assert!(rig.out.select("sel", "b").await.unwrap());
    assert_eq!(rig.moved.count(), moved_sel + 1);
    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 1);
    assert_eq!(rig.moved.count(), moved_sel + 1);

    rig.out
        .node("fb")
        .unwrap()
        .health()
        .record(TEST_URL, 0, true, false);
    rig.out.refresh_dirty_picks();
    let staged = rig.out.stage_selection("f", "fb").unwrap();
    rig.out.refresh_dirty_picks();
    drop(staged);
    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 6);

    let moved_smart = rig.moved.count();
    let chain_sa: Vec<Arc<str>> = vec![Arc::from("sa"), Arc::from("s")];
    let err = io::Error::new(io::ErrorKind::TimedOut, "timed out");
    for _ in 0..3 {
        rig.out.smart_dial_failed(
            &chain_sa,
            Some("site-a.test"),
            &err,
            Duration::from_secs(5),
            true,
        );
        rig.out.smart_dial_failed(
            &chain_sa,
            Some("site-b.test"),
            &err,
            Duration::from_secs(5),
            true,
        );
    }
    rig.out.refresh_dirty_picks();
    assert_eq!(rig.leaf("s"), "sb");
    assert_eq!(rig.moved.count(), moved_smart + 1);

    tokio::time::advance(Duration::from_secs(60 * 60)).await;
    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 1);
    assert_eq!(rig.leaf("s"), "sa");
    assert_eq!(rig.moved.count(), moved_smart + 2);
}

#[tokio::test(start_paused = true)]
async fn dirty_refresh_preserves_mid_scan_marks_fallback_revocation_and_delay_events() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: fa, type: direct}}
  - {{name: fb, type: direct}}
  - {{name: ua, type: direct}}
  - {{name: ub, type: direct}}
proxy-groups:
  - {{name: f, type: fallback, proxies: [fa, fb], url: '{TEST_URL}'}}
  - {{name: u, type: url-test, proxies: [ua, ub], url: '{TEST_URL}', tolerance: 0}}
"
    ));

    let ua = rig.out.node("ua").unwrap();
    let ub = rig.out.node("ub").unwrap();
    ua.health().record(TEST_URL, 50, false, true);
    ub.health().record(TEST_URL, 100, false, true);
    rig.out.refresh_dirty_picks();

    // A record arriving after take_dirty() during a refresh scan must stay dirty for the next batch.
    ua.health().record(TEST_URL, 60, false, true);
    let ua_hook = ua.clone();
    set_fastest_mid_scan(move || {
        ua_hook.health().record(TEST_URL, 0, true, false);
    });
    let moved_mid = rig.moved.count();
    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 1);
    assert_eq!(rig.moved.count(), moved_mid);

    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 1);
    assert_eq!(rig.leaf("u"), "ub");
    assert_eq!(rig.moved.count(), moved_mid + 1);

    rig.out
        .node("fa")
        .unwrap()
        .health()
        .record(TEST_URL, 20, false, true);
    rig.out
        .node("fb")
        .unwrap()
        .health()
        .record(TEST_URL, 30, false, true);
    assert!(rig.out.select("f", "fb").await.unwrap());
    assert_eq!(rig.leaf("f"), "fb");

    let events_before = rig.events.delays().len();
    rig.book.get("fb").fail.store(true, Ordering::SeqCst);
    let _ = rig
        .out
        .test_delay("fb", TEST_URL, Duration::from_secs(2))
        .await;
    assert_eq!(rig.events.delays().len(), events_before + 1);

    let moved_before = rig.moved.count();
    let _ = take_refresh_visits();
    rig.out.refresh_dirty_picks();
    assert_eq!(take_refresh_visits(), 1);
    assert_eq!(rig.leaf("f"), "fa");
    assert_eq!(rig.moved.count(), moved_before + 2);
    assert_eq!(rig.store.take_revoked().await, vec![Arc::from("f")]);
}

#[tokio::test(start_paused = true)]
async fn dirty_refresh_matches_full_refresh_across_nested_global_select_empty_and_events() {
    let yaml = format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
  - {{name: fa, type: direct}}
  - {{name: fb, type: direct}}
  - {{name: sa, type: direct}}
  - {{name: sb, type: direct}}
proxy-providers:
  p:
    type: http
    url: 'http://provider.test/p.yaml'
    path: 'p.yaml'
    payload:
      - {{name: x, type: direct}}
      - {{name: y, type: direct}}
proxy-groups:
  - {{name: u, type: url-test, proxies: [a, b], url: '{TEST_URL}', tolerance: 0}}
  - {{name: f, type: fallback, proxies: [fa, fb], url: '{TEST_URL}'}}
  - {{name: sel, type: select, proxies: [a, b]}}
  - {{name: up, type: url-test, use: [p], url: '{TEST_URL}', tolerance: 0}}
  - {{name: s, type: smart, proxies: [sa, sb], url: '{TEST_URL}', tolerance: 0}}
  - {{name: nested, type: url-test, proxies: [u, f, a], url: '{TEST_URL}', tolerance: 0}}
  - {{name: nested_sel, type: select, proxies: [u, f]}}
"
    );

    async fn drain_revoked(rig: &Rig) -> Vec<Arc<str>> {
        tokio::time::timeout(Duration::ZERO, rig.store.take_revoked())
            .await
            .unwrap_or_default()
    }

    async fn assert_batch_eq(full_rig: &Rig, dirty_rig: &Rig, label: &str) {
        let flow = Rig::flow("diff.org");
        full_rig.out.refresh_picks();
        dirty_rig.out.refresh_dirty_picks();
        let full_now: Vec<(String, String)> = full_rig
            .out
            .groups()
            .iter()
            .filter(|g| g.is_selectable())
            .map(|g| (g.name().to_string(), g.now(&flow)))
            .collect();
        let dirty_now: Vec<(String, String)> = dirty_rig
            .out
            .groups()
            .iter()
            .filter(|g| g.is_selectable())
            .map(|g| (g.name().to_string(), g.now(&flow)))
            .collect();
        assert_eq!(dirty_now, full_now, "now mismatch at {label}");
        assert_eq!(
            dirty_rig.moved.count(),
            full_rig.moved.count(),
            "moved mismatch at {label}"
        );
        assert_eq!(
            dirty_rig.events.delays(),
            full_rig.events.delays(),
            "delay events mismatch at {label}"
        );
        let full_rev = drain_revoked(full_rig).await;
        let dirty_rev = drain_revoked(dirty_rig).await;
        assert_eq!(dirty_rev, full_rev, "revoked mismatch at {label}");
    }

    let full_rig = Rig::new(&yaml);
    let dirty_rig = Rig::new(&yaml);

    let both = [&full_rig, &dirty_rig];
    for rig in both {
        rig.out
            .node("a")
            .unwrap()
            .health()
            .record(TEST_URL, 50, false, true);
        rig.out
            .node("b")
            .unwrap()
            .health()
            .record(TEST_URL, 100, false, true);
        rig.out
            .node("fa")
            .unwrap()
            .health()
            .record(TEST_URL, 20, false, true);
        rig.out
            .node("fb")
            .unwrap()
            .health()
            .record(TEST_URL, 30, false, true);
        rig.out
            .node("sa")
            .unwrap()
            .health()
            .record(TEST_URL, 20, false, true);
        rig.out
            .node("sb")
            .unwrap()
            .health()
            .record(TEST_URL, 60, false, true);
        rig.out
            .node("u")
            .unwrap()
            .health()
            .record(TEST_URL, 15, false, true);
        rig.out
            .node("f")
            .unwrap()
            .health()
            .record(TEST_URL, 80, false, true);
    }
    assert_batch_eq(&full_rig, &dirty_rig, "initial-health").await;

    for rig in both {
        let b = rig.out.node("b").unwrap();
        b.health().record(TEST_URL, 10, false, true);
        b.health().record(TEST_URL, 100, false, true);
    }
    assert_batch_eq(&full_rig, &dirty_rig, "oscillation-a-b-a").await;

    for rig in both {
        rig.out
            .node("f")
            .unwrap()
            .health()
            .record(TEST_URL, 5, false, true);
    }
    assert_batch_eq(&full_rig, &dirty_rig, "nested-group-health").await;

    for rig in both {
        assert!(rig.out.select("GLOBAL", "u").await.unwrap());
        assert!(rig.out.select("nested_sel", "f").await.unwrap());
    }
    assert_batch_eq(&full_rig, &dirty_rig, "global-and-nested-select").await;

    for rig in both {
        rig.store.set("GLOBAL", "nested");
        rig.store.set("sel", "b");
    }
    assert_batch_eq(&full_rig, &dirty_rig, "store-set-global-and-sel").await;

    for rig in both {
        assert!(rig.out.select("sel", "").await.unwrap());
    }
    assert_batch_eq(&full_rig, &dirty_rig, "select-cleared-empty").await;

    for rig in both {
        rig.store.set("sel", "b");
    }
    assert_batch_eq(&full_rig, &dirty_rig, "select-set-via-store").await;
    for rig in both {
        rig.store.set("sel", "");
    }
    assert_batch_eq(&full_rig, &dirty_rig, "select-empty-via-store").await;

    for rig in both {
        rig.out
            .provider("p")
            .unwrap()
            .side_load(b"proxies:\n  - {name: x, type: direct}\n  - {name: y, type: direct}\n")
            .await
            .unwrap();
    }
    assert_batch_eq(&full_rig, &dirty_rig, "provider-same-name").await;

    for rig in both {
        rig.out
            .provider("p")
            .unwrap()
            .side_load(b"proxies:\n  - {name: y, type: direct}\n  - {name: x, type: direct}\n")
            .await
            .unwrap();
    }
    assert_batch_eq(&full_rig, &dirty_rig, "provider-reordered").await;

    for rig in both {
        assert!(rig.out.select("f", "fb").await.unwrap());
        rig.book.get("fb").fail.store(true, Ordering::SeqCst);
        let _ = rig
            .out
            .test_delay("fb", TEST_URL, Duration::from_secs(2))
            .await;
    }
    assert_batch_eq(&full_rig, &dirty_rig, "fallback-dead-pin-revoke").await;

    let chain_sa: Vec<Arc<str>> = vec![Arc::from("sa"), Arc::from("s")];
    let err = io::Error::new(io::ErrorKind::TimedOut, "timed out");
    for rig in both {
        for _ in 0..3 {
            rig.out.smart_dial_failed(
                &chain_sa,
                Some("site-a.test"),
                &err,
                Duration::from_secs(5),
                true,
            );
            rig.out.smart_dial_failed(
                &chain_sa,
                Some("site-b.test"),
                &err,
                Duration::from_secs(5),
                true,
            );
        }
    }
    assert_batch_eq(&full_rig, &dirty_rig, "smart-ejected").await;

    tokio::time::advance(Duration::from_secs(60 * 60)).await;
    assert_batch_eq(&full_rig, &dirty_rig, "smart-time-only-decay").await;
}
