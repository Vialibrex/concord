use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::{Policy, ProxyView};

fn smart_config(groups: &str) -> String {
    format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
  - {{name: c, type: direct}}
proxy-groups:
{groups}"
    )
}

async fn delays(rig: &Rig, values: &[(&str, u64)]) {
    for (name, millis) in values {
        rig.book.get(name).set_delay(*millis);
        rig.test(name).await;
    }
}

fn same_pick(rig: &Rig) -> String {
    static SITES: AtomicUsize = AtomicUsize::new(0);
    let host = format!("site{}.org", SITES.fetch_add(1, Ordering::SeqCst));
    let (url_test, smart) = (rig.leaf_at("u", &host), rig.leaf_at("s", &host));
    assert_eq!(url_test, smart);
    smart
}

#[tokio::test(start_paused = true)]
async fn a_smart_group_without_priority_picks_like_url_test_for_a_new_site() {
    let rig = Rig::new(&smart_config(&format!(
        "  - {{name: u, type: url-test, proxies: [a, b, c], url: '{TEST_URL}', tolerance: 30}}\n  - {{name: s, type: smart, proxies: [a, b, c], url: '{TEST_URL}', tolerance: 30}}\n"
    )));
    same_pick(&rig);
    delays(&rig, &[("a", 100), ("b", 50), ("c", 200)]).await;
    assert_eq!(same_pick(&rig), "b");
    delays(&rig, &[("a", 40)]).await;
    assert_eq!(same_pick(&rig), "b");
    rig.out.select("u", "b").await;
    rig.out.select("s", "b").await;
    assert_eq!(same_pick(&rig), "b");
}

#[tokio::test(start_paused = true)]
async fn a_factor_above_one_prefers_a_node_and_below_one_pushes_it_back() {
    let rig = Rig::new(&format!(
        "proxies:
  - {{name: x1, type: direct}}
  - {{name: y1, type: direct}}
proxy-groups:
  - {{name: plain, type: url-test, proxies: [x1, y1], url: '{TEST_URL}'}}
  - {{name: boost, type: smart, proxies: [x1, y1], url: '{TEST_URL}', policy-priority: 'y:2'}}
  - {{name: edge, type: smart, proxies: [x1, y1], url: '{TEST_URL}', policy-priority: 'y:1.5'}}
  - {{name: back, type: smart, proxies: [x1, y1], url: '{TEST_URL}', policy-priority: 'x:0.5'}}
  - {{name: none, type: smart, proxies: [x1, y1], url: '{TEST_URL}', policy-priority: 'zzz:5'}}
  - {{name: first, type: smart, proxies: [x1, y1], url: '{TEST_URL}', policy-priority: 'y:0.5;y1:10'}}
"
    ));
    delays(&rig, &[("x1", 100), ("y1", 150)]).await;
    let picks: Vec<String> = ["plain", "boost", "edge", "back", "none", "first"]
        .iter()
        .map(|name| rig.leaf(name))
        .collect();
    assert_eq!(picks, ["x1", "y1", "x1", "y1", "x1", "x1"]);
}

#[tokio::test(start_paused = true)]
async fn a_pattern_is_a_regex_when_it_compiles_and_a_substring_when_it_does_not() {
    let rig = Rig::new(&format!(
        r#"proxies:
  - {{name: "[HK] a", type: direct}}
  - {{name: us-1, type: direct}}
proxy-groups:
  - {{name: plain, type: url-test, proxies: ["[HK] a", us-1], url: '{TEST_URL}'}}
  - {{name: sub, type: smart, proxies: ["[HK] a", us-1], url: '{TEST_URL}', policy-priority: '[HK:2'}}
  - {{name: re, type: smart, proxies: ["[HK] a", us-1], url: '{TEST_URL}', policy-priority: '^us-[0-9]$:0.5'}}
"#
    ));
    delays(&rig, &[("[HK] a", 150), ("us-1", 100)]).await;
    let picks: Vec<String> = ["plain", "sub", "re"]
        .iter()
        .map(|name| rig.leaf(name))
        .collect();
    assert_eq!(picks, ["us-1", "[HK] a", "[HK] a"]);
}

#[tokio::test]
async fn a_smart_group_is_named_smart_and_shows_its_pin_as_fixed() {
    let rig = Rig::new(&smart_config(&format!(
        "  - {{name: s, type: smart, proxies: [a, b], url: '{TEST_URL}', icon: bolt}}\n"
    )));
    let group = rig.out.group("s").unwrap();
    assert_eq!(group.type_name(), "Smart");
    assert!(matches!(group.policy(), Policy::Smart { .. }));
    assert!(group.is_selectable());
    assert_eq!(group.fixed(), "");
    assert!(rig.out.select("s", "b").await.changed);
    assert_eq!(group.fixed(), "b");
    let view = match rig
        .out
        .views()
        .proxies
        .into_iter()
        .find(|(key, _)| key.as_ref() == "s")
    {
        Some((_, ProxyView::Group(view))) => view,
        _ => panic!("s is not a group view"),
    };
    assert_eq!(view.kind, "Smart");
    assert_eq!(view.fixed.as_deref(), Some("b"));
    assert_eq!(view.now.as_deref(), Some("b"));
    assert_eq!(view.test_url, TEST_URL);
}

#[tokio::test(start_paused = true)]
async fn repeated_dial_failures_make_a_smart_group_test_its_members() {
    let rig = Rig::new(&smart_config(&format!(
        "  - {{name: s, type: smart, proxies: [a, b], url: '{TEST_URL}', max-failed-times: 2}}\n"
    )));
    let connects = |name: &str| rig.book.get(name).connects.load(Ordering::SeqCst);
    let chain: Vec<Arc<str>> = vec![Arc::from("a"), Arc::from("s")];
    let err = io::Error::new(io::ErrorKind::TimedOut, "i/o timeout");
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Tcp, &err);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(connects("a"), 0);
    rig.out
        .note_dial_failed(&chain, OutboundKind::Shadowsocks, Network::Udp, &err);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!((connects("a"), connects("b")), (1, 1));
}
