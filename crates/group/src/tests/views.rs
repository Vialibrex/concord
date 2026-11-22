use super::*;
use crate::ProxyView;

const CONFIG: &str = "proxies:
  - {name: a, type: direct}
  - {name: b, type: direct}
proxy-providers:
  p:
    type: inline
    payload:
      - {name: n1, type: direct}
      - {name: ts, type: tailscale}
      - {name: a, type: direct}
proxy-groups:
  - {name: sel, type: select, proxies: [a, b], use: [p]}
  - {name: ut, type: url-test, proxies: [a, b], url: 'http://probe.test/generate_204', expected-status: '204', icon: bolt}
  - {name: lb, type: load-balance, proxies: [a], hidden: true}
  - {name: fb, type: fallback, proxies: [b], url: 'http://probe.test/generate_204'}
";

fn group(rig: &Rig, name: &str) -> crate::GroupView {
    match rig
        .out
        .views()
        .proxies
        .into_iter()
        .find(|(key, _)| key.as_ref() == name)
    {
        Some((_, ProxyView::Group(view))) => view,
        other => panic!("{name} is not a group view: {}", other.is_some()),
    }
}

#[tokio::test]
async fn the_group_list_puts_global_first_and_keeps_config_order() {
    let rig = Rig::new(CONFIG);
    let all: Vec<String> = rig
        .out
        .views()
        .all
        .iter()
        .map(|name| name.to_string())
        .collect();
    assert_eq!(all, ["GLOBAL", "sel", "ut", "lb", "fb"]);
}

#[tokio::test]
async fn proxies_list_builtins_nodes_provider_nodes_and_groups_without_ghosts() {
    let rig = Rig::new(CONFIG);
    let views = rig.out.views();
    let keys: Vec<&str> = views
        .proxies
        .iter()
        .map(|(name, _)| name.as_ref())
        .collect();
    for expected in [
        "DIRECT", "REJECT", "a", "b", "n1", "GLOBAL", "sel", "ut", "lb", "fb",
    ] {
        assert!(keys.contains(&expected), "{expected} missing from {keys:?}");
    }
    assert!(!keys.contains(&"ts"));
    assert_eq!(keys.iter().filter(|name| **name == "a").count(), 1);
}

#[tokio::test]
async fn a_provider_node_wins_a_name_it_shares_with_a_config_node() {
    let rig = Rig::new(CONFIG);
    let views = rig.out.views();
    let (_, view) = views
        .proxies
        .iter()
        .find(|(name, _)| name.as_ref() == "a")
        .unwrap();
    let ProxyView::Node(node) = view else {
        panic!("a node");
    };
    assert_eq!(node.provider.as_deref(), Some("p"));
}

#[tokio::test]
async fn a_selector_view_lists_members_and_hides_the_default_test_url() {
    let rig = Rig::new(CONFIG);
    let view = group(&rig, "sel");
    assert_eq!(view.kind, "Selector");
    assert_eq!(view.now.as_deref(), Some("a"));
    let all: Vec<&str> = view
        .all
        .as_ref()
        .unwrap()
        .iter()
        .map(|name| name.as_ref())
        .collect();
    assert_eq!(all, ["a", "b", "n1", "a"]);
    assert_eq!(view.test_url, "");
    assert_eq!(view.expected_status, None);
    assert_eq!(view.empty_fallback.as_ref(), "COMPATIBLE");
}

#[tokio::test]
async fn url_test_and_fallback_views_carry_the_url_the_fixed_pick_and_the_icon() {
    let rig = Rig::new(CONFIG);
    rig.out.select("ut", "b").await.unwrap();
    let ut = group(&rig, "ut");
    assert_eq!(ut.kind, "URLTest");
    assert_eq!(ut.test_url, TEST_URL);
    assert_eq!(ut.expected_status.as_deref(), Some("204"));
    assert_eq!(ut.fixed.as_deref(), Some("b"));
    assert_eq!(ut.now.as_deref(), Some("b"));
    assert_eq!(ut.icon, "bolt");
    let fb = group(&rig, "fb");
    assert_eq!(fb.kind, "Fallback");
    assert_eq!(fb.fixed.as_deref(), Some(""));
}

#[tokio::test]
async fn a_load_balancer_has_no_now_and_the_hidden_flag_follows_the_config() {
    let rig = Rig::new(CONFIG);
    let lb = group(&rig, "lb");
    assert_eq!(lb.now, None);
    assert!(lb.hidden);
    assert!(group(&rig, "GLOBAL").hidden);
    assert!(!group(&rig, "sel").hidden);
}

#[tokio::test]
async fn an_emptied_group_lists_its_fallback_and_one_of_ghosts_lists_nothing() {
    let rig = Rig::new(
        "proxy-providers:
  p:
    type: inline
    payload:
      - {name: ts, type: tailscale}
      - {name: ok, type: direct}
proxy-groups:
  - {name: none, type: select, use: [p], filter: zzz}
  - {name: gone, type: select, use: [p], filter: ts}
",
    );
    let none = group(&rig, "none");
    assert_eq!(
        none.all
            .as_ref()
            .unwrap()
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
        ["COMPATIBLE"]
    );
    let gone = group(&rig, "gone");
    assert!(gone.all.as_ref().unwrap().is_empty());
    assert_eq!(gone.now.as_deref(), Some("ts"));
}
