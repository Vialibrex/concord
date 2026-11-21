use std::sync::atomic::Ordering;

use concord_common::CoreError;

use super::*;
use crate::FlowEnd;

fn config() -> String {
    format!(
        "proxies:
  - {{name: a, type: direct}}
  - {{name: b, type: direct}}
  - {{name: c, type: direct}}
proxy-groups:
  - {{name: s, type: smart, proxies: [a, b, c], url: '{TEST_URL}'}}
  - {{name: o, type: select, proxies: [s]}}
"
    )
}

fn chain(names: &[&str]) -> Vec<Arc<str>> {
    names.iter().map(|name| Arc::from(*name)).collect()
}

async fn delays(rig: &Rig, values: &[(&str, u64)]) {
    for (name, millis) in values {
        rig.book.get(name).set_delay(*millis);
        rig.test(name).await;
    }
}

fn budget(rig: &Rig, on: &[Arc<str>], tried: &[Arc<str>]) -> Option<Duration> {
    rig.out
        .smart_attempt_budget(on, &Rig::flow("example.com"), None, tried)
}

fn target_refused() -> io::Error {
    CoreError::TargetRefused("the target said no".into()).into()
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

#[tokio::test(start_paused = true)]
async fn a_site_stays_on_its_node_when_probes_later_favour_another() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
    delays(&rig, &[("a", 200), ("b", 20), ("c", 100)]).await;
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
    assert_eq!(rig.leaf_at("s", "three.org"), "b");
}

#[tokio::test(start_paused = true)]
async fn a_refusing_target_moves_only_its_site() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
    rig.out.smart_dial_failed(
        &chain(&["a", "s"]),
        Some("one.org"),
        &target_refused(),
        Duration::from_millis(40),
        false,
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(rig.leaf_at("s", "one.org"), "a");
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
    assert_eq!(rig.leaf_at("s", "three.org"), "a");
}

#[tokio::test(start_paused = true)]
async fn five_corroborated_timeouts_in_a_row_eject_the_node() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    for _ in 0..4 {
        rig.out.smart_dial_failed(
            &chain(&["a", "s"]),
            None,
            &timed_out(),
            Duration::from_secs(5),
            true,
        );
    }
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
    rig.out.smart_dial_failed(
        &chain(&["a", "s"]),
        None,
        &timed_out(),
        Duration::from_secs(5),
        true,
    );
    assert_ne!(rig.leaf_at("s", "three.org"), "a");
    assert_ne!(rig.leaf_at("s", "one.org"), "a");
}

#[tokio::test(start_paused = true)]
async fn a_dial_error_that_says_nothing_about_the_node_counts_for_nothing() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    let ignored = [
        io::Error::from(CoreError::UdpUnsupported("a".into())),
        io::Error::from(CoreError::Loopback("a".into())),
        io::Error::from(CoreError::DialerLoop("a".into())),
        io::Error::from(CoreError::Rejected("a".into())),
        io::Error::from(CoreError::FdPressure),
    ];
    for err in &ignored {
        for _ in 0..6 {
            rig.out
                .smart_dial_failed(&chain(&["a", "s"]), None, err, Duration::from_secs(5), true);
        }
    }
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
}

#[tokio::test(start_paused = true)]
async fn a_tls_flow_the_remote_closed_first_without_a_byte_demotes_the_node_for_its_site() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
    let site: Arc<str> = Arc::from("one.org");
    let flow = rig
        .out
        .smart_flow(&chain(&["a", "s"]), &site, true)
        .expect("the chain has a smart group");
    flow.on_upload();
    flow.finish(FlowEnd {
        download: 0,
        remote_first: Some(true),
        cancelled: false,
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_ne!(rig.leaf_at("s", "one.org"), "a");
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
}

#[tokio::test(start_paused = true)]
async fn a_flow_that_got_its_bytes_demotes_nothing() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    let site: Arc<str> = Arc::from("one.org");
    let flow = rig
        .out
        .smart_flow(&chain(&["a", "s"]), &site, true)
        .expect("the chain has a smart group");
    flow.on_upload();
    flow.on_download();
    flow.finish(FlowEnd {
        download: 100,
        remote_first: Some(true),
        cancelled: false,
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    assert!(
        rig.out
            .smart_flow(&chain(&["a", "DIRECT"]), &site, true)
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn a_network_change_makes_the_next_pick_of_a_site_start_fresh() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    delays(&rig, &[("a", 200), ("b", 20)]).await;
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    let before = rig.book.get("c").connects.load(Ordering::SeqCst);
    rig.out.network_changed();
    assert_eq!(rig.leaf_at("s", "one.org"), "b");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(rig.book.get("c").connects.load(Ordering::SeqCst) > before);
}

#[tokio::test(start_paused = true)]
async fn a_redial_skips_what_was_tried_and_keeps_the_outer_part_of_the_chain() {
    let rig = Rig::new(&config());
    delays(&rig, &[("a", 50), ("b", 20), ("c", 100)]).await;
    let Resolved::Route { chain: first, .. } = rig.resolve("o") else {
        panic!("o does not resolve to a route");
    };
    assert_eq!(
        first.iter().map(|name| &**name).collect::<Vec<_>>(),
        ["b", "s", "o"]
    );
    let meta = Rig::flow("example.com");
    let member = rig
        .out
        .smart_member(&first)
        .expect("a smart group is on the chain");
    assert_eq!(&*member, "b");

    let (resolved, chosen) = rig
        .out
        .smart_retry(&first, &meta, None, std::slice::from_ref(&member))
        .expect("two members are left");
    let Resolved::Route {
        leaf,
        chain: retried,
        provider_chain,
        ..
    } = resolved
    else {
        panic!("a retry resolves to a route");
    };
    assert_eq!(&*chosen, "a");
    assert_eq!(&*leaf.info().name, "a");
    assert_eq!(
        retried.iter().map(|name| &**name).collect::<Vec<_>>(),
        ["a", "s", "o"]
    );
    assert_eq!(provider_chain.len(), retried.len());

    let (_, next) = rig
        .out
        .smart_retry(&first, &meta, None, &[member.clone(), chosen])
        .expect("one member is left");
    assert_eq!(&*next, "c");
    let all = chain(&["a", "b", "c"]);
    assert!(rig.out.smart_retry(&first, &meta, None, &all).is_none());
    assert!(
        rig.out
            .smart_retry(&chain(&["a", "DIRECT"]), &meta, None, &[])
            .is_none()
    );
}

#[tokio::test(start_paused = true)]
async fn a_redial_budget_waits_for_a_connect_sample_and_is_at_least_a_second() {
    let rig = Rig::new(&config());
    let on_a = chain(&["a", "s"]);
    let tried = chain(&["a"]);
    assert_eq!(budget(&rig, &on_a, &tried), None);
    assert_eq!(budget(&rig, &chain(&["a", "DIRECT"]), &tried), None);
    rig.out
        .smart_dial_succeeded(&on_a, Duration::from_millis(200));
    assert_eq!(budget(&rig, &on_a, &tried), Some(Duration::from_secs(1)));
    for _ in 0..3 {
        rig.out.smart_dial_succeeded(&on_a, Duration::from_secs(4));
    }
    let slow = budget(&rig, &on_a, &tried).expect("a sample exists");
    assert!(slow > Duration::from_secs(4), "{slow:?}");
    assert_eq!(budget(&rig, &chain(&["b", "s"]), &chain(&["b"])), None);
}

#[tokio::test(start_paused = true)]
async fn the_last_member_left_and_a_pinned_group_get_no_budget() {
    let rig = Rig::new(&config());
    let on_a = chain(&["a", "s"]);
    rig.out
        .smart_dial_succeeded(&on_a, Duration::from_millis(200));
    assert!(budget(&rig, &on_a, &chain(&["a", "b"])).is_some());
    assert_eq!(
        budget(&rig, &on_a, &chain(&["c", "b", "a"])),
        None,
        "every member was tried"
    );
    rig.out.select("s", "a").await;
    assert_eq!(rig.out.selection("s"), "a");
    assert_eq!(budget(&rig, &on_a, &chain(&["a"])), None);
}

#[tokio::test(start_paused = true)]
async fn an_ejected_member_left_untried_does_not_cut_an_attempt_short() {
    let rig = Rig::new(&config());
    let on_a = chain(&["a", "s"]);
    rig.out
        .smart_dial_succeeded(&on_a, Duration::from_millis(200));
    for _ in 0..5 {
        rig.out.smart_dial_failed(
            &chain(&["b", "s"]),
            None,
            &timed_out(),
            Duration::from_secs(5),
            true,
        );
    }
    assert!(budget(&rig, &on_a, &chain(&["a", "b"])).is_some());
    assert_eq!(
        budget(&rig, &on_a, &chain(&["a", "c"])),
        None,
        "only the ejected b is left"
    );
    let meta = Rig::flow("example.com");
    let (_, member) = rig
        .out
        .smart_retry(&on_a, &meta, None, &chain(&["a", "c"]))
        .expect("an ejected member is still a redial's last resort");
    assert_eq!(&*member, "b");
}

#[tokio::test(start_paused = true)]
async fn a_pinned_smart_group_does_not_redial() {
    let rig = Rig::new(&config());
    rig.out.select("s", "b").await;
    assert_eq!(rig.out.selection("s"), "b");
    let first = chain(&["b", "s", "o"]);
    let meta = Rig::flow("example.com");
    assert!(
        rig.out
            .smart_retry(&first, &meta, None, &chain(&["b"]))
            .is_none()
    );
    rig.out.shared.selections.set("s", "gone");
    assert!(
        rig.out
            .smart_retry(&first, &meta, None, &chain(&["b"]))
            .is_some(),
        "a selection of a proxy that is no longer a member pins nothing"
    );
}

#[test]
fn only_node_level_failures_are_worth_a_redial() {
    assert!(Outbounds::smart_retryable(&timed_out()));
    assert!(Outbounds::smart_retryable(&io::Error::from(
        io::ErrorKind::ConnectionRefused
    )));
    assert!(Outbounds::smart_retryable(&io::Error::from(
        io::ErrorKind::ConnectionReset
    )));
    assert!(!Outbounds::smart_retryable(&target_refused()));
    assert!(!Outbounds::smart_retryable(&io::Error::from(
        CoreError::UdpUnsupported("a".into())
    )));
    assert!(!Outbounds::smart_retryable(&io::Error::from(
        CoreError::Rejected("a".into())
    )));
    assert!(!Outbounds::smart_retryable(&io::Error::from(
        CoreError::FdPressure
    )));
}

#[test]
fn a_site_is_the_registrable_domain_or_the_address_and_never_a_udp_flow() {
    let key =
        |flow: &FlowMeta, host| Outbounds::smart_site(flow, host).map(|site| site.to_string());
    assert_eq!(
        key(&Rig::flow("a.b.example.com"), None).as_deref(),
        Some("example.com")
    );
    assert_eq!(
        key(&Rig::flow("10.0.0.1"), None).as_deref(),
        Some("10.0.0.1")
    );
    assert_eq!(key(&Rig::flow("co.uk"), None), None);

    let mut by_ip = Rig::flow("example.com");
    by_ip.dst = Address::Socket(SocketAddr::from(([9, 9, 9, 9], 443)));
    assert_eq!(key(&by_ip, None).as_deref(), Some("9.9.9.9"));
    assert_eq!(
        key(&by_ip, Some("www.bbc.co.uk")).as_deref(),
        Some("bbc.co.uk")
    );

    let mut udp = Rig::flow("example.com");
    udp.network = Network::Udp;
    assert_eq!(key(&udp, None), None);
}

#[tokio::test(start_paused = true)]
async fn has_smart_sees_a_smart_group_outside_the_leaf_only() {
    let rig = Rig::new(&config());
    assert!(rig.out.has_smart(&chain(&["a", "s"])));
    assert!(rig.out.has_smart(&chain(&["a", "s", "o"])));
    assert!(!rig.out.has_smart(&chain(&["a", "o"])));
    assert!(!rig.out.has_smart(&chain(&["s"])));
}

#[tokio::test(start_paused = true)]
async fn a_test_round_begun_before_a_network_change_books_nothing() {
    let rig = Rig::new(&config());
    assert_eq!(rig.leaf_at("s", "one.org"), "a");
    let results = [
        (Arc::from("a"), false),
        (Arc::from("b"), true),
        (Arc::from("c"), true),
    ];
    let before = rig.out.smart_epochs();
    rig.out.network_changed();
    tokio::time::sleep(Duration::from_secs(1)).await;
    for _ in 0..5 {
        rig.out.feed_smart(TEST_URL, &results, &before);
    }
    assert_eq!(rig.leaf_at("s", "two.org"), "a");
    let now = rig.out.smart_epochs();
    for _ in 0..5 {
        rig.out.feed_smart(TEST_URL, &results, &now);
    }
    assert_ne!(rig.leaf_at("s", "three.org"), "a");
}
