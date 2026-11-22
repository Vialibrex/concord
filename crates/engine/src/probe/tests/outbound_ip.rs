use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::probe::outbound_ip::mentions_ip;
use crate::probe::testing::{FakeEnv, Resp, Server, exit_name, handler, serve, serve_fn};
use crate::probe::{OutboundIpResult, Prober, RouteHit};

fn hit(host: &str, proxy: &str, exit: &str) -> RouteHit {
    RouteHit {
        host: host.into(),
        proxy: proxy.into(),
        exit: exit.into(),
    }
}

fn urls(servers: &[&Server]) -> Vec<String> {
    servers.iter().map(|server| server.url("")).collect()
}

async fn lookup(prober: &Prober, proxy: &str, urls: &[String], timeout: i64) -> OutboundIpResult {
    prober.outbound_ip(proxy, urls, timeout).await
}

#[tokio::test]
async fn takes_the_first_usable_answer() {
    let env = FakeEnv::new(&["node-a"]);
    let slow = serve_fn(|_| Resp::ok("slow").delayed(Duration::from_millis(400))).await;
    let empty = serve_fn(|_| Resp::status(204)).await;
    let quick = serve_fn(|_| Resp::ok("ip=203.0.113.7")).await;

    let answer = lookup(
        &env.prober(),
        "node-a",
        &urls(&[&slow, &empty, &quick]),
        4000,
    )
    .await;

    assert_eq!(answer.error, None, "{answer:?}");
    assert_eq!(answer.body, "ip=203.0.113.7");
    assert_eq!(answer.url, quick.url(""));
    assert_eq!(answer.chains, ["node-a"]);
}

#[tokio::test]
async fn skips_an_answer_without_an_address() {
    let env = FakeEnv::new(&["node-a"]);
    let limited = serve_fn(|_| Resp::ok(r#"{"error":"rate limited"}"#)).await;
    let later = serve_fn(|_| {
        Resp::ok(r#"{"ip":"2001:db8::7","country":"JP"}"#).delayed(Duration::from_millis(200))
    })
    .await;

    let answer = lookup(&env.prober(), "node-a", &urls(&[&limited, &later]), 4000).await;

    assert_eq!(answer.url, later.url(""));
}

#[test]
fn an_address_has_to_be_whole() {
    let cases = [
        ("fl=12f\nip=203.0.113.7\nts=1700000000.1", true),
        (r#"{"ip":"2001:db8::7","country":"JP"}"#, true),
        (r#"{"ip":"::ffff:203.0.113.7"}"#, true),
        (r#"a::after{content:""}"#, false),
        ("div::before,li::marker{color:#fff}", false),
        ("::-webkit-scrollbar{width:0}", false),
        (r#"<a href="http://127.0.0.1/login">"#, false),
    ];
    for (body, want) in cases {
        assert_eq!(mentions_ip(body), want, "mentions_ip({body:?})");
    }
}

#[test]
fn local_addresses_do_not_count() {
    for body in [
        "ip=192.168.1.1",
        r#"{"ip":"10.20.30.40"}"#,
        "ip=172.16.0.9",
        "ip=100.64.12.34",
        "ip=100.127.255.254",
        r#"{"ip":"fd00::1"}"#,
        r#"{"ip":"::ffff:192.168.1.1"}"#,
        "ip=169.254.1.1",
        "ip=0.0.0.0",
        "ip=255.255.255.255",
    ] {
        assert!(!mentions_ip(body), "mentions_ip({body:?})");
    }
    assert!(mentions_ip("ip=100.128.0.1"));
}

#[tokio::test]
#[allow(clippy::disallowed_methods, reason = "loopback test server")]
async fn drops_the_losers_once_the_race_is_won() {
    let env = FakeEnv::new(&["node-a"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let losing = listener.local_addr().unwrap();
    let closed = Arc::new(AtomicBool::new(false));
    let seen_closed = closed.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 1024];
        while stream.read(&mut buffer).await.unwrap_or(0) > 0 {}
        seen_closed.store(true, Ordering::SeqCst);
    });
    let winning = serve_fn(|_| Resp::ok("ip=203.0.113.9")).await;
    let sources = vec![format!("http://{losing}"), winning.url("")];

    let answer = lookup(&env.prober(), "node-a", &sources, 5000).await;

    assert_eq!(answer.body, "ip=203.0.113.9");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !closed.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the losing request kept running");
}

#[tokio::test]
async fn a_lookup_from_an_older_epoch_is_cancelled() {
    let env = FakeEnv::new(&["node-a"]);
    let (reached_tx, mut reached) = tokio::sync::mpsc::unbounded_channel();
    let hanging = serve(handler(move |_| {
        let _ = reached_tx.send(());
        Resp::ok("").delayed(Duration::from_secs(3))
    }))
    .await;
    let winning = serve_fn(|_| Resp::ok("ip=203.0.113.9")).await;
    let prober = Arc::new(env.prober());

    env.set_stamp(1, 0);
    let older = {
        let prober = prober.clone();
        let sources = urls(&[&hanging]);
        tokio::spawn(async move { prober.outbound_ip("node-a", &sources, 5000).await })
    };
    reached.recv().await.unwrap();
    env.set_stamp(2, 0);
    lookup(&prober, "node-a", &urls(&[&winning]), 5000).await;

    let answer = tokio::time::timeout(Duration::from_secs(2), older)
        .await
        .expect("the lookup from the older epoch kept running")
        .unwrap();
    assert_eq!(answer.error, Some("failed"));
    assert_eq!(answer.core_epoch, 1);
}

#[tokio::test]
async fn a_lookup_from_the_same_epoch_is_left_alone() {
    let env = FakeEnv::new(&["node-a"]);
    let (reached_tx, mut reached) = tokio::sync::mpsc::unbounded_channel();
    let slow = serve(handler(move |_| {
        let _ = reached_tx.send(());
        Resp::ok("ip=203.0.113.7").delayed(Duration::from_millis(300))
    }))
    .await;
    let fast = serve_fn(|_| Resp::ok("ip=203.0.113.9")).await;
    let prober = Arc::new(env.prober());

    env.set_stamp(1, 0);
    let first = {
        let prober = prober.clone();
        let sources = urls(&[&slow]);
        tokio::spawn(async move { prober.outbound_ip("node-a", &sources, 5000).await })
    };
    reached.recv().await.unwrap();
    lookup(&prober, "node-a", &urls(&[&fast]), 5000).await;

    assert_eq!(first.await.unwrap().body, "ip=203.0.113.7");
}

#[tokio::test]
async fn reports_failure_when_every_source_fails() {
    let env = FakeEnv::new(&["node-a"]);
    let broken = serve_fn(|_| Resp::status(500)).await;

    let answer = lookup(&env.prober(), "node-a", &urls(&[&broken, &broken]), 3000).await;

    assert_eq!(answer.error, Some("failed"));
}

#[tokio::test]
async fn a_sweep_that_runs_out_of_time_reports_a_timeout() {
    let env = FakeEnv::new(&["node-a"]);
    let stuck = serve_fn(|_| Resp::ok("ip=203.0.113.9").delayed(Duration::from_secs(3))).await;

    let answer = lookup(&env.prober(), "node-a", &urls(&[&stuck]), 200).await;

    assert_eq!(answer.error, Some("timeout"));
}

#[tokio::test]
async fn an_empty_source_list_is_a_failure_with_the_stamp() {
    let env = FakeEnv::new(&["node-a"]);
    env.set_stamp(7, 42);

    let answer = lookup(&env.prober(), "node-a", &[], 1000).await;

    let OutboundIpResult {
        url,
        body,
        delay,
        chains,
        error,
        core_epoch,
        route_version,
        hits,
        node_hits,
    } = answer;
    assert_eq!((url, body, delay), (String::new(), String::new(), 0));
    assert!(chains.is_empty() && hits.is_empty() && node_hits.is_empty());
    assert_eq!(error, Some("failed"));
    assert_eq!((core_epoch, route_version), (7, 42));
}

#[tokio::test]
async fn the_answer_carries_the_stamp_and_the_exit_it_reached() {
    let env = FakeEnv::new(&["node-a", "DIRECT"]);
    env.set_stamp(7, 42);
    let server = serve_fn(|_| Resp::ok("ip=203.0.113.7")).await;
    let host = server.addr.to_string();

    let routed = lookup(&env.prober(), "", &urls(&[&server]), 4000).await;
    assert_eq!((routed.core_epoch, routed.route_version), (7, 42));
    assert_eq!(routed.hits, [hit(&host, "", &exit_name("DIRECT"))]);
    assert_eq!(
        routed.node_hits,
        [hit(&host, "DIRECT", &exit_name("DIRECT"))]
    );

    let pinned = lookup(&env.prober(), "node-a", &urls(&[&server]), 4000).await;
    assert_eq!(pinned.hits, [hit(&host, "node-a", &exit_name("node-a"))]);
}

#[tokio::test]
async fn a_failed_lookup_still_names_its_exit() {
    let env = FakeEnv::new(&["node-a"]);
    let dead = serve_fn(|_| Resp::ok("")).await;
    let sources = urls(&[&dead]);
    let host = dead.addr.to_string();
    env.refuse.store(true, Ordering::SeqCst);

    let failed = lookup(&env.prober(), "node-a", &sources, 2000).await;
    assert_eq!(failed.error, Some("failed"));
    assert_eq!(failed.hits, [hit(&host, "node-a", &exit_name("node-a"))]);

    let missing = lookup(&env.prober(), "gone", &sources, 2000).await;
    assert_eq!(missing.hits, [hit("", "gone", "")]);
}

#[tokio::test]
async fn the_node_under_a_group_is_reported_beside_the_target() {
    let env = FakeEnv::new(&["group-x", "node-of-group-x"]);
    let server = serve_fn(|_| Resp::ok("ip=203.0.113.7")).await;
    let host = server.addr.to_string();

    let answer = lookup(&env.prober(), "group-x", &urls(&[&server]), 4000).await;

    assert_eq!(answer.chains, ["node-of-group-x", "group-x"]);
    assert_eq!(
        answer.node_hits,
        [hit(&host, "node-of-group-x", &exit_name("node-of-group-x"))]
    );
    assert_eq!(answer.hits[0].proxy, "group-x");
}
