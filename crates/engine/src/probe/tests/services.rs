use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::probe::Prober;
use crate::probe::ctx::ProbeError;
use crate::probe::fetch::ProbeResult;
use crate::probe::services::{
    AVAILABLE, Checker, FAILED, RESTRICTED, ServiceItem, TIMEOUT, UNAVAILABLE, UNSUPPORTED_REGION,
    item_from, status_from_code, trace_ip, trace_value,
};
use crate::probe::testing::FakeEnv;

fn item(status: &'static str) -> ServiceItem {
    ServiceItem::with_status(status)
}

fn stub(name: &str, item: ServiceItem) -> Checker {
    Checker::new(name, move |_| {
        let item = item.clone();
        Box::pin(async move { item })
    })
}

fn prober(checkers: Vec<Checker>) -> Arc<Prober> {
    Arc::new(Prober::with_checkers(FakeEnv::new(&[]), checkers))
}

fn names(items: &Value) -> Vec<&str> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect()
}

fn strings(names: &[&str]) -> Vec<String> {
    names.iter().map(ToString::to_string).collect()
}

#[tokio::test]
async fn runs_every_checker_by_default() {
    let prober = prober(vec![
        stub(
            "alpha",
            ServiceItem {
                region: "US".into(),
                ..item(AVAILABLE)
            },
        ),
        stub("beta", item(UNSUPPORTED_REGION)),
    ]);

    let items = prober.services("", &[], 1000).await;

    assert_eq!(names(&items), ["alpha", "beta"]);
    assert_eq!(items[0]["status"], AVAILABLE);
    assert_eq!(items[0]["region"], "US");
    assert_eq!(items[1]["status"], UNSUPPORTED_REGION);
    assert_eq!(items[1].get("region"), None);
    assert!(
        items
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["checked-at"].as_i64().unwrap() > 0)
    );
}

#[tokio::test]
async fn stamps_the_registered_name() {
    let prober = prober(vec![stub(
        "alpha",
        ServiceItem {
            name: "stale".into(),
            ..item(AVAILABLE)
        },
    )]);

    let items = prober.services("", &[], 1000).await;

    assert_eq!(items[0]["name"], "alpha");
}

#[tokio::test]
async fn keeps_the_requested_order() {
    let prober = prober(vec![
        stub("alpha", item(AVAILABLE)),
        stub("beta", item(AVAILABLE)),
        stub("gamma", item(AVAILABLE)),
    ]);

    let items = prober
        .services("", &strings(&["gamma", "alpha"]), 1000)
        .await;

    assert_eq!(names(&items), ["gamma", "alpha"]);
}

#[tokio::test]
async fn ignores_an_unknown_name() {
    let prober = prober(vec![stub("alpha", item(AVAILABLE))]);

    assert_eq!(
        prober.services("", &strings(&["nope"]), 1000).await,
        json!([])
    );
}

#[tokio::test]
async fn survives_a_panicking_rule() {
    let prober = prober(vec![
        Checker::new("boom", |_| {
            Box::pin(async { std::panic::panic_any("rule blew up") })
        }),
        stub("alpha", item(AVAILABLE)),
    ]);

    let items = prober.services("", &[], 1000).await;

    assert_eq!(items[0]["status"], FAILED);
    assert_eq!(items[1]["status"], AVAILABLE);
}

#[tokio::test]
async fn answers_carry_the_route_stamp() {
    let env = FakeEnv::new(&[]);
    env.set_stamp(7, 42);
    let prober = Prober::with_checkers(env, vec![stub("alpha", item(AVAILABLE))]);

    let items = prober.services("", &[], 1000).await;

    assert_eq!(
        (&items[0]["core-epoch"], &items[0]["route-version"]),
        (&json!(7), &json!(42))
    );
}

struct Tracker {
    state: Mutex<(i32, i32)>,
    total: AtomicI32,
}

impl Tracker {
    fn checker(self: &Arc<Self>, name: &str) -> Checker {
        let tracker = self.clone();
        Checker::new(name, move |_| {
            let tracker = tracker.clone();
            Box::pin(async move {
                {
                    let mut state = lock(&tracker.state);
                    state.0 += 1;
                    state.1 = state.1.max(state.0);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                lock(&tracker.state).0 -= 1;
                tracker.total.fetch_add(1, Ordering::SeqCst);
                item(AVAILABLE)
            })
        })
    }

    fn verify(&self, want: i32) {
        assert_eq!(self.total.load(Ordering::SeqCst), want);
        assert!(lock(&self.state).1 <= 4, "peak concurrency above the limit");
    }
}

fn tracker() -> Arc<Tracker> {
    Arc::new(Tracker {
        state: Mutex::new((0, 0)),
        total: AtomicI32::new(0),
    })
}

#[tokio::test]
async fn bounds_concurrency() {
    let tracker = tracker();
    let prober = prober((0..12).map(|_| tracker.checker("x")).collect());

    prober.services("", &[], 5000).await;

    tracker.verify(12);
}

#[tokio::test]
async fn bounds_concurrency_across_requests() {
    let tracker = tracker();
    let all: Vec<String> = (0..12).map(|index| format!("service-{index}")).collect();
    let prober = prober(all.iter().map(|name| tracker.checker(name)).collect());

    let requests: Vec<_> = all
        .into_iter()
        .map(|name| {
            let prober = prober.clone();
            tokio::spawn(async move { prober.services("", &[name], 5000).await })
        })
        .collect();
    for request in requests {
        request.await.unwrap();
    }

    tracker.verify(12);
}

async fn wait_for_claim(prober: &Prober, name: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !lock(&prober.claims.services).contains_key(name) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{name} was never claimed"));
}

#[tokio::test]
async fn drops_a_queued_check_asked_again() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let prober = prober(vec![Checker::new("alpha", move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { item(AVAILABLE) })
    })]);
    let held = prober
        .services
        .slots
        .clone()
        .try_acquire_many_owned(4)
        .unwrap();
    let ask = |prober: &Arc<Prober>| {
        let prober = prober.clone();
        tokio::spawn(async move { prober.services("", &strings(&["alpha"]), 5000).await })
    };

    let older = ask(&prober);
    wait_for_claim(&prober, "alpha").await;
    let newer = ask(&prober);

    let older = tokio::time::timeout(Duration::from_secs(2), older)
        .await
        .expect("a check queued for a slot kept waiting after its service was asked again")
        .unwrap();
    assert_eq!(older[0]["status"], FAILED);
    drop(held);
    let newer = tokio::time::timeout(Duration::from_secs(2), newer)
        .await
        .expect("the newer check never got a slot")
        .unwrap();
    assert_eq!(newer[0]["status"], AVAILABLE);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "only the newer check runs");
}

#[tokio::test]
async fn hands_the_cancelled_checks_slot_to_its_replacement() {
    let (started_tx, mut started) = mpsc::unbounded_channel();
    let checkers: Vec<Checker> = (0..4)
        .map(|index| {
            let name = format!("service-{index}");
            let calls = Arc::new(AtomicUsize::new(0));
            let started_tx = started_tx.clone();
            let label = name.clone();
            Checker::new(&name, move |env| {
                let calls = calls.clone();
                let started_tx = started_tx.clone();
                let label = label.clone();
                Box::pin(async move {
                    if calls.fetch_add(1, Ordering::SeqCst) > 0 {
                        return item(AVAILABLE);
                    }
                    let _ = started_tx.send(label);
                    env.ctx.done().await;
                    item(FAILED)
                })
            })
        })
        .collect();
    let prober = prober(checkers);
    let older: Vec<_> = (0..4)
        .map(|index| {
            let prober = prober.clone();
            tokio::spawn(async move {
                prober
                    .services("", &[format!("service-{index}")], 5000)
                    .await
            })
        })
        .collect();
    for _ in 0..4 {
        started.recv().await.unwrap();
    }

    let replacement = tokio::time::timeout(
        Duration::from_secs(2),
        prober.services("", &strings(&["service-0"]), 5000),
    )
    .await
    .expect("the replacement waited behind the checks every slot was held by");

    assert_eq!(replacement[0]["status"], AVAILABLE);
    for index in 1..4 {
        prober
            .services("", &[format!("service-{index}")], 5000)
            .await;
    }
    for older in older {
        older.await.unwrap();
    }
}

#[tokio::test]
async fn retries_a_timeout_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let prober = prober(vec![Checker::new("flaky", move |_| {
        let first = counted.fetch_add(1, Ordering::SeqCst) == 0;
        Box::pin(async move { item(if first { TIMEOUT } else { AVAILABLE }) })
    })]);

    let items = prober.services("", &[], 1000).await;

    assert_eq!(items[0]["status"], AVAILABLE);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn reports_a_repeated_timeout_after_one_retry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let prober = prober(vec![Checker::new("down", move |_| {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { item(TIMEOUT) })
    })]);

    let items = prober.services("", &[], 1000).await;

    assert_eq!(items[0]["status"], TIMEOUT);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cancels_the_older_check_of_the_same_service() {
    let (started_tx, mut started) = mpsc::unbounded_channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let alpha = Checker::new("alpha", move |env| {
        let first = counted.fetch_add(1, Ordering::SeqCst) == 0;
        let started_tx = started_tx.clone();
        Box::pin(async move {
            if !first {
                return item(AVAILABLE);
            }
            let _ = started_tx.send(());
            env.ctx.done().await;
            item(FAILED)
        })
    });
    let (beta_tx, mut beta_started) = mpsc::unbounded_channel();
    let beta = Checker::new("beta", move |env| {
        let beta_tx = beta_tx.clone();
        Box::pin(async move {
            let _ = beta_tx.send(());
            tokio::select! {
                _ = env.ctx.done() => item(FAILED),
                () = tokio::time::sleep(Duration::from_millis(200)) => item(AVAILABLE),
            }
        })
    });
    let prober = prober(vec![alpha, beta]);
    let older = {
        let prober = prober.clone();
        tokio::spawn(async move { prober.services("", &[], 5000).await })
    };
    started.recv().await.unwrap();
    beta_started.recv().await.unwrap();

    let newer = prober.services("", &strings(&["alpha"]), 5000).await;

    assert_eq!(newer[0]["status"], AVAILABLE);
    let older = tokio::time::timeout(Duration::from_secs(2), older)
        .await
        .expect("the older sweep kept running after its service was asked again")
        .unwrap();
    assert_eq!(older[0]["status"], FAILED);
    assert_eq!(older[1]["status"], AVAILABLE);
}

#[test]
fn status_follows_the_http_code() {
    for (code, want) in [
        (200, AVAILABLE),
        (204, AVAILABLE),
        (401, RESTRICTED),
        (403, RESTRICTED),
        (429, RESTRICTED),
        (451, RESTRICTED),
        (404, UNAVAILABLE),
        (500, UNAVAILABLE),
    ] {
        assert_eq!(status_from_code(code), want, "{code}");
    }
}

#[test]
fn transport_errors_map_to_a_status() {
    let timed_out = ProbeResult {
        error: Some(ProbeError::Timeout),
        delay: 900,
        ..ProbeResult::default()
    };
    let timed_out = item_from(Some(&timed_out));
    assert_eq!((timed_out.status, timed_out.delay), (TIMEOUT, 0));
    assert_eq!(item_from(None).status, FAILED);
    let ok = ProbeResult {
        status: 200,
        delay: 120,
        ..ProbeResult::default()
    };
    let judged = item_from(Some(&ok));
    assert_eq!((judged.status, judged.delay), ("", 120));
}

#[test]
fn trace_value_reads_a_key() {
    let body = "fl=abc\nip=203.0.113.7\nloc=JP\nwarp=off\n";
    assert_eq!(trace_value(body, "loc"), "JP");
    assert_eq!(trace_value(body, "colo"), "");
    assert_eq!(trace_value("loc=JP \r\n", "loc"), "JP");
    assert_eq!(trace_value("location=xx\n", "loc"), "");
}

#[test]
fn trace_ip_keeps_only_an_address() {
    for (body, want) in [
        ("ip=203.0.113.7\n", "203.0.113.7"),
        ("ip=::ffff:203.0.113.7\n", "203.0.113.7"),
        ("ip=2001:db8::1\n", "2001:db8::1"),
        ("ip=<html>blocked\n", ""),
        ("ip=\nloc=US\n", ""),
        ("loc=US\n", ""),
        ("<html>ip=203.0.113.7</>\n", ""),
    ] {
        assert_eq!(trace_ip(body), want, "{body:?}");
    }
}

#[test]
fn an_item_serializes_like_the_go_one() {
    let full = ServiceItem {
        name: "claude".into(),
        region: "JP".into(),
        ip: "198.51.100.9".into(),
        delay: 120,
        chains: vec!["node".into()],
        checked_at: 5,
        core_epoch: 1,
        route_version: 2,
        ..item(AVAILABLE)
    };
    assert_eq!(
        serde_json::to_value(full).unwrap(),
        json!({
            "name": "claude", "status": "available", "region": "JP", "ip": "198.51.100.9",
            "delay": 120,
            "chains": ["node"], "checked-at": 5, "core-epoch": 1, "route-version": 2,
        })
    );
    assert_eq!(
        serde_json::to_value(item(FAILED)).unwrap(),
        json!({"name": "", "status": "failed", "checked-at": 0, "core-epoch": 0, "route-version": 0})
    );
}
