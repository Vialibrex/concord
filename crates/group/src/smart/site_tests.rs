use std::time::Duration;

use tokio::time::advance;

use super::tests::{
    A, B, C, at, base, cands, eject, names, pair, penalty, pick, settings, state, timeout,
};
use super::*;

fn target_refused(state: &SmartState, now: Stamp, node: &str, site: &str) -> Actions {
    state.dial_failed(
        now,
        node,
        Some(site),
        FailKind::TargetRefused,
        Duration::from_millis(100),
        true,
    )
}

fn answered(state: &Arc<SmartState>, node: &str, site: &str) {
    let tap = state.flow(Arc::from(node), Arc::from(site), false);
    tap.on_upload();
    tap.on_download();
    tap.finish(FlowEnd {
        download: 1,
        remote_first: None,
        cancelled: false,
    });
}

#[test]
fn a_site_sticks_to_its_node_and_never_moves_for_a_faster_probe() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    assert_eq!(pick(&state, t0, Some("x"), &cands(&names, &[10, 20])), A);
    assert_eq!(pick(&state, t0, Some("x"), &cands(&names, &[90, 20])), A);
    assert_eq!(pick(&state, t0, Some("y"), &cands(&names, &[90, 20])), B);
    assert_eq!(pick(&state, t0, None, &cands(&names, &[90, 20])), B);
}

#[test]
fn a_site_entry_expires_an_hour_after_its_last_use_and_each_use_renews_it() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let faster_b = cands(&names, &[90, 20]);
    pick(&state, t0, Some("x"), &cands(&names, &[10, 20]));
    assert_eq!(pick(&state, at(t0, 3599), Some("x"), &faster_b), A);
    assert_eq!(pick(&state, at(t0, 3599 + 3599), Some("x"), &faster_b), A);
    assert_eq!(state.book_sites(), 1);
    assert_eq!(
        pick(&state, at(t0, 3599 + 3599 + 3600), Some("x"), &faster_b),
        B
    );

    let idle = self::state();
    pick(&idle, t0, Some("x"), &cands(&names, &[10, 20]));
    assert_eq!(pick(&idle, at(t0, 3600), Some("x"), &faster_b), B);
}

#[test]
fn a_device_sleep_expires_sites_and_a_wall_clock_step_back_does_not() {
    let t0 = base();
    let names = names(&["a", "b"]);
    let faster_b = cands(&names, &[90, 20]);

    let slept = state();
    pick(&slept, t0, Some("x"), &cands(&names, &[10, 20]));
    let woke = Stamp {
        mono: t0.mono,
        wall: t0.wall + Duration::from_secs(3601),
    };
    assert_eq!(pick(&slept, woke, Some("x"), &faster_b), B);

    let stepped = state();
    pick(&stepped, t0, Some("x"), &cands(&names, &[10, 20]));
    let back = Stamp {
        mono: t0.mono + Duration::from_secs(10),
        wall: t0.wall - Duration::from_secs(7200),
    };
    assert_eq!(pick(&stepped, back, Some("x"), &faster_b), A);
}

#[test]
fn the_site_table_holds_4096_entries() {
    let state = state();
    let t0 = base();
    let names = names(&["a"]);
    let cands = cands(&names, &[10]);
    for site in 0..SITE_LIMIT + 10 {
        pick(&state, t0, Some(&format!("s{site}")), &cands);
    }
    assert_eq!(state.book_sites(), SITE_LIMIT);
}

#[test]
fn a_target_refused_dial_demotes_the_node_for_that_site_only() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);
    pick(&state, t0, Some("y"), &cands);
    target_refused(&state, t0, "a", "x");
    assert_eq!(pick(&state, t0, Some("x"), &cands), B);
    assert_eq!(pick(&state, t0, Some("y"), &cands), A);
    assert_eq!(penalty(&state, "a", t0), 0.0);
}

#[test]
fn a_node_failure_with_a_site_demotes_it_for_the_site_as_well() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);
    state.dial_failed(
        t0,
        "a",
        Some("x"),
        FailKind::Timeout,
        Duration::from_secs(5),
        true,
    );
    assert_eq!(pick(&state, t0, Some("x"), &cands), B);
    assert!(penalty(&state, "a", t0) > 0.0);
}

#[test]
fn a_refused_connect_is_booked_once_without_a_test() {
    let state = state();
    let t0 = base();
    let actions = state.dial_failed(
        t0,
        "a",
        None,
        FailKind::Refused,
        Duration::from_millis(3),
        false,
    );
    assert_eq!(actions, Actions::default());
    assert!(penalty(&state, "a", t0) > 0.0);
}

#[tokio::test(start_paused = true)]
async fn a_tls_flow_the_remote_closed_first_without_a_download_demotes_the_node() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);

    let tap = state.flow(names[A].clone(), Arc::from("x"), true);
    tap.on_upload();
    let held = tap.finish(FlowEnd {
        download: 0,
        remote_first: Some(true),
        cancelled: false,
    });
    assert_eq!(
        pair(&held),
        Some((names[A].clone(), Some(names[B].clone())))
    );
    assert_eq!(pick(&state, t0, Some("x"), &cands), A, "held, not booked");
    state.arbitrated_now(t0, true, true);
    assert_eq!(pick(&state, t0, Some("x"), &cands), B);
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_or_locally_closed_flow_is_not_a_failure() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);
    for (remote_first, cancelled) in [(Some(true), true), (Some(false), false), (None, false)] {
        let tap = state.flow(names[A].clone(), Arc::from("x"), true);
        tap.on_upload();
        let actions = tap.finish(FlowEnd {
            download: 0,
            remote_first,
            cancelled,
        });
        assert_eq!(actions, Actions::default());
    }
    let dropped = state.flow(names[A].clone(), Arc::from("x"), true);
    dropped.on_upload();
    drop(dropped);
    state.arbitrated_now(t0, true, true);
    assert_eq!(pick(&state, t0, Some("x"), &cands), A);
}

#[tokio::test(start_paused = true)]
async fn a_tls_flow_without_a_download_for_three_seconds_is_judged_once() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);
    let tap = state.flow(names[A].clone(), Arc::from("x"), true);
    tap.on_upload();

    advance(Duration::from_millis(2900)).await;
    let early = state.pick(
        at(t0, 0).after(Duration::from_millis(2900)),
        Some("y"),
        &cands,
        None,
        true,
    );
    assert_eq!(early.1, Actions::default());

    advance(Duration::from_millis(200)).await;
    let late = state.pick(at(t0, 3), Some("y"), &cands, None, true).1;
    assert_eq!(
        pair(&late),
        Some((names[A].clone(), Some(names[B].clone())))
    );
    state.arbitrated_now(at(t0, 3), true, true);
    assert_eq!(pick(&state, at(t0, 3), Some("x"), &cands), B);

    let again = state.pick(at(t0, 4), Some("y"), &cands, None, true).1;
    assert_eq!(again.arbitrate, None);
    advance(Duration::from_secs(2)).await;
    let ended = tap.finish(FlowEnd {
        download: 0,
        remote_first: Some(true),
        cancelled: false,
    });
    assert_eq!(ended, Actions::default());
}

#[tokio::test(start_paused = true)]
async fn a_slow_flow_that_ends_after_three_seconds_counts_even_when_cancelled() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    pick(&state, t0, Some("x"), &cands(&names, &[10, 20]));
    let tap = state.flow(names[A].clone(), Arc::from("x"), true);
    tap.on_upload();
    advance(Duration::from_secs(4)).await;
    let ended = tap.finish(FlowEnd {
        download: 0,
        remote_first: None,
        cancelled: true,
    });
    assert!(ended.arbitrate.is_some());
}

#[tokio::test(start_paused = true)]
async fn a_download_books_a_success_and_answers_the_flow() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);
    timeout(&state, t0, "a", true);
    let before = penalty(&state, "a", t0);
    answered(&state, "a", "x");
    assert!(penalty(&state, "a", t0) < before);

    let tap = state.flow(names[A].clone(), Arc::from("x"), true);
    tap.on_upload();
    tap.on_download();
    advance(Duration::from_secs(10)).await;
    assert_eq!(
        state
            .pick(at(t0, 10), Some("y"), &cands, None, true)
            .1
            .arbitrate,
        None
    );
}

#[test]
fn failures_on_two_distinct_sites_without_a_success_count_against_the_node() {
    let state = SmartState::new(Settings {
        max_failed: 2,
        ..settings()
    });
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    for site in ["x", "y", "z"] {
        pick(&state, t0, Some(site), &cands);
    }
    assert_eq!(target_refused(&state, t0, "a", "x"), Actions::default());
    assert_eq!(penalty(&state, "a", t0), 0.0);
    assert_eq!(target_refused(&state, t0, "a", "x"), Actions::default());
    assert_eq!(
        penalty(&state, "a", t0),
        0.0,
        "the same site twice is one site"
    );

    assert_eq!(target_refused(&state, t0, "a", "y"), Actions::default());
    assert!(
        penalty(&state, "a", t0) > 0.0,
        "the second site books one failure"
    );

    let ejected = target_refused(&state, t0, "a", "z");
    assert_eq!(
        ejected.probe,
        vec![names[A].clone()],
        "each further site books one more"
    );
}

#[tokio::test(start_paused = true)]
async fn a_success_between_site_failures_resets_the_escalation() {
    let state = SmartState::new(Settings {
        max_failed: 2,
        ..settings()
    });
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    for site in ["x", "y"] {
        pick(&state, t0, Some(site), &cands);
    }
    target_refused(&state, t0, "a", "x");
    answered(&state, "a", "w");
    target_refused(&state, t0, "a", "y");
    assert_eq!(penalty(&state, "a", t0), 0.0);
}

#[tokio::test(start_paused = true)]
async fn a_site_that_demoted_three_nodes_stays_on_the_one_that_answered_fastest() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c"]);
    let cands = cands(&names, &[10, 20, 30]);
    assert_eq!(pick(&state, t0, Some("x"), &cands), A);
    for (node, millis) in [("a", 200), ("b", 100), ("c", 300)] {
        let tap = state.flow(Arc::from(node), Arc::from("x"), false);
        tap.on_upload();
        advance(Duration::from_millis(millis)).await;
        tap.on_download();
    }
    let now = at(t0, 1);
    target_refused(&state, now, "a", "x");
    assert_eq!(pick(&state, now, Some("x"), &cands), B);
    target_refused(&state, now, "b", "x");
    assert_eq!(pick(&state, now, Some("x"), &cands), C);
    target_refused(&state, now, "c", "x");
    for _ in 0..3 {
        assert_eq!(
            pick(&state, now, Some("x"), &cands),
            B,
            "fixed on the least srtt"
        );
    }
    assert_eq!(
        pick(&state, now, Some("y"), &cands),
        A,
        "other sites are not affected"
    );
}

#[test]
fn a_site_whose_every_node_is_demoted_keeps_a_node_instead_of_returning_none() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);
    target_refused(&state, t0, "a", "x");
    pick(&state, t0, Some("x"), &cands);
    target_refused(&state, t0, "b", "x");
    let index = pick(&state, t0, Some("x"), &cands);
    assert!(index == A || index == B);
}

#[test]
fn a_site_on_an_ejected_node_moves_and_comes_back_to_the_default_afterwards() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    assert_eq!(pick(&state, t0, Some("x"), &cands), A);
    eject(&state, t0, "a");
    assert_eq!(pick(&state, t0, Some("x"), &cands), B);
    assert_eq!(
        pick(&state, at(t0, 40), Some("x"), &cands),
        B,
        "no move back: the entry stays"
    );
}

#[test]
fn udp_uses_the_default_not_the_site_memory() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    pick(&state, t0, Some("x"), &cands(&names, &[10, 20]));
    assert_eq!(pick(&state, t0, None, &cands(&names, &[90, 20])), B);
    assert_eq!(pick(&state, t0, Some("x"), &cands(&names, &[90, 20])), A);
}
