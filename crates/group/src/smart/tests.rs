use std::sync::Arc;
use std::time::Duration;

use concord_common::sync::lock;

use super::*;

pub(super) const A: usize = 0;
pub(super) const B: usize = 1;
pub(super) const C: usize = 2;

pub(super) fn base() -> Stamp {
    Stamp::now()
}

pub(super) fn at(base: Stamp, secs: u64) -> Stamp {
    base.after(Duration::from_secs(secs))
}

pub(super) fn names(list: &[&str]) -> Vec<Arc<str>> {
    list.iter().map(|name| Arc::from(*name)).collect()
}

pub(super) fn cands<'a>(names: &'a [Arc<str>], delays: &[u16]) -> Vec<Candidate<'a>> {
    names
        .iter()
        .zip(delays)
        .map(|(name, delay)| Candidate {
            name,
            delay_ms: Some(*delay),
            factor: 1.0,
        })
        .collect()
}

pub(super) fn settings() -> Settings {
    Settings {
        tolerance_ms: 0,
        max_failed: 5,
        half_life: Duration::from_secs(300),
        probe_timeout: Duration::from_secs(5),
    }
}

pub(super) fn state() -> Arc<SmartState> {
    SmartState::new(settings())
}

pub(super) fn pick(
    state: &SmartState,
    now: Stamp,
    site: Option<&str>,
    cands: &[Candidate<'_>],
) -> usize {
    state.pick(now, site, cands, None, true).0
}

pub(super) fn pair(actions: &Actions) -> Option<(Arc<str>, Option<Arc<str>>)> {
    actions
        .arbitrate
        .as_ref()
        .map(|arbitration| (arbitration.suspect.clone(), arbitration.witness.clone()))
}

pub(super) fn timeout(state: &SmartState, now: Stamp, node: &str, corroborated: bool) -> Actions {
    state.dial_failed(
        now,
        node,
        None,
        FailKind::Timeout,
        Duration::from_secs(5),
        corroborated,
    )
}

pub(super) fn eject(state: &SmartState, now: Stamp, node: &str) -> Actions {
    let mut last = Actions::default();
    for _ in 0..5 {
        last = timeout(state, now, node, true);
    }
    last
}

pub(super) fn penalty(state: &SmartState, node: &str, now: Stamp) -> f64 {
    lock(&state.book)
        .nodes
        .get(node)
        .map_or(0.0, |node| node.penalty_ms(now, settings().half_life))
}

pub(super) fn left(state: &SmartState, node: &str, now: Stamp) -> Duration {
    lock(&state.book)
        .nodes
        .get(node)
        .map_or(Duration::ZERO, |node| node.ejection_left(now))
}

fn ok_round(state: &SmartState, now: Stamp, names: &[Arc<str>]) {
    let results: Vec<_> = names.iter().map(|name| (name.clone(), true)).collect();
    state.probe_round(now, &results);
}

#[test]
fn stamp_takes_the_larger_of_monotonic_and_wall_elapsed() {
    let base = base();
    let slept = Stamp {
        mono: base.mono,
        wall: base.wall + Duration::from_secs(90),
    };
    assert_eq!(slept.since(&base), Duration::from_secs(90));
    let stepped_back = Stamp {
        mono: base.mono + Duration::from_secs(10),
        wall: base.wall - Duration::from_secs(7200),
    };
    assert_eq!(stepped_back.since(&base), Duration::from_secs(10));
    assert_eq!(base.since(&at(base, 5)), Duration::ZERO);
}

#[test]
fn consecutive_failures_eject_and_the_multiplier_grows_then_decays() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 100]);
    pick(&state, t0, None, &cands);

    for _ in 0..4 {
        assert_eq!(timeout(&state, t0, "a", true), Actions::default());
    }
    let ejected = timeout(&state, t0, "a", true);
    assert_eq!(ejected.probe, vec![names[A].clone()]);
    assert_eq!(left(&state, "a", t0), Duration::from_secs(30));
    assert_eq!(pick(&state, t0, None, &cands), B);

    assert!(left(&state, "a", at(t0, 30)).is_zero());
    let second = at(t0, 31);
    eject(&state, second, "a");
    assert_eq!(left(&state, "a", second), Duration::from_secs(60));

    // 91 s is where the second ejection ends; 34 s later the multiplier has fallen from 2 to 0.
    let third = at(t0, 125);
    eject(&state, third, "a");
    assert_eq!(left(&state, "a", third), Duration::from_secs(30));
}

#[test]
fn ejection_time_is_capped_at_300_seconds() {
    let state = state();
    let mut now = base();
    for round in 1..=12u64 {
        eject(&state, now, "a");
        let span = left(&state, "a", now);
        assert_eq!(
            span,
            Duration::from_secs((30 * round).min(300)),
            "round {round}"
        );
        now = now.after(span);
    }
}

#[test]
fn the_next_probe_after_an_ejection_clears_the_counts() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    eject(&state, t0, "a");
    assert!(penalty(&state, "a", t0) > 4000.0);

    ok_round(&state, at(t0, 10), &names);
    assert!(
        penalty(&state, "a", at(t0, 10)) > 4000.0,
        "still ejected: the probe clears nothing"
    );

    ok_round(&state, at(t0, 31), &names);
    assert_eq!(penalty(&state, "a", at(t0, 31)), 0.0);
}

#[test]
fn twenty_percent_failures_move_the_default_and_one_failure_on_a_busy_node_does_not() {
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[100, 160]);

    let busy = state();
    let t0 = base();
    pick(&busy, t0, None, &cands);
    for _ in 0..100 {
        ok_round(&busy, t0, &names);
    }
    timeout(&busy, t0, "a", true);
    let (index, actions) = busy.pick(t0, None, &cands, None, true);
    assert_eq!(index, A);
    assert!(!actions.refresh);

    let flaky = state();
    pick(&flaky, t0, None, &cands);
    for round in 0..100 {
        if round % 5 == 4 {
            timeout(&flaky, t0, "a", true);
        } else {
            ok_round(&flaky, t0, &names);
        }
    }
    let (index, actions) = flaky.pick(t0, None, &cands, None, true);
    assert_eq!(index, B);
    assert!(actions.refresh);
}

#[test]
fn an_idle_node_returns_to_the_default_after_a_single_timeout_in_1994_seconds() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[100, 150]);
    assert_eq!(pick(&state, t0, None, &cands), A);
    timeout(&state, t0, "a", true);
    assert_eq!(pick(&state, t0, None, &cands), B);

    // 100 + 5000 * 2^(-t/300) < 150 first holds at t = 300 * log2(100) = 1993.16 s.
    let back = (1..4000)
        .find(|secs| state.default_index(at(t0, *secs), &cands) == A)
        .expect("the default comes back");
    assert_eq!(back, 1994);
}

#[test]
fn a_failure_is_held_until_arbitration_unless_corroborated() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, None, &cands);

    let direct = timeout(&state, t0, "a", true);
    assert_eq!(direct, Actions::default());
    assert!(penalty(&state, "a", t0) > 0.0);

    let held = timeout(&state, t0, "b", false);
    assert_eq!(
        pair(&held),
        Some((names[B].clone(), Some(names[A].clone())))
    );
    assert_eq!(penalty(&state, "b", t0), 0.0);

    state.arbitrated_now(t0, false, true);
    assert!(
        penalty(&state, "b", t0) > 0.0,
        "the witness answered: the failure is booked"
    );
}

#[test]
fn failures_are_dropped_when_both_arbitration_probes_fail() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    pick(&state, t0, None, &cands(&names, &[10, 20]));
    timeout(&state, t0, "b", false);
    state.arbitrated_now(t0, false, false);
    assert_eq!(penalty(&state, "b", t0), 0.0);
    let again = timeout(&state, t0, "b", false);
    assert!(again.arbitrate.is_some(), "the in-flight flag was released");
}

#[test]
fn fifty_failures_ask_for_one_arbitration() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c"]);
    pick(&state, t0, None, &cands(&names, &[10, 20, 30]));
    let asked = (0..50)
        .filter(|round| {
            timeout(&state, t0, ["a", "b", "c"][round % 3], false)
                .arbitrate
                .is_some()
        })
        .count();
    assert_eq!(asked, 1);
    state.arbitrated_now(t0, true, true);
    assert!(penalty(&state, "a", t0) > 0.0 && penalty(&state, "c", t0) > 0.0);
}

#[test]
fn a_failure_with_no_witness_is_settled_by_a_test_of_the_suspect_alone() {
    let state = state();
    let t0 = base();
    let names = names(&["a"]);
    pick(&state, t0, None, &cands(&names, &[10]));
    let held = timeout(&state, t0, "a", false);
    assert_eq!(pair(&held), Some((names[A].clone(), None)));
    assert_eq!(penalty(&state, "a", t0), 0.0);
    state.arbitrated_now(t0, true, false);
    assert!(penalty(&state, "a", t0) > 0.0);
}

#[test]
fn a_probe_round_where_every_result_failed_records_nothing() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    pick(&state, t0, None, &cands(&names, &[10, 20]));
    timeout(&state, t0, "a", false);
    let down: Vec<_> = names.iter().map(|name| (name.clone(), false)).collect();
    for round in 0..8 {
        assert_eq!(state.probe_round(at(t0, round), &down), Actions::default());
    }
    assert_eq!(penalty(&state, "a", t0), 0.0);
    assert!(left(&state, "a", at(t0, 8)).is_zero());
    state.arbitrated_now(t0, true, true);
    assert_eq!(
        penalty(&state, "a", t0),
        0.0,
        "the held failure went with the round"
    );

    let mixed = [(names[A].clone(), true), (names[B].clone(), false)];
    state.probe_round(t0, &mixed);
    assert!(penalty(&state, "b", t0) > 0.0);
}

#[test]
fn a_failed_test_of_one_node_is_held_and_keeps_the_other_held_failures() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c"]);
    pick(&state, t0, None, &cands(&names, &[10, 20, 30]));
    assert!(timeout(&state, t0, "a", false).arbitrate.is_some());
    state.probe_round(t0, &[(names[B].clone(), false)]);
    assert_eq!(penalty(&state, "b", t0), 0.0);
    state.arbitrated_now(t0, false, true);
    assert!(penalty(&state, "a", t0) > 0.0 && penalty(&state, "b", t0) > 0.0);
}

#[test]
fn a_node_failing_probes_five_rounds_in_a_row_is_ejected() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let mixed = [(names[A].clone(), false), (names[B].clone(), true)];
    let mut last = Actions::default();
    for round in 0..5 {
        last = state.probe_round(at(t0, round), &mixed);
    }
    assert_eq!(last.probe, vec![names[A].clone()]);
}

#[test]
fn a_node_without_a_delay_waits_and_none_at_all_means_the_first() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c"]);
    let none = |delay: Option<u16>| Candidate {
        name: &names[A],
        delay_ms: delay,
        factor: 1.0,
    };
    let cold = [
        none(None),
        Candidate {
            name: &names[B],
            delay_ms: None,
            factor: 1.0,
        },
    ];
    assert_eq!(pick(&state, t0, None, &cold), A);
    let warm = [
        none(None),
        Candidate {
            name: &names[B],
            delay_ms: Some(80),
            factor: 1.0,
        },
        Candidate {
            name: &names[C],
            delay_ms: Some(60),
            factor: 1.0,
        },
    ];
    assert_eq!(pick(&state, t0, None, &warm), C);
}

#[test]
fn the_priority_factor_divides_the_delay_and_tolerance_keeps_the_previous_default() {
    let t0 = base();
    let names = names(&["a", "b"]);
    let favoured = [
        Candidate {
            name: &names[A],
            delay_ms: Some(100),
            factor: 1.0,
        },
        Candidate {
            name: &names[B],
            delay_ms: Some(150),
            factor: 2.0,
        },
    ];
    assert_eq!(pick(&state(), t0, None, &favoured), B);

    let tolerant = SmartState::new(Settings {
        tolerance_ms: 50,
        ..settings()
    });
    assert_eq!(pick(&tolerant, t0, None, &cands(&names, &[100, 120])), A);
    assert_eq!(
        pick(&tolerant, t0, None, &cands(&names, &[140, 100])),
        A,
        "within 50 ms"
    );
    assert_eq!(pick(&tolerant, t0, None, &cands(&names, &[170, 100])), B);
}

#[test]
fn every_node_ejected_serves_the_one_whose_ejection_ends_first() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    eject(&state, t0, "b");
    eject(&state, at(t0, 10), "a");
    let now = at(t0, 12);
    assert_eq!(pick(&state, now, None, &cands), B);
    assert_eq!(pick(&state, now, Some("x"), &cands), B);
    assert_eq!(state.default_index(now, &cands), B);
}

#[test]
fn a_pin_is_honoured_until_its_node_is_ejected() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    let (index, actions) = state.pick(t0, Some("x"), &cands, Some("b"), true);
    assert_eq!((index, actions.revoke_pin), (B, false));
    assert_eq!(state.book_sites(), 0, "a pinned pick leaves no site memory");

    eject(&state, t0, "b");
    let (index, actions) = state.pick(t0, Some("x"), &cands, Some("b"), true);
    assert_eq!((index, actions.revoke_pin), (A, true));
    let (_, quiet) = state.pick(t0, Some("x"), &cands, Some("b"), false);
    assert_eq!(quiet, Actions::default());
}

#[test]
fn a_read_only_pick_changes_nothing() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let (index, actions) = state.pick(t0, Some("x"), &cands(&names, &[10, 20]), None, false);
    assert_eq!((index, actions), (A, Actions::default()));
    assert_eq!(state.book_sites(), 0);
    assert!(lock(&state.book).default.is_none());
    assert_eq!(state.default_index(t0, &cands(&names, &[30, 20])), B);
    assert!(lock(&state.book).default.is_none());
}

#[test]
fn reset_network_clears_everything_and_asks_for_a_full_round() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let cands = cands(&names, &[10, 20]);
    pick(&state, t0, Some("x"), &cands);
    eject(&state, t0, "a");
    timeout(&state, t0, "b", false);
    let actions = state.reset_network(t0);
    assert!(actions.probe_all);
    assert_eq!(state.book_sites(), 0);
    assert!(left(&state, "a", t0).is_zero());
    assert_eq!(penalty(&state, "a", t0), 0.0);
    state.arbitrated_now(t0, true, true);
    assert_eq!(penalty(&state, "b", t0), 0.0);
    assert_eq!(pick(&state, t0, None, &cands), A);
}

#[test]
fn a_node_that_leaves_the_candidates_is_forgotten() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    timeout(&state, t0, "b", true);
    pick(&state, t0, None, &cands(&names[..1], &[10]));
    assert!(!lock(&state.book).nodes.contains_key("b"));
}

#[test]
fn the_first_pick_is_not_a_change_but_a_later_move_is() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let (_, first) = state.pick(t0, None, &cands(&names, &[10, 20]), None, true);
    assert!(!first.refresh);
    let (_, moved) = state.pick(t0, None, &cands(&names, &[90, 20]), None, true);
    assert!(moved.refresh);
    let (_, same) = state.pick(t0, None, &cands(&names, &[90, 20]), None, true);
    assert!(!same.refresh);
}

impl SmartState {
    pub(super) fn book_sites(&self) -> usize {
        lock(&self.book).sites.len()
    }
}

#[test]
fn a_completed_dial_only_feeds_the_connect_time() {
    let state = state();
    let t0 = base();
    state.dial_succeeded(t0, "a", Duration::from_millis(80));
    state.dial_succeeded(t0, "a", Duration::from_millis(160));
    let srtt = lock(&state.book)
        .nodes
        .get("a")
        .and_then(|node| node.connect_srtt());
    assert!(srtt.is_some_and(|ms| (ms - 90.0).abs() < 1e-6));
    assert_eq!(penalty(&state, "a", t0), 0.0);
    let failed = state.dial_failed(t0, "a", None, FailKind::Other, Duration::from_secs(1), true);
    assert_eq!(failed, Actions::default());
    assert!(penalty(&state, "a", t0) > 0.0);
}
