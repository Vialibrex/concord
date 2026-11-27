use std::future::{pending, ready};
use std::time::Duration;

use super::owner::first_answer;
use super::tests::{A, B, C, at, base, cands, left, names, pair, penalty, pick, state, timeout};
use super::*;

fn site_timeout(state: &SmartState, now: Stamp, node: &str, site: &str) -> Actions {
    state.dial_failed(
        now,
        node,
        Some(site),
        FailKind::Timeout,
        Duration::from_secs(1),
        false,
    )
}

#[test]
fn two_dead_members_of_three_are_ejected_through_the_live_one() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c"]);
    pick(&state, t0, None, &cands(&names, &[10, 20, 30]));
    let mut asked = Vec::new();
    for _ in 0..12 {
        let Some(arbitration) = timeout(&state, t0, "a", false).arbitrate else {
            continue;
        };
        let live = arbitration.witness.as_deref() == Some("c");
        asked.push(arbitration.witness.clone());
        state.arbitrated(t0, arbitration.token, false, live);
        if !left(&state, "a", t0).is_zero() {
            break;
        }
    }
    assert_eq!(asked.first(), Some(&Some(names[B].clone())));
    assert!(
        asked
            .iter()
            .skip(1)
            .all(|witness| witness.as_ref() == Some(&names[C]))
    );
    assert!(!left(&state, "a", t0).is_zero(), "a was never ejected");
}

#[test]
fn both_tests_failing_drops_only_the_failures_held_before_they_began() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c"]);
    pick(&state, t0, None, &cands(&names, &[10, 20, 30]));
    let first = timeout(&state, t0, "a", false)
        .arbitrate
        .expect("an arbitration starts");
    assert_eq!(timeout(&state, t0, "a", false).arbitrate, None);
    let next = state.arbitrated(t0, first.token, false, false);
    assert_eq!(
        pair(&next),
        Some((names[A].clone(), Some(names[C].clone())))
    );
    assert_eq!(state.held(), (1, 1), "the later failure is still held");
    let token = next.arbitrate.map(|arbitration| arbitration.token);
    state.arbitrated(t0, token.unwrap_or_default(), false, true);
    assert!(penalty(&state, "a", t0) > 0.0);
    assert_eq!(state.held(), (0, 0));
}

#[test]
fn an_arbitration_from_before_a_network_change_settles_nothing() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    pick(&state, t0, None, &cands(&names, &[10, 20]));
    let old = timeout(&state, t0, "a", false)
        .arbitrate
        .expect("an arbitration starts");
    state.reset_network(t0);
    pick(&state, t0, None, &cands(&names, &[10, 20]));
    let new = timeout(&state, t0, "a", false)
        .arbitrate
        .expect("the change ended the old one");
    assert_ne!(old.token, new.token);
    assert_eq!(
        state.arbitrated(t0, old.token, true, true),
        Actions::default()
    );
    assert_eq!(penalty(&state, "a", t0), 0.0);
    assert_eq!(
        timeout(&state, t0, "a", false).arbitrate,
        None,
        "the new arbitration still runs"
    );
    state.arbitrated(t0, new.token, true, true);
    assert!(penalty(&state, "a", t0) > 0.0);
}

#[test]
fn a_test_started_before_a_network_change_settles_nothing() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    let epoch = state.epoch();
    state.reset_network(t0);
    let results = [(names[A].clone(), false), (names[B].clone(), true)];
    assert_eq!(state.probed(epoch, t0, &results), Actions::default());
    assert_eq!(penalty(&state, "a", t0), 0.0);
    state.probed(state.epoch(), t0, &results);
    assert!(penalty(&state, "a", t0) > 0.0);
}

#[test]
fn held_failures_are_bounded_in_number_and_count() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    pick(&state, t0, None, &cands(&names, &[10, 20]));
    for round in 0..3 {
        for site in 0..100 {
            site_timeout(&state, at(t0, round), "a", &format!("s{site}.org"));
        }
    }
    assert_eq!(state.held(), (PENDING_LIMIT, 64));
    for _ in 0..20 {
        site_timeout(&state, t0, "b", "same.org");
    }
    assert_eq!(
        state.held(),
        (PENDING_LIMIT, 63 + super::tests::settings().max_failed),
        "the oldest entry made room and one entry counts to max-failed-times"
    );
}

#[test]
fn an_arbitration_that_never_answered_is_replaced_after_twice_the_probe_timeout() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b"]);
    pick(&state, t0, None, &cands(&names, &[10, 20]));
    let lost = timeout(&state, t0, "a", false)
        .arbitrate
        .expect("an arbitration starts");
    assert_eq!(timeout(&state, at(t0, 9), "a", false).arbitrate, None);
    let again = timeout(&state, at(t0, 10), "a", false)
        .arbitrate
        .expect("the lost one is replaced");
    assert_ne!(again.token, lost.token);
    assert_eq!(
        state.arbitrated(at(t0, 11), lost.token, true, true),
        Actions::default()
    );
}

#[test]
fn a_single_member_down_for_a_while_is_not_ejected_when_it_comes_back() {
    let state = state();
    let t0 = base();
    let names = names(&["a"]);
    for round in 0..20 {
        let now = at(t0, round);
        pick(&state, now, None, &cands(&names, &[10]));
        if let Some(arbitration) = timeout(&state, now, "a", false).arbitrate {
            assert_eq!(arbitration.witness, None);
            state.arbitrated(now, arbitration.token, false, false);
        }
    }
    state.probe_round(at(t0, 21), &[(names[A].clone(), true)]);
    assert!(left(&state, "a", at(t0, 21)).is_zero());
    assert_eq!(penalty(&state, "a", at(t0, 21)), 0.0);
}

#[tokio::test(start_paused = true)]
async fn the_first_passing_test_settles_an_arbitration() {
    assert_eq!(
        first_answer(ready(true), Some(pending::<bool>())).await,
        (true, false)
    );
    assert_eq!(
        first_answer(pending::<bool>(), Some(ready(true))).await,
        (false, true)
    );
    let late = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        true
    };
    assert_eq!(first_answer(ready(false), Some(late)).await, (false, true));
    assert_eq!(
        first_answer(ready(false), Some(ready(false))).await,
        (false, false)
    );
    assert_eq!(
        first_answer(ready(false), None::<std::future::Ready<bool>>).await,
        (false, false)
    );
}

#[test]
fn a_witness_that_failed_and_left_the_group_can_witness_again_when_it_returns() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c"]);
    let all = cands(&names, &[10, 20, 30]);
    pick(&state, t0, None, &all);
    let first = timeout(&state, t0, "a", false)
        .arbitrate
        .expect("an arbitration starts");
    assert_eq!(first.witness.as_deref(), Some("b"));
    assert_eq!(timeout(&state, t0, "a", false).arbitrate, None);
    let next = state.arbitrated(t0, first.token, false, false);
    assert_eq!(
        pair(&next),
        Some((names[A].clone(), Some(names[C].clone()))),
        "b failed as a witness"
    );
    let token = next.arbitrate.map(|arbitration| arbitration.token);
    state.arbitrated(t0, token.unwrap_or_default(), false, false);
    let without_b = [names[A].clone(), names[C].clone()];
    pick(&state, t0, None, &cands(&without_b, &[10, 30]));
    pick(&state, t0, None, &all);
    let again = timeout(&state, at(t0, 1), "a", false)
        .arbitrate
        .expect("an arbitration starts");
    assert_eq!(again.witness.as_deref(), Some("b"));
}

#[test]
fn the_live_members_left_are_the_redial_order_before_the_ejected() {
    let state = state();
    let t0 = base();
    let names = names(&["a", "b", "c", "d"]);
    let all = cands(&names, &[40, 10, 30, 20]);
    pick(&state, t0, None, &all);
    for _ in 0..super::tests::settings().max_failed {
        timeout(&state, t0, "c", true);
    }
    let tried = [names[A].clone()];
    let order = state.retry_order(t0, &all.view(), &tried);
    let mut live = state.live_untried(t0, all.names(), &tried);
    assert_eq!(order.last(), Some(&C), "the ejected c comes last");
    let mut before_ejected = order[..order.len() - 1].to_vec();
    before_ejected.sort_unstable();
    live.sort_unstable();
    assert_eq!(live, before_ejected);
}
