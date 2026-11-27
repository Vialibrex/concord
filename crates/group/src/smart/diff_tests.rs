use std::sync::Arc;
use std::time::Duration;

use concord_common::sync::lock;
use indexmap::IndexMap;

use super::book::Book;
use super::node::NodeState;
use super::site::Site;
use super::tests::{TestCands, at, base, eject, names, settings, timeout};
use super::*;

struct RefCand<'a> {
    name: &'a Arc<str>,
    delay_ms: Option<u16>,
    factor: f64,
}

fn ref_cands<'a>(names: &'a [Arc<str>], delays: &[u16]) -> Vec<RefCand<'a>> {
    names
        .iter()
        .zip(delays)
        .map(|(name, &delay)| RefCand {
            name,
            delay_ms: Some(delay),
            factor: 1.0,
        })
        .collect()
}

fn prod_cands(raw: &[RefCand<'_>]) -> TestCands {
    let names: Vec<Arc<str>> = raw.iter().map(|c| c.name.clone()).collect();
    let delays: Vec<Option<u16>> = raw.iter().map(|c| c.delay_ms).collect();
    let factors: Vec<f64> = raw.iter().map(|c| c.factor).collect();
    TestCands::from_parts(&names, &delays, &factors)
}

struct RefRow<'a> {
    name: &'a Arc<str>,
    score: Option<f64>,
    ejected: bool,
    left: Duration,
    aligned: bool,
}

fn ref_decay(dt: Duration, half_life: Duration) -> f64 {
    if half_life.is_zero() {
        return 1.0;
    }
    (-dt.as_secs_f64() / half_life.as_secs_f64()).exp2()
}

fn ref_state_of<'n>(
    nodes: &'n IndexMap<Arc<str>, NodeState>,
    index: usize,
    name: &Arc<str>,
) -> (Option<&'n NodeState>, bool) {
    let at = nodes
        .get_index(index)
        .filter(|(held, _)| Arc::ptr_eq(held, name) || *held == name);
    match at {
        Some((_, state)) => (Some(state), true),
        None => (nodes.get(&**name), false),
    }
}

fn ref_rows<'a>(
    nodes: &IndexMap<Arc<str>, NodeState>,
    now: Stamp,
    candidates: &'a [RefCand<'a>],
    half_life: Duration,
) -> Vec<RefRow<'a>> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let (state, aligned) = ref_state_of(nodes, index, candidate.name);
            let factor = if candidate.factor.is_finite() && candidate.factor > 0.0 {
                candidate.factor
            } else {
                1.0
            };
            let penalty = state.map_or(0.0, |state| {
                let (successes, failures, counted_at, t_fail_ms) = state.raw_penalty_parts();
                let k = ref_decay(now.since(&counted_at), half_life);
                let (s, f) = (successes * k, failures * k);
                f / (s + 1.0) * t_fail_ms.unwrap_or(0.0)
            });
            RefRow {
                name: candidate.name,
                score: candidate
                    .delay_ms
                    .map(|delay| f64::from(delay) / factor + penalty),
                ejected: state.is_some_and(|state| state.ejected(now)),
                left: state.map_or(Duration::ZERO, |state| state.ejection(now).1),
                aligned,
            }
        })
        .collect()
}

fn ref_default_of(
    rows: &[RefRow<'_>],
    previous: Option<&str>,
    tolerance: f64,
    allowed: impl Fn(&RefRow<'_>) -> bool,
) -> Option<usize> {
    let mut best: Option<(usize, f64)> = None;
    let mut first = None;
    for (index, row) in rows
        .iter()
        .enumerate()
        .filter(|(_, row)| !row.ejected && allowed(row))
    {
        first.get_or_insert(index);
        if let Some(score) = row.score
            && best.is_none_or(|(_, least)| score < least)
        {
            best = Some((index, score));
        }
    }
    let (best, least) = best.map_or((None, 0.0), |(index, score)| (Some(index), score));
    let Some(best) = best else {
        return first;
    };
    let kept = previous
        .and_then(|name| {
            rows.iter()
                .position(|row| &**row.name == name && !row.ejected && allowed(row))
        })
        .filter(|&index| {
            rows.get(index)
                .and_then(|row| row.score)
                .is_some_and(|score| score <= least + tolerance)
        });
    Some(kept.unwrap_or(best))
}

fn ref_soonest_ejected(
    rows: &[RefRow<'_>],
    allowed: impl Fn(&RefRow<'_>) -> bool,
) -> Option<usize> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| row.ejected && allowed(row))
        .min_by_key(|(_, row)| row.left)
        .map(|(index, _)| index)
}

fn ref_default_index(rows: &[RefRow<'_>], previous: Option<&str>, tolerance: f64) -> usize {
    ref_default_of(rows, previous, tolerance, |_| true)
        .or_else(|| ref_soonest_ejected(rows, |_| true))
        .unwrap_or(0)
}

fn ref_runner_up(rows: &[RefRow<'_>], best: usize) -> Option<usize> {
    rows.iter()
        .enumerate()
        .filter(|(index, row)| *index != best && !row.ejected)
        .min_by(|a, b| {
            let a = a.1.score.unwrap_or(f64::INFINITY);
            let b = b.1.score.unwrap_or(f64::INFINITY);
            a.total_cmp(&b)
        })
        .map(|(index, _)| index)
}

fn ref_least_srtt(
    rows: &[RefRow<'_>],
    site: &Site,
    allowed: impl Fn(&RefRow<'_>) -> bool,
) -> Option<usize> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| allowed(row))
        .filter_map(|(index, row)| site.srtt(row.name).map(|srtt| (index, srtt)))
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(index, _)| index)
}

fn ref_site_choice(
    rows: &[RefRow<'_>],
    entry: &Site,
    previous: Option<&str>,
    tolerance: f64,
    global: usize,
) -> usize {
    let current = rows
        .iter()
        .position(|row| **row.name == *entry.node)
        .filter(|&index| rows.get(index).is_some_and(|row| !row.ejected));
    if entry.problem {
        return current
            .or_else(|| ref_least_srtt(rows, entry, |row| !row.ejected))
            .unwrap_or(global);
    }
    if let Some(index) = current
        && !entry.is_demoted(&entry.node)
    {
        return index;
    }
    let open = |row: &RefRow<'_>| !entry.is_demoted(row.name);
    if let Some(index) = ref_default_of(rows, previous, tolerance, open) {
        return index;
    }
    ref_soonest_ejected(rows, open)
        .or_else(|| ref_least_srtt(rows, entry, |row| !row.ejected))
        .or(current)
        .unwrap_or(global)
}

struct RefSmart {
    settings: Settings,
    book: Book,
}

impl RefSmart {
    fn new(settings: Settings) -> Self {
        RefSmart {
            settings,
            book: Book::default(),
        }
    }

    fn pick(
        &mut self,
        now: Stamp,
        site: Option<&str>,
        candidates: &[RefCand<'_>],
        pin: Option<&str>,
        touch: bool,
    ) -> (usize, Actions) {
        let mut actions = Actions::default();
        if touch {
            self.book.sites.expire(now);
            actions.merge(self.book.judge_overdue(now, &self.settings));
        }
        let mut rows = ref_rows(&self.book.nodes, now, candidates, self.settings.half_life);
        let holds = self.book.nodes.len() == rows.len() && rows.iter().all(|row| row.aligned);
        if touch && !holds {
            let mut old = std::mem::take(&mut self.book.nodes);
            self.book.nodes = candidates
                .iter()
                .map(|candidate| {
                    let state = old
                        .swap_remove(&**candidate.name)
                        .unwrap_or_else(|| NodeState::new(now));
                    (candidate.name.clone(), state)
                })
                .collect();
            self.book.retain_failed_witnesses();
            rows = ref_rows(&self.book.nodes, now, candidates, self.settings.half_life);
        }
        let tolerance = f64::from(self.settings.tolerance_ms);
        let global = ref_default_index(&rows, self.book.default.as_deref(), tolerance);
        if touch {
            let name = rows.get(global).map(|row| row.name);
            if self.book.default.as_deref() != name.map(|n| &**n) {
                actions.refresh |= self.book.default.is_some() && name.is_some();
                self.book.default = name.cloned();
            }
            let runner = ref_runner_up(&rows, global)
                .and_then(|index| rows.get(index))
                .map(|row| row.name.clone());
            self.book.set_runner_up(runner);
        }
        if let Some(index) = pin.and_then(|pin| rows.iter().position(|row| &**row.name == pin)) {
            if rows.get(index).is_some_and(|row| !row.ejected) {
                let done = if touch {
                    self.book.finish(actions)
                } else {
                    Actions::default()
                };
                return (index, done);
            }
            actions.revoke_pin |= touch;
        }
        let index = match site {
            None => global,
            Some(site) => {
                let entry = self.book.sites.live(site, now);
                let live = entry.is_some();
                let index = entry.map_or(global, |entry| {
                    ref_site_choice(
                        &rows,
                        entry,
                        self.book.default.as_deref(),
                        tolerance,
                        global,
                    )
                });
                if touch && let Some(row) = rows.get(index) {
                    if live {
                        self.book.sites.renew(site, now);
                        self.book.sites.set_node(site, row.name);
                    } else {
                        self.book.sites.insert(site, row.name, now);
                    }
                }
                index
            }
        };
        let done = if touch {
            self.book.finish(actions)
        } else {
            Actions::default()
        };
        (index, done)
    }

    fn retry_order(
        &self,
        now: Stamp,
        candidates: &[RefCand<'_>],
        exclude: &[Arc<str>],
    ) -> Vec<usize> {
        let rows = ref_rows(&self.book.nodes, now, candidates, self.settings.half_life);
        let open = |row: &RefRow<'_>| !exclude.contains(row.name);
        let tolerance = f64::from(self.settings.tolerance_ms);
        let mut order: Vec<usize> =
            ref_default_of(&rows, self.book.default.as_deref(), tolerance, open)
                .into_iter()
                .collect();
        let mut scored: Vec<(usize, f64)> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| open(row) && !row.ejected)
            .filter_map(|(index, row)| row.score.map(|score| (index, score)))
            .collect();
        scored.sort_by(|a, b| a.1.total_cmp(&b.1));
        let unscored = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| open(row) && !row.ejected && row.score.is_none())
            .map(|(index, _)| index);
        let mut ejected: Vec<(usize, Duration)> = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| open(row) && row.ejected)
            .map(|(index, row)| (index, row.left))
            .collect();
        ejected.sort_by_key(|(_, left)| *left);
        let rest = scored
            .into_iter()
            .map(|(index, _)| index)
            .chain(unscored)
            .chain(ejected.into_iter().map(|(index, _)| index));
        for index in rest {
            if !order.contains(&index) {
                order.push(index);
            }
        }
        order
    }
}

#[test]
fn lazy_penalty_skips_exp2_for_healthy_unscored_and_ejected_nodes() {
    let total = 3000usize;
    let list: Vec<Arc<str>> = (0..total).map(|i| Arc::from(format!("n{i}"))).collect();
    let mut delays: Vec<Option<u16>> = (0..total).map(|i| Some(100 + (i % 50) as u16)).collect();
    let factors = vec![1.0; total];
    let members = crate::group::Members::for_test(&list, &factors);
    let state = SmartState::new(settings());
    let t0 = base();

    let view = CandidateView::from_delays(&members, &delays);
    let _ = state.pick(t0, None, &view, None, true);
    let _ = take_exp2_calls();

    let t1 = at(t0, 10);
    let _ = state.pick(t1, Some("example.com"), &view, None, true);
    assert_eq!(take_exp2_calls(), 0);

    for name in &list[..7] {
        timeout(&state, t1, name, true);
    }
    for name in &list[10..60] {
        eject(&state, t1, name);
    }
    for i in 100..200 {
        timeout(&state, t1, &list[i], true);
        delays[i] = None;
    }

    let view = CandidateView::from_delays(&members, &delays);
    let _ = take_exp2_calls();
    let _ = state.pick(t1, None, &view, None, true);
    assert_eq!(take_exp2_calls(), 0);

    let t2 = at(t1, 15);
    let _ = take_exp2_calls();
    let _ = state.pick(t2, None, &view, None, true);
    assert_eq!(take_exp2_calls(), 7);
}

#[test]
fn differential_pick_and_actions_match_reference_at_exact_boundaries() {
    let cfg = Settings {
        tolerance_ms: 20,
        ..settings()
    };
    let live = SmartState::new(cfg);
    let mut reference = RefSmart::new(cfg);
    let t0 = base();
    let list = names(&["a", "b", "c", "d", "e"]);

    let check_step = |reference: &mut RefSmart,
                      now: Stamp,
                      site: Option<&str>,
                      cs: &[RefCand<'_>],
                      pin: Option<&str>,
                      touch: bool,
                      label: &str| {
        let prod = prod_cands(cs);
        let got = live.pick(now, site, &prod.view(), pin, touch);
        let want = reference.pick(now, site, cs, pin, touch);
        assert_eq!(got, want, "pick mismatch at {label}");
    };

    let step1 = [
        RefCand {
            name: &list[0],
            delay_ms: None,
            factor: 0.0,
        },
        RefCand {
            name: &list[1],
            delay_ms: Some(100),
            factor: f64::NAN,
        },
        RefCand {
            name: &list[2],
            delay_ms: Some(120),
            factor: 1.0,
        },
        RefCand {
            name: &list[3],
            delay_ms: Some(120),
            factor: -2.0,
        },
        RefCand {
            name: &list[4],
            delay_ms: Some(100),
            factor: f64::INFINITY,
        },
    ];
    check_step(&mut reference, t0, Some("s1"), &step1, None, false, "no-1");
    check_step(&mut reference, t0, Some("s1"), &step1, None, true, "yes-1");

    let exact_tol = ref_cands(&list, &[150, 120, 100, 100, 100]);
    check_step(
        &mut reference,
        t0,
        None,
        &exact_tol,
        None,
        true,
        "exact-tol",
    );
    let over_tol = ref_cands(&list, &[150, 121, 100, 100, 100]);
    check_step(&mut reference, t0, None, &over_tol, None, true, "over-tol");

    let live2 = SmartState::new(settings());
    let mut ref2 = RefSmart::new(settings());
    let pair_names = names(&["a", "b"]);
    let pair_raw = ref_cands(&pair_names, &[100, 150]);
    let pair_prod = prod_cands(&pair_raw);
    assert_eq!(
        live2.pick(t0, None, &pair_prod.view(), None, true),
        ref2.pick(t0, None, &pair_raw, None, true)
    );
    timeout(&live2, t0, "a", true);
    let _ = ref2.book.report(
        t0,
        super::book::Failure {
            node: pair_names[0].clone(),
            site: None,
            site_level: false,
        },
        Duration::from_secs(5),
        true,
        &settings(),
    );
    for millis in [
        1_993_000u64,
        1_993_150,
        1_993_160,
        1_993_170,
        1_993_500,
        1_994_000,
    ] {
        let stamp = t0.after(Duration::from_millis(millis));
        let got_no = live2.pick(stamp, None, &pair_prod.view(), None, false);
        let want_no = ref2.pick(stamp, None, &pair_raw, None, false);
        assert_eq!(got_no, want_no, "non-int flip No at {millis}ms");
    }
    let after_flip = t0.after(Duration::from_millis(1_993_500));
    assert_eq!(
        live2
            .pick(after_flip, None, &pair_prod.view(), None, false)
            .0,
        0
    );

    check_step(
        &mut reference,
        t0,
        Some("s2"),
        &over_tol,
        Some("d"),
        true,
        "pin-live",
    );
    for _ in 0..5 {
        timeout(&live, t0, "d", true);
        let _ = ref_book_fail(&mut reference.book, t0, &list[3], &cfg);
    }
    check_step(
        &mut reference,
        t0,
        Some("s2"),
        &over_tol,
        Some("d"),
        false,
        "pin-ejected-no",
    );
    check_step(
        &mut reference,
        t0,
        Some("s2"),
        &over_tol,
        Some("d"),
        true,
        "pin-ejected-yes",
    );

    for (idx, secs) in [(0usize, 1u64), (1, 2), (2, 1), (4, 3)] {
        let stamp = at(t0, secs);
        for _ in 0..5 {
            timeout(&live, stamp, &list[idx], true);
            let _ = ref_book_fail(&mut reference.book, stamp, &list[idx], &cfg);
        }
    }
    let t_ejected = at(t0, 5);
    check_step(
        &mut reference,
        t_ejected,
        None,
        &over_tol,
        None,
        true,
        "all-ejected",
    );
}

fn ref_book_fail(book: &mut Book, now: Stamp, node: &Arc<str>, cfg: &Settings) -> Actions {
    book.report(
        now,
        super::book::Failure {
            node: node.clone(),
            site: None,
            site_level: false,
        },
        Duration::from_secs(5),
        true,
        cfg,
    )
}

#[test]
fn retry_order_matches_reference_across_ties_duplicates_ejected_and_3000_nodes() {
    let cfg = Settings {
        tolerance_ms: 30,
        ..settings()
    };
    let live = SmartState::new(cfg);
    let mut reference = RefSmart::new(cfg);
    let t0 = base();

    let list = names(&["a", "b", "c", "b", "d", "e", "f", "g"]);
    let cs = [
        RefCand {
            name: &list[0],
            delay_ms: Some(120),
            factor: 1.0,
        },
        RefCand {
            name: &list[1],
            delay_ms: Some(100),
            factor: 1.0,
        },
        RefCand {
            name: &list[2],
            delay_ms: Some(100),
            factor: 1.0,
        },
        RefCand {
            name: &list[3],
            delay_ms: Some(95),
            factor: 1.0,
        },
        RefCand {
            name: &list[4],
            delay_ms: None,
            factor: 1.0,
        },
        RefCand {
            name: &list[5],
            delay_ms: None,
            factor: 1.0,
        },
        RefCand {
            name: &list[6],
            delay_ms: Some(40),
            factor: 1.0,
        },
        RefCand {
            name: &list[7],
            delay_ms: Some(50),
            factor: 1.0,
        },
    ];
    let init = ref_cands(&list, &[10, 100, 100, 100, 100, 100, 100, 100]);
    let init_prod = prod_cands(&init);
    assert_eq!(
        live.pick(t0, None, &init_prod.view(), None, true),
        reference.pick(t0, None, &init, None, true)
    );

    for (idx, sec) in [(5usize, 1u64), (6, 2), (7, 2)] {
        let stamp = at(t0, sec);
        for _ in 0..5 {
            timeout(&live, stamp, &list[idx], true);
            let _ = ref_book_fail(&mut reference.book, stamp, &list[idx], &cfg);
        }
    }

    let now = at(t0, 4);
    let cs_prod = prod_cands(&cs);
    for exclude in [
        vec![],
        vec![list[0].clone()],
        vec![list[1].clone()],
        vec![
            list[0].clone(),
            list[1].clone(),
            list[2].clone(),
            list[4].clone(),
        ],
        list.clone(),
    ] {
        let got = live.retry_order(now, &cs_prod.view(), &exclude);
        let want = reference.retry_order(now, &cs, &exclude);
        assert_eq!(got, want, "retry_order mismatch for exclude={exclude:?}");
    }

    let big_names: Vec<Arc<str>> = (0..3000).map(|i| Arc::from(format!("p{i}"))).collect();
    let big_raw: Vec<RefCand<'_>> = big_names
        .iter()
        .enumerate()
        .map(|(i, name)| RefCand {
            name,
            delay_ms: (i % 7 != 0).then_some(((i * 37) % 500 + 1) as u16),
            factor: 1.0,
        })
        .collect();
    let big_prod = prod_cands(&big_raw);
    let big = SmartState::new(cfg);
    let mut big_ref = RefSmart::new(cfg);
    assert_eq!(
        big.pick(t0, None, &big_prod.view(), None, true),
        big_ref.pick(t0, None, &big_raw, None, true)
    );
    for (idx, sec) in [(5usize, 1u64), (17, 2), (2500, 1)] {
        let stamp = at(t0, sec);
        for _ in 0..5 {
            timeout(&big, stamp, &big_names[idx], true);
            let _ = ref_book_fail(&mut big_ref.book, stamp, &big_names[idx], &cfg);
        }
    }
    let excluded = [big_names[0].clone()];
    let at_retry = at(t0, 4);
    let order = big.retry_order(at_retry, &big_prod.view(), &excluded);
    let want = big_ref.retry_order(at_retry, &big_raw, &excluded);
    assert_eq!(order.len(), 2999);
    assert_eq!(order, want);
    assert_eq!(lock(&big.book).nodes.len(), 3000);
}

#[test]
fn book_alignment_and_streaming_selection_match_reference_across_edge_cases() {
    let cfg = Settings {
        tolerance_ms: 25,
        ..settings()
    };
    let live = SmartState::new(cfg);
    let mut reference = RefSmart::new(cfg);
    let t0 = base();

    let step = |reference: &mut RefSmart,
                now: Stamp,
                site: Option<&str>,
                cs: &[RefCand<'_>],
                pin: Option<&str>,
                touch: bool,
                label: &str| {
        let prod = prod_cands(cs);
        let got = live.pick(now, site, &prod.view(), pin, touch);
        let want = reference.pick(now, site, cs, pin, touch);
        assert_eq!(got, want, "mismatch at {label}");
    };

    let list = names(&["a", "b", "c"]);
    let init = ref_cands(&list, &[100, 120, 150]);
    step(
        &mut reference,
        t0,
        None,
        &init,
        None,
        true,
        "init-default-a",
    );
    let shifted = ref_cands(&list, &[115, 95, 200]);
    // Tolerance keeps `a` (115 <= 95+25), while raw lowest `b` must become runner-up.
    step(
        &mut reference,
        t0,
        None,
        &shifted,
        None,
        true,
        "tol-keep-a-runner-b",
    );
    let arb_live = timeout(&live, t0, "a", false);
    let arb_ref = reference.book.report(
        t0,
        super::book::Failure {
            node: list[0].clone(),
            site: None,
            site_level: false,
        },
        Duration::from_secs(5),
        false,
        &cfg,
    );
    assert_eq!(arb_live, arb_ref);
    assert_eq!(
        arb_live
            .arbitrate
            .as_ref()
            .and_then(|a| a.witness.as_deref()),
        Some("b")
    );
    live.arbitrated(t0, arb_live.arbitrate.as_ref().unwrap().token, false, false);
    reference
        .book
        .arbitrated(t0, arb_ref.arbitrate.as_ref().unwrap().token, false, &cfg);

    let overflow = [
        RefCand {
            name: &list[0],
            delay_ms: None,
            factor: 1.0,
        },
        RefCand {
            name: &list[1],
            delay_ms: Some(u16::MAX),
            factor: f64::MIN_POSITIVE,
        },
        RefCand {
            name: &list[2],
            delay_ms: None,
            factor: 1.0,
        },
    ];
    step(
        &mut reference,
        t0,
        None,
        &overflow,
        None,
        false,
        "overflow-no",
    );
    step(
        &mut reference,
        t0,
        None,
        &overflow,
        None,
        true,
        "overflow-yes",
    );

    let reordered = [
        RefCand {
            name: &list[2],
            delay_ms: Some(70),
            factor: 1.0,
        },
        RefCand {
            name: &list[0],
            delay_ms: Some(80),
            factor: 1.0,
        },
    ];
    let reordered_prod = prod_cands(&reordered);
    assert_eq!(
        live.pick(at(t0, 1), Some("s1"), &reordered_prod.view(), None, true),
        reference.pick(at(t0, 1), Some("s1"), &reordered, None, true)
    );
    let _ = take_align_scans();
    let _ = take_row_allocs();
    assert_eq!(
        live.pick(at(t0, 1), Some("s1"), &reordered_prod.view(), None, true),
        reference.pick(at(t0, 1), Some("s1"), &reordered, None, true)
    );
    assert_eq!(take_align_scans(), 0);
    assert_eq!(take_row_allocs(), 0);

    // A late dial_succeeded for departed `b` inserts an unknown node and must clear synced_members.
    live.dial_succeeded(at(t0, 2), "b", Duration::from_millis(50));
    let b_arc = reference.book.arc("b");
    super::node::Rtt::observe(
        &mut reference.book.node_mut(&b_arc, at(t0, 2)).connect,
        Duration::from_millis(50),
    );
    assert_eq!(
        live.pick(at(t0, 3), Some("s1"), &reordered_prod.view(), None, true),
        reference.pick(at(t0, 3), Some("s1"), &reordered, None, true)
    );
    assert_eq!(take_align_scans(), 1);
    assert_eq!(lock(&live.book).nodes.len(), 2);

    let dup_names = names(&["x", "y", "x"]);
    let dups = [
        RefCand {
            name: &dup_names[0],
            delay_ms: None,
            factor: 1.0,
        },
        RefCand {
            name: &dup_names[1],
            delay_ms: Some(100),
            factor: 1.0,
        },
        RefCand {
            name: &dup_names[2],
            delay_ms: Some(40),
            factor: 1.0,
        },
    ];
    step(
        &mut reference,
        at(t0, 4),
        Some("s2"),
        &dups,
        None,
        false,
        "dups-no",
    );
    step(
        &mut reference,
        at(t0, 4),
        Some("s2"),
        &dups,
        None,
        true,
        "dups-yes",
    );
    step(
        &mut reference,
        at(t0, 4),
        Some("s2"),
        &dups,
        Some("x"),
        true,
        "dups-pin-x",
    );

    let s4_live = SmartState::new(cfg);
    let mut s4_ref = RefSmart::new(cfg);
    let c3 = ref_cands(&list, &[50, 60, 70]);
    let c3_prod = prod_cands(&c3);
    assert_eq!(
        s4_live.pick(t0, Some("p.org"), &c3_prod.view(), None, true),
        s4_ref.pick(t0, Some("p.org"), &c3, None, true)
    );
    for (idx, ms) in [(0usize, 200u64), (1, 90), (2, 150)] {
        let f_ref = super::flow::FlowRef {
            id: idx as u64,
            node: &list[idx],
            site: &Arc::from("p.org"),
            upload_at: Some(t0),
            tls: false,
        };
        let done_at = t0.after(Duration::from_millis(ms));
        s4_live.flow_answered(&f_ref, done_at);
        s4_ref.book.flow_answered(&f_ref, done_at, &cfg);
    }
    let t1 = at(t0, 1);
    for (idx, name) in list.iter().enumerate() {
        let a1 = s4_live.dial_failed(
            t1,
            name,
            Some("p.org"),
            FailKind::TargetRefused,
            Duration::from_millis(10),
            true,
        );
        let a2 = s4_ref.book.report(
            t1,
            super::book::Failure {
                node: name.clone(),
                site: Some(Arc::from("p.org")),
                site_level: true,
            },
            Duration::from_millis(10),
            true,
            &cfg,
        );
        assert_eq!(a1, a2, "demote {idx}");
        assert_eq!(
            s4_live.pick(t1, Some("p.org"), &c3_prod.view(), None, true),
            s4_ref.pick(t1, Some("p.org"), &c3, None, true),
            "site pick after demote {idx}"
        );
    }
    for _ in 0..5 {
        timeout(&s4_live, t1, "b", true);
        let _ = ref_book_fail(&mut s4_ref.book, t1, &list[1], &cfg);
    }
    assert_eq!(
        s4_live.pick(at(t1, 1), Some("p.org"), &c3_prod.view(), None, true),
        s4_ref.pick(at(t1, 1), Some("p.org"), &c3, None, true)
    );
    for stamp in [
        at(t1, 30),
        Stamp {
            mono: t1.mono,
            wall: t1.wall + Duration::from_secs(3601),
        },
        Stamp {
            mono: t1.mono + Duration::from_secs(10),
            wall: t1.wall - Duration::from_secs(3600),
        },
    ] {
        assert_eq!(
            s4_live.pick(stamp, Some("p.org"), &c3_prod.view(), None, false),
            s4_ref.pick(stamp, Some("p.org"), &c3, None, false)
        );
        assert_eq!(
            s4_live.pick(stamp, None, &c3_prod.view(), None, false),
            s4_ref.pick(stamp, None, &c3, None, false)
        );
    }

    let old_epoch = s4_live.epoch();
    assert!(s4_live.reset_network(at(t1, 50)).probe_all);
    s4_ref.book.reset();
    let probe_res = [(list[0].clone(), false), (list[1].clone(), true)];
    assert_eq!(
        s4_live.probed(old_epoch, at(t1, 51), &probe_res),
        Actions::default()
    );
    assert_eq!(
        s4_live.pick(at(t1, 52), Some("fresh.org"), &c3_prod.view(), None, true),
        s4_ref.pick(at(t1, 52), Some("fresh.org"), &c3, None, true)
    );

    let dup_cfg = settings();
    let dup_live = SmartState::new(dup_cfg);
    let mut dup_ref = RefSmart::new(dup_cfg);
    let dup_names = names(&["x", "y", "x"]);
    let init_raw = ref_cands(&dup_names, &[200, 50, 200]);
    let init_prod = prod_cands(&init_raw);
    assert_eq!(
        dup_live.pick(t0, Some("dup.org"), &init_prod.view(), None, true),
        dup_ref.pick(t0, Some("dup.org"), &init_raw, None, true)
    );
    for target in [&dup_names[1], &dup_names[0]] {
        let a1 = dup_live.dial_failed(
            t0,
            target,
            Some("dup.org"),
            FailKind::TargetRefused,
            Duration::from_millis(10),
            true,
        );
        let a2 = dup_ref.book.report(
            t0,
            super::book::Failure {
                node: target.clone(),
                site: Some(Arc::from("dup.org")),
                site_level: true,
            },
            Duration::from_millis(10),
            true,
            &dup_cfg,
        );
        assert_eq!(a1, a2);
    }
    for _ in 0..5 {
        timeout(&dup_live, t0, "y", true);
        let _ = ref_book_fail(&mut dup_ref.book, t0, &dup_names[1], &dup_cfg);
    }
    let next_raw = ref_cands(&dup_names, &[60, 100, 40]);
    let next_prod = prod_cands(&next_raw);
    let got = dup_live.pick(at(t0, 1), Some("dup.org"), &next_prod.view(), None, true);
    let want = dup_ref.pick(at(t0, 1), Some("dup.org"), &next_raw, None, true);
    assert_eq!(got, want);
    assert_eq!(got.0, 2);
}
