use indexmap::IndexMap;
use std::sync::Arc;
use std::time::Duration;

use super::node::NodeState;
use super::site::Site;
use super::{CandidateView, Stamp};

#[cfg(test)]
std::thread_local! {
    static ROW_ALLOCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_row_allocs() -> usize {
    ROW_ALLOCS.with(|allocs| allocs.replace(0))
}

pub(super) struct Row<'a> {
    pub name: &'a Arc<str>,
    /// Live score (`None` when unscored or ejected).
    pub score: Option<f64>,
    pub ejected: bool,
    pub left: Duration,
}

pub(super) struct Summary {
    pub global: usize,
    pub runner_up: Option<usize>,
}

/// The state of the member at `index`, read by position while the table is in member order, and whether it was.
pub(super) fn state_of<'n>(
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

fn state_at<'n>(
    nodes: &'n IndexMap<Arc<str>, NodeState>,
    aligned: bool,
    index: usize,
    name: &Arc<str>,
) -> Option<&'n NodeState> {
    if aligned {
        nodes.get_index(index).map(|(_, state)| state)
    } else {
        state_of(nodes, index, name).0
    }
}

pub(super) fn is_ejected(
    nodes: &IndexMap<Arc<str>, NodeState>,
    aligned: bool,
    index: usize,
    name: Option<&Arc<str>>,
    now: Stamp,
) -> bool {
    name.and_then(|name| state_at(nodes, aligned, index, name))
        .is_some_and(|state| state.ejected(now))
}

#[expect(
    clippy::too_many_arguments,
    reason = "single-pass summary keeps all inputs explicit without allocating an intermediate Row buffer"
)]
pub(super) fn summarize(
    nodes: &IndexMap<Arc<str>, NodeState>,
    aligned: bool,
    now: Stamp,
    candidates: &CandidateView<'_>,
    half_life: Duration,
    previous: Option<&str>,
    tolerance: f64,
    need_runner_up: bool,
) -> Summary {
    let mut first_live: Option<usize> = None;
    let mut best_scored: Option<(usize, f64)> = None;
    let mut prev_default: Option<(usize, Option<f64>)> = None;
    let mut soonest: Option<(usize, Duration)> = None;
    let mut top1: Option<(usize, f64)> = None;
    let mut top2: Option<(usize, f64)> = None;

    for index in 0..candidates.len() {
        let Some((name, base_score)) = candidates.get(index) else {
            continue;
        };
        let state = state_at(nodes, aligned, index, name);
        let (ejected, left) = state.map_or((false, Duration::ZERO), |s| s.ejection(now));
        if ejected {
            if soonest.is_none_or(|(_, least)| left < least) {
                soonest = Some((index, left));
            }
            continue;
        }
        first_live.get_or_insert(index);
        let score =
            base_score.map(|base| base + state.map_or(0.0, |s| s.penalty_ms(now, half_life)));
        if let Some(score) = score
            && best_scored.is_none_or(|(_, least)| score < least)
        {
            best_scored = Some((index, score));
        }
        if prev_default.is_none() && previous == Some(&**name) {
            prev_default = Some((index, score));
        }
        if need_runner_up {
            let key = score.unwrap_or(f64::INFINITY);
            if top1.is_none_or(|(_, k1)| key.total_cmp(&k1).is_lt()) {
                top2 = top1;
                top1 = Some((index, key));
            } else if top2.is_none_or(|(_, k2)| key.total_cmp(&k2).is_lt()) {
                top2 = Some((index, key));
            }
        }
    }

    let global = match best_scored {
        Some((best, least)) => {
            let kept = prev_default.and_then(|(index, score)| {
                score
                    .is_some_and(|score| score <= least + tolerance)
                    .then_some(index)
            });
            kept.unwrap_or(best)
        }
        None => first_live
            .or_else(|| soonest.map(|(index, _)| index))
            .unwrap_or(0),
    };
    let runner_up = if need_runner_up {
        match top1 {
            Some((i1, _)) if i1 != global => Some(i1),
            Some(_) => top2.map(|(i2, _)| i2),
            None => None,
        }
    } else {
        None
    };
    Summary { global, runner_up }
}

pub(super) fn rows<'a>(
    nodes: &IndexMap<Arc<str>, NodeState>,
    now: Stamp,
    candidates: &CandidateView<'a>,
    half_life: Duration,
) -> Vec<Row<'a>> {
    #[cfg(test)]
    ROW_ALLOCS.with(|allocs| allocs.set(allocs.get() + 1));
    (0..candidates.len())
        .filter_map(|index| {
            let (name, base_score) = candidates.get(index)?;
            let (state, _) = state_of(nodes, index, name);
            let (ejected, left) = state.map_or((false, Duration::ZERO), |s| s.ejection(now));
            let score = (!ejected)
                .then_some(base_score)
                .flatten()
                .map(|base| base + state.map_or(0.0, |s| s.penalty_ms(now, half_life)));
            Some(Row {
                name,
                score,
                ejected,
                left,
            })
        })
        .collect()
}

/// The least score among the allowed, non-ejected rows with a delay, keeping `previous` while it is within
/// `tolerance` of the best (url-test's hysteresis). With no delay anywhere, the first allowed row.
pub(super) fn default_of(
    rows: &[Row<'_>],
    previous: Option<&str>,
    tolerance: f64,
    allowed: impl Fn(&Row<'_>) -> bool,
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

pub(super) fn soonest_ejected(
    rows: &[Row<'_>],
    allowed: impl Fn(&Row<'_>) -> bool,
) -> Option<usize> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| row.ejected && allowed(row))
        .min_by_key(|(_, row)| row.left)
        .map(|(index, _)| index)
}

fn least_srtt(rows: &[Row<'_>], site: &Site, allowed: impl Fn(&Row<'_>) -> bool) -> Option<usize> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| allowed(row))
        .filter_map(|(index, row)| site.srtt(row.name).map(|srtt| (index, srtt)))
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(index, _)| index)
}

fn position(rows: &[Row<'_>], node: &str) -> Option<usize> {
    rows.iter().position(|row| &**row.name == node)
}

/// What a TCP flow to a site with a live entry uses. A node that failed for the site is skipped; a site that
/// has demoted every node, or that is a problem, stays where it is; with every node ejected the one whose
/// ejection ends first serves.
pub(super) fn site_choice(
    rows: &[Row<'_>],
    entry: &Site,
    previous: Option<&str>,
    tolerance: f64,
    global: usize,
) -> usize {
    let current = position(rows, &entry.node)
        .filter(|&index| rows.get(index).is_some_and(|row| !row.ejected));
    if entry.problem {
        return current
            .or_else(|| least_srtt(rows, entry, |row| !row.ejected))
            .unwrap_or(global);
    }
    if let Some(index) = current
        && !entry.is_demoted(&entry.node)
    {
        return index;
    }
    let open = |row: &Row<'_>| !entry.is_demoted(row.name);
    if let Some(index) = default_of(rows, previous, tolerance, open) {
        return index;
    }
    soonest_ejected(rows, open)
        .or_else(|| least_srtt(rows, entry, |row| !row.ejected))
        .or(current)
        .unwrap_or(global)
}
