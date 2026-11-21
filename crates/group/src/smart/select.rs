use indexmap::IndexMap;
use std::sync::Arc;
use std::time::Duration;

use super::node::NodeState;
use super::site::Site;
use super::{Candidate, Stamp};

pub(super) struct Row<'a> {
    pub name: &'a Arc<str>,
    pub score: Option<f64>,
    pub ejected: bool,
    pub left: Duration,
    /// The book holds this member's state at the member's own position.
    pub aligned: bool,
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

pub(super) fn rows<'a>(
    nodes: &IndexMap<Arc<str>, NodeState>,
    now: Stamp,
    candidates: &'a [Candidate<'a>],
    half_life: Duration,
) -> Vec<Row<'a>> {
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let (state, aligned) = state_of(nodes, index, candidate.name);
            let factor = if candidate.factor.is_finite() && candidate.factor > 0.0 {
                candidate.factor
            } else {
                1.0
            };
            let penalty = state.map_or(0.0, |state| state.penalty_ms(now, half_life));
            Row {
                name: candidate.name,
                score: candidate
                    .delay_ms
                    .map(|delay| f64::from(delay) / factor + penalty),
                ejected: state.is_some_and(|state| state.ejected(now)),
                left: state.map_or(Duration::ZERO, |state| state.ejection_left(now)),
                aligned,
            }
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

/// The default as the host sees it: never empty unless there are no rows.
pub(super) fn default_index(rows: &[Row<'_>], previous: Option<&str>, tolerance: f64) -> usize {
    default_of(rows, previous, tolerance, |_| true)
        .or_else(|| soonest_ejected(rows, |_| true))
        .unwrap_or(0)
}

pub(super) fn runner_up(rows: &[Row<'_>], best: usize) -> Option<usize> {
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
) -> usize {
    let current = position(rows, &entry.node)
        .filter(|&index| rows.get(index).is_some_and(|row| !row.ejected));
    if entry.problem {
        return current
            .or_else(|| least_srtt(rows, entry, |row| !row.ejected))
            .unwrap_or_else(|| default_index(rows, previous, tolerance));
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
        .unwrap_or_else(|| default_index(rows, previous, tolerance))
}
