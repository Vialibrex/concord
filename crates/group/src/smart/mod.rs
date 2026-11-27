//! The smart group's state machine: per-node failure evidence and ejection, and per-site node memory. It owns
//! no task, timer or socket; every entry point takes the time and returns what the caller must do.

#[cfg(test)]
mod arbitration_tests;
mod book;
#[cfg(test)]
mod diff_tests;
mod flow;
mod node;
mod owner;
mod select;
mod site;
#[cfg(test)]
mod site_tests;
mod stamp;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use concord_common::sync::lock;
use std::sync::Mutex;

#[cfg(test)]
pub(crate) use book::take_align_scans;
use book::{Book, Failure};
pub use flow::{FlowEnd, FlowTap};
use node::Rtt;
#[cfg(test)]
pub(crate) use node::take_exp2_calls;
pub use owner::SmartFlow;
pub(crate) use owner::{CandidateView, Owner, answered, run};
#[cfg(test)]
pub(crate) use owner::{set_candidates_mid_scan, take_table_builds};
use select::Row;
#[cfg(test)]
pub(crate) use select::take_row_allocs;
pub use stamp::Stamp;

const DEFAULT_HALF_LIFE: Duration = Duration::from_secs(300);
const RTO_FLOOR: Duration = Duration::from_secs(1);

const SITE_TTL: Duration = Duration::from_secs(3600);
const NO_RESPONSE: Duration = Duration::from_secs(3);
const SITE_LIMIT: usize = 4096;
const EJECT_BASE: Duration = Duration::from_secs(30);
const EJECT_MAX: Duration = Duration::from_secs(300);
const EJECT_DECAY: Duration = Duration::from_secs(10);
const RTT_ALPHA: f64 = 1.0 / 8.0;
const RTT_BETA: f64 = 1.0 / 4.0;
const T_FAIL_GAIN: f64 = 1.0 / 8.0;
const SITE_PROBLEM_NODES: usize = 3;
const ESCALATION_SITES: usize = 2;
const PENDING_LIMIT: usize = 64;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Settings {
    pub tolerance_ms: u16,
    /// The group's `max-failed-times`: consecutive node failures before ejection.
    pub max_failed: u32,
    /// The group's interval; the owner substitutes the profile default when it is 0.
    pub half_life: Duration,
    /// The group's test timeout, booked as the time a failed probe took.
    pub probe_timeout: Duration,
}

/// Test `suspect` and `witness` (only the suspect when there is none), then call `SmartState::arbitrated`
/// with `token`.
#[derive(Debug, PartialEq)]
pub(crate) struct Arbitrate {
    pub suspect: Arc<str>,
    pub witness: Option<Arc<str>>,
    pub token: u64,
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct Actions {
    pub probe: Vec<Arc<str>>,
    pub arbitrate: Option<Arbitrate>,
    pub probe_all: bool,
    pub revoke_pin: bool,
    pub refresh: bool,
}

impl Actions {
    pub(super) fn add_probe(&mut self, node: &Arc<str>) {
        if !self.probe.contains(node) {
            self.probe.push(node.clone());
        }
    }

    pub(super) fn merge(&mut self, other: Actions) {
        for node in &other.probe {
            self.add_probe(node);
        }
        if self.arbitrate.is_none() {
            self.arbitrate = other.arbitrate;
        }
        self.probe_all |= other.probe_all;
        self.revoke_pin |= other.revoke_pin;
        self.refresh |= other.refresh;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailKind {
    Timeout,
    /// The node's server answered the TCP connect with RST.
    Refused,
    /// The node reported that the target refused.
    TargetRefused,
    Other,
}

pub(crate) struct SmartState {
    settings: Settings,
    book: Mutex<Book>,
    flows: AtomicU64,
}

impl SmartState {
    pub fn new(settings: Settings) -> Arc<SmartState> {
        Arc::new(SmartState {
            settings,
            book: Mutex::new(Book::default()),
            flows: AtomicU64::new(0),
        })
    }

    /// TCP with a site key, or UDP (`site` `None`). `touch` false is read-only: no memory update, no judgement
    /// and no actions. `candidates` is every member, ejected ones included.
    pub fn pick(
        &self,
        now: Stamp,
        site: Option<&str>,
        candidates: &CandidateView<'_>,
        pin: Option<&str>,
        touch: bool,
    ) -> (usize, Actions) {
        let settings = &self.settings;
        let mut book = lock(&self.book);
        let mut actions = Actions::default();
        if touch {
            book.sites.expire(now);
            actions.merge(book.judge_overdue(now, settings));
        }
        let aligned = if touch {
            book.ensure_aligned(candidates, now)
        } else {
            book.is_synced(candidates)
        };
        let tolerance = f64::from(settings.tolerance_ms);
        let summary = select::summarize(
            &book.nodes,
            aligned,
            now,
            candidates,
            settings.half_life,
            book.default.as_deref(),
            tolerance,
            touch,
        );
        if touch {
            let default = candidates.name(summary.global);
            let runner_up = summary.runner_up.and_then(|i| candidates.name(i));
            book.track_default_names(default, runner_up, &mut actions);
        }
        if let Some(index) = pin.and_then(|pin| candidates.index_of(pin)) {
            if !select::is_ejected(&book.nodes, aligned, index, candidates.name(index), now) {
                return (index, finish(&mut book, touch, actions));
            }
            actions.revoke_pin |= touch;
        }
        let index = match site {
            None => summary.global,
            Some(site) => {
                let entry = book.sites.live(site, now);
                let live = entry.is_some();
                let index = match entry {
                    None => summary.global,
                    Some(entry) => {
                        let current = candidates.index_of(&entry.node).filter(|&index| {
                            !select::is_ejected(
                                &book.nodes,
                                aligned,
                                index,
                                candidates.name(index),
                                now,
                            )
                        });
                        if let Some(index) = current
                            && (entry.problem || !entry.is_demoted(&entry.node))
                        {
                            index
                        } else {
                            let rows =
                                select::rows(&book.nodes, now, candidates, settings.half_life);
                            select::site_choice(
                                &rows,
                                entry,
                                book.default.as_deref(),
                                tolerance,
                                summary.global,
                            )
                        }
                    }
                };
                if touch && let Some(name) = candidates.name(index) {
                    if live {
                        book.sites.renew(site, now);
                        book.sites.set_node(site, name);
                    } else {
                        book.sites.insert(site, name, now);
                    }
                }
                index
            }
        };
        (index, finish(&mut book, touch, actions))
    }

    #[cfg(test)]
    pub fn default_index(&self, now: Stamp, candidates: &CandidateView<'_>) -> usize {
        let book = lock(&self.book);
        let aligned = book.is_synced(candidates);
        select::summarize(
            &book.nodes,
            aligned,
            now,
            candidates,
            self.settings.half_life,
            book.default.as_deref(),
            f64::from(self.settings.tolerance_ms),
            false,
        )
        .global
    }

    pub fn dial_failed(
        &self,
        now: Stamp,
        node: &str,
        site: Option<&str>,
        kind: FailKind,
        elapsed: Duration,
        corroborated: bool,
    ) -> Actions {
        let mut book = lock(&self.book);
        let node = book.arc(node);
        let site: Option<Arc<str>> = site.map(Arc::from);
        let failure = |site_level| Failure {
            node: node.clone(),
            site: site.clone(),
            site_level,
        };
        let mut actions = match kind {
            FailKind::TargetRefused if site.is_some() => {
                book.report(now, failure(true), elapsed, corroborated, &self.settings)
            }
            FailKind::TargetRefused => Actions::default(),
            FailKind::Refused => book.report(now, failure(false), elapsed, true, &self.settings),
            FailKind::Timeout | FailKind::Other => {
                book.report(now, failure(false), elapsed, corroborated, &self.settings)
            }
        };
        actions.merge(book.finish(Actions::default()));
        actions
    }

    pub fn dial_succeeded(&self, now: Stamp, node: &str, elapsed: Duration) {
        let mut book = lock(&self.book);
        let node = book.arc(node);
        Rtt::observe(&mut book.node_mut(&node, now).connect, elapsed);
    }

    #[cfg(test)]
    pub fn probe_round(&self, now: Stamp, results: &[(Arc<str>, bool)]) -> Actions {
        let mut book = lock(&self.book);
        self.probe_round_in(&mut book, now, results)
    }

    /// Which network the state is on: `reset_network` moves it, so a test started before it can be told apart.
    pub fn epoch(&self) -> u64 {
        lock(&self.book).epoch
    }

    /// The results of tests started on `epoch`; they are dropped once the network changed.
    pub fn probed(&self, epoch: u64, now: Stamp, results: &[(Arc<str>, bool)]) -> Actions {
        let mut book = lock(&self.book);
        if book.epoch != epoch {
            return book.finish(Actions::default());
        }
        self.probe_round_in(&mut book, now, results)
    }

    /// A periodic or single-node test. A failed test of one node says nothing about the local network, so it is
    /// held like an uncorroborated dial failure. A round of several nodes in which every result failed says the
    /// local network is down: nothing is recorded and the held failures are dropped.
    fn probe_round_in(&self, book: &mut Book, now: Stamp, results: &[(Arc<str>, bool)]) -> Actions {
        let settings = &self.settings;
        let mut actions = Actions::default();
        if results.is_empty() {
            return book.finish(actions);
        }
        if let [(name, false)] = results {
            let failure = Failure {
                node: name.clone(),
                site: None,
                site_level: false,
            };
            actions.merge(book.report(now, failure, settings.probe_timeout, false, settings));
            return book.finish(actions);
        }
        if results.iter().all(|(_, ok)| !ok) {
            book.drop_pending();
            return book.finish(actions);
        }
        actions.merge(book.book_pending(now, settings));
        for (name, ok) in results {
            if *ok {
                book.answered_test(name);
                book.node_mut(name, now)
                    .probe_success(now, settings.half_life);
            } else {
                book.node_failure(now, name, settings.probe_timeout, settings, &mut actions);
            }
        }
        book.finish(actions)
    }

    /// The outcome of the probes `Actions::arbitrate` asked for: either one passing means the local network
    /// works, so every held failure is booked; both failing drops those held when it began. A result for an
    /// arbitration that is no longer the current one (the network changed, or it was given up) is ignored.
    pub fn arbitrated(
        &self,
        now: Stamp,
        token: u64,
        suspect_ok: bool,
        witness_ok: bool,
    ) -> Actions {
        let mut book = lock(&self.book);
        let actions = book.arbitrated(now, token, suspect_ok || witness_ok, &self.settings);
        book.finish(actions)
    }

    #[cfg(test)]
    pub fn held(&self) -> (usize, u32) {
        lock(&self.book).held()
    }

    #[cfg(test)]
    pub fn arbitrated_now(&self, now: Stamp, suspect_ok: bool, witness_ok: bool) -> Actions {
        let token = lock(&self.book).arbitration_token();
        token.map_or_else(Actions::default, |token| {
            self.arbitrated(now, token, suspect_ok, witness_ok)
        })
    }

    pub fn reset_network(&self, _now: Stamp) -> Actions {
        let mut book = lock(&self.book);
        book.reset();
        Actions {
            probe_all: true,
            ..Actions::default()
        }
    }

    /// The time one connect attempt through `node` is given: its connect time's RFC 6298 retransmission timeout,
    /// at least `RTO_FLOOR`. `None` before the first connect sample.
    pub fn connect_budget(&self, node: &str) -> Option<Duration> {
        let book = lock(&self.book);
        let rto = book.nodes.get(node)?.connect?.rto_ms();
        Some(Duration::try_from_secs_f64(rto / 1000.0).map_or(RTO_FLOOR, |rto| rto.max(RTO_FLOOR)))
    }

    /// Members not in `exclude` and not ejected, in member order: the same set `retry_order` puts before the
    /// ejected ones, without the scoring that orders it.
    pub fn live_untried<'a>(
        &self,
        now: Stamp,
        names: impl Iterator<Item = &'a Arc<str>>,
        exclude: &[Arc<str>],
    ) -> Vec<usize> {
        let book = lock(&self.book);
        names
            .enumerate()
            .filter(|(index, name)| {
                !exclude.contains(*name)
                    && !select::state_of(&book.nodes, *index, name)
                        .0
                        .is_some_and(|state| state.ejected(now))
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// The order a redial tries the members in, without those named in `exclude`: the default, the other
    /// non-ejected members with a delay by score, those without a delay, then the ejected by the soonest end.
    pub fn retry_order(
        &self,
        now: Stamp,
        candidates: &CandidateView<'_>,
        exclude: &[Arc<str>],
    ) -> Vec<usize> {
        let book = lock(&self.book);
        let rows = select::rows(&book.nodes, now, candidates, self.settings.half_life);
        let open = |row: &Row<'_>| !exclude.contains(row.name);
        let tolerance = f64::from(self.settings.tolerance_ms);
        let first = select::default_of(&rows, book.default.as_deref(), tolerance, open);
        let mut order: Vec<usize> = Vec::with_capacity(rows.len());
        if let Some(index) = first {
            order.push(index);
        }
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
        order.extend(rest.filter(|&index| Some(index) != first));
        order
    }

    pub fn flow(self: &Arc<Self>, node: Arc<str>, site: Arc<str>, tls: bool) -> FlowTap {
        let id = self.flows.fetch_add(1, Ordering::Relaxed);
        FlowTap::new(self.clone(), id, node, site, tls)
    }

    pub(super) fn flow_uploaded(&self, flow: &flow::FlowRef<'_>, now: Stamp) {
        lock(&self.book).flow_uploaded(flow, now);
    }

    pub(super) fn flow_answered(&self, flow: &flow::FlowRef<'_>, now: Stamp) {
        lock(&self.book).flow_answered(flow, now, &self.settings);
    }

    pub(super) fn flow_ended(
        &self,
        flow: &flow::FlowRef<'_>,
        now: Stamp,
        answered: bool,
        end: &FlowEnd,
    ) -> Actions {
        let mut book = lock(&self.book);
        let actions = book.flow_ended(flow, now, answered, end, &self.settings);
        book.finish(actions)
    }

    pub(super) fn stash(&self, actions: Actions) {
        lock(&self.book).stash(actions);
    }
}

fn finish(book: &mut Book, touch: bool, actions: Actions) -> Actions {
    if touch {
        book.finish(actions)
    } else {
        Actions::default()
    }
}
