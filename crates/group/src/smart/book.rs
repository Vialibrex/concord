use std::sync::Arc;
use std::time::Duration;

use indexmap::IndexMap;
use indexmap::map::Entry;

use super::flow::{FlowEnd, FlowRef};
use super::node::NodeState;
use super::site::SiteBook;
use super::{Actions, Arbitrate, CandidateView, NO_RESPONSE, PENDING_LIMIT, Settings, Stamp};

#[cfg(test)]
std::thread_local! {
    static ALIGN_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_align_scans() -> usize {
    ALIGN_SCANS.with(|scans| scans.replace(0))
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct Failure {
    pub node: Arc<str>,
    pub site: Option<Arc<str>>,
    pub site_level: bool,
}

struct Held {
    count: u32,
    elapsed: Duration,
    /// How many of `count` the running arbitration answers for; later ones wait for the next.
    covered: u32,
}

struct Running {
    token: u64,
    started: Stamp,
    witness: Option<Arc<str>>,
}

#[derive(Default)]
pub(super) struct Book {
    /// In member order once a touching pick synced it, so a pick reads each member's state by position.
    pub nodes: IndexMap<Arc<str>, NodeState>,
    synced_members: Option<u64>,
    pub sites: SiteBook,
    pub default: Option<Arc<str>>,
    runner_up: Option<Arc<str>>,
    pending: IndexMap<Failure, Held>,
    running: Option<Running>,
    tokens: u64,
    /// Witnesses that failed alongside their suspect, passed over until a test of theirs passes.
    failed_witnesses: Vec<Arc<str>>,
    pub epoch: u64,
    outbox: Actions,
}

impl Book {
    pub fn node_mut(&mut self, name: &Arc<str>, now: Stamp) -> &mut NodeState {
        match self.nodes.entry(name.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                self.synced_members = None;
                entry.insert(NodeState::new(now))
            }
        }
    }

    pub fn arc(&self, name: &str) -> Arc<str> {
        self.nodes
            .get_key_value(name)
            .map_or_else(|| Arc::from(name), |(key, _)| key.clone())
    }

    /// Merges what flow events left behind into what this call returns.
    pub fn finish(&mut self, mut actions: Actions) -> Actions {
        let stashed = std::mem::take(&mut self.outbox);
        actions.merge(stashed);
        actions
    }

    pub fn stash(&mut self, actions: Actions) {
        self.outbox.merge(actions);
    }

    pub fn is_synced(&self, candidates: &CandidateView<'_>) -> bool {
        candidates
            .synced_id()
            .is_some_and(|id| self.synced_members == Some(id))
    }

    /// Ensures the book holds a state for each member in `candidates`, in order, and claims the
    /// snapshot ID when unique names already match so subsequent picks skip scanning.
    pub fn ensure_aligned(&mut self, candidates: &CandidateView<'_>, now: Stamp) -> bool {
        if self.is_synced(candidates) {
            return true;
        }
        #[cfg(test)]
        ALIGN_SCANS.with(|scans| scans.set(scans.get() + 1));
        let matches = self.nodes.len() == candidates.len()
            && (0..candidates.len()).all(|index| {
                self.nodes
                    .get_index(index)
                    .zip(candidates.name(index))
                    .is_some_and(|((held, _), name)| Arc::ptr_eq(held, name) || held == name)
            });
        if matches {
            self.synced_members = candidates.synced_id();
            return true;
        }
        self.sync_members(candidates, now);
        self.nodes.len() == candidates.len()
    }

    /// Keeps a state for exactly the current members, in their order, so any of them can witness.
    pub fn sync_members(&mut self, candidates: &CandidateView<'_>, now: Stamp) {
        let mut old = std::mem::take(&mut self.nodes);
        self.nodes = (0..candidates.len())
            .filter_map(|index| {
                let name = candidates.name(index)?;
                let state = old
                    .swap_remove(&**name)
                    .unwrap_or_else(|| NodeState::new(now));
                Some((name.clone(), state))
            })
            .collect();
        self.retain_failed_witnesses();
        self.synced_members = candidates
            .synced_id()
            .filter(|_| self.nodes.len() == candidates.len());
    }

    #[cfg(test)]
    pub fn set_runner_up(&mut self, name: Option<Arc<str>>) {
        self.runner_up = name;
    }

    pub fn retain_failed_witnesses(&mut self) {
        let nodes = &self.nodes;
        self.failed_witnesses
            .retain(|name| nodes.contains_key(&**name));
    }

    pub fn track_default_names(
        &mut self,
        default: Option<&Arc<str>>,
        runner_up: Option<&Arc<str>>,
        actions: &mut Actions,
    ) {
        if self.default.as_deref() != default.map(|name| &**name) {
            actions.refresh |= self.default.is_some() && default.is_some();
            self.default = default.cloned();
        }
        if self.runner_up.as_deref() != runner_up.map(|name| &**name) {
            self.runner_up = runner_up.cloned();
        }
    }

    pub fn reset(&mut self) {
        self.nodes.clear();
        self.synced_members = None;
        self.sites.clear();
        self.pending.clear();
        self.running = None;
        self.failed_witnesses.clear();
        self.epoch += 1;
        self.outbox = Actions::default();
    }

    pub fn drop_pending(&mut self) {
        self.pending.clear();
    }

    /// A node-level or site-level failure: booked at once when `corroborated`, otherwise held until a probe
    /// of the node and of a witness says the local network works.
    pub fn report(
        &mut self,
        now: Stamp,
        failure: Failure,
        elapsed: Duration,
        corroborated: bool,
        settings: &Settings,
    ) -> Actions {
        let mut actions = Actions::default();
        if self
            .nodes
            .get(&*failure.node)
            .is_some_and(|node| node.ejected(now))
        {
            return actions;
        }
        if corroborated {
            self.book(now, &failure, 1, elapsed, settings, &mut actions);
            return actions;
        }
        let suspect = failure.node.clone();
        self.hold(failure, elapsed, settings);
        actions.arbitrate = self.arbitrate(now, suspect, settings);
        actions
    }

    /// Adds one held failure. The count stops at `max-failed-times`, which already ejects; when the book is
    /// full the oldest entry goes.
    fn hold(&mut self, failure: Failure, elapsed: Duration, settings: &Settings) {
        if !self.pending.contains_key(&failure) && self.pending.len() >= PENDING_LIMIT {
            self.pending.shift_remove_index(0);
        }
        let held = self.pending.entry(failure).or_insert(Held {
            count: 0,
            elapsed: Duration::ZERO,
            covered: 0,
        });
        if held.count < settings.max_failed.max(1) {
            held.count += 1;
            held.elapsed = held.elapsed.saturating_add(elapsed);
        }
    }

    /// Starts an arbitration unless one is running. One that has not answered within twice the probe timeout
    /// (its two tests run side by side, each bounded by it) is taken as lost and replaced.
    fn arbitrate(
        &mut self,
        now: Stamp,
        suspect: Arc<str>,
        settings: &Settings,
    ) -> Option<Arbitrate> {
        if let Some(running) = &self.running
            && now.since(&running.started) < settings.probe_timeout.saturating_mul(2)
        {
            return None;
        }
        self.tokens += 1;
        let witness = self.witness(now, &suspect);
        for held in self.pending.values_mut() {
            held.covered = held.count;
        }
        self.running = Some(Running {
            token: self.tokens,
            started: now,
            witness: witness.clone(),
        });
        Some(Arbitrate {
            suspect,
            witness,
            token: self.tokens,
        })
    }

    /// A node other than the suspect that is not ejected and has not just failed as a witness: the default, the
    /// runner-up, then the others by name, preferring one with no failure held against it.
    fn witness(&self, now: Stamp, suspect: &Arc<str>) -> Option<Arc<str>> {
        let mut names: Vec<&Arc<str>> = [&self.default, &self.runner_up]
            .into_iter()
            .flatten()
            .collect();
        let mut others: Vec<&Arc<str>> = self
            .nodes
            .keys()
            .filter(|name| !names.contains(name))
            .collect();
        others.sort();
        names.extend(others);
        let usable = |name: &&Arc<str>| {
            *name != suspect
                && !self.failed_witnesses.contains(*name)
                && !self
                    .nodes
                    .get(&***name)
                    .is_some_and(|node| node.ejected(now))
        };
        let held = |name: &&Arc<str>| self.pending.keys().any(|failure| failure.node == **name);
        let mut usable_names = names.into_iter().filter(usable);
        let first = usable_names.clone().next();
        usable_names.find(|name| !held(name)).or(first).cloned()
    }

    pub fn arbitrated(
        &mut self,
        now: Stamp,
        token: u64,
        answered: bool,
        settings: &Settings,
    ) -> Actions {
        let Some(running) = self.running.take_if(|running| running.token == token) else {
            return Actions::default();
        };
        if answered {
            return self.book_pending(now, settings);
        }
        if let Some(witness) = running.witness
            && !self.failed_witnesses.contains(&witness)
        {
            self.failed_witnesses.push(witness);
        }
        self.pending.retain(|_, held| {
            let left = held.count - held.covered;
            if left > 0 {
                held.elapsed = held.elapsed * left / held.count;
                held.count = left;
                held.covered = 0;
            }
            left > 0
        });
        let mut actions = Actions::default();
        if let Some(suspect) = self.pending.last().map(|(failure, _)| failure.node.clone()) {
            actions.arbitrate = self.arbitrate(now, suspect, settings);
        }
        actions
    }

    #[cfg(test)]
    pub fn arbitration_token(&self) -> Option<u64> {
        self.running.as_ref().map(|running| running.token)
    }

    pub fn answered_test(&mut self, node: &Arc<str>) {
        self.failed_witnesses.retain(|name| name != node);
    }

    #[cfg(test)]
    pub fn held(&self) -> (usize, u32) {
        (
            self.pending.len(),
            self.pending.values().map(|held| held.count).sum(),
        )
    }

    /// Books every held failure: the local network was shown to work.
    pub fn book_pending(&mut self, now: Stamp, settings: &Settings) -> Actions {
        let mut actions = Actions::default();
        for (failure, held) in std::mem::take(&mut self.pending) {
            let mean = held.elapsed / held.count.max(1);
            self.book(now, &failure, held.count, mean, settings, &mut actions);
        }
        actions
    }

    fn book(
        &mut self,
        now: Stamp,
        failure: &Failure,
        times: u32,
        elapsed: Duration,
        settings: &Settings,
        actions: &mut Actions,
    ) {
        for _ in 0..times {
            match (&failure.site, failure.site_level) {
                (Some(site), true) => {
                    self.sites.demote(site, &failure.node, now);
                    if self.node_mut(&failure.node, now).site_failure(site) {
                        self.node_failure(now, &failure.node, elapsed, settings, actions);
                    }
                }
                (site, _) => {
                    self.node_failure(now, &failure.node, elapsed, settings, actions);
                    if let Some(site) = site {
                        self.sites.demote(site, &failure.node, now);
                    }
                }
            }
        }
    }

    pub fn node_failure(
        &mut self,
        now: Stamp,
        node: &Arc<str>,
        elapsed: Duration,
        settings: &Settings,
        actions: &mut Actions,
    ) {
        if self.node_mut(node, now).failure(now, elapsed, settings) {
            actions.add_probe(node);
        }
    }

    pub fn judge_overdue(&mut self, now: Stamp, settings: &Settings) -> Actions {
        let mut actions = Actions::default();
        for (node, site, waited) in self.sites.overdue(now, NO_RESPONSE) {
            let failure = Failure {
                node,
                site: Some(site),
                site_level: true,
            };
            actions.merge(self.report(now, failure, waited, false, settings));
        }
        actions
    }

    pub fn flow_uploaded(&mut self, flow: &FlowRef<'_>, now: Stamp) {
        self.sites.register(flow.site, flow.node, flow.id, now, now);
    }

    pub fn flow_answered(&mut self, flow: &FlowRef<'_>, now: Stamp, settings: &Settings) {
        self.node_mut(flow.node, now)
            .success(now, settings.half_life, true);
        self.sites.unregister(flow.site, flow.id, now);
        if let Some(upload) = flow.upload_at {
            self.sites
                .observe(flow.site, flow.node, now.since(&upload), now);
        }
    }

    pub fn flow_ended(
        &mut self,
        flow: &FlowRef<'_>,
        now: Stamp,
        answered: bool,
        end: &FlowEnd,
        settings: &Settings,
    ) -> Actions {
        if answered {
            return Actions::default();
        }
        if end.download > 0 {
            self.flow_answered(flow, now, settings);
            return Actions::default();
        }
        let judged = self.sites.unregister(flow.site, flow.id, now);
        let (true, Some(false), Some(upload)) = (flow.tls, judged, flow.upload_at) else {
            return Actions::default();
        };
        let waited = now.since(&upload);
        if waited < NO_RESPONSE && !(end.remote_first == Some(true) && !end.cancelled) {
            return Actions::default();
        }
        let failure = Failure {
            node: flow.node.clone(),
            site: Some(flow.site.clone()),
            site_level: true,
        };
        self.report(now, failure, waited, false, settings)
    }
}
