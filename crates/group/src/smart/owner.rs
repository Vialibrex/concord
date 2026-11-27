use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use concord_common::FlowMeta;
use concord_common::sync::lock;
use futures_util::future::{Either, join_all, select};

use super::{Actions, Arbitrate, DEFAULT_HALF_LIFE, FlowEnd, FlowTap, Settings, SmartState, Stamp};
use crate::group::{Group, Members, Touch};
use crate::health::Outcome;
use crate::node::Node;
use crate::outbounds::Outbounds;

#[cfg(test)]
std::thread_local! {
    static TABLE_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CANDIDATES_MID_SCAN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn take_table_builds() -> usize {
    TABLE_BUILDS.with(|builds| builds.replace(0))
}

#[cfg(test)]
pub(crate) fn set_candidates_mid_scan(hook: impl FnOnce() + 'static) {
    CANDIDATES_MID_SCAN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn fire_candidates_mid_scan() {
    let hook = CANDIDATES_MID_SCAN.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn divide_delay(delay: Option<u16>, factor: f64) -> Option<f64> {
    delay.map(|delay| f64::from(delay) / factor)
}

/// Immutable, version-paired view of a smart group's members and pre-divided base scores.
pub(crate) struct CandidateView<'a> {
    members: &'a Members,
    base_scores: Arc<[Option<f64>]>,
}

impl<'a> CandidateView<'a> {
    #[cfg(test)]
    pub(crate) fn from_delays(members: &'a Members, delays: &[Option<u16>]) -> CandidateView<'a> {
        let base_scores: Arc<[Option<f64>]> = delays
            .iter()
            .enumerate()
            .map(|(index, &delay)| divide_delay(delay, members.factor(index)))
            .collect();
        CandidateView {
            members,
            base_scores,
        }
    }

    pub fn len(&self) -> usize {
        self.members.nodes().len()
    }

    pub fn name(&self, index: usize) -> Option<&'a Arc<str>> {
        self.members.nodes().get(index).map(Node::name)
    }

    pub fn base_score(&self, index: usize) -> Option<f64> {
        self.base_scores.get(index).copied().flatten()
    }

    pub fn get(&self, index: usize) -> Option<(&'a Arc<str>, Option<f64>)> {
        self.name(index).map(|name| (name, self.base_score(index)))
    }

    pub fn synced_id(&self) -> Option<u64> {
        self.members.has_unique_names().then(|| self.members.id())
    }

    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.members.index_of(name)
    }
}

/// What a smart group holds besides its policy: the state, and the way back to the `Outbounds` that probes run on.
pub(crate) struct Owner {
    state: Arc<SmartState>,
    outbounds: OnceLock<Weak<Outbounds>>,
    table: Mutex<Option<Table>>,
}

/// Each member's pre-divided base score (`median_delay / factor`), valid while no watched member
/// recorded a test result and the member snapshot is the same one.
struct Table {
    epoch: u64,
    members_id: u64,
    base_scores: Arc<[Option<f64>]>,
}

impl Owner {
    pub fn new(
        tolerance: u16,
        max_failed: u32,
        interval: Duration,
        probe_timeout: Duration,
    ) -> Owner {
        Owner {
            state: SmartState::new(Settings {
                tolerance_ms: tolerance,
                max_failed,
                half_life: if interval.is_zero() {
                    DEFAULT_HALF_LIFE
                } else {
                    interval
                },
                probe_timeout,
            }),
            outbounds: OnceLock::new(),
            table: Mutex::new(None),
        }
    }

    pub fn bind(&self, outbounds: Weak<Outbounds>) {
        let _ = self.outbounds.set(outbounds);
    }

    pub fn state(&self) -> &Arc<SmartState> {
        &self.state
    }

    fn outbounds(&self) -> Option<Arc<Outbounds>> {
        self.outbounds.get()?.upgrade()
    }

    /// The index in `members` of the node a flow to `host` takes; read-only unless `touch` is `Yes`.
    pub fn pick(
        &self,
        group: &Arc<Group>,
        members: &Arc<Members>,
        flow: &FlowMeta,
        host: Option<&str>,
        touch: Touch,
    ) -> usize {
        let candidates = self.candidates(group, members);
        let site = Outbounds::smart_site(flow, host);
        let pin = group.shared().selections.get(group.name());
        let touch = touch == Touch::Yes;
        let (index, actions) = self.state.pick(
            Stamp::now(),
            site.as_deref(),
            &candidates,
            pin.as_deref(),
            touch,
        );
        if touch {
            run(group, actions);
        }
        index
    }

    /// Every member as the state reads it, recomputed only after a watched test result or a member change.
    pub fn candidates<'a>(&self, group: &Group, members: &'a Arc<Members>) -> CandidateView<'a> {
        let members_id = members.id();
        let mut slot = lock(&self.table);
        let epoch = group.health_watch().epoch();
        if let Some(table) = slot.as_ref()
            && table.epoch == epoch
            && table.members_id == members_id
        {
            return CandidateView {
                members,
                base_scores: Arc::clone(&table.base_scores),
            };
        }
        #[cfg(test)]
        TABLE_BUILDS.with(|builds| builds.set(builds.get() + 1));
        let base_scores: Arc<[Option<f64>]> = members
            .nodes()
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let score = divide_delay(
                    node.health().median_delay_for(group.url()),
                    members.factor(index),
                );
                #[cfg(test)]
                if index == 0 {
                    fire_candidates_mid_scan();
                }
                score
            })
            .collect();
        let stale_members = slot
            .as_ref()
            .is_some_and(|existing| existing.members_id > members_id);
        if !stale_members {
            *slot = Some(Table {
                epoch,
                members_id,
                base_scores: Arc::clone(&base_scores),
            });
        }
        CandidateView {
            members,
            base_scores,
        }
    }
}

/// Whether a test of `node` got an answer the group counts as one.
pub(crate) fn answered(node: &Node, url: &str, outcome: Outcome) -> bool {
    matches!(outcome, Outcome::Millis(_)) && node.health().alive_for(url)
}

async fn probe(group: &Group, outbounds: &Outbounds, node: &Node) -> bool {
    let outcome = outbounds
        .url_test_node(node, group.url(), group.expected(), group.test_timeout())
        .await;
    answered(node, group.url(), outcome)
}

/// Carries out what the state asked for. A group whose `Outbounds` is gone does nothing.
pub(crate) fn run(group: &Arc<Group>, actions: Actions) {
    if actions == Actions::default() {
        return;
    }
    let Some(outbounds) = group.smart().and_then(Owner::outbounds) else {
        return;
    };
    let shared = group.shared();
    if actions.revoke_pin && shared.selections.revoke(group.name()) {
        shared.route.moved();
    }
    if actions.refresh {
        shared.request_refresh();
    }
    if actions.probe_all {
        let group = group.clone();
        let outbounds = outbounds.clone();
        shared.tasks.spawn(async move {
            join_all(group.checks().map(|check| check.check(&outbounds))).await;
        });
    }
    if !actions.probe.is_empty() {
        let group = group.clone();
        let outbounds = outbounds.clone();
        let names = actions.probe;
        shared.tasks.spawn(async move {
            probe_nodes(&group, &outbounds, &names).await;
        });
    }
    if let Some(arbitration) = actions.arbitrate {
        let group = group.clone();
        shared.tasks.spawn(async move {
            arbitrate(&group, &outbounds, arbitration).await;
        });
    }
}

async fn probe_nodes(group: &Arc<Group>, outbounds: &Outbounds, names: &[Arc<str>]) {
    let (Some(owner), members) = (group.smart(), group.members()) else {
        return;
    };
    let epoch = owner.state.epoch();
    let nodes: Vec<&Node> = names.iter().filter_map(|name| members.find(name)).collect();
    let answers = join_all(nodes.iter().map(|node| probe(group, outbounds, node))).await;
    let results: Vec<(Arc<str>, bool)> = nodes
        .iter()
        .zip(answers)
        .map(|(node, ok)| (node.name().clone(), ok))
        .collect();
    group.shared().request_refresh();
    run(group, owner.state.probed(epoch, Stamp::now(), &results));
}

async fn arbitrate(group: &Arc<Group>, outbounds: &Outbounds, arbitration: Arbitrate) {
    let (Some(owner), members) = (group.smart(), group.members()) else {
        return;
    };
    let test = |name: &str| {
        let node = members.find(name);
        async move {
            match node {
                Some(node) => probe(group, outbounds, node).await,
                None => false,
            }
        }
    };
    let witness = arbitration.witness.as_deref().map(test);
    let (suspect_ok, witness_ok) = first_answer(test(&arbitration.suspect), witness).await;
    run(
        group,
        owner
            .state
            .arbitrated(Stamp::now(), arbitration.token, suspect_ok, witness_ok),
    );
}

/// Runs both tests side by side and stops at the first that passes: one is enough to show the local network
/// works. The one still running is reported as failed, which `SmartState::arbitrated` reads only as "not the
/// answer".
pub(super) async fn first_answer(
    suspect: impl Future<Output = bool>,
    witness: Option<impl Future<Output = bool>>,
) -> (bool, bool) {
    let Some(witness) = witness else {
        return (suspect.await, false);
    };
    let (suspect, witness) = (pin!(suspect), pin!(witness));
    match select(suspect, witness).await {
        Either::Left((true, _)) => (true, false),
        Either::Right((true, _)) => (false, true),
        Either::Left((false, witness)) => (false, witness.await),
        Either::Right((false, suspect)) => (suspect.await, false),
    }
}

/// The taps of every smart group on one chain.
pub struct SmartFlow {
    taps: Vec<(Arc<Group>, FlowTap)>,
}

impl SmartFlow {
    pub(crate) fn new(taps: Vec<(Arc<Group>, FlowTap)>) -> SmartFlow {
        SmartFlow { taps }
    }

    pub fn on_upload(&self) {
        for (_, tap) in &self.taps {
            tap.on_upload();
        }
    }

    pub fn on_download(&self) {
        for (_, tap) in &self.taps {
            tap.on_download();
        }
    }

    pub fn finish(self, end: FlowEnd) {
        for (group, tap) in self.taps {
            run(&group, tap.finish(end));
        }
    }
}
