use std::collections::HashSet;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use concord_common::sync::lock;
use concord_common::{CoreError, FlowMeta, OutboundKind};
use concord_config::filter::Matcher;
use concord_platform::is_local_exhaustion;
use indexmap::IndexMap;
use tokio::time::Instant;

use crate::check::Check;
use crate::health::{HealthWatch, NodeHealth, StatusRanges};
pub use crate::members::{Emptiness, Members};
use crate::node::{Item, Leaf, Node};
use crate::priority::{Priority, normalize_factor};
use crate::provider::ProxyProvider;
use crate::shared::Shared;
use crate::smart::Owner;
use crate::strategy::Strategy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Touch {
    Yes,
    No,
}

pub enum Policy {
    Select { default_selected: Arc<str> },
    UrlTest { tolerance: u16 },
    Smart { tolerance: u16, priority: Priority },
    Fallback,
    LoadBalance(Strategy),
    Relay,
}

#[cfg(test)]
std::thread_local! {
    static URL_TEST_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FASTEST_MID_SCAN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn take_url_test_scans() -> usize {
    URL_TEST_SCANS.with(|scans| scans.replace(0))
}

#[cfg(test)]
pub(crate) fn set_fastest_mid_scan(hook: impl FnOnce() + 'static) {
    FASTEST_MID_SCAN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn fire_fastest_mid_scan() {
    let hook = FASTEST_MID_SCAN.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

pub enum Pick {
    Node(Node),
    Rejected { reason: Arc<str>, shown: Arc<str> },
}

impl Pick {
    pub fn name(&self) -> &str {
        match self {
            Pick::Node(node) => node.name(),
            Pick::Rejected { shown, .. } => shown,
        }
    }
}

pub(crate) struct GroupParts {
    pub name: Arc<str>,
    pub policy: Policy,
    pub url: String,
    pub expected_text: String,
    pub expected: StatusRanges,
    pub disable_udp: bool,
    pub hidden: bool,
    pub icon: String,
    pub empty_fallback: Arc<Leaf>,
    pub explicit_fallback: bool,
    pub refused: bool,
    pub quarantined: Arc<HashSet<String>>,
    pub own: Vec<Item>,
    pub uses: Vec<Arc<ProxyProvider>>,
    pub use_position: IndexMap<String, i32>,
    pub filter: Vec<Matcher>,
    pub exclude_filter: Vec<Matcher>,
    pub exclude_type: Vec<String>,
    pub own_check: Option<Arc<Check>>,
    pub test_timeout: Duration,
    pub max_failed: u32,
    pub interval: Duration,
    pub shared: Arc<Shared>,
}

#[derive(Default)]
struct FastState {
    node: Option<Node>,
    cached: Option<Cached>,
}

struct Cached {
    epoch: u64,
    members_id: u64,
    pin: Option<Arc<str>>,
    node: Node,
}

#[derive(Default)]
struct FailState {
    count: u32,
    first: Option<Instant>,
    checking: bool,
}

pub struct Group {
    parts: GroupParts,
    members: ArcSwap<Members>,
    next_members_id: AtomicU64,
    health_watch: Arc<HealthWatch>,
    rebuild: Mutex<()>,
    health: NodeHealth,
    fast: Mutex<FastState>,
    fail: Mutex<FailState>,
    smart: Option<Owner>,
}

impl Group {
    pub(crate) fn new(parts: GroupParts) -> Arc<Group> {
        let smart = match &parts.policy {
            Policy::Smart { tolerance, .. } => Some(Owner::new(
                *tolerance,
                parts.max_failed,
                parts.interval,
                parts.test_timeout,
            )),
            _ => None,
        };
        let group = Group {
            members: ArcSwap::from_pointee(Members::empty(parts.uses.len())),
            next_members_id: AtomicU64::new(1),
            health_watch: HealthWatch::new(),
            parts,
            rebuild: Mutex::new(()),
            health: NodeHealth::default(),
            fast: Mutex::new(FastState::default()),
            fail: Mutex::new(FailState::default()),
            smart,
        };
        group.members.store(Arc::new(group.compute()));
        Arc::new(group)
    }

    pub fn name(&self) -> &Arc<str> {
        &self.parts.name
    }

    pub fn policy(&self) -> &Policy {
        &self.parts.policy
    }

    pub fn type_name(&self) -> &'static str {
        match self.parts.policy {
            Policy::Select { .. } => "Selector",
            Policy::UrlTest { .. } => "URLTest",
            Policy::Smart { .. } => "Smart",
            Policy::Fallback => "Fallback",
            Policy::LoadBalance(_) => "LoadBalance",
            Policy::Relay => "Relay",
        }
    }

    pub fn health(&self) -> &NodeHealth {
        &self.health
    }

    pub fn url(&self) -> &str {
        &self.parts.url
    }

    pub fn expected_text(&self) -> &str {
        &self.parts.expected_text
    }

    pub fn expected(&self) -> &StatusRanges {
        &self.parts.expected
    }

    pub fn hidden(&self) -> bool {
        self.parts.hidden
    }

    pub fn icon(&self) -> &str {
        &self.parts.icon
    }

    pub fn disable_udp(&self) -> bool {
        self.parts.disable_udp
    }

    pub fn is_load_balance(&self) -> bool {
        matches!(self.parts.policy, Policy::LoadBalance(_))
    }

    /// Select, url-test, smart and fallback take a manual pick.
    pub fn is_selectable(&self) -> bool {
        matches!(
            self.parts.policy,
            Policy::Select { .. }
                | Policy::UrlTest { .. }
                | Policy::Smart { .. }
                | Policy::Fallback
        )
    }

    pub fn empty_fallback(&self) -> &Arc<Leaf> {
        &self.parts.empty_fallback
    }

    pub(crate) fn smart(&self) -> Option<&Owner> {
        self.smart.as_ref()
    }

    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.parts.shared
    }

    pub(crate) fn health_watch(&self) -> &Arc<HealthWatch> {
        &self.health_watch
    }

    fn watches_health(&self) -> bool {
        matches!(
            self.parts.policy,
            Policy::UrlTest { .. } | Policy::Smart { .. } | Policy::Fallback
        )
    }

    pub(crate) fn test_timeout(&self) -> Duration {
        self.parts.test_timeout
    }

    pub(crate) fn own_check(&self) -> Option<&Arc<Check>> {
        self.parts.own_check.as_ref()
    }

    pub(crate) fn checks(&self) -> impl Iterator<Item = &Arc<Check>> {
        self.parts
            .own_check
            .iter()
            .chain(self.parts.uses.iter().map(|provider| provider.check()))
    }

    pub fn touch(&self) {
        for check in self.checks() {
            check.touch();
        }
    }

    pub fn members(&self) -> Arc<Members> {
        let current = self.members.load_full();
        if self.is_current(&current) {
            return current;
        }
        let _guard = lock(&self.rebuild);
        let current = self.members.load_full();
        if self.is_current(&current) {
            return current;
        }
        let next = Arc::new(self.compute());
        self.members.store(next.clone());
        next
    }

    fn is_current(&self, members: &Members) -> bool {
        let versions = members.versions();
        self.parts.uses.len() == versions.len()
            && self
                .parts
                .uses
                .iter()
                .zip(versions)
                .all(|(provider, version)| provider.version() == *version)
    }

    fn compute(&self) -> Members {
        let parts = &self.parts;
        let snapshots: Vec<_> = parts.uses.iter().map(|provider| provider.nodes()).collect();
        let versions: Vec<u32> = snapshots
            .iter()
            .map(|snapshot| snapshot.version())
            .collect();

        let mut sections: Vec<(Option<Arc<str>>, Vec<Item>)> = Vec::new();
        let has_own = !parts.own.is_empty();
        if has_own {
            sections.push((None, parts.own.clone()));
        }
        for (provider, snapshot) in parts.uses.iter().zip(&snapshots) {
            let items = if parts.filter.is_empty() {
                snapshot.items().to_vec()
            } else {
                let mut seen = HashSet::new();
                let mut kept = Vec::new();
                for filter in &parts.filter {
                    for item in snapshot.items() {
                        if filter.is_match(item.name()) && seen.insert(item.name().clone()) {
                            kept.push(item.clone());
                        }
                    }
                }
                kept
            };
            sections.push((Some(provider.name().clone()), items));
        }
        let providers_total = sections.len();
        let mut items = self.join(sections, has_own);

        if providers_total > 1 && parts.filter.len() > 1 {
            let mut seen = HashSet::new();
            let mut ordered = Vec::with_capacity(items.len());
            for filter in &parts.filter {
                for item in &items {
                    if filter.is_match(item.name()) && seen.insert(item.name().clone()) {
                        ordered.push(item.clone());
                    }
                }
            }
            for item in &items {
                if seen.insert(item.name().clone()) {
                    ordered.push(item.clone());
                }
            }
            items = ordered;
        }
        if !parts.exclude_filter.is_empty() {
            items.retain(|item| {
                !parts
                    .exclude_filter
                    .iter()
                    .any(|filter| filter.is_match(item.name()))
            });
        }
        if !parts.exclude_type.is_empty() {
            items.retain(|item| {
                !parts
                    .exclude_type
                    .iter()
                    .any(|excluded| item.type_name().eq_ignore_ascii_case(excluded))
            });
        }

        let mut nodes = Vec::with_capacity(items.len());
        let mut ghosts = Vec::new();
        for item in items {
            match item {
                Item::Live(node) => nodes.push(node),
                Item::Ghost(ghost) => ghosts.push(ghost),
            }
        }
        let factors: Box<[f64]> = match &parts.policy {
            Policy::Smart { priority, .. } if !priority.is_empty() => nodes
                .iter()
                .map(|node| normalize_factor(priority.factor(node.name())))
                .collect(),
            _ => Box::new([]),
        };
        let emptiness = if !nodes.is_empty() {
            Emptiness::NotEmpty
        } else if (!ghosts.is_empty() || parts.refused) && !parts.explicit_fallback {
            Emptiness::Quarantined
        } else {
            Emptiness::Fallback
        };
        let id = self.next_members_id.fetch_add(1, Ordering::Relaxed);
        let watch = if self.watches_health() {
            for node in &nodes {
                node.health().watch(&self.health_watch);
            }
            Some(Arc::clone(&self.health_watch))
        } else {
            None
        };
        Members::new(id, nodes, ghosts, factors, versions, emptiness, watch)
    }

    fn join(&self, sections: Vec<(Option<Arc<str>>, Vec<Item>)>, has_own: bool) -> Vec<Item> {
        let positions = &self.parts.use_position;
        if positions.is_empty() || !has_own {
            return sections.into_iter().flat_map(|(_, items)| items).collect();
        }
        let mut sections = sections.into_iter();
        let named = sections.next().map(|(_, items)| items).unwrap_or_default();
        let mut before: Vec<Vec<Item>> = vec![Vec::new(); named.len() + 1];
        for (provider, items) in sections {
            let position = provider
                .as_deref()
                .and_then(|name| positions.get(name))
                .map_or(named.len(), |position| {
                    usize::try_from(*position).unwrap_or(0).min(named.len())
                });
            if let Some(slot) = before.get_mut(position) {
                slot.extend(items);
            }
        }
        let mut out = Vec::new();
        for (index, section) in before.into_iter().enumerate() {
            out.extend(section);
            if let Some(item) = named.get(index) {
                out.push(item.clone());
            }
        }
        out
    }

    /// The names the host lists: the members, or the empty fallback standing in
    /// for none, or nothing when the group refuses.
    pub fn listing(&self, members: &Members) -> Vec<Arc<str>> {
        match members.emptiness() {
            Emptiness::NotEmpty => members
                .nodes()
                .iter()
                .map(|node| node.name().clone())
                .collect(),
            Emptiness::Fallback => vec![self.parts.empty_fallback.name().clone()],
            Emptiness::Quarantined => Vec::new(),
        }
    }

    pub fn pick(self: &Arc<Self>, flow: &FlowMeta, host: Option<&str>, touch: Touch) -> Pick {
        if touch == Touch::Yes {
            self.touch();
        }
        let members = self.members();
        match members.emptiness() {
            Emptiness::Fallback => {
                return Pick::Node(Node::Leaf(self.parts.empty_fallback.clone()));
            }
            Emptiness::Quarantined => {
                let shown = members
                    .ghosts()
                    .first()
                    .map(|ghost| ghost.name.clone())
                    .unwrap_or_default();
                return Pick::Rejected {
                    reason: Arc::from(format!(
                        "every node of group {} is not supported by this core",
                        self.parts.name
                    )),
                    shown,
                };
            }
            Emptiness::NotEmpty => {}
        }
        let nodes = members.nodes();
        let Some(first) = nodes.first() else {
            return Pick::Node(Node::Leaf(self.parts.empty_fallback.clone()));
        };
        match &self.parts.policy {
            Policy::Select { default_selected } => {
                let chosen = self
                    .parts
                    .shared
                    .selections
                    .get(&self.parts.name)
                    .or_else(|| Some(default_selected.clone()).filter(|name| !name.is_empty()));
                if let Some(chosen) = chosen {
                    if let Some(node) = members.find(&chosen) {
                        return Pick::Node(node.clone());
                    }
                    let ghost = members.ghosts().iter().find(|ghost| ghost.name == chosen);
                    if ghost.is_some() || self.parts.quarantined.contains(&*chosen) {
                        return Pick::Rejected {
                            reason: Arc::from(format!(
                                "the selected node {chosen} is not supported by this core"
                            )),
                            shown: ghost.map_or_else(|| chosen.clone(), |ghost| ghost.name.clone()),
                        };
                    }
                }
                Pick::Node(first.clone())
            }
            Policy::UrlTest { tolerance } => Pick::Node(self.url_test_pick(&members, *tolerance)),
            Policy::Smart { .. } => {
                let index = self
                    .smart
                    .as_ref()
                    .map_or(0, |owner| owner.pick(self, &members, flow, host, touch));
                Pick::Node(nodes.get(index).unwrap_or(first).clone())
            }
            Policy::Fallback => {
                let url = &self.parts.url;
                if let Some(pin) = self.parts.shared.selections.get(&self.parts.name)
                    && let Some(node) = members.find(&pin)
                {
                    if node.health().alive_for(url) {
                        return Pick::Node(node.clone());
                    }
                    let selections = &self.parts.shared.selections;
                    if !selections.is_probing(&self.parts.name)
                        && selections.revoke(&self.parts.name)
                    {
                        self.parts.shared.route.moved();
                    }
                }
                let node = nodes
                    .iter()
                    .find(|node| node.health().alive_for(url))
                    .unwrap_or(first);
                Pick::Node(node.clone())
            }
            Policy::LoadBalance(strategy) => {
                let index = strategy.pick(nodes, flow, host, &self.parts.url, touch == Touch::Yes);
                Pick::Node(nodes.get(index).unwrap_or(first).clone())
            }
            Policy::Relay => Pick::Rejected {
                reason: Arc::from("relay groups are not supported by this core"),
                shown: Arc::from(""),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn url_test_pick_with(&self, members: &Arc<Members>, tolerance: u16) -> Node {
        self.url_test_pick(members, tolerance)
    }

    fn url_test_pick(&self, members: &Arc<Members>, tolerance: u16) -> Node {
        let shared = &self.parts.shared;
        let url = self.parts.url.as_str();
        let members_id = members.id();
        let mut state = lock(&self.fast);
        let pin = shared.selections.get(&self.parts.name);
        let epoch = self.health_watch.epoch();
        if let Some(cached) = &state.cached
            && cached.epoch == epoch
            && cached.members_id == members_id
            && cached.pin == pin
        {
            return cached.node.clone();
        }
        #[cfg(test)]
        URL_TEST_SCANS.with(|scans| scans.set(scans.get() + 1));
        let nodes = members.nodes();
        let stale_members = state
            .cached
            .as_ref()
            .is_some_and(|cached| cached.members_id > members_id);
        let chosen = if stale_members {
            let mut prev = state.node.clone();
            self.fastest(&mut prev, nodes, pin.as_deref(), url, tolerance)
        } else {
            self.fastest(&mut state.node, nodes, pin.as_deref(), url, tolerance)
        };
        let changed = !stale_members
            && state
                .cached
                .as_ref()
                .is_none_or(|cached| !cached.node.same(&chosen));
        if !stale_members {
            state.cached = Some(Cached {
                epoch,
                members_id,
                pin,
                node: chosen.clone(),
            });
        }
        drop(state);
        if changed {
            shared.request_refresh();
        }
        chosen
    }

    fn fastest(
        &self,
        previous: &mut Option<Node>,
        nodes: &[Node],
        pin: Option<&str>,
        url: &str,
        tolerance: u16,
    ) -> Node {
        if let Some(pin) = pin
            && let Some(node) = nodes
                .iter()
                .find(|node| node.name().as_ref() == pin && node.health().alive_for(url))
        {
            *previous = Some(node.clone());
            return node.clone();
        }
        let mut fast = nodes
            .first()
            .cloned()
            .unwrap_or_else(|| Node::Leaf(self.parts.empty_fallback.clone()));
        let score = |node: &Node| f64::from(node.health().last_delay_for(url));
        let mut best = score(&fast);
        #[cfg(test)]
        fire_fastest_mid_scan();
        let mut previous_exists = false;
        for (index, node) in nodes.iter().enumerate() {
            if previous.as_ref().is_some_and(|prev| prev.same(node)) {
                previous_exists = true;
            }
            if index == 0 || !node.health().alive_for(url) {
                continue;
            }
            let delay = score(node);
            if delay < best {
                fast = node.clone();
                best = delay;
            }
        }
        let keep = previous.as_ref().filter(|prev| {
            previous_exists
                && prev.health().alive_for(url)
                && score(prev) <= score(&fast) + f64::from(tolerance)
        });
        let chosen = keep.cloned().unwrap_or(fast);
        *previous = Some(chosen.clone());
        chosen
    }

    /// The name the host shows as the current pick; empty for load balancing.
    pub fn now(self: &Arc<Self>, flow: &FlowMeta) -> String {
        if self.is_load_balance() {
            return String::new();
        }
        self.pick(flow, None, Touch::No).name().to_string()
    }

    /// What `proxy.list` shows as `fixed`: a manual pick of an url-test or fallback.
    pub fn fixed(&self) -> String {
        match self.parts.policy {
            Policy::UrlTest { .. } | Policy::Smart { .. } | Policy::Fallback => self
                .parts
                .shared
                .selections
                .get(&self.parts.name)
                .map(|name| name.to_string())
                .unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Whether this group, on a walk to a leaf, stops UDP.
    pub(crate) fn blocks_udp(&self) -> bool {
        self.parts.disable_udp
    }

    /// Counts a failed dial through this group. True when enough failed within
    /// the test window, or one was refused outright, that the group should test
    /// its members now. Running out of descriptors or memory says nothing about
    /// the members, and a test would only ask for more.
    pub(crate) fn dial_failed(&self, child: Option<OutboundKind>, err: &io::Error) -> bool {
        if child.is_some_and(|kind| {
            matches!(
                kind,
                OutboundKind::Direct
                    | OutboundKind::Compatible
                    | OutboundKind::Reject
                    | OutboundKind::RejectDrop
                    | OutboundKind::Pass
                    | OutboundKind::PassRule
            )
        }) || matches!(CoreError::of(err), Some(CoreError::UdpUnsupported(_)))
            || is_local_exhaustion(err)
        {
            return false;
        }
        let mut fail = lock(&self.fail);
        let refused = err.to_string().contains("connection refused");
        let trigger = if refused {
            true
        } else {
            fail.count += 1;
            if fail.count == 1 {
                fail.first = Some(Instant::now());
                false
            } else if fail
                .first
                .is_some_and(|first| first.elapsed() > self.parts.test_timeout)
            {
                fail.count = 0;
                false
            } else {
                fail.count >= self.parts.max_failed
            }
        };
        if trigger && !fail.checking {
            fail.checking = true;
            return true;
        }
        false
    }

    pub(crate) fn dial_succeeded(&self) {
        let mut fail = lock(&self.fail);
        if !fail.checking {
            fail.count = 0;
        }
    }

    pub(crate) fn finish_checking(&self) {
        let mut fail = lock(&self.fail);
        fail.checking = false;
        fail.count = 0;
    }
}
