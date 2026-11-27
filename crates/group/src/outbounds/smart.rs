use std::io;
use std::sync::Arc;
use std::time::Duration;

use concord_common::{CoreError, FlowMeta, Network};
use concord_platform::is_local_exhaustion;

use super::{Entry, Outbounds, Resolved};
use crate::group::{Group, Members, Touch};
use crate::node::Node;
use crate::smart::{FailKind, Owner, SmartFlow, Stamp, run};
use crate::strategy::destination_key;

/// A smart group on a chain, with the member of it the chain went through.
struct OnChain<'a> {
    chain: &'a [Arc<str>],
    position: usize,
    member: &'a Arc<str>,
    group: &'a Arc<Group>,
    owner: &'a Owner,
}

fn fail_kind(err: &io::Error) -> Option<FailKind> {
    match CoreError::of(err) {
        Some(CoreError::TargetRefused(_)) => return Some(FailKind::TargetRefused),
        Some(
            CoreError::UdpUnsupported(_)
            | CoreError::Loopback(_)
            | CoreError::DialerLoop(_)
            | CoreError::Rejected(_)
            | CoreError::FdPressure,
        ) => return None,
        _ => {}
    }
    if is_local_exhaustion(err) {
        return None;
    }
    Some(match err.kind() {
        io::ErrorKind::TimedOut => FailKind::Timeout,
        io::ErrorKind::ConnectionRefused => FailKind::Refused,
        _ => FailKind::Other,
    })
}

/// A selection the user made holds the group on its member, as `Owner::pick` reads it: one naming a proxy no
/// longer a member is ignored there, and one on an ejected member was revoked by the pick that met it.
fn pinned(group: &Group, members: &Members) -> bool {
    group
        .shared()
        .selections
        .get(group.name())
        .is_some_and(|pin| members.find(&pin).is_some())
}

impl Outbounds {
    /// Smart groups on `chain`, innermost first.
    fn smart_on<'a>(&'a self, chain: &'a [Arc<str>]) -> impl Iterator<Item = OnChain<'a>> {
        chain
            .iter()
            .enumerate()
            .skip(1)
            .filter_map(|(position, name)| {
                let Some(Entry::Group(group)) = self.table.get(name) else {
                    return None;
                };
                Some(OnChain {
                    chain,
                    position,
                    member: chain.get(position.checked_sub(1)?)?,
                    group,
                    owner: group.smart()?,
                })
            })
    }

    /// The site key of a flow: TCP only, the registrable domain of its name, else its destination address.
    pub fn smart_site(meta: &FlowMeta, host: Option<&str>) -> Option<Arc<str>> {
        if meta.network != Network::Tcp {
            return None;
        }
        let key = destination_key(&meta.dst, host);
        (!key.is_empty()).then(|| Arc::from(key))
    }

    pub fn has_smart(&self, chain: &[Arc<str>]) -> bool {
        self.smart_on(chain).next().is_some()
    }

    pub fn smart_dial_failed(
        &self,
        chain: &[Arc<str>],
        site: Option<&str>,
        err: &io::Error,
        elapsed: Duration,
        corroborated: bool,
    ) {
        let Some(kind) = fail_kind(err) else {
            return;
        };
        let now = Stamp::now();
        for on in self.smart_on(chain) {
            let actions =
                on.owner
                    .state()
                    .dial_failed(now, on.member, site, kind, elapsed, corroborated);
            run(on.group, actions);
        }
    }

    pub fn smart_dial_succeeded(&self, chain: &[Arc<str>], elapsed: Duration) {
        let now = Stamp::now();
        for on in self.smart_on(chain) {
            on.owner.state().dial_succeeded(now, on.member, elapsed);
        }
    }

    pub fn smart_flow(&self, chain: &[Arc<str>], site: &Arc<str>, tls: bool) -> Option<SmartFlow> {
        let taps: Vec<_> = self
            .smart_on(chain)
            .map(|on| {
                let tap = on.owner.state().flow(on.member.clone(), site.clone(), tls);
                (on.group.clone(), tap)
            })
            .collect();
        (!taps.is_empty()).then(|| SmartFlow::new(taps))
    }

    /// Which network each smart group was on, in `self.groups` order, for `feed_smart` to pass back.
    pub(crate) fn smart_epochs(&self) -> Vec<Option<u64>> {
        self.groups
            .iter()
            .map(|group| group.smart().map(|owner| owner.state().epoch()))
            .collect()
    }

    /// A round of tests that reached `url` hands each smart group on that URL the results for its own members.
    /// `epochs` is `smart_epochs` from before the round; a group whose network changed since drops them.
    pub(crate) fn feed_smart(
        &self,
        url: &str,
        results: &[(Arc<str>, bool)],
        epochs: &[Option<u64>],
    ) {
        let now = Stamp::now();
        for (group, epoch) in self.groups.iter().zip(epochs) {
            let (Some(owner), Some(epoch)) =
                (group.smart().filter(|_| group.url().trim() == url), epoch)
            else {
                continue;
            };
            let members = group.members();
            let own: Vec<(Arc<str>, bool)> = results
                .iter()
                .filter(|(name, _)| members.find(name).is_some())
                .cloned()
                .collect();
            if !own.is_empty() {
                run(group, owner.state().probed(*epoch, now, &own));
            }
        }
    }

    pub fn network_changed(&self) {
        let now = Stamp::now();
        for group in &self.groups {
            if let Some(owner) = group.smart() {
                run(group, owner.state().reset_network(now));
            }
        }
    }

    pub fn smart_retryable(err: &io::Error) -> bool {
        matches!(
            fail_kind(err),
            Some(FailKind::Timeout | FailKind::Refused | FailKind::Other)
        )
    }

    /// The time limit for one attempt through `chain` when a redial would follow it: the innermost smart
    /// group's member's connect RTO. `None` (the attempt gets all the time left) when the group is pinned, when
    /// no member left untried is both live and routable, or before a connect sample. An ejected member is a
    /// redial's last resort after a failure, not a reason to cut a live attempt short.
    pub fn smart_attempt_budget(
        &self,
        chain: &[Arc<str>],
        meta: &FlowMeta,
        host: Option<&str>,
        tried: &[Arc<str>],
    ) -> Option<Duration> {
        let on = self.smart_on(chain).next()?;
        let members = on.group.members();
        if pinned(on.group, &members) {
            return None;
        }
        let live = on.owner.state().live_untried(
            Stamp::now(),
            members.nodes().iter().map(Node::name),
            tried,
        );
        if !self.has_route(&members, &live, meta, host) {
            return None;
        }
        on.owner.state().connect_budget(on.member)
    }

    pub fn smart_member(&self, chain: &[Arc<str>]) -> Option<Arc<str>> {
        self.smart_on(chain).next().map(|on| on.member.clone())
    }

    pub fn smart_retry(
        &self,
        chain: &[Arc<str>],
        meta: &FlowMeta,
        host: Option<&str>,
        tried: &[Arc<str>],
    ) -> Option<(Resolved, Arc<str>)> {
        let on = self.smart_on(chain).next()?;
        let members = on.group.members();
        if pinned(on.group, &members) {
            return None;
        }
        let candidates = on.owner.candidates(on.group, &members);
        let order = on
            .owner
            .state()
            .retry_order(Stamp::now(), &candidates, tried);
        self.route_through(&on, &members, order, meta, host, Touch::Yes)
    }

    fn has_route(
        &self,
        members: &Members,
        order: &[usize],
        meta: &FlowMeta,
        host: Option<&str>,
    ) -> bool {
        order.iter().any(|&index| {
            members.nodes().get(index).is_some_and(|node| {
                matches!(
                    self.walk(node.clone(), meta, host, Touch::No),
                    Resolved::Route { .. }
                )
            })
        })
    }

    /// The route through the first of `order` that walks to one, with the groups outside the smart group kept.
    fn route_through(
        &self,
        on: &OnChain<'_>,
        members: &Members,
        order: Vec<usize>,
        meta: &FlowMeta,
        host: Option<&str>,
        touch: Touch,
    ) -> Option<(Resolved, Arc<str>)> {
        let outer = on.chain.get(on.position..).unwrap_or_default();
        for index in order {
            let Some(node) = members.nodes().get(index) else {
                continue;
            };
            let Resolved::Route {
                leaf,
                chain: walked,
                provider_chain: walked_providers,
                exit_group,
                udp,
            } = self.walk(node.clone(), meta, host, touch)
            else {
                continue;
            };
            let outer_groups: Vec<Arc<Group>> =
                outer.iter().filter_map(|name| self.group(name)).collect();
            let exit_group = outer_groups
                .iter()
                .rev()
                .find(|group| group.is_load_balance())
                .map(|group| group.name().clone())
                .or(exit_group);
            let udp = udp && !outer_groups.iter().any(|group| group.blocks_udp());
            let route = Resolved::Route {
                leaf,
                chain: walked.iter().chain(outer).cloned().collect(),
                provider_chain: walked_providers
                    .iter()
                    .cloned()
                    .chain(outer.iter().map(|_| Arc::from("")))
                    .collect(),
                exit_group,
                udp,
            };
            return Some((route, node.name().clone()));
        }
        None
    }
}
