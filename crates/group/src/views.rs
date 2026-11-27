use std::sync::Arc;

use concord_common::{Address, Network};

use crate::group::{Group, Policy};
use crate::health::HealthSnapshot;
use crate::node::{Leaf, Node};
use crate::outbounds::{Entry, Outbounds, dummy_flow};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeView {
    pub name: Arc<str>,
    pub kind: &'static str,
    pub provider: Option<Arc<str>>,
}

/// `now` is `None` for load balancing and `all` is `None` when a load balancer
/// has no members; `expected_status` and `fixed` exist only on the kinds the
/// host reads them from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupView {
    pub name: Arc<str>,
    pub kind: &'static str,
    pub now: Option<String>,
    pub all: Option<Vec<Arc<str>>>,
    pub test_url: String,
    pub expected_status: Option<String>,
    pub fixed: Option<String>,
    pub hidden: bool,
    pub icon: String,
    pub empty_fallback: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyView {
    Node(NodeView),
    Group(GroupView),
}

#[derive(Clone, Debug, Default)]
pub struct ProxyViews {
    pub all: Vec<Arc<str>>,
    pub proxies: Vec<(Arc<str>, ProxyView)>,
}

enum Routable<'a> {
    Leaf(&'a Arc<Leaf>),
    Group(&'a Arc<Group>),
}

impl Outbounds {
    fn group_view(&self, group: &Arc<Group>) -> GroupView {
        let flow = dummy_flow(Address::new("", 0), Network::Tcp);
        let members = group.members();
        let listing = group.listing(&members);
        let load_balance = matches!(group.policy(), Policy::LoadBalance(_));
        let is_select = matches!(group.policy(), Policy::Select { .. });
        let default_url = self.shared.default_url();
        let hidden = group.hidden() || (self.builtin_global() && group.name().as_ref() == "GLOBAL");
        GroupView {
            name: group.name().clone(),
            kind: group.type_name(),
            now: (!load_balance).then(|| group.now(&flow)),
            all: if load_balance && listing.is_empty() {
                None
            } else {
                Some(listing)
            },
            test_url: if is_select && group.url() == default_url {
                String::new()
            } else {
                group.url().to_string()
            },
            expected_status: (!is_select).then(|| group.expected_text().to_string()),
            fixed: matches!(
                group.policy(),
                Policy::UrlTest { .. } | Policy::Smart { .. } | Policy::Fallback
            )
            .then(|| group.fixed()),
            hidden,
            icon: group.icon().to_string(),
            empty_fallback: group.empty_fallback().name().clone(),
        }
    }

    fn visit_routable(&self, mut visit: impl FnMut(Routable<'_>)) {
        let mut shadowed = std::collections::HashSet::new();
        let mut from_providers = Vec::new();
        for provider in self.providers() {
            for item in provider.nodes().items() {
                if let crate::node::Item::Live(Node::Leaf(leaf)) = item
                    && shadowed.insert(leaf.name().clone())
                {
                    from_providers.push(leaf.clone());
                }
            }
        }
        for name in self.node_order() {
            if shadowed.contains(name) {
                continue;
            }
            if let Some(Entry::Leaf(leaf)) = self.table().get(name) {
                visit(Routable::Leaf(leaf));
            }
        }
        for leaf in &from_providers {
            visit(Routable::Leaf(leaf));
        }
        for group in self.groups() {
            if shadowed.contains(group.name()) {
                continue;
            }
            visit(Routable::Group(group));
        }
    }

    fn routable_names(&self) -> Vec<Arc<str>> {
        let flow = dummy_flow(Address::new("", 0), Network::Tcp);
        let mut names = Vec::new();
        self.visit_routable(|item| match item {
            Routable::Leaf(leaf) => names.push(leaf.name().clone()),
            Routable::Group(group) => {
                // Keep the selection side effects (`now`) of `group_view` in the same order
                // without building member display lists or view strings.
                if !matches!(group.policy(), Policy::LoadBalance(_)) {
                    let _ = group.now(&flow);
                }
                names.push(group.name().clone());
            }
        });
        names
    }

    /// What `proxy.list` shows: group names in config order with the built-in
    /// `GLOBAL` first, and every routable name, where a provider's node wins a
    /// name it shares with a node of the profile.
    pub fn views(&self) -> ProxyViews {
        let mut all: Vec<Arc<str>> = self
            .groups()
            .iter()
            .filter(|group| !(self.builtin_global() && group.name().as_ref() == "GLOBAL"))
            .map(|group| group.name().clone())
            .collect();
        if self.builtin_global() {
            all.insert(0, Arc::from("GLOBAL"));
        }

        let mut proxies: Vec<(Arc<str>, ProxyView)> = Vec::new();
        self.visit_routable(|item| match item {
            Routable::Leaf(leaf) => proxies.push((
                leaf.name().clone(),
                ProxyView::Node(NodeView {
                    name: leaf.name().clone(),
                    kind: leaf.info().kind.wire_name(),
                    provider: leaf.provider().cloned(),
                }),
            )),
            Routable::Group(group) => proxies.push((
                group.name().clone(),
                ProxyView::Group(self.group_view(group)),
            )),
        });
        ProxyViews { all, proxies }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStateView {
    pub name: Arc<str>,
    pub udp: bool,
    pub health: HealthSnapshot,
}

impl Outbounds {
    /// Every routable name when `names` is `None`; unknown names are left out.
    pub fn node_states(&self, names: Option<&[String]>) -> Vec<NodeStateView> {
        let listed: Vec<Arc<str>> = match names {
            Some(names) => names.iter().map(|name| Arc::from(name.as_str())).collect(),
            None => self.routable_names(),
        };
        listed
            .into_iter()
            .filter_map(|name| {
                let node = self.node(&name)?;
                Some(NodeStateView {
                    udp: self.udp_of(&node),
                    health: node.health().snapshot(),
                    name,
                })
            })
            .collect()
    }

    /// A group carries UDP when the member it would use now does.
    fn udp_of(&self, node: &Node) -> bool {
        let flow = dummy_flow(Address::new("", 0), Network::Tcp);
        let mut node = node.clone();
        for _ in 0..=self.table().len() {
            match node {
                Node::Leaf(leaf) => return leaf.info().udp,
                Node::Group(group) => match self.node(&group.now(&flow)) {
                    Some(next) => node = next,
                    None => return false,
                },
            }
        }
        false
    }
}
