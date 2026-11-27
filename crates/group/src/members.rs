use std::collections::HashMap;
use std::sync::Arc;

use crate::health::HealthWatch;
use crate::node::{Ghost, Node};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emptiness {
    NotEmpty,
    /// Nothing to pick, and the empty fallback answers.
    Fallback,
    /// Every member that would match is a node the core dropped.
    Quarantined,
}

pub struct Members {
    id: u64,
    nodes: Vec<Node>,
    ghosts: Vec<Arc<Ghost>>,
    index: HashMap<Arc<str>, usize>,
    factors: Box<[f64]>,
    versions: Vec<u32>,
    emptiness: Emptiness,
    watch: Option<Arc<HealthWatch>>,
}

impl Drop for Members {
    fn drop(&mut self) {
        if let Some(watch) = &self.watch {
            for node in &self.nodes {
                node.health().unwatch(watch);
            }
        }
    }
}

impl Members {
    pub(crate) fn empty(provider_count: usize) -> Members {
        Members {
            id: 0,
            nodes: Vec::new(),
            ghosts: Vec::new(),
            index: HashMap::new(),
            factors: Box::new([]),
            versions: vec![u32::MAX; provider_count],
            emptiness: Emptiness::Fallback,
            watch: None,
        }
    }

    pub(crate) fn new(
        id: u64,
        nodes: Vec<Node>,
        ghosts: Vec<Arc<Ghost>>,
        factors: Box<[f64]>,
        versions: Vec<u32>,
        emptiness: Emptiness,
        watch: Option<Arc<HealthWatch>>,
    ) -> Members {
        let mut index = HashMap::with_capacity(nodes.len());
        for (position, node) in nodes.iter().enumerate() {
            index.entry(node.name().clone()).or_insert(position);
        }
        Members {
            id,
            nodes,
            ghosts,
            index,
            factors,
            versions,
            emptiness,
            watch,
        }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    pub fn ghosts(&self) -> &[Arc<Ghost>] {
        &self.ghosts
    }

    pub(crate) fn versions(&self) -> &[u32] {
        &self.versions
    }

    pub fn emptiness(&self) -> Emptiness {
        self.emptiness
    }

    pub fn find(&self, name: &str) -> Option<&Node> {
        self.index
            .get(name)
            .and_then(|index| self.nodes.get(*index))
    }

    pub(crate) fn index_of(&self, name: &str) -> Option<usize> {
        self.index.get(name).copied()
    }

    pub(crate) fn has_unique_names(&self) -> bool {
        self.index.len() == self.nodes.len()
    }

    pub(crate) fn factor(&self, index: usize) -> f64 {
        self.factors.get(index).copied().unwrap_or(1.0)
    }

    #[cfg(test)]
    pub(crate) fn for_test(names: &[Arc<str>], factors: &[f64]) -> Members {
        use std::sync::atomic::{AtomicU64, Ordering};

        use concord_common::OutboundKind;

        use crate::node::Leaf;
        use crate::priority::normalize_factor;

        static TEST_ID: AtomicU64 = AtomicU64::new(1);
        let behavior = Arc::new(crate::tests::Behavior::default());
        let nodes: Vec<Node> = names
            .iter()
            .map(|name| {
                let outbound = crate::tests::FakeNode::outbound(
                    name,
                    OutboundKind::Direct,
                    true,
                    behavior.clone(),
                );
                Node::Leaf(Leaf::new(outbound, None))
            })
            .collect();
        let factors: Box<[f64]> = factors
            .iter()
            .map(|factor| normalize_factor(*factor))
            .collect();
        let emptiness = if nodes.is_empty() {
            Emptiness::Fallback
        } else {
            Emptiness::NotEmpty
        };
        Members::new(
            TEST_ID.fetch_add(1, Ordering::Relaxed),
            nodes,
            Vec::new(),
            factors,
            Vec::new(),
            emptiness,
            None,
        )
    }
}
