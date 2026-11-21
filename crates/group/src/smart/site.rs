use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use super::node::Rtt;
use super::{SITE_LIMIT, SITE_PROBLEM_NODES, SITE_TTL, Stamp};

pub(super) struct Unanswered {
    pub id: u64,
    pub node: Arc<str>,
    pub judged: bool,
}

pub(super) struct Site {
    seq: u64,
    used: Stamp,
    pub node: Arc<str>,
    pub demoted: Vec<Arc<str>>,
    pub problem: bool,
    rtt: Vec<(Arc<str>, Rtt)>,
    pub flows: Vec<Unanswered>,
}

impl Site {
    pub fn srtt(&self, node: &str) -> Option<f64> {
        self.rtt
            .iter()
            .find(|(name, _)| name.as_ref() == node)
            .map(|(_, rtt)| rtt.srtt)
    }

    pub fn is_demoted(&self, node: &str) -> bool {
        self.demoted.iter().any(|name| name.as_ref() == node)
    }
}

struct Watch {
    since: Stamp,
    site: Arc<str>,
    id: u64,
}

#[derive(Default)]
pub(super) struct SiteBook {
    map: HashMap<Arc<str>, Site>,
    order: BTreeMap<u64, Arc<str>>,
    next: u64,
    watch: VecDeque<Watch>,
}

impl SiteBook {
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
        self.watch.clear();
    }

    pub fn live(&self, site: &str, now: Stamp) -> Option<&Site> {
        self.map
            .get(site)
            .filter(|entry| now.since(&entry.used) < SITE_TTL)
    }

    fn live_mut(&mut self, site: &str, now: Stamp) -> Option<&mut Site> {
        self.map
            .get_mut(site)
            .filter(|entry| now.since(&entry.used) < SITE_TTL)
    }

    /// Drops the entries unused for `SITE_TTL`; the order is least recently used first.
    pub fn expire(&mut self, now: Stamp) {
        while let Some((_, key)) = self.order.first_key_value() {
            let key = key.clone();
            if self
                .map
                .get(&key)
                .is_some_and(|entry| now.since(&entry.used) < SITE_TTL)
            {
                break;
            }
            self.order.pop_first();
            self.map.remove(&key);
        }
    }

    pub fn renew(&mut self, site: &str, now: Stamp) {
        let Some((key, _)) = self.map.get_key_value(site) else {
            return;
        };
        let key = key.clone();
        let seq = self.next;
        let Some(entry) = self.map.get_mut(site) else {
            return;
        };
        self.order.remove(&entry.seq);
        entry.seq = seq;
        entry.used = now;
        self.order.insert(seq, key);
        self.next += 1;
    }

    pub fn set_node(&mut self, site: &str, node: &Arc<str>) {
        if let Some(entry) = self.map.get_mut(site)
            && entry.node != *node
        {
            entry.node = node.clone();
        }
    }

    pub fn insert(&mut self, site: &str, node: &Arc<str>, now: Stamp) {
        if let Some(old) = self.map.remove(site) {
            self.order.remove(&old.seq);
        }
        while self.map.len() >= SITE_LIMIT {
            let Some((_, key)) = self.order.pop_first() else {
                break;
            };
            self.map.remove(&key);
        }
        let key: Arc<str> = Arc::from(site);
        let seq = self.next;
        self.next += 1;
        self.order.insert(seq, key.clone());
        self.map.insert(
            key,
            Site {
                seq,
                used: now,
                node: node.clone(),
                demoted: Vec::new(),
                problem: false,
                rtt: Vec::new(),
                flows: Vec::new(),
            },
        );
    }

    /// Demotes `node` for `site`; a third demoted node makes the site a problem and fixes it on the demoted
    /// node that answered fastest.
    pub fn demote(&mut self, site: &str, node: &Arc<str>, now: Stamp) {
        let Some(entry) = self.live_mut(site, now) else {
            return;
        };
        if !entry.is_demoted(node) {
            entry.demoted.push(node.clone());
        }
        if entry.problem || entry.demoted.len() < SITE_PROBLEM_NODES {
            return;
        }
        entry.problem = true;
        let fastest = entry
            .demoted
            .iter()
            .filter_map(|name| entry.srtt(name).map(|srtt| (name, srtt)))
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(name, _)| name.clone());
        if let Some(name) = fastest {
            entry.node = name;
        }
    }

    pub fn register(
        &mut self,
        site: &Arc<str>,
        node: &Arc<str>,
        id: u64,
        since: Stamp,
        now: Stamp,
    ) {
        let Some(entry) = self.live_mut(site, now) else {
            return;
        };
        entry.flows.push(Unanswered {
            id,
            node: node.clone(),
            judged: false,
        });
        self.watch.push_back(Watch {
            since,
            site: site.clone(),
            id,
        });
    }

    /// Takes the flow out of its entry; `Some(judged)` when it was still there.
    pub fn unregister(&mut self, site: &str, id: u64, now: Stamp) -> Option<bool> {
        let entry = self.live_mut(site, now)?;
        let at = entry.flows.iter().position(|flow| flow.id == id)?;
        Some(entry.flows.swap_remove(at).judged)
    }

    pub fn observe(&mut self, site: &str, node: &Arc<str>, sample: Duration, now: Stamp) {
        let Some(entry) = self.live_mut(site, now) else {
            return;
        };
        match entry.rtt.iter_mut().find(|(name, _)| name == node) {
            Some((_, rtt)) => rtt.update(sample),
            None => entry.rtt.push((node.clone(), Rtt::first(sample))),
        }
    }

    /// Marks each flow that has gone `limit` without a download as judged and returns it once.
    pub fn overdue(&mut self, now: Stamp, limit: Duration) -> Vec<(Arc<str>, Arc<str>, Duration)> {
        let mut out = Vec::new();
        while let Some(front) = self.watch.front() {
            let waited = now.since(&front.since);
            if waited < limit {
                break;
            }
            let Some(Watch { site, id, .. }) = self.watch.pop_front() else {
                break;
            };
            let Some(entry) = self.live_mut(&site, now) else {
                continue;
            };
            if let Some(flow) = entry
                .flows
                .iter_mut()
                .find(|flow| flow.id == id && !flow.judged)
            {
                flow.judged = true;
                out.push((flow.node.clone(), site, waited));
            }
        }
        out
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }
}
