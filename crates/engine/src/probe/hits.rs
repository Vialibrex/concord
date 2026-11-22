use std::collections::HashMap;
use std::sync::Mutex;

use concord_common::RouteStamp;
use concord_common::sync::lock;

use super::{ProbeEnv, Prober};

/// Where a request for `host` (`host:port`) left: through `proxy` when the probe
/// was pinned to one, by the rules when `proxy` is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RouteHit {
    pub host: String,
    pub proxy: String,
    pub exit: String,
}

pub(super) fn with_hit(hits: &mut Vec<RouteHit>, hit: RouteHit) {
    match hits
        .iter_mut()
        .find(|known| known.host == hit.host && known.proxy == hit.proxy)
    {
        Some(known) => *known = hit,
        None => hits.push(hit),
    }
}

/// The hits of every request one answer is made from.
#[derive(Default)]
pub struct HitRecorder {
    hits: Mutex<Vec<RouteHit>>,
}

impl HitRecorder {
    pub fn add(&self, added: &[RouteHit]) {
        let mut hits = lock(&self.hits);
        for hit in added {
            with_hit(&mut hits, hit.clone());
        }
    }

    pub fn list(&self) -> Vec<RouteHit> {
        lock(&self.hits).clone()
    }
}

struct Dial {
    address: String,
    chains: Option<Vec<String>>,
}

/// Every connection a probe opened, in order, and the chains of the last one that
/// came up, which after redirects is the one that produced the final response.
#[derive(Default)]
pub struct DialLog {
    state: Mutex<DialState>,
}

#[derive(Default)]
struct DialState {
    dials: Vec<Dial>,
    last: Option<Vec<String>>,
}

impl DialLog {
    pub fn track(&self, address: &str) -> usize {
        let mut state = lock(&self.state);
        state.dials.push(Dial {
            address: address.to_string(),
            chains: None,
        });
        state.dials.len() - 1
    }

    pub fn settle(&self, index: usize, chains: Vec<String>) {
        let mut state = lock(&self.state);
        if let Some(dial) = state.dials.get_mut(index) {
            dial.chains = Some(chains.clone());
        }
        state.last = Some(chains);
    }

    pub fn last_chains(&self) -> Vec<String> {
        lock(&self.state).last.clone().unwrap_or_default()
    }

    /// A connection that never came up is matched again for where it would have left.
    pub fn hits(&self, env: &dyn ProbeEnv, proxy: &str) -> Vec<RouteHit> {
        let dials: Vec<(String, Option<Vec<String>>)> = lock(&self.state)
            .dials
            .iter()
            .map(|dial| (dial.address.clone(), dial.chains.clone()))
            .collect();
        let mut hits = Vec::new();
        for (address, chains) in dials {
            let exit = match chains {
                Some(chains) => exit_of_chains(env, &chains),
                None => resolve_exit(env, &address, proxy),
            };
            with_hit(
                &mut hits,
                RouteHit {
                    host: address,
                    proxy: proxy.to_string(),
                    exit,
                },
            );
        }
        hits
    }
}

pub(super) fn resolve_exit(env: &dyn ProbeEnv, host: &str, proxy: &str) -> String {
    let proxy = (!proxy.is_empty()).then_some(proxy);
    env.exit_through(host, proxy).unwrap_or_default()
}

pub(super) fn exit_of_chains(env: &dyn ProbeEnv, chains: &[String]) -> String {
    if chains.is_empty() {
        return String::new();
    }
    env.exit_of_chains(chains).unwrap_or_default()
}

impl Prober {
    /// The stamp is read before any route resolves, so a move that lands meanwhile
    /// is checked again under its own version rather than missed.
    pub async fn check_routes(&self, routes: &[Vec<RouteHit>]) -> (RouteStamp, Vec<bool>) {
        let stamp = self.env.stamp();
        let mut exits: HashMap<(&str, &str), String> = HashMap::new();
        let mut held = Vec::with_capacity(routes.len());
        for route in routes {
            let mut stands = !route.is_empty();
            for hit in route {
                let key = (hit.host.as_str(), hit.proxy.as_str());
                let exit = match exits.get(&key) {
                    Some(exit) => exit,
                    None => {
                        let proxy = (!hit.proxy.is_empty()).then_some(hit.proxy.as_str());
                        let exit = self
                            .env
                            .resolve_exit(&hit.host, proxy)
                            .await
                            .unwrap_or_default();
                        exits.entry(key).or_insert(exit)
                    }
                };
                if *exit != hit.exit {
                    stands = false;
                    break;
                }
            }
            held.push(stands);
        }
        (stamp, held)
    }
}
