use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use concord_common::sync::lock;
use concord_common::{Address, FlowMeta};
use tokio::time::{Duration, Instant};

use crate::node::Node;
use crate::public_suffix;

const STICKY_TTL: Duration = Duration::from_secs(600);
const STICKY_SIZE: usize = 1000;
const MAX_RETRY: usize = 5;

pub enum Strategy {
    ConsistentHashing { in_user: bool },
    RoundRobin(Mutex<usize>),
    StickySessions { in_user: bool, cache: Mutex<Sticky> },
}

#[derive(Default)]
pub struct Sticky {
    entries: HashMap<u64, (usize, Instant, u64)>,
    order: BTreeMap<u64, u64>,
    clock: u64,
}

impl Sticky {
    fn touch(&mut self, key: u64, old: Option<u64>) -> u64 {
        if let Some(old) = old {
            self.order.remove(&old);
        }
        self.clock += 1;
        self.order.insert(self.clock, key);
        self.clock
    }

    fn get(&mut self, key: u64) -> Option<usize> {
        let (index, at, rank) = *self.entries.get(&key)?;
        if at.elapsed() >= STICKY_TTL {
            self.entries.remove(&key);
            self.order.remove(&rank);
            return None;
        }
        let rank = self.touch(key, Some(rank));
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.2 = rank;
        }
        Some(index)
    }

    fn set(&mut self, key: u64, index: usize) {
        let old = self.entries.get(&key).map(|entry| entry.2);
        if old.is_none()
            && self.entries.len() >= STICKY_SIZE
            && let Some((_, oldest)) = self.order.pop_first()
        {
            self.entries.remove(&oldest);
        }
        let rank = self.touch(key, old);
        self.entries.insert(key, (index, Instant::now(), rank));
    }
}

impl Strategy {
    /// The index of the member this flow goes to. `nodes` is never empty.
    pub fn pick(
        &self,
        nodes: &[Node],
        flow: &FlowMeta,
        host: Option<&str>,
        url: &str,
        touch: bool,
    ) -> usize {
        let alive = |index: usize| nodes.get(index).is_some_and(|n| n.health().alive_for(url));
        let length = nodes.len();
        match self {
            Strategy::RoundRobin(cursor) => {
                let mut cursor = lock(cursor);
                let start = *cursor;
                for step in 0..length {
                    let index = (start + step) % length;
                    if alive(index) {
                        if touch {
                            *cursor = (start + step + 1) % length;
                        }
                        return index;
                    }
                }
                0
            }
            Strategy::ConsistentHashing { in_user } => {
                let mut key = map_hash(&route_key(flow, host, *in_user));
                for _ in 0..MAX_RETRY {
                    let index = jump_hash(key, length);
                    if alive(index) {
                        return index;
                    }
                    key = key.wrapping_add(1);
                }
                (0..length).find(|index| alive(*index)).unwrap_or(0)
            }
            Strategy::StickySessions { in_user, cache } => {
                let key = map_hash(&route_key_with_source(flow, host, *in_user));
                let mut cache = lock(cache);
                let cached = cache.get(key).filter(|index| *index < length);
                let first = cached.unwrap_or_else(|| jump_hash(key.wrapping_add(nanos()), length));
                let mut index = first;
                for _ in 1..MAX_RETRY {
                    if alive(index) {
                        if cached.is_none() || index != first {
                            cache.set(key, index);
                        }
                        return index;
                    }
                    index = jump_hash(key.wrapping_add(nanos()), length);
                }
                cache.set(key, 0);
                0
            }
        }
    }
}

fn nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0)
}

fn map_hash(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash
}

fn jump_hash(mut key: u64, buckets: usize) -> usize {
    let (mut bucket, mut next) = (0i64, 0i64);
    let buckets = buckets as i64;
    while next < buckets {
        bucket = next;
        key = key.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(1);
        next = ((bucket + 1) as f64 * ((1u64 << 31) as f64 / ((key >> 33) + 1) as f64)) as i64;
    }
    usize::try_from(bucket).unwrap_or(0)
}

fn route_key(flow: &FlowMeta, host: Option<&str>, in_user: bool) -> String {
    if in_user && let Some(user) = flow.inbound.user.as_deref().filter(|user| !user.is_empty()) {
        return user.to_string();
    }
    destination_key(&flow.dst, host)
}

fn route_key_with_source(flow: &FlowMeta, host: Option<&str>, in_user: bool) -> String {
    if in_user && let Some(user) = flow.inbound.user.as_deref().filter(|user| !user.is_empty()) {
        return user.to_string();
    }
    format!("{}{}", flow.src.ip(), destination_key(&flow.dst, host))
}

pub(crate) fn destination_key(dst: &Address, host: Option<&str>) -> String {
    let named = match (host.filter(|host| !host.is_empty()), dst) {
        (Some(host), _) => Some(host),
        (None, Address::Domain(host, _)) if !host.is_empty() => Some(&**host),
        _ => None,
    };
    if let Some(host) = named {
        if host.parse::<IpAddr>().is_ok() {
            return host.to_string();
        }
        if let Some(domain) = public_suffix::registrable_domain(host) {
            return domain;
        }
    }
    match dst {
        Address::Socket(addr) => addr.ip().to_string(),
        Address::Domain(..) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use concord_common::{InboundInfo, InboundKind, Network};

    use super::*;

    fn flow(user: Option<&str>, host: &str) -> FlowMeta {
        let mut inbound = InboundInfo::new(InboundKind::Socks5);
        inbound.user = user.map(Arc::from);
        FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound,
            src: SocketAddr::from(([127, 0, 0, 1], 5000)),
            dst: Address::new(host, 443),
        }
    }

    #[test]
    fn keys_are_the_registrable_domain_or_the_address() {
        assert_eq!(
            destination_key(&Address::new("a.b.example.com", 80), None),
            "example.com"
        );
        assert_eq!(
            destination_key(&Address::new("www.bbc.co.uk", 80), None),
            "bbc.co.uk"
        );
        assert_eq!(destination_key(&Address::new("co.uk", 80), None), "");
        assert_eq!(destination_key(&Address::new("localhost", 80), None), "");
        assert_eq!(
            destination_key(&Address::new("a.b.github.io", 80), None),
            "b.github.io"
        );
        assert_eq!(
            destination_key(&Address::new("x.app.vercel.app", 80), None),
            "app.vercel.app"
        );
        assert_eq!(
            destination_key(&Address::new("www.foo.unknowntld", 80), None),
            "foo.unknowntld"
        );
        assert_eq!(destination_key(&Address::new("example.com.", 80), None), "");
        assert_eq!(
            destination_key(
                &Address::Socket(SocketAddr::from(([9, 9, 9, 9], 80))),
                Some("localhost")
            ),
            "9.9.9.9"
        );
        assert_eq!(
            destination_key(&Address::new("1.2.3.4", 80), None),
            "1.2.3.4"
        );
    }

    #[test]
    fn the_in_user_key_ignores_the_destination_and_falls_back_without_a_user() {
        let hosts = ["a.example.com", "b.example.org", "c.example.net"];
        let keys: Vec<String> = hosts
            .iter()
            .map(|h| route_key(&flow(Some("job-1"), h), None, true))
            .collect();
        assert!(keys.iter().all(|key| key == "job-1"));
        assert_eq!(
            route_key(&flow(None, "a.example.com"), None, true),
            "example.com"
        );
        assert_eq!(
            route_key(&flow(Some("job-1"), "a.example.com"), None, false),
            "example.com"
        );
        let distinct: std::collections::HashSet<String> = hosts
            .iter()
            .map(|h| route_key(&flow(Some("job-1"), h), None, false))
            .collect();
        assert_eq!(distinct.len(), hosts.len());
    }

    #[test]
    fn sticky_sessions_key_on_source_and_destination() {
        let a = route_key_with_source(&flow(None, "a.example.com"), None, false);
        assert_eq!(a, "127.0.0.1example.com");
        let b = route_key_with_source(&flow(Some("job-2"), "a.example.com"), None, true);
        assert_eq!(b, "job-2");
    }

    #[test]
    fn jump_hash_stays_in_range_and_moves_few_keys_when_growing() {
        let mut moved = 0;
        for key in 0..2000u64 {
            let before = jump_hash(map_hash(&key.to_string()), 8);
            let after = jump_hash(map_hash(&key.to_string()), 9);
            assert!(before < 8 && after < 9);
            if before != after {
                moved += 1;
            }
        }
        assert!(moved < 500, "{moved} of 2000 keys moved");
    }

    #[test]
    fn sticky_sessions_evict_the_least_recently_used_entry() {
        let mut cache = Sticky::default();
        for key in 0..STICKY_SIZE as u64 {
            cache.set(key, 1);
        }
        assert_eq!(cache.get(0), Some(1));
        cache.set(10_000, 2);
        assert_eq!(cache.get(0), Some(1));
        assert_eq!(cache.get(1), None);
        assert_eq!(cache.get(10_000), Some(2));
        assert_eq!(cache.entries.len(), STICKY_SIZE);
        assert_eq!(cache.order.len(), STICKY_SIZE);
    }

    #[tokio::test(start_paused = true)]
    async fn sticky_sessions_do_not_extend_the_ttl_on_a_hit() {
        let mut cache = Sticky::default();
        cache.set(1, 3);
        tokio::time::advance(Duration::from_secs(400)).await;
        assert_eq!(cache.get(1), Some(3));
        tokio::time::advance(Duration::from_secs(250)).await;
        assert_eq!(cache.get(1), None);
        assert!(cache.order.is_empty());
    }
}
