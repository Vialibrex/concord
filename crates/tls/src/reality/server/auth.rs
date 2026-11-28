use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_lc_rs::agreement::{self, X25519};
use concord_common::sync::lock;

use super::hello::{ClientHello, open_session_id};
use crate::error::invalid_data;

/// What a REALITY listener lets in (`reality.go:383-433`); a hello it refuses goes to `dest`.
pub(crate) struct RealityAuth {
    private: agreement::PrivateKey,
    server_names: HashSet<String>,
    short_ids: HashSet<[u8; 8]>,
    max_time_diff: Duration,
    seen: Arc<RealityReplays>,
}

pub(crate) struct Authenticated {
    pub(crate) auth_key: Vec<u8>,
}

impl RealityAuth {
    /// `max_time_diff` of zero leaves the client's time unchecked, as in Go.
    pub(crate) fn new(
        private_key: &[u8; 32],
        server_names: HashSet<String>,
        short_ids: HashSet<[u8; 8]>,
        max_time_diff: Duration,
        seen: Arc<RealityReplays>,
    ) -> io::Result<Self> {
        let private = agreement::PrivateKey::from_private_key(&X25519, private_key)
            .map_err(|_| invalid_data("REALITY: private key"))?;
        Ok(RealityAuth {
            private,
            server_names,
            short_ids,
            max_time_diff,
            seen,
        })
    }

    pub(crate) fn authenticate(
        &self,
        hello: &ClientHello<'_>,
        unix_now: impl FnOnce() -> Duration,
    ) -> Option<Authenticated> {
        if !hello.may_authenticate(&self.server_names) {
            return None;
        }
        let opened = open_session_id(&self.private, hello)?;
        let [_, _, _, _, t0, t1, t2, t3, short_id @ ..] = opened.sealed;
        if !self.short_ids.contains(&short_id) {
            return None;
        }
        let sent = Duration::from_secs(u64::from(u32::from_be_bytes([t0, t1, t2, t3])));
        self.seen
            .first_in_time(hello.random(), sent, self.max_time_diff, unix_now)
            .then_some(Authenticated {
                auth_key: opened.auth_key,
            })
    }
}

/// How long a random is kept when the client's time is not checked.
const UNCHECKED_TIME_WINDOW: Duration = Duration::from_secs(120);
const REPLAY_CAPACITY: usize = 16_384;

/// Outlives the `RealityAuth` a reload replaces (reference-choices `Server replay state`).
#[derive(Default)]
pub(crate) struct RealityReplays(Mutex<Seen>);

impl RealityReplays {
    /// Reads the clock under the lock, so of two equal hellos the later is refused.
    fn first_in_time(
        &self,
        random: [u8; 32],
        sent: Duration,
        max_time_diff: Duration,
        unix_now: impl FnOnce() -> Duration,
    ) -> bool {
        let mut seen = lock(&self.0);
        let now = unix_now();
        let until = if max_time_diff.is_zero() {
            now.saturating_add(UNCHECKED_TIME_WINDOW)
        } else if now.abs_diff(sent) <= max_time_diff {
            sent.saturating_add(max_time_diff)
        } else {
            return false;
        };
        seen.first(random, until, now)
    }
}

/// Oldest first; when full, the oldest goes rather than a new client.
struct Seen {
    capacity: usize,
    order: VecDeque<([u8; 32], Duration)>,
    until: HashMap<[u8; 32], Duration>,
}

impl Default for Seen {
    fn default() -> Self {
        Seen::new(REPLAY_CAPACITY)
    }
}

impl Seen {
    fn new(capacity: usize) -> Self {
        Seen {
            capacity,
            order: VecDeque::new(),
            until: HashMap::new(),
        }
    }

    fn first(&mut self, random: [u8; 32], until: Duration, now: Duration) -> bool {
        while let Some((old, kept)) = self.order.front().copied()
            && kept < now
        {
            self.order.pop_front();
            self.forget(old, kept);
        }
        if self.until.get(&random).is_some_and(|kept| *kept >= now) {
            return false;
        }
        if self.order.len() >= self.capacity
            && let Some((old, kept)) = self.order.pop_front()
        {
            self.forget(old, kept);
        }
        self.until.insert(random, until);
        self.order.push_back((random, until));
        true
    }

    fn forget(&mut self, random: [u8; 32], kept: Duration) {
        if self.until.get(&random) == Some(&kept) {
            self.until.remove(&random);
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::fill;

    use super::super::hello::TLS13;
    use super::super::testing::*;
    use super::*;
    use crate::fingerprints::GROUP_X25519;

    const NOW: u64 = 1_700_000_000;
    const SHORT_ID: [u8; 8] = [0xab, 0xcd, 0, 0, 0, 0, 0, 0];

    fn auth(max_time_diff: Duration) -> (RealityAuth, [u8; 32]) {
        let mut private_key = [0; 32];
        fill(&mut private_key).unwrap();
        let names = HashSet::from(["reality.test".to_owned()]);
        let auth = RealityAuth::new(
            &private_key,
            names,
            HashSet::from([SHORT_ID]),
            max_time_diff,
            Arc::default(),
        )
        .unwrap();
        let public = auth.private.compute_public_key().unwrap();
        (auth, public.as_ref().try_into().unwrap())
    }

    fn lets_in(auth: &RealityAuth, message: &[u8], unix: u64) -> bool {
        let hello = ClientHello::parse(message).unwrap();
        auth.authenticate(&hello, || Duration::from_secs(unix))
            .is_some()
    }

    fn kept(auth: &RealityAuth) -> usize {
        lock(&auth.seen.0).order.len()
    }

    #[test]
    fn a_client_is_let_in_by_its_name_time_and_short_id() {
        let (auth, server) = auth(Duration::from_secs(60));
        let random = |n| [n; 32];
        let good = sealed_hello(server, random(1), "reality.test", SHORT_ID, NOW);
        assert!(lets_in(&auth, &good, NOW + 60));
        let refused = [
            sealed_hello(server, random(2), "other.test", SHORT_ID, NOW),
            sealed_hello(server, random(3), "reality.test", [1; 8], NOW),
            sealed_hello(server, random(4), "reality.test", SHORT_ID, NOW - 61),
            sealed_hello(server, random(5), "reality.test", SHORT_ID, NOW + 61),
        ];
        for message in &refused {
            assert!(!lets_in(&auth, message, NOW));
        }
        assert_eq!(kept(&auth), 1, "only the client that got in is kept");
    }

    /// mihomo `v1.19.33` `component/tls/reality.go:74-76`.
    #[test]
    fn the_client_seals_mihomos_version_ahead_of_its_time_and_short_id() {
        let (auth, server) = auth(Duration::ZERO);
        let message = sealed_hello(server, [1; 32], "reality.test", SHORT_ID, NOW);
        let hello = ClientHello::parse(&message).unwrap();
        let opened = open_session_id(&auth.private, &hello).unwrap();
        let mut sealed = vec![1, 8, 2, 0];
        sealed.extend_from_slice(&u32::try_from(NOW).unwrap().to_be_bytes());
        sealed.extend_from_slice(&SHORT_ID);
        assert_eq!(opened.sealed.as_slice(), sealed.as_slice());
    }

    #[test]
    fn a_hello_that_does_not_offer_tls13_is_not_let_in() {
        let (auth, server) = auth(Duration::ZERO);
        let client = agreement::PrivateKey::generate(&X25519).unwrap();
        let public = client.compute_public_key().unwrap();
        for (n, versions) in [&[0x0303][..], &[0x0303, TLS13][..]]
            .into_iter()
            .enumerate()
        {
            let mut extensions = server_name(&[(0, b"reality.test")]);
            extensions.extend_from_slice(&supported_versions(versions));
            extensions.extend_from_slice(&key_share(&[(GROUP_X25519, public.as_ref())]));
            let mut message = hello([u8::try_from(n).unwrap(); 32], Some(&extensions));
            seal(&mut message, &client, server, SHORT_ID, NOW);
            let offers = versions.contains(&TLS13);
            assert_eq!(lets_in(&auth, &message, NOW), offers);
        }
    }

    #[test]
    fn a_zero_time_difference_leaves_the_time_unchecked() {
        let (auth, server) = auth(Duration::ZERO);
        let old = sealed_hello(server, [1; 32], "reality.test", SHORT_ID, 0);
        assert!(lets_in(&auth, &old, NOW));
        assert!(!lets_in(&auth, &old, NOW + 119));
        assert!(!lets_in(&auth, &old, NOW + 120));
        assert!(lets_in(&auth, &old, NOW + 121));
    }

    #[test]
    fn a_replayed_hello_is_refused_for_as_long_as_its_time_is_accepted() {
        let (auth, server) = auth(Duration::from_secs(30));
        let message = sealed_hello(server, [1; 32], "reality.test", SHORT_ID, NOW);
        assert!(lets_in(&auth, &message, NOW + 30));
        for unix in [NOW - 30, NOW, NOW + 30] {
            assert!(!lets_in(&auth, &message, unix), "{unix}");
        }
        let early = sealed_hello(server, [2; 32], "reality.test", SHORT_ID, NOW + 30);
        assert!(lets_in(&auth, &early, NOW));
        assert!(!lets_in(&auth, &early, NOW + 60));
    }

    #[test]
    fn a_listener_built_again_keeps_the_hellos_the_last_one_let_in() {
        let mut private_key = [0; 32];
        fill(&mut private_key).unwrap();
        let seen = Arc::<RealityReplays>::default();
        let build = || {
            let names = HashSet::from(["reality.test".to_owned()]);
            let ids = HashSet::from([SHORT_ID]);
            RealityAuth::new(&private_key, names, ids, Duration::ZERO, seen.clone()).unwrap()
        };
        let first = build();
        let public = first.private.compute_public_key().unwrap();
        let server = public.as_ref().try_into().unwrap();
        let message = sealed_hello(server, [1; 32], "reality.test", SHORT_ID, NOW);
        assert!(lets_in(&first, &message, NOW));
        assert!(!lets_in(&build(), &message, NOW));
    }

    #[test]
    fn randoms_are_kept_until_their_time_and_the_oldest_give_way_to_new_ones() {
        let at = Duration::from_secs;
        let mut seen = Seen::new(3);
        assert!(seen.first([1; 32], at(10), at(0)));
        assert!(!seen.first([1; 32], at(20), at(10)));
        assert!(seen.first([1; 32], at(20), at(11)));
        for n in 2..=4 {
            assert!(seen.first([n; 32], at(20), at(11)));
        }
        assert_eq!(seen.order.len(), 3);
        assert!(seen.first([1; 32], at(20), at(11)));
        assert!(!seen.first([4; 32], at(20), at(11)));
        assert!(seen.first([5; 32], at(30), at(21)));
        assert_eq!((seen.order.len(), seen.until.len()), (1, 1));
    }
}
