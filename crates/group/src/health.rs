use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::SystemTime;

use concord_common::sync::lock;

const HISTORY: usize = 10;
pub const NOT_ALIVE: u16 = 0xffff;

/// An empty list accepts every status, which is what `*` and the empty string mean.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusRanges(Vec<(u16, u16)>);

impl StatusRanges {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() || text == "*" {
            return Some(StatusRanges::default());
        }
        let normalized = text.replace(',', "/");
        let parts: Vec<&str> = normalized.split('/').collect();
        if parts.len() > 28 {
            return None;
        }
        let mut ranges = Vec::new();
        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (start, end) = match part.split_once('-') {
                Some((a, b)) => (a.trim().parse().ok()?, b.trim().parse().ok()?),
                None => {
                    let n = part.parse().ok()?;
                    (n, n)
                }
            };
            if start > end {
                return None;
            }
            ranges.push((start, end));
        }
        Some(StatusRanges(ranges))
    }

    pub fn accepts(&self, status: u16) -> bool {
        self.0.is_empty() || self.0.iter().any(|(lo, hi)| (*lo..=*hi).contains(&status))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelayRecord {
    pub time: SystemTime,
    pub delay: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlHealth {
    pub url: String,
    pub alive: bool,
    pub history: Vec<DelayRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub alive: bool,
    pub history: Vec<DelayRecord>,
    pub extra: Vec<UrlHealth>,
}

#[derive(Debug)]
struct State {
    alive: bool,
    history: VecDeque<DelayRecord>,
}

impl State {
    fn new() -> Self {
        State {
            alive: true,
            history: VecDeque::new(),
        }
    }

    /// Room is taken on the first result: most of a very large profile is never tested.
    fn put(&mut self, record: DelayRecord) {
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history.reserve_exact(HISTORY - self.history.len());
        self.history.push_back(record);
    }
}

#[derive(Debug)]
struct Inner {
    global: State,
    extra: HashMap<String, State>,
}

/// Per-group health generation bumped synchronously when any watched member records a test result.
#[derive(Debug, Default)]
pub(crate) struct HealthWatch {
    epoch: AtomicU64,
}

impl HealthWatch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    pub fn notify(&self) {
        self.epoch.fetch_add(1, Ordering::Release);
    }
}

/// Results hang on the node that was tested, so a provider replacing the node
/// behind a name leaves the old result with the old node.
#[derive(Debug)]
pub struct NodeHealth {
    inner: Mutex<Inner>,
    watchers: Mutex<Vec<(Weak<HealthWatch>, usize)>>,
}

impl Default for NodeHealth {
    fn default() -> Self {
        NodeHealth {
            inner: Mutex::new(Inner {
                global: State::new(),
                extra: HashMap::new(),
            }),
            watchers: Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static LOCK_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_lock_calls() -> usize {
    LOCK_CALLS.with(|calls| calls.replace(0))
}

impl NodeHealth {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        #[cfg(test)]
        LOCK_CALLS.with(|calls| calls.set(calls.get() + 1));
        lock(&self.inner)
    }

    pub fn alive_for(&self, url: &str) -> bool {
        let inner = self.lock();
        match inner.extra.get(url) {
            Some(state) => state.alive,
            None => inner.global.alive,
        }
    }

    /// `NOT_ALIVE` when the node is dead or has no result at that URL, so the
    /// fastest node is the smallest value.
    pub fn last_delay_for(&self, url: &str) -> u16 {
        let inner = self.lock();
        let Some(state) = inner.extra.get(url) else {
            return NOT_ALIVE;
        };
        match state.history.back() {
            Some(record) if state.alive && record.delay != 0 => record.delay,
            _ => NOT_ALIVE,
        }
    }

    /// The median of the delays this node's tests at `url` got, failed tests left out.
    pub fn median_delay_for(&self, url: &str) -> Option<u16> {
        let inner = self.lock();
        let state = inner.extra.get(url)?;
        let mut buffer = [0u16; HISTORY];
        let mut count = 0;
        for record in state.history.iter().filter(|record| record.delay != 0) {
            if let Some(slot) = buffer.get_mut(count) {
                *slot = record.delay;
                count += 1;
            }
        }
        let delays = buffer.get_mut(..count)?;
        delays.sort_unstable();
        let high = *delays.get(count / 2)?;
        if count % 2 == 1 {
            return Some(high);
        }
        let low = *delays.get((count / 2).checked_sub(1)?)?;
        u16::try_from((u32::from(low) + u32::from(high)) / 2).ok()
    }

    pub fn history(&self) -> Vec<DelayRecord> {
        self.lock().global.history.iter().copied().collect()
    }

    pub fn history_for(&self, url: &str) -> Vec<DelayRecord> {
        self.lock()
            .extra
            .get(url)
            .map(|state| state.history.iter().copied().collect())
            .unwrap_or_default()
    }

    /// The global state and each tested URL's, URLs in sorted order.
    pub fn snapshot(&self) -> HealthSnapshot {
        let inner = self.lock();
        let mut extra: Vec<UrlHealth> = inner
            .extra
            .iter()
            .map(|(url, state)| UrlHealth {
                url: url.clone(),
                alive: state.alive,
                history: state.history.iter().copied().collect(),
            })
            .collect();
        extra.sort_by(|a, b| a.url.cmp(&b.url));
        HealthSnapshot {
            alive: inner.global.alive,
            history: inner.global.history.iter().copied().collect(),
            extra,
        }
    }

    pub(crate) fn watch(&self, watcher: &Arc<HealthWatch>) {
        let weak = Arc::downgrade(watcher);
        let mut watchers = lock(&self.watchers);
        for (existing, count) in watchers.iter_mut() {
            if existing.ptr_eq(&weak) {
                *count += 1;
                return;
            }
        }
        watchers.push((weak, 1));
    }

    pub(crate) fn unwatch(&self, watcher: &Arc<HealthWatch>) {
        let weak = Arc::downgrade(watcher);
        let mut watchers = lock(&self.watchers);
        let mut index = 0;
        while index < watchers.len() {
            let remove = match watchers.get_mut(index) {
                Some((existing, count)) if existing.ptr_eq(&weak) => {
                    *count = count.saturating_sub(1);
                    *count == 0
                }
                Some((existing, _)) => existing.strong_count() == 0,
                None => break,
            };
            if remove {
                watchers.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }

    /// `failed` is a test that did not complete; `satisfied` is an expected status
    /// match, which only the per-URL state cares about.
    pub fn record(&self, url: &str, delay: u16, failed: bool, satisfied: bool) {
        let mut record = DelayRecord {
            time: SystemTime::now(),
            delay: if failed { 0 } else { delay },
        };
        let mut alive = !failed;
        {
            let mut inner = self.lock();
            inner.global.alive = alive;
            inner.global.put(record);
            let state = inner
                .extra
                .entry(url.to_string())
                .or_insert_with(State::new);
            if !satisfied {
                record.delay = 0;
                alive = false;
            }
            state.alive = alive;
            state.put(record);
        }
        let mut watchers = lock(&self.watchers);
        let mut index = 0;
        while index < watchers.len() {
            let live = watchers.get(index).and_then(|(weak, _)| weak.upgrade());
            match live {
                Some(watcher) => {
                    watcher.notify();
                    index += 1;
                }
                None => {
                    watchers.swap_remove(index);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Millis(u16),
    TimedOut,
    Failed,
}

impl Outcome {
    /// `-1` for a timeout and `-2` for a failure, which the host tells apart.
    pub fn value(self) -> i32 {
        match self {
            Outcome::Millis(ms) => i32::from(ms),
            Outcome::TimedOut => -1,
            Outcome::Failed => -2,
        }
    }

    pub fn from_hook(delay: u16, timed_out: bool) -> Self {
        if delay > 0 {
            Outcome::Millis(delay)
        } else if timed_out {
            Outcome::TimedOut
        } else {
            Outcome::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_follow_the_expected_status_grammar() {
        let cases = [
            ("", 500, true),
            ("*", 500, true),
            ("200", 200, true),
            ("200", 204, false),
            ("200/302", 302, true),
            ("200,204,401-429", 404, true),
            ("200,204,401-429", 430, false),
            (" 200 / 301-302 ", 301, true),
        ];
        for (text, status, want) in cases {
            let ranges = StatusRanges::parse(text).unwrap();
            assert_eq!(ranges.accepts(status), want, "{text:?} accepts {status}");
        }
        assert!(StatusRanges::parse("20x").is_none());
        assert!(StatusRanges::parse("300-200").is_none());
        assert!(StatusRanges::parse("70000").is_none());
    }

    #[test]
    fn a_node_is_alive_until_a_test_says_otherwise() {
        let watch = HealthWatch::new();
        let health = NodeHealth::default();
        health.watch(&watch);
        assert!(health.alive_for("u"));
        assert_eq!(health.last_delay_for("u"), NOT_ALIVE);

        health.record("u", 120, false, true);
        assert!(health.alive_for("u"));
        assert_eq!(health.last_delay_for("u"), 120);
        assert!(
            health.alive_for("other"),
            "an untested URL follows the global state"
        );

        health.record("u", 0, true, false);
        assert!(!health.alive_for("u"));
        assert!(!health.alive_for("other"));
        assert_eq!(health.last_delay_for("u"), NOT_ALIVE);
        assert_eq!(watch.epoch(), 2);
    }

    #[test]
    fn an_unexpected_status_kills_only_that_url() {
        let health = NodeHealth::default();
        health.record("u", 80, false, false);
        assert!(!health.alive_for("u"));
        assert!(
            health.alive_for("v"),
            "the global state saw a completed test"
        );
        assert_eq!(health.history().last().map(|r| r.delay), Some(80));
        assert_eq!(health.history_for("u").last().map(|r| r.delay), Some(0));
    }

    #[test]
    fn history_keeps_the_last_ten() {
        let health = NodeHealth::default();
        for i in 1..=15 {
            health.record("u", i, false, true);
        }
        let history = health.history();
        assert_eq!(history.len(), 10);
        assert_eq!(history.first().map(|r| r.delay), Some(6));
    }

    #[test]
    fn delay_values_keep_timeout_and_failure_apart() {
        assert_eq!(Outcome::from_hook(35, false).value(), 35);
        assert_eq!(Outcome::from_hook(0, true).value(), -1);
        assert_eq!(Outcome::from_hook(0, false).value(), -2);
        assert_eq!(Outcome::from_hook(7, true).value(), 7);
    }
}
