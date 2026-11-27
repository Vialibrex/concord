use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use concord_common::sync::lock;
use concord_config::filter::{Matcher, compile_pattern};
use tokio::sync::Notify;
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;

use crate::health::StatusRanges;
use crate::node::{Item, Node};
use crate::outbounds::Outbounds;
use crate::provider::ProxyProvider;

const SHARE_ROUND: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extra {
    pub url: String,
    pub expected: StatusRanges,
    pub filters: Vec<String>,
}

pub(crate) enum Source {
    Static {
        nodes: Vec<Node>,
        names: HashSet<Arc<str>>,
    },
    Provider(Weak<ProxyProvider>),
}

impl Source {
    pub(crate) fn static_nodes(nodes: Vec<Node>) -> Self {
        let names = nodes.iter().map(|node| node.name().clone()).collect();
        Source::Static { nodes, names }
    }
}

#[derive(Default)]
struct Memo {
    version: u32,
    at: Option<Instant>,
}

/// One health-check schedule: the nodes it tests, the URLs, and how often.
pub struct Check {
    id: String,
    source: Source,
    url: String,
    timeout: Option<Duration>,
    interval: AtomicU64,
    lazy: bool,
    expected: StatusRanges,
    extras: Mutex<Vec<(Extra, Option<Matcher>)>>,
    base: Instant,
    last_touch: AtomicU64,
    kick: Notify,
    round: tokio::sync::Mutex<Memo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckSpec {
    pub url: String,
    pub interval: Duration,
    pub timeout: Option<Duration>,
    pub lazy: bool,
    pub expected: StatusRanges,
    pub extras: Vec<Extra>,
}

pub struct CheckParams {
    pub id: String,
    pub url: String,
    pub timeout_ms: u32,
    pub interval_secs: u32,
    pub lazy: bool,
    pub expected: StatusRanges,
}

impl Check {
    pub(crate) fn new(params: CheckParams, source: Source) -> Arc<Check> {
        let no_url = params.url.is_empty();
        Arc::new(Check {
            id: params.id,
            source,
            url: params.url,
            timeout: (params.timeout_ms > 0)
                .then(|| Duration::from_millis(u64::from(params.timeout_ms))),
            interval: AtomicU64::new(if no_url {
                0
            } else {
                u64::from(params.interval_secs)
            }),
            lazy: params.lazy,
            expected: if no_url {
                StatusRanges::default()
            } else {
                params.expected
            },
            extras: Mutex::new(Vec::new()),
            base: Instant::now(),
            last_touch: AtomicU64::new(0),
            kick: Notify::new(),
            round: tokio::sync::Mutex::new(Memo::default()),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn expected(&self) -> &StatusRanges {
        &self.expected
    }

    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval.load(Ordering::Relaxed))
    }

    pub fn is_auto(&self) -> bool {
        self.interval.load(Ordering::Relaxed) != 0
    }

    pub fn touch(&self) {
        let millis = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        self.last_touch.store(millis + 1, Ordering::Relaxed);
    }

    pub(crate) fn kick(&self) {
        self.kick.notify_one();
    }

    fn skip_for_laziness(&self) -> bool {
        if !self.lazy {
            return false;
        }
        match self.last_touch.load(Ordering::Relaxed) {
            0 => true,
            stamp => {
                let touched = self.base + Duration::from_millis(stamp - 1);
                Instant::now().saturating_duration_since(touched) >= self.interval()
            }
        }
    }

    /// A group using a provider asks for its own URL to be tested too. A
    /// provider without a schedule of its own adopts the group's interval.
    pub fn register_extra(
        &self,
        url: &str,
        expected: &StatusRanges,
        filter: &str,
        interval_secs: u32,
    ) {
        let url = url.trim();
        if url.is_empty() || url == self.url {
            return;
        }
        let _ = self.interval.compare_exchange(
            0,
            u64::from(interval_secs),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        let mut extras = lock(&self.extras);
        let position = match extras.iter().position(|(extra, _)| extra.url == url) {
            Some(position) => position,
            None => {
                extras.push((
                    Extra {
                        url: url.to_string(),
                        expected: expected.clone(),
                        filters: Vec::new(),
                    },
                    None,
                ));
                extras.len() - 1
            }
        };
        if let Some((extra, matcher)) = extras.get_mut(position) {
            for part in filter.trim().split('`') {
                let part = part.trim();
                if !part.is_empty() && !extra.filters.iter().any(|known| known == part) {
                    extra.filters.push(part.to_string());
                }
            }
            *matcher = if extra.filters.is_empty() {
                None
            } else {
                compile_pattern(&extra.filters.join("|"), false).ok()
            };
        }
    }

    pub fn spec(&self) -> CheckSpec {
        CheckSpec {
            url: self.url.clone(),
            interval: self.interval(),
            timeout: self.timeout,
            lazy: self.lazy,
            expected: self.expected.clone(),
            extras: lock(&self.extras)
                .iter()
                .map(|(extra, _)| extra.clone())
                .collect(),
        }
    }

    /// The timeout the config names for this URL, if this schedule tests it.
    pub fn timeout_for(&self, url: &str) -> Option<Duration> {
        let url = url.trim();
        let timeout = self.timeout?;
        if url.is_empty() {
            return None;
        }
        let tested =
            url == self.url || lock(&self.extras).iter().any(|(extra, _)| extra.url == url);
        tested.then_some(timeout)
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub fn version(&self) -> u32 {
        match &self.source {
            Source::Static { .. } => 0,
            Source::Provider(provider) => provider.upgrade().map_or(0, |p| p.version()),
        }
    }

    pub fn nodes(&self) -> (u32, Vec<Node>) {
        match &self.source {
            Source::Static { nodes, .. } => (0, nodes.clone()),
            Source::Provider(provider) => match provider.upgrade() {
                Some(provider) => {
                    let snapshot = provider.nodes();
                    let nodes = snapshot
                        .items()
                        .iter()
                        .filter_map(|item| match item {
                            Item::Live(node) => Some(node.clone()),
                            Item::Ghost(_) => None,
                        })
                        .collect();
                    (snapshot.version(), nodes)
                }
                None => (0, Vec::new()),
            },
        }
    }

    pub fn covers(&self, name: &str) -> bool {
        match &self.source {
            Source::Static { names, .. } => names.contains(name),
            Source::Provider(provider) => provider
                .upgrade()
                .is_some_and(|p| p.nodes().get(name).is_some()),
        }
    }

    pub(crate) fn plan(&self) -> Vec<(String, StatusRanges, Option<Matcher>)> {
        let mut plan = vec![(self.url.clone(), self.expected.clone(), None)];
        let extras = lock(&self.extras);
        plan.extend(
            extras.iter().map(|(extra, matcher)| {
                (extra.url.clone(), extra.expected.clone(), matcher.clone())
            }),
        );
        plan
    }

    /// Callers arriving while a round runs wait for it and share its result,
    /// and one arriving within a second of its end reuses it; a round that
    /// started before the nodes were replaced does not count.
    pub async fn check(&self, owner: &Outbounds) {
        loop {
            let (version, nodes) = self.nodes();
            if nodes.is_empty() {
                return;
            }
            {
                let mut memo = self.round.lock().await;
                let current = self.version();
                let fresh = memo
                    .at
                    .is_some_and(|at| at.elapsed() < SHARE_ROUND && memo.version == current);
                if !fresh {
                    let (version, nodes) = self.nodes();
                    owner.run_round(self, version, nodes).await;
                    memo.version = version;
                    memo.at = Some(Instant::now());
                }
            }
            if self.version() == version {
                return;
            }
        }
    }
}

pub(crate) async fn process(check: Arc<Check>, owner: Weak<Outbounds>, stop: CancellationToken) {
    let period = check.interval();
    if period.is_zero() {
        return;
    }
    let mut ticker = interval_at(Instant::now() + period, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut first = true;
    loop {
        if !first {
            tokio::select! {
                _ = stop.cancelled() => return,
                _ = ticker.tick() => {
                    if check.skip_for_laziness() {
                        continue;
                    }
                }
                _ = check.kick.notified() => {}
            }
        }
        first = false;
        let Some(outbounds) = owner.upgrade() else {
            return;
        };
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = check.check(&outbounds) => {}
        }
    }
}

struct Running {
    spec: CheckSpec,
    cancel: CancellationToken,
}

/// Keeps one task per schedule that runs on its own, restarting it when its
/// spec changed and cancelling it when the schedule is gone.
#[derive(Default)]
pub(crate) struct Supervisor {
    running: HashMap<String, Running>,
    restarts: u64,
}

impl Supervisor {
    pub fn reconcile(
        &mut self,
        checks: &[Arc<Check>],
        owner: &Weak<Outbounds>,
        stop: &CancellationToken,
        tasks: &concord_common::Tasks,
    ) {
        let wanted: HashMap<&str, &Arc<Check>> = checks
            .iter()
            .filter(|check| check.is_auto())
            .map(|check| (check.id(), check))
            .collect();
        self.running.retain(|id, running| {
            let keep = wanted.contains_key(id.as_str());
            if !keep {
                running.cancel.cancel();
            }
            keep
        });
        for (id, check) in wanted {
            let spec = check.spec();
            if let Some(running) = self.running.get(id) {
                if running.spec == spec {
                    continue;
                }
                running.cancel.cancel();
                self.restarts += 1;
            }
            let cancel = stop.child_token();
            tasks.spawn(process((*check).clone(), owner.clone(), cancel.clone()));
            self.running
                .insert(id.to_string(), Running { spec, cancel });
        }
    }

    #[cfg(test)]
    pub fn running(&self) -> usize {
        self.running.len()
    }

    #[cfg(test)]
    pub fn restarts(&self) -> u64 {
        self.restarts
    }
}
