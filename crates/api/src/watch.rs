use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use concord_common::ConnRecord;
use concord_engine::{Engine, GroupView, NodeView, ProxyView, ProxyViews, StatusRanges};
use concord_proto::types::{
    ConnectionSnapshot, DelayRunEvent, EngineStatus, GroupInfo, NodeInfo, ProxyDelta, ProxyGroups,
    Traffic,
};
use futures_util::stream::{self, Stream};
use futures_util::{FutureExt, StreamExt};
use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior, interval_at, sleep};
use tokio_util::task::AbortOnDropHandle;

use crate::bus::{ConnStream, EventBus};
use crate::convert;
use crate::stream::{Delivery, EventStream, PolicyQueue, QueueStream, Subscription, policy_of};

const DEFAULT_INTERVAL_MS: u32 = 1000;
const PROXY_DEBOUNCE: Duration = Duration::from_millis(250);

fn traffic_now(engine: &Engine, only_proxy: bool) -> Traffic {
    let (up, down) = engine.traffic_now(only_proxy);
    let (total_up, total_down) = engine.traffic_total(only_proxy);
    Traffic {
        up,
        down,
        total_up,
        total_down,
    }
}

/// A pull stream: nothing is sampled while the consumer holds no credit.
pub fn traffic(
    engine: Arc<Engine>,
    interval_ms: Option<u32>,
    only_proxy: bool,
    changes_only: bool,
) -> Subscription<Traffic, Traffic> {
    let period = Duration::from_millis(u64::from(
        interval_ms
            .filter(|ms| *ms > 0)
            .unwrap_or(DEFAULT_INTERVAL_MS),
    ));
    let snapshot = traffic_now(&engine, only_proxy);
    let mut ticker = interval_at(Instant::now() + period, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let state = (engine, ticker, snapshot.clone());
    let events = stream::unfold(state, move |(engine, mut ticker, mut sent)| async move {
        loop {
            ticker.tick().await;
            let data = traffic_now(&engine, only_proxy);
            if changes_only && data == sent {
                continue;
            }
            sent = data.clone();
            return Some((Delivery::Event { data, dropped: 0 }, (engine, ticker, sent)));
        }
    });
    Subscription::new(Some(snapshot), events.boxed())
}

fn snapshot_of(records: &[Arc<ConnRecord>]) -> ConnectionSnapshot {
    ConnectionSnapshot {
        connections: records
            .iter()
            .map(|record| convert::connection_info(record))
            .collect(),
    }
}

pub fn connection_snapshot(engine: &Engine) -> ConnectionSnapshot {
    snapshot_of(&engine.connections())
}

pub fn connections(
    engine: &Engine,
    bus: &EventBus,
    counters: bool,
) -> Subscription<ConnectionSnapshot, concord_proto::types::ConnectionDelta> {
    let live: ConnStream = bus.watch_connections(counters);
    let records = engine.connections();
    let mut known: Option<HashSet<u64>> = Some(records.iter().map(|record| record.seq).collect());
    let snapshot = snapshot_of(&records);
    let events = live.filter_map(move |mut delivery| {
        let keep = match (&mut delivery, known.take()) {
            (Delivery::Event { data, .. }, Some(seen)) => {
                data.opened.retain(|opened| !seen.contains(&opened.id));
                !(data.opened.is_empty() && data.closed.is_empty() && data.counters.is_empty())
            }
            _ => true,
        };
        std::future::ready(keep.then_some(delivery))
    });
    Subscription::new(Some(snapshot), events.boxed())
}

pub fn engine_state(rx: watch::Receiver<EngineStatus>) -> Subscription<EngineStatus, EngineStatus> {
    let snapshot = rx.borrow().clone();
    let events = stream::unfold(rx, |mut rx| async move {
        rx.changed().await.ok()?;
        let data = rx.borrow_and_update().clone();
        Some((Delivery::Event { data, dropped: 0 }, rx))
    });
    Subscription::new(Some(snapshot), events.boxed())
}

fn groups_of(views: &ProxyViews) -> ProxyGroups {
    let mut groups = Vec::new();
    let mut nodes = Vec::new();
    for (_, view) in &views.proxies {
        match view {
            ProxyView::Group(group) => groups.push(convert::group_info(group)),
            ProxyView::Node(node) => nodes.push(convert::node_info(node)),
        }
    }
    ProxyGroups {
        order: views.all.iter().map(ToString::to_string).collect(),
        groups,
        nodes,
    }
}

pub fn proxy_groups(engine: &Engine) -> ProxyGroups {
    groups_of(&engine.proxy_views())
}

/// What the client holds, to send only what differs.
#[derive(Default)]
struct ProxyMemo {
    order: Vec<Arc<str>>,
    groups: HashMap<Arc<str>, GroupView>,
    nodes: HashMap<Arc<str>, NodeView>,
}

impl ProxyMemo {
    fn of(views: ProxyViews) -> Self {
        let mut memo = ProxyMemo {
            order: views.all,
            ..ProxyMemo::default()
        };
        for (name, view) in views.proxies {
            match view {
                ProxyView::Group(group) => {
                    memo.groups.insert(name, group);
                }
                ProxyView::Node(node) => {
                    memo.nodes.insert(name, node);
                }
            }
        }
        memo
    }

    /// The change from this memo to `views`, which becomes the memo.
    fn advance(&mut self, views: ProxyViews) -> ProxyDelta {
        let next = ProxyMemo::of(views);
        let groups: Vec<GroupInfo> = next
            .groups
            .iter()
            .filter(|(name, group)| self.groups.get(*name) != Some(group))
            .map(|(_, group)| convert::group_info(group))
            .collect();
        let nodes: Vec<NodeInfo> = next
            .nodes
            .iter()
            .filter(|(name, node)| self.nodes.get(*name) != Some(node))
            .map(|(_, node)| convert::node_info(node))
            .collect();
        let mut removed: Vec<String> = self
            .groups
            .keys()
            .filter(|name| !next.groups.contains_key(*name))
            .chain(
                self.nodes
                    .keys()
                    .filter(|name| !next.nodes.contains_key(*name)),
            )
            .map(ToString::to_string)
            .collect();
        removed.sort_unstable();
        let order = (next.order != self.order)
            .then(|| next.order.iter().map(ToString::to_string).collect());
        *self = next;
        ProxyDelta {
            order,
            groups,
            nodes,
            removed,
        }
    }
}

fn is_empty(delta: &ProxyDelta) -> bool {
    delta.order.is_none()
        && delta.groups.is_empty()
        && delta.nodes.is_empty()
        && delta.removed.is_empty()
}

/// Every route move can have changed a pick, so each one is a cue to look again.
/// What is sent is the difference against the last batch, computed when the
/// consumer pulls, which is why a slow consumer loses nothing.
pub fn proxies(engine: Arc<Engine>, bus: &EventBus) -> Subscription<ProxyGroups, ProxyDelta> {
    let cues = bus.watch_route();
    let views = engine.proxy_views();
    let snapshot = groups_of(&views);
    let memo = ProxyMemo::of(views);
    let events = stream::unfold(
        (engine, cues, memo),
        |(engine, mut cues, mut memo)| async move {
            loop {
                cues.next().await?;
                sleep(PROXY_DEBOUNCE).await;
                while cues.next().now_or_never().flatten().is_some() {}
                let delta = memo.advance(engine.proxy_views());
                if !is_empty(&delta) {
                    return Some((
                        Delivery::Event {
                            data: delta,
                            dropped: 0,
                        },
                        (engine, cues, memo),
                    ));
                }
            }
        },
    );
    Subscription::new(Some(snapshot), events.boxed())
}

/// Ends the stream also when the engine stops the run before its `done`.
struct CloseOnDrop(Arc<PolicyQueue<DelayRunEvent>>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Tests every proxy at once, or `concurrency` at a time, and ends with `done`. Dropping the stream
/// stops the tests that are still running.
pub fn delay_run(
    engine: Arc<Engine>,
    proxies: Vec<String>,
    url: String,
    expected: StatusRanges,
    timeout: i64,
    concurrency: Option<u32>,
) -> EventStream<DelayRunEvent> {
    let queue = PolicyQueue::new(policy_of("delay.run"), proxies.len() + 8);
    let sink = CloseOnDrop(queue.clone());
    let width = concurrency.map_or(usize::MAX, |width| width.max(1) as usize);
    let driver = engine.tasks().spawn(async move {
        let mut results = stream::iter(proxies)
            .map(|name| {
                let (engine, url, expected) = (engine.clone(), url.clone(), expected.clone());
                async move {
                    let result = engine
                        .test_delay_expecting(&name, &url, &expected, timeout)
                        .await;
                    (name, result)
                }
            })
            .buffer_unordered(width);
        while let Some((name, result)) = results.next().await {
            sink.0.push(DelayRunEvent::Result {
                name,
                url: result.url,
                value: result.value,
            });
        }
        sink.0.push(DelayRunEvent::Done);
    });
    QueueStream::new(queue, AbortOnDropHandle::new(driver)).boxed()
}

pub fn map_stream<T, U>(
    source: impl Stream<Item = Delivery<T>> + Send + 'static,
    convert: impl Fn(T) -> U + Send + 'static,
) -> EventStream<U> {
    source
        .map(move |delivery| match delivery {
            Delivery::Event { data, dropped } => Delivery::Event {
                data: convert(data),
                dropped,
            },
            Delivery::Resync => Delivery::Resync,
        })
        .boxed()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn node_view(name: &str, kind: &'static str, provider: Option<&str>) -> (Arc<str>, ProxyView) {
        let name: Arc<str> = Arc::from(name);
        (
            name.clone(),
            ProxyView::Node(NodeView {
                name,
                kind,
                provider: provider.map(Arc::from),
            }),
        )
    }

    fn group_view(name: &str, now: &str, members: Vec<Arc<str>>) -> (Arc<str>, ProxyView) {
        let name: Arc<str> = Arc::from(name);
        (
            name.clone(),
            ProxyView::Group(GroupView {
                name,
                kind: "Selector",
                now: Some(now.to_string()),
                all: Some(members),
                test_url: String::new(),
                expected_status: None,
                fixed: None,
                hidden: false,
                icon: String::new(),
                empty_fallback: Arc::from("COMPATIBLE"),
            }),
        )
    }

    fn apply_delta(
        order: &mut Vec<String>,
        groups: &mut BTreeMap<String, GroupInfo>,
        nodes: &mut BTreeMap<String, NodeInfo>,
        delta: ProxyDelta,
    ) {
        if let Some(next_order) = delta.order {
            *order = next_order;
        }
        for name in delta.removed {
            groups.remove(&name);
            nodes.remove(&name);
        }
        for group in delta.groups {
            groups.insert(group.name.clone(), group);
        }
        for node in delta.nodes {
            nodes.insert(node.name.clone(), node);
        }
    }

    #[test]
    fn proxy_memo_moves_views_without_cloning_member_names() {
        let m1: Arc<str> = Arc::from("node-1");
        let m2: Arc<str> = Arc::from("node-2");
        let views = ProxyViews {
            all: vec![Arc::from("G")],
            proxies: vec![group_view("G", "node-1", vec![m1.clone(), m2.clone()])],
        };
        assert_eq!(Arc::strong_count(&m1), 2);
        assert_eq!(Arc::strong_count(&m2), 2);

        let mut memo = ProxyMemo::of(views);
        assert_eq!(Arc::strong_count(&m1), 2);
        assert_eq!(Arc::strong_count(&m2), 2);

        let next_m1: Arc<str> = Arc::from("node-1");
        let next_m2: Arc<str> = Arc::from("node-2");
        let next = ProxyViews {
            all: vec![Arc::from("G")],
            proxies: vec![group_view(
                "G",
                "node-1",
                vec![next_m1.clone(), next_m2.clone()],
            )],
        };
        let delta = memo.advance(next);
        assert!(is_empty(&delta));
        assert_eq!(Arc::strong_count(&m1), 1);
        assert_eq!(Arc::strong_count(&m2), 1);
        assert_eq!(Arc::strong_count(&next_m1), 2);
        assert_eq!(Arc::strong_count(&next_m2), 2);

        drop(memo);
        assert_eq!(Arc::strong_count(&next_m1), 1);
        assert_eq!(Arc::strong_count(&next_m2), 1);
    }

    #[test]
    fn proxy_memo_advance_covers_changes_reverts_swaps_removals_order_and_slow_consumers() {
        let v0 = ProxyViews {
            all: vec![Arc::from("G1"), Arc::from("G2")],
            proxies: vec![
                node_view("n1", "Direct", None),
                node_view("swap", "Socks5", Some("p1")),
                group_view("G1", "n1", vec![Arc::from("n1"), Arc::from("swap")]),
                group_view("G2", "n1", vec![Arc::from("n1")]),
            ],
        };
        let initial = groups_of(&v0);
        let mut fast = ProxyMemo::of(v0.clone());
        let mut slow = ProxyMemo::of(v0.clone());

        let mut fast_order = initial.order.clone();
        let mut fast_groups: BTreeMap<String, GroupInfo> = initial
            .groups
            .iter()
            .map(|group| (group.name.clone(), group.clone()))
            .collect();
        let mut fast_nodes: BTreeMap<String, NodeInfo> = initial
            .nodes
            .iter()
            .map(|node| (node.name.clone(), node.clone()))
            .collect();
        let mut slow_order = fast_order.clone();
        let mut slow_groups = fast_groups.clone();
        let mut slow_nodes = fast_nodes.clone();

        let v1 = ProxyViews {
            all: vec![Arc::from("G1"), Arc::from("G2")],
            proxies: vec![
                node_view("n1", "Direct", None),
                node_view("swap", "Socks5", Some("p1")),
                group_view("G1", "swap", vec![Arc::from("n1"), Arc::from("swap")]),
                group_view("G2", "n1", vec![Arc::from("n1")]),
            ],
        };
        let d1 = fast.advance(v1);
        assert_eq!(d1.order, None);
        assert_eq!(d1.groups.len(), 1);
        assert_eq!(d1.groups[0].name, "G1");
        assert_eq!(d1.groups[0].now.as_deref(), Some("swap"));
        assert!(d1.nodes.is_empty() && d1.removed.is_empty());
        apply_delta(&mut fast_order, &mut fast_groups, &mut fast_nodes, d1);

        let d_revert_slow = slow.advance(v0.clone());
        assert!(is_empty(&d_revert_slow));
        let d_revert_fast = fast.advance(v0);
        apply_delta(
            &mut fast_order,
            &mut fast_groups,
            &mut fast_nodes,
            d_revert_fast,
        );

        let v2 = ProxyViews {
            all: vec![Arc::from("swap"), Arc::from("G1")],
            proxies: vec![
                node_view("G2", "Socks5", Some("p2")),
                group_view("swap", "G2", vec![Arc::from("G2")]),
                group_view("G1", "G2", vec![Arc::from("G2")]),
            ],
        };
        let d2_fast = fast.advance(v2.clone());
        assert_eq!(
            d2_fast.order.as_deref(),
            Some(&["swap".to_string(), "G1".to_string()][..])
        );
        assert_eq!(d2_fast.removed, ["G2", "n1", "swap"]);
        assert_eq!(d2_fast.nodes.len(), 1);
        assert_eq!(d2_fast.nodes[0].name, "G2");
        assert_eq!(d2_fast.nodes[0].provider.as_deref(), Some("p2"));
        apply_delta(&mut fast_order, &mut fast_groups, &mut fast_nodes, d2_fast);

        let d2_slow = slow.advance(v2);
        apply_delta(&mut slow_order, &mut slow_groups, &mut slow_nodes, d2_slow);

        assert_eq!(fast_order, slow_order);
        assert_eq!(fast_groups, slow_groups);
        assert_eq!(fast_nodes, slow_nodes);
    }
}
