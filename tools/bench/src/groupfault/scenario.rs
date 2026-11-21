//! The scenarios: what to inject, and for how long to watch. Each run is setup, warm-up, fault, observe,
//! teardown.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::GroupFaultArgs;
use super::fault::{self, Fault};
use super::net::Topology;
use super::record::{Clock, Event, Recorder};
use super::summary::Meta;

#[derive(Clone, Copy)]
pub enum Kind {
    Blackhole,
    FlowDrop,
    Rate,
    SiteReject,
    Jitter,
    Scale,
    Idle,
    LocalDown,
    FlowDropOnce,
}

impl Kind {
    pub fn fault(self, args: &GroupFaultArgs) -> Option<Fault> {
        Some(match self {
            Kind::Blackhole => Fault::Blackhole,
            Kind::FlowDrop => Fault::FlowDrop(args.drop),
            Kind::Rate => Fault::Rate {
                kbit: args.rate_kbit,
            },
            Kind::SiteReject => Fault::SiteReject {
                site: args.reject_site,
            },
            Kind::Jitter => Fault::Jitter {
                ms: args.jitter_ms,
                period: Duration::from_secs_f64(args.jitter_period),
            },
            Kind::Scale => Fault::Scale(2.0),
            Kind::Idle => return None,
            Kind::LocalDown => Fault::LocalDown,
            Kind::FlowDropOnce => Fault::FlowDropOnce,
        })
    }
}

pub struct Scenario {
    pub name: &'static str,
    pub about: &'static str,
    /// Seconds observed after the fault begins, unless `--observe` says otherwise.
    pub observe_s: f64,
    /// A tolerance the scenario needs, which `--tolerance` does not override.
    pub tolerance: Option<u32>,
    pub kind: Kind,
}

const fn scenario(
    name: &'static str,
    about: &'static str,
    observe_s: f64,
    tolerance: Option<u32>,
    kind: Kind,
) -> Scenario {
    Scenario {
        name,
        about,
        observe_s,
        tolerance,
        kind,
    }
}

pub const SCENARIOS: &[Scenario] = &[
    scenario(
        "S1",
        "node death: the fastest node drops every packet",
        300.0,
        None,
        Kind::Blackhole,
    ),
    scenario(
        "S2",
        "intermittent: the fastest node drops a share of new flows",
        300.0,
        None,
        Kind::FlowDrop,
    ),
    scenario(
        "S3",
        "rate limit: the fastest node's link is capped",
        300.0,
        None,
        Kind::Rate,
    ),
    scenario(
        "S4",
        "site reject: the fastest node resets connections to one site",
        300.0,
        None,
        Kind::SiteReject,
    ),
    scenario(
        "S6",
        "jitter: every delay moves by a few milliseconds, tolerance 0",
        300.0,
        Some(0),
        Kind::Jitter,
    ),
    scenario(
        "S6b",
        "drift: every delay doubles",
        300.0,
        None,
        Kind::Scale,
    ),
    scenario(
        "S7",
        "idle: no traffic, then traffic; counts the health checks each node saw",
        300.0,
        None,
        Kind::Idle,
    ),
    scenario(
        "S8",
        "local outage: the client's links go down, then up",
        180.0,
        None,
        Kind::LocalDown,
    ),
    scenario(
        "S9",
        "one lost flow: the fastest node drops a single new flow",
        300.0,
        None,
        Kind::FlowDropOnce,
    ),
];

pub fn find(name: &str) -> Result<&'static Scenario, String> {
    SCENARIOS
        .iter()
        .find(|s| s.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| format!("unknown scenario {name}; see `concord-bench list`"))
}

pub struct Played {
    pub t0: f64,
    pub observe_s: f64,
    pub fault: String,
    pub node: usize,
    pub counters: Vec<Value>,
}

impl Played {
    pub fn meta(&self, args: &GroupFaultArgs, scenario: &Scenario, topo: &Topology) -> Meta {
        Meta {
            scenario: scenario.name.to_string(),
            group_type: args.group_type.clone(),
            fault: self.fault.clone(),
            node: self.node,
            t0: self.t0,
            observe_s: self.observe_s,
            egress: topo.nodes.iter().map(|n| n.egress.to_string()).collect(),
        }
    }
}

fn fastest(topo: &Topology) -> usize {
    topo.nodes
        .iter()
        .min_by(|a, b| a.rtt_ms.total_cmp(&b.rtt_ms))
        .map_or(1, |n| n.index)
}

pub async fn play(
    args: &GroupFaultArgs,
    scenario: &Scenario,
    topo: &Arc<Topology>,
    clock: &Clock,
    recorder: &Recorder,
    paused: &AtomicBool,
) -> Result<Played, String> {
    let observe = args.observe.unwrap_or(scenario.observe_s);
    let pause = |what: &str| {
        recorder.record(Event::Mark {
            t: clock.seconds(),
            what: what.to_string(),
        });
    };
    tokio::time::sleep(Duration::from_secs_f64(args.warmup)).await;
    if matches!(scenario.kind, Kind::Idle) {
        clock.phase.store(2, Ordering::Relaxed);
        paused.store(true, Ordering::Relaxed);
        pause("idle begins");
        tokio::time::sleep(Duration::from_secs_f64(args.idle_secs)).await;
        paused.store(false, Ordering::Relaxed);
    }
    let node = fastest(topo);
    let before = fault::read_counters(topo);
    let t0 = clock.seconds();
    clock.phase.store(1, Ordering::Relaxed);
    let planned = args.fault(scenario);
    let label = planned
        .as_ref()
        .map_or_else(|| "none".to_string(), |(f, _)| f.describe());
    pause(&format!("fault begins: {label} on node {node}"));
    let mut active = match &planned {
        Some((fault, _)) => Some(fault.start(topo, &topo.nodes[node - 1])?),
        None => None,
    };
    let mut remaining = observe;
    if let Some((_, Some(hold))) = &planned {
        let hold = hold.min(observe);
        tokio::time::sleep(Duration::from_secs_f64(hold)).await;
        if let Some(active) = active.take() {
            active.stop();
        }
        pause("fault ends");
        remaining -= hold;
    }
    tokio::time::sleep(Duration::from_secs_f64(remaining)).await;
    let after = fault::read_counters(topo);
    if let Some(active) = active.take() {
        active.stop();
    }
    let counters = before
        .iter()
        .zip(&after)
        .enumerate()
        .map(|(i, (b, a))| {
            json!({
                "node": i + 1,
                "syn_packets": a.0.saturating_sub(b.0),
                "marked_flows": a.1.saturating_sub(b.1),
            })
        })
        .collect();
    Ok(Played {
        t0,
        observe_s: observe,
        fault: label,
        node,
        counters,
    })
}
