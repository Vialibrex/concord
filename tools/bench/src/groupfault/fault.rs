//! Faults applied to one node while traffic flows. Each has a start and a stop, and both are idempotent in
//! effect: stop removes exactly what start added.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::task::JoinHandle;

use super::net::{Node, Topology, site_ip};
use crate::isolate::{run, words};

#[derive(Clone, Debug)]
pub enum Fault {
    /// Drops every packet to and from the node on its client link, with no reset.
    Blackhole,
    /// Drops this share of the client's new TCP flows to the node, every packet of each chosen flow.
    FlowDrop(f64),
    /// Drops the first new flow and no other.
    FlowDropOnce,
    Rate {
        kbit: u64,
    },
    /// Resets connections from the node to one site's address.
    SiteReject {
        site: usize,
    },
    /// Takes the client's own links down; the scenario brings them back after its duration.
    LocalDown,
    /// Moves every node's delay by up to `ms` either way each `period`.
    Jitter {
        ms: f64,
        period: Duration,
    },
    /// Multiplies every node's delay.
    Scale(f64),
}

impl Fault {
    pub fn describe(&self) -> String {
        match self {
            Fault::Blackhole => "blackhole".into(),
            Fault::FlowDrop(p) => format!("flowdrop {p}"),
            Fault::FlowDropOnce => "flowdrop once".into(),
            Fault::Rate { kbit } => format!("rate {kbit}kbit"),
            Fault::SiteReject { site } => format!("site-reject site{site}"),
            Fault::LocalDown => "local-down".into(),
            Fault::Jitter { ms, .. } => format!("jitter {ms}ms"),
            Fault::Scale(factor) => format!("delay x{factor}"),
        }
    }

    pub fn start(&self, topo: &Arc<Topology>, node: &Node) -> Result<Active, String> {
        let mut active = Active::default();
        let ns = node.ns.as_str();
        let dev = node.node_dev.as_str();
        match self {
            Fault::Blackhole => {
                active.rule(ns, "", "INPUT", &format!("-i {dev} -j DROP"))?;
                active.rule(ns, "", "OUTPUT", &format!("-o {dev} -j DROP"))?;
            }
            Fault::FlowDrop(p) => {
                let pick = format!("-m statistic --mode random --probability {p}");
                active.flow_drop(ns, dev, &pick)?;
            }
            Fault::FlowDropOnce => {
                active.flow_drop(ns, dev, "-m limit --limit 1/hour --limit-burst 1")?;
            }
            Fault::Rate { kbit } => {
                let burst = (kbit / 10).max(32);
                for (space, link) in [(&topo.client, &node.client_dev), (&node.ns, &node.node_dev)]
                {
                    active.step(
                        words(&format!(
                            "netns exec {space} tc qdisc add dev {link} parent 1:1 handle 10: \
                             tbf rate {kbit}kbit burst {burst}kbit latency 100ms"
                        )),
                        words(&format!(
                            "netns exec {space} tc qdisc del dev {link} parent 1:1 handle 10:"
                        )),
                    )?;
                }
            }
            Fault::SiteReject { site } => {
                let address = site_ip(*site);
                active.rule(
                    ns,
                    "",
                    "OUTPUT",
                    &format!("-d {address} -p tcp -j REJECT --reject-with tcp-reset"),
                )?;
            }
            Fault::LocalDown => {
                for other in &topo.nodes {
                    active.step(
                        words(&format!(
                            "-n {} link set {} down",
                            topo.client, other.client_dev
                        )),
                        words(&format!(
                            "-n {} link set {} up",
                            topo.client, other.client_dev
                        )),
                    )?;
                }
            }
            Fault::Jitter { ms, period } => {
                active.restore = Some(topo.clone());
                active.task = Some(jitter(topo.clone(), *ms, *period));
            }
            Fault::Scale(factor) => {
                active.restore = Some(topo.clone());
                let scaled: Vec<f64> = topo.nodes.iter().map(|n| n.rtt_ms * factor).collect();
                topo.set_rtts(&scaled)?;
            }
        }
        Ok(active)
    }
}

impl Active {
    /// Marks a share of new flows and drops the node's replies on them. The marked flow's first packet is let
    /// in so the connection tracker confirms the entry and keeps the mark; dropping it on the way in would
    /// discard the entry, and the retransmitted SYN would be drawn again.
    fn flow_drop(&mut self, ns: &str, dev: &str, pick: &str) -> Result<(), String> {
        self.rule(
            ns,
            "mangle",
            "PREROUTING",
            &format!(
                "-i {dev} -p tcp -m conntrack --ctstate NEW -m connmark --mark 0 {pick} \
                 -j CONNMARK --set-mark 1"
            ),
        )?;
        self.rule(
            ns,
            "",
            "OUTPUT",
            &format!("-o {dev} -m connmark --mark 1 -j DROP"),
        )
    }
}

#[derive(Default)]
pub struct Active {
    undo: Vec<Vec<String>>,
    restore: Option<Arc<Topology>>,
    task: Option<JoinHandle<()>>,
}

impl Active {
    fn step(&mut self, start: Vec<String>, undo: Vec<String>) -> Result<(), String> {
        run("ip", &start)?;
        self.undo.push(undo);
        Ok(())
    }

    fn rule(&mut self, ns: &str, table: &str, chain: &str, spec: &str) -> Result<(), String> {
        let table = if table.is_empty() {
            String::new()
        } else {
            format!("-t {table} ")
        };
        self.step(
            words(&format!(
                "netns exec {ns} iptables {table}-A {chain} {spec}"
            )),
            words(&format!(
                "netns exec {ns} iptables {table}-D {chain} {spec}"
            )),
        )
    }

    pub fn stop(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        for undo in self.undo.drain(..).rev() {
            let _ = run("ip", &undo);
        }
        if let Some(topo) = self.restore.take() {
            let base: Vec<f64> = topo.nodes.iter().map(|n| n.rtt_ms).collect();
            let _ = topo.set_rtts(&base);
        }
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn jitter(topo: Arc<Topology>, ms: f64, period: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(period).await;
            let rtts: Vec<f64> = {
                let mut rng = rand::rng();
                topo.nodes
                    .iter()
                    .map(|n| (n.rtt_ms + rng.random_range(-ms..=ms)).max(1.0))
                    .collect()
            };
            let _ = topo.set_rtts(&rtts);
        }
    })
}

/// Counts the new-connection packets each node saw on its client link, and the flows `FlowDrop` marked.
pub fn install_counters(topo: &Topology) -> Result<(), String> {
    for node in &topo.nodes {
        run(
            "ip",
            &words(&format!(
                "netns exec {} iptables -t mangle -A PREROUTING -i {} -p tcp --syn",
                node.ns, node.node_dev
            )),
        )?;
    }
    Ok(())
}

/// `(syn packets, marked flows)` per node, in node order.
pub fn read_counters(topo: &Topology) -> Vec<(u64, u64)> {
    topo.nodes
        .iter()
        .map(|node| {
            let listed = super::net::capture(
                "ip",
                &words(&format!(
                    "netns exec {} iptables -t mangle -nvxL PREROUTING",
                    node.ns
                )),
            )
            .unwrap_or_default();
            let mut rows = listed
                .lines()
                .skip(2)
                .filter_map(|l| l.split_whitespace().next()?.parse::<u64>().ok());
            (rows.next().unwrap_or(0), rows.next().unwrap_or(0))
        })
        .collect()
}
