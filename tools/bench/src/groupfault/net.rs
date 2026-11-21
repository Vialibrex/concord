//! Namespaces for the group-faults family: a client, one namespace per proxy node behind a veth of its own
//! with its own netem delay, and an origin that every node reaches through a second veth.

use std::net::Ipv4Addr;
use std::path::Path;

use crate::isolate::{Link, run, words};

pub const SITES: usize = 8;
pub const NODE_PORT: u16 = 8388;
pub const INFRA: Ipv4Addr = Ipv4Addr::new(10, 70, 0, 100);
const NAMESPACE_PREFIX: &str = "cbg";

pub fn site_ip(site: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 70, 0, site as u8)
}

pub fn site_name(site: usize) -> String {
    format!("site{site}.test")
}

#[derive(Clone, Debug)]
pub struct Node {
    pub index: usize,
    pub ns: String,
    pub client_dev: String,
    pub node_dev: String,
    pub origin_dev: String,
    pub origin_peer: String,
    pub address: Ipv4Addr,
    /// The source address the origin sees for traffic this node carries.
    pub egress: Ipv4Addr,
    pub rtt_ms: f64,
}

pub struct Topology {
    pub client: String,
    pub origin: String,
    pub nodes: Vec<Node>,
}

pub fn capture(program: &str, args: &[String]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Removes every namespace of this family, and the files that name them, left by an earlier run.
pub fn sweep() {
    let listed = capture("ip", &words("netns list")).unwrap_or_default();
    for name in listed
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| n.starts_with(NAMESPACE_PREFIX))
    {
        let _ = run("ip", &words(&format!("netns del {name}")));
    }
    if let Ok(entries) = std::fs::read_dir("/etc/netns") {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(NAMESPACE_PREFIX)
            {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

fn netem_args(dev_ns: &str, dev: &str, rtt_ms: f64, verb: &str) -> Vec<String> {
    let link = Link {
        rtt_ms,
        rate_mbit: None,
        loss_pct: 0.0,
        usec_ts: false,
    };
    let mut args = words(&format!(
        "netns exec {dev_ns} tc qdisc {verb} dev {dev} root handle 1:"
    ));
    args.extend(link.netem());
    args
}

impl Topology {
    /// `rtts` is the round trip of each node's link to the client, in milliseconds.
    pub fn create(rtts: &[f64]) -> Result<Topology, String> {
        sweep();
        let tag = std::process::id() % 100_000;
        let mut topology = Topology {
            client: format!("{NAMESPACE_PREFIX}c{tag}"),
            origin: format!("{NAMESPACE_PREFIX}o{tag}"),
            nodes: Vec::new(),
        };
        for (i, rtt) in rtts.iter().enumerate() {
            let n = i + 1;
            topology.nodes.push(Node {
                index: n,
                ns: format!("{NAMESPACE_PREFIX}n{tag}x{n}"),
                client_dev: format!("gc{tag}{n}"),
                node_dev: format!("gn{tag}{n}"),
                origin_dev: format!("go{tag}{n}"),
                origin_peer: format!("gq{tag}{n}"),
                address: Ipv4Addr::new(10, 60, n as u8, 2),
                egress: Ipv4Addr::new(10, 61, n as u8, 1),
                rtt_ms: *rtt,
            });
        }
        if let Err(err) = topology.build() {
            topology.destroy();
            return Err(err);
        }
        Ok(topology)
    }

    fn build(&self) -> Result<(), String> {
        let mut steps: Vec<String> = Vec::new();
        for ns in [&self.client, &self.origin] {
            steps.push(format!("netns add {ns}"));
        }
        for node in &self.nodes {
            steps.push(format!("netns add {}", node.ns));
        }
        steps.push(format!("-n {} link set lo up", self.client));
        steps.push(format!("-n {} link set lo up", self.origin));
        for site in 1..=SITES {
            steps.push(format!(
                "-n {} addr add {}/32 dev lo",
                self.origin,
                site_ip(site)
            ));
        }
        steps.push(format!("-n {} addr add {INFRA}/32 dev lo", self.origin));
        for node in &self.nodes {
            let n = node.index;
            let (c, o) = (&self.client, &self.origin);
            steps.extend([
                format!(
                    "link add {} netns {c} type veth peer name {} netns {}",
                    node.client_dev, node.node_dev, node.ns
                ),
                format!(
                    "link add {} netns {} type veth peer name {} netns {o}",
                    node.origin_dev, node.ns, node.origin_peer
                ),
                format!("-n {c} addr add 10.60.{n}.1/30 dev {}", node.client_dev),
                format!(
                    "-n {} addr add {}/30 dev {}",
                    node.ns, node.address, node.node_dev
                ),
                format!(
                    "-n {} addr add {}/30 dev {}",
                    node.ns, node.egress, node.origin_dev
                ),
                format!("-n {o} addr add 10.61.{n}.2/30 dev {}", node.origin_peer),
                format!("-n {} link set lo up", node.ns),
            ]);
            for (space, dev) in [
                (c.as_str(), node.client_dev.clone()),
                (node.ns.as_str(), node.node_dev.clone()),
                (node.ns.as_str(), node.origin_dev.clone()),
                (o.as_str(), node.origin_peer.clone()),
            ] {
                steps.push(format!("-n {space} link set {dev} up"));
            }
            steps.push(format!(
                "-n {} route add 10.70.0.0/24 via 10.61.{n}.2",
                node.ns
            ));
        }
        for step in steps {
            run("ip", &words(&step))?;
        }
        for node in &self.nodes {
            for (space, dev) in [(&self.client, &node.client_dev), (&node.ns, &node.node_dev)] {
                run("ip", &netem_args(space, dev, node.rtt_ms, "add"))?;
            }
            let hosts: String = std::iter::once("127.0.0.1 localhost\n".to_string())
                .chain((1..=SITES).map(|s| format!("{} {}\n", site_ip(s), site_name(s))))
                .collect();
            let dir = Path::new("/etc/netns").join(&node.ns);
            std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            std::fs::write(dir.join("hosts"), hosts).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Sets each node's round trip; the two ends of its client link each carry half.
    pub fn set_rtts(&self, rtts: &[f64]) -> Result<(), String> {
        for (node, rtt) in self.nodes.iter().zip(rtts) {
            for (space, dev) in [(&self.client, &node.client_dev), (&node.ns, &node.node_dev)] {
                run("ip", &netem_args(space, dev, *rtt, "change"))?;
            }
        }
        Ok(())
    }

    pub fn destroy(&self) {
        let spaces = [&self.client, &self.origin]
            .into_iter()
            .chain(self.nodes.iter().map(|n| &n.ns));
        for ns in spaces {
            let _ = run("ip", &words(&format!("netns del {ns}")));
            let _ = std::fs::remove_dir_all(Path::new("/etc/netns").join(ns));
        }
    }
}

impl Drop for Topology {
    fn drop(&mut self) {
        self.destroy();
    }
}
