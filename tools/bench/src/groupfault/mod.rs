//! Proxy groups under injected faults: one Concord client with four Shadowsocks nodes in one group, each node
//! behind a link of its own in its own network namespace, eight HTTPS sites behind them all, and a fault
//! applied to one node while a steady request stream runs. `concord-bench list` names the scenarios.

mod driver;
mod fault;
mod net;
mod record;
mod scenario;
mod sites;
mod summary;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use clap::Args;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Child;

use self::fault::Fault;
use self::net::{NODE_PORT, Topology};
use self::record::{Clock, Event, Recorder};
pub use self::scenario::SCENARIOS;
use crate::core::{CoreSpec, Launch, Running};
use crate::isolate::{self, Placement};
use crate::socks::Entry;
use crate::{env, mitm};

const GROUP: &str = "g";
const MIXED_PORT: u16 = 17_890;
const CONTROL_PORT: u16 = 19_090;

#[derive(Args)]
pub struct GroupFaultArgs {
    #[arg(help = "A scenario name from `concord-bench list`.")]
    #[arg(long)]
    scenario: String,
    #[arg(help = "The Concord binary under test.")]
    #[arg(long)]
    concord: PathBuf,
    #[arg(help = "The mihomo binary that serves the Shadowsocks nodes.")]
    #[arg(long, env = "MIHOMO")]
    mihomo: PathBuf,
    #[arg(help = "The group's `type`.")]
    #[arg(long, default_value = "url-test")]
    group_type: String,
    #[arg(help = "An extra `key=value` in the group, repeatable.")]
    #[arg(long = "group-key")]
    group_keys: Vec<String>,
    #[arg(help = "The group's `interval`, in seconds.")]
    #[arg(long, default_value_t = 60)]
    interval: u32,
    #[arg(help = "The group's `tolerance`; a scenario that names one overrides it.")]
    #[arg(long)]
    tolerance: Option<u32>,
    #[arg(help = "Each node's round trip to the client, in milliseconds, node 1 first.")]
    #[arg(long, value_delimiter = ',', default_value = "60,20,80,40")]
    delays: Vec<f64>,
    #[arg(help = "Seconds of traffic before the fault.")]
    #[arg(long, default_value_t = 60.0)]
    warmup: f64,
    #[arg(help = "Seconds observed after the fault begins; the scenario's own by default.")]
    #[arg(long)]
    observe: Option<f64>,
    #[arg(help = "Requests a second.")]
    #[arg(long, default_value_t = 4.0)]
    rate: f64,
    #[arg(help = "Seconds a request may take; keep it above the core's dial timeout.")]
    #[arg(long, default_value_t = 10.0)]
    timeout: f64,
    #[arg(help = "Share of new flows `flowdrop` drops.")]
    #[arg(long, default_value_t = 0.2)]
    drop: f64,
    #[arg(help = "Rate `rate` limits each end of the node's link to, in kbit/s.")]
    #[arg(long, default_value_t = 512)]
    rate_kbit: u64,
    #[arg(help = "Milliseconds `jitter` moves the delays by, either way.")]
    #[arg(long, default_value_t = 30.0)]
    jitter_ms: f64,
    #[arg(help = "Seconds between the moves of `jitter`.")]
    #[arg(long, default_value_t = 5.0)]
    jitter_period: f64,
    #[arg(help = "The site `site-reject` resets, counted from 1.")]
    #[arg(long, default_value_t = 3)]
    reject_site: usize,
    #[arg(help = "Seconds `local-down` keeps the client's links down.")]
    #[arg(long, default_value_t = 60.0)]
    down_secs: f64,
    #[arg(help = "Seconds without traffic before the observed phase of the idle scenario.")]
    #[arg(long, default_value_t = 600.0)]
    idle_secs: f64,
    #[arg(help = "The `log-level` of the core and of the nodes.")]
    #[arg(long, default_value = "error")]
    log_level: String,
    #[arg(help = "Where requests.jsonl, summary.json, results.json and logs go.")]
    #[arg(long)]
    out: PathBuf,
}

impl GroupFaultArgs {
    fn fault(&self, scenario: &scenario::Scenario) -> Option<(Fault, Option<f64>)> {
        let fault = scenario.kind.fault(self)?;
        let hold = matches!(fault, Fault::LocalDown).then_some(self.down_secs);
        Some((fault, hold))
    }
}

pub fn run(args: GroupFaultArgs) -> Result<bool, String> {
    let scenario = scenario::find(&args.scenario)?;
    if !(cfg!(target_os = "linux") && env::is_root()) {
        return Err("group-faults needs Linux and root".into());
    }
    if args.delays.len() < 2 || args.rate <= 0.0 || args.timeout <= 0.0 {
        return Err("--delays names at least two nodes; --rate and --timeout are positive".into());
    }
    for tool in [("ip", "-V"), ("tc", "-V"), ("iptables", "-V")] {
        std::process::Command::new(tool.0)
            .arg(tool.1)
            .output()
            .map_err(|e| format!("{}: {e}", tool.0))?;
    }
    std::fs::create_dir_all(args.out.join("logs"))
        .map_err(|e| format!("{}: {e}", args.out.display()))?;
    let work = std::env::temp_dir().join(format!("cbg-{}", std::process::id()));
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let topology = Arc::new(Topology::create(&args.delays)?);
    fault::install_counters(&topology)?;
    isolate::enter(&format!("/var/run/netns/{}", topology.client))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let outcome = runtime.block_on(async {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|e| e.to_string())?;
        tokio::select! {
            r = measure(&args, scenario, &topology, &work) => r,
            _ = tokio::signal::ctrl_c() => Err("interrupted".to_string()),
            _ = terminate.recv() => Err("terminated".to_string()),
        }
    });
    drop(runtime);
    drop(topology);
    let _ = std::fs::remove_dir_all(&work);
    outcome.map(|()| true)
}

fn node_config(address: Ipv4Addr, log_level: &str) -> String {
    format!(
        "log-level: {log_level}\nmode: direct\nipv6: false\nfind-process-mode: off\ngeo-auto-update: false\n\
         listeners:\n  - name: ss\n    type: shadowsocks\n    listen: {address}\n    port: {NODE_PORT}\n\
         \x20   password: pw\n    cipher: aes-128-gcm\n    udp: true\nhosts:\n{}",
        (1..=net::SITES)
            .map(|site| format!("  {}: {}\n", net::site_name(site), net::site_ip(site)))
            .collect::<String>()
    )
}

async fn start_nodes(
    topo: &Topology,
    args: &GroupFaultArgs,
    work: &Path,
) -> Result<Vec<Child>, String> {
    let mut children = Vec::new();
    for node in &topo.nodes {
        let home = work.join(format!("node{}", node.index));
        std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
        let config = home.join("config.yaml");
        std::fs::write(&config, node_config(node.address, &args.log_level))
            .map_err(|e| e.to_string())?;
        let log = std::fs::File::create(args.out.join(format!("logs/node{}.log", node.index)))
            .map_err(|e| e.to_string())?;
        let placement = Placement {
            cpus: None,
            netns: Some(node.ns.clone()),
        };
        let mut command = isolate::command(&args.mihomo, &placement);
        command
            .arg("-d")
            .arg(&home)
            .arg("-f")
            .arg(&config)
            .env("DISABLE_LOOPBACK_DETECTOR", "true")
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|e| e.to_string())?)
            .stderr(log);
        children.push(
            isolate::spawn(&mut command, &placement)
                .map_err(|e| format!("spawn node {}: {e}", node.index))?,
        );
    }
    for node in &topo.nodes {
        let target = SocketAddr::new(node.address.into(), NODE_PORT);
        let began = Instant::now();
        while TcpStream::connect(target).await.is_err() {
            if began.elapsed() > Duration::from_secs(30) {
                return Err(format!("node {} did not start listening", node.index));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    Ok(children)
}

fn profile(args: &GroupFaultArgs, topo: &Topology, tolerance: Option<u32>) -> String {
    let mut text = format!(
        "mixed-port: {MIXED_PORT}\nallow-lan: false\nmode: rule\nlog-level: {}\nipv6: false\n\
         find-process-mode: off\ngeo-auto-update: false\ndns:\n  enable: false\n\
         external-controller: 127.0.0.1:{CONTROL_PORT}\nproxies:\n",
        args.log_level
    );
    for node in &topo.nodes {
        text.push_str(&format!(
            "  - {{name: n{}, type: ss, server: {}, port: {NODE_PORT}, cipher: aes-128-gcm, \
             password: pw, udp: true}}\n",
            node.index, node.address
        ));
    }
    let members: Vec<String> = topo.nodes.iter().map(|n| format!("n{}", n.index)).collect();
    text.push_str(&format!(
        "proxy-groups:\n  - name: {GROUP}\n    type: {}\n    proxies: [{}]\n    url: {}\n    interval: {}\n",
        args.group_type,
        members.join(", "),
        sites::health_url(),
        args.interval
    ));
    if let Some(tolerance) = tolerance.or(args.tolerance) {
        text.push_str(&format!("    tolerance: {tolerance}\n"));
    }
    for key in &args.group_keys {
        if let Some((k, v)) = key.split_once('=') {
            text.push_str(&format!("    {k}: {v}\n"));
        }
    }
    text.push_str(&format!("rules:\n  - MATCH,{GROUP}\n"));
    text
}

/// The node the group reports as selected, from the core's REST API; `None` when it does not answer.
async fn selected() -> Option<String> {
    let work = async {
        let mut stream = TcpStream::connect(("127.0.0.1", CONTROL_PORT)).await.ok()?;
        let request = format!("GET /proxies/{GROUP} HTTP/1.0\r\nHost: localhost\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.ok()?;
        let text = String::from_utf8_lossy(&reply);
        let body = text.split("\r\n\r\n").nth(1)?;
        let value: serde_json::Value = serde_json::from_str(body).ok()?;
        value["now"].as_str().map(str::to_string)
    };
    tokio::time::timeout(Duration::from_secs(2), work)
        .await
        .ok()
        .flatten()
}

fn watch_group(clock: Arc<Clock>, events: Recorder) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last = None;
        loop {
            let now = selected().await;
            if let Some(now) = now.filter(|n| last.as_ref() != Some(n)) {
                events.record(Event::Group {
                    t: clock.seconds(),
                    now: now.clone(),
                });
                last = Some(now);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

async fn measure(
    args: &GroupFaultArgs,
    scenario: &scenario::Scenario,
    topo: &Arc<Topology>,
    work: &Path,
) -> Result<(), String> {
    let names: Vec<String> = (1..=net::SITES).map(net::site_name).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let (authority, tls) = mitm::authority_for(&names)?;
    let recorder = Recorder::create(&args.out.join("requests.jsonl"))?;
    let clock = Arc::new(Clock {
        start: Instant::now(),
        phase: Arc::new(AtomicU8::new(0)),
    });
    let mut nodes = start_nodes(topo, args, work).await?;
    let served = sites::serve(topo, tls, clock.clone(), recorder.clone())?;
    let spec = CoreSpec::parse(
        &format!("subject=concord:{}", args.concord.display()),
        &work.join("bin"),
        false,
    )?;
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, MIXED_PORT));
    let core = Running::start(Launch {
        spec: &spec,
        home: work.join("core"),
        profile: profile(args, topo, scenario.tolerance),
        proxy: None,
        tun: None,
        mitm: None,
        trust: None,
        mixed: MIXED_PORT,
        placement: Placement {
            cpus: None,
            netns: Some(topo.client.clone()),
        },
        log: args.out.join("logs/core.log"),
        probe: sites::echo_target(),
        entry: Entry::Socks(proxy),
    })
    .await?;
    let watcher = watch_group(clock.clone(), recorder.clone());
    let load = Arc::new(driver::Load {
        proxy,
        tls: driver::client_config(&authority.cert)?,
        timeout: Duration::from_secs_f64(args.timeout),
        nodes: topo.nodes.clone(),
    });
    let (paused, stop) = (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let driving = tokio::spawn(driver::run(
        load,
        args.rate,
        clock.clone(),
        recorder.clone(),
        paused.clone(),
        stop.clone(),
    ));
    let timeline = scenario::play(args, scenario, topo, &clock, &recorder, &paused).await;
    stop.store(true, Ordering::Relaxed);
    let _ = driving.await;
    watcher.abort();
    for task in served {
        task.abort();
    }
    core.stop().await;
    for child in &mut nodes {
        let _ = child.kill().await;
    }
    let played = timeline?;
    let events = recorder.finish();
    let summary = summary::summarize(&events, &played.meta(args, scenario, topo));
    write_results(args, &summary, &played).map_err(|e| e.to_string())
}

fn write_results(
    args: &GroupFaultArgs,
    summary: &summary::Summary,
    played: &scenario::Played,
) -> std::io::Result<()> {
    let summary = serde_json::to_value(summary)?;
    std::fs::write(
        args.out.join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )?;
    let results = json!({
        "schema": 1,
        "family": "group-faults",
        "args": std::env::args().skip(1).collect::<Vec<_>>(),
        "env": env::collect(),
        "summary": summary,
        "node_counters": played.counters,
        "requests": "requests.jsonl",
    });
    std::fs::write(
        args.out.join("results.json"),
        serde_json::to_string_pretty(&results)?,
    )
}
