use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{
    CoreEvent, DialEnv, Initiator, IpVersion, LookupIps, RawSocket, SockOpts, Tasks,
};
use concord_tsnet::{BATCH, Conns, Event, Host, Node, Packets};
use gotatun::packet::Packet;
use hickory_proto::rr::RecordType;
use tokio::sync::{Notify, oneshot, watch};
use tokio_util::sync::CancellationToken;

use super::inbox::Inbox;
use super::launch::{NodeOps, NodeSlot};
use super::via::Via;
use super::wait_on;
use crate::stack::{Stack, StackConfig, StackDriver, StackRecv, StackSend};
use crate::wireguard::dns;

/// The MTU tsnet gives its TUN device (`tstun.DefaultTUNMTU`).
pub(super) const MTU: usize = 1280;
/// mihomo's DNS request timeout, for a query to the node's resolver and for the node's own
/// lookup of a control or DERP host.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const LOOKUP_TIMEOUT: Duration = DNS_TIMEOUT;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum Phase {
    #[default]
    Starting,
    NeedsLogin(String),
    Running(Vec<IpAddr>),
    Failed(String),
}

/// Where the node's answer to one DNS query goes.
type DnsAnswer = oneshot::Sender<io::Result<Vec<u8>>>;

/// What the Go side calls back into, on its own threads.
pub(super) struct Bridge {
    env: Arc<DialEnv>,
    opts: SockOpts,
    version: IpVersion,
    tasks: Tasks,
    phase: watch::Sender<Phase>,
    inbox: Inbox,
    writable: Notify,
    answers: Mutex<HashMap<u64, DnsAnswer>>,
    next_query: AtomicU64,
    via: Via,
    name: Arc<str>,
    /// The node's last complaint, which a dial that gives up waiting reports: a refused auth key
    /// comes only as one.
    complaint: Mutex<Option<String>>,
}

impl Bridge {
    pub(super) fn new(start: Start, tasks: &Tasks) -> (Arc<Bridge>, watch::Receiver<Phase>) {
        let (phase, watching) = watch::channel(Phase::Starting);
        let env = Arc::new(start.env);
        let bridge = Bridge {
            via: Via::new(start.name.clone(), start.via, env.clone(), tasks.clone()),
            env,
            opts: start.opts,
            version: start.version,
            tasks: tasks.clone(),
            phase,
            inbox: Inbox::new(),
            writable: Notify::new(),
            answers: Mutex::new(HashMap::new()),
            next_query: AtomicU64::new(1),
            name: start.name,
            complaint: Mutex::new(None),
        };
        (Arc::new(bridge), watching)
    }

    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) fn close_inbox(&self) {
        self.inbox.close();
    }

    pub(super) fn last_complaint(&self) -> Option<String> {
        lock(&self.complaint).clone()
    }
}

impl Host for Bridge {
    fn deliver(&self, packets: Packets<'_>) {
        self.inbox.push(packets.iter());
    }

    fn writable(&self) {
        self.writable.notify_one();
    }

    fn prepare_socket(
        &self,
        socket: RawSocket,
        ipv6: bool,
        _datagram: bool,
        dest: Option<&str>,
    ) -> bool {
        let dest = dest
            .and_then(|text| text.parse::<std::net::SocketAddr>().ok())
            .map(|addr| addr.ip())
            .filter(|ip| !ip.is_unspecified());
        match self
            .env
            .sockets
            .prepare_foreign(socket, ipv6, dest, &self.opts)
        {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(
                    "[Tailscale]({}) preparing a socket failed: {err}",
                    self.name
                );
                false
            }
        }
    }

    fn event(&self, event: Event<'_>) {
        match event {
            Event::LoginUrl(url) => {
                tracing::warn!("[Tailscale]({}) to authenticate, visit: {url}", self.name);
                if self.env.events.enabled() {
                    self.env.events.publish(CoreEvent::NodeLogin {
                        name: self.name.clone(),
                        url: url.to_string(),
                    });
                }
                self.phase.send_replace(Phase::NeedsLogin(url.to_string()));
            }
            Event::State(state) => {
                tracing::info!("[Tailscale]({}) state: {state}", self.name);
            }
            Event::Addrs(json) => {
                let addrs = parse_addrs(json);
                *lock(&self.complaint) = None;
                self.phase.send_replace(Phase::Running(addrs));
            }
            Event::Log(line) => tracing::info!("[Tailscale]({}) {line}", self.name),
            Event::Debug(line) => tracing::debug!("[Tailscale]({}) {line}", self.name),
            Event::Error(why) => {
                tracing::warn!("[Tailscale]({}) {why}", self.name);
                *lock(&self.complaint) = Some(why.to_string());
            }
            Event::Failed(why) => {
                tracing::warn!("[Tailscale]({}) stopped: {why}", self.name);
                self.phase.send_replace(Phase::Failed(why.to_string()));
            }
        }
    }

    fn dns_answer(&self, id: u64, answer: Result<&[u8], &str>) {
        if let Some(waiter) = lock(&self.answers).remove(&id) {
            let _ = waiter.send(answer.map(<[u8]>::to_vec).map_err(io::Error::other));
        }
    }

    fn lookup(&self, host: &str) -> Option<Vec<IpAddr>> {
        let (env, version, name) = (self.env.clone(), self.version, host.to_string());
        let lookup = async move {
            let lookup = env.resolver.lookup(&name, version, Initiator::Proxy);
            tokio::time::timeout(LOOKUP_TIMEOUT, lookup).await
        };
        match wait_on(&self.tasks, lookup) {
            Some(Ok(Ok(found))) => Some(found.v4.into_iter().chain(found.v6).collect()),
            Some(Ok(Err(err))) => {
                tracing::warn!("[Tailscale]({}) resolving {host} failed: {err}", self.name);
                None
            }
            _ => None,
        }
    }

    fn verbose(&self) -> bool {
        tracing::enabled!(tracing::Level::DEBUG)
    }

    fn conns(&self) -> &dyn Conns {
        &self.via
    }
}

fn parse_addrs(json: &str) -> Vec<IpAddr> {
    let value: serde_json::Value = serde_json::from_str(json).unwrap_or_default();
    ["ipv4", "ipv6"]
        .iter()
        .filter_map(|key| value.get(key)?.as_str()?.parse().ok())
        .collect()
}

/// A userspace IP stack bound to one set of Tailscale addresses; the node itself belongs to
/// `Launch` and `NodeSlot`.
pub(super) struct Tunnel<N: NodeOps = Node> {
    pub(super) stack: Arc<Stack>,
    node: Arc<NodeSlot<N>>,
    bridge: Arc<Bridge>,
    addrs: Vec<IpAddr>,
    stop: CancellationToken,
    driver: StackDriver,
}

pub(super) struct Start {
    pub(super) name: Arc<str>,
    pub(super) config: String,
    pub(super) env: DialEnv,
    pub(super) opts: SockOpts,
    pub(super) version: IpVersion,
    /// The node's `dialer-proxy`, which then carries all of its own traffic.
    pub(super) via: Option<Arc<str>>,
}

impl<N: NodeOps> Tunnel<N> {
    pub(super) fn wire(
        bridge: Arc<Bridge>,
        node: Arc<NodeSlot<N>>,
        addrs: Vec<IpAddr>,
        tasks: &Tasks,
        launch: &CancellationToken,
    ) -> (Arc<Self>, [tokio::task::JoinHandle<()>; 2]) {
        let wired = Stack::start(
            &StackConfig {
                addrs: addrs.clone(),
                mtu: MTU,
            },
            tasks,
        );
        bridge.inbox.open();
        let tunnel = Arc::new(Tunnel {
            stack: wired.stack,
            node,
            bridge,
            addrs,
            stop: launch.child_token(),
            driver: wired.driver,
        });
        let send = tunnel.spawn(tasks, "send", send(wired.recv, tunnel.clone()));
        let receive = tunnel.spawn(tasks, "receive", receive(tunnel.bridge.clone(), wired.send));
        (tunnel, [send, receive])
    }

    fn spawn(
        &self,
        tasks: &Tasks,
        role: &'static str,
        work: impl Future<Output = io::Result<()>> + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let stop = self.stop.clone();
        let driver = self.driver.clone();
        let name = self.bridge.name.clone();
        tasks.spawn(async move {
            tokio::select! {
                () = stop.cancelled() => {}
                result = work => {
                    if let Err(err) = result {
                        tracing::warn!("[Tailscale]({name}) {role} ended: {err}");
                    }
                    stop.cancel();
                    driver.stop();
                }
            }
        })
    }

    pub(super) fn addrs(&self) -> &[IpAddr] {
        &self.addrs
    }

    pub(super) fn bridge(&self) -> &Bridge {
        &self.bridge
    }

    pub(super) fn usable(&self) -> bool {
        !self.stop.is_cancelled() && !self.driver.is_finished()
    }

    pub(super) fn stop_stack(&self) {
        self.stop.cancel();
        self.driver.stop();
    }

    pub(super) async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let id = self.bridge.next_query.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.bridge.answers).insert(id, tx);
        if !self
            .node
            .with(|node| node.query_dns(id, query))
            .unwrap_or(false)
        {
            lock(&self.bridge.answers).remove(&id);
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        let answer = tokio::time::timeout(DNS_TIMEOUT, rx).await;
        lock(&self.bridge.answers).remove(&id);
        match answer {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut)),
        }
    }

    /// A and AAAA through the node's resolver: MagicDNS names, then the tailnet's DNS settings.
    pub(super) async fn lookup(&self, host: &str) -> io::Result<LookupIps> {
        let ask = |rtype| async move {
            let (id, wire) = dns::query(host, rtype)?;
            let answer = self.exchange(&wire).await?;
            Ok::<_, io::Error>(dns::parse(&answer, id).map(|a| a.ips).unwrap_or_default())
        };
        let (v4, v6) = tokio::join!(ask(RecordType::A), ask(RecordType::AAAA));
        let found = LookupIps {
            v4: v4.unwrap_or_default(),
            v6: v6.unwrap_or_default(),
        };
        if found.is_empty() {
            return Err(concord_common::CoreError::IpNotFound(host.to_string()).into());
        }
        Ok(found)
    }
}

async fn send<N: NodeOps>(mut outgoing: StackRecv, tunnel: Arc<Tunnel<N>>) -> io::Result<()> {
    let mut packets: Vec<Packet> = Vec::with_capacity(BATCH);
    loop {
        packets.clear();
        outgoing.recv_many(&mut packets, BATCH).await?;
        let mut done = 0;
        while done < packets.len() {
            let rest = packets.get(done..).unwrap_or_default();
            let notified = tunnel.bridge.writable.notified();
            done += tunnel
                .node
                .with(|node| node.send(rest.iter().map(AsRef::as_ref)))?;
            if done < packets.len() {
                notified.await;
            }
        }
    }
}

async fn receive(bridge: Arc<Bridge>, mut incoming: StackSend) -> io::Result<()> {
    use gotatun::tun::IpSend;
    let mut batch = Inbox::spare();
    loop {
        bridge.inbox.take(&mut batch).await;
        for packet in batch.drain(..) {
            if let Ok(packet) = packet.try_into_ip() {
                incoming.send(packet).await?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_env;
    use concord_common::EventSink;

    #[derive(Default)]
    struct Logins(Mutex<Vec<(String, String)>>);

    impl EventSink for Logins {
        fn enabled(&self) -> bool {
            true
        }

        fn publish(&self, event: CoreEvent) {
            if let CoreEvent::NodeLogin { name, url } = event {
                lock(&self.0).push((name.to_string(), url));
            }
        }
    }

    #[tokio::test]
    async fn a_login_url_is_published_and_held_for_the_next_dial() {
        let logins = Arc::new(Logins::default());
        let env = DialEnv {
            events: logins.clone(),
            ..test_env()
        };
        let start = Start {
            name: "ts".into(),
            config: String::new(),
            env,
            opts: SockOpts::default(),
            version: IpVersion::default(),
            via: None,
        };
        let (bridge, phase) = Bridge::new(start, &crate::testing::Tracked::new().tasks);
        bridge.event(Event::LoginUrl("https://login.test/a"));
        assert_eq!(
            *lock(&logins.0),
            [("ts".to_string(), "https://login.test/a".to_string())]
        );
        assert_eq!(
            *phase.borrow(),
            Phase::NeedsLogin("https://login.test/a".into())
        );
    }
}
