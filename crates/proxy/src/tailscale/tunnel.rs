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
use concord_tsnet::{BATCH, Conns, Event, Host, Library, Node, Packets};
use gotatun::packet::Packet;
use hickory_proto::rr::RecordType;
use tokio::sync::{Notify, oneshot, watch};
use tokio_util::sync::CancellationToken;

use super::inbox::Inbox;
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
    via: Via,
    name: Arc<str>,
    /// The node's last complaint, which a dial that gives up waiting reports: a refused auth key
    /// comes only as one.
    complaint: Mutex<Option<String>>,
}

impl Bridge {
    fn new(start: Start, tasks: &Tasks) -> (Arc<Bridge>, watch::Receiver<Phase>) {
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
            name: start.name,
            complaint: Mutex::new(None),
        };
        (Arc::new(bridge), watching)
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

/// A running node and the userspace stack that is its TUN device.
pub(super) struct Tunnel {
    pub(super) stack: Arc<Stack>,
    node: Mutex<Option<Node>>,
    bridge: Arc<Bridge>,
    addrs: Vec<IpAddr>,
    next_query: AtomicU64,
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

/// A node starting in the background. It outlives the dial that started it, as mihomo's
/// `startOnce` does: a dial gives up after its own deadline (5 s for TCP), while a login that
/// takes longer, or a login URL the user has yet to visit, keeps the same node going.
pub(super) struct Launch {
    phase: watch::Receiver<Phase>,
    ready: watch::Receiver<Option<Arc<Tunnel>>>,
    stop: CancellationToken,
    bridge: Arc<Bridge>,
}

impl Launch {
    pub(super) fn spawn(
        mut start: Start,
        lib: &'static Library,
        tasks: &Tasks,
    ) -> io::Result<Arc<Launch>> {
        let config = std::mem::take(&mut start.config);
        let (bridge, watching) = Bridge::new(start, tasks);
        let node = Node::start(lib, &config, bridge.clone())
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        let (ready_tx, ready) = watch::channel(None);
        let stop = tasks.child_token();
        let launch = Arc::new(Launch {
            phase: watching.clone(),
            ready,
            stop: stop.clone(),
            bridge: bridge.clone(),
        });
        let owner = tasks.clone();
        tasks.spawn(async move {
            let guard = StopOnDrop(Some(node));
            let mut watching = watching;
            let addrs = tokio::select! {
                () = stop.cancelled() => return,
                addrs = running(&mut watching) => addrs,
            };
            if let Some(addrs) = addrs {
                let tunnel = Tunnel::wire(bridge, guard.take(), addrs, &owner, &stop);
                ready_tx.send_replace(Some(tunnel.clone()));
                if stop.is_cancelled() {
                    tunnel.close();
                }
            }
        });
        Ok(launch)
    }

    pub(super) fn alive(&self) -> bool {
        !self.stop.is_cancelled()
            && !matches!(*self.phase.borrow(), Phase::Failed(_))
            && self
                .ready
                .borrow()
                .as_ref()
                .is_none_or(|tunnel| tunnel.usable() && tunnel.serves(&self.phase.borrow()))
    }

    pub(super) fn link_changed(&self) {
        if let Some(tunnel) = self.ready.borrow().as_ref() {
            tunnel.link_changed();
        }
    }

    /// Why the node will not come up, once the task that waited for it is gone.
    fn ended(&self) -> io::Error {
        match &*self.phase.borrow() {
            Phase::Failed(why) => io::Error::other(why.clone()),
            _ => io::Error::from(io::ErrorKind::BrokenPipe),
        }
    }

    pub(super) fn close(&self) {
        self.stop.cancel();
        if let Some(tunnel) = self.ready.borrow().as_ref() {
            tunnel.close();
        }
    }

    /// The running tunnel, waiting at most `wait` for the node to come up.
    pub(super) async fn tunnel(&self, wait: Duration) -> io::Result<Arc<Tunnel>> {
        let mut ready = self.ready.clone();
        let mut phase = self.phase.clone();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(tunnel) = ready.borrow_and_update().clone() {
                return Ok(tunnel);
            }
            match phase.borrow_and_update().clone() {
                Phase::NeedsLogin(url) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("tailscale node needs login: visit {url}"),
                    ));
                }
                Phase::Failed(why) => return Err(io::Error::other(why)),
                Phase::Starting | Phase::Running(_) => {}
            }
            tokio::select! {
                changed = ready.changed() => {
                    if changed.is_err() && ready.borrow().is_none() {
                        return Err(self.ended());
                    }
                }
                changed = phase.changed() => {
                    if changed.is_err() {
                        return Err(self.ended());
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    let why = match lock(&self.bridge.complaint).as_deref() {
                        Some(complaint) => format!("tailscale node is not running yet: {complaint}"),
                        None => "tailscale node is not running yet".to_string(),
                    };
                    return Err(io::Error::new(io::ErrorKind::TimedOut, why));
                }
            }
        }
    }
}

#[cfg(test)]
impl Launch {
    /// A launch whose node is still starting, without the library, and what makes its tunnel
    /// ready.
    pub(super) fn waiting(tasks: &Tasks) -> (Arc<Launch>, watch::Sender<Option<Arc<Tunnel>>>) {
        let start = Start {
            name: "ts".into(),
            config: String::new(),
            env: crate::testing::test_env(),
            opts: SockOpts::default(),
            version: IpVersion::default(),
            via: None,
        };
        let (bridge, phase) = Bridge::new(start, tasks);
        let (ready_tx, ready) = watch::channel(None);
        let launch = Arc::new(Launch {
            phase,
            ready,
            stop: tasks.child_token(),
            bridge,
        });
        (launch, ready_tx)
    }

    pub(super) fn closed(&self) -> bool {
        self.stop.is_cancelled()
    }
}

impl Drop for Launch {
    fn drop(&mut self) {
        self.close();
    }
}

async fn running(phase: &mut watch::Receiver<Phase>) -> Option<Vec<IpAddr>> {
    loop {
        match phase.borrow_and_update().clone() {
            Phase::Running(addrs) => return Some(addrs),
            Phase::Failed(_) => return None,
            Phase::Starting | Phase::NeedsLogin(_) => {}
        }
        phase.changed().await.ok()?;
    }
}

impl Tunnel {
    /// `launch` is the stop of the launch that waited for the node, which stops this too.
    fn wire(
        bridge: Arc<Bridge>,
        node: Option<Node>,
        addrs: Vec<IpAddr>,
        tasks: &Tasks,
        launch: &CancellationToken,
    ) -> Arc<Tunnel> {
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
            node: Mutex::new(node),
            bridge,
            addrs,
            next_query: AtomicU64::new(1),
            stop: launch.child_token(),
            driver: wired.driver,
        });
        tunnel.spawn(tasks, "send", send(wired.recv, tunnel.clone()));
        tunnel.spawn(tasks, "receive", receive(tunnel.bridge.clone(), wired.send));
        tunnel
    }

    fn spawn(
        &self,
        tasks: &Tasks,
        role: &'static str,
        work: impl Future<Output = io::Result<()>> + Send + 'static,
    ) {
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
        });
    }

    pub(super) fn usable(&self) -> bool {
        !self.stop.is_cancelled() && !self.driver.is_finished()
    }

    /// Whether the stack still has the node's addresses: one that came back from a new login
    /// with others is replaced by a new node, as mihomo reads them for every dial.
    fn serves(&self, phase: &Phase) -> bool {
        match phase {
            Phase::Running(addrs) => *addrs == self.addrs,
            _ => true,
        }
    }

    fn link_changed(&self) {
        let _ = self.with_node(Node::link_changed);
    }

    /// Stops the stack and the node; the node's Go side is stopped off the runtime, on a thread
    /// of its own as this may run outside it.
    pub(super) fn close(&self) {
        self.stop.cancel();
        self.driver.stop();
        self.bridge.inbox.close();
        if let Some(node) = lock(&self.node).take() {
            std::thread::spawn(move || drop(node));
        }
    }

    fn with_node<R>(&self, f: impl FnOnce(&Node) -> R) -> io::Result<R> {
        lock(&self.node)
            .as_ref()
            .map(f)
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    pub(super) async fn exchange(&self, query: &[u8]) -> io::Result<Vec<u8>> {
        let id = self.next_query.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        lock(&self.bridge.answers).insert(id, tx);
        if !self
            .with_node(|node| node.query_dns(id, query))
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

impl Drop for Tunnel {
    fn drop(&mut self) {
        if let Some(node) = lock(&self.node).take() {
            std::thread::spawn(move || drop(node));
        }
    }
}

struct StopOnDrop(Option<Node>);

impl StopOnDrop {
    fn take(mut self) -> Option<Node> {
        self.0.take()
    }
}

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        if let Some(node) = self.0.take() {
            std::thread::spawn(move || drop(node));
        }
    }
}

async fn send(mut outgoing: StackRecv, tunnel: Arc<Tunnel>) -> io::Result<()> {
    let mut packets: Vec<Packet> = Vec::with_capacity(BATCH);
    loop {
        packets.clear();
        outgoing.recv_many(&mut packets, BATCH).await?;
        let mut done = 0;
        while done < packets.len() {
            let rest = packets.get(done..).unwrap_or_default();
            let notified = tunnel.bridge.writable.notified();
            done += tunnel.with_node(|node| node.send(rest.iter().map(AsRef::as_ref)))?;
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

    const WAIT: Duration = Duration::from_millis(20);

    fn failed(tunnel: io::Result<Arc<Tunnel>>) -> io::Error {
        match tunnel {
            Ok(_) => panic!("the node came up"),
            Err(err) => err,
        }
    }

    #[tokio::test]
    async fn a_dial_that_gives_up_reports_the_nodes_last_complaint_until_it_runs() {
        let tracked = crate::testing::Tracked::new();
        let (launch, _ready) = Launch::waiting(&tracked.tasks);
        launch.bridge.event(Event::Error("invalid key"));
        let err = failed(launch.tunnel(WAIT).await);
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            err.to_string(),
            "tailscale node is not running yet: invalid key"
        );
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let err = failed(launch.tunnel(WAIT).await);
        assert_eq!(err.to_string(), "tailscale node is not running yet");
    }

    #[tokio::test]
    async fn a_dial_reports_why_the_node_failed() {
        let tracked = crate::testing::Tracked::new();
        let (launch, ready) = Launch::waiting(&tracked.tasks);
        drop(ready);
        let err = failed(launch.tunnel(WAIT).await);
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        launch.bridge.event(Event::Failed("state dir is a file"));
        assert_eq!(launch.ended().to_string(), "state dir is a file");
        let err = failed(launch.tunnel(WAIT).await);
        assert_eq!(err.to_string(), "state dir is a file");
        assert!(!launch.alive());
    }

    #[tokio::test]
    async fn a_node_back_with_other_addresses_is_no_longer_alive() {
        let tracked = crate::testing::Tracked::new();
        let (launch, ready) = Launch::waiting(&tracked.tasks);
        assert!(launch.alive());
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let addrs = vec![IpAddr::from([100, 64, 0, 2])];
        let tunnel = Tunnel::wire(
            launch.bridge.clone(),
            None,
            addrs,
            &tracked.tasks,
            &launch.stop,
        );
        ready.send_replace(Some(tunnel.clone()));
        assert!(Arc::ptr_eq(&launch.tunnel(WAIT).await.unwrap(), &tunnel));
        assert!(launch.alive());
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.3"}"#));
        assert!(!launch.alive());
        tunnel.close();
    }
}
