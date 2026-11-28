use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::Tasks;
use concord_common::sync::lock;
#[cfg(test)]
use concord_common::{IpVersion, SockOpts};
use concord_tsnet::{Library, Node};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::tunnel::{Bridge, Phase, Start, Tunnel};

const SWAP_GRACE: Duration = Duration::from_secs(5);

pub(super) trait NodeOps: Send + 'static {
    fn send<'p>(&self, packets: impl IntoIterator<Item = &'p [u8]>) -> usize;
    fn query_dns(&self, id: u64, query: &[u8]) -> bool;
    fn link_changed(&self);
}

impl NodeOps for Node {
    fn send<'p>(&self, packets: impl IntoIterator<Item = &'p [u8]>) -> usize {
        Node::send(self, packets)
    }

    fn query_dns(&self, id: u64, query: &[u8]) -> bool {
        Node::query_dns(self, id, query)
    }

    fn link_changed(&self) {
        Node::link_changed(self);
    }
}

pub(super) struct NodeSlot<N: NodeOps> {
    inner: Mutex<Option<N>>,
}

impl<N: NodeOps> NodeSlot<N> {
    fn new(node: N) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Some(node)),
        })
    }

    #[cfg(test)]
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(None),
        })
    }

    pub(super) fn with<R>(&self, f: impl FnOnce(&N) -> R) -> io::Result<R> {
        lock(&self.inner)
            .as_ref()
            .map(f)
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    /// Stops the node on a thread of its own: `cts_stop` blocks on Go goroutines that may call
    /// back into the tokio runtime through `wait_on`, and `Drop` may run outside it.
    fn close(&self) {
        if let Some(node) = lock(&self.inner).take() {
            std::thread::spawn(move || drop(node));
        }
    }
}

impl<N: NodeOps> Drop for NodeSlot<N> {
    fn drop(&mut self) {
        self.close();
    }
}

/// A node starting in the background. It outlives the dial that started it, as mihomo's
/// `startOnce` does: a dial gives up after its own deadline (5 s for TCP), while a login that
/// takes longer, or a login URL the user has yet to visit, keeps the same node going.
pub(super) struct Launch<N: NodeOps = Node> {
    phase: watch::Receiver<Phase>,
    ready: watch::Receiver<Option<Arc<Tunnel<N>>>>,
    stop: CancellationToken,
    bridge: Arc<Bridge>,
    node: Arc<NodeSlot<N>>,
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
        Ok(Launch::with_node(bridge, watching, node, tasks))
    }
}

impl<N: NodeOps> Launch<N> {
    fn with_node(
        bridge: Arc<Bridge>,
        watching: watch::Receiver<Phase>,
        node: N,
        tasks: &Tasks,
    ) -> Arc<Self> {
        let node = NodeSlot::new(node);
        let (ready_tx, ready) = watch::channel(None);
        let stop = tasks.child_token();
        let launch = Arc::new(Launch {
            phase: watching.clone(),
            ready,
            stop: stop.clone(),
            bridge: bridge.clone(),
            node: node.clone(),
        });
        let owner = tasks.clone();
        tasks.spawn(supervise(bridge, node, watching, ready_tx, owner, stop));
        launch
    }

    pub(super) fn alive(&self) -> bool {
        !self.stop.is_cancelled()
            && !matches!(*self.phase.borrow(), Phase::Failed(_))
            && self
                .ready
                .borrow()
                .as_ref()
                .is_none_or(|tunnel| tunnel.usable())
    }

    pub(super) fn link_changed(&self) {
        let _ = self.node.with(NodeOps::link_changed);
    }

    /// Why the node will not come up, once the task that waited for it is gone.
    fn ended(&self) -> io::Error {
        match &*self.phase.borrow() {
            Phase::Failed(why) => io::Error::other(why.clone()),
            _ => io::Error::from(io::ErrorKind::BrokenPipe),
        }
    }

    /// Synchronous teardown for `Drop` and immediate cancellation; `supervise` awaits its tasks
    /// separately.
    pub(super) fn close(&self) {
        self.stop.cancel();
        if let Some(tunnel) = self.ready.borrow().as_ref() {
            tunnel.stop_stack();
        }
        self.bridge.close_inbox();
        self.node.close();
    }

    /// The running tunnel, waiting at most `wait` for the node to come up.
    pub(super) async fn tunnel(&self, wait: Duration) -> io::Result<Arc<Tunnel<N>>> {
        let mut ready = self.ready.clone();
        let mut phase = self.phase.clone();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let current_phase = phase.borrow_and_update().clone();
            let current_ready = ready.borrow_and_update().clone();
            match current_phase {
                Phase::NeedsLogin(url) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("tailscale node needs login: visit {url}"),
                    ));
                }
                Phase::Failed(why) => return Err(io::Error::other(why)),
                Phase::Starting => {}
                Phase::Running(ref addrs) => {
                    if let Some(tunnel) = current_ready
                        && tunnel.usable()
                        && tunnel.addrs() == addrs.as_slice()
                    {
                        return Ok(tunnel);
                    }
                }
            }
            tokio::select! {
                changed = ready.changed() => {
                    if changed.is_err() {
                        return Err(self.ended());
                    }
                }
                changed = phase.changed() => {
                    if changed.is_err() {
                        return Err(self.ended());
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    let why = match self.bridge.last_complaint() {
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
            node: NodeSlot::empty(),
        });
        (launch, ready_tx)
    }

    pub(super) fn closed(&self) -> bool {
        self.stop.is_cancelled()
    }
}

impl<N: NodeOps> Drop for Launch<N> {
    fn drop(&mut self) {
        self.close();
    }
}

struct ActiveStack<N: NodeOps> {
    tunnel: Arc<Tunnel<N>>,
    tasks: [tokio::task::JoinHandle<()>; 2],
}

impl<N: NodeOps> ActiveStack<N> {
    fn wire(
        bridge: Arc<Bridge>,
        node: Arc<NodeSlot<N>>,
        addrs: Vec<IpAddr>,
        tasks: &Tasks,
        launch: &CancellationToken,
    ) -> Self {
        let (tunnel, handles) = Tunnel::wire(bridge, node, addrs, tasks, launch);
        ActiveStack {
            tunnel,
            tasks: handles,
        }
    }

    async fn teardown(self) {
        self.tunnel.stop_stack();
        self.tunnel.bridge().close_inbox();
        await_teardown(self.tunnel.bridge().name(), self.tasks).await;
    }
}

async fn await_teardown(name: &str, handles: [tokio::task::JoinHandle<()>; 2]) {
    let [mut first, mut second] = handles;
    let finished = tokio::time::timeout(SWAP_GRACE, async {
        let _ = tokio::join!(&mut first, &mut second);
    })
    .await;
    if finished.is_err() {
        tracing::warn!(
            "[Tailscale]({name}) stack tasks did not stop within {}s; aborting",
            SWAP_GRACE.as_secs()
        );
        first.abort();
        second.abort();
    }
}

async fn drop_active<N: NodeOps>(
    active: &mut Option<ActiveStack<N>>,
    ready_tx: &watch::Sender<Option<Arc<Tunnel<N>>>>,
) -> bool {
    let Some(old) = active.take() else {
        return false;
    };
    ready_tx.send_replace(None);
    old.teardown().await;
    true
}

async fn supervise<N: NodeOps>(
    bridge: Arc<Bridge>,
    node: Arc<NodeSlot<N>>,
    mut watching: watch::Receiver<Phase>,
    ready_tx: watch::Sender<Option<Arc<Tunnel<N>>>>,
    tasks: Tasks,
    stop: CancellationToken,
) {
    let mut active: Option<ActiveStack<N>> = None;
    loop {
        let phase = watching.borrow_and_update().clone();
        match phase {
            Phase::Starting => {}
            Phase::NeedsLogin(_) => {
                if drop_active(&mut active, &ready_tx).await {
                    if stop.is_cancelled() {
                        break;
                    }
                    continue;
                }
            }
            Phase::Failed(_) => break,
            Phase::Running(addrs) => {
                let matches = active.as_ref().is_some_and(|current| {
                    current.tunnel.addrs() == addrs.as_slice() && current.tunnel.usable()
                });
                if !matches {
                    if drop_active(&mut active, &ready_tx).await {
                        if stop.is_cancelled() {
                            break;
                        }
                        continue;
                    }
                    if stop.is_cancelled() {
                        break;
                    }
                    let next =
                        ActiveStack::wire(bridge.clone(), node.clone(), addrs, &tasks, &stop);
                    ready_tx.send_replace(Some(next.tunnel.clone()));
                    active = Some(next);
                }
            }
        }
        let changed = tokio::select! {
            () = stop.cancelled() => break,
            changed = watching.changed() => changed,
        };
        if changed.is_err() {
            break;
        }
    }
    ready_tx.send_replace(None);
    if let Some(old) = active.take() {
        old.teardown().await;
    } else {
        bridge.close_inbox();
    }
    node.close();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use concord_tsnet::{Event, Host};
    use tokio::sync::oneshot;

    use super::*;
    use crate::testing::test_env;

    #[derive(Default)]
    struct MockState {
        link_changes: AtomicUsize,
        dropped: AtomicBool,
    }

    struct MockNode {
        state: Arc<MockState>,
    }

    impl NodeOps for MockNode {
        fn send<'p>(&self, packets: impl IntoIterator<Item = &'p [u8]>) -> usize {
            packets.into_iter().count()
        }

        fn query_dns(&self, _id: u64, _query: &[u8]) -> bool {
            false
        }

        fn link_changed(&self) {
            self.state.link_changes.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for MockNode {
        fn drop(&mut self) {
            self.state.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn mock_launch(tasks: &Tasks) -> (Arc<Launch<MockNode>>, Arc<MockState>) {
        let start = Start {
            name: "ts".into(),
            config: String::new(),
            env: test_env(),
            opts: SockOpts::default(),
            version: IpVersion::default(),
            via: None,
        };
        let (bridge, watching) = Bridge::new(start, tasks);
        let state = Arc::new(MockState::default());
        let launch = Launch::with_node(
            bridge,
            watching,
            MockNode {
                state: state.clone(),
            },
            tasks,
        );
        (launch, state)
    }

    async fn wait_until(mut check: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while !check() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "condition did not become true"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    const WAIT: Duration = Duration::from_millis(20);
    const SWAP_WAIT: Duration = Duration::from_secs(2);

    fn failed<N: NodeOps>(tunnel: io::Result<Arc<Tunnel<N>>>) -> io::Error {
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
    async fn a_link_change_before_running_reaches_the_node() {
        let tracked = crate::testing::Tracked::new();
        let (launch, state) = mock_launch(&tracked.tasks);
        launch.link_changed();
        assert_eq!(state.link_changes.load(Ordering::SeqCst), 1);

        launch.bridge.event(Event::LoginUrl("https://login.test/a"));
        launch.link_changed();
        assert_eq!(state.link_changes.load(Ordering::SeqCst), 2);

        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let _tunnel = launch.tunnel(SWAP_WAIT).await.unwrap();
        launch.link_changed();
        assert_eq!(state.link_changes.load(Ordering::SeqCst), 3);

        launch.close();
        wait_until(|| state.dropped.load(Ordering::SeqCst)).await;
    }

    #[tokio::test]
    async fn other_addresses_replace_the_stack_and_keep_the_node() {
        let tracked = crate::testing::Tracked::new();
        let (launch, state) = mock_launch(&tracked.tasks);
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let first = launch.tunnel(SWAP_WAIT).await.unwrap();
        assert_eq!(first.addrs(), &[IpAddr::from([100, 64, 0, 2])]);
        assert!(launch.alive());
        assert!(!state.dropped.load(Ordering::SeqCst));

        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.3"}"#));
        let second = launch.tunnel(SWAP_WAIT).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(!first.usable());
        assert!(second.usable());
        assert_eq!(second.addrs(), &[IpAddr::from([100, 64, 0, 3])]);
        assert!(launch.alive());
        assert!(!state.dropped.load(Ordering::SeqCst));

        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.3"}"#));
        let same = launch.tunnel(SWAP_WAIT).await.unwrap();
        assert!(Arc::ptr_eq(&second, &same));

        launch.link_changed();
        assert_eq!(state.link_changes.load(Ordering::SeqCst), 1);
        launch.close();
        wait_until(|| state.dropped.load(Ordering::SeqCst)).await;
    }

    #[tokio::test]
    async fn needs_login_tears_down_the_stack_keeps_the_node_and_recovers() {
        let tracked = crate::testing::Tracked::new();
        let (launch, state) = mock_launch(&tracked.tasks);
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let first = launch.tunnel(SWAP_WAIT).await.unwrap();

        launch
            .bridge
            .event(Event::LoginUrl("https://login.test/reauth"));
        assert!(launch.alive());
        let err = failed(launch.tunnel(WAIT).await);
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("https://login.test/reauth"));
        wait_until(|| !first.usable()).await;
        assert!(!state.dropped.load(Ordering::SeqCst));
        launch.link_changed();
        assert_eq!(state.link_changes.load(Ordering::SeqCst), 1);

        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let same_ip = launch.tunnel(SWAP_WAIT).await.unwrap();
        assert!(!Arc::ptr_eq(&first, &same_ip));
        assert!(same_ip.usable());
        assert_eq!(same_ip.addrs(), &[IpAddr::from([100, 64, 0, 2])]);
        assert!(!state.dropped.load(Ordering::SeqCst));

        launch
            .bridge
            .event(Event::LoginUrl("https://login.test/reauth2"));
        wait_until(|| !same_ip.usable()).await;
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.4"}"#));
        let recovered = launch.tunnel(SWAP_WAIT).await.unwrap();
        assert!(!Arc::ptr_eq(&same_ip, &recovered));
        assert!(recovered.usable());
        assert_eq!(recovered.addrs(), &[IpAddr::from([100, 64, 0, 4])]);
        assert!(!state.dropped.load(Ordering::SeqCst));

        launch.close();
        wait_until(|| state.dropped.load(Ordering::SeqCst)).await;
    }

    #[tokio::test]
    async fn a_dropped_supervisor_with_a_stale_tunnel_ends_without_spinning() {
        let tracked = crate::testing::Tracked::new();
        let (launch, ready) = Launch::waiting(&tracked.tasks);
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let active = ActiveStack::wire(
            launch.bridge.clone(),
            launch.node.clone(),
            vec![IpAddr::from([100, 64, 0, 2])],
            &tracked.tasks,
            &launch.stop,
        );
        ready.send_replace(Some(active.tunnel.clone()));
        active.teardown().await;
        drop(ready);

        let err = failed(launch.tunnel(Duration::from_secs(30)).await);
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn failed_phase_tears_down_the_stack_and_closes_the_node() {
        let tracked = crate::testing::Tracked::new();
        let (launch, state) = mock_launch(&tracked.tasks);
        launch
            .bridge
            .event(Event::Addrs(r#"{"ipv4":"100.64.0.2"}"#));
        let first = launch.tunnel(SWAP_WAIT).await.unwrap();

        launch.bridge.event(Event::Failed("control rejected node"));
        assert!(!launch.alive());
        let err = failed(launch.tunnel(WAIT).await);
        assert_eq!(err.to_string(), "control rejected node");
        wait_until(|| !first.usable()).await;
        wait_until(|| state.dropped.load(Ordering::SeqCst)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stack_teardown_aborts_stuck_tasks_after_swap_grace() {
        struct DropSignal(Option<oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }

        let (aborted_tx, aborted_rx) = oneshot::channel();
        let guard = DropSignal(Some(aborted_tx));
        let fast = tokio::spawn(async {});
        let stuck = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });

        let started = tokio::time::Instant::now();
        await_teardown("ts", [fast, stuck]).await;
        assert!(started.elapsed() >= SWAP_GRACE);
        assert!(
            aborted_rx.await.is_ok(),
            "stuck task was aborted and dropped"
        );
    }
}
