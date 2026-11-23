mod driver;
mod own_wake;
mod pool;
mod queues;
mod replies;
mod reply_packet;
mod stats;
mod udp;

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use concord_common::{
    Address, BoxStream, FlowHandler, FlowKey, FlowMeta, IcmpAnswer, InboundInfo, InboundKind,
    Network, Tasks, UdpFlow, UdpPayload, UdpReply,
};
use tokio_util::sync::CancellationToken;

use crate::device::Device;
use crate::dns::{DnsHijack, DnsMatcher};

pub use concord_netstack::Congestion;
pub use stats::{StackStats, StatsSnapshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Reject,
    Drop,
}

pub trait FlowSink: Send + Sync + 'static {
    fn judge(&self, _flow: &FlowKey, _first: &[u8]) -> Verdict {
        Verdict::Accept
    }

    fn tcp(&self, flow: FlowKey, stream: BoxStream);

    /// Called only inside [`udp_round`](Self::udp_round).
    fn udp(&self, flow: FlowKey, payload: &[u8], reply: &Arc<dyn UdpReply>);

    /// An echo request, not called when ICMP forwarding is disabled. `true` means the sink
    /// calls `answer` once the destination has replied; otherwise the stack replies as if
    /// the destination had.
    fn icmp(&self, _dst: IpAddr, _message: &[u8], _answer: IcmpAnswer) -> bool {
        false
    }

    /// One receive round, so the sink can send that round's datagrams together; see
    /// [`FlowHandler::udp_round`].
    fn udp_round(&self, round: &mut dyn FnMut()) {
        round();
    }
}

pub struct HandlerSink {
    handler: Arc<dyn FlowHandler>,
    inbound: InboundInfo,
    tasks: Tasks,
}

impl HandlerSink {
    /// The handler runs in the runtime of `tasks`, whichever thread the stack calls from.
    pub fn new(handler: Arc<dyn FlowHandler>, inbound_name: &str, tasks: Tasks) -> Self {
        let mut inbound = InboundInfo::new(InboundKind::Tun);
        inbound.name = Arc::from(inbound_name);
        HandlerSink {
            handler,
            inbound,
            tasks,
        }
    }

    fn meta(&self, flow: &FlowKey) -> FlowMeta {
        let mut inbound = self.inbound.clone();
        if flow.network == Network::Tcp {
            inbound.addr = Some(flow.dst);
        }
        FlowMeta {
            dscp: 0,
            network: flow.network,
            inbound,
            src: flow.src,
            dst: Address::Socket(flow.dst),
        }
    }
}

impl FlowSink for HandlerSink {
    fn tcp(&self, flow: FlowKey, stream: BoxStream) {
        let _owner = self.tasks.enter();
        self.handler.handle_tcp(self.meta(&flow), stream);
    }

    fn udp(&self, flow: FlowKey, payload: &[u8], reply: &Arc<dyn UdpReply>) {
        let flow = UdpFlow {
            inbound: &self.inbound,
            src: flow.src,
            dst: Address::Socket(flow.dst),
            dscp: 0,
        };
        self.handler
            .handle_udp(flow, UdpPayload::Borrowed(payload), reply);
    }

    fn icmp(&self, dst: IpAddr, message: &[u8], answer: IcmpAnswer) -> bool {
        let _owner = self.tasks.enter();
        self.handler.handle_icmp(dst, message, answer)
    }

    fn udp_round(&self, round: &mut dyn FnMut()) {
        let _owner = self.tasks.enter();
        self.handler.udp_round(round);
    }
}

pub struct DnsConfig {
    pub matcher: DnsMatcher,
    pub handler: Arc<dyn DnsHijack>,
}

#[derive(Clone)]
pub struct StackOptions {
    pub mtu: usize,
    pub max_tcp_flows: usize,
    pub max_half_open_tcp: usize,
    pub broadcast: Option<IpAddr>,
    pub udp_timeout: Duration,
    pub disable_icmp_forwarding: bool,
    pub congestion: Congestion,
    pub dns: Option<Arc<DnsConfig>>,
    pub stats: Arc<StackStats>,
    /// Where the stack and the DNS answers it starts run.
    pub tasks: Tasks,
}

impl Default for StackOptions {
    fn default() -> Self {
        let stack = concord_netstack::StackConfig::default();
        StackOptions {
            mtu: 1500,
            max_tcp_flows: stack.max_connections,
            max_half_open_tcp: stack.max_half_open,
            broadcast: None,
            udp_timeout: crate::options::UDP_TIMEOUT,
            disable_icmp_forwarding: false,
            congestion: Congestion::Cubic,
            dns: None,
            stats: Arc::default(),
            tasks: Tasks::default(),
        }
    }
}

pub trait IpStack: Send + 'static {
    fn run<D: Device>(
        self,
        dev: D,
        sink: Arc<dyn FlowSink>,
        stop: CancellationToken,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

pub struct NetStack {
    options: StackOptions,
}

impl NetStack {
    pub fn new(options: StackOptions) -> Self {
        NetStack { options }
    }

    pub(crate) fn prepare<D: Device>(
        self,
        dev: D,
        sink: Arc<dyn FlowSink>,
        stop: CancellationToken,
    ) -> io::Result<(
        impl Future<Output = io::Result<()>> + Send,
        impl Future<Output = io::Result<()>> + Send,
    )> {
        let mut queues = driver::prepare(dev)?;
        let ready: Vec<_> = queues.iter_mut().map(driver::Prepared::ready).collect();
        Ok((
            driver::run_prepared(self.options, queues, sink, stop),
            async move {
                for queue in ready {
                    queue.await.map_err(io::Error::other)?;
                }
                Ok(())
            },
        ))
    }
}

impl IpStack for NetStack {
    fn run<D: Device>(
        self,
        dev: D,
        sink: Arc<dyn FlowSink>,
        stop: CancellationToken,
    ) -> impl Future<Output = io::Result<()>> + Send {
        driver::run(self.options, dev, sink, stop)
    }
}

pub(crate) fn flow_key(
    network: Network,
    src: std::net::SocketAddr,
    dst: std::net::SocketAddr,
) -> FlowKey {
    FlowKey { network, src, dst }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test setup and assertions")]
mod tests {
    use super::*;

    struct Idle;

    impl FlowHandler for Idle {
        fn handle_tcp(&self, _meta: FlowMeta, _stream: BoxStream) {}

        fn handle_udp(
            &self,
            _flow: UdpFlow<'_>,
            _payload: UdpPayload<'_>,
            _reply: &Arc<dyn UdpReply>,
        ) {
        }
    }

    fn key(network: Network) -> FlowKey {
        FlowKey {
            network,
            src: "10.0.0.2:5000".parse().unwrap(),
            dst: "1.1.1.1:443".parse().unwrap(),
        }
    }

    #[test]
    fn tcp_reports_the_destination_as_the_inbound_address_and_udp_none() {
        let sink = HandlerSink::new(Arc::new(Idle), "tun", Tasks::default());
        let tcp = sink.meta(&key(Network::Tcp));
        assert_eq!(tcp.inbound.addr, Some("1.1.1.1:443".parse().unwrap()));
        assert_eq!(sink.meta(&key(Network::Udp)).inbound.addr, None);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handler_dispatch_retains_the_callers_runtime() {
        struct Probe(
            std::sync::Mutex<Option<tokio::sync::oneshot::Sender<tokio::runtime::RuntimeFlavor>>>,
        );
        impl FlowHandler for Probe {
            fn handle_tcp(&self, _meta: FlowMeta, _stream: BoxStream) {
                let sent = concord_common::sync::lock(&self.0).take().unwrap();
                tokio::spawn(async move {
                    let _ = sent.send(tokio::runtime::Handle::current().runtime_flavor());
                });
            }
            fn handle_udp(
                &self,
                _flow: UdpFlow<'_>,
                _payload: UdpPayload<'_>,
                _reply: &Arc<dyn UdpReply>,
            ) {
            }
        }
        let (sent, received) = tokio::sync::oneshot::channel();
        let tasks = Tasks::current(Default::default(), Default::default());
        let sink = HandlerSink::new(
            Arc::new(Probe(std::sync::Mutex::new(Some(sent)))),
            "tun",
            tasks,
        );
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    assert_eq!(
                        tokio::runtime::Handle::current().runtime_flavor(),
                        tokio::runtime::RuntimeFlavor::CurrentThread
                    );
                    let (stream, _peer) = tokio::io::duplex(16);
                    sink.tcp(key(Network::Tcp), Box::new(stream));
                });
        })
        .join()
        .unwrap();
        assert_eq!(
            received.await.unwrap(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
    }
}
