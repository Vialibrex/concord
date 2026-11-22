mod support;

use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{Address, Network};
use concord_tun::testing::{FakeNet, fake_device, fake_queues};
use concord_tun::{
    Device, DnsConfig, DnsHijack, DnsMatcher, IpStack, NetStack, StackOptions, StackStats,
};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpProtocol};
use support::{Seg, TcpPeer, TcpRx, UdpRx, channel_sink, parse_udp, split_ip, udp_packet, wrap_ip};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

struct Reverse;

#[async_trait]
impl DnsHijack for Reverse {
    async fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        Some(query.iter().rev().copied().collect())
    }
}

struct Harness {
    net: FakeNet,
    tcp: TcpRx,
    udp: UdpRx,
    stats: Arc<StackStats>,
    stop: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}

fn start(options: StackOptions) -> Harness {
    start_on(options, false)
}

fn start_on(options: StackOptions, batched: bool) -> Harness {
    let (device, net) = fake_device(256, 2048);
    if batched {
        start_with(options, device.batched(), net)
    } else {
        start_with(options, device, net)
    }
}

fn start_with(mut options: StackOptions, device: impl Device, net: FakeNet) -> Harness {
    let (sink, tcp, udp) = channel_sink();
    let stop = CancellationToken::new();
    options.mtu = 1500;
    let stats = Arc::clone(&options.stats);
    let stack = NetStack::new(options);
    let task = tokio::spawn(stack.run(device, sink, stop.clone()));
    Harness {
        net,
        tcp,
        udp,
        stats,
        stop,
        task,
    }
}

fn with_dns() -> StackOptions {
    StackOptions {
        dns: Some(Arc::new(DnsConfig {
            matcher: DnsMatcher::parse(["any:53"]).unwrap(),
            handler: Arc::new(Reverse),
        })),
        ..StackOptions::default()
    }
}

impl Harness {
    async fn shutdown(self) {
        self.stop.cancel();
        timeout(Duration::from_secs(2), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

async fn next_seg(net: &FakeNet, peer: &TcpPeer) -> Seg {
    timeout(Duration::from_secs(2), async {
        loop {
            let raw = net.take_vec().await;
            if let Some(seg) = peer.parse(&raw) {
                return seg;
            }
        }
    })
    .await
    .expect("no segment from the stack")
}

async fn handshake(net: &FakeNet, peer: &mut TcpPeer) {
    net.inject(&peer.syn());
    let synack = next_seg(net, peer).await;
    assert!(synack.syn && synack.ack == Some(peer.seq));
    peer.absorb(&synack);
    net.inject(&peer.ack());
}

async fn read_payload(net: &FakeNet, peer: &mut TcpPeer, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    while got.len() < want {
        let seg = next_seg(net, peer).await;
        if !seg.payload.is_empty() {
            peer.absorb(&seg);
            got.extend_from_slice(&seg.payload);
            net.inject(&peer.ack());
        }
    }
    got
}

async fn tcp_round_trip(client: &str, server: &str, batched: bool) {
    let mut h = start_on(StackOptions::default(), batched);
    let mut peer = TcpPeer::new(client, server);
    handshake(&h.net, &mut peer).await;
    net_data(&h.net, &mut peer, b"hello");
    let (flow, mut stream) = timeout(Duration::from_secs(2), h.tcp.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.network, Network::Tcp);
    assert_eq!(flow.src, peer.client);
    assert_eq!(flow.dst, peer.server);

    let mut buf = [0u8; 5];
    timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"hello");

    stream.write_all(b"world").await.unwrap();
    assert_eq!(read_payload(&h.net, &mut peer, 5).await, b"world");

    let big = vec![0x5au8; 20_000];
    let sender = tokio::spawn(async move {
        stream.write_all(&big).await.unwrap();
        stream
    });
    let echoed = read_payload(&h.net, &mut peer, 20_000).await;
    assert!(echoed.iter().all(|&byte| byte == 0x5a));
    let mut stream = sender.await.unwrap();

    h.net.inject(&peer.fin());
    let mut eof = [0u8; 1];
    let n = timeout(Duration::from_secs(2), stream.read(&mut eof))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(n, 0);

    stream.shutdown().await.unwrap();
    let fin = loop {
        let seg = next_seg(&h.net, &peer).await;
        if seg.fin {
            break seg;
        }
    };
    peer.absorb(&fin);
    h.net.inject(&peer.ack());
    drop(stream);
    assert_eq!(h.stats.snapshot().tcp_accepted, 1);
    h.shutdown().await;
}

#[tokio::test]
async fn a_device_with_checksum_offload_takes_payloads_in_place() {
    let (device, net) = fake_device(256, 2048);
    let (device, placed) = device.offloading();
    let mut h = start_with(StackOptions::default(), device, net);
    let mut peer = TcpPeer::new("10.0.0.2:40000", "93.184.216.34:443");
    handshake(&h.net, &mut peer).await;
    net_data(&h.net, &mut peer, b"hello");
    let (_, mut stream) = timeout(Duration::from_secs(2), h.tcp.recv())
        .await
        .unwrap()
        .unwrap();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let sender = {
        let big = big.clone();
        tokio::spawn(async move {
            stream.write_all(&big).await.unwrap();
            stream
        })
    };
    assert!(read_payload(&h.net, &mut peer, big.len()).await == big);
    assert!(placed.load(std::sync::atomic::Ordering::Relaxed) > 0);
    drop(sender.await.unwrap());
    h.shutdown().await;
}

fn net_data(net: &FakeNet, peer: &mut TcpPeer, payload: &[u8]) {
    assert!(net.inject(&peer.data(payload)));
}

/// Notes where in the receive buffer each read landed and how long its packet was.
struct Recording<D> {
    inner: D,
    reads: Arc<std::sync::Mutex<Vec<(usize, usize)>>>,
}

impl<D: Device> Device for Recording<D> {
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.inner.poll_recv(cx, buf)
    }

    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        packet: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.inner.poll_send(cx, packet)
    }

    fn poll_recv_batch(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
        stride: usize,
        lens: &mut [usize],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let at = buf.as_ptr() as usize;
        let result = self.inner.poll_recv_batch(cx, buf, stride, lens);
        if let std::task::Poll::Ready(Ok(1..)) = result {
            lock(&self.reads).push((at, lens[0]));
        }
        result
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reads_pack_while_a_socket_gathers_and_start_over_otherwise() {
    let (device, net) = fake_device(256, 2048);
    let reads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let device = Recording {
        inner: device,
        reads: Arc::clone(&reads),
    };
    let mut h = start_with(StackOptions::default(), device, net);
    let mut peer = TcpPeer::new("10.0.0.2:40000", "93.184.216.34:80");
    handshake(&h.net, &mut peer).await;
    net_data(&h.net, &mut peer, b"hello");
    let (_, mut stream) = timeout(Duration::from_secs(2), h.tcp.recv())
        .await
        .unwrap()
        .unwrap();
    let mut hello = [0u8; 5];
    stream.read_exact(&mut hello).await.unwrap();

    lock(&reads).clear();
    for byte in 0..8u8 {
        net_data(&h.net, &mut peer, &[byte; 1000]);
    }
    let mut queued = vec![0u8; 8000];
    timeout(Duration::from_secs(2), stream.read_exact(&mut queued))
        .await
        .unwrap()
        .unwrap();
    let held = std::mem::take(&mut *lock(&reads));
    assert!(held.len() >= 8);
    assert!(
        held.iter().all(|&(at, _)| at == held[0].0),
        "nothing gathered, so every read starts at the front: {held:?}"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    #[allow(clippy::disallowed_methods, reason = "a loopback test pair")]
    let connecting = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
    let (near, (mut far, _)) = tokio::try_join!(connecting, listener.accept()).unwrap();
    let _attached = stream
        .direct()
        .and_then(|direct| direct.attach_owned(&mut Some(near.into())))
        .expect("an idle connection takes a socket");
    tokio::time::sleep(Duration::from_millis(20)).await;
    for byte in 0..8u8 {
        net_data(&h.net, &mut peer, &[byte; 1000]);
    }
    let mut passed = vec![0u8; 8000];
    timeout(Duration::from_secs(2), far.read_exact(&mut passed))
        .await
        .unwrap()
        .unwrap();
    assert!(
        passed
            .chunks(1000)
            .enumerate()
            .all(|(i, chunk)| chunk.iter().all(|&b| b == i as u8))
    );
    let gathered = std::mem::take(&mut *lock(&reads));
    assert!(
        gathered
            .windows(2)
            .all(|pair| pair[1].0 == pair[0].0 + pair[0].1),
        "each read lands right after the packet before it: {gathered:?}"
    );
    assert!(gathered.len() >= 8);
    drop(stream);
    h.shutdown().await;
}

#[tokio::test]
async fn segments_on_a_queue_that_does_not_own_the_connection_reach_it() {
    let (device, nets) = fake_queues(2, 256, 2048);
    let (sink, mut tcp, _udp) = channel_sink();
    let stop = CancellationToken::new();
    let options = StackOptions {
        mtu: 1500,
        ..StackOptions::default()
    };
    let stats = Arc::clone(&options.stats);
    let task = tokio::spawn(NetStack::new(options).run(device, sink, stop.clone()));
    let (owner, other) = (&nets[0], &nets[1]);

    let mut peer = TcpPeer::new("10.0.0.2:40000", "93.184.216.34:80");
    handshake(owner, &mut peer).await;
    net_data(other, &mut peer, b"hello");
    let (_, mut stream) = timeout(Duration::from_secs(2), tcp.recv())
        .await
        .unwrap()
        .unwrap();
    let mut buf = [0u8; 5];
    timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"hello");
    stream.write_all(b"world").await.unwrap();
    assert_eq!(read_payload(owner, &mut peer, 5).await, b"world");

    let mut second = TcpPeer::new("10.0.0.2:40001", "93.184.216.34:80");
    handshake(other, &mut second).await;
    let (flow, _second_stream) = timeout(Duration::from_secs(2), tcp.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.src, second.client);
    let snapshot = stats.snapshot();
    assert_eq!((snapshot.tcp_accepted, snapshot.tcp_active), (2, 2));

    stop.cancel();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn tcp_handshake_echo_and_close_over_ipv4() {
    tcp_round_trip("10.0.0.2:40000", "93.184.216.34:80", false).await;
}

#[tokio::test]
async fn tcp_handshake_echo_and_close_over_ipv6() {
    tcp_round_trip("[fd00::2]:40000", "[2001:db8::1]:80", false).await;
}

#[tokio::test]
async fn a_client_reset_fails_the_stream_and_frees_the_flow() {
    let mut h = start(StackOptions::default());
    let mut peer = TcpPeer::new("10.0.0.2:40001", "1.1.1.1:443");
    handshake(&h.net, &mut peer).await;
    let (_, mut stream) = timeout(Duration::from_secs(2), h.tcp.recv())
        .await
        .unwrap()
        .unwrap();
    h.net.inject(&peer.rst());
    let mut buf = [0u8; 8];
    let err = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.stats.snapshot().tcp_active, 0);
    h.shutdown().await;
}

#[tokio::test]
async fn dropping_the_stream_sends_a_fin() {
    let mut h = start(StackOptions::default());
    let mut peer = TcpPeer::new("10.0.0.2:40002", "1.1.1.1:443");
    handshake(&h.net, &mut peer).await;
    let (_, stream) = timeout(Duration::from_secs(2), h.tcp.recv())
        .await
        .unwrap()
        .unwrap();
    drop(stream);
    loop {
        if next_seg(&h.net, &peer).await.fin {
            break;
        }
    }
    h.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_closed_flow_leaves_the_table_after_time_wait() {
    let mut h = start(StackOptions::default());
    let mut peer = TcpPeer::new("10.0.0.2:40003", "1.1.1.1:443");
    handshake(&h.net, &mut peer).await;
    let (_, mut stream) = h.tcp.recv().await.unwrap();
    stream.shutdown().await.unwrap();
    let fin = loop {
        let seg = next_seg(&h.net, &peer).await;
        if seg.fin {
            break seg;
        }
    };
    peer.absorb(&fin);
    h.net.inject(&peer.ack());
    h.net.inject(&peer.fin());
    let ack = loop {
        let seg = next_seg(&h.net, &peer).await;
        if seg.ack == Some(peer.seq) && seg.ack != fin.ack {
            break seg;
        }
    };
    let _ = ack;
    drop(stream);
    assert_eq!(h.stats.snapshot().tcp_active, 1);
    tokio::time::sleep(Duration::from_secs(70)).await;
    assert_eq!(h.stats.snapshot().tcp_active, 0);
    h.shutdown().await;
}

#[tokio::test]
async fn syns_past_the_flow_limit_are_refused() {
    let h = start(StackOptions {
        max_tcp_flows: 1,
        ..StackOptions::default()
    });
    let mut first = TcpPeer::new("10.0.0.2:40010", "1.1.1.1:443");
    handshake(&h.net, &mut first).await;
    let mut second = TcpPeer::new("10.0.0.2:40011", "1.1.1.1:443");
    h.net.inject(&second.syn());
    let reply = timeout(Duration::from_millis(200), async {
        loop {
            let raw = h.net.take_vec().await;
            if second.parse(&raw).is_some() {
                return;
            }
        }
    })
    .await;
    assert!(reply.is_err());
    assert_eq!(h.stats.snapshot().tcp_refused, 1);
    h.shutdown().await;
}

#[tokio::test]
async fn syns_past_the_half_open_limit_are_refused_until_a_handshake_completes() {
    let h = start(StackOptions {
        max_half_open_tcp: 1,
        ..StackOptions::default()
    });
    let mut first = TcpPeer::new("10.0.0.2:40030", "1.1.1.1:443");
    h.net.inject(&first.syn());
    let synack = next_seg(&h.net, &first).await;
    assert!(synack.syn);

    let mut second = TcpPeer::new("10.0.0.2:40031", "1.1.1.1:443");
    h.net.inject(&second.syn());
    let reply = timeout(Duration::from_millis(200), async {
        loop {
            let raw = h.net.take_vec().await;
            if second.parse(&raw).is_some() {
                return;
            }
        }
    })
    .await;
    assert!(reply.is_err());
    assert_eq!(h.stats.snapshot().tcp_refused, 1);

    first.absorb(&synack);
    h.net.inject(&first.ack());
    let mut third = TcpPeer::new("10.0.0.2:40032", "1.1.1.1:443");
    handshake(&h.net, &mut third).await;
    assert_eq!(h.stats.snapshot().tcp_refused, 1);
    h.shutdown().await;
}

#[tokio::test]
async fn the_broadcast_address_of_the_device_subnet_is_dropped() {
    let mut h = start(StackOptions {
        broadcast: Some("198.18.0.3".parse().unwrap()),
        ..StackOptions::default()
    });
    let client: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    h.net.inject(&udp_packet(
        client,
        "198.18.0.3:137".parse().unwrap(),
        b"nb",
    ));
    h.net.inject(&udp_packet(
        client,
        "198.18.0.4:137".parse().unwrap(),
        b"ok",
    ));
    let (_, packet, _) = timeout(Duration::from_secs(2), h.udp.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet.as_slice(), b"ok");
    assert_eq!(h.stats.snapshot().rx_dropped, 1);
    h.shutdown().await;
}

#[tokio::test]
async fn data_for_an_unknown_flow_is_answered_with_a_reset() {
    let h = start(StackOptions::default());
    let mut peer = TcpPeer::new("10.0.0.2:40020", "1.1.1.1:443");
    peer.ack = 77;
    h.net.inject(&peer.data(b"stray"));
    let seg = next_seg(&h.net, &peer).await;
    assert!(seg.rst);
    h.shutdown().await;
}

async fn udp_round_trip(client: &str, server: &str, batched: bool) {
    let mut h = start_on(StackOptions::default(), batched);
    let (client, server): (SocketAddr, SocketAddr) =
        (client.parse().unwrap(), server.parse().unwrap());
    h.net.inject(&udp_packet(client, server, b"ping"));
    let (flow, packet, reply) = timeout(Duration::from_secs(2), h.udp.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flow.network, Network::Udp);
    assert_eq!((flow.src, flow.dst), (client, server));
    assert_eq!(packet.as_slice(), b"ping");
    drop(packet);

    let from = Address::Socket(server);
    poll_fn(|cx| reply.poll_write_back(cx, b"pong", &from))
        .await
        .unwrap();
    let raw = timeout(Duration::from_secs(2), h.net.take_vec())
        .await
        .unwrap();
    let udp = parse_udp(&raw).unwrap();
    assert_eq!((udp.src, udp.dst), (server, client));
    assert_eq!(udp.payload, b"pong");
    h.shutdown().await;
}

#[tokio::test]
async fn udp_echo_over_ipv4() {
    udp_round_trip("10.0.0.2:5000", "8.8.4.4:9999", false).await;
}

#[tokio::test]
async fn a_batching_device_carries_tcp_and_udp() {
    tcp_round_trip("10.0.0.2:40000", "93.184.216.34:80", true).await;
    udp_round_trip("[fd00::2]:5000", "[2001:4860:4860::8844]:9999", true).await;
}

struct Wakes(std::sync::atomic::AtomicUsize);

impl std::task::Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn replies_waiting_on_a_full_device_neither_spin_nor_all_wake_for_one_slot() {
    use std::sync::atomic::Ordering;
    use std::task::{Context, Waker};

    let mut h = start(StackOptions::default());
    let (client, server): (SocketAddr, SocketAddr) = (
        "10.0.0.2:5000".parse().unwrap(),
        "8.8.4.4:9999".parse().unwrap(),
    );
    h.net.inject(&udp_packet(client, server, b"ping"));
    let (_, _, reply) = timeout(Duration::from_secs(2), h.udp.recv())
        .await
        .unwrap()
        .unwrap();
    let from = Address::Socket(server);
    let tasks: Vec<_> = (0..300)
        .map(|_| Arc::new(Wakes(Default::default())))
        .collect();
    let filler = Waker::from(Arc::clone(&tasks[0]));
    let mut accepted = 0;
    for _ in 0..2 {
        while reply
            .poll_write_back(&mut Context::from_waker(&filler), b"pong", &from)
            .is_ready()
        {
            accepted += 1;
            if accepted % 64 == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tasks[0].0.store(0, Ordering::SeqCst);
    for task in &tasks[1..] {
        let waker = Waker::from(Arc::clone(task));
        assert!(
            reply
                .poll_write_back(&mut Context::from_waker(&waker), b"pong", &from)
                .is_pending()
        );
    }
    let woken = || {
        tasks
            .iter()
            .filter(|task| task.0.load(Ordering::SeqCst) > 0)
            .count()
    };
    let spinning = woken();
    let mut buf = [0u8; 2048];
    assert!(h.net.try_take(&mut buf).is_some());
    tokio::time::sleep(Duration::from_millis(20)).await;
    let after_one = woken();
    assert_eq!(
        (spinning, after_one),
        (0, 1),
        "after {accepted} accepted replies: waiters that woke themselves, then waiters woken \
         by one free device slot"
    );
    h.shutdown().await;
}

#[tokio::test]
async fn udp_echo_over_ipv6() {
    udp_round_trip("[fd00::2]:5000", "[2001:4860:4860::8844]:9999", false).await;
}

#[tokio::test]
async fn udp_dns_is_answered_without_reaching_the_sink() {
    let mut h = start(with_dns());
    let client: SocketAddr = "10.0.0.2:5353".parse().unwrap();
    let server: SocketAddr = "9.9.9.9:53".parse().unwrap();
    h.net.inject(&udp_packet(client, server, b"query"));
    let raw = timeout(Duration::from_secs(2), h.net.take_vec())
        .await
        .unwrap();
    let udp = parse_udp(&raw).unwrap();
    assert_eq!((udp.src, udp.dst), (server, client));
    assert_eq!(udp.payload, b"yreuq");
    assert!(h.udp.try_recv().is_err());
    assert_eq!(h.stats.snapshot().dns_hijacked, 1);
    h.shutdown().await;
}

/// Holds every query until it is dropped, and counts the drops.
struct Stalled(Arc<std::sync::atomic::AtomicUsize>);

struct CountsDrop(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for CountsDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl DnsHijack for Stalled {
    async fn answer(&self, _query: &[u8]) -> Option<Vec<u8>> {
        let _counted = CountsDrop(self.0.clone());
        std::future::pending().await
    }
}

#[tokio::test]
async fn dns_answers_in_flight_end_when_their_owner_stops() {
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let tracker = tokio_util::task::TaskTracker::new();
    let owner = CancellationToken::new();
    let h = start(StackOptions {
        dns: Some(Arc::new(DnsConfig {
            matcher: DnsMatcher::parse(["any:53"]).unwrap(),
            handler: Arc::new(Stalled(dropped.clone())),
        })),
        tasks: concord_common::Tasks::current(tracker.clone(), owner.clone()),
        ..StackOptions::default()
    });
    let client: SocketAddr = "10.0.0.2:5353".parse().unwrap();
    h.net
        .inject(&udp_packet(client, "9.9.9.9:53".parse().unwrap(), b"query"));
    let mut peer = TcpPeer::new("[fd00::2]:40031", "[2606:4700::1111]:53");
    handshake(&h.net, &mut peer).await;
    h.net.inject(&peer.data(&[0, 3, b'a', b'b', b'c']));
    timeout(Duration::from_secs(2), async {
        while tracker.len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both answers are under way on the owner's tasks");
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 0);

    owner.cancel();
    tracker.close();
    timeout(Duration::from_secs(2), tracker.wait())
        .await
        .expect("an answer outlived its owner");
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 2);
    h.shutdown().await;
}

#[tokio::test]
async fn tcp_dns_is_answered_with_length_prefix() {
    let mut h = start(with_dns());
    let mut peer = TcpPeer::new("[fd00::2]:40030", "[2606:4700::1111]:53");
    handshake(&h.net, &mut peer).await;
    h.net.inject(&peer.data(&[0, 3, b'a', b'b', b'c']));
    let answer = read_payload(&h.net, &mut peer, 5).await;
    assert_eq!(answer, [0, 3, b'c', b'b', b'a']);
    assert!(h.tcp.try_recv().is_err());
    h.shutdown().await;
}

#[tokio::test]
async fn echo_requests_are_answered_for_both_families() {
    let h = start(StackOptions::default());
    let caps = ChecksumCapabilities::default();

    let (src, dst) = ("10.0.0.2".parse().unwrap(), "1.1.1.1".parse().unwrap());
    let repr = Icmpv4Repr::EchoRequest {
        ident: 7,
        seq_no: 3,
        data: b"abcd",
    };
    let mut l4 = vec![0u8; repr.buffer_len()];
    repr.emit(&mut Icmpv4Packet::new_unchecked(&mut l4[..]), &caps);
    h.net.inject(&wrap_ip(src, dst, IpProtocol::Icmp, &l4));
    let raw = timeout(Duration::from_secs(2), h.net.take_vec())
        .await
        .unwrap();
    let (from, to, l4) = split_ip(&raw).unwrap();
    assert_eq!((from, to), (dst, src));
    assert_eq!(l4.first(), Some(&0));

    let (src6, dst6): (std::net::Ipv6Addr, std::net::Ipv6Addr) =
        ("fd00::2".parse().unwrap(), "2001:db8::9".parse().unwrap());
    let repr = Icmpv6Repr::EchoRequest {
        ident: 7,
        seq_no: 3,
        data: b"abcd",
    };
    let mut l4 = vec![0u8; repr.buffer_len()];
    repr.emit(
        &src6,
        &dst6,
        &mut Icmpv6Packet::new_unchecked(&mut l4[..]),
        &caps,
    );
    h.net
        .inject(&wrap_ip(src6.into(), dst6.into(), IpProtocol::Icmpv6, &l4));
    let raw = timeout(Duration::from_secs(2), h.net.take_vec())
        .await
        .unwrap();
    let (from, to, l4) = split_ip(&raw).unwrap();
    assert_eq!((from, to), (dst6.into(), src6.into()));
    assert_eq!(l4.first(), Some(&129));
    assert_eq!(h.stats.snapshot().icmp_echo, 2);
    h.shutdown().await;
}

#[tokio::test]
async fn malformed_fragmented_and_corrupt_packets_do_not_stop_the_stack() {
    let mut h = start(StackOptions::default());
    let client: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    let server: SocketAddr = "8.8.4.4:9999".parse().unwrap();

    let good = udp_packet(client, server, b"ok");
    let mut fragment = good.clone();
    fragment[6] = 0x20;
    let mut corrupt = good.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let truncated = good[..good.len() - 3].to_vec();
    let mut junk = Vec::new();
    for seed in 0..64u32 {
        let packet: Vec<u8> = (0..(seed as usize * 7 % 200))
            .map(|i| (seed.wrapping_mul(31).wrapping_add(i as u32 * 17) >> 3) as u8)
            .collect();
        junk.push(packet);
    }
    for packet in [
        &fragment,
        &corrupt,
        &truncated,
        &vec![0x45],
        &vec![],
        &vec![0x60; 40],
    ]
    .into_iter()
    .chain(junk.iter())
    {
        h.net.inject(packet);
    }
    h.net.inject(&good);
    let (_, packet, _) = timeout(Duration::from_secs(2), h.udp.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet.as_slice(), b"ok");
    assert!(h.stats.snapshot().rx_dropped >= 3);
    assert!(!h.task.is_finished());
    h.shutdown().await;
}

#[tokio::test]
async fn stopping_resets_open_streams() {
    let mut h = start(StackOptions::default());
    let mut peer = TcpPeer::new("10.0.0.2:40040", "1.1.1.1:443");
    handshake(&h.net, &mut peer).await;
    let (_, mut stream) = h.tcp.recv().await.unwrap();
    h.stop.cancel();
    let mut buf = [0u8; 4];
    let err = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    h.task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_idle_established_flow_outlives_the_handshake_timeout() {
    let mut h = start(StackOptions::default());
    let mut peer = TcpPeer::new("10.0.0.2:40050", "1.1.1.1:443");
    handshake(&h.net, &mut peer).await;
    let (_, mut stream) = h.tcp.recv().await.unwrap();
    tokio::time::sleep(Duration::from_secs(200)).await;
    assert_eq!(h.stats.snapshot().tcp_active, 1);
    let mut buf = [0u8; 1];
    assert!(
        timeout(Duration::from_millis(10), stream.read(&mut buf))
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_secs(400)).await;
    assert_eq!(h.stats.snapshot().tcp_active, 0);
    h.shutdown().await;
}
