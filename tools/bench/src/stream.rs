//! Bulk TCP transfer workloads (`tcp-down`, `tcp-up`, `tcp-multi`).
//!
//! Downloads count what the client reads; uploads count what the origin stamps and reports
//! on its own 100 ms cadence, so neither socket buffers nor reverse-path report coalescing
//! skews throughput or interval steadiness.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::sync::Notify;

use crate::load::{Ctx, Io, Metrics, Windows, costs, io};
use crate::origin::{self, CHUNK, REPORT_BYTES, REPORT_EVERY, SINK_MAGIC};
use crate::sockets;
use crate::socks::{self, Entry};
use crate::stats;
use crate::syscalls;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    Down,
    Up,
}

type OriginSamples = Arc<Mutex<Vec<(u64, u64)>>>;

struct WindowEdges {
    tcp_before: Option<sockets::Snapshot>,
    tcp_after: Option<sockets::Snapshot>,
    net_before: Option<NetEdge>,
    net_after: Option<NetEdge>,
}

struct FirstByte<'a> {
    slot: &'a AtomicU64,
    connected: Instant,
    ready: &'a Notify,
}

impl FirstByte<'_> {
    fn record(&self) {
        let elapsed_ns = self
            .connected
            .elapsed()
            .as_nanos()
            .clamp(1, u64::MAX as u128) as u64;
        self.slot.store(elapsed_ns, Ordering::Relaxed);
        self.ready.notify_waiters();
    }
}

struct Flows {
    counters: Arc<Vec<AtomicU64>>,
    first_byte_ns: Arc<Vec<AtomicU64>>,
    ready: Arc<Notify>,
    origin_samples: OriginSamples,
    stop: Arc<AtomicBool>,
    failed: Arc<Mutex<Option<String>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Flows {
    async fn spawn(ctx: &Ctx, direction: Direction, flows: usize) -> Io<Flows> {
        let counters: Arc<Vec<AtomicU64>> =
            Arc::new((0..flows).map(|_| AtomicU64::new(0)).collect());
        let first_byte_ns: Arc<Vec<AtomicU64>> =
            Arc::new((0..flows).map(|_| AtomicU64::new(0)).collect());
        let ready = Arc::new(Notify::new());
        let origin_samples: OriginSamples = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(Mutex::new(None::<String>));
        let target = ctx.at(match direction {
            Direction::Down => ctx.ports.source,
            Direction::Up => ctx.ports.sink,
        });
        let rate = ctx.client_rate;
        let mut tasks = Vec::with_capacity(flows);
        for flow in 0..flows {
            let stream = socks::connect(ctx.entry, target)
                .await
                .map_err(io("connect"))?;
            let connected = Instant::now();
            let (counters, first_byte_ns, ready) =
                (counters.clone(), first_byte_ns.clone(), ready.clone());
            let (stop, failed) = (stop.clone(), failed.clone());
            let samples = (direction == Direction::Up && flow == 0).then(|| origin_samples.clone());
            tasks.push(tokio::spawn(async move {
                let first = FirstByte {
                    slot: &first_byte_ns[flow],
                    connected,
                    ready: &ready,
                };
                let result = match direction {
                    Direction::Down => drain(stream, &counters[flow], &first, &stop).await,
                    Direction::Up => {
                        fill(
                            stream,
                            rate,
                            &counters[flow],
                            &first,
                            samples.as_deref(),
                            &stop,
                        )
                        .await
                    }
                };
                if let Err(err) = result
                    && !stop.load(Ordering::Relaxed)
                {
                    *failed.lock().unwrap_or_else(|e| e.into_inner()) = Some(err.to_string());
                    ready.notify_waiters();
                }
            }));
        }
        Ok(Flows {
            counters,
            first_byte_ns,
            ready,
            origin_samples,
            stop,
            failed,
            tasks,
        })
    }

    fn total(&self) -> u64 {
        self.counters
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
    }

    fn sample_len(&self) -> usize {
        self.origin_samples
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    fn samples_from(&self, start: usize) -> Vec<(u64, u64)> {
        self.origin_samples
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(start..)
            .unwrap_or_default()
            .to_vec()
    }

    fn ready_count(&self) -> usize {
        self.first_byte_ns
            .iter()
            .filter(|ns| ns.load(Ordering::Relaxed) > 0)
            .count()
    }

    fn first_byte_ms(&self) -> Option<f64> {
        if self.ready_count() < self.counters.len() {
            return None;
        }
        self.first_byte_ns
            .iter()
            .map(|ns| ns.load(Ordering::Relaxed))
            .max()
            .map(|ns| ns as f64 / 1e6)
    }

    async fn wait_first_byte(&self, timeout: Duration, connect_ms: f64) -> Io<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(err) = self
                .failed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
            {
                return Err(err);
            }
            if self.ready_count() == self.counters.len() {
                return Ok(());
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(format!(
                        "first byte timed out after {:.0} ms ({}/{} flows ready, connect_ms={connect_ms:.1}, bytes={})",
                        timeout.as_secs_f64() * 1e3,
                        self.ready_count(),
                        self.counters.len(),
                        self.total(),
                    ));
                }
            }
        }
    }

    fn finish(self) -> Option<String> {
        self.stop.store(true, Ordering::Relaxed);
        for task in self.tasks {
            task.abort();
        }
        self.failed.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Bulk transfer over `flows` connections.
pub(crate) async fn run(ctx: &Ctx, direction: Direction, flows: usize) -> Io<Metrics> {
    let connect_started = Instant::now();
    let active = Flows::spawn(ctx, direction, flows).await?;
    let connect_ms = connect_started.elapsed().as_secs_f64() * 1e3;
    if !ctx.first_byte_timeout.is_zero()
        && let Err(err) = active
            .wait_first_byte(ctx.first_byte_timeout, connect_ms)
            .await
    {
        let task_err = active.finish();
        return Err(task_err.unwrap_or(err));
    }
    tokio::time::sleep(ctx.warmup).await;
    let mixed_port = match ctx.entry {
        Entry::Socks(proxy) => Some(proxy.port()),
        Entry::Tun => None,
    };
    let tcp_before = sockets::snapshot(ctx.pids.core, mixed_port);
    let net_before = ctx.net_counters.then(|| NetEdge::read(ctx));
    let per_flow_start: Vec<u64> = active
        .counters
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    let sample_start = active.sample_len();
    let windows = Windows::open(ctx.pids);
    let started = Instant::now();
    let start_bytes = active.total();
    let mut intervals = sample_window(&active, direction, started, start_bytes, ctx.duration).await;
    let elapsed = started.elapsed().as_secs_f64();
    let bytes = active.total() - start_bytes;
    let per_flow: Vec<f64> = active
        .counters
        .iter()
        .zip(&per_flow_start)
        .map(|(c, s)| (c.load(Ordering::Relaxed) - s) as f64 * 8.0 / 1e9 / elapsed)
        .collect();
    let closed = windows.close();
    let up_samples = (direction == Direction::Up).then(|| active.samples_from(sample_start));
    let first_byte_ms = active.first_byte_ms();
    let edges = WindowEdges {
        tcp_before,
        tcp_after: sockets::snapshot(ctx.pids.core, mixed_port),
        net_before,
        net_after: ctx.net_counters.then(|| NetEdge::read(ctx)),
    };
    if let Some(err) = active.finish() {
        return Err(err);
    }
    if bytes == 0 {
        let first = first_byte_ms.map_or_else(|| "none".into(), |ms| format!("{ms:.1}"));
        return Err(format!(
            "no bytes moved (connect_ms={connect_ms:.1}, first_byte_ms={first}, warmup_ms={:.0}, warmup_bytes={start_bytes}, window_ms={:.0})",
            ctx.warmup.as_secs_f64() * 1e3,
            elapsed * 1e3,
        ));
    }
    if let Some(samples) = up_samples {
        intervals = origin_intervals(&samples);
        if intervals.is_empty() && ctx.duration >= REPORT_EVERY * 2 {
            return Err(format!(
                "no origin upload interval samples in {:.0} ms window ({} reports received)",
                elapsed * 1e3,
                samples.len(),
            ));
        }
    }
    let mut m = Metrics::new();
    m.insert("gbps".into(), bytes as f64 * 8.0 / 1e9 / elapsed);
    if let Some(ms) = first_byte_ms {
        m.insert("first_byte_ms".into(), ms);
    }
    record_intervals(&mut m, &intervals);
    record_multi_flow(&mut m, &per_flow, ctx.net_counters);
    costs(&mut m, &closed, Some(bytes), None);
    record_socket_metrics(&mut m, &closed, &edges, bytes, elapsed);
    Ok(m)
}

fn record_multi_flow(m: &mut Metrics, per_flow: &[f64], net_counters: bool) {
    if per_flow.len() <= 1 {
        return;
    }
    m.insert("jain".into(), stats::jain(per_flow));
    m.insert(
        "min_flow_gbps".into(),
        per_flow.iter().copied().fold(f64::INFINITY, f64::min),
    );
    if net_counters {
        for (flow, rate) in per_flow.iter().enumerate() {
            m.insert(format!("flow_{flow}_gbps"), *rate);
        }
    }
}

async fn sample_window(
    active: &Flows,
    direction: Direction,
    started: Instant,
    start_bytes: u64,
    duration: Duration,
) -> Vec<f64> {
    if direction == Direction::Up {
        tokio::time::sleep(duration).await;
        return Vec::new();
    }
    let mut intervals = Vec::new();
    let mut last = (started, start_bytes);
    let mut tick =
        tokio::time::interval_at(tokio::time::Instant::now() + REPORT_EVERY, REPORT_EVERY);
    while started.elapsed() < duration {
        tick.tick().await;
        let now = (Instant::now(), active.total());
        intervals
            .push((now.1 - last.1) as f64 * 8.0 / 1e9 / now.0.duration_since(last.0).as_secs_f64());
        last = now;
    }
    intervals
}

fn record_intervals(m: &mut Metrics, intervals: &[f64]) {
    if intervals.is_empty() {
        return;
    }
    m.insert("interval_cv".into(), stats::cv(intervals));
    let mut sorted = intervals.to_vec();
    sorted.sort_by(f64::total_cmp);
    m.insert("interval_p10_gbps".into(), stats::quantile(&sorted, 0.1));
}

/// Converts origin-stamped `(elapsed_ns, total_bytes)` samples into Gbit/s rates per interval,
/// skipping any interval shorter than half a report period (such as catch-up ticks after a stall
/// or a trailing EOF report).
fn origin_intervals(samples: &[(u64, u64)]) -> Vec<f64> {
    let min_dt_ns = (REPORT_EVERY / 2).as_nanos() as u64;
    samples
        .windows(2)
        .filter_map(|pair| {
            let dt_ns = pair[1].0.checked_sub(pair[0].0)?;
            if dt_ns < min_dt_ns {
                return None;
            }
            let db = pair[1].1.saturating_sub(pair[0].1);
            Some(db as f64 * 8.0 / dt_ns as f64)
        })
        .collect()
}

fn record_socket_metrics(
    m: &mut Metrics,
    closed: &crate::load::Closed,
    edges: &WindowEdges,
    bytes: u64,
    elapsed: f64,
) {
    if let (Some(before), Some(after)) = (edges.tcp_before.as_ref(), edges.tcp_after.as_ref()) {
        let (received, sent) = sockets::metrics(before, after, m);
        if let Some(counts) = closed.core.syscall_counts.filter(|c| c.get("splice") == 0) {
            let per_call =
                |bytes: u64, calls: u64| (calls > 0).then(|| bytes as f64 / calls as f64);
            if let Some(v) = per_call(received, counts.sum(&syscalls::RECV)) {
                m.insert("socket_bytes_per_recv_call".into(), v);
            }
            if let Some(v) = per_call(sent, counts.sum(&syscalls::SEND)) {
                m.insert("socket_bytes_per_send_call".into(), v);
            }
        }
        if edges.net_after.is_some() {
            sockets::receive_state(before, after, m);
        }
    }
    if let (Some(before), Some(after)) = (edges.net_before.as_ref(), edges.net_after.as_ref()) {
        crate::netstat::metrics(&before.counters, &after.counters, bytes, m);
        if let (Some(before), Some(after)) = (&before.server, &after.server) {
            sockets::link_metrics(before, after, elapsed, m);
        }
    }
}

/// What `--net-counters` reads at one edge of a window.
struct NetEdge {
    counters: crate::netstat::Edge,
    server: Option<sockets::Snapshot>,
}

impl NetEdge {
    fn read(ctx: &Ctx) -> NetEdge {
        let far = ctx.far_netns.as_deref();
        NetEdge {
            counters: crate::netstat::edge(far),
            server: far
                .zip(ctx.pids.server)
                .and_then(|(netns, server)| sockets::snapshot_link(server, netns)),
        }
    }
}

async fn drain(
    mut stream: tokio::net::TcpStream,
    counter: &AtomicU64,
    first: &FirstByte<'_>,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4 * CHUNK];
    let mut saw_first = false;
    while !stop.load(Ordering::Relaxed) {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::other("origin closed the download"));
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
        if !saw_first {
            saw_first = true;
            first.record();
        }
    }
    socks::abort(stream);
    Ok(())
}

async fn fill(
    stream: tokio::net::TcpStream,
    rate_mbit: Option<f64>,
    counter: &AtomicU64,
    first: &FirstByte<'_>,
    samples: Option<&Mutex<Vec<(u64, u64)>>>,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let (mut read, mut write) = stream.into_split();
    let writer = crate::pace::send_chunks(&mut write, 0xa5, rate_mbit);
    let reports = async {
        let mut magic = [0u8; SINK_MAGIC.len()];
        read.read_exact(&mut magic).await?;
        if magic != SINK_MAGIC {
            return Err(std::io::Error::other(
                "origin speaks an older or incompatible upload report format; rebuild the remote origin from the same commit",
            ));
        }
        let mut report = [0u8; REPORT_BYTES];
        let mut saw_first = false;
        while !stop.load(Ordering::Relaxed) {
            read.read_exact(&mut report).await?;
            let (origin_ns, total) = origin::decode_report(report);
            counter.store(total, Ordering::Relaxed);
            if let Some(samples) = samples {
                samples
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((origin_ns, total));
            }
            if !saw_first && total > 0 {
                saw_first = true;
                first.record();
            }
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        result = writer => result,
        result = reports => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncWriteExt;

    use crate::load::Pids;
    use crate::origin::Ports;

    fn test_ctx(source_port: u16, warmup: Duration, first_byte_timeout: Duration) -> Ctx {
        Ctx {
            entry: Entry::Tun,
            origin: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ports: Ports {
                source: source_port,
                sink: source_port,
                echo: 0,
                crr: 0,
                udp: 0,
                https: 0,
                http: 0,
            },
            warmup,
            first_byte_timeout,
            duration: Duration::from_millis(250),
            pids: Pids {
                core: std::process::id(),
                server: None,
                origin: None,
            },
            flows: 1,
            crr_conns: 1,
            rr_slow: None,
            crr_concurrency: 1,
            page_conns: 1,
            udp_size: 1200,
            udp_window: 1,
            idle_conns: 1,
            net_counters: false,
            client_rate: None,
            far_netns: None,
            tls: None,
            origin_tls: None,
        }
    }

    #[test]
    fn origin_intervals_ignore_delivery_coalescing_and_short_intervals() {
        // 1 Gbit/s = 12_500_000 bytes per 100 ms.
        let samples = [
            (0, 0),
            (100_000_000, 12_500_000),
            // Mid-stream 5 ms catch-up burst must be skipped without distorting surrounding rates.
            (105_000_000, 12_500_000),
            (205_000_000, 25_000_000),
            (305_000_000, 37_500_000),
            // Trailing 10 ms EOF stub must also be skipped.
            (315_000_000, 37_500_000),
        ];
        let rates = origin_intervals(&samples);
        assert_eq!(rates.len(), 3);
        assert!(rates.iter().all(|&r| (r - 1.0).abs() < 1e-9));
        assert!(stats::cv(&rates) < 1e-9);
    }

    #[test]
    fn origin_intervals_surface_real_forward_stalls() {
        let samples = [
            (100_000_000, 12_500_000),
            (200_000_000, 25_000_000),
            (300_000_000, 25_000_000),
            (400_000_000, 25_000_000),
            (500_000_000, 37_500_000),
        ];
        let rates = origin_intervals(&samples);
        assert_eq!(rates, vec![1.0, 0.0, 0.0, 1.0]);
        let mut sorted = rates.clone();
        sorted.sort_by(f64::total_cmp);
        assert_eq!(stats::quantile(&sorted, 0.1), 0.0);
        assert!(stats::cv(&rates) > 1.0);
    }

    #[tokio::test]
    async fn fill_reads_origin_stamped_reports_over_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (server, _) = listener.accept().await.unwrap();
            let _ = origin::sink_flow(server).await;
        });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let counter = Arc::new(AtomicU64::new(0));
        let first_slot = Arc::new(AtomicU64::new(0));
        let ready = Arc::new(Notify::new());
        let samples = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (c, f, r, s, st) = (
            counter.clone(),
            first_slot.clone(),
            ready.clone(),
            samples.clone(),
            stop.clone(),
        );
        let task = tokio::spawn(async move {
            let first = FirstByte {
                slot: &f,
                connected: Instant::now(),
                ready: &r,
            };
            fill(client, Some(200.0), &c, &first, Some(&s), &st).await
        });
        tokio::time::sleep(Duration::from_millis(550)).await;
        stop.store(true, Ordering::Relaxed);
        task.abort();
        let recorded = samples.lock().unwrap().clone();
        assert!(
            recorded.len() >= 3,
            "expected >=3 origin reports, got {recorded:?}"
        );
        assert!(
            recorded.windows(2).all(|w| w[1].0 > w[0].0),
            "origin timestamps must be strictly increasing: {recorded:?}"
        );
        assert!(first_slot.load(Ordering::Relaxed) > 0);
        let mut rates = origin_intervals(&recorded);
        assert!(!rates.is_empty());
        rates.sort_by(f64::total_cmp);
        let median = stats::quantile(&rates, 0.5);
        assert!(
            (0.05..=0.4).contains(&median),
            "expected median rate near 0.2 Gbit/s, got {median}"
        );
        assert!(counter.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn fill_rejects_legacy_origin_without_sink_magic() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            // Simulate an older origin sending bare 8-byte cumulative totals with no header.
            let _ = server.write_all(&12_500_000u64.to_le_bytes()).await;
            let _ = server.write_all(&25_000_000u64.to_le_bytes()).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let counter = AtomicU64::new(0);
        let first_slot = AtomicU64::new(0);
        let ready = Notify::new();
        let first = FirstByte {
            slot: &first_slot,
            connected: Instant::now(),
            ready: &ready,
        };
        let stop = AtomicBool::new(false);
        let err = fill(client, Some(200.0), &counter, &first, None, &stop)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("older or incompatible upload report"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn delayed_first_byte_waits_before_warmup_and_reports_latency() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            // Longer than warmup + duration (100 ms + 250 ms) so without waiting it would fail.
            tokio::time::sleep(Duration::from_millis(450)).await;
            let chunk = vec![0x5au8; CHUNK];
            while server.write_all(&chunk).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let ctx = test_ctx(port, Duration::from_millis(100), Duration::from_secs(2));
        let metrics = run(&ctx, Direction::Down, 1).await.unwrap();
        assert!(metrics["gbps"] > 0.0);
        assert!(
            metrics["first_byte_ms"] >= 400.0,
            "expected first_byte_ms >= 400, got {}",
            metrics["first_byte_ms"]
        );
    }

    #[tokio::test]
    async fn stalled_peer_hits_first_byte_timeout_with_diagnostics() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _hold = tokio::spawn(async move {
            let (_server, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let ctx = test_ctx(port, Duration::from_millis(50), Duration::from_millis(150));
        let err = run(&ctx, Direction::Down, 1).await.unwrap_err();
        assert!(err.contains("first byte timed out"), "got: {err}");
        assert!(err.contains("0/1 flows ready"), "got: {err}");
        assert!(err.contains("connect_ms="), "got: {err}");
    }

    #[tokio::test]
    async fn zero_first_byte_timeout_reports_timing_on_no_bytes_moved() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let _hold = tokio::spawn(async move {
            let (_server, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let ctx = test_ctx(port, Duration::from_millis(50), Duration::ZERO);
        let err = run(&ctx, Direction::Down, 1).await.unwrap_err();
        assert!(err.contains("no bytes moved"), "got: {err}");
        assert!(err.contains("first_byte_ms=none"), "got: {err}");
        assert!(err.contains("warmup_bytes=0"), "got: {err}");
        assert!(err.contains("window_ms="), "got: {err}");
    }
}
