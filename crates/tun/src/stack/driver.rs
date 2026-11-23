mod dispatch;
mod rx;
mod tx;

use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use concord_common::Tasks;
use concord_netstack::frag::Reassembler;
use concord_netstack::wire::L4Checksum;
use concord_netstack::{StackConfig, TcpConfig, TcpStack};
use concord_platform::SparseBuf;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tokio::time::Sleep;
use tokio_util::sync::CancellationToken;

use super::own_wake::OwnWake;
use super::pool::{Slot, TxPool};
use super::queues::Queues;
use super::replies::ReplySources;
use super::stats::{StackStats, report};
use super::udp::UdpTable;
use super::{DnsConfig, FlowSink, StackOptions};
use crate::device::{Device, MAX_BATCH};
use tx::PoolEgress;

const RX_BATCH: usize = 64;
const RX_BATCH_START: usize = 8;
const MAX_ROUNDS: usize = 8;
/// Bytes a round reads before the stack answers them, as sing-tun ends a read burst: an
/// upload's ACKs go out while the sender still has window, not after the device runs dry.
const ROUND_READ_BYTES: usize = 1 << 20;
const SWEEP_INTERVAL: u64 = 15_000_000;
const RX_BUFFER: usize = 65_536 + 16;
const DNS_CONCURRENCY: usize = 256;
const TX_POOL_BYTES: usize = 1 << 20;
/// Slots start at the MTU and grow to a frame's size the first time they carry one.
const SEGMENTED_SLOTS: usize = 64;
const MAX_FRAME: usize = 65_535;

enum QueueRole {
    Single,
    Multi { index: usize, queues: Arc<Queues> },
}

pub(super) struct Prepared<D> {
    dev: D,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
}

pub(super) fn prepare<D: Device>(dev: D) -> io::Result<Vec<Prepared<D>>> {
    dev.into_queues()
        .into_iter()
        .map(|dev| {
            let dev = dev.prepare()?;
            Ok(Prepared { dev, ready: None })
        })
        .collect()
}

impl<D> Prepared<D> {
    pub fn ready(&mut self) -> tokio::sync::oneshot::Receiver<()> {
        let (sent, received) = tokio::sync::oneshot::channel();
        self.ready = Some(sent);
        received
    }
}

pub(super) async fn run<D: Device>(
    options: StackOptions,
    dev: D,
    sink: Arc<dyn FlowSink>,
    stop: CancellationToken,
) -> io::Result<()> {
    run_prepared(options, prepare(dev)?, sink, stop).await
}

pub(super) async fn run_prepared<D: Device>(
    options: StackOptions,
    devs: Vec<Prepared<D>>,
    sink: Arc<dyn FlowSink>,
    stop: CancellationToken,
) -> io::Result<()> {
    let count = devs.len();
    if count <= 1 {
        let Some(dev) = devs.into_iter().next() else {
            return Ok(());
        };
        return run_queue(options, dev, sink, stop, QueueRole::Single).await;
    }
    let queues = Arc::new(Queues::new(count));
    let stop = stop.child_token();
    let _cancel = stop.clone().drop_guard();
    let mut running = FuturesUnordered::new();
    for (index, dev) in devs.into_iter().enumerate() {
        let options = StackOptions {
            max_tcp_flows: options.max_tcp_flows.div_ceil(count),
            max_half_open_tcp: options.max_half_open_tcp.div_ceil(count),
            ..options.clone()
        };
        running.push(options.tasks.clone().spawn_returning(run_queue(
            options,
            dev,
            Arc::clone(&sink),
            stop.clone(),
            QueueRole::Multi {
                index,
                queues: Arc::clone(&queues),
            },
        )));
    }
    let mut result = Ok(());
    while let Some(joined) = running.next().await {
        if let Err(err) = joined
            .map_err(io::Error::other)
            .and_then(|done| done.unwrap_or(Ok(())))
            && result.is_ok()
        {
            result = Err(err);
            stop.cancel();
        }
    }
    result
}

async fn run_queue<D: Device>(
    options: StackOptions,
    prepared: Prepared<D>,
    sink: Arc<dyn FlowSink>,
    stop: CancellationToken,
    queue: QueueRole,
) -> io::Result<()> {
    let Prepared { dev, ready } = prepared;
    let stop = stop.child_token();
    let cancelled = stop.clone();
    let work = move || async move {
        let driver = Driver::new(options, dev, sink, queue);
        drive(driver, stop, ready).await
    };
    let _cancel = cancelled.drop_guard();
    work().await
}

async fn drive<D: Device>(
    mut driver: Driver<D>,
    stop: CancellationToken,
    mut ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> io::Result<()> {
    let mut cancelled = Box::pin(stop.cancelled_owned());
    let (own, waker) = OwnWake::new();
    poll_fn(|task| {
        if cancelled.as_mut().poll(task).is_ready() {
            return Poll::Ready(Ok(()));
        }
        let cx = &mut Context::from_waker(&waker);
        if let Poll::Ready(Err(error)) = own.before_pass(task.waker(), || driver.dev.poll_io(cx)) {
            return Poll::Ready(Err(error));
        }
        let result = driver.poll_run(cx);
        if result.is_pending() {
            // Cooperative Pending already schedules another poll; it is not an empty I/O set.
            let busy = !driver.drained || !tokio::task::coop::has_budget_remaining();
            match driver.dev.set_busy(busy) {
                Ok(true) => {
                    driver.replies.requeue();
                    cx.waker().wake_by_ref();
                }
                Err(error) => return Poll::Ready(Err(error)),
                Ok(false) => {}
            }
            if !busy && let Poll::Ready(outcome) = driver.dev.poll_park(cx) {
                if let Err(error) = outcome {
                    return Poll::Ready(Err(error));
                }
                cx.waker().wake_by_ref();
            }
        }
        if result.is_pending()
            && let Some(ready) = ready.take()
        {
            let _ = ready.send(());
        }
        result
    })
    .await
}

struct Driver<D: Device> {
    dev: D,
    tcp: TcpStack,
    pool: Arc<TxPool>,
    stats: Arc<StackStats>,
    sink: Arc<dyn FlowSink>,
    handlers: Tasks,
    dns: Option<Arc<DnsConfig>>,
    dns_slots: Arc<Semaphore>,
    udp: UdpTable,
    replies: ReplySources,
    fragments: Reassembler,
    reassembled: Vec<u8>,
    inflight: VecDeque<Slot>,
    /// Room for one batch of reads: a batch's TCP payload goes to attached sockets straight
    /// from here when the batch ends.
    rx_buf: SparseBuf,
    rx_stride: usize,
    rx_extended: bool,
    rx_receive_epoch: u64,
    /// `recvmsg_x` walks every slot it is handed, so the batch follows what the device delivers.
    rx_batch: usize,
    options: StackOptions,
    sleep: Pin<Box<Sleep>>,
    next_sweep: u64,
    queue: QueueRole,
    tcp_reported: usize,
    udp_reported: usize,
    drained: bool,
}

impl<D: Device> Drop for Driver<D> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl<D: Device> Driver<D> {
    fn new(options: StackOptions, dev: D, sink: Arc<dyn FlowSink>, queue: QueueRole) -> Self {
        let mtu = options.mtu.clamp(576, 65_535);
        let device_batch = D::BATCH.clamp(1, MAX_BATCH);
        let rx_stride = if device_batch == 1 { RX_BUFFER } else { mtu };
        let (checksum, segment_limit) = if dev.checksum_offload() {
            (L4Checksum::Pseudo, dev.segment_limit())
        } else {
            (L4Checksum::Full, 0)
        };
        let slots = if segment_limit > 0 {
            SEGMENTED_SLOTS
        } else {
            (TX_POOL_BYTES / mtu).clamp(32, 256)
        };
        let pool = TxPool::new(slots, mtu);
        let pool = Arc::new(pool.with_offload(checksum, segment_limit));
        let stats = Arc::clone(&options.stats);
        let udp_timeout = i64::try_from(options.udp_timeout.as_micros()).unwrap_or(i64::MAX);
        let mut tcp = TcpStack::new(StackConfig {
            tcp: TcpConfig {
                mtu,
                congestion: options.congestion,
                ..TcpConfig::default()
            },
            max_connections: options.max_tcp_flows,
            max_half_open: options.max_half_open_tcp,
        })
        .with_socket_owner(dev.socket_owner());
        if let QueueRole::Multi { index, queues } = &queue {
            tcp.set_flow_owner(queues.flow_owner(*index));
        }
        let mut replies = ReplySources::new(Arc::clone(&pool), mtu, Arc::clone(&stats));
        replies.watch_with(dev.socket_watcher());
        Driver {
            dev,
            tcp,
            udp: UdpTable::new(
                udp_timeout,
                Arc::clone(&pool),
                replies.queue(),
                mtu,
                Arc::clone(&stats),
            ),
            replies,
            pool,
            stats,
            sink,
            handlers: options.tasks.clone(),
            dns: options.dns.clone(),
            dns_slots: Arc::new(Semaphore::new(DNS_CONCURRENCY)),
            fragments: Reassembler::default(),
            reassembled: Vec::new(),
            inflight: VecDeque::with_capacity(device_batch),
            rx_buf: SparseBuf::zeroed(rx_stride * RX_BATCH),
            rx_stride,
            rx_extended: false,
            rx_receive_epoch: 0,
            rx_batch: device_batch.min(RX_BATCH_START),
            options: StackOptions { mtu, ..options },
            sleep: Box::pin(tokio::time::sleep(Duration::from_secs(3600))),
            next_sweep: SWEEP_INTERVAL,
            queue,
            tcp_reported: 0,
            udp_reported: 0,
            drained: true,
        }
    }

    fn poll_run(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.pool.register_driver(cx.waker());
        self.tcp.register_waker(cx.waker());
        if let QueueRole::Multi { index, queues } = &self.queue {
            queues.register(*index, cx.waker());
        }
        let mut busy = true;
        let mut rounds = 0;
        let mut deadline = None;
        let mut replies_left = false;
        while busy && rounds < MAX_ROUNDS {
            rounds += 1;
            self.udp.set_now(self.tcp.now());
            busy = false;
            let sink = Arc::clone(&self.sink);
            let mut drained = Ok(false);
            sink.udp_round(&mut || {
                drained = self.drain_rx(cx).map(|read| self.drain_handoffs() | read);
            });
            match drained {
                Ok(read) => busy |= read,
                Err(err) => return Poll::Ready(Err(err)),
            }
            // Once a poll, after the first TUN reads, as sing-tun dispatches socket events once a
            // run loop (`stack_go_engine.go:283-298`).
            if rounds == 1 {
                replies_left = self.replies.drain();
            }
            deadline = self
                .tcp
                .poll(&mut PoolEgress::new(&self.pool, &self.dev, &self.inflight));
            self.announce();
            busy |= self.flush(cx);
            busy |= self.tcp.has_blocked() && self.pool.free_count() > 0;
        }
        let now = self.tcp.now();
        if now >= self.next_sweep {
            let now_i = i64::try_from(now).unwrap_or(i64::MAX);
            self.udp.sweep(now_i);
            report(
                &self.stats.udp_sessions,
                &mut self.udp_reported,
                self.udp.len(),
            );
            if let QueueRole::Multi { index, queues } = &self.queue {
                queues.retain(*index, |(local, remote)| self.tcp.owns(*local, *remote));
            }
            self.next_sweep = now + SWEEP_INTERVAL;
        }
        report(
            &self.stats.tcp_active,
            &mut self.tcp_reported,
            self.tcp.len(),
        );
        self.retire_rx();
        busy |= replies_left;
        self.drained = !busy;
        if busy {
            cx.waker().wake_by_ref();
        } else {
            self.arm_timer(cx, deadline);
        }
        Poll::Pending
    }

    fn arm_timer(&mut self, cx: &mut Context<'_>, deadline: Option<u64>) {
        let next = deadline.map_or(self.next_sweep, |at| at.min(self.next_sweep));
        self.sleep.as_mut().reset(self.tcp.instant_at(next));
        if self.sleep.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
    }

    fn shutdown(&mut self) {
        self.tcp.shutdown();
        self.pool.close();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test setup and assertions")]
mod owner_tests {
    use std::sync::atomic::{AtomicU8, Ordering};

    use super::*;
    use tokio::io::AsyncReadExt;

    struct Silent;
    impl Device for Silent {
        fn poll_recv(&self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
        fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }
    struct Idle;
    impl FlowSink for Idle {
        fn tcp(&self, _: concord_common::FlowKey, _: concord_common::BoxStream) {}
        fn udp(&self, _: concord_common::FlowKey, _: &[u8], _: &Arc<dyn concord_common::UdpReply>) {
        }
    }

    #[tokio::test]
    async fn unused_receive_lifetimes_release_extended_rx_but_keep_single_frame_storage() {
        let mut driver = Driver::new(
            StackOptions::default(),
            Silent,
            Arc::new(Idle),
            QueueRole::Single,
        );
        let mut previous = driver.rx_buf.as_ptr();
        for extended in [false, true, false, true] {
            let stream = driver
                .tcp
                .connect(
                    "10.0.0.1:1234".parse().unwrap(),
                    "10.0.0.2:80".parse().unwrap(),
                    concord_netstack::Congestion::Cubic,
                )
                .unwrap();
            let written = if extended { driver.rx_stride * 2 } else { 64 };
            driver.rx_buf[..written].fill(0x7b);
            driver.rx_extended = extended;
            driver.retire_rx();
            assert_eq!(
                driver.rx_buf.as_ptr(),
                previous,
                "an active receiver keeps storage"
            );
            assert_eq!(driver.rx_buf[0], 0x7b);
            driver.tcp.shutdown();
            driver.retire_rx();
            if extended {
                assert_ne!(driver.rx_buf.as_ptr(), previous);
                assert!(driver.rx_buf[..written].iter().all(|byte| *byte == 0));
            } else {
                assert_eq!(
                    driver.rx_buf.as_ptr(),
                    previous,
                    "small traffic does not remap on close"
                );
            }
            previous = driver.rx_buf.as_ptr();
            drop(stream);
        }
    }

    #[tokio::test]
    async fn cooperative_pending_keeps_the_owner_runnable_but_idle_io_can_park() {
        struct PendingDevice {
            exhaust: bool,
            stop: CancellationToken,
            observed: Arc<AtomicU8>,
        }
        impl Device for PendingDevice {
            fn poll_recv(&self, cx: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                if self.exhaust {
                    while tokio::task::coop::has_budget_remaining() {
                        match tokio::task::coop::poll_proceed(cx) {
                            Poll::Ready(budget) => budget.made_progress(),
                            Poll::Pending => break,
                        }
                    }
                    let Poll::Pending = tokio::task::coop::poll_proceed(cx) else {
                        return Poll::Ready(Err(io::Error::other("budget did not exhaust")));
                    };
                }
                Poll::Pending
            }

            fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn set_busy(&self, busy: bool) -> io::Result<bool> {
                self.observed
                    .store(if busy { 2 } else { 1 }, Ordering::Release);
                self.stop.cancel();
                Ok(false)
            }
        }
        for exhaust in [false, true] {
            let observed = Arc::new(AtomicU8::new(0));
            let stop = CancellationToken::new();
            let device = PendingDevice {
                exhaust,
                stop: stop.clone(),
                observed: Arc::clone(&observed),
            };
            let task = tokio::spawn(async move {
                let driver = Driver::new(
                    StackOptions::default(),
                    device,
                    Arc::new(Idle),
                    QueueRole::Single,
                );
                drive(driver, stop, None).await
            });
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(
                observed.load(Ordering::Acquire),
                if exhaust { 2 } else { 1 }
            );
        }
    }

    #[tokio::test]
    async fn a_full_transmit_pool_does_not_stop_reading_the_device() {
        struct Queued(std::sync::atomic::AtomicUsize);
        impl Device for Queued {
            fn poll_recv(&self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                match self
                    .0
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                        left.checked_sub(1)
                    }) {
                    Ok(_) => Poll::Ready(Ok(1)),
                    Err(_) => Poll::Pending,
                }
            }
            fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
        }
        let device = Queued(std::sync::atomic::AtomicUsize::new(5));
        let mut driver = Driver::new(
            StackOptions::default(),
            device,
            Arc::new(Idle),
            QueueRole::Single,
        );
        let mut held = Vec::new();
        driver.pool.take_up_to(&mut held, usize::MAX);
        assert_eq!(driver.pool.free_count(), 0);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(driver.drain_rx(&mut cx).unwrap());
        assert_eq!(
            driver.dev.0.load(Ordering::Relaxed),
            0,
            "the peer's ACKs are read while every transmit slot is taken"
        );
        driver.pool.give_back(&mut held, 0);
    }

    #[tokio::test]
    async fn reading_without_transmit_room_is_bounded_and_returns() {
        struct Flood(std::sync::atomic::AtomicUsize);
        impl Device for Flood {
            fn poll_recv(&self, _: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(1))
            }
            fn poll_send(&self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Pending
            }
        }
        let device = Flood(std::sync::atomic::AtomicUsize::new(0));
        let mut driver = Driver::new(
            StackOptions::default(),
            device,
            Arc::new(Idle),
            QueueRole::Single,
        );
        let mut held = Vec::new();
        driver.pool.take_up_to(&mut held, usize::MAX);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(driver.poll_run(&mut cx).is_pending());
        let reads = driver.dev.0.load(Ordering::Relaxed);
        assert!(
            (1..=RX_BATCH * MAX_ROUNDS).contains(&reads),
            "{reads} reads in one pass"
        );
        driver.pool.give_back(&mut held, 0);
    }

    #[tokio::test]
    async fn queued_writes_leave_the_cooperative_budget_room_for_reads() {
        #[derive(Default)]
        struct Busy {
            reads: std::sync::atomic::AtomicUsize,
            writes: std::sync::atomic::AtomicUsize,
        }
        impl Device for Busy {
            fn poll_recv(&self, cx: &mut Context<'_>, _: &mut [u8]) -> Poll<io::Result<usize>> {
                let budget = std::task::ready!(tokio::task::coop::poll_proceed(cx));
                budget.made_progress();
                self.reads.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(1))
            }
            fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
                let budget = std::task::ready!(tokio::task::coop::poll_proceed(cx));
                budget.made_progress();
                self.writes.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(packet.len()))
            }
        }
        let mut driver = Driver::new(
            StackOptions::default(),
            Busy::default(),
            Arc::new(Idle),
            QueueRole::Single,
        );
        let mut queued = Vec::new();
        driver.pool.take_up_to(&mut queued, usize::MAX);
        for mut slot in queued {
            slot.len = 20;
            driver.pool.push_filled(slot);
        }
        std::future::poll_fn(|cx| {
            let _ = driver.poll_run(cx);
            Poll::Ready(())
        })
        .await;
        let reads = driver.dev.reads.load(Ordering::Relaxed);
        let writes = driver.dev.writes.load(Ordering::Relaxed);
        assert!(
            reads >= RX_BATCH && writes > 0,
            "{reads} reads and {writes} writes in one pass"
        );
    }

    #[tokio::test]
    async fn a_round_answers_its_reads_after_a_mebibyte() {
        struct Upload(std::sync::atomic::AtomicUsize);
        impl Device for Upload {
            fn poll_recv(&self, _: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_send(&self, _: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(packet.len()))
            }
        }
        let device = Upload(std::sync::atomic::AtomicUsize::new(0));
        let mut driver = Driver::new(
            StackOptions::default(),
            device,
            Arc::new(Idle),
            QueueRole::Single,
        );
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(driver.drain_rx(&mut cx).unwrap());
        let reads = driver.dev.0.load(Ordering::Relaxed);
        assert!(
            reads < RX_BATCH && reads * driver.rx_stride >= ROUND_READ_BYTES,
            "{reads} reads of {} bytes in one round",
            driver.rx_stride
        );
    }

    #[tokio::test]
    async fn dropping_the_driver_closes_outstanding_connections() {
        let mut driver = Driver::new(
            StackOptions::default(),
            Silent,
            Arc::new(Idle),
            QueueRole::Single,
        );
        let mut stream = driver
            .tcp
            .connect(
                "10.0.0.1:1234".parse().unwrap(),
                "10.0.0.2:80".parse().unwrap(),
                concord_netstack::Congestion::Cubic,
            )
            .unwrap();
        drop(driver);
        let error = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }
}
