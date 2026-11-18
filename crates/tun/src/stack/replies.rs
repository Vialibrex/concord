//! UDP sessions whose replies the driver receives and writes itself, as sing-tun's engine
//! polls each flow's socket from its own loop (`stack_go_splice.go:842-909`): a ready source
//! wakes the driver once, not once a datagram, and its replies go straight into pool slots.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Wake, Waker};

use concord_common::packet::RECV_MAX;
use concord_common::sync::lock;
use concord_common::{Address, Replies, ReplyOut, ReplySource, SocketWatcher};
use concord_netstack::wire::{
    L4Checksum, UDP_HEADER, build_udp, fragment_count, ip_header_len, write_fragment,
};

use super::pool::{Slot, TxPool};
use super::stats::StackStats;

/// What other threads hand the driver: newly adopted sources and the ones that became ready.
pub(crate) struct ReplyQueue {
    pending: Mutex<Pending>,
    pool: Arc<TxPool>,
}

#[derive(Default)]
struct Pending {
    adopted: Vec<(SocketAddr, Arc<dyn ReplySource>)>,
    ready: Vec<usize>,
}

impl ReplyQueue {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        lock(&self.pending)
    }

    /// `local` is the client the source's replies go to.
    pub(crate) fn adopt(&self, local: SocketAddr, source: Arc<dyn ReplySource>) {
        self.lock().adopted.push((local, source));
        self.pool.wake_driver();
    }
}

/// Wakes the driver for one source, once until the driver polls it again.
struct Wakeup {
    index: usize,
    queued: AtomicBool,
    queue: Weak<ReplyQueue>,
}

impl Wake for Wakeup {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(queue) = self.queue.upgrade() {
            queue.lock().ready.push(self.index);
            queue.pool.wake_driver();
        }
    }
}

struct Source {
    source: Arc<dyn ReplySource>,
    local: SocketAddr,
    ready: Arc<Wakeup>,
    waker: Waker,
}

/// The driver's side: each source in turn, one batch at a time, while the pool has room.
pub(crate) struct ReplySources {
    queue: Arc<ReplyQueue>,
    sources: Vec<Option<Source>>,
    vacant: Vec<usize>,
    order: VecDeque<usize>,
    /// Swapped with the queue's lists under its lock, so taking them keeps both allocations.
    taken: Pending,
    slots: Vec<Slot>,
    mtu: usize,
    stats: Arc<StackStats>,
    watcher: Option<Arc<dyn SocketWatcher + Send + Sync>>,
}

impl ReplySources {
    pub(crate) fn new(pool: Arc<TxPool>, mtu: usize, stats: Arc<StackStats>) -> Self {
        ReplySources {
            queue: Arc::new(ReplyQueue {
                pending: Mutex::default(),
                pool,
            }),
            sources: Vec::new(),
            vacant: Vec::new(),
            order: VecDeque::new(),
            taken: Pending::default(),
            slots: Vec::with_capacity(RECV_MAX),
            mtu,
            stats,
            watcher: None,
        }
    }

    /// Adopted sources are offered the queue poller, as sing-tun registers each flow's socket
    /// in its queue's own epoll (`stack_go_io_linux.go:230`).
    pub(crate) fn watch_with(&mut self, watcher: Option<Arc<dyn SocketWatcher + Send + Sync>>) {
        self.watcher = watcher;
    }

    /// Reply handles hold this weakly, so a session that outlives the driver adopts nothing.
    pub(crate) fn queue(&self) -> Weak<ReplyQueue> {
        Arc::downgrade(&self.queue)
    }

    /// Serves each ready source once, in the order they became ready; true when one filled its
    /// slots and may have more. Sources the pool has no room for wait, and their datagrams stay
    /// in the socket.
    pub(crate) fn drain(&mut self) -> bool {
        self.take_pending();
        let pool = Arc::clone(&self.queue.pool);
        let mut more = false;
        for _ in 0..self.order.len() {
            let Some(index) = self.order.pop_front() else {
                break;
            };
            let Some(Some(entry)) = self.sources.get(index) else {
                continue;
            };
            if pool.take_up_to(&mut self.slots, RECV_MAX) == 0 {
                self.order.push_front(index);
                break;
            }
            entry.ready.queued.store(false, Ordering::Release);
            let mut out = SlotOut {
                slots: &mut self.slots,
                used: 0,
                local: entry.local,
                mtu: self.mtu,
                checksum: pool.checksum,
                pool: &pool,
                stats: &self.stats,
            };
            let polled = entry
                .source
                .poll_replies(&mut Context::from_waker(&entry.waker), &mut out);
            let used = out.used;
            pool.give_back(&mut self.slots, used);
            match polled {
                Poll::Ready(Replies::Received) => {
                    if !entry.ready.queued.swap(true, Ordering::AcqRel) {
                        self.order.push_back(index);
                    }
                    more = true;
                }
                Poll::Ready(Replies::Ended) => {
                    // The socket may still hold this waker; left unqueued, a late wake would
                    // queue the index again after another source took it.
                    entry.ready.queued.store(true, Ordering::Release);
                    self.remove(index);
                }
                Poll::Ready(Replies::Drained) | Poll::Pending => {}
            }
        }
        more
    }

    /// Polls every source again: when the queue's sockets move between its poller and Tokio's
    /// reactor, a waker left with the old one is never woken.
    pub(crate) fn requeue(&mut self) {
        for (index, entry) in self.sources.iter().enumerate() {
            if let Some(entry) = entry
                && !entry.ready.queued.swap(true, Ordering::AcqRel)
            {
                self.order.push_back(index);
            }
        }
    }

    fn take_pending(&mut self) {
        {
            let mut pending = self.queue.lock();
            std::mem::swap(&mut pending.ready, &mut self.taken.ready);
            std::mem::swap(&mut pending.adopted, &mut self.taken.adopted);
        }
        self.order.extend(self.taken.ready.drain(..));
        let mut adopted = std::mem::take(&mut self.taken.adopted);
        for (local, source) in adopted.drain(..) {
            if let Some(watcher) = &self.watcher {
                source.watch(&**watcher);
            }
            let index = self.vacant.pop().unwrap_or(self.sources.len());
            let ready = Arc::new(Wakeup {
                index,
                queued: AtomicBool::new(true),
                queue: Arc::downgrade(&self.queue),
            });
            let entry = Source {
                source,
                local,
                waker: Waker::from(Arc::clone(&ready)),
                ready,
            };
            match self.sources.get_mut(index) {
                Some(vacant) => *vacant = Some(entry),
                None => self.sources.push(Some(entry)),
            }
            self.order.push_back(index);
        }
        self.taken.adopted = adopted;
    }

    fn remove(&mut self, index: usize) {
        if let Some(entry) = self.sources.get_mut(index)
            && entry.take().is_some()
        {
            self.vacant.push(index);
        }
    }
}

/// Builds each reply in the next of the slots taken for this batch.
struct SlotOut<'a> {
    slots: &'a mut Vec<Slot>,
    used: usize,
    local: SocketAddr,
    mtu: usize,
    checksum: L4Checksum,
    pool: &'a TxPool,
    stats: &'a StackStats,
}

impl ReplyOut for SlotOut<'_> {
    fn room(&self) -> usize {
        self.slots.len() - self.used
    }

    fn put(&mut self, payload: &[u8], from: &Address) -> io::Result<()> {
        let Address::Socket(from) = *from else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a reply needs an IP source address",
            ));
        };
        if payload.len() + ip_header_len(self.local.ip()) + UDP_HEADER > self.mtu {
            return self.put_fragments(payload, from);
        }
        let Some(slot) = self.slots.get_mut(self.used) else {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        };
        let len = build_udp(&mut slot.buf, from, self.local, payload, self.checksum)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        slot.len = len;
        self.used += 1;
        self.stats.udp_replies.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

impl SlotOut<'_> {
    /// A reply past the MTU needs several slots; without them here it is dropped, as one the
    /// pool could never hold is.
    fn put_fragments(&mut self, payload: &[u8], from: SocketAddr) -> io::Result<()> {
        let mut whole = vec![0u8; ip_header_len(self.local.ip()) + UDP_HEADER + payload.len()];
        let len = build_udp(&mut whole, from, self.local, payload, L4Checksum::Full)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        whole.truncate(len);
        let count = fragment_count(&whole, self.mtu).unwrap_or(usize::MAX);
        let Some(slots) = self
            .slots
            .get_mut(self.used..self.used.saturating_add(count))
        else {
            self.stats.udp_oversize.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        };
        let ident = self.pool.next_ident();
        for (index, slot) in slots.iter_mut().enumerate() {
            slot.len = write_fragment(&whole, self.mtu, ident, index, &mut slot.buf)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        }
        self.used += count;
        self.stats.udp_replies.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use concord_netstack::wire::{parse_ip, parse_udp};

    use super::*;
    use crate::stack::udp::UdpTable;

    /// Puts as many datagrams as it is given room for, or waits, or ends.
    #[derive(Default)]
    struct Fake {
        polls: AtomicUsize,
        watched: AtomicUsize,
        waits: AtomicBool,
        /// Puts its script and reports the socket empty.
        drains: AtomicBool,
        ends: AtomicBool,
        waker: Mutex<Option<Waker>>,
        /// Payloads to put in order; when empty and not waiting, it fills `room` with one byte.
        script: Mutex<VecDeque<Vec<u8>>>,
    }

    impl ReplySource for Fake {
        fn poll_replies(&self, cx: &mut Context<'_>, out: &mut dyn ReplyOut) -> Poll<Replies> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            if self.ends.load(Ordering::SeqCst) {
                return Poll::Ready(Replies::Ended);
            }
            if self.waits.load(Ordering::SeqCst) {
                *lock(&self.waker) = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let from = Address::Socket("1.1.1.1:53".parse().unwrap());
            let mut script = lock(&self.script);
            if script.is_empty() {
                for _ in 0..out.room() {
                    out.put(&[0], &from).unwrap();
                }
            }
            while out.room() > 0
                && let Some(payload) = script.pop_front()
            {
                out.put(&payload, &from).unwrap();
            }
            if self.drains.load(Ordering::SeqCst) {
                *lock(&self.waker) = Some(cx.waker().clone());
                return Poll::Ready(Replies::Drained);
            }
            Poll::Ready(Replies::Received)
        }

        fn watch(&self, _watcher: &dyn SocketWatcher) {
            self.watched.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct Unused;

    impl SocketWatcher for Unused {
        fn watch(
            &self,
            _socket: Arc<std::net::UdpSocket>,
        ) -> io::Result<Arc<dyn concord_common::SocketWatch>> {
            Err(io::Error::other("unused"))
        }
    }

    fn watched(fakes: &[Arc<Fake>]) -> Vec<usize> {
        fakes
            .iter()
            .map(|fake| fake.watched.load(Ordering::SeqCst))
            .collect()
    }

    fn sources(slots: usize) -> (ReplySources, Arc<TxPool>) {
        let pool = Arc::new(TxPool::new(slots, 256));
        (
            ReplySources::new(Arc::clone(&pool), 256, Arc::default()),
            pool,
        )
    }

    fn local() -> SocketAddr {
        "10.0.0.2:5000".parse().unwrap()
    }

    fn adopt(replies: &ReplySources, count: usize) -> Vec<Arc<Fake>> {
        (0..count)
            .map(|_| {
                let fake = Arc::new(Fake::default());
                replies.queue.adopt(local(), fake.clone());
                fake
            })
            .collect()
    }

    fn written(pool: &TxPool) -> usize {
        let mut count = 0;
        while let Some(slot) = pool.pop_filled() {
            pool.release(slot);
            count += 1;
        }
        count
    }

    fn polls(fakes: &[Arc<Fake>]) -> Vec<usize> {
        fakes
            .iter()
            .map(|fake| fake.polls.load(Ordering::SeqCst))
            .collect()
    }

    #[test]
    fn each_adopted_source_is_offered_the_queue_s_watcher_once() {
        let (mut replies, _pool) = sources(40);
        replies.watch_with(Some(Arc::new(Unused)));
        let fakes = adopt(&replies, 2);

        replies.drain();
        replies.drain();

        assert_eq!(watched(&fakes), [1, 1]);
    }

    #[test]
    fn a_queue_without_a_watcher_leaves_its_sources_where_they_are() {
        let (mut replies, _pool) = sources(40);
        let fakes = adopt(&replies, 2);

        replies.drain();

        assert_eq!(watched(&fakes), [0, 0]);
    }

    #[test]
    fn requeueing_polls_every_source_again() {
        let (mut replies, _pool) = sources(40);
        let fakes = adopt(&replies, 3);
        for fake in &fakes {
            fake.waits.store(true, Ordering::SeqCst);
        }
        replies.drain();
        replies.drain();
        assert_eq!(polls(&fakes), [1; 3]);

        replies.requeue();
        replies.drain();

        assert_eq!(polls(&fakes), [2; 3]);
    }

    #[test]
    fn ready_sources_take_turns_while_the_pool_has_room() {
        let (mut replies, pool) = sources(40);
        let fakes = adopt(&replies, 6);
        for _ in 0..12 {
            assert!(replies.drain());
            assert_eq!(written(&pool), 40, "a batch of 32, then the 8 left");
        }
        assert_eq!(polls(&fakes), [4; 6]);
    }

    #[test]
    fn a_full_pool_polls_nobody_until_slots_come_back() {
        let (mut replies, pool) = sources(16);
        let fakes = adopt(&replies, 3);
        let mut held = Vec::new();
        pool.take_up_to(&mut held, usize::MAX);
        for _ in 0..100 {
            assert!(!replies.drain());
        }
        assert_eq!(polls(&fakes), [0; 3]);
        pool.give_back(&mut held, 0);
        assert!(replies.drain());
        assert_eq!(
            polls(&fakes),
            [1, 0, 0],
            "16 slots less 2 kept free make one batch"
        );
    }

    #[test]
    fn a_waiting_source_is_polled_once_per_wake() {
        let (mut replies, _pool) = sources(16);
        let fakes = adopt(&replies, 1);
        fakes[0].waits.store(true, Ordering::SeqCst);
        assert!(!replies.drain());
        assert!(!replies.drain());
        assert_eq!(polls(&fakes), [1]);
        let waker = lock(&fakes[0].waker).take().unwrap();
        waker.wake_by_ref();
        waker.wake();
        assert!(!replies.drain());
        assert!(!replies.drain());
        assert_eq!(polls(&fakes), [2]);
    }

    #[test]
    fn a_source_that_emptied_its_socket_leaves_nothing_to_come_back_for() {
        let (mut replies, pool) = sources(16);
        let fakes = adopt(&replies, 1);
        fakes[0].drains.store(true, Ordering::SeqCst);
        lock(&fakes[0].script).push_back(vec![7]);
        assert!(!replies.drain(), "nothing left: the driver is not busy");
        assert_eq!(written(&pool), 1);
        assert!(!replies.drain());
        assert_eq!(polls(&fakes), [1]);
        lock(&fakes[0].script).push_back(vec![8]);
        lock(&fakes[0].waker).take().unwrap().wake();
        assert!(!replies.drain());
        assert_eq!(polls(&fakes), [2]);
        assert_eq!(written(&pool), 1);
    }

    #[test]
    fn an_ended_source_is_dropped_and_its_place_reused() {
        let (mut replies, _pool) = sources(16);
        let fakes = adopt(&replies, 1);
        fakes[0].ends.store(true, Ordering::SeqCst);
        assert!(!replies.drain());
        assert_eq!(Arc::strong_count(&fakes[0]), 1);
        let next = adopt(&replies, 1);
        next[0].waits.store(true, Ordering::SeqCst);
        replies.drain();
        assert_eq!(replies.sources.len(), 1);
        assert_eq!(polls(&next), [1]);
    }

    #[test]
    fn a_late_wake_of_an_ended_source_does_not_reach_the_one_in_its_place() {
        let (mut replies, _pool) = sources(16);
        let ended = adopt(&replies, 1);
        ended[0].waits.store(true, Ordering::SeqCst);
        replies.drain();
        let stale = lock(&ended[0].waker).take().unwrap();
        ended[0].ends.store(true, Ordering::SeqCst);
        stale.wake_by_ref();
        replies.drain();
        let next = adopt(&replies, 1);
        next[0].waits.store(true, Ordering::SeqCst);
        replies.drain();
        assert_eq!(replies.sources.len(), 1);
        stale.wake();
        replies.drain();
        assert_eq!(polls(&next), [1]);
    }

    #[test]
    fn replies_go_out_in_order_to_the_client_from_the_address_it_sent_to() {
        let (mut replies, pool) = sources(16);
        let fakes = adopt(&replies, 1);
        lock(&fakes[0].script).extend([b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);
        replies.drain();
        for want in [&b"one"[..], b"two", b"three"] {
            let slot = pool.pop_filled().unwrap();
            let view = parse_ip(slot.packet()).unwrap();
            let udp = parse_udp(&view).unwrap();
            assert_eq!(view.dst, local().ip());
            assert_eq!(view.src, "1.1.1.1".parse::<std::net::IpAddr>().unwrap());
            assert_eq!((udp.src_port, udp.dst_port), (53, 5000));
            assert_eq!(udp.payload, want);
            pool.release(slot);
        }
        assert_eq!(pool.free_count(), 16);
    }

    #[test]
    fn a_source_stays_with_the_queue_that_adopted_it() {
        let (mut first, _) = sources(16);
        let (mut second, second_pool) = sources(16);
        let mut table = UdpTable::new(
            1_000_000,
            Arc::clone(&second_pool),
            first.queue(),
            256,
            Arc::default(),
        );
        let fake = Arc::new(Fake::default());
        fake.waits.store(true, Ordering::SeqCst);
        assert!(table.reply_for(local()).adopt(fake.clone()).is_ok());
        second.drain();
        assert_eq!(fake.polls.load(Ordering::SeqCst), 0);
        first.drain();
        assert_eq!(fake.polls.load(Ordering::SeqCst), 1);
        drop(first);
        let refused = table
            .reply_for("10.0.0.3:5000".parse().unwrap())
            .adopt(fake.clone());
        assert!(refused.is_err(), "a stopped driver adopts nothing");
    }
}
