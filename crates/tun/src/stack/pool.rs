use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

use concord_common::sync::lock;
use concord_netstack::wire::L4Checksum;
use futures_util::task::AtomicWaker;

pub(crate) struct Slot {
    pub buf: Vec<u8>,
    pub len: usize,
    /// The payload size the device cuts this frame into, or 0 for a single packet.
    pub segment: u16,
}

impl Slot {
    pub fn packet(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }

    pub fn grow(&mut self, size: usize) {
        if self.buf.len() < size {
            self.buf.resize(size, 0);
        }
    }
}

struct Waiter {
    waker: Waker,
    need: usize,
}

struct PoolState {
    free: Vec<Slot>,
    filled: VecDeque<Slot>,
    waiters: VecDeque<Waiter>,
    closed: bool,
}

impl PoolState {
    /// One place per task, however often it is polled before a slot comes back.
    fn wait(&mut self, waker: &Waker, need: usize) {
        match self
            .waiters
            .iter_mut()
            .find(|waiter| waiter.waker.will_wake(waker))
        {
            Some(waiter) => waiter.need = need,
            None => self.waiters.push_back(Waiter {
                waker: waker.clone(),
                need,
            }),
        }
    }
}

/// Fixed packet buffers shared by every writer to the device: the stack's own segments,
/// UDP replies and echo replies are built in place and queued for the driver, so nothing
/// is allocated per packet.
pub(crate) struct TxPool {
    state: Mutex<PoolState>,
    driver: AtomicWaker,
    pub checksum: L4Checksum,
    pub segment_limit: AtomicUsize,
    slots: usize,
    ident: AtomicU32,
}

impl TxPool {
    pub fn new(slots: usize, slot_size: usize) -> Self {
        let free = (0..slots)
            .map(|_| Slot {
                buf: vec![0u8; slot_size],
                len: 0,
                segment: 0,
            })
            .collect();
        TxPool {
            state: Mutex::new(PoolState {
                free,
                filled: VecDeque::with_capacity(slots),
                waiters: VecDeque::new(),
                closed: false,
            }),
            driver: AtomicWaker::new(),
            checksum: L4Checksum::Full,
            segment_limit: AtomicUsize::new(0),
            slots,
            ident: AtomicU32::new(0),
        }
    }

    pub fn with_offload(mut self, checksum: L4Checksum, segment_limit: usize) -> Self {
        self.checksum = checksum;
        self.segment_limit = AtomicUsize::new(segment_limit);
        self
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        lock(&self.state)
    }

    pub fn register_driver(&self, waker: &Waker) {
        self.driver.register(waker);
    }

    pub fn free_count(&self) -> usize {
        self.lock().free.len()
    }

    pub fn take_free(&self) -> Option<Slot> {
        self.lock().free.pop()
    }

    /// `Ready(None)` once the stack has stopped.
    pub fn poll_take_free(&self, cx: &mut Context<'_>) -> Poll<Option<Slot>> {
        let mut state = self.lock();
        if state.closed {
            return Poll::Ready(None);
        }
        if let Some(slot) = state.free.pop() {
            return Poll::Ready(Some(slot));
        }
        state.wait(cx.waker(), 1);
        Poll::Pending
    }

    /// All `count` slots at once, so a datagram's fragments are never split between waiters.
    /// `Ready(None)` once the stack has stopped; `Ready(Some(empty))` when the pool can never
    /// hold that many.
    pub fn poll_take_many(&self, cx: &mut Context<'_>, count: usize) -> Poll<Option<Vec<Slot>>> {
        let mut state = self.lock();
        if state.closed {
            return Poll::Ready(None);
        }
        if count > self.slots {
            return Poll::Ready(Some(Vec::new()));
        }
        if let Some(at) = state.free.len().checked_sub(count) {
            return Poll::Ready(Some(state.free.split_off(at)));
        }
        state.wait(cx.waker(), count);
        Poll::Pending
    }

    pub fn next_ident(&self) -> u32 {
        self.ident.fetch_add(1, Ordering::Relaxed)
    }

    pub fn push_filled(&self, slot: Slot) {
        self.lock().filled.push_back(slot);
        self.driver.wake();
    }

    pub fn has_filled(&self) -> bool {
        !self.lock().filled.is_empty()
    }

    pub fn pop_filled(&self) -> Option<Slot> {
        self.lock().filled.pop_front()
    }

    pub fn wake_driver(&self) {
        self.driver.wake();
    }

    /// Moves up to `most` free slots into `into` under one lock.
    pub fn take_up_to(&self, into: &mut Vec<Slot>, most: usize) -> usize {
        let mut state = self.lock();
        if state.closed {
            return 0;
        }
        let count = state.free.len().min(most);
        let at = state.free.len() - count;
        into.extend(state.free.drain(at..));
        count
    }

    /// Queues the first `used` of `slots` for the device and frees the rest, under one lock.
    /// The caller writes the device itself, so the driver is not woken.
    pub fn give_back(&self, slots: &mut Vec<Slot>, used: usize) {
        if slots.is_empty() {
            return;
        }
        let freed = used < slots.len();
        let mut state = self.lock();
        for (index, mut slot) in slots.drain(..).enumerate() {
            if index < used {
                state.filled.push_back(slot);
            } else {
                slot.len = 0;
                slot.segment = 0;
                state.free.push(slot);
            }
        }
        if freed {
            self.wake_waiters(state);
        }
    }

    pub fn release(&self, mut slot: Slot) {
        slot.len = 0;
        slot.segment = 0;
        let mut state = self.lock();
        state.free.push(slot);
        self.wake_waiters(state);
    }

    fn wake_waiters(&self, mut state: MutexGuard<'_, PoolState>) {
        // A woken writer may never come back for its slot (its session ended); once every slot
        // is free no later release would wake the rest, so they all go.
        if state.free.len() == self.slots {
            let waiters = std::mem::take(&mut state.waiters);
            drop(state);
            waiters.into_iter().for_each(|waiter| waiter.waker.wake());
            return;
        }
        let free = state.free.len();
        let fits = state
            .waiters
            .front()
            .is_some_and(|waiter| waiter.need <= free);
        let next = if fits {
            state.waiters.pop_front()
        } else {
            None
        };
        drop(state);
        if let Some(waiter) = next {
            waiter.waker.wake();
        }
    }

    pub fn close(&self) {
        let mut state = self.lock();
        state.closed = true;
        state.filled.clear();
        let waiters = std::mem::take(&mut state.waiters);
        drop(state);
        waiters.into_iter().for_each(|waiter| waiter.waker.wake());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::task::Wake;

    use super::*;

    struct Flag(std::sync::atomic::AtomicBool);

    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_writer_waits_for_a_free_slot_and_is_woken_by_release() {
        let pool = TxPool::new(1, 64);
        let held = pool.take_free().unwrap();
        let flag = Arc::new(Flag(Default::default()));
        let waker = Waker::from(flag.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(pool.poll_take_free(&mut cx).is_pending());
        pool.release(held);
        assert!(flag.0.load(Ordering::SeqCst));
        assert!(matches!(pool.poll_take_free(&mut cx), Poll::Ready(Some(_))));
    }

    #[test]
    fn filled_slots_come_back_in_order() {
        let pool = TxPool::new(2, 8);
        for tag in [1u8, 2] {
            let mut slot = pool.take_free().unwrap();
            slot.len = 1;
            slot.buf[0] = tag;
            pool.push_filled(slot);
        }
        assert_eq!(pool.pop_filled().unwrap().packet(), &[1]);
        assert_eq!(pool.pop_filled().unwrap().packet(), &[2]);
        assert!(pool.pop_filled().is_none());
    }

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Count {
        fn get(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn task() -> (Arc<Count>, Waker) {
        let count = Arc::new(Count::default());
        let waker = Waker::from(Arc::clone(&count));
        (count, waker)
    }

    fn empty_pool(slots: usize) -> (TxPool, Vec<Slot>) {
        let pool = TxPool::new(slots, 8);
        let held = (0..slots).map(|_| pool.take_free().unwrap()).collect();
        (pool, held)
    }

    fn waits(pool: &TxPool, waker: &Waker) -> bool {
        pool.poll_take_free(&mut Context::from_waker(waker))
            .is_pending()
    }

    fn woken(tasks: &[(Arc<Count>, Waker)]) -> usize {
        tasks.iter().filter(|(count, _)| count.get() > 0).count()
    }

    #[test]
    fn replies_past_the_waiter_limit_wait_without_waking_themselves() {
        let (pool, _held) = empty_pool(1);
        let tasks: Vec<_> = (0..300).map(|_| task()).collect();
        for (_, waker) in &tasks {
            assert!(waits(&pool, waker));
        }
        let spinning = woken(&tasks);
        assert_eq!(spinning, 0, "{spinning} waiting replies woke themselves");
    }

    #[test]
    fn a_task_polled_again_keeps_one_place() {
        let (pool, mut held) = empty_pool(1);
        let (count, waker) = task();
        for _ in 0..3 {
            assert!(waits(&pool, &waker));
        }
        pool.release(held.pop().unwrap());
        assert_eq!(
            count.get(),
            1,
            "one release woke the same task several times"
        );
    }

    #[test]
    fn a_few_tasks_polled_repeatedly_leave_room_for_others() {
        let (pool, _held) = empty_pool(1);
        let few: Vec<_> = (0..4).map(|_| task()).collect();
        for _ in 0..256 {
            for (_, waker) in &few {
                assert!(waits(&pool, waker));
            }
        }
        let (late, waker) = task();
        assert!(waits(&pool, &waker));
        assert_eq!(
            late.get(),
            0,
            "a new waiter woke itself behind four busy tasks"
        );
    }

    #[test]
    fn each_released_slot_wakes_one_waiter() {
        let (pool, mut held) = empty_pool(4);
        let tasks: Vec<_> = (0..10).map(|_| task()).collect();
        for (_, waker) in &tasks {
            assert!(waits(&pool, waker));
        }
        pool.release(held.pop().unwrap());
        let first = woken(&tasks);
        assert_eq!(first, 1, "one free slot woke {first} waiters");
        pool.release(held.pop().unwrap());
        pool.release(held.pop().unwrap());
        assert_eq!(woken(&tasks), 3);
    }

    #[test]
    fn a_waiter_for_several_slots_is_woken_when_they_are_free() {
        let (pool, mut held) = empty_pool(4);
        let (count, waker) = task();
        let mut cx = Context::from_waker(&waker);
        assert!(pool.poll_take_many(&mut cx, 3).is_pending());
        pool.release(held.pop().unwrap());
        pool.release(held.pop().unwrap());
        assert_eq!(count.get(), 0, "woken while two of three slots were free");
        pool.release(held.pop().unwrap());
        assert_eq!(count.get(), 1);
        assert!(matches!(
            pool.poll_take_many(&mut cx, 3),
            Poll::Ready(Some(slots)) if slots.len() == 3
        ));
    }

    #[test]
    fn a_woken_waiter_that_never_returns_does_not_strand_the_rest() {
        let (pool, mut held) = empty_pool(1);
        let (_gone, gone) = task();
        let (live, waker) = task();
        assert!(waits(&pool, &gone));
        assert!(waits(&pool, &waker));
        pool.release(held.pop().unwrap());
        assert!(live.get() > 0, "the last free slot left a waiter parked");
    }

    #[test]
    fn closing_releases_writers_with_none() {
        let pool = TxPool::new(1, 8);
        let waker = Waker::from(Arc::new(Flag(Default::default())));
        let mut cx = Context::from_waker(&waker);
        pool.close();
        assert!(matches!(pool.poll_take_free(&mut cx), Poll::Ready(None)));
    }
}
