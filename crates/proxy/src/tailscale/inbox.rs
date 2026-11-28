use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};

use concord_common::sync::lock;
use concord_tsnet::BATCH;
use gotatun::packet::{Packet, PacketBufPool};
use tokio::sync::Notify;

/// Packets queued at most; a full queue holds the Go thread back, as a full kernel TUN would.
const QUEUED: usize = 2 * BATCH;
/// Buffers kept for reuse: a packet holds its buffer from `push` until the stack is done with
/// it, through the queue, the batch `take` swapped out, and the channel into the stack.
const POOLED: usize = 2 * QUEUED + crate::stack::OUTBOUND_QUEUE;
/// One buffer holds a packet of the node's MTU.
const BUFFER: usize = super::tunnel::MTU;

/// Packets from the tailnet on their way to the stack. `push` runs on Go threads and allocates
/// nothing: glibc gives each thread that allocates an arena of its own, and Go runs many. The
/// buffers come from a pool filled where the inbox is made, and the queue never outgrows the
/// capacity it was made with.
pub(super) struct Inbox {
    queue: Mutex<VecDeque<Packet>>,
    room: Condvar,
    ready: Notify,
    pool: PacketBufPool<BUFFER>,
    open: AtomicBool,
}

impl Inbox {
    pub(super) fn new() -> Inbox {
        Inbox {
            queue: Mutex::new(VecDeque::with_capacity(QUEUED)),
            room: Condvar::new(),
            ready: Notify::new(),
            pool: PacketBufPool::new(POOLED),
            open: AtomicBool::new(false),
        }
    }

    /// Lets packets in; before this, and after `close`, they are dropped.
    pub(super) fn open(&self) {
        self.open.store(true, Ordering::Release);
    }

    pub(super) fn close(&self) {
        self.open.store(false, Ordering::Release);
        lock(&self.queue).clear();
        self.room.notify_all();
    }

    pub(super) fn push<'p>(&self, packets: impl IntoIterator<Item = &'p [u8]>) {
        let mut queue = lock(&self.queue);
        for bytes in packets {
            while queue.len() >= QUEUED && self.open.load(Ordering::Acquire) {
                self.ready.notify_one();
                queue = self
                    .room
                    .wait(queue)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if !self.open.load(Ordering::Acquire) {
                return;
            }
            let mut packet = self.pool.get();
            let buf = packet.buf_mut();
            buf.clear();
            buf.extend_from_slice(bytes);
            queue.push_back(packet);
        }
        drop(queue);
        self.ready.notify_one();
    }

    /// Waits for packets and swaps them into `into`, which must be empty and keeps the
    /// capacity the queue needs.
    pub(super) async fn take(&self, into: &mut VecDeque<Packet>) {
        loop {
            {
                let mut queue = lock(&self.queue);
                if !queue.is_empty() {
                    std::mem::swap(&mut *queue, into);
                    break;
                }
            }
            self.ready.notified().await;
        }
        self.room.notify_all();
    }

    pub(super) fn spare() -> VecDeque<Packet> {
        VecDeque::with_capacity(QUEUED)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn packet(tag: u8) -> Vec<u8> {
        vec![tag; 60]
    }

    #[tokio::test]
    async fn packets_before_open_and_after_close_are_dropped() {
        let inbox = Inbox::new();
        inbox.push([packet(1).as_slice()]);
        assert!(lock(&inbox.queue).is_empty());
        inbox.open();
        inbox.push([packet(2).as_slice()]);
        let mut batch = Inbox::spare();
        inbox.take(&mut batch).await;
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].as_ref(), packet(2).as_slice());
        inbox.close();
        inbox.push([packet(3).as_slice()]);
        assert!(lock(&inbox.queue).is_empty());
    }

    #[tokio::test]
    async fn a_full_queue_holds_the_pusher_until_a_take() {
        let inbox = Arc::new(Inbox::new());
        inbox.open();
        let many: Vec<Vec<u8>> = (0..QUEUED + 3).map(|_| packet(4)).collect();
        let pusher = {
            let inbox = inbox.clone();
            std::thread::spawn(move || inbox.push(many.iter().map(Vec::as_slice)))
        };
        while lock(&inbox.queue).len() < QUEUED {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!pusher.is_finished(), "a full queue let the pusher past");
        let mut batch = Inbox::spare();
        inbox.take(&mut batch).await;
        assert_eq!(batch.len(), QUEUED);
        pusher.join().unwrap();
        batch.clear();
        inbox.take(&mut batch).await;
        assert_eq!(batch.len(), 3);
    }

    #[tokio::test]
    async fn close_releases_a_held_pusher() {
        let inbox = Arc::new(Inbox::new());
        inbox.open();
        let many: Vec<Vec<u8>> = (0..QUEUED + 1).map(|_| packet(5)).collect();
        let pusher = {
            let inbox = inbox.clone();
            std::thread::spawn(move || inbox.push(many.iter().map(Vec::as_slice)))
        };
        while lock(&inbox.queue).len() < QUEUED {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        inbox.close();
        pusher.join().unwrap();
    }

    #[tokio::test]
    async fn packets_reuse_the_buffers_made_with_the_inbox() {
        let inbox = Inbox::new();
        inbox.open();
        let data = packet(6);
        let mut batch = Inbox::spare();
        let mut buffers = std::collections::HashSet::new();
        for _ in 0..POOLED / BATCH + 2 {
            inbox.push((0..BATCH).map(|_| data.as_slice()));
            inbox.take(&mut batch).await;
            assert_eq!(batch.len(), BATCH);
            buffers.extend(batch.iter().map(|packet| packet.as_ref().as_ptr().addr()));
            batch.clear();
        }
        assert_eq!(buffers.len(), POOLED);
    }
}
