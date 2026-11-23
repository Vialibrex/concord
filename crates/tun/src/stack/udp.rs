use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};

use concord_common::{Address, ReplySource, UdpReply};

use super::pool::TxPool;
use super::replies::ReplyQueue;
use super::reply_packet::ReplyPacket;
use super::stats::StackStats;

const TABLE_LIMIT: usize = 65_536;

#[derive(Default)]
pub(crate) struct FxHasher(u64);

impl Hasher for FxHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            if let Some(head) = word.get_mut(..chunk.len()) {
                head.copy_from_slice(chunk);
            }
            self.write_u64(u64::from_le_bytes(word));
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(0x517c_c1b7_2722_0a95);
    }

    fn write_u8(&mut self, value: u8) {
        self.write_u64(u64::from(value));
    }

    fn write_u16(&mut self, value: u16) {
        self.write_u64(u64::from(value));
    }

    fn write_u32(&mut self, value: u32) {
        self.write_u64(u64::from(value));
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }
}

pub(crate) type FxBuild = BuildHasherDefault<FxHasher>;

/// Writes datagrams back to one local UDP source as IP packets from whatever address the
/// application sent to.
pub(crate) struct UdpReplyHandle {
    local: SocketAddr,
    pool: Arc<TxPool>,
    replies: Weak<ReplyQueue>,
    mtu: usize,
    stats: Arc<StackStats>,
}

impl UdpReply for UdpReplyHandle {
    fn poll_write_back(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        from: &Address,
    ) -> Poll<io::Result<()>> {
        let reply = ReplyPacket::new(payload, from, self.local)?;
        if reply.len() > self.mtu {
            return self.poll_write_fragments(cx, &reply);
        }
        let mut slot = match self.pool.poll_take_free(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            Poll::Ready(Some(slot)) => slot,
        };
        match reply.write(&mut slot, self.pool.checksum) {
            Ok(()) => {
                self.pool.push_filled(slot);
                self.stats.udp_replies.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                self.pool.release(slot);
                Poll::Ready(Err(error))
            }
        }
    }

    /// The source stays with this queue's driver even when the session's later uploads come
    /// from another queue, as a sing-tun flow belongs to one engine (`stack_go_engine.go:712-716`).
    fn adopt(&self, source: Arc<dyn ReplySource>) -> Result<(), Arc<dyn ReplySource>> {
        match self.replies.upgrade() {
            Some(queue) => {
                queue.adopt(self.local, source);
                Ok(())
            }
            None => Err(source),
        }
    }
}

impl UdpReplyHandle {
    fn poll_write_fragments(
        &self,
        cx: &mut Context<'_>,
        reply: &ReplyPacket<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(fragments) = reply.fragments(self.mtu)? else {
            self.stats.udp_oversize.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(()));
        };
        let mut slots = match self.pool.poll_take_many(cx, fragments.count) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            Poll::Ready(Some(slots)) => slots,
        };
        if slots.is_empty() {
            self.stats.udp_oversize.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(()));
        }
        if let Err(error) = fragments.write(&mut slots, self.pool.next_ident()) {
            for slot in slots {
                self.pool.release(slot);
            }
            return Poll::Ready(Err(error));
        }
        for slot in slots {
            self.pool.push_filled(slot);
        }
        self.stats.udp_replies.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

struct Entry {
    reply: Arc<dyn UdpReply>,
    last_active: i64,
}

pub(crate) struct UdpTable {
    entries: HashMap<SocketAddr, Entry, FxBuild>,
    timeout_micros: i64,
    /// Set once a driver round: a flow's last use only needs the sweep's precision.
    now: i64,
    pool: Arc<TxPool>,
    replies: Weak<ReplyQueue>,
    mtu: usize,
    stats: Arc<StackStats>,
}

impl UdpTable {
    pub fn new(
        timeout_micros: i64,
        pool: Arc<TxPool>,
        replies: Weak<ReplyQueue>,
        mtu: usize,
        stats: Arc<StackStats>,
    ) -> Self {
        UdpTable {
            entries: HashMap::with_capacity_and_hasher(256, FxBuild::default()),
            timeout_micros,
            now: 0,
            pool,
            replies,
            mtu,
            stats,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn set_now(&mut self, now: u64) {
        self.now = i64::try_from(now).unwrap_or(i64::MAX);
    }

    /// Owned only when the table is full and the handle is not kept.
    pub fn reply_for(&mut self, local: SocketAddr) -> Cow<'_, Arc<dyn UdpReply>> {
        let now = self.now;
        if self.entries.len() >= TABLE_LIMIT && !self.entries.contains_key(&local) {
            self.sweep(now);
        }
        let full = self.entries.len() >= TABLE_LIMIT;
        let (pool, replies, mtu, stats) = (&self.pool, &self.replies, self.mtu, &self.stats);
        let new = || -> Arc<dyn UdpReply> {
            Arc::new(UdpReplyHandle {
                local,
                pool: Arc::clone(pool),
                replies: Weak::clone(replies),
                mtu,
                stats: Arc::clone(stats),
            })
        };
        if full && !self.entries.contains_key(&local) {
            return Cow::Owned(new());
        }
        let entry = self.entries.entry(local).or_insert_with(|| Entry {
            reply: new(),
            last_active: now,
        });
        entry.last_active = now;
        Cow::Borrowed(&entry.reply)
    }

    pub fn sweep(&mut self, now: i64) {
        let cutoff = now - self.timeout_micros;
        self.entries.retain(|_, entry| entry.last_active >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use std::task::Waker;

    use super::*;
    use concord_netstack::wire::{parse_ip, parse_udp};

    fn table(slots: usize) -> (UdpTable, Arc<TxPool>) {
        let pool = Arc::new(TxPool::new(slots, 256));
        let table = UdpTable::new(
            1_000_000,
            Arc::clone(&pool),
            Weak::new(),
            256,
            Arc::default(),
        );
        (table, pool)
    }

    fn write(reply: &dyn UdpReply, payload: &[u8], from: &Address) -> Poll<io::Result<()>> {
        let mut cx = Context::from_waker(Waker::noop());
        reply.poll_write_back(&mut cx, payload, from)
    }

    #[test]
    fn replies_spoof_the_address_the_application_sent_to() {
        let (mut table, pool) = table(2);
        let local: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let reply = table.reply_for(local).into_owned();
        let from = Address::Socket("8.8.8.8:53".parse().unwrap());
        assert!(matches!(
            write(&*reply, b"answer", &from),
            Poll::Ready(Ok(()))
        ));
        let slot = pool.pop_filled().unwrap();
        let view = parse_ip(slot.packet()).unwrap();
        assert_eq!(view.src, "8.8.8.8".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(view.dst, local.ip());
        let udp = parse_udp(&view).unwrap();
        assert_eq!((udp.src_port, udp.dst_port), (53, 5000));
        assert_eq!(udp.payload, b"answer");
    }

    #[test]
    fn wrong_family_domains_and_oversize_are_handled() {
        let (mut table, pool) = table(2);
        let reply = table
            .reply_for("10.0.0.2:5000".parse().unwrap())
            .into_owned();
        let v6 = Address::Socket("[::1]:53".parse().unwrap());
        assert!(matches!(write(&*reply, b"x", &v6), Poll::Ready(Err(_))));
        let domain = Address::Domain("example.com".into(), 53);
        assert!(matches!(write(&*reply, b"x", &domain), Poll::Ready(Err(_))));
        let from = Address::Socket("8.8.8.8:53".parse().unwrap());
        let huge = vec![0u8; 70_000];
        assert!(matches!(write(&*reply, &huge, &from), Poll::Ready(Err(_))));
        assert!(pool.pop_filled().is_none());
    }

    #[test]
    fn an_oversize_reply_goes_out_as_fragments_that_reassemble() {
        let (mut table, pool) = table(8);
        let reply = table
            .reply_for("10.0.0.2:5000".parse().unwrap())
            .into_owned();
        let from = Address::Socket("8.8.8.8:53".parse().unwrap());
        let payload: Vec<u8> = (0..600).map(|i| i as u8).collect();
        assert!(matches!(
            write(&*reply, &payload, &from),
            Poll::Ready(Ok(()))
        ));
        let mut reassembler = concord_netstack::frag::Reassembler::default();
        let mut whole = Vec::new();
        let mut count = 0;
        while let Some(slot) = pool.pop_filled() {
            assert!(slot.len <= 256);
            let Ok(concord_netstack::wire::Parsed::Fragment(view)) =
                concord_netstack::wire::parse_packet(slot.packet())
            else {
                panic!("expected a fragment");
            };
            reassembler.push(&view, 0, &mut whole);
            count += 1;
        }
        assert_eq!(count, 3);
        let view = parse_ip(&whole).unwrap();
        assert_eq!(parse_udp(&view).unwrap().payload, &payload[..]);
        assert_eq!(table.stats.udp_replies.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fragments_wait_for_enough_free_slots_and_a_pool_too_small_counts_oversize() {
        let from = Address::Socket("8.8.8.8:53".parse().unwrap());
        let (mut tiny, pool) = table(1);
        let reply = tiny
            .reply_for("10.0.0.2:5000".parse().unwrap())
            .into_owned();
        assert!(matches!(
            write(&*reply, &[0; 300], &from),
            Poll::Ready(Ok(()))
        ));
        assert!(pool.pop_filled().is_none());
        assert_eq!(tiny.stats.udp_oversize.load(Ordering::Relaxed), 1);

        let (mut small, pool) = table(3);
        let reply = small
            .reply_for("10.0.0.2:5000".parse().unwrap())
            .into_owned();
        let held = (pool.take_free().unwrap(), pool.take_free().unwrap());
        assert!(write(&*reply, &[0; 300], &from).is_pending());
        pool.release(held.0);
        assert!(matches!(
            write(&*reply, &[0; 300], &from),
            Poll::Ready(Ok(()))
        ));
        pool.release(held.1);
    }

    #[test]
    fn a_full_pool_applies_backpressure() {
        let (mut table, pool) = table(1);
        let reply = table
            .reply_for("10.0.0.2:5000".parse().unwrap())
            .into_owned();
        let from = Address::Socket("8.8.8.8:53".parse().unwrap());
        assert!(matches!(write(&*reply, b"a", &from), Poll::Ready(Ok(()))));
        assert!(write(&*reply, b"b", &from).is_pending());
        let slot = pool.pop_filled().unwrap();
        pool.release(slot);
        assert!(matches!(write(&*reply, b"b", &from), Poll::Ready(Ok(()))));
    }

    #[test]
    fn handles_are_cached_per_source_and_swept_when_idle() {
        let (mut table, _pool) = table(1);
        let local: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let first = table.reply_for(local).into_owned();
        table.set_now(1_500_000);
        let second = table.reply_for(local).into_owned();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(table.len(), 1);
        table.sweep(2_000_000);
        assert_eq!(table.len(), 1);
        table.sweep(3_000_000);
        assert_eq!(table.len(), 0);
    }
}
