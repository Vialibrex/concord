use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use concord_common::Address;
use concord_common::sync::lock;
use tokio::sync::mpsc;

/// sing-quic's received-message queue per UDP session, dropping when full.
const QUEUE: usize = 64;
/// How long the fragments of one datagram wait for the rest.
const DEFRAG_TTL: Duration = Duration::from_secs(10);

/// One piece of a relayed datagram. `addr` is read from the first piece only.
pub struct Fragment<A> {
    pub packet: u16,
    pub index: u8,
    pub total: u8,
    pub addr: Option<A>,
    pub data: Bytes,
}

struct Pending<A> {
    pieces: Vec<Option<Bytes>>,
    count: usize,
    addr: Option<A>,
    touched: Instant,
}

/// Puts the fragments of one session's datagrams back together, as sing-quic's
/// `udpDefragger` does for Hysteria2 and TUIC.
pub struct Defrag<A> {
    pending: HashMap<u16, Pending<A>>,
    /// Expired entries are swept once the map doubles, so a sweep costs O(1) per feed.
    sweep_at: usize,
}

impl<A> Default for Defrag<A> {
    fn default() -> Self {
        Defrag {
            pending: HashMap::new(),
            sweep_at: 0,
        }
    }
}

impl<A> Defrag<A> {
    pub fn feed(&mut self, part: Fragment<A>) -> Option<(A, Bytes)> {
        if part.total <= 1 {
            return part.addr.map(|addr| (addr, part.data));
        }
        if part.index >= part.total {
            return None;
        }
        let now = Instant::now();
        if self.pending.len() >= self.sweep_at {
            self.pending
                .retain(|_, entry| now.duration_since(entry.touched) < DEFRAG_TTL);
            self.sweep_at = 2 * self.pending.len();
        }
        let total = usize::from(part.total);
        let fresh = || Pending {
            pieces: vec![None; total],
            count: 0,
            addr: None,
            touched: now,
        };
        let entry = self.pending.entry(part.packet).or_insert_with(fresh);
        if entry.pieces.len() != total || now.duration_since(entry.touched) > DEFRAG_TTL {
            *entry = fresh();
        }
        entry.touched = now;
        let slot = entry.pieces.get_mut(usize::from(part.index))?;
        if slot.is_some() {
            return None;
        }
        if part.index == 0 {
            entry.addr = part.addr;
        }
        *slot = Some(part.data);
        entry.count += 1;
        if entry.count < total {
            return None;
        }
        let done = self.pending.remove(&part.packet)?;
        let size = done.pieces.iter().flatten().map(Bytes::len).sum();
        if size == 0 {
            return None;
        }
        let mut whole = Vec::with_capacity(size);
        for piece in done.pieces.iter().flatten() {
            whole.extend_from_slice(piece);
        }
        done.addr.map(|addr| (addr, Bytes::from(whole)))
    }
}

pub type Inbox = mpsc::Receiver<(Address, Bytes)>;

struct Entry<A> {
    queue: mpsc::Sender<(Address, Bytes)>,
    defrag: Mutex<Defrag<A>>,
}

/// The UDP sessions of one connection, each with its queue of received datagrams.
pub struct Sessions<A> {
    entries: Mutex<HashMap<u32, Arc<Entry<A>>>>,
}

impl<A> Default for Sessions<A> {
    fn default() -> Self {
        Sessions {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<A> Sessions<A> {
    /// Opens a session under the id `pick` returns; `pick` is told which ids are taken.
    pub fn register(
        &self,
        pick: impl FnOnce(&dyn Fn(u32) -> bool) -> Option<u32>,
    ) -> Option<(u32, Inbox)> {
        let mut entries = lock(&self.entries);
        let id = pick(&|id| entries.contains_key(&id))?;
        let (queue, inbox) = mpsc::channel(QUEUE);
        entries.insert(
            id,
            Arc::new(Entry {
                queue,
                defrag: Mutex::new(Defrag::default()),
            }),
        );
        Some((id, inbox))
    }

    pub fn remove(&self, id: u32) {
        lock(&self.entries).remove(&id);
    }

    pub fn clear(&self) {
        lock(&self.entries).clear();
    }

    /// Hands a datagram to session `id` once its fragments are complete and `resolve` reads
    /// its address.
    pub fn deliver(&self, id: u32, part: Fragment<A>, resolve: impl FnOnce(A) -> Option<Address>) {
        let Some(entry) = lock(&self.entries).get(&id).cloned() else {
            return;
        };
        let Some((addr, data)) = lock(&entry.defrag).feed(part) else {
            return;
        };
        if let Some(addr) = resolve(addr) {
            let _ = entry.queue.try_send((addr, data));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piece(
        index: u8,
        total: u8,
        addr: Option<&'static str>,
        data: &'static [u8],
    ) -> Fragment<&'static str> {
        Fragment {
            packet: 9,
            index,
            total,
            addr,
            data: Bytes::from_static(data),
        }
    }

    #[test]
    fn fragments_join_in_any_order_and_the_first_names_the_address() {
        let mut defrag = Defrag::default();
        assert!(defrag.feed(piece(2, 3, Some("c"), b"cc")).is_none());
        assert!(defrag.feed(piece(1, 3, None, b"bb")).is_none());
        assert!(defrag.feed(piece(2, 3, Some("z"), b"zz")).is_none());
        let (addr, whole) = defrag.feed(piece(0, 3, Some("a"), b"aa")).unwrap();
        assert_eq!(addr, "a");
        assert_eq!(&whole[..], b"aabbcc");
    }

    #[test]
    fn an_unfragmented_datagram_passes_through_and_a_stray_index_is_dropped() {
        let mut defrag = Defrag::default();
        let (_, data) = defrag.feed(piece(0, 1, Some("a"), b"x")).unwrap();
        assert_eq!(&data[..], b"x");
        assert!(defrag.feed(piece(0, 1, None, b"x")).is_none());
        assert!(defrag.feed(piece(5, 2, Some("a"), b"x")).is_none());
    }

    #[test]
    fn a_datagram_whose_fragments_are_all_empty_is_dropped() {
        let mut defrag = Defrag::default();
        assert!(defrag.feed(piece(0, 2, Some("a"), b"")).is_none());
        assert!(defrag.feed(piece(1, 2, None, b"")).is_none());
    }

    #[tokio::test]
    async fn a_session_gets_its_datagrams_and_a_taken_id_is_skipped() {
        let sessions = Sessions::default();
        let (first, mut inbox) = sessions.register(|_| Some(1)).unwrap();
        let second = sessions.register(|taken| (1..).find(|id| !taken(*id)));
        assert_eq!(second.map(|(id, _)| id), Some(2));
        sessions.deliver(first, piece(0, 1, Some("1.2.3.4:53"), b"x"), Address::parse);
        let (addr, data) = inbox.recv().await.unwrap();
        assert_eq!(addr, Address::new("1.2.3.4", 53));
        assert_eq!(&data[..], b"x");
        sessions.clear();
        assert!(inbox.recv().await.is_none());
    }
}
