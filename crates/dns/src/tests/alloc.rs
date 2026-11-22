#![allow(
    unsafe_code,
    reason = "a counting global allocator wraps the system one"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use concord_common::{EventSink, Initiator};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};

use crate::msg;
use crate::resolver::{Group, GroupParts};
use crate::trie::{DomainSet, DomainTrie};

struct Counting;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<usize> = const { Cell::new(0) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    if ARMED.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCS.try_with(|count| count.set(count.get() + 1));
        let _ = BYTES.try_with(|bytes| bytes.set(bytes.get() + size));
    }
}

// SAFETY: forwards every call to the system allocator unchanged.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract passes straight through to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn start() {
    ALLOCS.with(|count| count.set(0));
    BYTES.with(|bytes| bytes.set(0));
    ARMED.with(|armed| armed.set(true));
}

fn stop() -> (usize, usize) {
    ARMED.with(|armed| armed.set(false));
    (ALLOCS.with(Cell::get), BYTES.with(Cell::get))
}

struct Quiet;

impl EventSink for Quiet {
    fn enabled(&self) -> bool {
        false
    }

    fn publish(&self, _event: concord_common::CoreEvent) {}
}

fn answer(name: &Name) -> Message {
    let mut resp = Message::query();
    resp.add_query(Query::query(name.clone(), RecordType::A));
    for last in 1..=3 {
        resp.answers
            .push(msg::a_record(name, 300, Ipv4Addr::new(10, 0, 0, last)));
    }
    resp
}

#[tokio::test(flavor = "current_thread")]
async fn a_cache_hit_reads_the_shared_message() {
    let events: Arc<dyn EventSink> = Arc::new(Quiet);
    let group = Group::new(
        GroupParts {
            main: Vec::new(),
            fallback: Vec::new(),
            fallback_domain: Vec::new(),
            fallback_ip: Vec::new(),
            fallback_lazy: false,
            policy: Arc::new(Vec::new()),
            cache_algorithm: Default::default(),
            cache_size: 16,
            ipv6_timeout: Duration::ZERO,
            tasks: Default::default(),
        },
        events,
    );
    let name = Name::from_ascii("Cache.Example.com.").unwrap();
    let mut req = Message::query();
    req.add_query(Query::query(name.clone(), RecordType::A));
    let query = req.queries.first().unwrap().clone();
    group.store(&query, &answer(&name), "upstream");

    let hit = group.exchange_with(&req, Initiator::Other, msg::answer_ips);
    start();
    let ips = hit.await.unwrap();
    let (allocs, bytes) = stop();
    assert_eq!(ips.len(), 3);
    assert_eq!(
        allocs, 1,
        "a hit allocates only the address list ({bytes} bytes counted)"
    );
}

#[test]
fn a_trie_lookup_does_not_allocate() {
    let mut trie = DomainTrie::new();
    for (index, pattern) in ["www.example.com", "*.google.com", "+.baidu.com"]
        .into_iter()
        .enumerate()
    {
        trie.insert(pattern, index).unwrap();
    }
    start();
    let found = [
        trie.search("www.example.com").copied(),
        trie.search("WWW.Example.COM").copied(),
        trie.search("a.google.com").copied(),
        trie.search("x.y.baidu.com").copied(),
        trie.search("example.org").copied(),
    ];
    let (allocs, bytes) = stop();
    assert_eq!(found, [Some(0), Some(0), Some(1), Some(2), None]);
    assert_eq!(allocs, 0, "{bytes} bytes counted");
}

#[test]
fn an_empty_trie_answers_without_allocating() {
    let trie: DomainTrie<u32> = DomainTrie::new();
    let set = DomainSet::new();
    start();
    let found = (trie.search("www.example.com"), set.has("Bad..Name"));
    let (allocs, bytes) = stop();
    assert_eq!(found, (None, false));
    assert_eq!(allocs, 0, "{bytes} bytes counted");
}
