use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use concord_common::sync::lock;
use concord_common::{ConnEnd, ConnRecord, CoreEvent, EndReason, EventSink, Tasks, TrafficDelta};
use concord_net::Direction;
use dashmap::DashMap;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const REPORT_INTERVAL: Duration = Duration::from_secs(1);
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Closed connections' ids by number, for reading their MITM exchanges. Each captured exchange
/// is filed under one connection, so a capture of `capacity` entries refers to at most that many.
#[derive(Default)]
struct ClosedIds {
    order: VecDeque<u64>,
    ids: HashMap<u64, String>,
    capacity: usize,
}

impl ClosedIds {
    fn remember(&mut self, seq: u64, id: &str) {
        if self.capacity == 0 {
            return;
        }
        if self.ids.insert(seq, id.to_string()).is_none() {
            self.order.push_back(seq);
        }
        self.trim();
    }

    fn trim(&mut self) {
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }
    }
}

#[derive(Default)]
struct Totals {
    up: AtomicU64,
    down: AtomicU64,
}

impl Totals {
    fn of(&self, direction: Direction) -> &AtomicU64 {
        match direction {
            Direction::Upload => &self.up,
            Direction::Download => &self.down,
        }
    }
}

#[derive(Default)]
struct RateCursor {
    since: Option<Instant>,
    up_total: u64,
    down_total: u64,
    up_rate: u64,
    down_rate: u64,
}

impl RateCursor {
    fn sample(&mut self, totals: &Totals, now: Instant) -> (u64, u64) {
        let up = totals.up.load(Ordering::Relaxed);
        let down = totals.down.load(Ordering::Relaxed);
        match self.since {
            None => {
                self.since = Some(now);
                self.up_total = up;
                self.down_total = down;
            }
            Some(since) => {
                let elapsed = now.saturating_duration_since(since);
                if elapsed >= RATE_WINDOW {
                    let per_second = |delta: u64| {
                        let scaled = u128::from(delta) * 1000 / elapsed.as_millis().max(1);
                        u64::try_from(scaled).unwrap_or(u64::MAX)
                    };
                    self.up_rate = per_second(up.saturating_sub(self.up_total));
                    self.down_rate = per_second(down.saturating_sub(self.down_total));
                    self.since = Some(now);
                    self.up_total = up;
                    self.down_total = down;
                }
            }
        }
        (self.up_rate, self.down_rate)
    }
}

/// Reporting state of one connection, kept beside the record so the data path
/// touches two atomics and never a map.
pub struct Tracked {
    pub record: Arc<ConnRecord>,
    listed: AtomicBool,
    dirty: AtomicBool,
    table: Arc<ConnTable>,
}

impl Tracked {
    pub fn uploaded(self: &Arc<Self>, bytes: u64) {
        self.record.upload.fetch_add(bytes, Ordering::Relaxed);
        self.table
            .push(Direction::Upload, self.record.direct, bytes);
        self.mark_dirty();
    }

    pub fn downloaded(self: &Arc<Self>, bytes: u64) {
        self.record.download.fetch_add(bytes, Ordering::Relaxed);
        self.table
            .push(Direction::Download, self.record.direct, bytes);
        self.mark_dirty();
    }

    fn mark_dirty(self: &Arc<Self>) {
        if self.listed.load(Ordering::Acquire)
            && self.table.events.wants_connection_counters()
            && !self.dirty.swap(true, Ordering::AcqRel)
        {
            self.table.enqueue_dirty(self.clone());
        }
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.record.close();
    }
}

/// Removes the connection from the table when the task that owns it ends, whichever
/// way it ends, so a connection cannot leak out of `connection.list`.
pub struct Registration {
    tracked: Arc<Tracked>,
}

impl Registration {
    pub fn tracked(&self) -> &Arc<Tracked> {
        &self.tracked
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.tracked.record.settle_end();
        self.tracked.record.close();
        self.tracked.table.remove_open(&self.tracked.record);
        self.tracked.table.remember_closed(&self.tracked.record);
        if self.tracked.listed.load(Ordering::Acquire) && self.tracked.table.events.enabled() {
            let _announcing = lock(&self.tracked.table.announcing);
            self.tracked.table.events.closed(&self.tracked.record);
        }
    }
}

/// Every connection of the process and its traffic. It outlives configs.
pub struct ConnTable {
    open: DashMap<String, Arc<ConnRecord>>,
    /// Active connections indexed by `seq`; `open` is the source of truth—every entry in `open`
    /// lives here, so inserts write `by_seq` first and removes clear `open` first.
    by_seq: DashMap<u64, Arc<ConnRecord>>,
    all: Totals,
    proxied: Totals,
    all_rate: Mutex<RateCursor>,
    proxied_rate: Mutex<RateCursor>,
    dirty: Mutex<Vec<Arc<Tracked>>>,
    reporting: AtomicBool,
    /// Held while a report reads counters and offers them and while a close is announced, so
    /// a connection's counters never follow its close: a report skips what is already closed.
    announcing: Mutex<()>,
    closed_ids: Mutex<ClosedIds>,
    closes: AtomicU64,
    closing: ArcSwap<CancellationToken>,
    events: Arc<dyn EventSink>,
    tasks: Tasks,
}

impl ConnTable {
    pub fn new(events: Arc<dyn EventSink>, tasks: Tasks) -> Arc<Self> {
        Arc::new(ConnTable {
            open: DashMap::new(),
            by_seq: DashMap::new(),
            all: Totals::default(),
            proxied: Totals::default(),
            all_rate: Mutex::new(RateCursor::default()),
            proxied_rate: Mutex::new(RateCursor::default()),
            dirty: Mutex::new(Vec::new()),
            reporting: AtomicBool::new(false),
            announcing: Mutex::new(()),
            closed_ids: Mutex::new(ClosedIds::default()),
            closes: AtomicU64::new(0),
            closing: ArcSwap::from_pointee(CancellationToken::new()),
            events,
            tasks,
        })
    }

    /// Cancelled by the next `close_all`. A flow routes and dials under it, so a close that lands
    /// before the flow registers ends the setup too; it reads this before [`closes`](Self::closes).
    pub fn closing(&self) -> CancellationToken {
        CancellationToken::clone(&self.closing.load())
    }

    /// How many times `close_all` has run; a flow reads it before it starts to set up.
    pub fn closes(&self) -> u64 {
        self.closes.load(Ordering::SeqCst)
    }

    /// Registers a connection whose flow read [`closes`](Self::closes) before setting up, or,
    /// when `close_all` ran since, closes it with the rest and returns `None`.
    pub fn register_since(
        self: &Arc<Self>,
        record: Arc<ConnRecord>,
        closes: u64,
    ) -> Option<Registration> {
        if self.closes() != closes {
            return None;
        }
        let registration = self.prepare(record, 0);
        #[cfg(test)]
        if let Some(hook) = tests::ON_REGISTER_SINCE_PREPARE.with(std::cell::Cell::take) {
            hook(self);
        }
        // `close_all` counts before it walks the table, so either it finds this entry or the
        // count read here has moved.
        if self.closes() != closes {
            return None;
        }
        self.list(registration.tracked());
        Some(registration)
    }

    /// `initial_upload` is what went out with the handshake, which the record starts
    /// with so its first report is already right.
    pub fn register(
        self: &Arc<Self>,
        record: Arc<ConnRecord>,
        initial_upload: u64,
    ) -> Registration {
        let registration = self.prepare(record, initial_upload);
        self.list(registration.tracked());
        registration
    }

    /// Counts a connection's traffic while keeping it out of `connection.list` until
    /// `list`: MITM decides how a decrypted connection shows once its client answers.
    pub fn prepare(self: &Arc<Self>, record: Arc<ConnRecord>, initial_upload: u64) -> Registration {
        if initial_upload > 0 {
            self.push(Direction::Upload, record.direct, initial_upload);
        }
        Registration {
            tracked: Arc::new(Tracked {
                record,
                listed: AtomicBool::new(false),
                dirty: AtomicBool::new(false),
                table: self.clone(),
            }),
        }
    }

    /// A registration dropped meanwhile closed the record first and removed it after,
    /// so whichever way the two interleave the entry does not stay behind.
    pub fn list(&self, tracked: &Arc<Tracked>) {
        let record = &tracked.record;
        self.by_seq.insert(record.seq, record.clone());
        self.open.insert(record.id.clone(), record.clone());
        tracked.listed.store(true, Ordering::Release);
        if self.events.enabled() {
            self.events.publish(CoreEvent::Request(record.clone()));
        }
        if record.is_closed() {
            self.remove_open(record);
            self.remember_closed(record);
            if self.events.enabled() {
                let _announcing = lock(&self.announcing);
                self.events.closed(record);
            }
        } else {
            tracked.mark_dirty();
        }
    }

    fn remove_open(&self, record: &ConnRecord) {
        self.open.remove(&record.id);
        self.by_seq.remove(&record.seq);
    }

    fn open_by_seq(&self, seq: u64) -> Option<Arc<ConnRecord>> {
        let candidate = self.by_seq.get(&seq).map(|entry| entry.value().clone())?;
        let open = self
            .open
            .get(&candidate.id)
            .map(|entry| entry.value().clone())?;
        Arc::ptr_eq(&candidate, &open).then_some(open)
    }

    /// Lists a connection whose dial failed as opened and closed at once, to watchers only:
    /// it never enters `connection.list`, and nothing is built while no one watches.
    pub fn failed(&self, record: impl FnOnce() -> Arc<ConnRecord>) {
        if !self.events.enabled() {
            return;
        }
        let record = record();
        record.set_end(ConnEnd::new(EndReason::Failed));
        record.close();
        self.events.publish(CoreEvent::Request(record.clone()));
        self.events.closed(&record);
    }

    pub fn is_open(&self, id: &str) -> bool {
        self.open.contains_key(id)
    }

    fn remember_closed(&self, record: &ConnRecord) {
        lock(&self.closed_ids).remember(record.seq, &record.id);
    }

    /// How many closed connections stay findable by number: the MITM capture's entry limit,
    /// or none while nothing is captured.
    pub fn set_closed_capacity(&self, capacity: usize) {
        let mut closed = lock(&self.closed_ids);
        closed.capacity = capacity;
        closed.trim();
    }

    /// The uuid of a connection by its number, open or recently closed.
    pub fn id_of(&self, seq: u64) -> Option<String> {
        if let Some(record) = self.open_by_seq(seq) {
            return Some(record.id.clone());
        }
        lock(&self.closed_ids).ids.get(&seq).cloned()
    }

    fn push(&self, direction: Direction, direct: bool, bytes: u64) {
        self.all.of(direction).fetch_add(bytes, Ordering::Relaxed);
        if !direct {
            self.proxied
                .of(direction)
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn total(&self, only_proxy: bool) -> (u64, u64) {
        let totals = if only_proxy { &self.proxied } else { &self.all };
        (
            totals.up.load(Ordering::Relaxed),
            totals.down.load(Ordering::Relaxed),
        )
    }

    /// Sampled on read, so a host that stops asking leaves no timer running.
    pub fn now(&self, only_proxy: bool) -> (u64, u64) {
        let (cursor, totals) = if only_proxy {
            (&self.proxied_rate, &self.proxied)
        } else {
            (&self.all_rate, &self.all)
        };
        lock(cursor).sample(totals, Instant::now())
    }

    pub fn reset(&self) {
        for totals in [&self.all, &self.proxied] {
            totals.up.store(0, Ordering::Relaxed);
            totals.down.store(0, Ordering::Relaxed);
        }
        for cursor in [&self.all_rate, &self.proxied_rate] {
            *lock(cursor) = RateCursor::default();
        }
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    pub fn snapshot(&self) -> Vec<Arc<ConnRecord>> {
        self.open
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn close(&self, id: &str) {
        if let Some(record) = self.open.get(id).map(|entry| entry.value().clone()) {
            record.close();
        }
    }

    pub fn close_seqs(&self, seqs: &[u64]) {
        match seqs {
            [] => {}
            [seq] => {
                if let Some(record) = self.open_by_seq(*seq) {
                    record.close();
                }
            }
            seqs => {
                let mut seen = HashSet::with_capacity(seqs.len());
                let mut targets = Vec::with_capacity(seqs.len());
                for &seq in seqs {
                    if seen.insert(seq)
                        && let Some(record) = self.open_by_seq(seq)
                    {
                        targets.push(record);
                    }
                }
                for record in targets {
                    record.close();
                }
            }
        }
    }

    pub fn close_all(&self) {
        self.closes.fetch_add(1, Ordering::SeqCst);
        self.closing
            .swap(Arc::new(CancellationToken::new()))
            .cancel();
        for entry in &self.open {
            entry.value().close();
        }
    }

    fn enqueue_dirty(self: &Arc<Self>, tracked: Arc<Tracked>) {
        lock(&self.dirty).push(tracked);
        if !self.reporting.swap(true, Ordering::AcqRel)
            && !self.tasks.spawn_to_end(self.clone().report_traffic())
        {
            self.reporting.store(false, Ordering::Release);
        }
    }

    async fn report_traffic(self: Arc<Self>) {
        let mut ticker =
            tokio::time::interval_at(Instant::now() + REPORT_INTERVAL, REPORT_INTERVAL);
        loop {
            ticker.tick().await;
            if !self.report_once() {
                self.reporting.store(false, Ordering::Release);
                // A mark that came in after the drain found `reporting` still set.
                let pending = !lock(&self.dirty).is_empty();
                if pending && !self.reporting.swap(true, Ordering::AcqRel) {
                    continue;
                }
                return;
            }
        }
    }

    /// True while there is anything left to report next round.
    fn report_once(&self) -> bool {
        let batch = std::mem::take(&mut *lock(&self.dirty));
        if batch.is_empty() {
            return false;
        }
        for tracked in &batch {
            tracked.dirty.swap(false, Ordering::Acquire);
        }
        if !self.events.wants_connection_counters() {
            return false;
        }
        let announcing = lock(&self.announcing);
        let deltas: Vec<_> = batch
            .iter()
            .filter(|tracked| !tracked.record.is_closed())
            .map(|tracked| TrafficDelta {
                seq: tracked.record.seq,
                id: tracked.record.id.clone(),
                upload: tracked.record.upload.load(Ordering::Relaxed),
                download: tracked.record.download.load(Ordering::Relaxed),
            })
            .collect();
        if deltas.is_empty() {
            return false;
        }
        if self.events.offer(CoreEvent::RequestTraffic(deltas)) {
            return true;
        }
        drop(announcing);
        let retained = batch
            .into_iter()
            .filter(|tracked| !tracked.record.is_closed());
        let mut dirty = lock(&self.dirty);
        for tracked in retained {
            if !tracked.dirty.swap(true, Ordering::Relaxed) {
                dirty.push(tracked);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicUsize;

    use concord_common::{Address, ConnMeta, Host, InboundInfo, InboundKind, Network, NullSink};

    use super::*;

    thread_local! {
        pub(super) static ON_REGISTER_SINCE_PREPARE: std::cell::Cell<Option<fn(&ConnTable)>> =
            const { std::cell::Cell::new(None) };
    }

    #[derive(Default)]
    struct Sink {
        accept: AtomicBool,
        requests: AtomicUsize,
        traffic: StdMutex<Vec<Vec<TrafficDelta>>>,
        closed: StdMutex<Vec<(u64, u64, u64)>>,
        ends: StdMutex<Vec<(u64, Option<EndReason>)>>,
        /// Counters and closes by sequence number, in the order the sink took them.
        heard: StdMutex<Vec<(&'static str, u64)>>,
        /// Runs inside the next published request.
        during_request: StdMutex<Option<Box<dyn FnOnce() + Send>>>,
        /// Runs inside the next accepted traffic offer.
        during_offer: StdMutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl EventSink for Sink {
        fn enabled(&self) -> bool {
            true
        }

        fn publish(&self, event: CoreEvent) {
            self.offer(event);
        }

        fn offer(&self, event: CoreEvent) -> bool {
            match event {
                CoreEvent::Request(_) => {
                    self.requests.fetch_add(1, Ordering::Relaxed);
                    let during = lock(&self.during_request).take();
                    if let Some(during) = during {
                        during();
                    }
                    true
                }
                CoreEvent::RequestTraffic(deltas) if self.accept.load(Ordering::Relaxed) => {
                    let during = lock(&self.during_offer).take();
                    if let Some(during) = during {
                        during();
                    }
                    lock(&self.heard).extend(deltas.iter().map(|delta| ("counters", delta.seq)));
                    lock(&self.traffic).push(deltas);
                    true
                }
                _ => false,
            }
        }

        fn closed(&self, record: &ConnRecord) {
            lock(&self.ends).push((record.seq, record.end().map(|end| end.reason)));
            lock(&self.heard).push(("closed", record.seq));
            lock(&self.closed).push((
                record.seq,
                record.upload.load(Ordering::Relaxed),
                record.download.load(Ordering::Relaxed),
            ));
        }
    }

    fn record(direct: bool) -> Arc<ConnRecord> {
        let _ = Address::Socket("1.1.1.1:1".parse().unwrap());
        Arc::new(ConnRecord::new(
            ConnMeta {
                network: Network::Tcp,
                inbound: InboundInfo::new(InboundKind::Socks5),
                src: "127.0.0.1:1".parse().unwrap(),
                dst_ip: None,
                dst_port: 1,
                host: Host::default(),
                sniff_host: Host::default(),
                dns_mode: None,
                uid: None,
                process: String::new(),
                process_path: String::new(),
                remote_destination: String::new(),
                src_geoip: None,
                dst_geoip: None,
                src_asn: String::new(),
                dst_asn: String::new(),
                rematch_name: String::new(),
                special_rules: String::new(),
                special_proxy: String::new(),
            },
            Box::new([Arc::from("DIRECT")]),
            Box::new([]),
            Arc::from("Match"),
            Arc::from(""),
            direct,
            0,
        ))
    }

    #[tokio::test]
    async fn a_split_metered_stream_counts_each_direction_and_closes_with_the_last_half() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let registration = table.register(record(false), 0);
        let tracked = registration.tracked().clone();
        let (near, mut far) = tokio::io::duplex(64);
        let stream: concord_common::BoxStream =
            Box::new(crate::tcp::MeteredStream::new(Box::new(near), registration));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        far.write_all(b"down").await.unwrap();
        write.write_all(b"up!").await.unwrap();
        write.shutdown().await.unwrap();
        let mut sent = [0u8; 3];
        far.read_exact(&mut sent).await.unwrap();
        far.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"down");
        assert_eq!(table.total(false), (3, 4));
        assert_eq!(table.len(), 1);
        drop(write);
        assert_eq!(table.len(), 0);
        assert!(tracked.record.is_closed());
    }

    #[tokio::test]
    async fn only_proxy_totals_leave_out_direct_connections() {
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let direct = table.register(record(true), 5);
        let proxied = table.register(record(false), 0);
        direct.tracked().downloaded(10);
        proxied.tracked().uploaded(3);
        assert_eq!(table.total(false), (8, 10));
        assert_eq!(table.total(true), (3, 0));
    }

    #[tokio::test]
    async fn a_close_carries_the_traffic_after_the_last_report() {
        let sink = Arc::new(Sink::default());
        sink.accept.store(true, Ordering::Relaxed);
        let table = ConnTable::new(sink.clone(), Default::default());
        let registration = table.register(record(false), 0);
        let seq = registration.tracked().record.seq;
        registration.tracked().uploaded(5);
        assert!(table.report_once());
        registration.tracked().uploaded(3);
        registration.tracked().downloaded(2);
        drop(registration);
        let reported = lock(&sink.traffic);
        assert_eq!(reported.len(), 1);
        assert_eq!((reported[0][0].upload, reported[0][0].download), (5, 0));
        assert_eq!(*lock(&sink.closed), [(seq, 8, 2)]);
    }

    #[tokio::test]
    async fn a_close_that_lands_while_a_report_is_offered_is_announced_after_it() {
        let sink = Arc::new(Sink::default());
        sink.accept.store(true, Ordering::Relaxed);
        let table = ConnTable::new(sink.clone(), Default::default());
        let registration = table.register(record(false), 0);
        let seq = registration.tracked().record.seq;
        registration.tracked().uploaded(5);
        *lock(&sink.during_offer) = Some(Box::new(move || {
            registration.tracked().downloaded(2);
            let (dropped, was_dropped) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                drop(registration);
                let _ = dropped.send(());
            });
            assert!(
                was_dropped
                    .recv_timeout(std::time::Duration::from_millis(200))
                    .is_err(),
                "the close waits for the report being offered"
            );
        }));
        assert!(table.report_once());
        for _ in 0..200 {
            if !lock(&sink.closed).is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(*lock(&sink.heard), [("counters", seq), ("closed", seq)]);
        assert_eq!(lock(&sink.traffic)[0][0].upload, 5);
        assert_eq!(*lock(&sink.closed), [(seq, 5, 2)]);
    }

    #[tokio::test]
    async fn a_connection_closed_by_id_or_by_close_all_reports_only_its_close() {
        let sink = Arc::new(Sink::default());
        sink.accept.store(true, Ordering::Relaxed);
        let table = ConnTable::new(sink.clone(), Default::default());
        let by_id = table.register(record(false), 0);
        let rest = table.register(record(false), 0);
        let (first, second) = (by_id.tracked().record.seq, rest.tracked().record.seq);
        by_id.tracked().uploaded(3);
        rest.tracked().downloaded(4);
        table.close(&by_id.tracked().record.id);
        table.close_all();
        assert!(!table.report_once(), "nothing open is left to count");
        by_id.tracked().uploaded(1);
        drop((by_id, rest));
        assert!(lock(&sink.traffic).is_empty());
        let mut closed = lock(&sink.closed).clone();
        closed.sort_unstable();
        assert_eq!(closed, [(first, 4, 0), (second, 0, 4)]);
    }

    #[tokio::test]
    async fn a_connection_that_closed_before_it_was_listed_is_listed_with_its_final_totals() {
        let sink = Arc::new(Sink::default());
        let table = ConnTable::new(sink.clone(), Default::default());
        let registration = table.prepare(record(false), 0);
        let tracked = registration.tracked().clone();
        tracked.uploaded(6);
        tracked.downloaded(7);
        drop(registration);
        assert!(
            lock(&sink.closed).is_empty(),
            "an unlisted close is not announced"
        );
        table.list(&tracked);
        assert_eq!(*lock(&sink.closed), [(tracked.record.seq, 6, 7)]);
        assert!(table.is_empty());
    }

    #[tokio::test]
    async fn a_failed_dial_is_heard_of_as_opened_and_closed_but_never_listed() {
        let sink = Arc::new(Sink::default());
        let table = ConnTable::new(sink.clone(), Default::default());
        let record = record(false);
        let seq = record.seq;
        table.failed(|| record.clone());
        assert_eq!(sink.requests.load(Ordering::Relaxed), 1);
        assert_eq!(*lock(&sink.closed), [(seq, 0, 0)]);
        assert!(record.is_closed());
        assert!(table.is_empty() && table.id_of(seq).is_none());

        let unheard = ConnTable::new(Arc::new(NullSink), Default::default());
        unheard.failed(|| panic!("nothing is built while no one listens"));
    }

    #[tokio::test]
    async fn a_close_nobody_explained_says_whether_the_core_closed_it() {
        let sink = Arc::new(Sink::default());
        let table = ConnTable::new(sink.clone(), Default::default());
        let let_go = table.register(record(false), 0);
        let closed = table.register(record(false), 0);
        let told = table.register(record(false), 0);
        let seqs = [&let_go, &closed, &told].map(|reg| reg.tracked().record.seq);
        table.close(&closed.tracked().record.id);
        told.tracked()
            .record
            .set_end(ConnEnd::new(EndReason::Remote));
        drop((let_go, closed, told));
        let failed = record(false);
        table.failed(|| failed.clone());
        assert_eq!(
            *lock(&sink.ends),
            [
                (seqs[0], Some(EndReason::Finished)),
                (seqs[1], Some(EndReason::Core)),
                (seqs[2], Some(EndReason::Remote)),
                (failed.seq, Some(EndReason::Failed)),
            ]
        );
    }

    #[tokio::test]
    async fn dropping_the_registration_removes_and_closes_the_connection() {
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let record = record(false);
        let registration = table.register(record.clone(), 0);
        assert_eq!(table.len(), 1);
        drop(registration);
        assert!(table.is_empty());
        assert!(record.is_closed());
        assert!(record.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn a_closed_connection_is_found_by_its_number_until_newer_ones_push_it_out() {
        const CAPTURE: usize = 8;
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        table.set_closed_capacity(CAPTURE);
        let first = record(false);
        let (seq, id) = (first.seq, first.id.clone());
        let open = table.register(first, 0);
        assert_eq!(table.id_of(seq).as_deref(), Some(id.as_str()));
        drop(open);
        assert!(!table.is_open(&id));
        assert_eq!(table.id_of(seq).as_deref(), Some(id.as_str()));
        assert_eq!(table.id_of(u64::MAX), None);
        for _ in 0..CAPTURE {
            drop(table.register(record(false), 0));
        }
        assert_eq!(table.id_of(seq), None);
    }

    #[tokio::test]
    async fn without_a_capture_a_closed_connection_is_not_remembered() {
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let first = record(false);
        let seq = first.seq;
        drop(table.register(first, 0));
        assert_eq!(table.id_of(seq), None);
    }

    fn metered(table: &Arc<ConnTable>) -> (crate::tcp::MeteredStream, tokio::io::DuplexStream) {
        let (near, far) = tokio::io::duplex(64);
        let registration = table.register(record(false), 0);
        (
            crate::tcp::MeteredStream::new(Box::new(near), registration),
            far,
        )
    }

    fn read_buffer(
        stream: &mut crate::tcp::MeteredStream,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<concord_common::stream_buffer::StreamBuffer>> {
        use concord_common::Stream;
        use concord_common::stream_buffer::{BufferRequirements, ReadBufferOptions};

        let none = BufferRequirements::default();
        stream.poll_read_buffer(cx, ReadBufferOptions::for_copy(none, none).unwrap())
    }

    async fn next_buffer(stream: &mut crate::tcp::MeteredStream) -> io::Result<usize> {
        let buffer = std::future::poll_fn(|cx| read_buffer(stream, cx)).await?;
        Ok(buffer.len())
    }

    #[tokio::test]
    async fn a_buffer_read_counts_each_segment_once_alongside_plain_reads() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let (mut stream, mut far) = metered(&table);
        far.write_all(b"do").await.unwrap();
        assert_eq!(next_buffer(&mut stream).await.unwrap(), 2);
        assert_eq!(table.total(false), (0, 2));
        far.write_all(b"wn").await.unwrap();
        assert_eq!(next_buffer(&mut stream).await.unwrap(), 2);
        far.write_all(b"!!").await.unwrap();
        let mut plain = [0u8; 2];
        stream.read_exact(&mut plain).await.unwrap();
        assert_eq!(table.total(false), (0, 6));
    }

    #[tokio::test]
    async fn a_buffer_read_that_waits_counts_nothing() {
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let (mut stream, _far) = metered(&table);
        let waited =
            std::future::poll_fn(|cx| std::task::Poll::Ready(read_buffer(&mut stream, cx))).await;
        assert!(waited.is_pending());
        assert_eq!(table.total(false), (0, 0));
    }

    #[tokio::test]
    async fn a_buffer_read_at_the_end_counts_nothing() {
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let (mut stream, far) = metered(&table);
        drop(far);
        assert_eq!(next_buffer(&mut stream).await.unwrap(), 0);
        assert_eq!(table.total(false), (0, 0));
    }

    #[tokio::test]
    async fn a_buffer_read_of_a_closed_connection_fails_and_counts_nothing() {
        use tokio::io::AsyncWriteExt;

        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let (mut stream, mut far) = metered(&table);
        far.write_all(b"late").await.unwrap();
        table.close_all();
        let err = next_buffer(&mut stream).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(table.total(false), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn the_rate_is_measured_over_the_time_since_the_last_read() {
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let registration = table.register(record(false), 0);
        assert_eq!(table.now(false), (0, 0));
        registration.tracked().downloaded(2000);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(table.now(false), (0, 1000));
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(table.now(false), (0, 1000));
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_is_reported_once_per_change_and_stops_when_idle() {
        let sink = Arc::new(Sink::default());
        sink.accept.store(true, Ordering::Relaxed);
        let table = ConnTable::new(sink.clone(), Default::default());
        let registration = table.register(record(false), 0);
        registration.tracked().uploaded(1);
        registration.tracked().uploaded(1);
        tokio::time::sleep(REPORT_INTERVAL * 3).await;
        assert_eq!(lock(&sink.traffic).len(), 1);
        assert_eq!(lock(&sink.traffic)[0][0].upload, 2);
        assert!(!table.reporting.load(Ordering::Acquire));

        registration.tracked().uploaded(1);
        tokio::time::sleep(REPORT_INTERVAL * 3).await;
        assert_eq!(lock(&sink.traffic).len(), 2);
        assert_eq!(lock(&sink.traffic)[1][0].upload, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_report_drops_a_closed_connection() {
        let sink = Arc::new(Sink::default());
        let table = ConnTable::new(sink.clone(), Default::default());
        let registration = table.register(record(false), 0);
        registration.tracked().uploaded(1);
        drop(registration);
        tokio::time::sleep(REPORT_INTERVAL * 10).await;
        assert!(lock(&table.dirty).is_empty());
        assert!(!table.reporting.load(Ordering::Acquire));
        assert!(lock(&sink.traffic).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_is_still_reported_after_a_panic_poisoned_the_queue() {
        let sink = Arc::new(Sink::default());
        sink.accept.store(true, Ordering::Relaxed);
        let table = ConnTable::new(sink.clone(), Default::default());
        let poisoner = table.clone();
        let _ = std::thread::spawn(move || {
            let _held = lock(&poisoner.dirty);
            panic!("a holder of the queue panicked");
        })
        .join();
        assert!(table.dirty.is_poisoned());
        let registration = table.register(record(false), 0);
        registration.tracked().uploaded(1);
        tokio::time::sleep(REPORT_INTERVAL * 3).await;
        assert_eq!(lock(&sink.traffic).len(), 1);
    }

    struct ScopedSink {
        inner: Sink,
        enabled: AtomicBool,
        wants_counters: AtomicBool,
    }

    impl ScopedSink {
        fn new(enabled: bool, wants_counters: bool) -> Arc<Self> {
            let inner = Sink::default();
            inner.accept.store(true, Ordering::Relaxed);
            Arc::new(ScopedSink {
                inner,
                enabled: AtomicBool::new(enabled),
                wants_counters: AtomicBool::new(wants_counters),
            })
        }
    }

    impl EventSink for ScopedSink {
        fn enabled(&self) -> bool {
            self.enabled.load(Ordering::Acquire)
        }

        fn wants_connection_counters(&self) -> bool {
            self.wants_counters.load(Ordering::Acquire)
        }

        fn publish(&self, event: CoreEvent) {
            self.inner.publish(event);
        }

        fn offer(&self, event: CoreEvent) -> bool {
            self.inner.offer(event)
        }

        fn closed(&self, record: &ConnRecord) {
            self.inner.closed(record);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_does_not_mark_dirty_without_counter_interest_but_still_counts_and_closes() {
        let sink = ScopedSink::new(true, false);
        let table = ConnTable::new(sink.clone(), Default::default());
        table.set_closed_capacity(4);
        let registration = table.register(record(false), 0);
        let tracked = registration.tracked().clone();
        let seq = tracked.record.seq;
        let id = tracked.record.id.clone();

        tracked.uploaded(15);
        tracked.downloaded(23);
        assert!(lock(&table.dirty).is_empty());
        assert!(!table.reporting.load(Ordering::Acquire));
        assert!(!tracked.dirty.load(Ordering::Acquire));
        assert_eq!(table.total(false), (15, 23));

        tokio::time::sleep(REPORT_INTERVAL * 3).await;
        assert!(lock(&sink.inner.traffic).is_empty());

        drop(registration);
        assert_eq!(*lock(&sink.inner.closed), [(seq, 15, 23)]);
        assert_eq!(*lock(&sink.inner.ends), [(seq, Some(EndReason::Finished))]);
        assert_eq!(table.id_of(seq).as_deref(), Some(id.as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn last_counter_watcher_leaving_drains_dirty_and_allows_later_resubscribe() {
        let sink = ScopedSink::new(true, true);
        let table = ConnTable::new(sink.clone(), Default::default());
        let registration = table.register(record(false), 0);
        let tracked = registration.tracked().clone();
        let seq = tracked.record.seq;

        tracked.uploaded(10);
        assert_eq!(lock(&table.dirty).len(), 1);
        assert!(table.reporting.load(Ordering::Acquire));

        sink.wants_counters.store(false, Ordering::Release);
        tokio::time::sleep(REPORT_INTERVAL * 3).await;
        assert!(lock(&table.dirty).is_empty());
        assert!(!table.reporting.load(Ordering::Acquire));
        assert!(!tracked.dirty.load(Ordering::Acquire));
        assert!(lock(&sink.inner.traffic).is_empty());

        tracked.uploaded(5);
        tracked.downloaded(7);
        assert!(lock(&table.dirty).is_empty());
        assert!(!table.reporting.load(Ordering::Acquire));
        assert_eq!(table.total(false), (15, 7));

        sink.wants_counters.store(true, Ordering::Release);
        tracked.uploaded(3);
        assert_eq!(lock(&table.dirty).len(), 1);
        assert!(table.reporting.load(Ordering::Acquire));
        tokio::time::sleep(REPORT_INTERVAL * 3).await;
        assert_eq!(lock(&sink.inner.traffic).len(), 1);
        assert_eq!(lock(&sink.inner.traffic)[0][0].seq, seq);
        assert_eq!(lock(&sink.inner.traffic)[0][0].upload, 18);
        assert_eq!(lock(&sink.inner.traffic)[0][0].download, 7);
        assert!(!table.reporting.load(Ordering::Acquire));

        drop(registration);
        assert_eq!(*lock(&sink.inner.closed), [(seq, 18, 7)]);
    }

    #[tokio::test]
    async fn close_seqs_handles_empty_single_batch_duplicates_and_unknowns() {
        let sink = Arc::new(Sink::default());
        sink.accept.store(true, Ordering::Relaxed);
        let table = ConnTable::new(sink.clone(), Default::default());

        let first = table.register(record(false), 0);
        let second = table.register(record(false), 0);
        let third = table.register(record(false), 0);
        let fourth = table.register(record(false), 0);
        let seqs = [&first, &second, &third, &fourth].map(|reg| reg.tracked().record.seq);
        assert_eq!(table.open.len(), 4);
        assert_eq!(table.by_seq.len(), 4);

        table.close_seqs(&[]);
        table.close_seqs(&[u64::MAX]);
        assert!(
            [&first, &second, &third, &fourth]
                .iter()
                .all(|reg| !reg.tracked().record.is_closed())
        );

        assert!(table.report_once());
        lock(&sink.traffic).clear();

        first.tracked().uploaded(7);
        table.close_seqs(&[seqs[0]]);
        assert!(first.tracked().record.is_closed());
        assert!(!second.tracked().record.is_closed());
        assert!(
            !table.report_once(),
            "closed connection emits no periodic counters"
        );

        second.tracked().downloaded(9);
        table.close_seqs(&[seqs[1], seqs[1], u64::MAX, seqs[2]]);
        assert!(second.tracked().record.is_closed());
        assert!(third.tracked().record.is_closed());
        assert!(!fourth.tracked().record.is_closed());

        drop((first, second, third));
        assert_eq!(table.open.len(), 1);
        assert_eq!(table.by_seq.len(), 1);
        assert!(table.id_of(seqs[3]).is_some());
        assert!(lock(&sink.traffic).is_empty());
        let ends: HashMap<u64, Option<EndReason>> = lock(&sink.ends).iter().copied().collect();
        assert_eq!(ends.get(&seqs[0]), Some(&Some(EndReason::Core)));
        assert_eq!(ends.get(&seqs[1]), Some(&Some(EndReason::Core)));
        assert_eq!(ends.get(&seqs[2]), Some(&Some(EndReason::Core)));

        drop(fourth);
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());
    }

    #[tokio::test]
    async fn dual_index_stays_consistent_across_prepare_list_drop_races_and_failed() {
        let sink = Arc::new(Sink::default());
        let table = ConnTable::new(sink.clone(), Default::default());
        table.set_closed_capacity(4);

        let prepared = table.prepare(record(false), 0);
        let prepared_seq = prepared.tracked().record.seq;
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());
        assert_eq!(table.id_of(prepared_seq), None);
        table.close_seqs(&[prepared_seq]);
        assert!(!prepared.tracked().record.is_closed());
        table.list(prepared.tracked());
        assert_eq!(table.open.len(), 1);
        assert_eq!(table.by_seq.len(), 1);
        assert_eq!(
            table.id_of(prepared_seq).as_deref(),
            Some(prepared.tracked().record.id.as_str())
        );
        drop(prepared);
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());

        let raced = table.prepare(record(false), 0);
        let raced_tracked = raced.tracked().clone();
        let raced_seq = raced_tracked.record.seq;
        let raced_id = raced_tracked.record.id.clone();
        drop(raced);
        table.list(&raced_tracked);
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());
        assert_eq!(table.id_of(raced_seq).as_deref(), Some(raced_id.as_str()));

        let failed = record(false);
        let failed_seq = failed.seq;
        table.failed(|| failed.clone());
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());
        assert_eq!(table.id_of(failed_seq), None);

        let stale = record(false);
        let stale_seq = stale.seq;
        table.by_seq.insert(stale_seq, stale);
        assert!(table.open_by_seq(stale_seq).is_none());
        assert_eq!(table.id_of(stale_seq), None);
        table.by_seq.remove(&stale_seq);

        // `close_all` before `register_since` rejects on the first check.
        let closes = table.closes();
        table.close_all();
        assert!(table.register_since(record(false), closes).is_none());
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());

        // `close_all` between `register_since`'s first and second checks rejects after `prepare`.
        let closes = table.closes();
        let mid_record = record(false);
        let mid_seq = mid_record.seq;
        ON_REGISTER_SINCE_PREPARE.with(|cell| cell.set(Some(ConnTable::close_all)));
        assert!(table.register_since(mid_record.clone(), closes).is_none());
        assert!(mid_record.is_closed());
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());
        assert!(
            !lock(&sink.closed).iter().any(|(seq, _, _)| *seq == mid_seq),
            "unlisted registration dropped on close_all is not announced"
        );

        // `drop` landing after `list` inserts into `by_seq` and `open`, before `is_closed()`.
        let in_list = table.prepare(record(false), 0);
        let in_list_tracked = in_list.tracked().clone();
        let in_list_seq = in_list_tracked.record.seq;
        let in_list_id = in_list_tracked.record.id.clone();
        in_list_tracked.uploaded(11);
        *lock(&sink.during_request) = Some(Box::new(move || {
            drop(in_list);
        }));
        table.list(&in_list_tracked);
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());
        assert!(in_list_tracked.record.is_closed());
        assert_eq!(
            table.id_of(in_list_seq).as_deref(),
            Some(in_list_id.as_str())
        );
        assert!(lock(&sink.closed).contains(&(in_list_seq, 11, 0)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_list_drop_lookup_and_close_leave_both_tables_empty() {
        let table = ConnTable::new(Arc::new(Sink::default()), Default::default());
        let mut handles = Vec::new();
        for _ in 0..64 {
            let table = table.clone();
            handles.push(tokio::spawn(async move {
                let reg = table.prepare(record(false), 0);
                let tracked = reg.tracked().clone();
                let seq = tracked.record.seq;
                let closer = table.clone();
                let list_task = tokio::spawn(async move {
                    closer.list(&tracked);
                });
                let _ = table.id_of(seq);
                table.close_seqs(&[seq]);
                drop(reg);
                list_task.await.unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert!(table.open.is_empty());
        assert!(table.by_seq.is_empty());
    }
}
