use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use concord_common::query_trail;
use concord_common::sync::lock;
use concord_common::{CoreError, EventSink, Initiator, LookupIps, Tasks};
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::client::{ClientRef, timed_out};
use crate::dialer::{self, Cx};
use crate::lru::{ArcCache, LruCache};
use crate::record::Trace;
use crate::trie::DomainTrie;
use crate::{DomainMatch, IpMatch, msg};

pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_CACHE_SIZE: usize = 4096;
const DEFAULT_IPV6_WAIT: Duration = Duration::from_millis(100);

pub(crate) struct Batch {
    pub msg: Message,
    pub upstream: String,
    pub cache: bool,
}

/// All clients at once, first usable answer wins. A SERVFAIL or REFUSED does
/// not count as one; an `rcode://` client answers at once and is not cached.
pub(crate) async fn batch_exchange(
    clients: &[ClientRef],
    req: &Message,
    cx: Cx,
) -> io::Result<Batch> {
    let mut pending = FuturesUnordered::new();
    for client in clients {
        if client.is_rcode() {
            let msg = client.exchange(req, cx).await?;
            return Ok(Batch {
                msg,
                upstream: client.address(),
                cache: false,
            });
        }
        pending.push(async move { (client, client.exchange(req, cx).await) });
    }
    let mut first_error: Option<io::Error> = None;
    let waited = tokio::time::timeout(DNS_TIMEOUT, async {
        while let Some((client, result)) = pending.next().await {
            match result {
                Ok(msg)
                    if matches!(
                        msg.metadata.response_code,
                        ResponseCode::ServFail | ResponseCode::Refused
                    ) =>
                {
                    first_error.get_or_insert_with(|| {
                        io::Error::other(format!(
                            "server failure: {}",
                            msg::rcode_name(msg.metadata.response_code)
                        ))
                    });
                }
                Ok(msg) => {
                    return Some(Batch {
                        msg,
                        upstream: client.address(),
                        cache: true,
                    });
                }
                Err(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }
        None
    })
    .await;
    if let Ok(Some(batch)) = waited {
        return Ok(batch);
    }
    let kind = if waited.is_err() {
        io::ErrorKind::TimedOut
    } else {
        first_error
            .as_ref()
            .map(io::Error::kind)
            .unwrap_or(io::ErrorKind::Other)
    };
    Err(io::Error::new(kind, AllFailed(first_error)))
}

/// Every upstream of a batch failed; the first failure is kept as the source, so a reader can
/// still tell what it was.
#[derive(Debug)]
struct AllFailed(Option<io::Error>);

impl fmt::Display for AllFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("all DNS requests failed")?;
        match &self.0 {
            Some(err) => write!(f, ", first error: {err}"),
            None => Ok(()),
        }
    }
}

impl Error for AllFailed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.as_ref().map(|err| err as &(dyn Error + 'static))
    }
}

/// The failure of a flight, handed to every query that joined it.
#[derive(Debug)]
struct Shared(Arc<io::Error>);

impl fmt::Display for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for Shared {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

fn spawn_batch(
    tasks: &Tasks,
    clients: Vec<ClientRef>,
    req: Message,
    cx: Cx,
) -> JoinHandle<Option<io::Result<Batch>>> {
    dialer::spawn(
        tasks,
        async move { batch_exchange(&clients, &req, cx).await },
    )
}

async fn joined(handle: JoinHandle<Option<io::Result<Batch>>>) -> io::Result<Batch> {
    handle
        .await
        .map_err(io::Error::other)?
        .unwrap_or_else(|| Err(io::Error::from(io::ErrorKind::Interrupted)))
}

pub(crate) enum PolicyItem {
    Trie(DomainTrie<Vec<ClientRef>>),
    Matcher(Arc<dyn DomainMatch>, Vec<ClientRef>),
}

impl PolicyItem {
    fn clients_for(&self, domain: &str) -> Option<&[ClientRef]> {
        let found = match self {
            PolicyItem::Trie(trie) => trie.search(domain).map(Vec::as_slice),
            PolicyItem::Matcher(matcher, clients) => {
                matcher.matches(domain).then_some(clients.as_slice())
            }
        };
        found.filter(|clients| !clients.is_empty())
    }
}

struct Entry {
    msg: Arc<Message>,
    expire: Instant,
    upstream: Arc<str>,
}

enum Age {
    Stale,
    Remaining(u32),
}

enum Cache {
    Lru(LruCache<String, Entry>),
    Arc(ArcCache<String, Entry>),
}

impl Cache {
    fn new(algorithm: &str, size: i32) -> Self {
        let size = usize::try_from(size)
            .ok()
            .filter(|size| *size > 0)
            .unwrap_or(DEFAULT_CACHE_SIZE);
        if algorithm == "arc" {
            Cache::Arc(ArcCache::new(size))
        } else {
            Cache::Lru(LruCache::new(size))
        }
    }

    fn get(&mut self, key: &str) -> Option<(Arc<Message>, Instant, Arc<str>)> {
        let entry = match self {
            Cache::Lru(cache) => cache.get(key),
            Cache::Arc(cache) => cache.get(key),
        }?;
        Some((Arc::clone(&entry.msg), entry.expire, entry.upstream.clone()))
    }

    fn put(&mut self, key: String, entry: Entry) {
        match self {
            Cache::Lru(cache) => cache.insert(key, entry),
            Cache::Arc(cache) => cache.insert(key, entry),
        }
    }

    fn clear(&mut self) {
        match self {
            Cache::Lru(cache) => cache.clear(),
            Cache::Arc(cache) => cache.clear(),
        }
    }
}

/// The answer and the id of the record that told it, which every caller joining the flight notes.
type Outcome = (Result<Arc<Message>, Arc<io::Error>>, Option<u64>);
type Flight = watch::Receiver<Option<Outcome>>;

pub(crate) struct GroupParts {
    pub main: Vec<ClientRef>,
    pub fallback: Vec<ClientRef>,
    pub fallback_domain: Vec<Arc<dyn DomainMatch>>,
    pub fallback_ip: Vec<Arc<dyn IpMatch>>,
    pub fallback_lazy: bool,
    pub policy: Arc<Vec<PolicyItem>>,
    pub cache_algorithm: String,
    pub cache_size: i32,
    pub ipv6_timeout: Duration,
    pub tasks: Tasks,
}

/// One of the resolvers mihomo builds: its servers, its policy, its own cache.
pub(crate) struct Group {
    parts: GroupParts,
    cache: Mutex<Cache>,
    flights: Mutex<HashMap<String, Flight>>,
    events: Arc<dyn EventSink>,
}

impl Group {
    pub(crate) fn new(parts: GroupParts, events: Arc<dyn EventSink>) -> Arc<Self> {
        Arc::new(Group {
            cache: Mutex::new(Cache::new(&parts.cache_algorithm, parts.cache_size)),
            flights: Mutex::new(HashMap::new()),
            parts,
            events,
        })
    }

    pub(crate) fn policy(&self) -> Arc<Vec<PolicyItem>> {
        Arc::clone(&self.parts.policy)
    }

    pub(crate) fn clear_cache(&self) {
        {
            let mut cache = lock(&self.cache);
            cache.clear();
        }
    }

    fn cached(
        &self,
        query: &hickory_proto::op::Query,
    ) -> Option<(Arc<Message>, Instant, Arc<str>)> {
        msg::with_cache_key(query, |key| lock(&self.cache).get(key))
    }

    pub(crate) fn store(
        &self,
        query: &hickory_proto::op::Query,
        message: &Message,
        upstream: &str,
    ) {
        if msg::is_acme_challenge(query) {
            return;
        }
        let mut copy = message.clone();
        copy.edns = None;
        let ttl = msg::cache_ttl(&copy);
        if ttl == 0 {
            return;
        }
        let expire = Instant::now() + Duration::from_secs(u64::from(ttl));
        {
            let mut cache = lock(&self.cache);
            let upstream = Arc::from(upstream);
            cache.put(
                msg::cache_key(query),
                Entry {
                    msg: Arc::new(copy),
                    expire,
                    upstream,
                },
            );
        }
    }

    fn matched_clients(&self, req: &Message) -> Option<Vec<ClientRef>> {
        let domain = msg::msg_domain(req);
        if domain.is_empty() {
            return None;
        }
        self.parts
            .policy
            .iter()
            .find_map(|item| item.clients_for(&domain))
            .map(<[ClientRef]>::to_vec)
    }

    fn only_fallback(&self, req: &Message) -> bool {
        if self.parts.fallback.is_empty() || self.parts.fallback_domain.is_empty() {
            return false;
        }
        let domain = msg::msg_domain(req);
        !domain.is_empty()
            && self
                .parts
                .fallback_domain
                .iter()
                .any(|filter| filter.matches(&domain))
    }

    fn should_ip_fallback(&self, ip: IpAddr) -> bool {
        self.parts
            .fallback_ip
            .iter()
            .any(|filter| filter.matches(ip))
    }

    async fn ip_exchange(&self, req: &Message, cx: Cx) -> io::Result<Batch> {
        if let Some(matched) = self.matched_clients(req) {
            return batch_exchange(&matched, req, cx).await;
        }
        if self.only_fallback(req) {
            return batch_exchange(&self.parts.fallback, req, cx).await;
        }
        if self.parts.fallback.is_empty() {
            return batch_exchange(&self.parts.main, req, cx).await;
        }
        let main = spawn_batch(&self.parts.tasks, self.parts.main.clone(), req.clone(), cx);
        let mut fallback = (!self.parts.fallback_lazy).then(|| {
            spawn_batch(
                &self.parts.tasks,
                self.parts.fallback.clone(),
                req.clone(),
                cx,
            )
        });
        if let Ok(batch) = joined(main).await {
            let ips = msg::answer_ips(&batch.msg);
            if !ips.is_empty() && ips.iter().all(|ip| !self.should_ip_fallback(*ip)) {
                if let Some(handle) = &fallback {
                    handle.abort();
                }
                return Ok(batch);
            }
        }
        let handle = fallback.take().unwrap_or_else(|| {
            spawn_batch(
                &self.parts.tasks,
                self.parts.fallback.clone(),
                req.clone(),
                cx,
            )
        });
        joined(handle).await
    }

    async fn run_query(
        &self,
        req: &Message,
        initiator: Initiator,
    ) -> (io::Result<Message>, Option<u64>) {
        let Some(query) = msg::first_query(req).cloned() else {
            return (
                Err(io::Error::other("should have one question at least")),
                None,
            );
        };
        let trace = Trace::new(&query, initiator);
        let cx = Cx { initiator };
        let result = tokio::time::timeout(DNS_TIMEOUT, async {
            if msg::is_ip_request(&query) {
                self.ip_exchange(req, cx).await.map(|batch| Batch {
                    cache: true,
                    ..batch
                })
            } else if let Some(matched) = self.matched_clients(req) {
                batch_exchange(&matched, req, cx).await
            } else {
                batch_exchange(&self.parts.main, req, cx).await
            }
        })
        .await
        .unwrap_or_else(|_| Err(timed_out()));
        match result {
            Ok(batch) => {
                if batch.cache {
                    self.store(&query, &batch.msg, &batch.upstream);
                }
                let id = trace.emit(self.events.as_ref(), Ok(&batch.msg), &batch.upstream, false);
                (Ok(batch.msg), id)
            }
            Err(err) => {
                let id = trace.emit(self.events.as_ref(), Err(&err), "", false);
                (Err(err), id)
            }
        }
    }

    fn join_flight(self: &Arc<Self>, req: &Message, initiator: Initiator, retry: bool) -> Flight {
        let Some(query) = msg::first_query(req) else {
            let (_, rx) = watch::channel(None);
            return rx;
        };
        let mut key = msg::cache_key(query);
        if initiator == Initiator::Proxy {
            key.insert(0, 'p');
        }
        // A node asking for its own server must not join the flight that dials it.
        for via in dialer::through().iter() {
            key.push('\t');
            key.push_str(via);
        }
        let mut flights = lock(&self.flights);
        if let Some(rx) = flights.get(&key) {
            return rx.clone();
        }
        let (tx, rx) = watch::channel(None);
        flights.insert(key.clone(), rx.clone());
        drop(flights);
        let group = Arc::clone(self);
        let request = req.clone();
        dialer::spawn(&self.parts.tasks, async move {
            let (result, id) = group.run_query(&request, initiator).await;
            {
                let mut flights = lock(&group.flights);
                flights.remove(&key);
            }
            let failed = result.is_err();
            tx.send_replace(Some((result.map(Arc::new).map_err(Arc::new), id)));
            if failed && retry {
                group.join_flight(&request, initiator, false);
            }
        });
        rx
    }

    async fn exchange_uncached(
        self: &Arc<Self>,
        req: &Message,
        initiator: Initiator,
    ) -> io::Result<Message> {
        let mut flight = self.join_flight(req, initiator, true);
        let outcome = flight
            .wait_for(Option::is_some)
            .await
            .map_err(|_| io::Error::other("dns query was dropped"))?
            .clone();
        let Some((result, id)) = outcome else {
            return Err(io::Error::other("dns query was dropped"));
        };
        note_for(initiator, id);
        match result {
            Ok(message) => Ok((*message).clone()),
            Err(err) => Err(io::Error::new(err.kind(), Shared(err))),
        }
    }

    /// A fresh cache entry, or a stale one that a refresh was started for. The message is
    /// the cached one: its TTLs are those of the moment it was stored.
    fn hit(self: &Arc<Self>, req: &Message, initiator: Initiator) -> Option<(Arc<Message>, Age)> {
        let query = msg::first_query(req)?;
        let (cached, expire, upstream) = self.cached(query)?;
        let now = Instant::now();
        let age = if expire < now {
            self.join_flight(req, initiator, false);
            Age::Stale
        } else {
            Age::Remaining(u32::try_from(expire.duration_since(now).as_secs()).unwrap_or(u32::MAX))
        };
        if self.events.enabled() {
            let id = Trace::new(query, initiator).emit(
                self.events.as_ref(),
                Ok(&cached),
                &upstream,
                true,
            );
            note_for(initiator, id);
        }
        Some((cached, age))
    }

    /// `ExchangeContext`: the cache first, a stale entry is answered with TTL 1
    /// and refreshed behind the caller.
    pub(crate) async fn exchange(
        self: &Arc<Self>,
        req: &Message,
        initiator: Initiator,
    ) -> io::Result<Message> {
        if msg::first_query(req).is_none() {
            return Err(io::Error::other("should have one question at least"));
        }
        let Some((cached, age)) = self.hit(req, initiator) else {
            let mut resp = self.exchange_uncached(req, initiator).await?;
            resp.metadata.id = req.metadata.id;
            return Ok(resp);
        };
        let mut owned = Message::clone(&cached);
        match age {
            Age::Stale => msg::set_msg_ttl(&mut owned, 1),
            Age::Remaining(remaining) => msg::update_msg_ttl(&mut owned, remaining),
        }
        owned.metadata.id = req.metadata.id;
        Ok(owned)
    }

    /// As `exchange`, for a caller that only reads the answer: a cache hit is read in
    /// place, without the copy `exchange` patches TTLs and the id into.
    pub(crate) async fn exchange_with<R>(
        self: &Arc<Self>,
        req: &Message,
        initiator: Initiator,
        read: impl FnOnce(&Message) -> R + Send,
    ) -> io::Result<R> {
        if msg::first_query(req).is_none() {
            return Err(io::Error::other("should have one question at least"));
        }
        if let Some((cached, _)) = self.hit(req, initiator) {
            return Ok(read(&cached));
        }
        let resp = self.exchange_uncached(req, initiator).await?;
        Ok(read(&resp))
    }

    async fn lookup_one(
        self: &Arc<Self>,
        host: &str,
        record_type: RecordType,
        initiator: Initiator,
    ) -> io::Result<Vec<IpAddr>> {
        let query = msg::build_query(host, record_type)
            .ok_or_else(|| CoreError::IpNotFound(host.to_string()))?;
        let ips = self
            .exchange_with(&query, initiator, |resp| {
                let mut ips = msg::answer_ips(resp);
                ips.retain(|ip| ip.is_ipv4() == (record_type == RecordType::A));
                ips
            })
            .await?;
        if ips.is_empty() {
            return Err(CoreError::IpNotFound(host.to_string()).into());
        }
        Ok(ips)
    }

    pub(crate) async fn lookup_v4(
        self: &Arc<Self>,
        host: &str,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        Ok(LookupIps {
            v4: self.lookup_one(host, RecordType::A, initiator).await?,
            v6: Vec::new(),
        })
    }

    pub(crate) async fn lookup_v6(
        self: &Arc<Self>,
        host: &str,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        Ok(LookupIps {
            v4: Vec::new(),
            v6: self.lookup_one(host, RecordType::AAAA, initiator).await?,
        })
    }

    /// A and AAAA at once; the AAAA answer is waited for only `ipv6-timeout`
    /// (100 ms by default) after the A answer.
    pub(crate) async fn lookup_dual(
        self: &Arc<Self>,
        host: &str,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        let group = Arc::clone(self);
        let name = host.to_string();
        let v6_task = dialer::spawn(
            &self.parts.tasks,
            query_trail::on_trail(async move {
                group.lookup_one(&name, RecordType::AAAA, initiator).await
            }),
        );
        let v4 = self.lookup_one(host, RecordType::A, initiator).await;
        let wait = if self.parts.ipv6_timeout.is_zero() {
            DEFAULT_IPV6_WAIT
        } else {
            self.parts.ipv6_timeout
        };
        let v6 = match tokio::time::timeout(wait, v6_task).await {
            Ok(Ok(Some(Ok(ips)))) => ips,
            _ => Vec::new(),
        };
        match v4 {
            Ok(v4) => Ok(LookupIps { v4, v6 }),
            Err(_) if !v6.is_empty() => Ok(LookupIps { v4: Vec::new(), v6 }),
            Err(err) => Err(err),
        }
    }

    pub(crate) async fn lookup_ips(
        self: &Arc<Self>,
        host: &str,
        ipv6: bool,
        cx: Cx,
    ) -> io::Result<Vec<IpAddr>> {
        let initiator = if cx.initiator == Initiator::Proxy {
            Initiator::Proxy
        } else {
            Initiator::Other
        };
        let found = if ipv6 {
            self.lookup_dual(host, initiator).await?
        } else {
            self.lookup_v4(host, initiator).await?
        };
        Ok(found.v4.into_iter().chain(found.v6).collect())
    }
}

/// A node's lookup of its own server is the node's, not the connection's.
fn note_for(initiator: Initiator, id: Option<u64>) {
    if let Some(id) = id
        && initiator != Initiator::Proxy
    {
        query_trail::note_query(id);
    }
}
