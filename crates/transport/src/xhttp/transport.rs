use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use concord_common::Tasks;
use concord_common::sync::lock;
use futures_util::future::BoxFuture;
use h2::client::SendRequest;
use http::{Method, Request};
use tokio::io::AsyncReadExt;

use super::config::{Range, XhttpReuse, parse_range};
use super::h1::H1Transport;
use super::h3::{H3Transport, QuicDialFn};
use super::request::Built;
use super::{BoxRead, BoxWrite};
use crate::DialFn;
use crate::h2io::{
    ClientSlot, H2Reader, H2Writer, Incoming, StreamGuard, client_builder, h2_io_error,
};
use crate::http1::invalid;

const CHROME_H2_KEEP_ALIVE: Duration = Duration::from_secs(45);

/// What the client needs to hear from one HTTP request: the status, and the body
/// when it is a stream.
pub(crate) type Pending = BoxFuture<'static, io::Result<(u16, BoxRead)>>;

pub(crate) struct H2Transport {
    dial: DialFn,
    tasks: Tasks,
    keep_alive: Option<Duration>,
    slot: ClientSlot,
}

impl H2Transport {
    async fn sender(&self) -> io::Result<SendRequest<Bytes>> {
        self.slot
            .ready_sender(&self.dial, &client_builder(), &self.tasks, self.keep_alive)
            .await
            .map(|(sender, _)| sender)
    }

    fn request(req: &Built) -> io::Result<Request<()>> {
        let mut builder = Request::builder()
            .method(
                Method::from_bytes(req.method.as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            )
            .uri(format!("https://{}{}", req.host, req.path_and_query()));
        for (key, value) in req.headers.iter() {
            if key.eq_ignore_ascii_case("host") {
                continue;
            }
            builder = builder.header(key, value);
        }
        builder
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    async fn fixed(&self, req: &Built, body: Vec<u8>) -> io::Result<u16> {
        let mut sender = self.sender().await?;
        let empty = body.is_empty();
        let (response, mut send) = sender
            .send_request(Self::request(req)?, empty)
            .map_err(h2_io_error)?;
        if !empty {
            send.send_data(Bytes::from(body), true)
                .map_err(h2_io_error)?;
        }
        let response = response.await.map_err(h2_io_error)?;
        let status = response.status().as_u16();
        let mut reader = H2Reader::new(Incoming::Body(response.into_body()));
        let mut sink = [0u8; 1024];
        while reader.read(&mut sink).await? > 0 {}
        Ok(status)
    }

    async fn start_download(&self, req: &Built) -> io::Result<Pending> {
        let mut sender = self.sender().await?;
        let (response, _) = sender
            .send_request(Self::request(req)?, true)
            .map_err(h2_io_error)?;
        Ok(Box::pin(async move {
            let response = response.await.map_err(h2_io_error)?;
            let status = response.status().as_u16();
            let body: BoxRead = Box::new(H2Reader::new(Incoming::Body(response.into_body())));
            Ok((status, body))
        }))
    }

    async fn stream(&self, req: &Built) -> io::Result<(BoxWrite, Pending)> {
        let mut sender = self.sender().await?;
        let (response, send) = sender
            .send_request(Self::request(req)?, false)
            .map_err(h2_io_error)?;
        let pending: Pending = Box::pin(async move {
            let response = response.await.map_err(h2_io_error)?;
            let status = response.status().as_u16();
            let body: BoxRead = Box::new(H2Reader::new(Incoming::Body(response.into_body())));
            Ok((status, body))
        });
        Ok((Box::new(H2Writer::new(send)), pending))
    }
}

pub(crate) enum Transport {
    H2(H2Transport),
    H1(H1Transport),
    H3(H3Transport),
}

impl Transport {
    pub fn h3(dial: QuicDialFn, tasks: Tasks) -> Arc<Self> {
        Arc::new(Self::H3(H3Transport::new(dial, tasks)))
    }
    /// `period` is `h-keep-alive-period`: 0 keeps Chrome's 45 s, negative turns pings off.
    pub fn new(http1: bool, dial: DialFn, period: i64, tasks: Tasks) -> Arc<Transport> {
        if http1 {
            return Arc::new(Transport::H1(H1Transport::new(dial)));
        }
        let keep_alive = match period {
            0 => Some(CHROME_H2_KEEP_ALIVE),
            p if p < 0 => None,
            p => Some(Duration::from_secs(p.unsigned_abs())),
        };
        Arc::new(Transport::H2(H2Transport {
            dial,
            tasks,
            keep_alive,
            slot: ClientSlot::new(),
        }))
    }

    pub async fn fixed(&self, req: &Built, body: Vec<u8>) -> io::Result<u16> {
        match self {
            Transport::H2(t) => t.fixed(req, body).await,
            Transport::H1(t) => t.fixed(req, body).await,
            Transport::H3(t) => t.fixed(req, body).await,
        }
    }

    pub async fn start_download(&self, req: &Built) -> io::Result<Pending> {
        match self {
            Transport::H2(t) => t.start_download(req).await,
            Transport::H1(t) => t.download(req).await,
            Transport::H3(t) => t.download(req).await,
        }
    }

    pub async fn stream(&self, req: &Built) -> io::Result<(BoxWrite, Pending)> {
        match self {
            Transport::H2(t) => t.stream(req).await,
            Transport::H1(t) => t.stream(req).await,
            Transport::H3(t) => t.stream(req).await,
        }
    }

    fn close(&self) {
        if let Transport::H3(t) = self {
            t.close();
        }
        if let Transport::H2(t) = self {
            t.slot.close();
        }
    }

    fn has_h2_capacity(&self, need: usize) -> bool {
        match self {
            Transport::H2(t) => t.slot.has_capacity_for(need),
            Transport::H1(_) | Transport::H3(_) => true,
        }
    }

    fn reserve_h2_streams(&self, count: usize) -> Option<StreamGuard> {
        match self {
            Transport::H2(t) => Some(t.slot.reserve_streams(count)),
            Transport::H1(_) | Transport::H3(_) => None,
        }
    }

    fn is_dead(&self) -> bool {
        match self {
            Transport::H2(t) => t.slot.is_dead(),
            Transport::H1(_) | Transport::H3(_) => false,
        }
    }
}

struct Entry {
    transport: Arc<Transport>,
    open_usage: AtomicI32,
    left_requests: AtomicI32,
    reuse_count: AtomicI32,
    max_reuse_times: i32,
    unreusable_at: Option<Instant>,
    closed: AtomicBool,
}

impl Entry {
    fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.transport.close();
        }
    }

    fn release(&self) {
        let remaining = self.open_usage.fetch_sub(1, Ordering::SeqCst) - 1;
        if remaining < 0 {
            self.open_usage.store(0, Ordering::SeqCst);
        }
        if remaining <= 0 {
            let expired = self.unreusable_at.is_some_and(|t| Instant::now() > t);
            if self.left_requests.load(Ordering::SeqCst) <= 0
                || (self.max_reuse_times > 0
                    && self.reuse_count.load(Ordering::SeqCst) >= self.max_reuse_times)
                || expired
            {
                self.close();
            }
        }
    }
}

/// A transport on loan, which counts against its entry until dropped.
pub(crate) struct Lease {
    transport: Arc<Transport>,
    entry: Option<Arc<Entry>>,
    _reserved: Option<StreamGuard>,
}

impl Lease {
    pub fn owned(transport: Arc<Transport>) -> Lease {
        Lease {
            transport,
            entry: None,
            _reserved: None,
        }
    }

    pub fn shared(&self) -> Arc<Transport> {
        self.transport.clone()
    }
}

impl Deref for Lease {
    type Target = Transport;

    fn deref(&self) -> &Transport {
        &self.transport
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self._reserved = None;
        if let Some(entry) = &self.entry {
            entry.release();
        }
    }
}

pub(crate) type Maker = Arc<dyn Fn() -> Arc<Transport> + Send + Sync>;

/// `xhttp.ReuseManager`: XMUX, which decides when a dial may share a connection.
pub(crate) struct ReuseManager {
    max_concurrency: usize,
    max_connections: usize,
    c_max_reuse_times: Range,
    h_max_request_times: Range,
    h_max_reusable_secs: Range,
    maker: Maker,
    entries: Mutex<Vec<Arc<Entry>>>,
}

impl ReuseManager {
    pub fn new(cfg: &XhttpReuse, maker: Maker) -> io::Result<ReuseManager> {
        let parse = |name: &str, value: &str| {
            parse_range(value, "0").map_err(|e| invalid(format!("invalid {name}: {e}")))
        };
        Ok(ReuseManager {
            max_concurrency: parse("max-concurrency", &cfg.max_concurrency)?.rand(),
            max_connections: parse("max-connections", &cfg.max_connections)?.rand(),
            c_max_reuse_times: parse("c-max-reuse-times", &cfg.c_max_reuse_times)?,
            h_max_request_times: parse("h-max-request-times", &cfg.h_max_request_times)?,
            h_max_reusable_secs: parse("h-max-reusable-secs", &cfg.h_max_reusable_secs)?,
            maker,
            entries: Mutex::new(Vec::new()),
        })
    }

    pub fn close(&self) {
        for entry in lock(&self.entries).drain(..) {
            entry.close();
        }
    }

    fn cleanup(entries: &mut Vec<Arc<Entry>>, now: Instant) {
        entries.retain(|entry| {
            if entry.closed.load(Ordering::SeqCst) {
                return false;
            }
            if entry.transport.is_dead() {
                entry.close();
                return false;
            }
            let idle = entry.open_usage.load(Ordering::SeqCst) == 0;
            if (entry.left_requests.load(Ordering::SeqCst) <= 0 && idle)
                || (idle && entry.unreusable_at.is_some_and(|t| now > t))
            {
                entry.close();
                return false;
            }
            true
        });
    }

    fn pick(&self, entries: &[Arc<Entry>], need: usize) -> Option<Arc<Entry>> {
        let mut best: Option<&Arc<Entry>> = None;
        for entry in entries {
            if entry.closed.load(Ordering::SeqCst)
                || entry.transport.is_dead()
                || entry.left_requests.load(Ordering::SeqCst) <= 0
                || (entry.max_reuse_times > 0
                    && entry.reuse_count.load(Ordering::SeqCst) >= entry.max_reuse_times)
                || (self.max_concurrency > 0
                    && usize::try_from(entry.open_usage.load(Ordering::SeqCst))
                        .is_ok_and(|n| n >= self.max_concurrency))
                || !entry.transport.has_h2_capacity(need)
            {
                continue;
            }
            if best.is_none_or(|b| {
                entry.open_usage.load(Ordering::SeqCst) < b.open_usage.load(Ordering::SeqCst)
            }) {
                best = Some(entry);
            }
        }
        best.cloned()
    }

    pub fn lease(&self, need: usize) -> Lease {
        let now = Instant::now();
        let mut entries = lock(&self.entries);
        Self::cleanup(&mut entries, now);
        let should_create = entries.is_empty()
            || (self.max_connections > 0 && entries.len() < self.max_connections);
        let picked = if should_create {
            None
        } else {
            self.pick(&entries, need)
        };
        let reused = picked.is_some();
        let entry = picked.unwrap_or_else(|| {
            let entry = Arc::new(Entry {
                transport: (self.maker)(),
                open_usage: AtomicI32::new(0),
                left_requests: AtomicI32::new(if self.h_max_request_times.max > 0 {
                    i32::try_from(self.h_max_request_times.rand()).unwrap_or(i32::MAX)
                } else {
                    (1 << 30) - 1
                }),
                reuse_count: AtomicI32::new(0),
                max_reuse_times: if self.c_max_reuse_times.max > 0 {
                    i32::try_from(self.c_max_reuse_times.rand()).unwrap_or(i32::MAX)
                } else {
                    0
                },
                unreusable_at: (self.h_max_reusable_secs.max > 0)
                    .then(|| now + Duration::from_secs(self.h_max_reusable_secs.rand() as u64)),
                closed: AtomicBool::new(false),
            });
            entries.push(entry.clone());
            entry
        });
        if reused {
            entry.reuse_count.fetch_add(1, Ordering::SeqCst);
        }
        entry.open_usage.fetch_add(1, Ordering::SeqCst);
        if entry.left_requests.load(Ordering::SeqCst) > 0 {
            entry.left_requests.fetch_sub(1, Ordering::SeqCst);
        }
        let reserved = entry.transport.reserve_h2_streams(need);
        Lease {
            transport: entry.transport.clone(),
            entry: Some(entry),
            _reserved: reserved,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    fn manager(reuse: XhttpReuse) -> (ReuseManager, Arc<AtomicUsize>) {
        let made = Arc::new(AtomicUsize::new(0));
        let counter = made.clone();
        let dial: DialFn = Arc::new(|| Box::pin(async { Err(io::Error::other("unused")) }));
        let maker: Maker = Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Transport::new(false, dial.clone(), 0, Default::default())
        });
        (ReuseManager::new(&reuse, maker).unwrap(), made)
    }

    #[tokio::test]
    async fn without_limits_everything_shares_one_transport() {
        let (m, made) = manager(XhttpReuse::default());
        let leases: Vec<Lease> = (0..5).map(|_| m.lease(1)).collect();
        assert_eq!(made.load(Ordering::SeqCst), 1);
        drop(leases);
    }

    #[tokio::test]
    async fn max_concurrency_spills_to_a_new_transport() {
        let (m, made) = manager(XhttpReuse {
            max_concurrency: "2".into(),
            ..XhttpReuse::default()
        });
        let a: Vec<Lease> = (0..2).map(|_| m.lease(1)).collect();
        assert_eq!(made.load(Ordering::SeqCst), 1);
        let _third = m.lease(1);
        assert_eq!(made.load(Ordering::SeqCst), 2);
        drop(a);
    }

    #[tokio::test]
    async fn max_connections_creates_up_to_the_bound_first() {
        let (m, made) = manager(XhttpReuse {
            max_connections: "3".into(),
            ..XhttpReuse::default()
        });
        let leases: Vec<Lease> = (0..5).map(|_| m.lease(1)).collect();
        assert_eq!(made.load(Ordering::SeqCst), 3);
        drop(leases);
    }

    #[tokio::test]
    async fn h_max_request_times_retires_a_transport() {
        let (m, made) = manager(XhttpReuse {
            h_max_request_times: "2".into(),
            ..XhttpReuse::default()
        });
        drop(m.lease(1));
        drop(m.lease(1));
        assert_eq!(made.load(Ordering::SeqCst), 1);
        drop(m.lease(1));
        assert_eq!(made.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn c_max_reuse_times_stops_sharing() {
        let (m, made) = manager(XhttpReuse {
            c_max_reuse_times: "1".into(),
            ..XhttpReuse::default()
        });
        let _a = m.lease(1);
        let _b = m.lease(1);
        assert_eq!(made.load(Ordering::SeqCst), 1);
        let _c = m.lease(1);
        assert_eq!(made.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn invalid_reuse_settings_are_rejected() {
        let dial: DialFn = Arc::new(|| Box::pin(async { Err(io::Error::other("unused")) }));
        let maker: Maker =
            Arc::new(move || Transport::new(false, dial.clone(), 0, Default::default()));
        let bad = XhttpReuse {
            max_connections: "x".into(),
            ..XhttpReuse::default()
        };
        assert!(ReuseManager::new(&bad, maker).is_err());
    }

    #[tokio::test]
    async fn h2_reuse_opens_another_transport_at_peer_stream_limit() {
        use tokio::io::{AsyncWriteExt, duplex};

        let connections = Arc::new(AtomicUsize::new(0));
        let dial: DialFn = {
            let connections = connections.clone();
            Arc::new(move || {
                let connections = connections.clone();
                Box::pin(async move {
                    let (near, far) = duplex(1 << 20);
                    connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let Ok(mut conn) = h2::server::Builder::new()
                            .max_concurrent_streams(2)
                            .handshake::<_, Bytes>(far)
                            .await
                        else {
                            return;
                        };
                        while let Some(Ok((request, mut respond))) = conn.accept().await {
                            tokio::spawn(async move {
                                let mut body = request.into_body();
                                let Ok(mut send) = respond.send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                    false,
                                ) else {
                                    return;
                                };
                                while let Some(Ok(chunk)) = body.data().await {
                                    let _ = body.flow_control().release_capacity(chunk.len());
                                    if send.send_data(chunk, false).is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    });
                    Ok(Box::new(near) as concord_common::BoxStream)
                })
            })
        };
        let maker: Maker =
            Arc::new(move || Transport::new(false, dial.clone(), 0, Default::default()));
        let manager = ReuseManager::new(&XhttpReuse::default(), maker).unwrap();
        let req = Built::test_new(
            "POST",
            "example.com",
            "/x",
            crate::http1::HeaderMap::default(),
        );
        let mut held = Vec::new();
        for idx in 0..3u8 {
            let (lease, wr, rd) = tokio::time::timeout(Duration::from_secs(2), async {
                let lease = manager.lease(1);
                let (mut wr, pending) = lease.stream(&req).await.unwrap();
                wr.write_all(&[idx]).await.unwrap();
                let (status, mut rd) = pending.await.unwrap();
                assert_eq!(status, 200);
                let mut back = [0u8; 1];
                rd.read_exact(&mut back).await.unwrap();
                assert_eq!(back[0], idx);
                (lease, wr, rd)
            })
            .await
            .expect("xhttp h2 stream stalled past peer concurrent-stream limit");
            held.push((lease, wr, rd));
        }
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        drop(held);
    }

    #[tokio::test]
    async fn h2_reuse_counts_two_streams_per_lease_in_split_upload_download_mode() {
        use tokio::io::{AsyncWriteExt, duplex};

        let connections = Arc::new(AtomicUsize::new(0));
        let dial: DialFn = {
            let connections = connections.clone();
            Arc::new(move || {
                let connections = connections.clone();
                Box::pin(async move {
                    let (near, far) = duplex(1 << 20);
                    connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let Ok(mut conn) = h2::server::Builder::new()
                            .max_concurrent_streams(2)
                            .handshake::<_, Bytes>(far)
                            .await
                        else {
                            return;
                        };
                        while let Some(Ok((request, mut respond))) = conn.accept().await {
                            tokio::spawn(async move {
                                let is_get = request.method() == http::Method::GET;
                                let mut body = request.into_body();
                                let Ok(mut send) = respond.send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                    false,
                                ) else {
                                    return;
                                };
                                if is_get {
                                    let _ = send.send_data(Bytes::from_static(b"d"), false);
                                    std::future::pending::<()>().await;
                                }
                                while let Some(Ok(chunk)) = body.data().await {
                                    let _ = body.flow_control().release_capacity(chunk.len());
                                    if send.send_data(chunk, false).is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    });
                    Ok(Box::new(near) as concord_common::BoxStream)
                })
            })
        };
        let maker: Maker =
            Arc::new(move || Transport::new(false, dial.clone(), 0, Default::default()));
        let manager = ReuseManager::new(&XhttpReuse::default(), maker).unwrap();
        let get = Built::test_new(
            "GET",
            "example.com",
            "/x",
            crate::http1::HeaderMap::default(),
        );
        let post = Built::test_new(
            "POST",
            "example.com",
            "/x",
            crate::http1::HeaderMap::default(),
        );

        let lease1 = manager.lease(2);
        let download1 = lease1.start_download(&get).await.unwrap();
        let (status, mut dl_rd1) = download1.await.unwrap();
        assert_eq!(status, 200);
        let mut mark = [0u8; 1];
        dl_rd1.read_exact(&mut mark).await.unwrap();
        assert_eq!(&mark, b"d");

        let upload1 = Lease::owned(lease1.shared());
        let (mut up_wr1, up_pending1) = upload1.stream(&post).await.unwrap();
        up_wr1.write_all(b"u").await.unwrap();
        let (up_status, mut up_rd1) = up_pending1.await.unwrap();
        assert_eq!(up_status, 200);
        up_rd1.read_exact(&mut mark).await.unwrap();
        assert_eq!(&mark, b"u");
        assert_eq!(connections.load(Ordering::SeqCst), 1);

        let lease2 = manager.lease(2);
        let (up_wr2, up_pending2) = tokio::time::timeout(Duration::from_secs(2), async {
            let (mut wr, pending) = lease2.stream(&post).await.unwrap();
            wr.write_all(b"2").await.unwrap();
            let (status, mut rd) = pending.await.unwrap();
            assert_eq!(status, 200);
            let mut back = [0u8; 1];
            rd.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"2");
            (wr, rd)
        })
        .await
        .expect("second lease stalled after first split lease filled peer stream limit");
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        drop((
            lease1,
            dl_rd1,
            upload1,
            up_wr1,
            up_rd1,
            lease2,
            up_wr2,
            up_pending2,
        ));
    }

    #[tokio::test]
    async fn h2_reuse_packet_up_reserves_upload_stream_slot_at_lease_time() {
        use tokio::io::duplex;

        let connections = Arc::new(AtomicUsize::new(0));
        let dial: DialFn = {
            let connections = connections.clone();
            Arc::new(move || {
                let connections = connections.clone();
                Box::pin(async move {
                    let (near, far) = duplex(1 << 20);
                    connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let Ok(mut conn) = h2::server::Builder::new()
                            .max_concurrent_streams(2)
                            .handshake::<_, Bytes>(far)
                            .await
                        else {
                            return;
                        };
                        while let Some(Ok((request, mut respond))) = conn.accept().await {
                            tokio::spawn(async move {
                                let is_get = request.method() == http::Method::GET;
                                let mut body = request.into_body();
                                if is_get {
                                    let Ok(mut send) = respond.send_response(
                                        http::Response::builder().status(200).body(()).unwrap(),
                                        false,
                                    ) else {
                                        return;
                                    };
                                    let _ = send.send_data(Bytes::from_static(b"d"), false);
                                    std::future::pending::<()>().await;
                                }
                                while let Some(Ok(chunk)) = body.data().await {
                                    let _ = body.flow_control().release_capacity(chunk.len());
                                }
                                let _ = respond.send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                    true,
                                );
                            });
                        }
                    });
                    Ok(Box::new(near) as concord_common::BoxStream)
                })
            })
        };
        let maker: Maker =
            Arc::new(move || Transport::new(false, dial.clone(), 0, Default::default()));
        let manager = ReuseManager::new(&XhttpReuse::default(), maker).unwrap();
        let get = Built::test_new(
            "GET",
            "example.com",
            "/x",
            crate::http1::HeaderMap::default(),
        );
        let post = Built::test_new(
            "POST",
            "example.com",
            "/x",
            crate::http1::HeaderMap::default(),
        );

        let lease1 = manager.lease(2);
        let download1 = lease1.start_download(&get).await.unwrap();
        let (status, mut dl_rd1) = download1.await.unwrap();
        assert_eq!(status, 200);
        let mut mark = [0u8; 1];
        dl_rd1.read_exact(&mut mark).await.unwrap();
        assert_eq!(&mark, b"d");

        let lease2 = manager.lease(2);
        let download2 = lease2.start_download(&get).await.unwrap();
        let (status, mut dl_rd2) = download2.await.unwrap();
        assert_eq!(status, 200);
        dl_rd2.read_exact(&mut mark).await.unwrap();
        assert_eq!(&mark, b"d");
        assert_eq!(connections.load(Ordering::SeqCst), 2);

        let upload1 = Lease::owned(lease1.shared());
        let post_status =
            tokio::time::timeout(Duration::from_secs(2), upload1.fixed(&post, b"p".to_vec()))
                .await
                .expect("packet-up POST stalled behind another lease's GET")
                .unwrap();
        assert_eq!(post_status, 200);

        drop((upload1, dl_rd1, lease1));
        let lease3 = manager.lease(2);
        let download3 = lease3.start_download(&get).await.unwrap();
        let (status, mut dl_rd3) = download3.await.unwrap();
        assert_eq!(status, 200);
        dl_rd3.read_exact(&mut mark).await.unwrap();
        assert_eq!(&mark, b"d");
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        drop((dl_rd2, lease2, dl_rd3, lease3));
    }

    #[tokio::test]
    async fn h2_reuse_evicts_a_poisoned_transport() {
        use std::task::Context;
        use tokio::io::{AsyncWriteExt, duplex};

        let connections = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let dial: DialFn = {
            let connections = connections.clone();
            let release = release.clone();
            Arc::new(move || {
                let connections = connections.clone();
                let release = release.clone();
                Box::pin(async move {
                    let (near, far) = duplex(1 << 20);
                    let idx = connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let Ok(mut conn) =
                            h2::server::Builder::new().handshake::<_, Bytes>(far).await
                        else {
                            return;
                        };
                        if idx == 0 {
                            if let Some(Ok((_req, mut respond))) = conn.accept().await {
                                release.notified().await;
                                let _ = respond.send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                    false,
                                );
                                while conn.accept().await.is_some() {}
                            }
                            return;
                        }
                        while let Some(Ok((request, mut respond))) = conn.accept().await {
                            tokio::spawn(async move {
                                let mut body = request.into_body();
                                let Ok(mut send) = respond.send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                    false,
                                ) else {
                                    return;
                                };
                                while let Some(Ok(chunk)) = body.data().await {
                                    let _ = body.flow_control().release_capacity(chunk.len());
                                    if send.send_data(chunk, false).is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    });
                    Ok(Box::new(near) as concord_common::BoxStream)
                })
            })
        };
        let maker: Maker =
            Arc::new(move || Transport::new(false, dial.clone(), 0, Default::default()));
        let manager = ReuseManager::new(&XhttpReuse::default(), maker).unwrap();
        let req = Built::test_new(
            "POST",
            "example.com",
            "/x",
            crate::http1::HeaderMap::default(),
        );
        let first_lease = manager.lease(1);
        let (first_wr, mut first_pending) = first_lease.stream(&req).await.unwrap();
        let waker = crate::h2io::tests::panic_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(first_pending.as_mut().poll(&mut cx).is_pending());
        release.notify_one();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let second_lease = manager.lease(1);
        let (mut wr, pending) = second_lease.stream(&req).await.unwrap();
        wr.write_all(b"k").await.unwrap();
        let (status, mut rd) = pending.await.unwrap();
        assert_eq!(status, 200);
        let mut back = [0u8; 1];
        rd.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"k");
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            drop((first_wr, first_pending, first_lease))
        }));
    }
}
