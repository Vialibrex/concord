use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use concord_common::intercept::{
    ConnInterceptor, ConnMark, ConnTag, DialFailure, HeldConn, InterceptFlow, Offer, Reject, Route,
    RuleLabel, Upstream, UpstreamDialer, UpstreamRequest,
};
use concord_common::sync::lock;
use concord_common::{
    Address, ConnStep, ConnTiming, CoreEvent, EventSink, FlowMeta, InboundInfo, InboundKind,
    Network, ScriptNotification,
};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::{http1 as client1, http2 as client2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::config::RawConfig;
use crate::cron::UtcClock;
use crate::facade::{Mitm, MitmEnv};
use crate::script::ScriptRuntime;

mod origin;

pub(crate) use origin::{
    Handler, Reply, Service, TestServer, echo, full_body, start_server, start_service,
};

/// The first value of `name` in `list`, compared without case; empty when absent.
pub(crate) fn header_value(list: &crate::script::HeaderList, name: &str) -> String {
    list.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first().cloned())
        .unwrap_or_default()
}

/// The test dialer's connections all belong to this app.
pub(crate) const TEST_APP: &str = "test-app";

fn test_conn(id: String, seq: usize) -> Arc<ConnTag> {
    Arc::new(ConnTag {
        id,
        seq: seq as u64,
        process: TEST_APP.to_string(),
        ..ConnTag::default()
    })
}

pub(crate) struct TestHeld {
    conn: Arc<ConnTag>,
    pub mark: Mutex<Option<ConnMark>>,
    pub steps: Mutex<Vec<ConnStep>>,
}

impl HeldConn for TestHeld {
    fn conn(&self) -> &Arc<ConnTag> {
        &self.conn
    }

    fn release(&self, mark: ConnMark) {
        *lock(&self.mark) = Some(mark);
    }

    fn mark(&self, step: ConnStep) {
        lock(&self.steps).push(step);
    }
}

pub(crate) struct TestDialer {
    target: SocketAddr,
    pub flows: Mutex<Vec<(InterceptFlow, bool)>>,
    pub closed: Mutex<Vec<(String, Vec<String>)>>,
    pub closed_ids: Mutex<Vec<String>>,
    pub closed_rules: Mutex<Vec<Option<String>>>,
    rejected: Mutex<HashSet<String>>,
    routes: Mutex<HashMap<String, SocketAddr>>,
    /// URL substring, chain name, and the server it dials or none to reject.
    url_routes: Mutex<Vec<(String, String, Option<SocketAddr>)>>,
    /// The URL of every request routed, none for one routed without a request.
    pub routed: Mutex<Vec<Option<String>>>,
    pub held: Mutex<Vec<Arc<TestHeld>>>,
    next: AtomicUsize,
}

impl TestDialer {
    pub fn new(target: SocketAddr) -> Arc<TestDialer> {
        Arc::new(TestDialer {
            target,
            flows: Mutex::default(),
            closed: Mutex::default(),
            closed_ids: Mutex::default(),
            closed_rules: Mutex::default(),
            rejected: Mutex::default(),
            routes: Mutex::default(),
            url_routes: Mutex::default(),
            routed: Mutex::default(),
            held: Mutex::default(),
            next: AtomicUsize::new(1),
        })
    }

    pub fn reject(&self, host: &str) {
        lock(&self.rejected).insert(host.to_string());
    }

    pub fn route(&self, host: &str, target: SocketAddr) {
        lock(&self.routes).insert(host.to_string(), target);
    }

    /// Routes a request whose URL holds `needle` through `name`, rejecting it without a target.
    pub fn route_url(&self, needle: &str, name: &str, target: Option<SocketAddr>) {
        lock(&self.url_routes).push((needle.to_string(), name.to_string(), target));
    }

    pub fn dialed(&self) -> Vec<(String, u16)> {
        lock(&self.flows)
            .iter()
            .map(|(flow, _)| (crate::engine::host_of(flow), flow.port))
            .collect()
    }

    pub fn steps(&self) -> Vec<Vec<ConnStep>> {
        lock(&self.held)
            .iter()
            .map(|held| lock(&held.steps).clone())
            .collect()
    }

    pub fn marks(&self) -> Vec<Option<ConnMark>> {
        lock(&self.held)
            .iter()
            .map(|held| *lock(&held.mark))
            .collect()
    }
}

#[async_trait]
impl UpstreamDialer for TestDialer {
    async fn route(&self, request: &UpstreamRequest) -> Result<Route, DialFailure> {
        let host = crate::engine::host_of(&request.flow);
        let url = request.http.as_ref().map(|http| http.url.to_string());
        lock(&self.routed).push(url.clone());
        let by_url = url.as_deref().and_then(|url| {
            lock(&self.url_routes)
                .iter()
                .find(|(needle, ..)| url.contains(needle.as_str()))
                .cloned()
        });
        if let Some((needle, name, target)) = by_url {
            let rule = Some(RuleLabel {
                name: Arc::from("URLRegex"),
                payload: Arc::from(needle.as_str()),
                index: None,
            });
            let reject = match (target, name.as_str()) {
                (Some(_), _) => None,
                (None, "REJECT-DROP") => Some(Reject::Drop),
                (None, _) => Some(Reject::Reply),
            };
            return Ok(Route::new(
                Arc::from([Arc::from(name.as_str())]),
                rule,
                reject,
                false,
                Box::new(target),
            ));
        }
        let pending = !lock(&self.url_routes).is_empty() && url.is_none();
        if lock(&self.rejected).contains(&host) {
            lock(&self.flows).push((request.flow.clone(), request.hold));
            let rule = Some(RuleLabel {
                name: Arc::from("DOMAIN"),
                payload: Arc::from(host.as_str()),
                index: None,
            });
            return Ok(Route::new(
                Arc::from([Arc::from("REJECT")]),
                rule,
                Some(Reject::Reply),
                pending,
                Box::new(None::<SocketAddr>),
            ));
        }
        let target = lock(&self.routes).get(&host).copied();
        Ok(Route::new(
            Arc::from([Arc::from("DIRECT")]),
            None,
            None,
            pending,
            Box::new(Some(target.unwrap_or(self.target))),
        ))
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "the test dialer reaches a loopback server"
    )]
    async fn dial_routed(
        &self,
        request: UpstreamRequest,
        mut route: Route,
    ) -> Result<Upstream, DialFailure> {
        if route.reject.is_some() {
            return Err(DialFailure {
                error: io::Error::other("rejected by the rules"),
                ..route.rejected()
            });
        }
        lock(&self.flows).push((request.flow.clone(), request.hold));
        let target = route
            .take_plan()
            .and_then(|plan| plan.downcast::<Option<SocketAddr>>().ok())
            .and_then(|target| *target)
            .unwrap_or(self.target);
        let stream = tokio::net::TcpStream::connect(target).await?;
        let seq = self.next.fetch_add(1, Ordering::SeqCst);
        let conn = test_conn(format!("conn-{seq}"), seq);
        let held = request.hold.then(|| {
            let held = Arc::new(TestHeld {
                conn: conn.clone(),
                mark: Mutex::new(None),
                steps: Mutex::default(),
            });
            lock(&self.held).push(held.clone());
            held as Arc<dyn HeldConn>
        });
        Ok(Upstream {
            stream: Box::new(stream),
            conn: Some(conn),
            held,
        })
    }

    fn reads_http(&self, _flow: &InterceptFlow) -> bool {
        !lock(&self.url_routes).is_empty()
    }

    fn record_closed(
        &self,
        flow: &InterceptFlow,
        chain: &[Arc<str>],
        rule: Option<&RuleLabel>,
    ) -> Option<Arc<ConnTag>> {
        let seq = self.next.fetch_add(1, Ordering::SeqCst);
        let id = format!("closed-{seq}");
        lock(&self.closed).push((
            crate::engine::host_of(flow),
            chain.iter().map(ToString::to_string).collect(),
        ));
        lock(&self.closed_ids).push(id.clone());
        lock(&self.closed_rules).push(rule.map(|rule| format!("{},{}", rule.name, rule.payload)));
        Some(test_conn(id, seq))
    }
}

static SOURCE_PORT: AtomicU16 = AtomicU16::new(40000);

pub(crate) fn flow(host: &str, port: u16) -> InterceptFlow {
    flow_of(InboundKind::Tun, Address::new(host, port))
}

pub(crate) fn flow_of(kind: InboundKind, dst: Address) -> InterceptFlow {
    let (host, dst_ip) = match &dst {
        Address::Socket(addr) => (None, Some(addr.ip())),
        Address::Domain(name, _) => (Some(name.clone()), None),
    };
    let port = dst.port();
    InterceptFlow {
        meta: FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound: InboundInfo::new(kind),
            src: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                SOURCE_PORT.fetch_add(1, Ordering::SeqCst),
            ),
            dst,
        },
        host,
        sniffed: false,
        dst_ip,
        port,
        timing: ConnTiming::start(),
        dns_queries: Vec::new(),
    }
}

/// Keeps the scripts' notifications a rig's engine publishes.
#[derive(Default)]
pub(crate) struct Notices(Mutex<Vec<ScriptNotification>>);

impl Notices {
    pub fn taken(&self) -> Vec<ScriptNotification> {
        std::mem::take(&mut *lock(&self.0))
    }
}

impl EventSink for Notices {
    fn enabled(&self) -> bool {
        true
    }

    fn publish(&self, event: CoreEvent) {
        if let CoreEvent::ScriptNotification(notice) = event {
            lock(&self.0).push(notice);
        }
    }
}

pub(crate) struct Rig {
    pub mitm: Mitm,
    pub dialer: Arc<TestDialer>,
    pub notices: Arc<Notices>,
    _home: tempfile::TempDir,
    pub root: CertificateDer<'static>,
}

impl Rig {
    pub fn config(&self, value: serde_json::Value) -> Vec<String> {
        let raw: RawConfig = serde_json::from_value(value).unwrap();
        self.mitm.apply(Some(raw))
    }

    /// As `config`, with the engine running on `tasks`, as the host's apply does.
    pub fn config_on(&self, value: serde_json::Value, tasks: concord_common::Tasks) -> Vec<String> {
        let raw: RawConfig = serde_json::from_value(value).unwrap();
        self.mitm
            .apply_section(Some(concord_config::mitm::MitmDef::read(&raw)), tasks)
    }

    pub fn resources(&self) -> std::path::PathBuf {
        self.mitm.authority().resources_dir()
    }
}

pub(crate) fn rig_for(server: &TestServer, runtime: Option<Arc<dyn ScriptRuntime>>) -> Rig {
    let mut rig = rig_without_ca(server, runtime);
    let info = rig.mitm.generate_certificate().unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(info.pem.as_bytes()).unwrap();
    rig.root = CertificateDer::from(pem.contents);
    rig
}

pub(crate) fn rig_without_ca(server: &TestServer, runtime: Option<Arc<dyn ScriptRuntime>>) -> Rig {
    let home = tempfile::tempdir().unwrap();
    let dialer = TestDialer::new(server.addr);
    let notices = Arc::new(Notices::default());
    let mitm = Mitm::new(MitmEnv {
        home: Arc::new(HomeDir::new(home.path())),
        trust: TrustStore::new(&[], Vec::new()),
        dialer: dialer.clone(),
        clock: Arc::new(UtcClock),
        runtime,
        events: notices.clone(),
        tasks: concord_common::Tasks::default(),
    });
    Rig {
        mitm,
        dialer,
        notices,
        _home: home,
        root: CertificateDer::from(Vec::new()),
    }
}

pub(crate) enum Wire {
    H1(client1::SendRequest<Full<Bytes>>),
    H2(client2::SendRequest<Full<Bytes>>),
}

pub(crate) struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> String {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }
}

pub(crate) struct Client {
    pub wire: Wire,
    _offer: JoinHandle<Offer>,
    pub alpn: Option<Vec<u8>>,
    host: String,
}

pub(crate) fn client_config(
    root: &CertificateDer<'static>,
    alpn: &[&str],
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    Arc::new(config)
}

pub(crate) fn offer_on(
    interceptor: Arc<dyn ConnInterceptor>,
    flow: InterceptFlow,
) -> (tokio::io::DuplexStream, JoinHandle<Offer>) {
    let (near, far) = tokio::io::duplex(1 << 20);
    let offer =
        tokio::spawn(async move { interceptor.offer(&flow, Box::new(far), Vec::new()).await });
    (near, offer)
}

impl Client {
    pub async fn tls(rig: &Rig, host: &str, port: u16, alpn: &[&str]) -> io::Result<Client> {
        Self::tls_flow(rig, flow(host, port), host, alpn).await
    }

    pub async fn tls_flow(
        rig: &Rig,
        flow: InterceptFlow,
        server_name: &str,
        alpn: &[&str],
    ) -> io::Result<Client> {
        let (near, offer) = offer_on(rig.mitm.interceptor(), flow);
        let name = ServerName::try_from(server_name.to_string()).unwrap();
        let connector = TlsConnector::from(client_config(&rig.root, alpn));
        // A hello the section does not decrypt is left to the caller, which a test never relays.
        let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, near))
            .await
            .map_err(|_| io::Error::other("the TLS handshake got no answer"))??;
        let negotiated = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let wire = if negotiated.as_deref() == Some(b"h2") {
            let (sender, conn) = client2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(tls))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(conn);
            Wire::H2(sender)
        } else {
            let (sender, conn) = client1::handshake(TokioIo::new(tls))
                .await
                .map_err(io::Error::other)?;
            tokio::spawn(conn.with_upgrades());
            Wire::H1(sender)
        };
        Ok(Client {
            wire,
            _offer: offer,
            alpn: negotiated,
            host: server_name.to_string(),
        })
    }

    pub async fn plain(rig: &Rig, host: &str, port: u16) -> Client {
        let (near, offer) = offer_on(rig.mitm.interceptor(), flow(host, port));
        let (sender, conn) = client1::handshake(TokioIo::new(near)).await.unwrap();
        tokio::spawn(conn.with_upgrades());
        Client {
            wire: Wire::H1(sender),
            _offer: offer,
            alpn: None,
            host: host.to_string(),
        }
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Request<Full<Bytes>> {
        let h2 = matches!(self.wire, Wire::H2(_));
        let mut request = Request::builder().method(method);
        request = if h2 {
            request.uri(format!("https://{}{path}", self.host))
        } else {
            request.uri(path).header("Host", &self.host)
        };
        for (name, value) in headers {
            request = request.header(
                HeaderName::try_from(*name).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        request
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap()
    }

    pub async fn send(&mut self, request: Request<Full<Bytes>>) -> io::Result<Answer> {
        let response = match &mut self.wire {
            Wire::H1(sender) => sender.send_request(request).await,
            Wire::H2(sender) => sender.send_request(request).await,
        }
        .map_err(io::Error::other)?;
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes()
            .to_vec();
        Ok(Answer {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }

    pub async fn get(&mut self, path: &str) -> Answer {
        let request = self.request("GET", path, &[], "");
        self.send(request).await.unwrap()
    }
}
