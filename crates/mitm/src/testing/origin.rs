use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use concord_common::sync::lock;
use http::{HeaderMap, Request, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::{http1 as server1, http2 as server2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Debug)]
pub(crate) struct Seen {
    #[cfg_attr(
        not(feature = "script"),
        expect(dead_code, reason = "only the QuickJS tests read it")
    )]
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub version: Version,
}

pub(crate) struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn ok(body: &str) -> Reply {
        Reply {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    pub fn with(mut self, name: &str, value: &str) -> Reply {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

pub(crate) type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// Answers `host|path|x-added|body` of what it was sent, marked `X-Upstream: yes`.
pub(crate) fn echo() -> Handler {
    Arc::new(|seen| {
        let added = seen
            .headers
            .get("x-added")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        Reply::ok(&format!(
            "{}|{}|{added}|{}",
            seen.host,
            seen.path,
            String::from_utf8_lossy(&seen.body)
        ))
        .with("X-Upstream", "yes")
    })
}

pub(crate) struct TestServer {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    pub connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub fn requests(&self) -> Vec<Seen> {
        lock(&self.seen).clone()
    }
}

fn server_tls(alpn: &[&str]) -> TlsAcceptor {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let key = PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .unwrap();
    config.alpn_protocols = alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect();
    TlsAcceptor::from(Arc::new(config))
}

async fn answer(
    mut request: Request<Incoming>,
    seen: Arc<Mutex<Vec<Seen>>>,
    handler: Handler,
) -> Result<http::Response<Full<Bytes>>, io::Error> {
    let upgrading = request.headers().contains_key(http::header::UPGRADE);
    let upgrade = upgrading.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map_err(io::Error::other)?
        .to_bytes()
        .to_vec();
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.authority().map(|authority| authority.to_string()))
        .unwrap_or_default();
    let record = Seen {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), ToString::to_string),
        host,
        headers: parts.headers.clone(),
        body,
        version: parts.version,
    };
    lock(&seen).push(record.clone());
    if let Some(upgrade) = upgrade {
        tokio::spawn(async move {
            if let Ok(upgraded) = upgrade.await {
                let mut io = TokioIo::new(upgraded);
                let mut buf = [0u8; 1024];
                while let Ok(read) = io.read(&mut buf).await {
                    if read == 0 || io.write_all(&buf[..read]).await.is_err() {
                        break;
                    }
                }
            }
        });
        return Ok(http::Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    let reply = handler(&record);
    let mut response = http::Response::builder().status(reply.status);
    for (name, value) in &reply.headers {
        response = response.header(name, value);
    }
    Ok(response.body(Full::new(Bytes::from(reply.body))).unwrap())
}

#[allow(
    clippy::disallowed_methods,
    reason = "a loopback server for the tests, not a proxied socket"
)]
pub(crate) async fn start_server(tls: bool, alpn: &[&str], handler: Handler) -> TestServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let acceptor = tls.then(|| server_tls(alpn));
    let task = tokio::spawn({
        let (seen, connections) = (seen.clone(), connections.clone());
        async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let (seen, handler, acceptor) = (seen.clone(), handler.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let service = |seen: Arc<Mutex<Vec<Seen>>>, handler: Handler| {
                        service_fn(move |request| answer(request, seen.clone(), handler.clone()))
                    };
                    match acceptor {
                        Some(acceptor) => {
                            let Ok(tls) = acceptor.accept(stream).await else {
                                return;
                            };
                            let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                            if h2 {
                                let _ = server2::Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls), service(seen, handler))
                                    .await;
                            } else {
                                let _ = server1::Builder::new()
                                    .serve_connection(TokioIo::new(tls), service(seen, handler))
                                    .with_upgrades()
                                    .await;
                            }
                        }
                        None => {
                            let _ = server1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service(seen, handler))
                                .with_upgrades()
                                .await;
                        }
                    }
                });
            }
        }
    });
    TestServer {
        addr,
        seen,
        connections,
        task,
    }
}

pub(crate) type ServiceBody = http_body_util::combinators::BoxBody<Bytes, io::Error>;

pub(crate) type Service = Arc<
    dyn Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = http::Response<ServiceBody>> + Send>>
        + Send
        + Sync,
>;

pub(crate) fn full_body(data: impl Into<Bytes>) -> ServiceBody {
    Full::new(data.into())
        .map_err(|never| match never {})
        .boxed()
}

/// A TLS server whose answers the test writes itself: streamed, held open or
/// with trailers.
#[allow(
    clippy::disallowed_methods,
    reason = "a loopback server for the tests, not a proxied socket"
)]
pub(crate) async fn start_service(alpn: &[&str], service: Service) -> TestServer {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let acceptor = server_tls(alpn);
    let task = tokio::spawn({
        let connections = connections.clone();
        async move {
            while let Ok((stream, _)) = listener.accept().await {
                connections.fetch_add(1, Ordering::SeqCst);
                let (service, acceptor) = (service.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    let serve = service_fn(move |request| {
                        let answer = service(request);
                        async move { Ok::<_, io::Error>(answer.await) }
                    });
                    if h2 {
                        let _ = server2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), serve)
                            .await;
                    } else {
                        let _ = server1::Builder::new()
                            .serve_connection(TokioIo::new(tls), serve)
                            .with_upgrades()
                            .await;
                    }
                });
            }
        }
    });
    TestServer {
        addr,
        seen: Arc::default(),
        connections,
        task,
    }
}
