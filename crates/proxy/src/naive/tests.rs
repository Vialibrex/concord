#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests use loopback peers and fixed wire shapes"
)]

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use concord_common::{DialCx, Initiator, Outbound};
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use concord_transport::h2io::{H2Body, Incoming};
use http::{HeaderMap, Response, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::testing::test_env;

#[derive(Clone, Copy)]
enum Answer {
    Padded,
    /// Padded, but from the second tunnel on the answer waits for the tunnel's first DATA frame.
    PaddedAfterData,
    /// Padded, with a graceful GOAWAY once the first tunnel is accepted.
    GoAwayAfterFirst,
    Plain,
    Status(u16),
}

#[derive(Default)]
struct Seen {
    connections: AtomicUsize,
    early_data: AtomicUsize,
    requests: Mutex<Vec<(String, HeaderMap)>>,
    preface: Mutex<Vec<u8>>,
}

struct Server {
    addr: SocketAddr,
    seen: Arc<Seen>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Keeps the first bytes the client sends after TLS.
struct Tee<S> {
    io: S,
    seen: Arc<Seen>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tee<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        let mut preface = this.seen.preface.lock().unwrap();
        if preface.len() < 4096 {
            preface.extend_from_slice(&buf.filled()[before..]);
        }
        polled
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Tee<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// A naive server that echoes every tunnel, framing it as `answer` says.
async fn server(answer: Answer) -> Server {
    let (mut tls, _) = concord_test_support::localhost_tls(rustls::DEFAULT_VERSIONS);
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let shared = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            shared.connections.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(serve(tcp, acceptor.clone(), answer, shared.clone()));
        }
    });
    Server { addr, seen, task }
}

async fn serve(tcp: TcpStream, acceptor: TlsAcceptor, answer: Answer, seen: Arc<Seen>) {
    let tls = acceptor.accept(tcp).await.unwrap();
    let io = Tee {
        io: tls,
        seen: seen.clone(),
    };
    let mut conn = ::h2::server::handshake(io).await.unwrap();
    while let Some(Ok((request, mut respond))) = conn.accept().await {
        let (head, mut recv) = request.into_parts();
        let index = {
            let mut requests = seen.requests.lock().unwrap();
            requests.push((head.uri.to_string(), head.headers.clone()));
            requests.len() - 1
        };
        if matches!(answer, Answer::PaddedAfterData) && index > 0 {
            let seen = seen.clone();
            tokio::spawn(async move {
                let wait = std::time::Duration::from_secs(5);
                let Ok(Some(Ok(first))) = tokio::time::timeout(wait, recv.data()).await else {
                    return;
                };
                seen.early_data.fetch_add(1, Ordering::Relaxed);
                let answer = Response::builder().header("padding-type-reply", "1");
                let mut send = respond
                    .send_response(answer.body(()).unwrap(), false)
                    .unwrap();
                // The client's first frame is padded the way the reply direction expects.
                send.send_data(first, false).unwrap();
                let _ = recv.data().await;
            });
            continue;
        }
        let mut response = Response::builder();
        let padding = match answer {
            Answer::Padded | Answer::PaddedAfterData | Answer::GoAwayAfterFirst => {
                response = response.header("padding-type-reply", "1");
                PaddingType::Variant1
            }
            Answer::Plain => PaddingType::None,
            Answer::Status(code) => {
                response = response.status(code);
                PaddingType::None
            }
        };
        let response = response.body(()).unwrap();
        let ok = response.status() == StatusCode::OK;
        let send = respond.send_response(response, !ok).unwrap();
        if !ok {
            continue;
        }
        tokio::spawn(async move {
            let body: BoxStream = Box::new(H2Body::new(send, Incoming::Body(recv)));
            let (mut read, mut write) = tokio::io::split(padding.wrap(body));
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        if matches!(answer, Answer::GoAwayAfterFirst) {
            conn.graceful_shutdown();
        }
    }
}

fn node(server: &Server, extra: Value) -> Arc<dyn Outbound> {
    Arc::new(built(server.addr.port(), extra).unwrap())
}

fn built(port: u16, extra: Value) -> Result<Naive, BuildError> {
    let mut raw = json!({
        "name": "naive", "type": "naive", "server": "127.0.0.1", "port": port,
        "username": "user", "password": "pass", "sni": "localhost", "skip-cert-verify": true,
    });
    raw.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let ProxyParse::Ok(def) = parse_proxy(raw.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("naive was quarantined");
    };
    let concord_config::proxy::ProxyKind::Naive(opts) = &def.kind else {
        unreachable!()
    };
    naive(&def, opts, &BuildCtx::new(TrustStore::new(b"", vec![])))
}

async fn echo(node: &dyn Outbound, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let mut stream = node
        .connect(&cx, &Address::Domain("example.com".into(), 443))
        .await?;
    stream.write_all(payload).await?;
    let mut got = vec![0; payload.len()];
    stream.read_exact(&mut got).await?;
    Ok(got)
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7) as u8).collect()
}

#[tokio::test]
async fn tunnels_share_one_connection_and_fast_open_once_padding_is_known() {
    let server = server(Answer::Padded).await;
    let node = node(&server, json!({}));
    for size in [1, 300, 5000, 200_000] {
        let data = payload(size);
        assert_eq!(echo(&*node, &data).await.unwrap(), data);
    }
    assert_eq!(server.seen.connections.load(Ordering::Relaxed), 1);
    let requests = server.seen.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    let (authority, headers) = &requests[0];
    assert_eq!(authority, "example.com:443");
    let names: Vec<&str> = headers.keys().map(http::HeaderName::as_str).collect();
    assert_eq!(
        names,
        ["proxy-authorization", "padding", "padding-type-request"]
    );
}

#[tokio::test]
async fn known_padding_sends_data_before_the_answer() {
    let server = server(Answer::PaddedAfterData).await;
    let node = node(&server, json!({}));
    for _ in 0..2 {
        assert_eq!(echo(&*node, b"x").await.unwrap(), b"x");
    }
    assert_eq!(server.seen.early_data.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn a_goaway_sends_new_tunnels_to_a_new_connection_and_keeps_the_old_one() {
    let server = server(Answer::GoAwayAfterFirst).await;
    let node = built(server.addr.port(), json!({})).unwrap();
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let mut old = node
        .connect(&cx, &Address::Domain("example.com".into(), 443))
        .await
        .unwrap();
    let mut byte = [0; 1];
    old.write_all(b"a").await.unwrap();
    old.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"a");
    let slot = lock(&node.slots).first().cloned().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while slot.session.get(Conn::usable).0.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let data = payload(300);
    assert_eq!(echo(&node, &data).await.unwrap(), data);
    assert_eq!(server.seen.connections.load(Ordering::Relaxed), 2);
    old.write_all(b"b").await.unwrap();
    old.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"b");
    node.reset_sessions();
    let _ = old.write_all(b"c").await;
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), old.read_exact(&mut byte));
    assert!(read.await.unwrap().is_err());
}

#[tokio::test]
async fn a_connection_moved_off_while_a_reset_ran_is_closed() {
    let server = server(Answer::Padded).await;
    let node = built(server.addr.port(), json!({})).unwrap();
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let moved_off = node.dialer.connect(&cx).await.unwrap();
    let since = lock(&node.retired).resets.ticket();
    node.reset_sessions();
    node.retire(&moved_off, since);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while moved_off.usable() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(lock(&node.retired).conns.is_empty());
}

#[test]
fn an_unknown_udp_over_tcp_version_fails_the_build() {
    let built = built(
        443,
        json!({"udp": true, "udp-over-tcp": true, "udp-over-tcp-version": 3}),
    );
    assert!(built.is_err());
}

#[tokio::test]
async fn a_server_without_padding_gets_plain_bytes() {
    let server = server(Answer::Plain).await;
    let node = node(&server, json!({}));
    for _ in 0..2 {
        let data = payload(4000);
        assert_eq!(echo(&*node, &data).await.unwrap(), data);
    }
}

#[tokio::test]
async fn refused_credentials_fail_the_dial() {
    let server = server(Answer::Status(407)).await;
    let node = node(&server, json!({}));
    let err = echo(&*node, b"x").await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn concurrency_spreads_tunnels_and_a_reset_redials() {
    let server = server(Answer::Padded).await;
    let node = node(&server, json!({"insecure-concurrency": 2}));
    for _ in 0..4 {
        assert_eq!(echo(&*node, b"hello").await.unwrap(), b"hello");
    }
    assert_eq!(server.seen.connections.load(Ordering::Relaxed), 2);
    node.reset_sessions();
    assert_eq!(echo(&*node, b"again").await.unwrap(), b"again");
    assert_eq!(server.seen.connections.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn the_connection_opens_with_chromium_settings() {
    let server = server(Answer::Plain).await;
    let node = node(&server, json!({}));
    echo(&*node, b"x").await.unwrap();
    let preface = server.seen.preface.lock().unwrap().clone();
    let preface = preface
        .strip_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice())
        .unwrap();
    let length = usize::from(u16::from_be_bytes([preface[1], preface[2]]));
    assert_eq!((preface[0], preface[3]), (0, 4), "a SETTINGS frame first");
    let settings: Vec<(u16, u32)> = preface[9..9 + length]
        .chunks(6)
        .map(|item| {
            (
                u16::from_be_bytes([item[0], item[1]]),
                u32::from_be_bytes([item[2], item[3], item[4], item[5]]),
            )
        })
        .collect();
    assert_eq!(
        settings,
        [(1, 65_536), (2, 0), (4, 64 << 20), (6, 256 << 10)]
    );
    let update = &preface[9 + length..];
    assert_eq!(update[3], 8, "then the connection WINDOW_UPDATE");
    let increment = u32::from_be_bytes([update[9], update[10], update[11], update[12]]);
    assert_eq!(increment, (128 << 20) - 65_535);
}

#[tokio::test]
async fn udp_needs_udp_over_tcp() {
    let server = server(Answer::Plain).await;
    let node = node(&server, json!({"udp": true}));
    assert!(!node.info().udp);
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let err = node
        .associate(&cx, &Address::Domain("example.com".into(), 53))
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    let node = self::node(&server, json!({"udp": true, "udp-over-tcp": true}));
    assert!(node.info().udp);
    node.associate(&cx, &Address::Domain("example.com".into(), 53))
        .await
        .unwrap();
    assert_eq!(
        server.seen.requests.lock().unwrap().last().unwrap().0,
        "sp.v2.udp-over-tcp.arpa:0"
    );
}

#[test]
fn windows_follow_naive_and_cronet_go() {
    assert_eq!(Windows::new(0), Windows::new(128 << 20));
    assert_ne!(Windows::new(0), Windows::new(1 << 20));
}

/// What a server that never ends its side saw of a tunnel: the bytes, whether they ended with a
/// FIN, and the error its next write met.
struct Held {
    got: Vec<u8>,
    fin: bool,
    write_error: String,
}

/// An HTTP/3 naive server without padding that echoes every tunnel, or with `hold` reads each
/// tunnel to its end without ever ending its own side and reports it.
async fn h3_server(
    hold: Option<tokio::sync::mpsc::UnboundedSender<Held>>,
) -> (Arc<Seen>, u16, quinn::Endpoint) {
    let (endpoint, port) = crate::testing::quic_server(b"h3", |socket| socket);
    let seen = Arc::new(Seen::default());
    let shared = seen.clone();
    let accept = endpoint.clone();
    tokio::spawn(async move {
        while let Some(connecting) = accept.accept().await {
            let shared = shared.clone();
            let hold = hold.clone();
            tokio::spawn(async move {
                let Ok(conn) = connecting.await else {
                    return;
                };
                shared.connections.fetch_add(1, Ordering::Relaxed);
                let mut h3 = ::h3::server::builder()
                    .build::<_, bytes::Bytes>(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    let shared = shared.clone();
                    let hold = hold.clone();
                    tokio::spawn(async move {
                        let (request, mut stream) = resolver.resolve_request().await.unwrap();
                        let (head, ()) = request.into_parts();
                        shared
                            .requests
                            .lock()
                            .unwrap()
                            .push((head.uri.to_string(), head.headers.clone()));
                        stream
                            .send_response(Response::builder().body(()).unwrap())
                            .await
                            .unwrap();
                        if let Some(hold) = hold {
                            let _ = hold.send(held(&mut stream).await);
                            return;
                        }
                        while let Ok(Some(mut data)) = stream.recv_data().await {
                            use bytes::Buf;
                            let chunk = data.copy_to_bytes(data.remaining());
                            if stream.send_data(chunk).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            });
        }
    });
    (seen, port, endpoint)
}

async fn held<S>(stream: &mut ::h3::server::RequestStream<S, bytes::Bytes>) -> Held
where
    S: ::h3::quic::BidiStream<bytes::Bytes>,
{
    use bytes::Buf;
    let mut got = Vec::new();
    let fin = loop {
        match stream.recv_data().await {
            Ok(Some(mut data)) => got.extend_from_slice(&data.copy_to_bytes(data.remaining())),
            Ok(None) => break true,
            Err(_) => break false,
        }
    };
    let write_error = loop {
        if let Err(err) = stream.send_data(bytes::Bytes::from_static(b"x")).await {
            break format!("{err:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    Held {
        got,
        fin,
        write_error,
    }
}

fn quic_node(port: u16) -> Arc<dyn Outbound> {
    let raw = json!({
        "name": "naive", "type": "naive", "server": "127.0.0.1", "port": port, "quic": true,
        "username": "user", "password": "pass", "sni": "localhost", "skip-cert-verify": true,
    });
    let ProxyParse::Ok(def) = parse_proxy(raw.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("naive was quarantined");
    };
    let concord_config::proxy::ProxyKind::Naive(opts) = &def.kind else {
        unreachable!()
    };
    build(&def, opts, &BuildCtx::new(TrustStore::new(b"", vec![]))).unwrap()
}

#[tokio::test]
async fn quic_tunnels_share_one_connection() {
    let (seen, port, _endpoint) = h3_server(None).await;
    let node = quic_node(port);
    for size in [1, 300, 5000, 100_000] {
        let data = payload(size);
        assert_eq!(echo(&*node, &data).await.unwrap(), data);
    }
    assert_eq!(seen.connections.load(Ordering::Relaxed), 1);
    let requests = seen.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].0, "example.com:443");
    let names: Vec<&str> = requests[0].1.keys().map(http::HeaderName::as_str).collect();
    assert_eq!(
        names,
        ["proxy-authorization", "padding", "padding-type-request"]
    );
}

#[tokio::test]
async fn a_quic_tunnel_ended_while_its_reader_waits_stops_the_stream_cancelled() {
    let (hold, mut held) = tokio::sync::mpsc::unbounded_channel();
    let (_seen, port, _endpoint) = h3_server(Some(hold)).await;
    let node = quic_node(port);
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = node
        .connect(&cx, &Address::Domain("example.com".into(), 443))
        .await
        .unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let patience = std::time::Duration::from_secs(5);
    let reader = tokio::spawn(async move {
        let mut rest = Vec::new();
        read.read_to_end(&mut rest).await.map(|_| rest)
    });
    write.write_all(b"hello").await.unwrap();
    write.flush().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!reader.is_finished());
    tokio::time::timeout(patience, write.shutdown())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(patience, reader)
        .await
        .unwrap()
        .expect("the reader panicked")
        .unwrap();
    let held = tokio::time::timeout(patience, held.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.got, b"hello");
    assert!(held.fin);
    assert!(
        held.write_error.contains("H3_REQUEST_CANCELLED"),
        "{}",
        held.write_error
    );
}

#[tokio::test]
async fn a_closed_quic_tunnel_sends_its_writes_then_stops_the_stream() {
    let (hold, mut held) = tokio::sync::mpsc::unbounded_channel();
    let (_seen, port, _endpoint) = h3_server(Some(hold)).await;
    let node = quic_node(port);
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = node
        .connect(&cx, &Address::Domain("example.com".into(), 443))
        .await
        .unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let patience = std::time::Duration::from_secs(5);
    let reader = tokio::spawn(async move {
        let mut rest = Vec::new();
        read.read_to_end(&mut rest).await.map(|_| rest)
    });
    let data = payload(300_000);
    write.write_all(&data).await.unwrap();
    tokio::time::timeout(patience, write.shutdown())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(patience, reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let held = tokio::time::timeout(patience, held.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.got.len(), data.len());
    assert!(held.got == data);
    assert!(held.fin);
    assert!(
        held.write_error.contains("H3_REQUEST_CANCELLED"),
        "{}",
        held.write_error
    );
}
