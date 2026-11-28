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
pub(super) struct Seen {
    pub(super) connections: AtomicUsize,
    early_data: AtomicUsize,
    pub(super) requests: Mutex<Vec<(String, HeaderMap)>>,
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
        if preface.len() < 1 << 16 {
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

pub(super) async fn echo(node: &dyn Outbound, payload: &[u8]) -> std::io::Result<Vec<u8>> {
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

pub(super) fn payload(len: usize) -> Vec<u8> {
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
        ["padding", "padding-type-request", "proxy-authorization"]
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

struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// The frames the client sent after the preface, as far as the server kept them.
fn client_frames(seen: &Seen) -> Vec<Frame> {
    let bytes = seen.preface.lock().unwrap().clone();
    let mut rest = &bytes[24..];
    let mut frames = Vec::new();
    while rest.len() >= 9 {
        let length = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]) as usize;
        if rest.len() < 9 + length {
            break;
        }
        frames.push(Frame {
            kind: rest[3],
            flags: rest[4],
            stream: u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]) & 0x7fff_ffff,
            payload: rest[9..9 + length].to_vec(),
        });
        rest = &rest[9 + length..];
    }
    frames
}

/// The stream, dependency, exclusive flag and weight octet of each HEADERS frame the client sent
/// with priority fields.
fn priorities(seen: &Seen) -> Vec<(u32, u32, bool, u8)> {
    client_frames(seen)
        .iter()
        .filter(|frame| frame.kind == 1 && frame.flags & 0x20 != 0)
        .map(|frame| {
            let dependency = u32::from_be_bytes(frame.payload[..4].try_into().unwrap());
            (
                frame.stream,
                dependency & 0x7fff_ffff,
                dependency >> 31 == 1,
                frame.payload[4],
            )
        })
        .collect()
}

/// A tunnel in `testdata/naiveproxy-h2.txt`.
struct Recorded {
    flags: u8,
    exclusive: bool,
    weight: u8,
    block: Vec<u8>,
    fields: Vec<String>,
    end: Vec<String>,
}

fn recorded_tunnels() -> Vec<Recorded> {
    let value = |line: &str, key: &str| {
        line.split(' ')
            .find_map(|word| word.strip_prefix(key))
            .unwrap()
            .to_owned()
    };
    let mut tunnels: Vec<Recorded> = Vec::new();
    for line in include_str!("testdata/naiveproxy-h2.txt").lines() {
        if line.starts_with("HEADERS ") {
            let block = value(line, "block=");
            tunnels.push(Recorded {
                flags: u8::from_str_radix(value(line, "flags=0x").as_str(), 16).unwrap(),
                exclusive: value(line, "excl=") == "true",
                weight: value(line, "weight=").parse().unwrap(),
                block: (0..block.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&block[at..at + 2], 16).unwrap())
                    .collect(),
                fields: Vec::new(),
                end: Vec::new(),
            });
        } else if let Some(field) = line.strip_prefix("field ") {
            let name = field.split(' ').nth(1).unwrap().trim_end_matches(':');
            tunnels.last_mut().unwrap().fields.push(name.to_owned());
        } else if let Some(tunnel) = tunnels.last_mut()
            && (line.starts_with("DATA flags=0x9 ") || line.starts_with("RST_STREAM "))
        {
            tunnel.end.push(line.to_owned());
        }
    }
    tunnels
}

#[tokio::test]
async fn tunnels_open_and_end_as_naiveproxy_does() {
    let recorded = recorded_tunnels();
    assert_eq!(recorded.len(), 3);
    let server = server(Answer::Padded).await;
    let node = node(&server, json!({}));
    for _ in &recorded {
        echo(&*node, b"x").await.unwrap();
    }
    let resets = |frames: &[Frame]| frames.iter().filter(|frame| frame.kind == 3).count();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while resets(&client_frames(&server.seen)) < recorded.len() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let frames = client_frames(&server.seen);
    let requests = server.seen.requests.lock().unwrap();
    let opened: Vec<&Frame> = frames.iter().filter(|frame| frame.kind == 1).collect();
    assert_eq!(opened.len(), recorded.len());
    for ((reference, headers), (_, fields)) in recorded.iter().zip(opened).zip(requests.iter()) {
        assert_eq!(headers.flags, reference.flags);
        // naiveproxy's non-zero dependencies are the GETs it sends ahead of a tunnel.
        assert_eq!(headers.payload[..4], [0x80, 0, 0, 0]);
        assert!(reference.exclusive);
        assert_eq!(headers.payload[4], reference.weight);
        let method = &reference.block[..9];
        assert_eq!(method, b"\x02\x07CONNECT");
        assert!(headers.payload[5..].starts_with(method));
        let names: Vec<&str> = fields.keys().map(http::HeaderName::as_str).collect();
        assert_eq!(names, reference.fields[2..]);
        assert!(reference.end[0].starts_with("DATA flags=0x9 "));
        assert!(reference.end[1].starts_with("RST_STREAM "));
        let padding: usize = reference.end[0]
            .split(' ')
            .find_map(|word| word.strip_prefix("len="))
            .unwrap()
            .parse()
            .unwrap();
        assert!((26..=50).contains(&padding));
        let end: Vec<&Frame> = frames
            .iter()
            .filter(|frame| frame.stream == headers.stream && matches!(frame.kind, 0 | 3))
            .collect();
        let [.., data, reset] = end.as_slice() else {
            panic!("no end on stream {}", headers.stream);
        };
        assert_eq!((data.kind, data.flags), (0, 0x9));
        assert!((26..=50).contains(&data.payload.len()));
        assert_eq!(usize::from(data.payload[0]), data.payload.len() - 1);
        assert_eq!(reset.kind, 3);
        assert_eq!(reset.payload, u32::from(::h2::Reason::CANCEL).to_be_bytes());
    }
}

async fn tunnel(node: &dyn Outbound) -> BoxStream {
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let mut stream = node
        .connect(&cx, &Address::Domain("example.com".into(), 443))
        .await
        .unwrap();
    stream.write_all(b"x").await.unwrap();
    let mut echoed = [0];
    stream.read_exact(&mut echoed).await.unwrap();
    stream
}

#[tokio::test]
async fn tunnels_one_after_another_depend_on_the_root() {
    let server = server(Answer::Padded).await;
    let node = node(&server, json!({}));
    echo(&*node, b"x").await.unwrap();
    echo(&*node, b"y").await.unwrap();
    assert_eq!(
        priorities(&server.seen),
        [(1, 0, true, 146), (3, 0, true, 146)]
    );
}

#[tokio::test]
async fn a_tunnel_depends_on_the_newest_one_still_open() {
    let server = server(Answer::Padded).await;
    let node = node(&server, json!({}));
    let first = tunnel(&*node).await;
    let second = tunnel(&*node).await;
    drop(second);
    let third = tunnel(&*node).await;
    let fourth = tunnel(&*node).await;
    drop((first, third, fourth));
    assert_eq!(
        priorities(&server.seen),
        [
            (1, 0, true, 146),
            (3, 1, true, 146),
            (5, 1, true, 146),
            (7, 5, true, 146)
        ]
    );
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
