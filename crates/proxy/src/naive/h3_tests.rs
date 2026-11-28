#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests use loopback peers and fixed wire shapes"
)]

use std::fmt;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use concord_common::{Address, DialCx, Initiator, Outbound};
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use concord_transport::RESET_DRAIN;
use http::Response;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tests::{Seen, echo, payload};
use super::*;
use crate::ctx::BuildCtx;
use crate::testing::test_env;

/// What a server that never ends its side saw of a tunnel: the bytes, how and when they ended,
/// and the error its next write met.
struct Held {
    got: Vec<u8>,
    end: Result<(), String>,
    ended: Instant,
    write_error: String,
}

/// An HTTP/3 naive server without padding that echoes every tunnel, or with `hold` reads each
/// tunnel to its end without ever ending its own side and reports it.
async fn h3_server(
    hold: Option<tokio::sync::mpsc::UnboundedSender<Held>>,
) -> (Arc<Seen>, u16, quinn::Endpoint) {
    h3_server_on(hold, |socket| socket).await
}

async fn h3_server_on(
    hold: Option<tokio::sync::mpsc::UnboundedSender<Held>>,
    wrap: impl FnOnce(Arc<dyn AsyncUdpSocket>) -> Arc<dyn AsyncUdpSocket>,
) -> (Arc<Seen>, u16, quinn::Endpoint) {
    let (endpoint, port) = crate::testing::quic_server(b"h3", wrap);
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
    let end = loop {
        match stream.recv_data().await {
            Ok(Some(mut data)) => got.extend_from_slice(&data.copy_to_bytes(data.remaining())),
            Ok(None) => break Ok(()),
            Err(err) => break Err(format!("{err:?}")),
        }
    };
    let ended = Instant::now();
    let write_error = loop {
        if let Err(err) = stream.send_data(bytes::Bytes::from_static(b"x")).await {
            break format!("{err:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    Held {
        got,
        end,
        ended,
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
        ["padding", "padding-type-request", "proxy-authorization"]
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
    cancelled(&held);
}

#[tokio::test]
async fn a_closed_quic_tunnel_sends_its_writes_then_resets_the_stream() {
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
    cancelled(&held);
}

/// The server read the client's data to a RESET_STREAM H3_REQUEST_CANCELLED rather than a FIN, and
/// its own writes met the client's STOP_SENDING H3_REQUEST_CANCELLED.
fn cancelled(held: &Held) {
    let end = held.end.as_ref().unwrap_err();
    assert!(end.contains("H3_REQUEST_CANCELLED"), "{end}");
    assert!(
        held.write_error.contains("H3_REQUEST_CANCELLED"),
        "{}",
        held.write_error
    );
}

/// A socket that drops what its endpoint sends while `muted`, acknowledgements among it.
struct Muted(Arc<dyn AsyncUdpSocket>, Arc<AtomicBool>);

impl fmt::Debug for Muted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Muted")
    }
}

impl AsyncUdpSocket for Muted {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.0.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if self.1.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.0.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.0.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.0.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.0.may_fragment()
    }
}

/// Opens a tunnel to a holding server whose packets `mute` can drop, writes, mutes the server and
/// writes again, then shuts the tunnel down and returns what the server saw.
async fn closed_while_muted(unmute_after: Option<Duration>) -> (Held, Instant) {
    let mute = Arc::new(AtomicBool::new(false));
    let (hold, mut held) = tokio::sync::mpsc::unbounded_channel();
    let muted = mute.clone();
    let (_seen, port, endpoint) =
        h3_server_on(Some(hold), move |socket| Arc::new(Muted(socket, muted))).await;
    let node = quic_node(port);
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let stream = node
        .connect(&cx, &Address::Domain("example.com".into(), 443))
        .await
        .unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let reader = tokio::spawn(async move {
        let mut rest = Vec::new();
        read.read_to_end(&mut rest).await.map(|_| rest)
    });
    write.write_all(b"acknowledged ").await.unwrap();
    write.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    mute.store(true, Ordering::Relaxed);
    write.write_all(b"unacknowledged").await.unwrap();
    let closing = Instant::now();
    let shutdown = tokio::spawn(async move { write.shutdown().await });
    let mut unmuted = closing;
    if let Some(after) = unmute_after {
        tokio::time::sleep(after).await;
        assert!(held.try_recv().is_err(), "reset before the acknowledgement");
        unmuted = Instant::now();
        mute.store(false, Ordering::Relaxed);
    }
    let patience = RESET_DRAIN + Duration::from_secs(5);
    let got = tokio::time::timeout(patience, held.recv())
        .await
        .unwrap()
        .unwrap();
    mute.store(false, Ordering::Relaxed);
    tokio::time::timeout(patience, shutdown)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(patience, reader)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(endpoint);
    let since = if unmute_after.is_some() {
        unmuted
    } else {
        closing
    };
    assert!(got.ended >= since);
    (got, closing)
}

#[tokio::test]
async fn a_quic_tunnel_is_reset_only_once_its_writes_are_acknowledged() {
    let (held, closing) = closed_while_muted(Some(Duration::from_secs(1))).await;
    assert_eq!(held.got, b"acknowledged unacknowledged");
    cancelled(&held);
    assert!(held.ended - closing < RESET_DRAIN);
}

#[tokio::test]
async fn a_quic_tunnel_whose_writes_go_unacknowledged_is_reset_at_the_limit() {
    let (held, closing) = closed_while_muted(None).await;
    assert_eq!(held.got, b"acknowledged unacknowledged");
    cancelled(&held);
    assert!(held.ended - closing >= RESET_DRAIN);
}

fn varint(bytes: &mut &[u8]) -> u64 {
    let first = bytes[0];
    let len = 1 << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for &byte in &bytes[1..len] {
        value = value << 8 | u64::from(byte);
    }
    *bytes = &bytes[len..];
    value
}

/// `(type, payload)` of each whole frame in `bytes`.
fn frames(mut bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let kind = varint(&mut bytes);
        let len = varint(&mut bytes) as usize;
        frames.push((kind, bytes[..len].to_vec()));
        bytes = &bytes[len..];
    }
    frames
}

fn reserved(id: u64) -> bool {
    id >= 0x21 && (id - 0x21).is_multiple_of(0x1f)
}

/// The 32-bit `N` of a reserved id `0x1f * N + 0x21`, as Chromium picks its grease ids.
fn chromium_grease(id: u64) -> Option<u32> {
    reserved(id)
        .then(|| (id - 0x21) / 0x1f)
        .and_then(|n| u32::try_from(n).ok())
}

/// A request stream as the server read it: its id, its bytes, and the code it was reset with.
type Request = (u64, Vec<u8>, Option<u64>);

#[derive(Default)]
struct Wire {
    uni: Mutex<Vec<u64>>,
    control: Mutex<Vec<u8>>,
    requests: Mutex<Vec<Request>>,
}

const RECORDED: &str = include_str!("testdata/naiveproxy-h3.txt");

/// The value after `key=` on each recorded line that starts with `start`.
fn recorded<'a>(start: &str, key: &str) -> Vec<&'a str> {
    RECORDED
        .lines()
        .filter(|line| line.starts_with(start))
        .filter_map(|line| line.split(key).nth(1))
        .map(|rest| rest.split([' ', ']']).next().unwrap())
        .collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn number(text: &str) -> u64 {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).unwrap(),
        None => text.parse().unwrap(),
    }
}

/// A bare QUIC server that answers each request 200 and records the client's streams byte for
/// byte: the unidirectional stream types, the control stream, and each request stream with the
/// code it was reset with, if it was.
async fn wire_server() -> (Arc<Wire>, u16, quinn::Endpoint) {
    let (endpoint, port) = crate::testing::quic_server(b"h3", |socket| socket);
    let wire = Arc::new(Wire::default());
    let shared = wire.clone();
    let accept = endpoint.clone();
    tokio::spawn(async move {
        let conn = accept.accept().await.unwrap().await.unwrap();
        let uni = conn.clone();
        let wire = shared.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = uni.accept_uni().await {
                let wire = wire.clone();
                tokio::spawn(async move {
                    let mut first = [0; 1];
                    stream.read_exact(&mut first).await.unwrap();
                    let mut kind = vec![first[0]];
                    kind.resize(1 << (first[0] >> 6), 0);
                    stream.read_exact(&mut kind[1..]).await.unwrap();
                    wire.uni.lock().unwrap().push(varint(&mut kind.as_slice()));
                    if kind != [0] {
                        return;
                    }
                    while let Ok(Some(chunk)) = stream.read_chunk(usize::MAX, true).await {
                        wire.control.lock().unwrap().extend_from_slice(&chunk.bytes);
                    }
                });
            }
        });
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let wire = shared.clone();
            tokio::spawn(async move {
                let id = u64::from(recv.id());
                send.write_all(&[0x01, 0x03, 0x00, 0x00, 0xd9])
                    .await
                    .unwrap();
                let mut got = Vec::new();
                let reset = loop {
                    match recv.read_chunk(usize::MAX, true).await {
                        Ok(Some(chunk)) => got.extend_from_slice(&chunk.bytes),
                        Ok(None) => break None,
                        Err(quinn::ReadError::Reset(code)) => break Some(code.into_inner()),
                        Err(err) => panic!("{err:?}"),
                    }
                };
                wire.requests.lock().unwrap().push((id, got, reset));
                let _ = send.finish();
            });
        }
    });
    (wire, port, endpoint)
}

#[tokio::test]
async fn quic_tunnels_open_and_end_as_naiveproxy_does() {
    let (wire, port, _endpoint) = wire_server().await;
    let node = quic_node(port);
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    for _ in 0..2 {
        let mut stream = node
            .connect(&cx, &Address::Domain("example.com".into(), 443))
            .await
            .unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.shutdown().await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while wire.requests.lock().unwrap().len() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    assert_eq!(*wire.uni.lock().unwrap(), [0]);
    assert_eq!(recorded("uni ", "type="), ["0x0"]);
    let control = frames(&wire.control.lock().unwrap());
    let (kinds, payloads): (Vec<u64>, Vec<Vec<u8>>) = control.into_iter().unzip();
    assert_eq!(kinds.len(), 4, "{kinds:x?}");
    assert_eq!(kinds[0], 0x4);
    let mut settings = payloads[0].as_slice();
    let mut pairs = Vec::new();
    while !settings.is_empty() {
        pairs.push((varint(&mut settings), varint(&mut settings)));
    }
    let reference: Vec<(u64, u64)> = RECORDED
        .lines()
        .find_map(|line| line.split("settings=[").nth(1))
        .and_then(|rest| rest.split(']').next())
        .unwrap()
        .split(' ')
        .map(|pair| pair.split_once('=').unwrap())
        .map(|(id, value)| (number(id), number(value)))
        .collect();
    // Without a dynamic table h3 leaves out QPACK_MAX_TABLE_CAPACITY and QPACK_BLOCKED_STREAMS.
    let kept: Vec<(u64, u64)> = reference
        .iter()
        .copied()
        .filter(|&(id, _)| !reserved(id) && id != 0x1 && id != 0x7)
        .collect();
    assert_eq!(pairs[..pairs.len() - 1], kept);
    assert!(chromium_grease(reference.last().unwrap().0).is_some());
    assert!(chromium_grease(pairs.last().unwrap().0).is_some());
    assert!(pairs.last().unwrap().1 <= u64::from(u32::MAX));
    let grease = recorded("control frame type=0x18", "type=");
    let grease_len = recorded("control frame type=0x18", "len=");
    let n = chromium_grease(number(grease[0])).unwrap();
    assert_eq!((n % 4).to_string(), grease_len[0]);
    let n = chromium_grease(kinds[1]).unwrap();
    assert_eq!(payloads[1].len(), (n % 4) as usize);
    let requests = wire.requests.lock().unwrap();
    let mut ids: Vec<u64> = requests.iter().map(|request| request.0).collect();
    ids.sort_unstable();
    assert_eq!(ids, [0, 4]);
    let updates = recorded("control frame type=0xf0700", "raw=");
    let mut value = &hex(updates[0])[..];
    varint(&mut value);
    for ((kind, payload), id) in kinds[2..].iter().zip(&payloads[2..]).zip(&ids) {
        assert_eq!(*kind, 0xf0700);
        let mut element = payload.as_slice();
        assert_eq!(varint(&mut element), *id);
        assert_eq!(element, value);
    }

    let ends = recorded("end ", "code=");
    let code = number(ends[0]);
    assert!(ends.iter().all(|end| number(end) == code));
    let start = &hex(recorded("req ", "block=")[0])[..3];
    for (_, bytes, reset) in requests.iter() {
        assert_eq!(*reset, Some(code));
        let frames = frames(bytes);
        assert_eq!(frames[0].0, 0x1);
        let block = &frames[0].1;
        assert_eq!(&block[..3], start);
        let raw = block
            .split(|byte| !request::NON_INDEX.contains(byte))
            .map(<[u8]>::len)
            .max()
            .unwrap();
        assert!(raw >= 16, "the padding value went out Huffman-coded");
        assert!(
            frames[1..].iter().all(|frame| frame.0 == 0x0),
            "{frames:x?}"
        );
    }
}

/// A server whose connection window is `WINDOW` and that leaves the first tunnel unread until
/// `release`, so a client that fills it has no flow credit left for any stream.
async fn starved_server() -> (u16, quinn::Endpoint, Arc<tokio::sync::Notify>) {
    const WINDOW: u32 = 64 * 1024;
    let (endpoint, port) = crate::testing::quic_server_tuned(
        b"h3",
        |socket| socket,
        |transport| {
            transport.receive_window(WINDOW.into());
            transport.stream_receive_window(WINDOW.into());
        },
    );
    let release = Arc::new(tokio::sync::Notify::new());
    let accept = endpoint.clone();
    let held = release.clone();
    tokio::spawn(async move {
        let conn = accept.accept().await.unwrap().await.unwrap();
        let uni = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = uni.accept_uni().await {
                tokio::spawn(async move {
                    while let Ok(Some(_)) = stream.read_chunk(usize::MAX, true).await {}
                });
            }
        });
        let mut first = true;
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let held = std::mem::take(&mut first).then(|| held.clone());
            tokio::spawn(async move {
                if send
                    .write_all(&[0x01, 0x03, 0x00, 0x00, 0xd9])
                    .await
                    .is_err()
                {
                    return;
                }
                if let Some(held) = held {
                    held.notified().await;
                }
                while let Ok(Some(_)) = recv.read_chunk(usize::MAX, true).await {}
            });
        }
    });
    (port, endpoint, release)
}

#[tokio::test]
async fn quic_tunnels_opened_together_on_a_connection_out_of_credit_both_open() {
    let (port, _endpoint, release) = starved_server().await;
    let node = quic_node(port);
    let env = test_env();
    let target = Address::Domain("example.com".into(), 443);
    let mut first = node
        .connect(&DialCx::new(&env, Initiator::Direct, None), &target)
        .await
        .unwrap();
    let _filling = tokio::spawn(async move {
        let _ = first.write_all(&vec![0; 1 << 20]).await;
        first
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let opens: Vec<_> = (0..2)
        .map(|_| {
            let node = node.clone();
            let env = env.clone();
            let target = target.clone();
            tokio::spawn(async move {
                node.connect(&DialCx::new(&env, Initiator::Direct, None), &target)
                    .await
                    .map(drop)
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(300)).await;
    release.notify_one();
    for open in opens {
        tokio::time::timeout(Duration::from_secs(5), open)
            .await
            .expect("a tunnel opened alongside another never finished opening")
            .unwrap()
            .unwrap();
    }
}

/// A client stream with bytes the server never receives, since the client's sends are muted after
/// the first, and the server's end of the connection with that stream accepted.
async fn unacknowledged_stream() -> (
    quinn::SendStream,
    quinn::RecvStream,
    quinn::Connection,
    Vec<quinn::Endpoint>,
) {
    use quinn::Runtime;
    let (mut server_tls, mut client_tls) =
        concord_test_support::localhost_tls(&[&rustls::version::TLS13]);
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
        )),
        loopback,
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let mute = Arc::new(AtomicBool::new(false));
    let socket = quinn::TokioRuntime
        .wrap_udp_socket(std::net::UdpSocket::bind(loopback).unwrap())
        .unwrap();
    let mut client = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        Arc::new(Muted(socket, mute.clone())),
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
    )));
    let accepted = tokio::spawn({
        let server = server.clone();
        async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (_, recv) = conn.accept_bi().await.unwrap();
            (recv, conn)
        }
    });
    let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut send, _) = conn.open_bi().await.unwrap();
    send.write_all(b"opens the stream").await.unwrap();
    let (recv, server_conn) = accepted.await.unwrap();
    mute.store(true, Ordering::Relaxed);
    send.write_all(b"never arrives").await.unwrap();
    (send, recv, server_conn, vec![client, server])
}

async fn acked(send: &mut quinn::SendStream) -> Result<Option<quinn::VarInt>, quinn::StoppedError> {
    tokio::time::timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| send.poll_acked(cx)),
    )
    .await
    .expect("the wait for acknowledgements was never woken")
}

#[tokio::test]
async fn a_wait_for_acknowledgements_ends_when_the_peer_stops_the_stream() {
    let (mut send, mut recv, _conn, _endpoints) = unacknowledged_stream().await;
    let waiting = tokio::spawn(async move { acked(&mut send).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiting.is_finished());
    recv.stop(7u32.into()).unwrap();
    assert_eq!(waiting.await.unwrap().unwrap(), Some(7u32.into()));
}

#[tokio::test]
async fn a_wait_for_acknowledgements_ends_when_the_connection_closes() {
    let (mut send, _recv, conn, _endpoints) = unacknowledged_stream().await;
    let waiting = tokio::spawn(async move { acked(&mut send).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiting.is_finished());
    conn.close(9u32.into(), b"closed");
    assert!(matches!(
        waiting.await.unwrap(),
        Err(quinn::StoppedError::ConnectionLost(_))
    ));
}
