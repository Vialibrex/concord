#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "the tests run a loopback server on plain sockets"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use concord_common::{Address, DialCx, Initiator, Outbound, PacketBuf, recv_packet, send_packet};
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_quic::{ObfsSpec, wrap_socket};
use concord_tls::TrustStore;
use quinn::Endpoint;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use super::wire::{Defrag, UdpHeader, parse_udp, put_udp_header, udp_header_len};
use crate::ctx::BuildCtx;
use crate::testing::{HeldLookup, quic_server, test_env};

#[derive(Clone)]
struct Behavior {
    auth: Vec<u8>,
    refuse: Option<&'static str>,
    obfs: Option<ObfsSpec>,
    accepted: Arc<AtomicUsize>,
}

impl Default for Behavior {
    fn default() -> Self {
        Behavior {
            auth: b"secret".to_vec(),
            refuse: None,
            obfs: None,
            accepted: Arc::default(),
        }
    }
}

fn server_endpoint(behavior: &Behavior) -> (Endpoint, u16) {
    quic_server(b"hysteria", |socket| match &behavior.obfs {
        Some(obfs) => wrap_socket(socket, obfs, None, &Default::default()),
        None => socket,
    })
}

async fn read_text(recv: &mut quinn::RecvStream, len: usize) -> String {
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

async fn serve(endpoint: Endpoint, behavior: Behavior) {
    while let Some(incoming) = endpoint.accept().await {
        behavior.accepted.fetch_add(1, Ordering::SeqCst);
        let behavior = behavior.clone();
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                session(conn, behavior).await;
            }
        });
    }
}

async fn session(conn: quinn::Connection, behavior: Behavior) {
    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
        return;
    };
    let mut head = [0u8; 19];
    recv.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 3);
    let auth_len = usize::from(u16::from_be_bytes([head[17], head[18]]));
    let mut auth = vec![0u8; auth_len];
    recv.read_exact(&mut auth).await.unwrap();
    let rate = u64::from_be_bytes(head[9..17].try_into().unwrap());
    let accepted = auth == behavior.auth;
    let message: &[u8] = if accepted { b"Welcome" } else { b"bad auth" };
    let mut hello = vec![u8::from(accepted)];
    hello.extend_from_slice(&rate.to_be_bytes());
    hello.extend_from_slice(&rate.to_be_bytes());
    hello.extend_from_slice(&(message.len() as u16).to_be_bytes());
    hello.extend_from_slice(message);
    send.write_all(&hello).await.unwrap();
    if !accepted {
        let _ = send.finish();
        let _ = send.stopped().await;
        conn.close(2u32.into(), b"auth error");
        return;
    }
    let sessions = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::<
        u32,
        Arc<UdpSocket>,
    >::new()));
    tokio::spawn(relay_datagrams(conn.clone(), sessions.clone()));
    let mut next_session = 0u32;
    while let Ok((send, recv)) = conn.accept_bi().await {
        let (conn, sessions, behavior) = (conn.clone(), sessions.clone(), behavior.clone());
        next_session += 1;
        tokio::spawn(request(conn, send, recv, behavior, sessions, next_session));
    }
}

async fn request(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    behavior: Behavior,
    sessions: Arc<tokio::sync::Mutex<std::collections::HashMap<u32, Arc<UdpSocket>>>>,
    id: u32,
) {
    let udp = recv.read_u8().await.unwrap() == 1;
    let host_len = usize::from(recv.read_u16().await.unwrap());
    let host = read_text(&mut recv, host_len).await;
    let port = recv.read_u16().await.unwrap();
    let respond = |ok: bool, session: u32, message: &str| {
        let mut out = vec![u8::from(ok)];
        out.extend_from_slice(&session.to_be_bytes());
        out.extend_from_slice(&(message.len() as u16).to_be_bytes());
        out.extend_from_slice(message.as_bytes());
        out
    };
    if let Some(reason) = behavior.refuse {
        send.write_all(&respond(false, 0, reason)).await.unwrap();
        let _ = send.finish();
        return;
    }
    if udp {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        sessions.lock().await.insert(id, socket.clone());
        send.write_all(&respond(true, id, "")).await.unwrap();
        let replier = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                reply(&conn, id, from, &buf[..n]);
            }
        });
        let mut sink = [0u8; 64];
        while matches!(recv.read(&mut sink).await, Ok(Some(_))) {}
        replier.abort();
        return;
    }
    let target = tokio::net::TcpStream::connect((host.as_str(), port)).await;
    let Ok(target) = target else {
        send.write_all(&respond(false, 0, "dial failed"))
            .await
            .unwrap();
        return;
    };
    send.write_all(&respond(true, 0, "")).await.unwrap();
    let (mut read, mut write) = target.into_split();
    let upstream = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        while let Ok(Some(n)) = recv.read(&mut buf).await {
            if write.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let mut buf = vec![0u8; 16 * 1024];
    while let Ok(n) = read.read(&mut buf).await {
        if n == 0 || send.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = send.finish();
    upstream.abort();
}

fn reply(conn: &quinn::Connection, id: u32, from: SocketAddr, data: &[u8]) {
    let host = from.ip().to_string();
    let limit = conn.max_datagram_size().unwrap();
    let room = limit - udp_header_len(&host);
    let pieces: Vec<&[u8]> = data.chunks(room).collect();
    for (index, piece) in pieces.iter().enumerate() {
        let mut out = Vec::new();
        put_udp_header(
            &mut out,
            &UdpHeader {
                session: id,
                host: &host,
                port: from.port(),
                message: 77,
                fragment: index as u8,
                fragments: pieces.len() as u8,
                data_len: piece.len() as u16,
            },
        );
        out.extend_from_slice(piece);
        conn.send_datagram(Bytes::from(out)).unwrap();
    }
}

async fn relay_datagrams(
    conn: quinn::Connection,
    sessions: Arc<tokio::sync::Mutex<std::collections::HashMap<u32, Arc<UdpSocket>>>>,
) {
    let mut defrag = Defrag::default();
    while let Ok(datagram) = conn.read_datagram().await {
        let Ok(message) = parse_udp(&datagram) else {
            continue;
        };
        let Some(data) = defrag.feed(&message) else {
            continue;
        };
        let socket = sessions.lock().await.get(&message.session).cloned();
        if let Some(socket) = socket {
            let target = format!("{}:{}", message.host, message.port);
            socket.send_to(&data, target).await.unwrap();
        }
    }
}

fn client(port: u16, extra: Value) -> Result<Arc<dyn Outbound>, crate::ctx::BuildError> {
    let mut proxy = json!({
        "name": "h", "type": "hysteria", "server": "127.0.0.1", "port": port,
        "up": "50", "down": "50", "auth-str": "secret", "sni": "localhost",
        "skip-cert-verify": true, "udp": true,
    });
    if let (Some(base), Some(more)) = (proxy.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        panic!("the proxy was quarantined");
    };
    let ProxyKind::Hysteria(opts) = &def.kind else {
        unreachable!()
    };
    super::build(&def, opts, &BuildCtx::new(TrustStore::new(b"", Vec::new())))
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                while let Ok(n) = conn.read(&mut buf).await {
                    if n == 0 || conn.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

fn dst(addr: SocketAddr) -> Address {
    Address::new(&addr.ip().to_string(), addr.port())
}

async fn echo_tcp(outbound: &dyn Outbound, target: SocketAddr) -> std::io::Result<()> {
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let mut stream =
        tokio::time::timeout(Duration::from_secs(10), outbound.connect(&cx, &dst(target)))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    for size in [3usize, 70_000] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (mut read, mut write) = tokio::io::split(&mut stream);
        let writer = async {
            write.write_all(&data).await?;
            write.flush().await
        };
        let reader = async {
            let mut got = vec![0u8; size];
            read.read_exact(&mut got).await?;
            Ok::<_, std::io::Error>(got)
        };
        let (written, got) = tokio::join!(writer, reader);
        written?;
        assert_eq!(got?, data);
    }
    Ok(())
}

async fn echo_udp(outbound: &dyn Outbound, target: SocketAddr) {
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let session = outbound.associate(&cx, &dst(target)).await.unwrap();
    for size in [10usize, 1100, 3000] {
        let data: Vec<u8> = (0..size).map(|i| (i % 249) as u8).collect();
        let mut packet = PacketBuf::with_headroom(session.headroom());
        packet.extend_from_slice(&data);
        send_packet(&*session, &mut packet, &dst(target))
            .await
            .unwrap();
        let (got, from) = tokio::time::timeout(Duration::from_secs(10), recv_packet(&*session))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.as_slice(), data, "{size} bytes");
        assert_eq!(from, dst(target));
    }
}

async fn running(behavior: Behavior) -> (u16, Endpoint) {
    let (endpoint, port) = server_endpoint(&behavior);
    tokio::spawn(serve(endpoint.clone(), behavior));
    (port, endpoint)
}

#[tokio::test]
async fn tcp_and_udp_cross_the_wire() {
    let (port, _server) = running(Behavior::default()).await;
    let (tcp, udp) = (tcp_echo().await, udp_echo().await);
    let outbound = client(port, json!({})).unwrap();
    echo_tcp(&*outbound, tcp).await.unwrap();
    echo_udp(&*outbound, udp).await;
}

#[tokio::test]
async fn fast_open_reads_the_answer_late() {
    let (port, _server) = running(Behavior::default()).await;
    let tcp = tcp_echo().await;
    let outbound = client(port, json!({"fast-open": true})).unwrap();
    echo_tcp(&*outbound, tcp).await.unwrap();
}

#[tokio::test]
async fn a_refused_request_is_reported() {
    let behavior = Behavior {
        refuse: Some("nope"),
        ..Behavior::default()
    };
    let (port, _server) = running(behavior).await;
    let tcp = tcp_echo().await;
    let err = echo_tcp(&*client(port, json!({})).unwrap(), tcp)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("connection rejected: nope"),
        "{err}"
    );
    let err = echo_tcp(&*client(port, json!({"fast-open": true})).unwrap(), tcp)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("connection rejected: nope"),
        "{err}"
    );
}

#[tokio::test]
async fn a_wrong_auth_string_fails_the_connection() {
    let (port, _server) = running(Behavior::default()).await;
    let outbound = client(port, json!({"auth-str": "wrong"})).unwrap();
    let err = echo_tcp(&*outbound, tcp_echo().await).await.unwrap_err();
    assert!(err.to_string().contains("auth error"), "{err}");
}

#[tokio::test]
async fn base64_auth_overrides_the_auth_string() {
    let behavior = Behavior {
        auth: b"binary-token".to_vec(),
        ..Behavior::default()
    };
    let (port, _server) = running(behavior).await;
    let outbound = client(
        port,
        json!({"auth-str": "ignored", "auth": "YmluYXJ5LXRva2Vu"}),
    )
    .unwrap();
    echo_tcp(&*outbound, tcp_echo().await).await.unwrap();
}

#[tokio::test]
async fn obfuscated_links_carry_traffic() {
    let cases = [
        (ObfsSpec::XPlus(b"pw".to_vec()), json!({"obfs": "pw"})),
        (ObfsSpec::WeChat(None), json!({"protocol": "wechat-video"})),
        (
            ObfsSpec::WeChat(Some(b"pw".to_vec())),
            json!({"obfs-protocol": "wechat-video", "obfs": "pw"}),
        ),
    ];
    for (spec, extra) in cases {
        let behavior = Behavior {
            obfs: Some(spec),
            ..Behavior::default()
        };
        let (port, _server) = running(behavior).await;
        let (tcp, udp) = (tcp_echo().await, udp_echo().await);
        let outbound = client(port, extra.clone()).unwrap();
        echo_tcp(&*outbound, tcp).await.unwrap();
        echo_udp(&*outbound, udp).await;
    }
}

#[tokio::test]
async fn a_dropped_connection_is_replaced_on_the_next_request() {
    let (port, _server) = running(Behavior::default()).await;
    let tcp = tcp_echo().await;
    let outbound = client(port, json!({})).unwrap();
    echo_tcp(&*outbound, tcp).await.unwrap();
    outbound.reset_sessions();
    echo_tcp(&*outbound, tcp).await.unwrap();
}

#[tokio::test]
async fn a_connection_made_across_a_reset_is_not_kept() {
    let behavior = Behavior::default();
    let accepted = behavior.accepted.clone();
    let (port, _server) = running(behavior).await;
    let tcp = tcp_echo().await;
    let outbound = client(port, json!({"server": "localhost"})).unwrap();
    let held = HeldLookup::new();
    let straddling = {
        let (outbound, env) = (outbound.clone(), held.env());
        tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            outbound.connect(&cx, &dst(tcp)).await.map(drop)
        })
    };
    held.entered().await;
    outbound.reset_sessions();
    held.release();
    let outcome = crate::testing::settled(straddling).await;
    echo_tcp(&*outbound, tcp).await.unwrap();
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "the next request went over the connection made before the reset"
    );
    assert!(outcome.is_err());
}

#[test]
fn options_follow_the_go_adapter() {
    let ok = |extra: Value| client(1, extra);
    assert!(ok(json!({})).is_ok());
    assert!(ok(json!({"up": "fast"})).is_err());
    assert!(ok(json!({"down": "0"})).is_err());
    assert!(ok(json!({"up": "5 Mbps", "down": "1 Gbps"})).is_ok());
    assert!(ok(json!({"auth": "***"})).is_err());
    assert!(ok(json!({"protocol": "bogus"})).is_err());
    assert!(ok(json!({"ports": "1000-1010", "hop-interval": 3})).is_ok());
    assert!(ok(json!({"ports": "70000"})).is_err());
    let faketcp = ok(json!({"protocol": "faketcp"})).err().unwrap();
    assert!(faketcp.is_unsupported());
    let faketcp = ok(json!({"obfs-protocol": "faketcp"})).err().unwrap();
    assert!(faketcp.is_unsupported());
}

#[test]
fn the_speed_options_override_the_rate_strings() {
    let proxy = json!({"name": "h", "type": "hysteria", "server": "x", "port": 1,
        "up": "10", "down": "20", "up-speed": 30});
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        unreachable!()
    };
    let ProxyKind::Hysteria(opts) = &def.kind else {
        unreachable!()
    };
    assert_eq!(super::rates(opts).unwrap(), (30 * 125_000, 20 * 125_000));
}
