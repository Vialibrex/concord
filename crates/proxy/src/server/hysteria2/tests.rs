use indexmap::IndexMap;

use super::super::quic_testing::{Running, close_and_drain, tls_setup, unnamed_tls};
use super::*;
use crate::hysteria2::wire::{UdpHeader, put_udp_header, put_varint, tcp_request};

fn config(users: &[(&str, &str)]) -> Hysteria2Server {
    Hysteria2Server {
        users: users
            .iter()
            .map(|(name, password)| ((*name).to_owned(), (*password).to_owned()))
            .collect::<IndexMap<_, _>>(),
        salamander: None,
        up: String::new(),
        down: String::new(),
        ignore_client_bandwidth: false,
        tls: unnamed_tls(),
        alpn: Vec::new(),
        udp_mtu: 0,
        cwnd: 0,
        bbr_profile: String::new(),
        initial_stream_window: 0,
        max_stream_window: 0,
        initial_conn_window: 0,
        max_conn_window: 0,
    }
}

fn server(users: &[(&str, &str)]) -> Arc<Hysteria2> {
    Arc::new(Hysteria2::new(&config(users), tls_setup()).unwrap())
}

type Requests = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// A connection takes one HTTP/3 client: a second would open a second control stream, which
/// the server refuses.
async fn h3(conn: &quinn::Connection) -> Requests {
    let (mut driver, requests) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    requests
}

async fn authenticate(requests: &mut Requests, password: &str) -> u16 {
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("https://hysteria/auth")
        .header("Hysteria-Auth", password)
        .header("Hysteria-CC-RX", "0")
        .body(())
        .unwrap();
    let mut exchange = requests.send_request(request).await.unwrap();
    exchange.finish().await.unwrap();
    exchange.recv_response().await.unwrap().status().as_u16()
}

async fn requests_tcp(conn: &quinn::Connection) -> bool {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&tcp_request("1.2.3.4:80")).await.unwrap();
    let mut first = [0u8; 1];
    matches!(recv.read(&mut first).await, Ok(Some(1)))
}

#[tokio::test]
async fn a_wrong_password_gets_the_404_and_no_tcp_is_served_before_authentication() {
    let running = Running::start(server(&[("alice", "secret")]));
    let conn = running.connect(b"h3").await;
    assert!(!requests_tcp(&conn).await);
    let mut requests = h3(&conn).await;
    assert_eq!(authenticate(&mut requests, "wrong").await, 404);
    assert!(!requests_tcp(&conn).await);
    assert_eq!(running.flows.opened(), []);

    assert_eq!(authenticate(&mut requests, "secret").await, AUTH_OK);
    requests_tcp(&conn).await;
    let opened = running.flows.wait_for(1).await;
    assert_eq!(
        opened,
        [(Address::new("1.2.3.4", 80), Some(Arc::from("alice")))]
    );
}

#[tokio::test]
async fn a_header_block_over_the_limit_is_refused_from_its_length_and_the_connection_stays() {
    let running = Running::start(server(&[("alice", "secret")]));
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    let mut head = Vec::new();
    put_varint(&mut head, 0x01);
    put_varint(&mut head, MAX_HEADER_BYTES + 1);
    send.write_all(&head).await.unwrap();
    let excessive_load = VarInt::from_u32(0x107);
    assert_eq!(send.stopped().await.unwrap(), Some(excessive_load));
    assert_eq!(authenticate(&mut requests, "secret").await, AUTH_OK);
}

#[tokio::test]
async fn a_kept_port_takes_new_users_for_new_connections_and_keeps_open_ones() {
    let running = Running::start(server(&[("alice", "one")]));
    let open = running.connect(b"h3").await;
    let mut open_requests = h3(&open).await;
    assert_eq!(authenticate(&mut open_requests, "one").await, AUTH_OK);

    running.current.send_replace(Current {
        service: server(&[("bob", "two")]),
        cx: running.cx.clone(),
    });
    requests_tcp(&open).await;
    let opened = running.flows.wait_for(1).await;
    assert_eq!(opened.first().unwrap().1.as_deref(), Some("alice"));

    let stale = running.connect(b"h3").await;
    assert_eq!(authenticate(&mut h3(&stale).await, "one").await, 404);
    let fresh = running.connect(b"h3").await;
    assert_eq!(authenticate(&mut h3(&fresh).await, "two").await, AUTH_OK);
}

fn datagram(session: u32) -> Bytes {
    let mut out = Vec::new();
    put_udp_header(
        &mut out,
        &UdpHeader {
            session,
            packet: 0,
            fragment: 0,
            fragments: 1,
            addr: "1.2.3.4:53",
        },
    );
    out.extend_from_slice(b"query");
    Bytes::from(out)
}

#[tokio::test]
async fn an_idle_udp_session_ends_and_frees_its_id() {
    let running = Running::start(server(&[("alice", "secret")]));
    let conn = running.connect(b"h3").await;
    let sessions = Arc::new(Sessions::<String>::default());
    let (_, inbox) = sessions.register(|_| Some(7)).unwrap();
    tokio::time::pause();
    let session = Session::new(7, Sender::new(7, conn, DEFAULT_UDP_MTU), inbox, &sessions);
    let start = tokio::time::Instant::now();
    let mut buf = PacketBuf::take();
    let ended = std::future::poll_fn(|cx| session.poll_recv(cx, &mut buf)).await;
    assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(start.elapsed(), UDP_IDLE);
    assert!(
        sessions
            .register(|taken| (!taken(7)).then_some(7))
            .is_some(),
        "the idle session kept its id"
    );
}

#[tokio::test]
async fn a_stopped_listener_frees_its_port_while_a_udp_reply_is_kept() {
    let running = Running::start(server(&[("alice", "secret")]));
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    assert_eq!(authenticate(&mut requests, "secret").await, AUTH_OK);
    conn.send_datagram(datagram(7)).unwrap();
    running.flows.datagrams(1).await;
    drop(requests);
    close_and_drain(&conn).await;
    running.stop_and_rebind().await;
}

#[test]
fn the_client_rate_picks_brutal_or_bbr_as_sing_quic_does() {
    let mbps = 125_000;
    for (up, down, ignore, rx, pace) in [
        ("", "", false, 0, Some(Pace::Bbr)),
        ("", "", false, mbps, Some(Pace::Brutal(mbps))),
        ("1 Mbps", "", false, 9 * mbps, Some(Pace::Brutal(mbps))),
        ("", "", true, mbps, Some(Pace::Bbr)),
        ("", "1 Mbps", true, 0, None),
        ("", "1 Mbps", true, mbps, Some(Pace::Brutal(mbps))),
    ] {
        let mut config = config(&[]);
        config.up = up.into();
        config.down = down.into();
        config.ignore_client_bandwidth = ignore;
        let server = Hysteria2::new(&config, tls_setup()).unwrap();
        assert_eq!(
            server.pace(rx),
            pace,
            "up {up:?} down {down:?} ignore {ignore} rx {rx}"
        );
    }
}
