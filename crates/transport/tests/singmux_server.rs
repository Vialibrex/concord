//! The sing-mux server against the client, and against raw frames where the server's side
//! of a protocol differs from the client's.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use concord_common::sync::lock;
use concord_common::{Address, BoxStream, Tasks};
use concord_transport::{MuxDialFn, MuxProtocol, SingMuxClient, SingMuxOptions, serve_mux_session};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex, split};

const PROTOCOLS: [MuxProtocol; 3] = [MuxProtocol::Smux, MuxProtocol::Yamux, MuxProtocol::H2Mux];

/// Each stream's flags and destination, as the server's stream handler read them.
type Requests = Arc<Mutex<Vec<(u16, Address)>>>;

async fn read_request(stream: &mut BoxStream) -> (u16, Address) {
    let flags = stream.read_u16().await.unwrap();
    let address = match stream.read_u8().await.unwrap() {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            Address::Socket((octets, port).into())
        }
        0x03 => {
            let mut name = vec![0u8; usize::from(stream.read_u8().await.unwrap())];
            stream.read_exact(&mut name).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            Address::new(std::str::from_utf8(&name).unwrap(), port)
        }
        other => panic!("unexpected address family {other}"),
    };
    (flags, address)
}

/// Echoes every stream after its request.
fn echo(requests: &Requests) -> impl Fn(BoxStream) + Send + Sync + 'static {
    let requests = requests.clone();
    move |mut stream: BoxStream| {
        let requests = requests.clone();
        tokio::spawn(async move {
            let request = read_request(&mut stream).await;
            lock(&requests).push(request);
            let (mut read, mut write) = split(stream);
            let _ = tokio::io::copy(&mut read, &mut write).await;
            let _ = write.shutdown().await;
        });
    }
}

struct Harness {
    client: Arc<SingMuxClient>,
    requests: Requests,
    sessions: Arc<AtomicUsize>,
}

fn harness(opts: SingMuxOptions, server_padding: bool) -> Harness {
    let requests = Requests::default();
    let sessions = Arc::new(AtomicUsize::new(0));
    let tasks = Tasks::default();
    let dial: MuxDialFn = {
        let (requests, sessions) = (requests.clone(), sessions.clone());
        Arc::new(move |_| {
            let (near, far) = duplex(1 << 20);
            let on_stream = echo(&requests);
            let (sessions, tasks) = (sessions.clone(), tasks.clone());
            tokio::spawn(async move {
                let served = serve_mux_session(Box::new(far), server_padding, &tasks, &on_stream);
                if served.await.is_ok() {
                    sessions.fetch_add(1, Ordering::SeqCst);
                }
            });
            Box::pin(async move { Ok(Box::new(near) as BoxStream) })
        })
    };
    Harness {
        client: SingMuxClient::new(opts, dial, Tasks::default()),
        requests,
        sessions,
    }
}

fn options(protocol: MuxProtocol, padding: bool) -> SingMuxOptions {
    SingMuxOptions {
        protocol,
        padding,
        max_connections: 1,
        ..SingMuxOptions::default()
    }
}

fn target() -> Address {
    Address::new("example.com", 443)
}

#[tokio::test]
async fn every_protocol_echoes_with_and_without_padding() {
    for protocol in PROTOCOLS {
        for padding in [false, true] {
            let h = harness(options(protocol, padding), false);
            let mut io = h.client.connect_tcp(&target()).await.unwrap();
            io.write_all(b"hello").await.unwrap();
            let mut got = [0u8; 5];
            io.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello", "{protocol:?} padding={padding}");
            assert_eq!(lock(&h.requests).clone(), [(0, target())]);
        }
    }
}

#[tokio::test]
async fn a_server_that_pads_refuses_a_client_that_does_not() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false), true);
        let refused = async {
            let mut io = h.client.connect_tcp(&target()).await?;
            io.write_all(b"hello").await?;
            io.read_u8().await
        };
        assert!(refused.await.is_err(), "{protocol:?}");
        assert!(lock(&h.requests).is_empty());
        let h = harness(options(protocol, true), true);
        let mut io = h.client.connect_tcp(&target()).await.unwrap();
        io.write_all(b"x").await.unwrap();
        assert_eq!(io.read_u8().await.unwrap(), b'x', "{protocol:?}");
    }
}

#[tokio::test]
async fn streams_of_one_session_carry_their_own_bytes_both_ways() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false), false);
        let mut ios = Vec::new();
        for _ in 0..5 {
            ios.push(h.client.connect_tcp(&target()).await.unwrap());
        }
        for (i, io) in ios.iter_mut().enumerate() {
            io.write_all(&[i as u8]).await.unwrap();
        }
        for (i, io) in ios.iter_mut().enumerate() {
            assert_eq!(io.read_u8().await.unwrap(), i as u8, "{protocol:?}");
        }
        assert_eq!(lock(&h.requests).len(), 5);
    }
}

#[tokio::test]
async fn large_transfers_cross_the_flow_control_windows() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false), false);
        let io = h.client.connect_tcp(&target()).await.unwrap();
        let data: Vec<u8> = (0..900_000u32).map(|i| (i % 253) as u8).collect();
        let (mut read, mut write) = split(io);
        let send = {
            let data = data.clone();
            async move {
                for chunk in data.chunks(9000) {
                    write.write_all(chunk).await.unwrap();
                }
                write
            }
        };
        let mut echoed = vec![0u8; data.len()];
        let (_, got) = tokio::join!(send, read.read_exact(&mut echoed));
        got.unwrap();
        assert!(echoed == data, "{protocol:?}");
    }
}

#[tokio::test]
async fn a_half_closed_stream_still_gets_its_echo_where_the_protocol_has_half_close() {
    for protocol in [MuxProtocol::Yamux, MuxProtocol::H2Mux] {
        let h = harness(options(protocol, false), false);
        let mut io = h.client.connect_tcp(&target()).await.unwrap();
        io.write_all(b"abc").await.unwrap();
        io.shutdown().await.unwrap();
        let mut got = Vec::new();
        io.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"abc", "{protocol:?}");
    }
}

#[tokio::test]
async fn udp_streams_carry_their_flags() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false), false);
        let dns = Address::new("8.8.8.8", 53);
        let mut udp = h.client.connect_udp(&dns).await.unwrap();
        udp.write_all(&[0, 1, b'q']).await.unwrap();
        let mut echoed = [0u8; 3];
        udp.read_exact(&mut echoed).await.unwrap();
        let mut packets = h.client.listen_packet(Some(&dns)).await.unwrap();
        packets.write_all(b"p").await.unwrap();
        assert_eq!(packets.read_u8().await.unwrap(), b'p');
        assert_eq!(
            lock(&h.requests).clone(),
            [(1, dns.clone()), (3, dns)],
            "{protocol:?}"
        );
    }
}

#[tokio::test]
async fn a_session_ends_when_its_client_closes() {
    for protocol in PROTOCOLS {
        let h = harness(options(protocol, false), false);
        let mut io = h.client.connect_tcp(&target()).await.unwrap();
        io.write_all(b"x").await.unwrap();
        io.read_u8().await.unwrap();
        h.client.close().await;
        drop(io);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while h.sessions.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

fn yamux_header(kind: u8, flags: u16, sid: u32, length: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[1] = kind;
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[4..8].copy_from_slice(&sid.to_be_bytes());
    out[8..12].copy_from_slice(&length.to_be_bytes());
    out
}

/// metacubex/yamux's `AcceptStream` (`session.go:263-277`) answers a SYN with a window update
/// that carries ACK.
#[tokio::test]
async fn a_yamux_server_acknowledges_the_stream_a_client_opens() {
    let (mut near, far) = duplex(1 << 16);
    let requests = Requests::default();
    let on_stream = echo(&requests);
    tokio::spawn(async move {
        let _ = serve_mux_session(Box::new(far), false, &Tasks::default(), &on_stream).await;
    });
    near.write_all(&[0, 1]).await.unwrap();
    near.write_all(&yamux_header(1, 1, 1, 0)).await.unwrap();
    let mut reply = [0u8; 12];
    near.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, yamux_header(1, 2, 1, 0));
}

/// sing-mux's h2mux server ends a connection that has had no stream for its 30 s
/// `IdleTimeout` (`h2mux.go:35-65`).
#[tokio::test(start_paused = true)]
async fn an_idle_h2mux_session_ends() {
    let (mut near, far) = duplex(1 << 16);
    let requests = Requests::default();
    let on_stream = echo(&requests);
    let served = tokio::spawn(async move {
        serve_mux_session(Box::new(far), false, &Tasks::default(), &on_stream).await
    });
    near.write_all(&[0, 2]).await.unwrap();
    let (_send, connection) = h2::client::handshake(near).await.unwrap();
    tokio::spawn(connection);
    let started = tokio::time::Instant::now();
    tokio::time::timeout(std::time::Duration::from_secs(60), served)
        .await
        .expect("the idle session stayed open")
        .unwrap()
        .unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(30));
}
