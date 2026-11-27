use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use concord_common::sync::lock;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::*;

type Request = (String, String, String, String, String);

#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<Request>>,
    connections: AtomicUsize,
}

fn dial_to_server(seen: Arc<Seen>, status: u16) -> DialFn {
    dial_to_server_with_limit(seen, status, None)
}

fn dial_to_server_with_limit(
    seen: Arc<Seen>,
    status: u16,
    max_concurrent_streams: Option<u32>,
) -> DialFn {
    Arc::new(move || {
        let seen = seen.clone();
        Box::pin(async move {
            let (client, server) = duplex(1 << 20);
            seen.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut builder = h2::server::Builder::new();
                if let Some(limit) = max_concurrent_streams {
                    builder.max_concurrent_streams(limit);
                }
                let Ok(mut conn) = builder.handshake::<_, Bytes>(server).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    let seen = seen.clone();
                    tokio::spawn(async move {
                        let (parts, body) = request.into_parts();
                        let header = |name: &str| {
                            parts
                                .headers
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default()
                                .to_string()
                        };
                        lock(&seen.requests).push((
                            parts.method.to_string(),
                            parts.uri.path().to_string(),
                            parts
                                .uri
                                .authority()
                                .map(ToString::to_string)
                                .unwrap_or_default(),
                            header("content-type"),
                            header("user-agent"),
                        ));
                        let response = http::Response::builder().status(status).body(()).unwrap();
                        let send = respond.send_response(response, false).unwrap();
                        let mut framed = gun_framed(H2Body::new(send, Incoming::Body(body)));
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match framed.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if framed.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        let _ = framed.shutdown().await;
                    });
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    })
}

fn opts() -> GrpcOptions {
    GrpcOptions {
        service_name: "svc".into(),
        authority: "node.example.com:443".into(),
        ..GrpcOptions::default()
    }
}

#[tokio::test]
async fn advertises_the_reference_h2_flow_control_and_frame_limits() {
    let (near, mut far) = duplex(1 << 16);
    let observed = tokio::spawn(async move { crate::h2io::tests::client_settings(&mut far).await });
    let io = Box::new(near) as BoxStream;
    let (sender, conn) = client_builder().handshake::<_, Bytes>(io).await.unwrap();
    let driver = tokio::spawn(conn);
    let (settings, update) = observed.await.unwrap();
    assert_eq!(settings.get(&2), Some(&0));
    assert_eq!(settings.get(&4), Some(&(4 << 20)));
    assert_eq!(settings.get(&5), Some(&(1 << 20)));
    assert_eq!(settings.get(&6), Some(&(10 << 20)));
    assert_eq!(update, 1 << 30);
    drop(sender);
    driver.abort();
}

#[test]
fn service_paths_match_gun() {
    assert_eq!(service_path(""), "/GunService/Tun");
    assert_eq!(service_path("abc"), "/abc/Tun");
    assert_eq!(service_path("/custom/path"), "/custom/path");
}

#[tokio::test]
async fn request_shape_and_large_echo() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server(seen.clone(), 200),
        Default::default(),
    );
    let conn = client.dial().await.unwrap();
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 247) as u8).collect();
    let send = payload.clone();
    let (mut rd, mut wr) = tokio::io::split(conn);
    let writer = tokio::spawn(async move {
        wr.write_all(&send).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    rd.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got, payload);
    let requests = lock(&seen.requests);
    assert_eq!(
        requests[0],
        (
            "POST".to_string(),
            "/svc/Tun".to_string(),
            "node.example.com:443".to_string(),
            "application/grpc".to_string(),
            "grpc-go/1.36.0".to_string()
        )
    );
}

#[tokio::test]
async fn custom_user_agent_is_sent() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.user_agent = "my-agent".into();
    let client = GunClient::new(o, dial_to_server(seen.clone(), 200), Default::default());
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    conn.read_exact(&mut one).await.unwrap();
    assert_eq!(lock(&seen.requests)[0].4, "my-agent");
}

#[tokio::test]
async fn streams_share_one_connection_by_default() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server(seen.clone(), 200),
        Default::default(),
    );
    let mut conns = Vec::new();
    for _ in 0..5 {
        conns.push(client.dial().await.unwrap());
    }
    for (idx, conn) in conns.iter_mut().enumerate() {
        let msg = [idx as u8; 3];
        conn.write_all(&msg).await.unwrap();
        let mut back = [0u8; 3];
        conn.read_exact(&mut back).await.unwrap();
        assert_eq!(back, msg);
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn max_streams_opens_another_connection_when_full() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.max_streams = 2;
    let client = GunClient::new(o, dial_to_server(seen.clone(), 200), Default::default());
    let mut conns = Vec::new();
    for _ in 0..5 {
        conns.push(client.dial().await.unwrap());
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
    drop(conns);
    let _again = client.dial().await.unwrap();
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn max_connections_bounds_the_pool_and_min_streams_fills_first() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.max_connections = 2;
    o.min_streams = 3;
    let client = GunClient::new(o, dial_to_server(seen.clone(), 200), Default::default());
    let mut conns = Vec::new();
    for _ in 0..3 {
        conns.push(client.dial().await.unwrap());
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    for _ in 0..4 {
        conns.push(client.dial().await.unwrap());
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn half_close_still_delivers_the_reply() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(opts(), dial_to_server(seen, 200), Default::default());
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"last words").await.unwrap();
    conn.shutdown().await.unwrap();
    let mut got = Vec::new();
    conn.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"last words");
}

#[tokio::test]
async fn a_failing_status_is_a_read_error() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(opts(), dial_to_server(seen, 404), Default::default());
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 1];
    let err = conn.read(&mut buf).await.unwrap_err();
    assert!(err.to_string().contains("404"));
}

#[tokio::test]
async fn a_dead_connection_is_replaced() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server(seen.clone(), 200),
        Default::default(),
    );
    drop(client.dial().await.unwrap());
    {
        let transport = lock(&client.pool).first().cloned().unwrap();
        transport.close();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut conn = client.dial().await.unwrap();
    conn.write_all(b"ok").await.unwrap();
    let mut back = [0u8; 2];
    conn.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ok");
}

#[tokio::test]
async fn split_halves_echo_concurrently_and_shutdown_keeps_reading() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(opts(), dial_to_server(seen, 200), Default::default());
    let (mut rd, mut wr) = client.dial().await.unwrap().into_split();
    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 241) as u8).collect();
    let send = payload.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&send).await.unwrap();
        wr.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    rd.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();
    assert_eq!(got, payload);
}

async fn echo_once(conn: &mut BoxStream, byte: u8) {
    conn.write_all(&[byte]).await.unwrap();
    let mut back = [0u8; 1];
    conn.read_exact(&mut back).await.unwrap();
    assert_eq!(back[0], byte);
}

#[tokio::test]
async fn peer_stream_limit_opens_another_connection_by_default() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server_with_limit(seen.clone(), 200, Some(2)),
        Default::default(),
    );
    let mut conns = Vec::new();
    for idx in 0..5u8 {
        let mut conn = tokio::time::timeout(Duration::from_secs(2), async {
            let mut conn = client.dial().await.unwrap();
            echo_once(&mut conn, idx).await;
            conn
        })
        .await
        .expect("stream stalled past peer concurrent-stream limit");
        echo_once(&mut conn, idx + 10).await;
        conns.push(conn);
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
    drop(conns);
}

#[tokio::test]
async fn explicit_max_connections_opens_another_connection_past_peer_limit() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.max_connections = 1;
    let client = GunClient::new(
        o,
        dial_to_server_with_limit(seen.clone(), 200, Some(2)),
        Default::default(),
    );
    let mut conns = Vec::new();
    for idx in 0..3u8 {
        let conn = tokio::time::timeout(Duration::from_secs(2), async {
            let mut conn = client.dial().await.unwrap();
            echo_once(&mut conn, idx).await;
            conn
        })
        .await
        .expect("stream stalled past peer limit with explicit max_connections");
        conns.push(conn);
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
    drop(conns);
}

#[tokio::test]
async fn explicit_max_connections_spills_at_peer_limit_before_min_streams() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.max_connections = 2;
    o.min_streams = 4;
    let client = GunClient::new(
        o,
        dial_to_server_with_limit(seen.clone(), 200, Some(2)),
        Default::default(),
    );
    let mut conns = Vec::new();
    for idx in 0..5u8 {
        let conn = tokio::time::timeout(Duration::from_secs(2), async {
            let mut conn = client.dial().await.unwrap();
            echo_once(&mut conn, idx).await;
            conn
        })
        .await
        .expect("stream stalled past peer limit");
        conns.push(conn);
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
    drop(conns);
}

#[tokio::test]
async fn max_streams_above_peer_limit_opens_another_connection() {
    let seen = Arc::new(Seen::default());
    let mut o = opts();
    o.max_streams = 10;
    let client = GunClient::new(
        o,
        dial_to_server_with_limit(seen.clone(), 200, Some(2)),
        Default::default(),
    );
    let mut conns = Vec::new();
    for idx in 0..3u8 {
        let conn = tokio::time::timeout(Duration::from_secs(2), async {
            let mut conn = client.dial().await.unwrap();
            echo_once(&mut conn, idx).await;
            conn
        })
        .await
        .expect("stream stalled past peer limit under larger max_streams");
        conns.push(conn);
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
    drop(conns);
}

fn dial_hold_first_then_echo(seen: Arc<Seen>, release: Arc<tokio::sync::Notify>) -> DialFn {
    Arc::new(move || {
        let seen = seen.clone();
        let release = release.clone();
        Box::pin(async move {
            let (client, server) = duplex(1 << 20);
            let idx = seen.connections.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(mut conn) = h2::server::Builder::new()
                    .handshake::<_, Bytes>(server)
                    .await
                else {
                    return;
                };
                if idx == 0 {
                    if let Some(Ok((_req, mut respond))) = conn.accept().await {
                        release.notified().await;
                        let _ = respond.send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                            true,
                        );
                        while conn.accept().await.is_some() {}
                    }
                    return;
                }
                while let Some(Ok((request, mut respond))) = conn.accept().await {
                    tokio::spawn(async move {
                        let send = respond
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                false,
                            )
                            .unwrap();
                        let mut framed =
                            gun_framed(H2Body::new(send, Incoming::Body(request.into_body())));
                        let mut buf = [0u8; 64];
                        while let Ok(n) = framed.read(&mut buf).await {
                            if n == 0 || framed.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            Ok(Box::new(client) as BoxStream)
        })
    })
}

#[tokio::test]
async fn pick_evicts_a_transport_whose_driver_ended() {
    let seen = Arc::new(Seen::default());
    let release = Arc::new(tokio::sync::Notify::new());
    let dial: DialFn = {
        let seen = seen.clone();
        let release = release.clone();
        Arc::new(move || {
            let seen = seen.clone();
            let release = release.clone();
            Box::pin(async move {
                let (client, server) = duplex(1 << 20);
                let idx = seen.connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let Ok(mut conn) = h2::server::Builder::new()
                        .handshake::<_, Bytes>(server)
                        .await
                    else {
                        return;
                    };
                    if idx == 0 {
                        if let Some(Ok((request, mut respond))) = conn.accept().await {
                            tokio::spawn(async move {
                                let send = respond
                                    .send_response(
                                        http::Response::builder().status(200).body(()).unwrap(),
                                        false,
                                    )
                                    .unwrap();
                                let mut framed = gun_framed(H2Body::new(
                                    send,
                                    Incoming::Body(request.into_body()),
                                ));
                                let mut one = [0u8; 1];
                                if framed.read_exact(&mut one).await.is_ok() {
                                    let _ = framed.write_all(&one).await;
                                    let _ = framed.shutdown().await;
                                }
                            });
                            tokio::select! {
                                _ = release.notified() => {}
                                _ = async { while conn.accept().await.is_some() {} } => {}
                            }
                        }
                        return;
                    }
                    while let Some(Ok((request, mut respond))) = conn.accept().await {
                        tokio::spawn(async move {
                            let send = respond
                                .send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                    false,
                                )
                                .unwrap();
                            let mut framed =
                                gun_framed(H2Body::new(send, Incoming::Body(request.into_body())));
                            let mut buf = [0u8; 64];
                            while let Ok(n) = framed.read(&mut buf).await {
                                if n == 0 || framed.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        });
                    }
                });
                Ok(Box::new(client) as BoxStream)
            })
        })
    };
    let client = GunClient::new(opts(), dial, Default::default());
    let mut first = client.dial().await.unwrap();
    echo_once(&mut first, 1).await;
    let first_transport = lock(&client.pool).first().cloned().unwrap();
    drop(first);
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut second = client.dial().await.unwrap();
    echo_once(&mut second, 2).await;
    let pool = lock(&client.pool);
    assert_eq!(pool.len(), 1);
    assert!(!Arc::ptr_eq(&pool[0], &first_transport));
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn pick_evicts_a_transport_whose_h2_streams_lock_is_poisoned() {
    use std::pin::Pin;
    use std::task::Context;
    use tokio::io::{AsyncRead, ReadBuf};

    let seen = Arc::new(Seen::default());
    let release = Arc::new(tokio::sync::Notify::new());
    let client = GunClient::new(
        opts(),
        dial_hold_first_then_echo(seen.clone(), release.clone()),
        Default::default(),
    );
    let mut first = client.dial().await.unwrap();
    let first_transport = lock(&client.pool).first().cloned().unwrap();
    let waker = crate::h2io::tests::panic_waker();
    let mut cx = Context::from_waker(&waker);
    let mut byte = [0u8; 1];
    let mut buf = ReadBuf::new(&mut byte);
    assert!(
        Pin::new(&mut first)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut second = client.dial().await.unwrap();
    echo_once(&mut second, 7).await;
    let pool = lock(&client.pool);
    assert_eq!(pool.len(), 1);
    assert!(!Arc::ptr_eq(&pool[0], &first_transport));
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
    drop(pool);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(first)));
}

#[tokio::test]
async fn concurrent_burst_past_peer_limit_opens_enough_connections() {
    let seen = Arc::new(Seen::default());
    let client = GunClient::new(
        opts(),
        dial_to_server_with_limit(seen.clone(), 200, Some(100)),
        Default::default(),
    );
    let mut tasks = Vec::new();
    for idx in 0..205usize {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let mut conn = client.dial().await.unwrap();
            echo_once(&mut conn, (idx % 251) as u8).await;
            conn
        }));
    }
    let mut held = Vec::with_capacity(205);
    for task in tasks {
        held.push(
            tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("concurrent burst stalled past peer limit")
                .unwrap(),
        );
    }
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
    drop(held);
}

#[tokio::test]
async fn mid_flight_lower_peer_limit_opens_another_connection() {
    let seen = Arc::new(Seen::default());
    let lower = Arc::new(tokio::sync::Notify::new());
    let lowered = Arc::new(tokio::sync::Notify::new());
    let dial: DialFn = {
        let seen = seen.clone();
        let lower = lower.clone();
        let lowered = lowered.clone();
        Arc::new(move || {
            let seen = seen.clone();
            let lower = lower.clone();
            let lowered = lowered.clone();
            Box::pin(async move {
                let (client, mut server) = duplex(1 << 20);
                let idx = seen.connections.fetch_add(1, Ordering::SeqCst);
                if idx == 0 {
                    tokio::spawn(async move {
                        let mut preface = [0u8; 24];
                        if server.read_exact(&mut preface).await.is_err() {
                            return;
                        }
                        let settings_4 = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 4];
                        let settings_ack = [0, 0, 0, 4, 1, 0, 0, 0, 0];
                        let _ = server.write_all(&settings_4).await;
                        let _ = server.write_all(&settings_ack).await;
                        let _ = server.flush().await;
                        lower.notified().await;
                        let settings_2 = [0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 2];
                        let _ = server.write_all(&settings_2).await;
                        let _ = server.flush().await;
                        lowered.notify_one();
                        let mut drain = [0u8; 256];
                        while matches!(server.read(&mut drain).await, Ok(n) if n > 0) {}
                    });
                } else {
                    tokio::spawn(async move {
                        let Ok(mut conn) = h2::server::Builder::new()
                            .max_concurrent_streams(2)
                            .handshake::<_, Bytes>(server)
                            .await
                        else {
                            return;
                        };
                        while let Some(Ok((request, mut respond))) = conn.accept().await {
                            tokio::spawn(async move {
                                let send = respond
                                    .send_response(
                                        http::Response::builder().status(200).body(()).unwrap(),
                                        false,
                                    )
                                    .unwrap();
                                let mut framed = gun_framed(H2Body::new(
                                    send,
                                    Incoming::Body(request.into_body()),
                                ));
                                let mut buf = [0u8; 64];
                                while let Ok(n) = framed.read(&mut buf).await {
                                    if n == 0 || framed.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    });
                }
                Ok(Box::new(client) as BoxStream)
            })
        })
    };
    let client = GunClient::new(opts(), dial, Default::default());
    let first = client.dial().await.unwrap();
    let second = client.dial().await.unwrap();
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);

    lower.notify_one();
    lowered.notified().await;
    for _ in 0..40 {
        if lock(&client.pool)[0].peer_max_streams() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(lock(&client.pool)[0].peer_max_streams(), 2);

    let mut third = tokio::time::timeout(Duration::from_secs(2), client.dial())
        .await
        .expect("stream stalled after peer lowered concurrent-stream limit")
        .unwrap();
    echo_once(&mut third, 9).await;
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
    drop((first, second, third));
}

#[tokio::test]
async fn cancelled_dial_releases_reserved_stream_count() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let entered_dial = entered.clone();
    let dial: DialFn = Arc::new(move || {
        let entered_dial = entered_dial.clone();
        Box::pin(async move {
            entered_dial.notify_one();
            std::future::pending::<io::Result<BoxStream>>().await
        })
    });
    let client = GunClient::new(opts(), dial, Default::default());
    let pending = {
        let client = client.clone();
        tokio::spawn(async move { client.dial().await })
    };
    entered.notified().await;
    assert_eq!(lock(&client.pool)[0].streams(), 1);
    pending.abort();
    let _ = pending.await;
    assert_eq!(lock(&client.pool)[0].streams(), 0);
}
