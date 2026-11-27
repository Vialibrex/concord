use h2::Reason;
use h2::client::SendRequest;
use tokio::sync::{mpsc, oneshot};

use super::*;

fn echo(req: http::Request<h2::RecvStream>, mut respond: h2::server::SendResponse<Bytes>) {
    let Ok(mut send) = respond.send_response(http::Response::new(()), false) else {
        return;
    };
    tokio::spawn(async move {
        let mut body = req.into_body();
        let mut got = Vec::new();
        while let Some(Ok(chunk)) = body.data().await {
            let _ = body.flow_control().release_capacity(chunk.len());
            got.extend_from_slice(&chunk);
        }
        let _ = send.send_data(Bytes::from(got), true);
    });
}

async fn open(sender: &SendRequest<Bytes>) -> H2Body {
    let (response, send) = sender
        .clone()
        .ready()
        .await
        .unwrap()
        .send_request(http::Request::new(()), false)
        .unwrap();
    H2Body::new(send, Incoming::Response(response))
}

async fn finish_echo(mut body: H2Body, sent: &[u8]) -> io::Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        body.write_all(sent).await?;
        body.shutdown().await?;
        let mut got = Vec::new();
        body.read_to_end(&mut got).await?;
        Ok(got)
    })
    .await
    .expect("the echo stream should finish")
}

/// Starts a write on `body` while the outbound flush is paused and returns once the write is
/// parked on that flush, so the stream owns the writer.
async fn write_parked_on_flush(
    ctrl: &WriteControl,
    mut body: H2Body,
    data: Vec<u8>,
) -> tokio::task::JoinHandle<(H2Body, io::Result<usize>)> {
    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.set_flush_paused(true);
    let task = tokio::spawn(async move {
        let res = body.write(&data).await;
        (body, res)
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !task.is_finished(),
        "the write should wait on the paused flush"
    );
    task
}

async fn joined<T>(task: tokio::task::JoinHandle<T>, what: &str) -> T {
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap_or_else(|_| panic!("{what}"))
        .unwrap()
}

#[tokio::test]
async fn split_direct_write_finishes_its_frame_when_the_initial_window_shrinks_mid_flush() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let (window_tx, mut window_rx) = mpsc::unbounded_channel::<u32>();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        loop {
            tokio::select! {
                next = conn.accept() => match next {
                    Some(Ok((req, respond))) => echo(req, respond),
                    _ => break,
                },
                Some(window) = window_rx.recv() => conn.set_initial_window_size(window).unwrap(),
            }
        }
    });
    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let mut body = open(&sender).await;
    body.write_all(b"opened").await.unwrap();
    let first = vec![1u8; 4096];
    let write = write_parked_on_flush(&ctrl, body, first.clone()).await;
    window_tx.send(5000).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.set_flush_paused(false);

    let (body, res) = joined(write, "the parked write should finish").await;
    assert_eq!(res.unwrap(), first.len());
    let rest = vec![2u8; 8192];
    let got = finish_echo(body, &rest).await.unwrap();
    assert_eq!(got, [&b"opened"[..], &first[..], &rest[..]].concat());
    assert_eq!(
        finish_echo(open(&sender).await, b"sibling").await.unwrap(),
        b"sibling"
    );

    driver.abort();
    server.abort();
}

#[tokio::test]
async fn split_direct_write_survives_a_reset_of_its_stream_mid_flush() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let (reset_tx, reset_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let (_req, mut first) = conn.accept().await.unwrap().unwrap();
        let mut reset_rx = Some(reset_rx);
        loop {
            tokio::select! {
                next = conn.accept() => match next {
                    Some(Ok((req, respond))) => echo(req, respond),
                    _ => break,
                },
                Ok(()) = async { reset_rx.as_mut().unwrap().await }, if reset_rx.is_some() => {
                    reset_rx = None;
                    first.send_reset(Reason::CANCEL);
                }
            }
        }
    });
    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let mut body = open(&sender).await;
    body.write_all(b"opened").await.unwrap();
    let write = write_parked_on_flush(&ctrl, body, vec![1u8; 4096]).await;
    reset_tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.set_flush_paused(false);

    let (mut body, _) = joined(write, "the parked write should finish").await;
    let after = tokio::time::timeout(Duration::from_secs(3), body.write_all(&[2u8; 4096]))
        .await
        .expect("a write after the reset should not hang");
    assert!(
        after.is_err(),
        "the reset stream should refuse further writes"
    );
    drop(body);
    assert_eq!(
        finish_echo(open(&sender).await, b"sibling").await.unwrap(),
        b"sibling"
    );
    assert!(!driver.is_finished());

    driver.abort();
    server.abort();
}

#[tokio::test]
async fn split_direct_write_finishes_its_stream_after_a_graceful_goaway_mid_flush() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let (goaway_tx, goaway_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let mut goaway_rx = Some(goaway_rx);
        loop {
            tokio::select! {
                next = conn.accept() => match next {
                    Some(Ok((req, respond))) => echo(req, respond),
                    _ => break,
                },
                Ok(()) = async { goaway_rx.as_mut().unwrap().await }, if goaway_rx.is_some() => {
                    goaway_rx = None;
                    conn.graceful_shutdown();
                }
            }
        }
    });
    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let mut body = open(&sender).await;
    body.write_all(b"opened").await.unwrap();
    let first = vec![1u8; 4096];
    let write = write_parked_on_flush(&ctrl, body, first.clone()).await;
    goaway_tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    ctrl.set_flush_paused(false);

    let (body, res) = joined(write, "the parked write should finish").await;
    assert_eq!(res.unwrap(), first.len());
    let got = finish_echo(body, b"tail").await.unwrap();
    assert_eq!(got, [&b"opened"[..], &first[..], &b"tail"[..]].concat());

    drop(sender);
    let _ = joined(driver, "the connection should close after its last stream").await;
    server.abort();
}

#[tokio::test]
async fn split_connection_closing_waits_for_the_stream_that_owns_the_writer() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let (abort_tx, abort_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let held = conn.accept().await.unwrap().unwrap();
        let _ = abort_rx.await;
        conn.abrupt_shutdown(Reason::INTERNAL_ERROR);
        while conn.accept().await.is_some() {}
        drop(held);
    });
    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let mut body = open(&sender).await;
    body.write_all(b"opened").await.unwrap();
    let write = write_parked_on_flush(&ctrl, body, vec![1u8; 4096]).await;
    abort_tx.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !driver.is_finished(),
        "closing must not shut the sink down under a stream's unflushed frame"
    );
    ctrl.set_flush_paused(false);

    let _ = joined(write, "the parked write should finish").await;
    let _ = joined(
        driver,
        "the connection should close once the stream releases the writer",
    )
    .await;
    server.abort();
}

#[tokio::test]
async fn split_direct_write_on_a_broken_writer_fails_instead_of_waiting() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        while let Some(Ok((req, respond))) = conn.accept().await {
            echo(req, respond);
        }
    });
    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let mut first = open(&sender).await;
    first.write_all(b"opened").await.unwrap();
    let mut idle = open(&sender).await;
    idle.write_all(b"opened").await.unwrap();

    let write = write_parked_on_flush(&ctrl, first, vec![1u8; 4096]).await;
    ctrl.inject_error(io::ErrorKind::ConnectionAborted);
    let (_, res) = joined(write, "the parked write should fail").await;
    assert!(res.is_err());

    let later = tokio::time::timeout(Duration::from_secs(2), idle.write(&[2u8; 64]))
        .await
        .expect("a write on a broken writer should fail at once");
    assert_eq!(
        later.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted,
        "the write should fail with the writer's error, not as a write on a closed stream"
    );
    joined(driver, "the connection should end")
        .await
        .unwrap_err();
    server.abort();
}

#[tokio::test]
async fn split_queued_data_flushed_for_a_dropped_writer_half_still_reaches_the_peer() {
    const QUEUED: usize = 40_000;
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 17);
    let (total_tx, mut total_rx) = mpsc::unbounded_channel::<usize>();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let send = respond.send_response(http::Response::new(()), false);
            let total_tx = total_tx.clone();
            tokio::spawn(async move {
                let _send = send;
                let mut body = req.into_body();
                let mut total = 0;
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    total += chunk.len();
                    let _ = total_tx.send(total);
                }
            });
        }
    });
    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let (response, mut send) = sender
        .clone()
        .ready()
        .await
        .unwrap()
        .send_request(http::Request::new(()), false)
        .unwrap();
    send.send_data(Bytes::from(vec![7u8; QUEUED]), false)
        .unwrap();
    let mut body = H2Body::new(send, Incoming::Response(response));
    ctrl.set_flush_paused(true);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), body.write(b"tail"))
            .await
            .is_err(),
        "the write should first flush the queued frames and wait on the paused flush"
    );
    let (read, write) = Box::new(body).into_split();
    drop(write);
    ctrl.set_flush_paused(false);

    tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(total) = total_rx.recv().await {
            if total >= QUEUED {
                return;
            }
        }
        panic!("the server stopped before the queued body arrived");
    })
    .await
    .expect("the queued body should reach the server");
    assert!(!driver.is_finished());

    drop(read);
    driver.abort();
    server.abort();
}

/// Copies client-to-server bytes through, counting the WINDOW_UPDATE frames in them.
#[derive(Default, Debug, PartialEq, Eq)]
struct WindowUpdates {
    conn_frames: usize,
    conn_increment: u64,
    stream_frames: usize,
    stream_increment: u64,
}

fn tap(client_far: DuplexStream) -> (DuplexStream, oneshot::Receiver<WindowUpdates>) {
    let (server_io, tap_end) = duplex(1 << 20);
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut from_client, mut to_client) = tokio::io::split(client_far);
        let (mut from_server, mut to_server) = tokio::io::split(tap_end);
        let down = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
        });
        let mut counts = WindowUpdates::default();
        let mut preface = [0u8; 24];
        if from_client.read_exact(&mut preface).await.is_ok()
            && to_server.write_all(&preface).await.is_ok()
        {
            let mut header = [0u8; 9];
            while from_client.read_exact(&mut header).await.is_ok() {
                let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
                let mut payload = vec![0u8; len];
                if from_client.read_exact(&mut payload).await.is_err() {
                    break;
                }
                if header[3] == 0x8 && len == 4 {
                    let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & !(1 << 31);
                    let increment = u64::from(
                        u32::from_be_bytes(payload[..4].try_into().unwrap()) & !(1 << 31),
                    );
                    if stream == 0 {
                        counts.conn_frames += 1;
                        counts.conn_increment += increment;
                    } else {
                        counts.stream_frames += 1;
                        counts.stream_increment += increment;
                    }
                }
                if to_server.write_all(&header).await.is_err()
                    || to_server.write_all(&payload).await.is_err()
                {
                    break;
                }
            }
        }
        down.abort();
        let _ = done_tx.send(counts);
    });
    (server_io, done_rx)
}

const DOWNLOAD: usize = 32 << 20;

async fn download_window_updates(split: bool) -> WindowUpdates {
    const CHUNK: usize = 16 << 10;
    let (client_io, client_far, _ctrl) = controlled_duplex(1 << 20);
    let (server_io, counts) = tap(client_far);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        if let Some(Ok((_req, mut respond))) = conn.accept().await {
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tokio::spawn(async move {
                let mut left = DOWNLOAD;
                while left > 0 {
                    send.reserve_capacity(left.min(CHUNK));
                    let Some(Ok(cap)) = std::future::poll_fn(|cx| send.poll_capacity(cx)).await
                    else {
                        return;
                    };
                    let n = cap.min(left);
                    left -= n;
                    send.send_data(Bytes::from(vec![9u8; n]), false).unwrap();
                }
                std::future::pending::<()>().await;
            });
        }
        while conn.accept().await.is_some() {}
    });

    let (mut body, driver) = if split {
        let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        (open(&sender).await, driver)
    } else {
        let (sender, conn) = client_builder().handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        (open(&sender).await, driver)
    };
    body.shutdown().await.unwrap();
    let mut got = 0;
    let mut buf = vec![0u8; 64 << 10];
    while got < DOWNLOAD {
        let n = body.read(&mut buf).await.unwrap();
        assert!(n > 0, "the body ended after {got} bytes");
        got += n;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(body);
    driver.abort();
    server.abort();
    tokio::time::timeout(Duration::from_secs(3), counts)
        .await
        .expect("the tap should stop with the connection")
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_and_plain_clients_send_matching_window_updates_on_download() {
    let plain = download_window_updates(false).await;
    let split = download_window_updates(true).await;
    let released = (DOWNLOAD - STREAM_WINDOW as usize) as u64;
    assert!(plain.stream_increment >= released, "{plain:?}");
    assert!(split.stream_increment >= released, "{split:?}");
    assert_eq!(
        (split.conn_frames, split.conn_increment),
        (plain.conn_frames, plain.conn_increment)
    );
    assert!(
        split.stream_frames.abs_diff(plain.stream_frames) <= (plain.stream_frames / 5).max(2),
        "split {split:?} against plain {plain:?}"
    );
}
