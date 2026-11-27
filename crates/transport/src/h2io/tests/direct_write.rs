use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use concord_common::stream_buffer::ReadBufferOptions;
use concord_common::sync::lock;
use concord_common::{BoxRead, BoxStream, BoxWrite, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex};

use super::*;

mod events;

#[derive(Clone)]
struct WriteControl {
    state: Arc<Mutex<WriteControlInner>>,
}

struct WriteControlInner {
    paused: bool,
    flush_paused: bool,
    max_chunk: usize,
    budget: Option<usize>,
    fail_with: Option<io::ErrorKind>,
    pending_every: usize,
    write_calls: usize,
    waker: Option<Waker>,
    pause_hit: Option<tokio::sync::oneshot::Sender<()>>,
}

impl WriteControl {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(WriteControlInner {
                paused: false,
                flush_paused: false,
                max_chunk: usize::MAX,
                budget: None,
                fail_with: None,
                pending_every: 0,
                write_calls: 0,
                waker: None,
                pause_hit: None,
            })),
        }
    }

    fn set_paused(&self, paused: bool) {
        let waker = {
            let mut s = lock(&self.state);
            s.paused = paused;
            if !paused { s.waker.take() } else { None }
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_flush_paused(&self, paused: bool) {
        let waker = {
            let mut s = lock(&self.state);
            s.flush_paused = paused;
            if !paused { s.waker.take() } else { None }
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_budget(&self, bytes: usize) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut s = lock(&self.state);
        s.budget = Some(bytes);
        s.pause_hit = Some(tx);
        rx
    }

    fn clear_budget(&self) {
        let waker = {
            let mut s = lock(&self.state);
            s.budget = None;
            s.paused = false;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn set_partial_and_pending(&self, max_chunk: usize, pending_every: usize) {
        let mut s = lock(&self.state);
        s.max_chunk = max_chunk;
        s.pending_every = pending_every;
    }

    fn inject_error(&self, kind: io::ErrorKind) {
        let waker = {
            let mut s = lock(&self.state);
            s.fail_with = Some(kind);
            s.paused = false;
            s.budget = None;
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

struct ControlledWrite {
    inner: BoxWrite,
    ctrl: WriteControl,
}

impl AsyncWrite for ControlledWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let take = {
            let mut s = lock(&self.ctrl.state);
            if let Some(kind) = s.fail_with {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            if s.paused {
                s.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if let Some(rem) = s.budget
                && rem == 0
            {
                s.paused = true;
                s.waker = Some(cx.waker().clone());
                if let Some(tx) = s.pause_hit.take() {
                    let _ = tx.send(());
                }
                return Poll::Pending;
            }
            s.write_calls += 1;
            if s.pending_every > 0 && s.write_calls.is_multiple_of(s.pending_every) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let mut cap = buf.len().min(s.max_chunk);
            if let Some(rem) = s.budget {
                cap = cap.min(rem);
            }
            cap
        };
        let slice = &buf[..take];
        match Pin::new(&mut self.inner).poll_write(cx, slice) {
            Poll::Ready(Ok(n)) => {
                let mut s = lock(&self.ctrl.state);
                if let Some(rem) = s.budget.as_mut() {
                    *rem = rem.saturating_sub(n);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut s = lock(&self.ctrl.state);
        if let Some(kind) = s.fail_with {
            return Poll::Ready(Err(io::Error::from(kind)));
        }
        if s.paused || s.flush_paused {
            s.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        drop(s);
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct SplitPairStream {
    read: Option<BoxRead>,
    write: Option<BoxWrite>,
}

impl AsyncRead for SplitPairStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.read.as_mut().unwrap()).poll_read(cx, buf)
    }
}

impl AsyncWrite for SplitPairStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.write.as_mut().unwrap()).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.write.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.write.as_mut().unwrap()).poll_shutdown(cx)
    }
}

impl Stream for SplitPairStream {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(mut self: Box<Self>) -> (BoxRead, BoxWrite) {
        (self.read.take().unwrap(), self.write.take().unwrap())
    }
}

fn controlled_duplex(buf_size: usize) -> (BoxStream, DuplexStream, WriteControl) {
    let (near, far) = duplex(buf_size);
    let (read, write) = tokio::io::split(near);
    let ctrl = WriteControl::new();
    let stream = Box::new(SplitPairStream {
        read: Some(Box::new(read)),
        write: Some(Box::new(ControlledWrite {
            inner: Box::new(write),
            ctrl: ctrl.clone(),
        })),
    });
    (stream, far, ctrl)
}

#[tokio::test]
async fn split_direct_write_blocks_on_outbound_backpressure_without_buffering_ahead() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let (got_tx, got_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let (req, mut respond) = conn.accept().await.unwrap().unwrap();
        let _send = respond
            .send_response(http::Response::new(()), true)
            .unwrap();
        tokio::spawn(async move {
            let mut body = req.into_body();
            let mut got = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                body.flow_control().release_capacity(chunk.len()).unwrap();
                got.extend_from_slice(&chunk);
            }
            let _ = got_tx.send(got);
        });
        while conn.accept().await.is_some() {}
    });

    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);
    let (response, send) = sender
        .ready()
        .await
        .unwrap()
        .send_request(http::Request::new(()), false)
        .unwrap();
    let response = response.await.unwrap();
    let mut body = H2Body::new(send, Incoming::Body(response.into_body()));

    ctrl.set_paused(true);
    let payload = vec![0xABu8; 4096];
    let mut write_fut = Box::pin(body.write(&payload));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut write_fut)
            .await
            .is_err(),
        "direct write must wait for outbound socket rather than buffering in memory"
    );

    ctrl.set_paused(false);
    let written = write_fut.await.unwrap();
    assert_eq!(written, payload.len());
    body.shutdown().await.unwrap();

    assert_eq!(got_rx.await.unwrap(), payload);
    driver.abort();
    server.abort();
}

#[tokio::test]
async fn split_direct_write_frame_integrity_with_partial_writes_interleaved_control_and_hpack_order()
 {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    ctrl.set_partial_and_pending(113, 3);

    let (server_done_tx, server_done_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::Builder::new()
            .initial_window_size(16_384)
            .handshake::<_, Bytes>(server_io)
            .await
            .unwrap();
        let mut ping_pong = conn.ping_pong().unwrap();
        let mut received: Vec<tokio::task::JoinHandle<(String, Vec<u8>)>> = Vec::new();
        let mut accepted = 0usize;

        while let Some(Ok((req, mut respond))) = conn.accept().await {
            accepted += 1;
            let tag = req
                .headers()
                .get("x-stream-tag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let shared = req
                .headers()
                .get("x-shared-hpack")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            assert_eq!(shared, "concord-hpack-dynamic-table-order-check");

            if tag == "reset-me" {
                respond.send_reset(h2::Reason::CANCEL);
                continue;
            }

            if tag == "server-push-data" {
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                tokio::spawn(async move {
                    let chunk = Bytes::from(vec![0x5Au8; 16_384]);
                    for _ in 0..8 {
                        send.reserve_capacity(chunk.len());
                        while send.capacity() < chunk.len() {
                            if std::future::poll_fn(|cx| send.poll_capacity(cx))
                                .await
                                .is_none()
                            {
                                return;
                            }
                        }
                        send.send_data(chunk.clone(), false).unwrap();
                    }
                    send.send_data(Bytes::new(), true).unwrap();
                });
                continue;
            }

            if accepted == 2 {
                let _ = conn.set_initial_window_size(32_768);
                let _ = ping_pong.send_ping(h2::Ping::opaque());
            }

            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            received.push(tokio::spawn(async move {
                let mut body = req.into_body();
                let mut got = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                    got.extend_from_slice(&chunk);
                }
                send.send_data(Bytes::from_static(b"ok"), true).unwrap();
                (tag, got)
            }));

            if accepted == 6 {
                break;
            }
        }

        let mut results = std::collections::BTreeMap::new();
        let all_uploads = async move {
            for h in received {
                let (tag, data) = h.await.unwrap();
                results.insert(tag, data);
            }
            results
        };
        let results = tokio::select! {
            res = all_uploads => res,
            _ = async { while conn.accept().await.is_some() {} } => {
                panic!("server connection ended before uploads finished")
            }
        };
        conn.graceful_shutdown();
        // A client that closes right after its GOAWAY fails the final GOAWAY, and h2 then repeats that error.
        while let Some(Ok(_)) = conn.accept().await {}
        let _ = server_done_tx.send(results);
    });

    let mut builder = client_builder();
    builder.initial_window_size(32_768);
    let (sender, mut conn) = handshake_split(&builder, client_io).await.unwrap();
    let mut client_ping = conn.ping_pong().unwrap();
    let driver = tokio::spawn(conn);

    let ping_task = tokio::spawn(async move {
        let _ = client_ping.ping(h2::Ping::opaque()).await;
    });

    let mut handles = Vec::new();
    let expected: Arc<std::collections::BTreeMap<String, Vec<u8>>> = Arc::new(
        (0..4usize)
            .map(|i| {
                let tag = format!("upload-{i}");
                let data: Vec<u8> = (0..48 * 1024usize)
                    .map(|j| ((j.wrapping_mul(31).wrapping_add(i * 17)) & 0xFF) as u8)
                    .collect();
                (tag, data)
            })
            .collect(),
    );

    for (idx, tag) in [
        "upload-0",
        "server-push-data",
        "upload-1",
        "reset-me",
        "upload-2",
        "upload-3",
    ]
    .into_iter()
    .enumerate()
    {
        let mut s = sender.clone().ready().await.unwrap();
        let req = http::Request::builder()
            .uri(format!("https://example.test/{tag}/{idx}"))
            .header("x-stream-tag", tag)
            .header("x-shared-hpack", "concord-hpack-dynamic-table-order-check")
            .header(format!("x-unique-{idx}"), format!("val-{idx}"))
            .body(())
            .unwrap();
        let (resp, send) = s.send_request(req, false).unwrap();
        let mut body = H2Body::new(send, Incoming::Response(resp));

        if tag == "server-push-data" {
            handles.push(tokio::spawn(async move {
                let mut total = 0usize;
                let mut buf = [0u8; 4096];
                while let Ok(n) = body.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                assert_eq!(total, 8 * 16_384);
            }));
        } else if tag == "reset-me" {
            handles.push(tokio::spawn(async move {
                let mut buf = [0u8; 16];
                assert!(body.read(&mut buf).await.is_err());
            }));
        } else {
            let data = expected[tag].clone();
            let use_owned = idx % 2 == 0;
            handles.push(tokio::spawn(async move {
                if use_owned {
                    let opts = ReadBufferOptions::for_copy(Default::default(), Default::default())
                        .unwrap();
                    for chunk in data.chunks(4096) {
                        let mut buf = opts.take_for_read(chunk.len(), 0).unwrap();
                        buf.spare_mut()[..chunk.len()].copy_from_slice(chunk);
                        buf.advance(chunk.len()).unwrap();
                        while !buf.is_empty() {
                            let n = std::future::poll_fn(|cx| body.poll_write_buffer(cx, &mut buf))
                                .await
                                .unwrap();
                            assert!(n > 0);
                        }
                    }
                } else {
                    body.write_all(&data).await.unwrap();
                }
                body.shutdown().await.unwrap();
                let mut ack = Vec::new();
                body.read_to_end(&mut ack).await.unwrap();
                assert_eq!(ack, b"ok");
            }));
        }
    }

    for h in handles {
        h.await.unwrap();
    }
    drop(sender);
    let _ = ping_task.await;

    let got = tokio::time::timeout(Duration::from_secs(10), server_done_rx)
        .await
        .expect("server did not finish within timeout")
        .unwrap();
    assert_eq!(got.len(), expected.len());
    for (tag, exp) in expected.iter() {
        assert_eq!(got.get(tag).unwrap(), exp, "byte mismatch on {tag}");
    }
    let _ = driver.await;
    let _ = server.await;
}

#[tokio::test]
async fn split_direct_write_mid_frame_drop_abandons_and_completes_wire_frame_for_siblings() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);

    let (sib_tx, sib_rx) = tokio::sync::oneshot::channel();
    let (dropped_saw_reset_tx, dropped_saw_reset_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let mut count = 0;
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            count += 1;
            let tag = req
                .headers()
                .get("x-tag")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let _send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            if tag == "drop-mid-frame" {
                let tx = dropped_saw_reset_tx;
                tokio::spawn(async move {
                    let mut body = req.into_body();
                    let mut got = 0usize;
                    let mut saw_err = false;
                    while let Some(item) = body.data().await {
                        match item {
                            Ok(chunk) => {
                                got += chunk.len();
                                let _ = body.flow_control().release_capacity(chunk.len());
                            }
                            Err(_) => {
                                saw_err = true;
                                break;
                            }
                        }
                    }
                    let _ = tx.send((got, saw_err));
                });
                break;
            }
        }
        if let Some(Ok((req, mut respond))) = conn.accept().await {
            assert_eq!(req.headers().get("x-tag").unwrap(), "sibling");
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tokio::spawn(async move {
                let mut body = req.into_body();
                let mut got = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                    got.extend_from_slice(&chunk);
                }
                send.send_data(Bytes::from_static(b"sib-ok"), true).unwrap();
                let _ = sib_tx.send(got);
            });
        }
        assert_eq!(count, 1);
        while conn.accept().await.is_some() {}
    });

    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let req1 = http::Request::builder()
        .header("x-tag", "drop-mid-frame")
        .body(())
        .unwrap();
    let (resp1, send1) = sender
        .clone()
        .ready()
        .await
        .unwrap()
        .send_request(req1, false)
        .unwrap();
    let resp1 = resp1.await.unwrap();
    let mut body1 = H2Body::new(send1, Incoming::Body(resp1.into_body()));

    // 20 bytes end mid-frame: the 9-byte DATA header and 11 bytes of payload.
    let hit_pause = ctrl.set_budget(20);
    let payload1 = vec![0xCDu8; 4096];
    let mut write1 = Box::pin(body1.write(&payload1));
    tokio::select! {
        _ = &mut write1 => panic!("write1 should have paused mid-frame"),
        _ = hit_pause => {}
    }
    drop(write1);
    drop(body1);

    ctrl.clear_budget();

    let req2 = http::Request::builder()
        .header("x-tag", "sibling")
        .body(())
        .unwrap();
    let (resp2, send2) = sender
        .ready()
        .await
        .unwrap()
        .send_request(req2, false)
        .unwrap();
    let mut body2 = H2Body::new(send2, Incoming::Response(resp2));
    let payload2: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    body2.write_all(&payload2).await.unwrap();
    body2.shutdown().await.unwrap();
    let mut ack = Vec::new();
    body2.read_to_end(&mut ack).await.unwrap();
    assert_eq!(ack, b"sib-ok");

    assert_eq!(sib_rx.await.unwrap(), payload2);
    let (dropped_bytes, saw_reset) = dropped_saw_reset_rx.await.unwrap();
    assert_eq!(dropped_bytes, payload1.len());
    assert!(
        saw_reset,
        "dropped stream should receive RST_STREAM after abandoned frame finishes"
    );

    driver.abort();
    server.abort();
}

#[tokio::test]
async fn split_direct_write_dropped_while_its_flush_waits_leaves_the_connection_usable() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
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
    });

    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let request = || http::Request::builder().body(()).unwrap();
    let (resp1, send1) = sender
        .clone()
        .ready()
        .await
        .unwrap()
        .send_request(request(), false)
        .unwrap();
    let resp1 = resp1.await.unwrap();
    let mut body1 = H2Body::new(send1, Incoming::Body(resp1.into_body()));

    ctrl.set_flush_paused(true);
    {
        let write1 = body1.write(b"written, flush pending");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), write1)
                .await
                .is_err(),
            "the write should wait on the paused flush"
        );
    }
    drop(body1);
    ctrl.set_flush_paused(false);

    let (resp2, send2) = sender
        .ready()
        .await
        .unwrap()
        .send_request(request(), false)
        .unwrap();
    let mut body2 = H2Body::new(send2, Incoming::Response(resp2));
    let echoed = tokio::time::timeout(Duration::from_secs(5), async {
        body2.write_all(b"next stream").await?;
        body2.shutdown().await?;
        let mut got = Vec::new();
        body2.read_to_end(&mut got).await?;
        io::Result::Ok(got)
    })
    .await
    .expect("the next stream should finish");
    assert_eq!(echoed.unwrap(), b"next stream");
    assert!(
        !driver.is_finished(),
        "the connection should still be running"
    );

    driver.abort();
    server.abort();
}

#[tokio::test]
async fn split_direct_write_io_error_closes_connection_and_wakes_all_streams() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let mut holds = Vec::new();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            holds.push((req, send));
        }
    });

    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let (r1, s1) = sender
        .clone()
        .ready()
        .await
        .unwrap()
        .send_request(http::Request::new(()), false)
        .unwrap();
    let (r2, s2) = sender
        .ready()
        .await
        .unwrap()
        .send_request(http::Request::new(()), false)
        .unwrap();
    let mut body1 = H2Body::new(s1, Incoming::Body(r1.await.unwrap().into_body()));
    let mut body2 = H2Body::new(s2, Incoming::Body(r2.await.unwrap().into_body()));

    ctrl.set_paused(true);
    let t1 = tokio::spawn(async move { body1.write(&[1u8; 1024]).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    let t2 = tokio::spawn(async move { body2.write(&[2u8; 1024]).await });
    tokio::time::sleep(Duration::from_millis(10)).await;

    ctrl.inject_error(io::ErrorKind::BrokenPipe);

    let res1 = tokio::time::timeout(Duration::from_secs(2), t1)
        .await
        .expect("stream 1 must wake on write error")
        .unwrap();
    let res2 = tokio::time::timeout(Duration::from_secs(2), t2)
        .await
        .expect("stream 2 must wake on write error")
        .unwrap();
    let conn_res = tokio::time::timeout(Duration::from_secs(2), driver)
        .await
        .expect("SplitConnection must terminate on fatal direct write error")
        .unwrap();

    assert!(res1.is_err());
    assert!(res2.is_err());
    assert!(conn_res.is_err());
    server.abort();
}

#[tokio::test]
async fn split_direct_write_fifo_fairness_under_concurrent_bulk_and_rr() {
    let (client_io, server_io, ctrl) = controlled_duplex(1 << 16);
    ctrl.set_partial_and_pending(1024, 2);

    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server_io).await.unwrap();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let tag = req
                .headers()
                .get("x-kind")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tokio::spawn(async move {
                let mut body = req.into_body();
                if tag == "bulk" {
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                    let _ = send.send_data(Bytes::new(), true);
                } else {
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        send.reserve_capacity(chunk.len());
                        while send.capacity() < chunk.len() {
                            if std::future::poll_fn(|cx| send.poll_capacity(cx))
                                .await
                                .is_none()
                            {
                                return;
                            }
                        }
                        if send.send_data(chunk, false).is_err() {
                            return;
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                }
            });
        }
    });

    let (sender, conn) = handshake_split(&client_builder(), client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    let req_bulk = http::Request::builder()
        .header("x-kind", "bulk")
        .body(())
        .unwrap();
    let (rb, sb) = sender
        .clone()
        .ready()
        .await
        .unwrap()
        .send_request(req_bulk, false)
        .unwrap();
    let mut bulk = H2Body::new(sb, Incoming::Body(rb.await.unwrap().into_body()));

    let req_rr = http::Request::builder()
        .header("x-kind", "rr")
        .body(())
        .unwrap();
    let (rr, sr) = sender
        .ready()
        .await
        .unwrap()
        .send_request(req_rr, false)
        .unwrap();
    let mut rr_stream = H2Body::new(sr, Incoming::Body(rr.await.unwrap().into_body()));

    let bulk_done = Arc::new(AtomicBool::new(false));
    let bulk_frames = Arc::new(AtomicUsize::new(0));
    let bd = bulk_done.clone();
    let bf = bulk_frames.clone();
    let bulk_task = tokio::spawn(async move {
        let chunk = vec![0xEEu8; 8192];
        while !bd.load(Ordering::Relaxed) {
            bulk.write_all(&chunk).await.unwrap();
            bf.fetch_add(1, Ordering::Relaxed);
        }
        bulk.shutdown().await.unwrap();
    });

    for round in 0..10u8 {
        let msg = [round; 32];
        rr_stream.write_all(&msg).await.unwrap();
        let mut reply = [0u8; 32];
        tokio::time::timeout(Duration::from_secs(2), rr_stream.read_exact(&mut reply))
            .await
            .expect("RR stream starved behind bulk stream")
            .unwrap();
        assert_eq!(reply, msg);
    }
    assert!(
        bulk_frames.load(Ordering::Relaxed) > 0,
        "bulk stream should have been running concurrently"
    );

    bulk_done.store(true, Ordering::Relaxed);
    bulk_task.await.unwrap();
    rr_stream.shutdown().await.unwrap();
    driver.abort();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn split_direct_write_max_concurrent_streams_pending_open_does_not_spin_or_leak() {
    let (client_io, server_io, _ctrl) = controlled_duplex(1 << 20);
    let server = tokio::spawn(async move {
        let mut sb = h2::server::Builder::new();
        sb.max_concurrent_streams(2);
        let mut conn = sb.handshake(server_io).await.unwrap();
        let mut tasks = Vec::new();
        while let Some(next) = conn.accept().await {
            let (req, mut respond) = next.unwrap();
            let mut body = req.into_body();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tasks.push(tokio::spawn(async move {
                while let Some(chunk) = body.data().await {
                    let bytes = chunk.unwrap();
                    let _ = body.flow_control().release_capacity(bytes.len());
                    send.send_data(bytes, false).unwrap();
                }
                send.send_data(Bytes::new(), true).unwrap();
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    });

    let mut builder = h2::client::Builder::new();
    builder.enable_push(false);
    let (sender, conn) = handshake_split(&builder, client_io).await.unwrap();
    let driver = tokio::spawn(conn);

    // Complete one stream first so the server's SETTINGS(max_concurrent_streams = 2)
    // is applied on the client before launching the burst.
    {
        let mut s = sender.clone().ready().await.unwrap();
        let (resp, send) = s.send_request(http::Request::new(()), false).unwrap();
        let mut body = H2Body::new(send, Incoming::Response(resp));
        body.write_all(b"init").await.unwrap();
        body.shutdown().await.unwrap();
        let mut got = Vec::new();
        body.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"init");
    }

    let mut handles = Vec::new();
    for i in 0..5u8 {
        let mut s = sender.clone().ready().await.unwrap();
        let (resp, send) = s.send_request(http::Request::new(()), false).unwrap();
        let mut body = H2Body::new(send, Incoming::Response(resp));
        handles.push(tokio::spawn(async move {
            let payload = vec![i + 1; 64];
            body.write_all(&payload).await.unwrap();
            body.shutdown().await.unwrap();
            let mut got = Vec::new();
            body.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, payload);
        }));
    }

    for h in handles {
        tokio::time::timeout(Duration::from_secs(3), h)
            .await
            .expect("pending_open stream stalled (possible SplitConnection spin)")
            .unwrap();
    }

    drop(sender);
    tokio::time::timeout(Duration::from_secs(3), driver)
        .await
        .expect("SplitConnection failed to drain cleanly after all streams closed")
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .expect("server did not finish")
        .unwrap();
}
