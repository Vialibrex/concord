use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use concord_common::stream_buffer::ReadBufferOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

use super::*;

mod cancellation;
mod direct_write;

#[test]
fn the_last_read_releases_data_storage_before_the_next_frame_arrives() {
    struct DataOwner([u8; 4], Arc<AtomicUsize>);
    impl AsRef<[u8]> for DataOwner {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl Drop for DataOwner {
        fn drop(&mut self) {
            self.1.fetch_add(1, Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(AtomicUsize::new(0));
    let mut reader = H2Reader::new(Incoming::Done);
    reader.pending = Bytes::from_owner(DataOwner(*b"data", dropped.clone()));
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for (index, expected) in [b"da", b"ta"].into_iter().enumerate() {
        let mut bytes = [0; 2];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(buf.filled(), expected);
        assert_eq!(dropped.load(Ordering::SeqCst), index);
    }
    assert!(reader.pending.is_empty());
}

struct TrackedIo {
    inner: DuplexStream,
    payload: Arc<(AtomicUsize, AtomicUsize)>,
    direct_writes: Arc<AtomicUsize>,
}

impl AsyncRead for TrackedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrackedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pointer = data.as_ptr() as usize;
        let first = self.payload.0.load(Ordering::SeqCst);
        let last = self.payload.1.load(Ordering::SeqCst);
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0)
            && first != 0
            && (first..last).contains(&pointer)
        {
            self.direct_writes.fetch_add(1, Ordering::SeqCst);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Stream for TrackedIo {
    concord_common::stream_policy!(default: all);
}

#[tokio::test]
async fn owned_data_preserves_storage_and_partial_reads_under_flow_control() {
    for window in [16, 1 << 20] {
        let (near, far) = duplex(1 << 16);
        let payload_range = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
        let direct_writes = Arc::new(AtomicUsize::new(0));
        let near = Box::new(TrackedIo {
            inner: near,
            payload: payload_range.clone(),
            direct_writes: direct_writes.clone(),
        }) as BoxStream;
        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut conn = h2::server::Builder::new()
                .initial_window_size(window)
                .handshake::<_, Bytes>(far)
                .await
                .unwrap();
            let (request, mut respond) = conn.accept().await.unwrap().unwrap();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut got = Vec::new();
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    got.extend_from_slice(&data);
                    body.flow_control().release_capacity(data.len()).unwrap();
                }
                send.send_data(Bytes::copy_from_slice(&got), true).unwrap();
                let _ = received_tx.send(got);
            });
            while conn.accept().await.is_some() {}
        });
        let (mut sender, connection) = h2::client::Builder::new()
            .handshake::<_, Bytes>(near)
            .await
            .unwrap();
        let client = tokio::spawn(connection);
        let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
        let response = response.await.unwrap();
        let mut body = H2Body::new(send, Incoming::Body(response.into_body()));
        let payload: Vec<_> = (0..4096).map(|n| (n % 251) as u8).collect();
        let mut buffer = ReadBufferOptions::for_copy(Default::default(), Default::default())
            .unwrap()
            .take();
        buffer.spare_mut()[..payload.len()].copy_from_slice(&payload);
        buffer.advance(payload.len()).unwrap();
        let pointer = buffer.as_slice().as_ptr() as usize;
        payload_range.0.store(pointer, Ordering::SeqCst);
        payload_range
            .1
            .store(pointer + payload.len(), Ordering::SeqCst);
        let mut total = 0;
        while !buffer.is_empty() {
            let n = std::future::poll_fn(|cx| body.poll_write_buffer(cx, &mut buffer))
                .await
                .unwrap();
            assert!(n > 0);
            total += n;
        }
        assert_eq!(total, payload.len());
        assert!(buffer.is_empty());
        body.shutdown().await.unwrap();
        let mut response = Vec::new();
        let mut one = [0; 1];
        while body.read(&mut one).await.unwrap() != 0 {
            response.push(one[0]);
        }
        assert_eq!(response, payload);
        assert_eq!(received_rx.await.unwrap(), payload);
        if window > payload.len() as u32 {
            assert!(direct_writes.load(Ordering::SeqCst) > 0);
        }
        client.abort();
        server.abort();
    }
}

#[tokio::test]
async fn the_drop_hook_runs_once_after_both_halves_are_gone() {
    let (client, server) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let mut conn = h2::server::handshake(server).await.unwrap();
        while let Some(Ok((_request, mut respond))) = conn.accept().await {
            let _ = respond.send_response(http::Response::new(()), true);
        }
    });
    let (mut sender, conn) = client_builder().handshake(client).await.unwrap();
    tokio::spawn(conn);
    let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
    let runs = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&runs);
    let body = H2Body::new(send, Incoming::Response(response)).on_drop(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let (read, write) = Box::new(body).into_split();
    drop(read);
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    drop(write);
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn client_builder_advertises_the_reference_frame_size_and_windows() {
    let (near, mut far) = duplex(1 << 16);
    let observed = tokio::spawn(async move { client_settings(&mut far).await });
    let io = Box::new(near) as BoxStream;
    let (sender, conn) = client_builder().handshake::<_, Bytes>(io).await.unwrap();
    let driver = tokio::spawn(conn);
    let (settings, update) = observed.await.unwrap();
    assert_eq!(settings.get(&2), Some(&0));
    assert_eq!(settings.get(&4), Some(&(4 << 20)));
    assert_eq!(settings.get(&5), Some(&(1 << 20)));
    assert_eq!(update, 1 << 30);
    drop(sender);
    driver.abort();
}

async fn wait_buffered(reader: &mut H2Reader, want: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Incoming::Body(recv) = &mut reader.incoming
                && recv.flow_control().used_capacity() >= want
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn h2_reader_drains_ready_frames_in_one_read_and_keeps_tail() {
    let (near, far) = duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(far).await.unwrap();
        let (_req, mut respond) = conn.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(b"aaaa"), false).unwrap();
        send.send_data(Bytes::from_static(b"bbbb"), false).unwrap();
        send.send_data(Bytes::from_static(b"cccc"), false).unwrap();
        while conn.accept().await.is_some() {}
    });
    let (mut sender, conn) = client_builder().handshake::<_, Bytes>(near).await.unwrap();
    let driver = tokio::spawn(conn);
    let (response, _send) = sender.send_request(http::Request::new(()), true).unwrap();
    let response = response.await.unwrap();
    let mut reader = H2Reader::new(Incoming::Body(response.into_body()));
    wait_buffered(&mut reader, 12).await;

    let mut first = [0u8; 10];
    let n = reader.read(&mut first).await.unwrap();
    assert_eq!(n, 10);
    assert_eq!(&first, b"aaaabbbbcc");
    assert_eq!(reader.pending.as_ref(), b"cc");
    if let Incoming::Body(recv) = &mut reader.incoming {
        assert_eq!(recv.flow_control().used_capacity(), 0);
    } else {
        panic!("expected open body");
    }

    let mut tail = [0u8; 4];
    let n = reader.read(&mut tail).await.unwrap();
    assert_eq!(n, 2);
    assert_eq!(tail.get(..n), Some(b"cc".as_slice()));
    assert!(reader.pending.is_empty());

    driver.abort();
    server.abort();
}

#[tokio::test]
async fn h2_reader_preserves_eof_after_partial_drain() {
    let (near, far) = duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(far).await.unwrap();
        let (_req, mut respond) = conn.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(b"hi"), false).unwrap();
        send.send_data(Bytes::from_static(b"!"), true).unwrap();
        while conn.accept().await.is_some() {}
    });
    let (mut sender, conn) = client_builder().handshake::<_, Bytes>(near).await.unwrap();
    let driver = tokio::spawn(conn);
    let (response, _send) = sender.send_request(http::Request::new(()), true).unwrap();
    let response = response.await.unwrap();
    let mut reader = H2Reader::new(Incoming::Body(response.into_body()));
    wait_buffered(&mut reader, 3).await;

    let mut buf = [0u8; 16];
    let n = reader.read(&mut buf).await.unwrap();
    assert_eq!(buf.get(..n), Some(b"hi!".as_slice()));
    assert_eq!(reader.read(&mut buf).await.unwrap(), 0);

    driver.abort();
    server.abort();
}

#[tokio::test]
async fn h2_reader_preserves_error_after_partial_drain() {
    let (near, far) = duplex(1 << 16);
    let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(far).await.unwrap();
        let (_req, mut respond) = conn.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(b"o"), false).unwrap();
        send.send_data(Bytes::from_static(b"k"), false).unwrap();
        let mut barrier_respond: Option<h2::server::SendResponse<Bytes>> = None;
        let mut sent_rx = Some(sent_rx);
        loop {
            tokio::select! {
                _ = async { sent_rx.as_mut().unwrap().await }, if sent_rx.is_some() => {
                    sent_rx = None;
                    send.send_reset(h2::Reason::CANCEL);
                    if let Some(mut respond) = barrier_respond.take() {
                        let _ = respond.send_response(http::Response::new(()), true);
                    }
                }
                next = conn.accept() => match next {
                    Some(Ok((_req, mut respond))) => {
                        if sent_rx.is_none() {
                            let _ = respond.send_response(http::Response::new(()), true);
                        } else {
                            barrier_respond = Some(respond);
                        }
                    }
                    _ => break,
                }
            }
        }
    });
    let (mut sender, conn) = client_builder().handshake::<_, Bytes>(near).await.unwrap();
    let driver = tokio::spawn(conn);
    let (response, _send) = sender.send_request(http::Request::new(()), true).unwrap();
    let response = response.await.unwrap();
    let mut reader = H2Reader::new(Incoming::Body(response.into_body()));
    wait_buffered(&mut reader, 2).await;
    let _ = sent_tx.send(());
    let mut barrier_sender = sender.ready().await.unwrap();
    let (barrier, _barrier_send) = barrier_sender
        .send_request(http::Request::new(()), true)
        .unwrap();
    barrier.await.unwrap();

    let mut buf = [0u8; 16];
    let n = reader.read(&mut buf).await.unwrap();
    assert_eq!(buf.get(..n), Some(b"ok".as_slice()));
    assert!(reader.pending_err.is_some());
    let err = reader.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    assert!(reader.pending_err.is_none());

    driver.abort();
    server.abort();
}

/// Plays the server side of a client handshake on `far`: sends an empty SETTINGS, then
/// returns the client's SETTINGS and its connection-level WINDOW_UPDATE increment.
pub(crate) async fn client_settings(
    far: &mut DuplexStream,
) -> (std::collections::BTreeMap<u16, u32>, u32) {
    far.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
    let mut preface = [0; 24];
    far.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    let mut settings = std::collections::BTreeMap::new();
    let mut connection_update = None;
    loop {
        let mut header = [0; 9];
        far.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; length];
        far.read_exact(&mut payload).await.unwrap();
        match header[3] {
            4 if header[4] & 1 == 0 => {
                assert_eq!(payload.len() % 6, 0);
                for setting in payload.as_chunks::<6>().0 {
                    settings.insert(
                        u16::from_be_bytes(setting[..2].try_into().unwrap()),
                        u32::from_be_bytes(setting[2..].try_into().unwrap()),
                    );
                }
            }
            8 => {
                assert_eq!(&header[5..9], &[0; 4]);
                connection_update = Some(u32::from_be_bytes(payload.try_into().unwrap()));
            }
            _ => {}
        }
        if !settings.is_empty()
            && let Some(update) = connection_update
        {
            return (settings, update);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_silent_peer_is_dropped_though_streams_keep_opening() {
    let (near, far) = duplex(1 << 20);
    tokio::spawn(async move {
        let _silent: Result<h2::server::Connection<_, Bytes>, _> = h2::server::handshake(far).await;
        std::future::pending::<()>().await;
    });
    let (_send, conn) = client_builder()
        .handshake::<BoxStream, Bytes>(Box::new(near))
        .await
        .unwrap();
    let activity = Activity::new();
    spawn_checked_connection(&concord_common::Tasks::default(), conn, activity.clone());
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        activity.before_stream();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(activity.ended());
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_answers_pings_stays_up() {
    let (near, far) = duplex(1 << 20);
    tokio::spawn(async move {
        let Ok(mut conn) = h2::server::handshake(far).await else {
            return;
        };
        while conn.accept().await.is_some() {}
    });
    let (_send, conn) = client_builder()
        .handshake::<BoxStream, Bytes>(Box::new(near))
        .await
        .unwrap();
    let activity = Activity::new();
    spawn_checked_connection(&concord_common::Tasks::default(), conn, activity.clone());
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        activity.before_stream();
    }
    assert!(!activity.ended());
}

const SETTINGS: [u8; 9] = [0, 0, 0, 4, 0, 0, 0, 0, 0];
const WINDOW_UPDATE: [u8; 13] = [0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[tokio::test(start_paused = true)]
async fn a_peer_that_only_sends_window_updates_is_not_pinged_to_death() {
    let (near, mut far) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        if far.write_all(&SETTINGS).await.is_err() {
            return;
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if far.write_all(&WINDOW_UPDATE).await.is_err() {
                return;
            }
        }
    });
    let tasks = concord_common::Tasks::default();
    let (_sender, activity) = checked_handshake(&client_builder(), Box::new(near), &tasks)
        .await
        .unwrap();
    for _ in 0..8 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        activity.before_stream();
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!activity.ended());
}

/// What a server that never ends its side of a tunnel saw: the DATA, then how the stream ended.
async fn holding_server(far: DuplexStream) -> (Vec<u8>, Option<h2::Reason>) {
    let mut conn = h2::server::handshake(far).await.unwrap();
    let (request, mut respond) = conn.accept().await.unwrap().unwrap();
    tokio::spawn(async move { while conn.accept().await.is_some() {} });
    let _send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    let mut body = request.into_body();
    let mut got = Vec::new();
    loop {
        match body.data().await {
            Some(Ok(data)) => {
                got.extend_from_slice(&data);
                body.flow_control().release_capacity(data.len()).unwrap();
            }
            Some(Err(err)) => return (got, err.reason()),
            None => return (got, None),
        }
    }
}

#[tokio::test]
async fn a_tunnel_without_half_close_sends_its_writes_then_resets_the_stream() {
    let (near, far) = duplex(1 << 16);
    let server = tokio::spawn(holding_server(far));
    let (mut sender, connection) = h2::client::handshake(near).await.unwrap();
    tokio::spawn(connection);
    let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
    let body = H2Body::new(send, Incoming::Response(response)).without_half_close();
    let (mut read, mut write) = Box::new(body).into_split();
    let payload: Vec<u8> = (0..300_000).map(|n| (n % 251) as u8).collect();
    write.write_all(&payload).await.unwrap();
    let patience = std::time::Duration::from_secs(5);
    tokio::time::timeout(patience, write.shutdown())
        .await
        .unwrap()
        .unwrap();
    let mut rest = Vec::new();
    assert_eq!(
        tokio::time::timeout(patience, read.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let (got, reason) = tokio::time::timeout(patience, server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.len(), payload.len());
    assert!(got == payload);
    assert_eq!(reason, Some(h2::Reason::CANCEL));
}

#[tokio::test(start_paused = true)]
async fn a_tunnel_whose_peer_grants_no_window_is_reset_after_the_drain_limit() {
    let (near, mut far) = duplex(1 << 16);
    let frames = tokio::spawn(async move {
        far.write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut preface = [0; 24];
        far.read_exact(&mut preface).await.unwrap();
        let mut kinds = Vec::new();
        loop {
            let mut header = [0; 9];
            far.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
            let mut payload = vec![0; length];
            far.read_exact(&mut payload).await.unwrap();
            kinds.push((header[3], length));
            if header[3] == 3 {
                return (kinds, u32::from_be_bytes(payload.try_into().unwrap()));
            }
        }
    });
    let (mut sender, connection) = h2::client::handshake(near).await.unwrap();
    tokio::spawn(connection);
    let (response, mut send) = sender.send_request(http::Request::new(()), false).unwrap();
    send.send_data(Bytes::from_static(&[7; 1024]), false)
        .unwrap();
    let mut body = H2Body::new(send, Incoming::Response(response)).without_half_close();
    let started = Instant::now();
    tokio::time::timeout(RESET_DRAIN + Duration::from_secs(1), body.shutdown())
        .await
        .expect("shutdown outlived the drain limit")
        .unwrap();
    let waited = started.elapsed();
    assert!(waited >= RESET_DRAIN, "{waited:?}");
    assert!(waited < RESET_DRAIN + Duration::from_secs(1), "{waited:?}");
    let (kinds, code) = tokio::time::timeout(Duration::from_secs(5), frames)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !kinds.iter().any(|&(kind, length)| kind == 0 && length > 0),
        "{kinds:?}"
    );
    assert_eq!(code, u32::from(h2::Reason::CANCEL));
    let mut one = [0; 1];
    assert_eq!(body.read(&mut one).await.unwrap(), 0);
}
