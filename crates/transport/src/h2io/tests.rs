use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Poll, Wake, Waker};

use concord_common::stream_buffer::ReadBufferOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

use super::*;

mod cancellation;
mod direct_write;

struct PanicWake;

impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
        panic!("poison h2 streams lock");
    }
}

pub(crate) fn panic_waker() -> Waker {
    Waker::from(Arc::new(PanicWake))
}

#[tokio::test]
async fn client_slot_reports_dead_for_poisoned_sender_even_before_activity_ends() {
    let (near, far) = duplex(1 << 20);
    let release = Arc::new(tokio::sync::Notify::new());
    let server_release = release.clone();
    let server = tokio::spawn(async move {
        let mut conn = h2::server::Builder::new()
            .handshake::<_, Bytes>(far)
            .await
            .unwrap();
        if let Some(Ok((_req, mut respond))) = conn.accept().await {
            server_release.notified().await;
            let _ = respond.send_response(
                http::Response::builder().status(200).body(()).unwrap(),
                false,
            );
            while conn.accept().await.is_some() {}
        }
    });
    let (mut sender, conn) = handshake_split(&client_builder(), Box::new(near))
        .await
        .unwrap();
    let driver = tokio::spawn(conn);
    let (mut response, send) = sender.send_request(http::Request::new(()), false).unwrap();
    let waker = panic_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut response).poll(&mut cx).is_pending());
    release.notify_one();
    assert!(driver.await.is_err());

    let slot = ClientSlot::new();
    let live_activity = Activity::new();
    assert!(!live_activity.ended());
    *concord_common::sync::lock(&slot.live) = Some(Live::new(sender, live_activity));
    assert!(slot.is_dead());
    assert_eq!(slot.peer_max_streams(), INITIAL_MAX_SEND_STREAMS);
    assert!(slot.current().is_none());
    assert!(!slot.is_dead());
    server.abort();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop((response, send))));
}

#[tokio::test]
async fn initial_and_unadvertised_peer_stream_limits_match_go() {
    let (near, mut far) = duplex(1 << 16);
    let (sender, conn) = handshake_split(&client_builder(), Box::new(near))
        .await
        .unwrap();
    assert_eq!(sender_max_streams(&sender), Some(INITIAL_MAX_SEND_STREAMS));

    let driver = tokio::spawn(conn);
    far.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
    far.flush().await.unwrap();
    for _ in 0..40 {
        if sender_max_streams(&sender) == Some(DEFAULT_MAX_SEND_STREAMS) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(sender_max_streams(&sender), Some(DEFAULT_MAX_SEND_STREAMS));
    drop(sender);
    driver.abort();
}

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
    let (_send, conn) = handshake_split(&client_builder(), Box::new(near))
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
    let (_send, conn) = handshake_split(&client_builder(), Box::new(near))
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

/// What a server that never ends its side of a tunnel saw: the DATA, whether END_STREAM came
/// first, then how the stream ended.
async fn holding_server(far: DuplexStream) -> (Vec<u8>, bool, Option<h2::Reason>) {
    let mut conn = h2::server::handshake(far).await.unwrap();
    let (request, mut respond) = conn.accept().await.unwrap().unwrap();
    tokio::spawn(async move { while conn.accept().await.is_some() {} });
    let mut send = respond
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
            Some(Err(err)) => return (got, false, err.reason()),
            None => {
                let reset = std::future::poll_fn(|cx| send.poll_reset(cx)).await;
                return (got, true, reset.ok());
            }
        }
    }
}

#[tokio::test]
async fn a_tunnel_without_half_close_sends_its_writes_then_resets_the_stream() {
    let (near, far) = duplex(1 << 16);
    let server = tokio::spawn(holding_server(far));
    let (sender, connection) = h2::client::handshake(near).await.unwrap();
    tokio::spawn(connection);
    writes_then_reset(sender, server, false).await;
}

#[tokio::test]
async fn a_split_tunnel_without_half_close_sends_its_writes_then_resets_the_stream() {
    let (near, far) = duplex(1 << 16);
    let server = tokio::spawn(holding_server(far));
    let (sender, conn) = handshake_split(&client_builder(), Box::new(near))
        .await
        .unwrap();
    tokio::spawn(conn);
    writes_then_reset(sender, server, true).await;
}

async fn writes_then_reset(
    mut sender: h2::client::SendRequest<Bytes>,
    server: tokio::task::JoinHandle<(Vec<u8>, bool, Option<h2::Reason>)>,
    direct: bool,
) {
    let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
    assert_eq!(send.has_direct_writer(), direct);
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
    let (got, ended, reason) = tokio::time::timeout(patience, server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.len(), payload.len());
    assert!(got == payload);
    assert!(ended);
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

struct WriteLog(Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

impl tokio::io::AsyncWrite for WriteLog {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        concord_common::sync::lock(&self.0).push(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn split_handshake_writes_preface_settings_and_window_update_at_once() {
    let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (near, _far) = duplex(1 << 16);
    let (_sender, _conn) = client_builder()
        .handshake_split::<_, _, Bytes>(near, WriteLog(writes.clone()))
        .await
        .unwrap();
    let writes = concord_common::sync::lock(&writes);
    assert_eq!(writes.len(), 1);
    let frames = writes[0]
        .strip_prefix(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice())
        .unwrap();
    let settings_len = u32::from_be_bytes([0, frames[0], frames[1], frames[2]]) as usize;
    let (settings, rest) = frames.split_at(9 + settings_len);
    assert_eq!(settings[3], 0x4);
    assert_eq!(rest[..9], [0, 0, 4, 0x8, 0, 0, 0, 0, 0]);
    let increment = u32::from_be_bytes(rest[9..13].try_into().unwrap());
    assert_eq!(increment, CONN_WINDOW - 65_535);
    assert_eq!(rest.len(), 13);
}

type RawFrame = (u8, u8, Vec<u8>);

/// Plays a server that sends empty SETTINGS and no WINDOW_UPDATE, and returns the client's frames
/// after the preface up to the one `last` picks.
async fn raw_frames(mut far: DuplexStream, last: impl Fn(&[RawFrame]) -> bool) -> Vec<RawFrame> {
    far.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
    let mut preface = [0; 24];
    far.read_exact(&mut preface).await.unwrap();
    let mut frames = Vec::new();
    while !last(&frames) {
        let mut header = [0; 9];
        far.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; length];
        far.read_exact(&mut payload).await.unwrap();
        frames.push((header[3], header[4], payload));
    }
    frames
}

fn ends_with_reset(frames: &[RawFrame]) -> bool {
    frames.last().is_some_and(|frame| frame.0 == 3)
}

async fn tunnel_end(written: usize) -> Vec<RawFrame> {
    let (near, far) = duplex(1 << 20);
    let frames = tokio::spawn(raw_frames(far, ends_with_reset));
    let (mut sender, conn) = handshake_split(&client_builder(), Box::new(near))
        .await
        .unwrap();
    tokio::spawn(conn);
    let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
    let mut body = H2Body::new(send, Incoming::Response(response)).without_half_close();
    body.write_all(&vec![7; written]).await.unwrap();
    body.shutdown().await.unwrap();
    let mut frames = tokio::time::timeout(Duration::from_secs(5), frames)
        .await
        .unwrap()
        .unwrap();
    frames.retain(|frame| matches!(frame.0, 0 | 3));
    frames
}

#[tokio::test]
async fn a_tunnel_sends_a_padded_empty_end_stream_ahead_of_its_reset() {
    let frames = tunnel_end(4).await;
    assert_eq!(frames.len(), 3, "{frames:?}");
    assert_eq!((frames[0].0, frames[0].1, frames[0].2.len()), (0, 0, 4));
    let (kind, flags, padding) = &frames[1];
    assert_eq!((*kind, *flags), (0, 0x1 | 0x8));
    assert!((26..=50).contains(&padding.len()), "{}", padding.len());
    assert_eq!(usize::from(padding[0]), padding.len() - 1);
    assert!(padding[1..].iter().all(|&octet| octet == 0));
    assert_eq!(frames[2].2, u32::from(h2::Reason::CANCEL).to_be_bytes());
}

#[tokio::test]
async fn a_tunnel_with_under_72_octets_of_connection_window_sends_only_its_reset() {
    let frames = tunnel_end(65_535 - 71).await;
    let (last, data) = frames.split_last().unwrap();
    assert_eq!(last.0, 3);
    assert!(data.iter().all(|frame| frame.1 == 0), "{frames:?}");
    assert_eq!(
        data.iter().map(|frame| frame.2.len()).sum::<usize>(),
        65_535 - 71
    );
}

async fn connect_headers(builder: &h2::client::Builder) -> Vec<(u8, Vec<u8>)> {
    let (near, far) = duplex(1 << 16);
    let frames = tokio::spawn(raw_frames(far, |frames| {
        frames.iter().filter(|frame| frame.0 == 1).count() == 2
    }));
    let (mut sender, conn) = handshake_split(builder, Box::new(near)).await.unwrap();
    tokio::spawn(conn);
    let mut streams = Vec::new();
    for _ in 0..2 {
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .header("padding", "!!!!")
            .body(())
            .unwrap();
        request.extensions_mut().insert(h2::ext::StreamPriority {
            dependency: 0,
            weight: 73,
            exclusive: true,
        });
        streams.push(sender.send_request(request, false).unwrap());
    }
    let frames = tokio::time::timeout(Duration::from_secs(5), frames)
        .await
        .unwrap()
        .unwrap();
    frames
        .into_iter()
        .filter(|frame| frame.0 == 1)
        .map(|(_, flags, payload)| (flags, payload))
        .collect()
}

#[tokio::test]
async fn a_request_carries_its_priority_and_raw_values_where_huffman_is_longer() {
    let headers = connect_headers(&client_builder()).await;
    for (flags, payload) in &headers {
        assert_eq!(*flags, 0x4 | 0x20);
        assert_eq!(payload[..5], [0x80, 0, 0, 0, 73]);
    }
    assert!(headers[0].1[5..].windows(5).any(|run| run == b"\x04!!!!"));
}

#[tokio::test]
async fn pseudo_headers_other_than_authority_can_stay_out_of_the_dynamic_table() {
    let indexed = connect_headers(&client_builder()).await;
    assert_eq!(indexed[0].1[5], 0x42);
    assert!(indexed[1].1[5] & 0x80 != 0);
    let mut builder = client_builder();
    builder.index_pseudo_headers(false);
    let literal = connect_headers(&builder).await;
    for (_, payload) in &literal {
        assert!(payload[5..].starts_with(b"\x02\x07CONNECT"));
    }
    assert_eq!(literal[0].1[14], 0x41);
    assert!(literal[1].1[14] & 0x80 != 0);
}

#[tokio::test]
async fn a_split_tunnel_whose_write_half_is_dropped_ends_its_read_half_without_an_error() {
    let (near, far) = duplex(1 << 16);
    let server = tokio::spawn(holding_server(far));
    let (mut sender, connection) = h2::client::handshake(near).await.unwrap();
    tokio::spawn(connection);
    let (response, send) = sender.send_request(http::Request::new(()), false).unwrap();
    let body = H2Body::new(send, Incoming::Response(response)).without_half_close();
    let (mut read, mut write) = Box::new(body).into_split();
    write.write_all(b"tail").await.unwrap();
    drop(write);
    let patience = std::time::Duration::from_secs(5);
    let mut rest = Vec::new();
    assert_eq!(
        tokio::time::timeout(patience, read.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let (_, ended, reason) = tokio::time::timeout(patience, server)
        .await
        .unwrap()
        .unwrap();
    assert!(ended);
    assert_eq!(reason, Some(h2::Reason::CANCEL));
}
