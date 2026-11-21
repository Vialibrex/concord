use std::sync::atomic::{AtomicU64, Ordering};

use concord_common::sync::lock;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};

use super::*;

#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

impl Meter for Counters {
    fn on_upload(&self, bytes: u64) {
        self.up.fetch_add(bytes, Ordering::Relaxed);
    }

    fn on_download(&self, bytes: u64) {
        self.down.fetch_add(bytes, Ordering::Relaxed);
    }
}

fn pair(capacity: usize) -> (BoxStream, DuplexStream) {
    let (near, far) = duplex(capacity);
    (Box::new(near), far)
}

#[tokio::test]
async fn bytes_cross_in_both_directions_and_are_metered() {
    let (a, mut a_far) = pair(1024);
    let (b, mut b_far) = pair(1024);
    let meter = std::sync::Arc::new(Counters::default());
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let meter = meter.clone();
        async move { relay(a, b, meter.as_ref(), &cancel).await }
    });

    a_far.write_all(b"request").await.unwrap();
    let mut got = [0u8; 7];
    b_far.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"request");
    b_far.write_all(b"response!").await.unwrap();
    let mut got = [0u8; 9];
    a_far.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"response!");

    a_far.shutdown().await.unwrap();
    b_far.shutdown().await.unwrap();
    let outcome = task.await.unwrap();
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert_eq!((outcome.upload, outcome.download), (7, 9));
    assert_eq!(meter.up.load(Ordering::Relaxed), 7);
    assert_eq!(meter.down.load(Ordering::Relaxed), 9);
}

#[tokio::test]
async fn closing_one_side_finishes_that_direction_and_keeps_the_other() {
    let (a, mut a_far) = pair(1024);
    let (b, mut b_far) = pair(1024);
    let meter = Counters::default();
    let cancel = CancellationToken::new();
    let relaying = relay(a, b, &meter, &cancel);

    let peers = async {
        a_far.write_all(b"GET /").await.unwrap();
        a_far.shutdown().await.unwrap();
        let mut request = Vec::new();
        b_far.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"GET /");

        b_far.write_all(b"200 OK").await.unwrap();
        b_far.shutdown().await.unwrap();
        let mut response = Vec::new();
        a_far.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"200 OK");
    };
    let (outcome, ()) = tokio::join!(relaying, peers);
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert_eq!((outcome.upload, outcome.download), (5, 6));
}

#[tokio::test]
async fn the_client_closing_first_reports_upload_first() {
    let (a, mut a_far) = pair(1024);
    let (b, mut b_far) = pair(1024);
    let meter = Counters::default();
    let cancel = CancellationToken::new();

    let peers = async {
        a_far.shutdown().await.unwrap();
        let mut eof = Vec::new();
        b_far.read_to_end(&mut eof).await.unwrap();
        b_far.shutdown().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(relay(a, b, &meter, &cancel), peers);
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert_eq!(outcome.first_finished, Some(Direction::Upload));
}

#[tokio::test]
async fn the_server_closing_first_with_no_download_reports_download_first() {
    let (a, mut a_far) = pair(1024);
    let (b, mut b_far) = pair(1024);
    let meter = Counters::default();
    let cancel = CancellationToken::new();

    let peers = async {
        b_far.shutdown().await.unwrap();
        let mut eof = Vec::new();
        a_far.read_to_end(&mut eof).await.unwrap();
        a_far.shutdown().await.unwrap();
    };
    let (outcome, ()) = tokio::join!(relay(a, b, &meter, &cancel), peers);
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert_eq!(outcome.download, 0);
    assert_eq!(outcome.first_finished, Some(Direction::Download));
}

#[tokio::test]
async fn cancelling_ends_the_relay_and_closes_both_streams() {
    let (a, mut a_far) = pair(1024);
    let (b, mut b_far) = pair(1024);
    let meter = Counters::default();
    let cancel = CancellationToken::new();
    let task = tokio::spawn({
        let cancel = cancel.clone();
        async move { relay(a, b, &meter, &cancel).await }
    });

    a_far.write_all(b"x").await.unwrap();
    let mut one = [0u8; 1];
    b_far.read_exact(&mut one).await.unwrap();
    cancel.cancel();
    let outcome = task.await.unwrap();
    assert!(matches!(outcome.end, RelayEnd::Cancelled));
    assert_eq!(outcome.first_finished, None);
    assert_eq!(outcome.upload, 1);
    assert_eq!(a_far.read(&mut one).await.unwrap(), 0);
    assert_eq!(b_far.read(&mut one).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_half_closed_connection_carries_the_open_direction_until_its_peer_closes() {
    let (a, mut a_far) = pair(1024);
    let (b, mut b_far) = pair(1024);
    let meter = Counters::default();
    let cancel = CancellationToken::new();
    a_far.shutdown().await.unwrap();

    let peer = async {
        let mut eof = Vec::new();
        b_far.read_to_end(&mut eof).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3600)).await;
        b_far.write_all(b"late").await.unwrap();
        b_far.shutdown().await.unwrap();
        let mut got = Vec::new();
        a_far.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"late");
    };
    let (outcome, ()) = tokio::join!(relay(a, b, &meter, &cancel), peer);
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert_eq!(outcome.download, 4);
}

struct Broken;

impl AsyncRead for Broken {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
    }
}

impl AsyncWrite for Broken {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for Broken {}

#[tokio::test]
async fn a_read_error_ends_the_relay_with_that_error() {
    let (b, _b_far) = pair(1024);
    let meter = Counters::default();
    let outcome = relay(Box::new(Broken), b, &meter, &CancellationToken::new()).await;
    let RelayEnd::Error(err) = outcome.end else {
        panic!("expected an error, got {:?}", outcome.end);
    };
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn a_large_transfer_arrives_intact() {
    let payload: Vec<u8> = (0..1_500_000u32).map(|n| (n % 251) as u8).collect();
    let (a, mut a_far) = pair(16 * 1024);
    let (b, mut b_far) = pair(16 * 1024);
    let meter = Counters::default();
    let cancel = CancellationToken::new();

    let sender = async {
        a_far.write_all(&payload).await.unwrap();
        a_far.shutdown().await.unwrap();
    };
    let receiver = async {
        let mut received = Vec::new();
        b_far.read_to_end(&mut received).await.unwrap();
        b_far.shutdown().await.unwrap();
        received
    };
    let (outcome, (), received) = tokio::join!(relay(a, b, &meter, &cancel), sender, receiver);
    assert_eq!(received, payload);
    assert_eq!(outcome.upload, payload.len() as u64);
    assert_eq!(meter.up.load(Ordering::Relaxed), payload.len() as u64);
}

/// A stack stream that only moves bytes through `DirectIo`; its copy path fails.
struct DirectOnly {
    outgoing: Vec<u8>,
    sent: usize,
    received: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    shut: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl AsyncRead for DirectOnly {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("copy path used")))
    }
}

impl AsyncWrite for DirectOnly {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("copy path used")))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shut.store(true, Ordering::Relaxed);
        Poll::Ready(Ok(()))
    }
}

impl concord_common::DirectIo for DirectOnly {
    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        socket: &tokio::net::TcpStream,
    ) -> Poll<io::Result<usize>> {
        let rest = self.outgoing.get(self.sent..).unwrap_or_default();
        if rest.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            ready!(socket.poll_write_ready(cx))?;
            match socket.try_write(rest) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                result => {
                    let n = result?;
                    self.sent += n;
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        socket: &tokio::net::TcpStream,
    ) -> Poll<io::Result<usize>> {
        let mut buf = [0u8; 8192];
        loop {
            ready!(socket.poll_read_ready(cx))?;
            match socket.try_read(&mut buf) {
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                result => {
                    let n = result?;
                    {
                        let mut received = lock(&self.received);
                        received.extend_from_slice(buf.get(..n).unwrap_or_default());
                    }
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }
}

impl Stream for DirectOnly {
    fn direct(&mut self) -> Option<&mut dyn concord_common::DirectIo> {
        Some(self)
    }
}

#[tokio::test]
async fn a_stack_stream_and_a_bare_socket_relay_without_the_copy_buffer() {
    let (near, mut far) = crate::test_support::loopback_pair().await;
    let upload: Vec<u8> = (0..700_000u32).map(|n| (n % 241) as u8).collect();
    let download: Vec<u8> = (0..900_000u32).map(|n| (n % 239) as u8).collect();
    let received = std::sync::Arc::default();
    let shut = std::sync::Arc::default();
    let stack = DirectOnly {
        outgoing: upload.clone(),
        sent: 0,
        received: std::sync::Arc::clone(&received),
        shut: std::sync::Arc::clone(&shut),
    };
    let meter = Counters::default();
    let cancel = CancellationToken::new();
    let peer = async {
        let (mut reader, mut writer) = far.split();
        let mut got = Vec::new();
        let (read, wrote) = tokio::join!(reader.read_to_end(&mut got), async {
            writer.write_all(&download).await?;
            writer.shutdown().await
        });
        read.unwrap();
        wrote.unwrap();
        got
    };
    let (outcome, got) = tokio::join!(
        relay(Box::new(stack), Box::new(near), &meter, &cancel),
        peer
    );
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert!(got == upload, "the socket got every uploaded byte");
    assert!(
        *lock(&received) == download,
        "the stack got every downloaded byte"
    );
    assert!(
        shut.load(Ordering::Relaxed),
        "the socket's end of stream reached the stack"
    );
    assert_eq!(
        (outcome.upload, outcome.download),
        (upload.len() as u64, download.len() as u64)
    );
    assert_eq!(meter.down.load(Ordering::Relaxed), download.len() as u64);
}

#[derive(Default)]
struct Session {
    up: AtomicU64,
    down: AtomicU64,
    done: std::sync::atomic::AtomicBool,
    dropped: std::sync::atomic::AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
    received: std::sync::Mutex<Vec<u8>>,
    accepted: tokio::sync::Notify,
}

struct SessionHandle(std::sync::Arc<Session>);

impl concord_common::Attached for SessionHandle {
    fn moved(&self) -> (u64, u64) {
        (
            self.0.up.load(Ordering::Relaxed),
            self.0.down.load(Ordering::Relaxed),
        )
    }

    fn poll_done(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        *lock(&self.0.waker) = Some(cx.waker().clone());
        if self.0.done.load(Ordering::Acquire) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::Release);
    }
}

/// A stack stream that takes the socket over: a task stands in for the stack's engine.
struct Attaching {
    outgoing: Vec<u8>,
    session: std::sync::Arc<Session>,
    on_attach: Option<Box<dyn FnOnce(concord_common::OwnedTcp) + Send>>,
}

impl AsyncRead for Attaching {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl AsyncWrite for Attaching {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("copy path used")))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl concord_common::DirectIo for Attaching {
    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        _: &tokio::net::TcpStream,
    ) -> Poll<io::Result<usize>> {
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        _: &tokio::net::TcpStream,
    ) -> Poll<io::Result<usize>> {
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn attach(
        &mut self,
        socket: tokio::net::TcpStream,
    ) -> Option<Box<dyn concord_common::Attached>> {
        self.attach_owned(&mut Some(socket.into()))
    }

    fn attach_owned(
        &mut self,
        socket: &mut Option<concord_common::OwnedTcp>,
    ) -> Option<Box<dyn concord_common::Attached>> {
        let socket = socket.take()?;
        if let Some(accept) = self.on_attach.take() {
            accept(socket);
            self.session.accepted.notify_one();
            return Some(Box::new(SessionHandle(self.session.clone())));
        }
        let session = std::sync::Arc::clone(&self.session);
        let outgoing = std::mem::take(&mut self.outgoing);
        tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(socket);
            let mut got = Vec::new();
            let (read, wrote) = tokio::join!(reader.read_to_end(&mut got), async {
                writer.write_all(&outgoing).await?;
                writer.shutdown().await
            });
            read.unwrap();
            wrote.unwrap();
            session.up.store(outgoing.len() as u64, Ordering::Relaxed);
            session.down.store(got.len() as u64, Ordering::Relaxed);
            *lock(&session.received) = got;
            session.done.store(true, Ordering::Release);
            if let Some(waker) = lock(&session.waker).take() {
                waker.wake();
            }
        });
        Some(Box::new(SessionHandle(std::sync::Arc::clone(
            &self.session,
        ))))
    }
}

impl Stream for Attaching {
    fn direct(&mut self) -> Option<&mut dyn concord_common::DirectIo> {
        Some(self)
    }
}

#[tokio::test]
async fn a_stack_that_takes_the_socket_moves_the_bytes_and_the_relay_counts_them() {
    let (near, mut far) = crate::test_support::loopback_pair().await;
    let upload: Vec<u8> = (0..300_000u32).map(|n| (n % 241) as u8).collect();
    let download: Vec<u8> = (0..400_000u32).map(|n| (n % 239) as u8).collect();
    let session = std::sync::Arc::<Session>::default();
    let stack = Attaching {
        outgoing: upload.clone(),
        session: std::sync::Arc::clone(&session),
        on_attach: None,
    };
    let meter = Counters::default();
    let cancel = CancellationToken::new();
    let peer = async {
        let (mut reader, mut writer) = far.split();
        let mut got = Vec::new();
        let (read, wrote) = tokio::join!(reader.read_to_end(&mut got), async {
            writer.write_all(&download).await?;
            writer.shutdown().await
        });
        read.unwrap();
        wrote.unwrap();
        got
    };
    let (outcome, got) = tokio::join!(
        relay(Box::new(near), Box::new(stack), &meter, &cancel),
        peer
    );
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert!(got == upload, "the socket got every byte the stack sent");
    assert!(*lock(&session.received) == download);
    assert_eq!(
        (outcome.upload, outcome.download),
        (download.len() as u64, upload.len() as u64),
        "upload is the first stream's bytes, here the socket's"
    );
    assert_eq!(meter.up.load(Ordering::Relaxed), download.len() as u64);
    assert!(session.dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn a_stack_takes_the_socket_after_the_peeked_head_was_replayed() {
    let (near, mut far) = crate::test_support::loopback_pair().await;
    let head = b"first bytes the dial read".to_vec();
    let upload: Vec<u8> = (0..200_000u32).map(|n| (n % 233) as u8).collect();
    let session = std::sync::Arc::<Session>::default();
    let stack = Attaching {
        outgoing: upload.clone(),
        session: std::sync::Arc::clone(&session),
        on_attach: None,
    };
    let local: BoxStream = Box::new(concord_common::PeekedStream::new(head.clone(), stack));
    let meter = Counters::default();
    let cancel = CancellationToken::new();
    let peer = async {
        let (mut reader, mut writer) = far.split();
        let mut got = Vec::new();
        let (read, wrote) = tokio::join!(reader.read_to_end(&mut got), writer.shutdown());
        read.unwrap();
        wrote.unwrap();
        got
    };
    let both = async { tokio::join!(relay(local, Box::new(near), &meter, &cancel), peer) };
    let (outcome, got) = tokio::time::timeout(Duration::from_secs(10), both)
        .await
        .expect("the stack never took the socket");
    assert!(matches!(outcome.end, RelayEnd::Eof), "{:?}", outcome.end);
    assert!(
        session.done.load(Ordering::Acquire),
        "the stack took the socket"
    );
    assert!(got == [head.as_slice(), upload.as_slice()].concat());
    let sent = (head.len() + upload.len()) as u64;
    assert_eq!(outcome.upload, sent);
    assert_eq!(meter.up.load(Ordering::Relaxed), sent);
}

#[tokio::test]
async fn cancelling_a_relay_drops_the_attached_connection() {
    let (near, _far) = crate::test_support::loopback_pair().await;
    let session = std::sync::Arc::<Session>::default();
    let stack = Attaching {
        outgoing: Vec::new(),
        session: std::sync::Arc::clone(&session),
        on_attach: None,
    };
    let meter = Counters::default();
    let cancel = CancellationToken::new();
    let relaying = relay(Box::new(stack), Box::new(near), &meter, &cancel);
    let canceller = async {
        tokio::task::yield_now().await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(relaying, canceller);
    assert!(
        matches!(outcome.end, RelayEnd::Cancelled),
        "{:?}",
        outcome.end
    );
    assert!(session.dropped.load(Ordering::Acquire));
    assert!(!session.done.load(Ordering::Acquire));
}

#[tokio::test]
async fn an_attached_socket_keeps_the_loopback_ticket_after_relay_cancellation() {
    let guard = crate::LoopbackGuard::new(true);
    let (near, mut far) = crate::test_support::loopback_pair().await;
    let local = near.local_addr().unwrap();
    let peer = near.peer_addr().unwrap();
    let held = std::sync::Arc::new(std::sync::Mutex::new(None));
    let session = std::sync::Arc::<Session>::default();
    let keep = held.clone();
    let stack = Attaching {
        outgoing: Vec::new(),
        session: session.clone(),
        on_attach: Some(Box::new(move |socket| *lock(&keep) = Some(socket))),
    };
    let cancel = CancellationToken::new();
    let cancelling = async {
        session.accepted.notified().await;
        cancel.cancel();
    };
    let meter = Counters::default();
    let both = async {
        tokio::join!(
            relay(
                Box::new(stack),
                Box::new(guard.track_tcp(near)),
                &meter,
                &cancel
            ),
            cancelling
        )
    };
    let (outcome, ()) = tokio::time::timeout(Duration::from_secs(10), both)
        .await
        .unwrap();
    assert!(matches!(outcome.end, RelayEnd::Cancelled));
    assert!(guard.check_flow(local, Some(peer)).is_err());
    drop(lock(&held).take());
    assert!(guard.check_flow(local, Some(peer)).is_ok());
    assert_eq!(far.read(&mut [0]).await.unwrap(), 0);
}

#[tokio::test]
async fn resetting_the_duplicate_before_accept_returns_keeps_the_original_ticket() {
    let guard = crate::LoopbackGuard::new(true);
    let (near, mut far) = crate::test_support::loopback_pair().await;
    let local = near.local_addr().unwrap();
    let peer = near.peer_addr().unwrap();
    let observing = guard.clone();
    let stack = Attaching {
        outgoing: Vec::new(),
        session: std::sync::Arc::default(),
        on_attach: Some(Box::new(move |socket| {
            drop(socket);
            assert!(observing.check_flow(local, Some(peer)).is_err());
        })),
    };
    let mut a: Option<BoxStream> = Some(Box::new(stack));
    let mut b: Option<BoxStream> = Some(Box::new(guard.track_tcp(near)));
    let Attach::Taken(handle, true) = attach(&mut a, &mut b) else {
        panic!("stack did not take the socket");
    };
    assert!(b.is_none());
    assert!(guard.check_flow(local, Some(peer)).is_ok());
    assert_eq!(far.read(&mut [0]).await.unwrap(), 0);
    drop(handle);
}

#[tokio::test]
async fn an_owned_refusal_restores_the_original_guarded_socket() {
    let guard = crate::LoopbackGuard::new(true);
    let (near, mut far) = crate::test_support::loopback_pair().await;
    let local = near.local_addr().unwrap();
    let peer = near.peer_addr().unwrap();
    let stack = DirectOnly {
        outgoing: Vec::new(),
        sent: 0,
        received: std::sync::Arc::default(),
        shut: std::sync::Arc::default(),
    };
    let mut a: Option<BoxStream> = Some(Box::new(stack));
    let mut b: Option<BoxStream> = Some(Box::new(guard.track_tcp(near)));
    assert!(matches!(attach(&mut a, &mut b), Attach::Never));
    assert!(guard.check_flow(local, Some(peer)).is_err());
    let socket = b.as_mut().unwrap();
    assert_eq!(socket.peer_addr(), Some(peer));
    assert!(socket.raw_socket().is_some());
    socket.write_all(b"request").await.unwrap();
    socket.shutdown().await.unwrap();
    let mut request = Vec::new();
    far.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");
    far.write_all(b"reply").await.unwrap();
    far.shutdown().await.unwrap();
    let mut reply = Vec::new();
    socket.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply");
    drop(b);
    assert!(guard.check_flow(local, Some(peer)).is_ok());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn accepting_a_socket_closes_the_original_descriptor() {
    use std::os::fd::AsRawFd;

    let (near, _far) = crate::test_support::loopback_pair().await;
    let descriptor = near.as_raw_fd();
    let path = format!("/proc/self/fd/{descriptor}");
    let inode = std::fs::read_link(&path).unwrap();
    let held = std::sync::Arc::new(std::sync::Mutex::new(None));
    let keep = held.clone();
    let stack = Attaching {
        outgoing: Vec::new(),
        session: std::sync::Arc::default(),
        on_attach: Some(Box::new(move |socket| *lock(&keep) = Some(socket))),
    };
    let mut a: Option<BoxStream> = Some(Box::new(stack));
    let mut b: Option<BoxStream> = Some(Box::new(near));
    assert!(matches!(attach(&mut a, &mut b), Attach::Taken(_, true)));
    assert!(b.is_none());
    assert_ne!(std::fs::read_link(path).ok(), Some(inode));
    assert!(lock(&held).is_some());
}

struct Chunky {
    left: usize,
}

macro_rules! discards_writes {
    ($($name:ty),*) => {$(
        impl Stream for $name {}

        impl AsyncWrite for $name {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(data.len()))
            }

            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }

            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
    )*};
}

discards_writes!(Chunky, DataThenReset);

impl Stream for Recorder {
    fn write_requirements(&self) -> concord_common::stream_buffer::BufferRequirements {
        self.requirements
    }
}

impl AsyncRead for Recorder {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Chunky {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let take = self.left.min(700).min(buf.remaining());
        buf.put_slice(&vec![1u8; take]);
        self.left -= take;
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct Recorder {
    writes: Vec<usize>,
    bytes: Vec<u8>,
    requirements: concord_common::stream_buffer::BufferRequirements,
}

impl AsyncWrite for Recorder {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.push(data.len());
        self.bytes.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn each_read_is_written_before_the_next_read() {
    let mut half = Half::new();
    let mut reader = Chunky { left: 7000 };
    let mut writer = Recorder::default();
    loop {
        let step = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}));
        if let Step::Finished = step.await.unwrap() {
            break;
        }
    }
    assert_eq!(writer.writes, [700; 10]);
}

struct DataThenReset(bool);

impl AsyncRead for DataThenReset {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.0 {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        self.0 = true;
        buf.put_slice(&[1u8; 100]);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn data_read_before_an_error_is_written_first() {
    let mut half = Half::new();
    let mut writer = Recorder::default();
    let mut reader = DataThenReset(false);
    let first = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {})).await;
    assert!(matches!(first, Ok(Step::Progress)));
    let second = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {})).await;
    assert_eq!(
        second.err().map(|e| e.kind()),
        Some(io::ErrorKind::ConnectionReset)
    );
    assert_eq!(writer.writes, [100]);
}

#[derive(Default)]
struct PartialVector {
    wire: Vec<u8>,
    pending: bool,
}

impl Stream for PartialVector {}

impl AsyncRead for PartialVector {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PartialVector {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pending = true;
        let mut left = 3;
        let mut written = 0;
        for buffer in buffers {
            let take = left.min(buffer.len());
            self.wire.extend_from_slice(buffer.get(..take).unwrap());
            written += take;
            left -= take;
            if left == 0 {
                break;
            }
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn vectored_buffers_keep_order_through_partial_and_pending_writes() {
    let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
    let chunks: [&[u8]; 3] = [b"first-", b"second-", b"third"];
    let mut half = Half::new();
    for chunk in chunks {
        let mut buffer = options.take();
        buffer
            .spare_mut()
            .get_mut(..chunk.len())
            .unwrap()
            .copy_from_slice(chunk);
        buffer.advance(chunk.len()).unwrap();
        half.queued.push_back(buffer);
    }
    let mut writer = PartialVector::default();
    poll_fn(|cx| half.drain(cx, &mut writer)).await.unwrap();
    assert_eq!(writer.wire, chunks.concat());
    assert!(half.queued.is_empty());
}

#[tokio::test]
async fn a_tcp_writer_holds_owned_reads_until_the_batch_or_eof() {
    let (mut writer, mut receiver) = crate::test_support::loopback_pair().await;
    let mut reader = Chunky { left: 7000 };
    let mut half = Half::new();
    for held in 1..=TCP_BATCH_BUFFERS {
        let step = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
            .await
            .unwrap();
        assert!(matches!(step, Step::Progress));
        assert_eq!(half.queued.len(), held);
        assert!(half.buffer.is_none());
        assert_eq!(
            receiver.try_read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    loop {
        let step = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
            .await
            .unwrap();
        if matches!(step, Step::Finished) {
            break;
        }
    }
    let mut received = Vec::new();
    receiver.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, vec![1; 7000]);
    assert_eq!(half.total, 7000);
    assert!(half.queued.is_empty());
}

#[tokio::test]
async fn a_full_tcp_batch_waits_for_the_writer_before_reading_more() {
    let mut writer = PartialVector {
        pending: true,
        ..Default::default()
    };
    let mut reader = Chunky { left: 1400 };
    let mut half = Half::new();
    let options = ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
    for _ in 0..TCP_BATCH_BUFFERS {
        let mut buffer = options.take();
        buffer.spare_mut()[..700].fill(1);
        buffer.advance(700).unwrap();
        half.queued.push_back(buffer);
    }
    let unread = reader.left;
    poll_fn(|cx| {
        assert!(
            half.poll(cx, &mut reader, &mut writer, &|_| {})
                .is_pending()
        );
        assert_eq!(reader.left, unread);
        assert_eq!(half.queued.len(), TCP_BATCH_BUFFERS);
        assert!(half.buffer.is_none());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn a_pending_source_flushes_a_partial_tcp_batch_without_eof() {
    let (mut writer, mut receiver) = crate::test_support::loopback_pair().await;
    let (mut reader, mut source) = duplex(1024);
    source.write_all(b"request").await.unwrap();
    let mut half = Half::new();
    let step = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
        .await
        .unwrap();
    assert!(matches!(step, Step::Progress));
    assert_eq!(half.queued.len(), 1);
    poll_fn(
        |cx| match half.poll(cx, &mut reader, &mut writer, &|_| {}) {
            Poll::Pending if half.queued.is_empty() => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => panic!("source is still open: {}", result.is_ok()),
        },
    )
    .await;
    let mut received = [0; 7];
    receiver.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"request");
    assert!(!half.read_done());
    assert!(!half.need_flush);
}

#[tokio::test]
async fn a_source_reset_drains_accepted_tcp_buffers_first() {
    let (mut writer, mut receiver) = crate::test_support::loopback_pair().await;
    let mut reader = DataThenReset(false);
    let mut half = Half::new();
    let first = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
        .await
        .unwrap();
    assert!(matches!(first, Step::Progress));
    let second = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {})).await;
    assert_eq!(
        second.err().map(|err| err.kind()),
        Some(io::ErrorKind::ConnectionReset)
    );
    let mut received = [0; 100];
    receiver.read_exact(&mut received).await.unwrap();
    assert_eq!(received, [1; 100]);
    assert!(half.queued.is_empty());
}

#[derive(Default)]
struct BufferedSink {
    buffered: Vec<u8>,
    wire: Vec<u8>,
    pending: bool,
}

impl Stream for BufferedSink {}

impl AsyncRead for BufferedSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for BufferedSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.buffered.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut written = 0;
        for buffer in buffers {
            self.buffered.extend_from_slice(buffer);
            written += buffer.len();
        }
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let this = self.get_mut();
        this.wire.append(&mut this.buffered);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

#[tokio::test]
async fn a_source_error_flushes_scalar_prefetched_and_drained_acceptances() {
    for mode in 0..3 {
        let mut half = Half::new();
        let mut reader = DataThenReset(mode != 0);
        let mut writer = BufferedSink {
            pending: true,
            ..Default::default()
        };
        let count = if mode == 2 { TCP_BATCH_BUFFERS } else { 3 };
        if mode != 0 {
            let options =
                ReadBufferOptions::for_copy(Default::default(), Default::default()).unwrap();
            for _ in 0..count {
                let mut buffer = options.take();
                buffer.spare_mut()[..100].fill(1);
                buffer.advance(100).unwrap();
                if mode == 1 {
                    half.read_queue.push_back(buffer);
                } else {
                    half.queued.push_back(buffer);
                }
            }
            half.need_flush = mode == 2;
        }
        loop {
            match poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {})).await {
                Ok(Step::Progress) => {}
                Ok(Step::Finished) => panic!("the source resets"),
                Err(err) => {
                    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
                    break;
                }
            }
        }
        assert_eq!(
            writer.wire,
            vec![1; if mode == 0 { 100 } else { 100 * count }]
        );
        assert!(writer.buffered.is_empty());
        assert!(half.read_queue.is_empty());
        assert!(half.queued.is_empty());
        assert!(!half.need_flush);
    }
}

struct FramedSink {
    wire: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    active: Option<(usize, usize, usize)>,
}

impl AsyncRead for FramedSink {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FramedSink {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for FramedSink {
    fn write_requirements(&self) -> concord_common::stream_buffer::BufferRequirements {
        concord_common::stream_buffer::BufferRequirements {
            mtu: 8,
            front: 2,
            rear: 1,
        }
    }

    fn poll_write_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut StreamBuffer,
    ) -> Poll<io::Result<usize>> {
        if self.active.is_none() {
            let len = buffer.len();
            buffer.prepend(2)?.copy_from_slice(&[b'H', len as u8]);
            buffer.append(1)?.copy_from_slice(b"!");
            self.active = Some((len, buffer.as_slice().as_ptr() as usize, 0));
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let (plain, pointer, consumed) = self.active.unwrap();
        assert_eq!(buffer.as_slice().as_ptr() as usize, pointer + consumed);
        let take = buffer.len().min(3);
        lock(&self.wire).extend_from_slice(&buffer.as_slice()[..take]);
        buffer.consume(take)?;
        if buffer.is_empty() {
            self.active = None;
            Poll::Ready(Ok(plain))
        } else {
            self.active = Some((plain, pointer, consumed + take));
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn wait_queued(socket: &tokio::net::TcpStream, bytes: usize) {
    let mut peeked = vec![std::mem::MaybeUninit::<u8>::uninit(); bytes];
    loop {
        socket.readable().await.unwrap();
        // A short peek reports WouldBlock so the readiness clears and the next arrival wakes us.
        let queued = socket.try_io(
            tokio::io::Interest::READABLE,
            || match socket2::SockRef::from(socket).peek(&mut peeked)? {
                n if n < bytes => Err(io::ErrorKind::WouldBlock.into()),
                n => Ok(n),
            },
        );
        match queued {
            Ok(_) => return,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("{err}"),
        }
    }
}

#[tokio::test]
async fn tcp_scatter_preserves_default_and_large_mtu_fallback_buffers() {
    use concord_common::stream_buffer::{BufferRequirements, COPY_BUFFER_SIZE};

    for requirements in [
        BufferRequirements::default(),
        BufferRequirements {
            mtu: 65535,
            front: 18,
            rear: 16,
        },
    ] {
        let payload: Vec<u8> = (0..COPY_BUFFER_SIZE * 6 + 17)
            .map(|n| (n % 251) as u8)
            .collect();
        let sent = payload.clone();
        let (mut source, mut reader) = crate::test_support::loopback_pair().await;
        socket2::SockRef::from(&reader)
            .set_recv_buffer_size(4 * payload.len())
            .unwrap();
        let sending = tokio::spawn(async move {
            source.write_all(&sent).await.unwrap();
            source.shutdown().await.unwrap();
        });
        // Scatter reads follow a full read, so whether one happens depends on how much
        // loopback has delivered when the relay polls; start with all of it queued.
        wait_queued(&reader, payload.len()).await;
        let mut writer = Recorder {
            requirements,
            ..Default::default()
        };
        let mut half = Half::new();
        let mut prefetched = false;
        loop {
            let step = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
                .await
                .unwrap();
            if writer.writes.len() == 1 {
                assert!(half.read_queue.is_empty(), "first read remains scalar");
            }
            prefetched |= !half.read_queue.is_empty();
            assert!(
                half.read_queue.len() + half.queued.len() + usize::from(half.buffer.is_some())
                    <= TCP_BATCH_BUFFERS
            );
            if matches!(step, Step::Finished) {
                break;
            }
        }
        sending.await.unwrap();
        assert!(prefetched, "fallback buffers must also use scatter reads");
        assert_eq!(writer.bytes, payload);
        assert_eq!(half.total, payload.len() as u64);
        let capacity = COPY_BUFFER_SIZE - requirements.front - requirements.rear;
        assert!(writer.writes.iter().all(|n| *n <= capacity));
    }
}

fn framed_wire(payload: &[u8]) -> Vec<u8> {
    [
        vec![b'H', payload.len() as u8],
        payload.to_vec(),
        b"!".to_vec(),
    ]
    .concat()
}

#[tokio::test]
async fn framed_tcp_reads_keep_mtu_and_order_through_readv_pending_and_eof() {
    let (mut source, mut reader) = crate::test_support::loopback_pair().await;
    let payload: Vec<u8> = (0..257).map(|n| n as u8).collect();
    source.write_all(&payload).await.unwrap();
    source.shutdown().await.unwrap();
    let wire = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut writer = FramedSink {
        wire: wire.clone(),
        active: None,
    };
    let mut half = Half::new();
    let mut saw_prefetch = false;
    let mut steps = 0;
    loop {
        let step = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
            .await
            .unwrap();
        steps += 1;
        if steps == 1 {
            assert!(half.read_queue.is_empty(), "the first read stays scalar");
        }
        saw_prefetch |= !half.read_queue.is_empty();
        assert!(
            half.read_queue.len() + half.queued.len() + usize::from(half.buffer.is_some())
                <= TCP_BATCH_BUFFERS
        );
        if !half.read_queue.is_empty() {
            assert!(!half.idle(), "prefetched bytes prevent a socket handoff");
        }
        if matches!(step, Step::Finished) {
            break;
        }
    }
    assert!(saw_prefetch);
    assert_eq!(half.total, payload.len() as u64);
    assert_eq!(
        *lock(&wire),
        payload.chunks(8).flat_map(framed_wire).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn framed_tcp_readv_preserves_a_peeked_prefix() {
    let (mut source, reader) = crate::test_support::loopback_pair().await;
    let payload: Vec<u8> = (0..257).map(|n| n as u8).collect();
    source.write_all(&payload).await.unwrap();
    source.shutdown().await.unwrap();
    let mut reader = concord_common::PeekedStream::new(b"head".to_vec(), reader);
    let wire = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut writer = FramedSink {
        wire: wire.clone(),
        active: None,
    };
    let mut half = Half::new();
    loop {
        if matches!(
            poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
                .await
                .unwrap(),
            Step::Finished
        ) {
            break;
        }
    }
    let expected = [
        framed_wire(b"head"),
        payload.chunks(8).flat_map(framed_wire).collect(),
    ]
    .concat();
    assert_eq!(*lock(&wire), expected);
    assert_eq!(half.total, payload.len() as u64 + 4);
}

#[tokio::test]
async fn short_framed_tcp_requests_keep_one_read_owner() {
    let (mut source, mut reader) = crate::test_support::loopback_pair().await;
    let wire = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut writer = FramedSink {
        wire: wire.clone(),
        active: None,
    };
    let mut half = Half::new();
    for byte in [1, 2, 3] {
        source.write_all(&[byte]).await.unwrap();
        let step = poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
            .await
            .unwrap();
        assert!(matches!(step, Step::Progress));
        assert!(half.read_queue.is_empty());
        assert!(!half.read_was_full);
    }
    source.shutdown().await.unwrap();
    loop {
        if matches!(
            poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {}))
                .await
                .unwrap(),
            Step::Finished
        ) {
            break;
        }
    }
    assert_eq!(
        *lock(&wire),
        [framed_wire(&[1]), framed_wire(&[2]), framed_wire(&[3])].concat()
    );
}

#[tokio::test]
async fn prefetched_frames_are_written_before_a_source_reset() {
    let mut half = Half::new();
    let wire = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut writer = FramedSink {
        wire: wire.clone(),
        active: None,
    };
    let options =
        ReadBufferOptions::for_copy(Default::default(), writer.write_requirements()).unwrap();
    for chunk in [b"before".as_slice(), b"-", b"reset"] {
        let mut buffer = options.take();
        buffer.spare_mut()[..chunk.len()].copy_from_slice(chunk);
        buffer.advance(chunk.len()).unwrap();
        half.read_queue.push_back(buffer);
    }
    let mut reader = DataThenReset(true);
    loop {
        match poll_fn(|cx| half.poll(cx, &mut reader, &mut writer, &|_| {})).await {
            Ok(Step::Progress) => {}
            Ok(Step::Finished) => panic!("the source resets"),
            Err(err) => {
                assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
                break;
            }
        }
    }
    assert_eq!(
        *lock(&wire),
        [
            framed_wire(b"before"),
            framed_wire(b"-"),
            framed_wire(b"reset")
        ]
        .concat()
    );
    assert_eq!(half.total, 12);
}

#[tokio::test]
async fn cancelling_a_prefetched_write_returns_every_owner() {
    let mut half = Half::new();
    let mut writer = FramedSink {
        wire: Default::default(),
        active: None,
    };
    let options =
        ReadBufferOptions::for_copy(Default::default(), writer.write_requirements()).unwrap();
    for byte in [1, 2, 3] {
        let mut buffer = options.take();
        buffer.spare_mut()[..8].fill(byte);
        buffer.advance(8).unwrap();
        half.read_queue.push_back(buffer);
    }
    let mut reader = DataThenReset(true);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(
        half.poll(&mut cx, &mut reader, &mut writer, &|_| {})
            .is_pending()
    );
    let addresses: std::collections::BTreeSet<_> = half
        .read_queue
        .iter()
        .chain(half.buffer.iter())
        .map(|b| b.as_slice().as_ptr().wrapping_sub(b.headroom()) as usize)
        .collect();
    assert_eq!(addresses.len(), 3);
    drop(half);
    let recovered: Vec<_> = (0..3).map(|_| options.take()).collect();
    let returned: std::collections::BTreeSet<_> = recovered
        .iter()
        .map(|b| b.as_slice().as_ptr().wrapping_sub(b.headroom()) as usize)
        .collect();
    assert_eq!(addresses, returned);
}

#[tokio::test]
async fn an_in_place_write_keeps_its_buffer_across_pending_and_counts_plaintext() {
    let wire = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = FramedSink {
        wire: wire.clone(),
        active: None,
    };
    let mut writer: BoxStream = Box::new(concord_common::PeekedStream::new(Vec::new(), sink));
    let mut reader = Chunky { left: 21 };
    let mut half = Half::new();
    let counted = std::cell::Cell::new(0);
    loop {
        let step = poll_fn(|cx| {
            half.poll(cx, &mut reader, &mut writer, &|n| {
                counted.set(counted.get() + n)
            })
        })
        .await
        .unwrap();
        if matches!(step, Step::Finished) {
            break;
        }
        assert!(half.buffer.is_none());
    }
    let expected: Vec<u8> = [8, 8, 5]
        .into_iter()
        .flat_map(|n| [vec![b'H', n], vec![1; usize::from(n)], b"!".to_vec()].concat())
        .collect();
    assert_eq!(*lock(&wire), expected);
    assert_eq!(half.total, 21);
    assert_eq!(counted.get(), 21);
}

#[tokio::test]
async fn dropping_a_pending_in_place_write_returns_the_storage() {
    let mut writer = FramedSink {
        wire: Default::default(),
        active: None,
    };
    let mut reader = Chunky { left: 8 };
    let mut half = Half::new();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(
        half.poll(&mut cx, &mut reader, &mut writer, &|_| {})
            .is_pending()
    );
    let pointer = half.buffer.as_ref().unwrap().as_slice().as_ptr();
    drop(half);
    let buffer =
        ReadBufferOptions::for_copy(reader.read_requirements(), writer.write_requirements())
            .unwrap()
            .take();
    assert_eq!(buffer.as_slice().as_ptr(), pointer.wrapping_add(2));
    assert!(buffer.is_empty());
    assert!(lock(&writer.wire).is_empty());
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn bare_tcp_sockets_are_spliced_once_the_transfer_is_long() {
    use crate::test_support::loopback_pair as pair;

    let (mut sender, mut source) = pair().await;
    let (mut target, mut receiver) = pair().await;
    let payload: Vec<u8> = (0..3_000_000u32).map(|n| (n % 251) as u8).collect();
    let total = std::cell::Cell::new(0u64);
    let note = |bytes| total.set(total.get() + bytes);

    let send = async {
        sender.write_all(&payload).await.unwrap();
        sender.shutdown().await.unwrap();
    };
    let receive = async {
        let mut received = Vec::new();
        receiver.read_to_end(&mut received).await.unwrap();
        received
    };
    let copy = async {
        let mut half = Half::new();
        loop {
            let step = poll_fn(|cx| half.poll(cx, &mut source, &mut target, &note));
            if let Step::Finished = step.await.unwrap() {
                return half;
            }
        }
    };
    let ((), received, half) = tokio::join!(send, receive, copy);
    assert!(received == payload);
    assert!(matches!(half.bulk, Bulk::Pipe(_)));
    assert_eq!(total.get(), payload.len() as u64);
}

#[tokio::test]
async fn each_completed_read_returns_its_buffer_even_after_bulk_traffic() {
    let (mut source, mut reader_side) = duplex(64 * 1024);
    let mut writer_side = Recorder::default();
    let counted = std::cell::Cell::new(0u64);
    let note = |bytes| counted.set(counted.get() + bytes);

    let writer = async move {
        source.write_all(&vec![7u8; 2 * 1024 * 1024]).await.unwrap();
        source.shutdown().await.unwrap();
    };
    let copier = async {
        let mut half = Half::new();
        loop {
            let step = poll_fn(|cx| half.poll(cx, &mut reader_side, &mut writer_side, &note));
            if let Step::Finished = step.await.unwrap() {
                return half;
            }
            assert!(half.buffer.is_none(), "completed writes release the buffer");
            assert!(
                writer_side.writes.last().copied().unwrap_or_default()
                    <= concord_common::stream_buffer::COPY_BUFFER_SIZE
            );
        }
    };
    let ((), half) = tokio::join!(writer, copier);
    assert_eq!(half.total, 2 * 1024 * 1024);
    assert_eq!(counted.get(), half.total);
}

struct Endless {
    reads: std::sync::Arc<AtomicU64>,
}

impl AsyncRead for Endless {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let room = buf.remaining();
        buf.initialize_unfilled().fill(1);
        buf.advance(room);
        Poll::Ready(Ok(()))
    }
}

discards_writes!(Endless);

#[tokio::test(flavor = "current_thread")]
async fn a_relay_of_streams_that_never_block_yields_after_a_tokio_budget() {
    let reads = std::sync::Arc::new(AtomicU64::new(0));
    let endless = || -> BoxStream {
        Box::new(Endless {
            reads: reads.clone(),
        })
    };
    let cancel = CancellationToken::new();
    let relaying = tokio::spawn({
        let (a, b, cancel) = (endless(), endless(), cancel.clone());
        async move { relay(a, b, &Counters::default(), &cancel).await }
    });
    let before_others = tokio::spawn({
        let reads = reads.clone();
        async move { reads.load(Ordering::Relaxed) }
    });

    let seen = tokio::time::timeout(Duration::from_secs(10), before_others)
        .await
        .expect("the relay starved the other task")
        .unwrap();
    cancel.cancel();
    let outcome = relaying.await.unwrap();
    assert!(matches!(outcome.end, RelayEnd::Cancelled));
    let budget = 128;
    assert!(
        (32..=2 * budget).contains(&seen),
        "{seen} reads ran before the other task"
    );
}
