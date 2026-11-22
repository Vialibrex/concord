use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use concord_common::sync::lock;
use concord_common::{BoxRead, BoxStream, BoxWrite};
use concord_test_support::tcp_pair;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use super::support::{Ca, Leaf, ServerSpec, connect_whole, server_config};
use crate::{ClientFingerprint, TlsConnector, TlsOptions};

const TOTAL: usize = 4 << 20;

async fn connect(
    fingerprint: Option<ClientFingerprint>,
    spec: &ServerSpec,
) -> (BoxStream, TlsStream<TcpStream>) {
    connect_with(fingerprint, |leaf| server_config(leaf, spec), false).await
}

async fn connect_with(
    fingerprint: Option<ClientFingerprint>,
    server: impl FnOnce(&Leaf) -> Arc<ServerConfig>,
    aligned: bool,
) -> (BoxStream, TlsStream<TcpStream>) {
    connect_with_transport(fingerprint, server, aligned, |io| Box::new(io)).await
}

async fn connect_with_transport(
    fingerprint: Option<ClientFingerprint>,
    server: impl FnOnce(&Leaf) -> Arc<ServerConfig>,
    aligned: bool,
    wrap: impl FnOnce(TcpStream) -> BoxStream,
) -> (BoxStream, TlsStream<TcpStream>) {
    let (client, server) = connect_typed(fingerprint, server, aligned, wrap).await;
    (Box::new(client), server)
}

async fn connect_typed(
    fingerprint: Option<ClientFingerprint>,
    server: impl FnOnce(&Leaf) -> Arc<ServerConfig>,
    aligned: bool,
    wrap: impl FnOnce(TcpStream) -> BoxStream,
) -> (crate::TlsConn, TlsStream<TcpStream>) {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let config = server(&leaf);
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        client_fingerprint: fingerprint,
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();
    let (client, server) = tcp_pair().await;
    let client = wrap(client);
    let connecting = async {
        if aligned {
            connector.connect(client, "node.test").await
        } else {
            connector.connect_unaligned(client, "node.test").await
        }
    };
    let (client, server) = tokio::join!(
        connecting,
        tokio_rustls::TlsAcceptor::from(config).accept(server)
    );
    (client.unwrap(), server.unwrap())
}

fn split(stream: BoxStream) -> (BoxRead, BoxWrite) {
    stream.into_split()
}

async fn send(mut write: impl AsyncWrite + Unpin, total: usize) {
    let chunk: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    let mut left = total;
    while left > 0 {
        let n = left.min(chunk.len());
        write.write_all(&chunk[..n]).await.unwrap();
        left -= n;
    }
    write.shutdown().await.unwrap();
}

async fn drain(mut read: impl AsyncRead + Unpin) -> io::Result<usize> {
    let mut total = 0;
    let mut buf = vec![0u8; 7000];
    loop {
        let n = read.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        assert!(
            buf[..n]
                .iter()
                .enumerate()
                .all(|(i, b)| usize::from(*b) == (total + i) % 1500 % 251)
        );
        total += n;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn split_halves_move_both_directions_at_once() {
    for fingerprint in [None, Some(ClientFingerprint::Chrome)] {
        let (client, server) = connect(fingerprint, &ServerSpec::default()).await;
        let (read, write) = split(client);
        let (server_read, server_write) = tokio::io::split(server);
        let (_, _, client_got, server_got) = tokio::join!(
            tokio::spawn(send(write, TOTAL)),
            tokio::spawn(send(server_write, TOTAL)),
            tokio::spawn(drain(read)),
            tokio::spawn(drain(server_read)),
        );
        assert_eq!(client_got.unwrap().unwrap(), TOTAL, "{fingerprint:?}");
        assert_eq!(server_got.unwrap().unwrap(), TOTAL, "{fingerprint:?}");
    }
}

#[tokio::test]
async fn shutting_the_write_half_leaves_the_read_half_open() {
    let (client, mut server) = connect(None, &ServerSpec::default()).await;
    let (mut read, mut write) = split(client);
    write.write_all(b"request").await.unwrap();
    write.shutdown().await.unwrap();
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"request");
    server.write_all(b"response").await.unwrap();
    server.shutdown().await.unwrap();
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"response");
}

/// Go's crypto/tls rule (conn.go readRecordOrCCS): an EOF without close_notify is a clean
/// end at a record boundary.
#[tokio::test]
async fn a_bare_eof_at_a_record_boundary_ends_the_stream() {
    let (client, mut server) = connect(None, &ServerSpec::default()).await;
    let (mut read, _write) = split(client);
    server.write_all(b"last").await.unwrap();
    server.flush().await.unwrap();
    let (mut tcp, _) = server.into_inner();
    tcp.shutdown().await.unwrap();
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"last");
}

#[tokio::test]
async fn a_bare_eof_inside_a_record_is_unexpected() {
    let (client, server) = connect(None, &ServerSpec::default()).await;
    let (mut read, _write) = split(client);
    let (mut tcp, _) = server.into_inner();
    tcp.write_all(&[23, 3, 3, 0, 64, 1, 2, 3]).await.unwrap();
    tcp.shutdown().await.unwrap();
    let err = read.read(&mut [0u8; 16]).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_halves_follow_server_key_updates() {
    let spec = ServerSpec {
        tls13_only: true,
        ..ServerSpec::default()
    };
    let (client, mut server) = connect(None, &spec).await;
    let (read, write) = split(client);
    let reader = tokio::spawn(drain(read));
    let chunk: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
    for _ in 0..4 {
        for _ in 0..300 {
            server.write_all(&chunk).await.unwrap();
        }
        server.get_mut().1.refresh_traffic_keys().unwrap();
        server.flush().await.unwrap();
    }
    server.shutdown().await.unwrap();
    assert_eq!(reader.await.unwrap().unwrap(), 4 * 300 * 1500);

    let writer = tokio::spawn(send(write, TOTAL));
    assert_eq!(drain(&mut server).await.unwrap(), TOTAL);
    writer.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_aead_suite_seals_and_opens_both_ways() {
    use rustls::crypto::aws_lc_rs::cipher_suite as cs;
    let suites = [
        (cs::TLS13_AES_128_GCM_SHA256, &rustls::version::TLS13),
        (cs::TLS13_AES_256_GCM_SHA384, &rustls::version::TLS13),
        (cs::TLS13_CHACHA20_POLY1305_SHA256, &rustls::version::TLS13),
        (
            cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            &rustls::version::TLS12,
        ),
        (
            cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            &rustls::version::TLS12,
        ),
        (
            cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            &rustls::version::TLS12,
        ),
    ];
    for (suite, version) in suites {
        let (client, server) = connect_with(
            None,
            |leaf| {
                let provider = rustls::crypto::CryptoProvider {
                    cipher_suites: vec![suite],
                    ..(*crate::policy::provider()).clone()
                };
                let config = ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[version])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(leaf.chain.clone(), leaf.key())
                    .unwrap();
                Arc::new(config)
            },
            false,
        )
        .await;
        assert_eq!(
            server.get_ref().1.negotiated_cipher_suite(),
            Some(suite),
            "{suite:?}"
        );
        let (read, write) = split(client);
        let (server_read, server_write) = tokio::io::split(server);
        let total = 1 << 20;
        let (_, _, client_got, server_got) = tokio::join!(
            tokio::spawn(send(write, total)),
            tokio::spawn(send(server_write, total)),
            tokio::spawn(drain(read)),
            tokio::spawn(drain(server_read)),
        );
        assert_eq!(client_got.unwrap().unwrap(), total, "{suite:?}");
        assert_eq!(server_got.unwrap().unwrap(), total, "{suite:?}");
    }
}

async fn records_in_one_read(aligned: bool) -> usize {
    let (client, mut server) = connect_with(
        None,
        |leaf| server_config(leaf, &ServerSpec::default()),
        aligned,
    )
    .await;
    let (mut read, _write) = split(client);
    for _ in 0..3 {
        server.write_all(&[7u8; 5000]).await.unwrap();
        server.flush().await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    read.read(&mut buf).await.unwrap()
}

#[tokio::test]
async fn one_read_takes_every_record_the_transport_has_ready() {
    assert_eq!(records_in_one_read(false).await, 15_000);
}

#[tokio::test]
async fn an_aligned_read_stops_at_the_end_of_a_record() {
    assert_eq!(records_in_one_read(true).await, 5000);
}

/// Bytes still queued in the client socket after its split read half has taken the first
/// record and one byte of the second, out of three full records sent at once.
async fn left_in_socket_after_one_record(aligned: bool) -> usize {
    let mut probe = None;
    let (client, mut server) = connect_with_transport(
        None,
        |leaf| server_config(leaf, &ServerSpec::default()),
        aligned,
        |io| {
            let io = io.into_std().unwrap();
            probe = Some(io.try_clone().unwrap());
            Box::new(TcpStream::from_std(io).unwrap())
        },
    )
    .await;
    let probe = probe.unwrap();
    let (mut read, _write) = split(client);
    for _ in 0..3 {
        server.write_all(&[7u8; 16 * 1024]).await.unwrap();
    }
    server.flush().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 16 * 1024 + 1];
    read.read_exact(&mut buf).await.unwrap();
    let mut rest = vec![0u8; 64 * 1024];
    match probe.peek(&mut rest) {
        Ok(n) => n,
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => 0,
        Err(err) => panic!("{err}"),
    }
}

#[tokio::test]
async fn a_split_read_half_completes_a_record_and_reads_ahead_in_one_call() {
    assert_eq!(left_in_socket_after_one_record(false).await, 0);
}

#[tokio::test]
async fn an_aligned_split_read_half_leaves_the_next_record_in_the_socket() {
    assert!(left_in_socket_after_one_record(true).await > 0);
}

#[tokio::test]
async fn a_whole_connection_reads_ahead_on_the_native_engine() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();
    let (client, server) = tcp_pair().await;
    let (client, server) = tokio::join!(
        connect_whole(&connector, Box::new(client), "node.test"),
        tokio_rustls::TlsAcceptor::from(server_config(&leaf, &ServerSpec::default()))
            .accept(server)
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    assert!(matches!(client, crate::TlsConn::Record(_)));
    for _ in 0..3 {
        server.write_all(&[7u8; 5000]).await.unwrap();
        server.flush().await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut buf = vec![0u8; 64 * 1024];
    assert_eq!(client.read(&mut buf).await.unwrap(), 15_000);
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut got = [0u8; 4];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
}

#[tokio::test]
async fn a_whole_connection_split_after_a_read_keeps_what_it_read_ahead() {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();
    let (client, server) = tcp_pair().await;
    let (client, server) = tokio::join!(
        connect_whole(&connector, Box::new(client), "node.test"),
        tokio_rustls::TlsAcceptor::from(server_config(&leaf, &ServerSpec::default()))
            .accept(server)
    );
    let (mut client, mut server) = (client.unwrap(), server.unwrap());
    let expected: Vec<u8> = (0..3 * 5000).map(|i| (i % 251) as u8).collect();
    for record in expected.chunks(5000) {
        server.write_all(record).await.unwrap();
        server.flush().await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut first = [0u8; 3];
    client.read_exact(&mut first).await.unwrap();
    assert_eq!(first, expected[..3]);

    let client: BoxStream = Box::new(client);
    let (mut read, mut write) = client.into_split();
    let mut rest = vec![0u8; expected.len() - 3];
    read.read_exact(&mut rest).await.unwrap();
    assert_eq!(rest, expected[3..]);
    write.write_all(b"ping").await.unwrap();
    write.flush().await.unwrap();
    let mut got = [0u8; 4];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    server.write_all(b"pong").await.unwrap();
    server.flush().await.unwrap();
    read.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"pong");
}

struct ReadRequests {
    io: TcpStream,
    sizes: Arc<Mutex<Vec<usize>>>,
}

impl AsyncRead for ReadRequests {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        lock(&this.sizes).push(out.remaining());
        Pin::new(&mut this.io).poll_read(cx, out)
    }
}

impl AsyncWrite for ReadRequests {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl concord_common::Stream for ReadRequests {
    concord_common::stream_policy!(default: all);
}

#[tokio::test]
async fn bulk_socket_reads_are_not_capped_at_one_record() {
    let sizes = Arc::new(Mutex::new(Vec::new()));
    let observed = sizes.clone();
    let (client, mut server) = connect_with_transport(
        None,
        |leaf| {
            let mut config = (*server_config(leaf, &ServerSpec::default())).clone();
            config.send_tls13_tickets = 0;
            Arc::new(config)
        },
        false,
        move |io| {
            Box::new(ReadRequests {
                io,
                sizes: observed,
            })
        },
    )
    .await;
    let (mut client, _write) = client.into_split();
    lock(&sizes).clear();
    let expected: Vec<u8> = (0..3 * 16384 + 113).map(|i| (i % 251) as u8).collect();
    server.write_all(&expected).await.unwrap();
    server.shutdown().await.unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, expected);
    assert!(lock(&sizes).iter().any(|size| *size > 16384 + 2048 + 5));
}

#[tokio::test]
async fn split_bulk_reads_keep_records_in_order_across_owned_blocks() {
    let (client, mut server) = connect_with(
        None,
        |leaf| {
            let mut config = (*server_config(
                leaf,
                &ServerSpec {
                    tls13_only: true,
                    ..ServerSpec::default()
                },
            ))
            .clone();
            config.send_tls13_tickets = 0;
            Arc::new(config)
        },
        false,
    )
    .await;
    let (mut client, _write) = client.into_split();
    let expected: Vec<u8> = (0..4 * 32768 + 113).map(|i| (i % 251) as u8).collect();
    let sending = async {
        // The next TLS 1.3 header straddles the 32 KiB ciphertext block after these records.
        for chunk in [&expected[..16384], &expected[16384..32722]] {
            server.write_all(chunk).await.unwrap();
            server.flush().await.unwrap();
        }
        for chunk in expected[32722..].chunks(5001) {
            server.write_all(chunk).await.unwrap();
        }
        server.shutdown().await.unwrap();
    };
    let receiving = async {
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::join!(sending, receiving);
    assert_eq!(got, expected);
}

struct SplitObserved {
    io: TcpStream,
    splits: Arc<AtomicUsize>,
    pause_shutdown: bool,
}

impl AsyncRead for SplitObserved {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, out)
    }
}

impl AsyncWrite for SplitObserved {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if std::mem::take(&mut this.pause_shutdown) {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

impl concord_common::Stream for SplitObserved {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer,
            raw_socket, tcp, peer_addr, needs_handshake, direct, into_tcp);
    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        self.splits.fetch_add(1, Ordering::Relaxed);
        let (read, write) = self.io.into_split();
        (Box::new(read), Box::new(write))
    }
}

async fn observed(
    fingerprint: Option<ClientFingerprint>,
    aligned: bool,
    pause_shutdown: bool,
) -> (crate::TlsConn, TlsStream<TcpStream>, Arc<AtomicUsize>) {
    let splits = Arc::new(AtomicUsize::new(0));
    let seen = splits.clone();
    let (client, server) = connect_typed(
        fingerprint,
        |leaf| {
            let mut config = (*server_config(leaf, &ServerSpec::default())).clone();
            config.send_tls13_tickets = 0;
            Arc::new(config)
        },
        aligned,
        move |io| {
            Box::new(SplitObserved {
                io,
                splits: seen,
                pause_shutdown,
            })
        },
    )
    .await;
    (client, server, splits)
}

#[tokio::test]
async fn write_only_tls_handoff_preserves_sequences_and_uses_native_split() {
    for fingerprint in [None, Some(ClientFingerprint::Chrome)] {
        let (mut client, mut server, splits) = observed(fingerprint, false, false).await;
        client.write_all(b"before").await.unwrap();
        client.flush().await.unwrap();
        let mut before = [0; 6];
        server.read_exact(&mut before).await.unwrap();
        assert_eq!(&before, b"before");
        if let crate::TlsConn::Buffered(ref stream) = client
            && fingerprint.is_none()
        {
            assert!(stream.test_kernel_ready());
        }
        let client: BoxStream = Box::new(client);
        let (mut read, mut write) = client.into_split();
        assert_eq!(splits.load(Ordering::Relaxed), 1);
        write.write_all(b"after").await.unwrap();
        write.shutdown().await.unwrap();
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).await.unwrap();
        assert_eq!(sent, b"after");
        server.write_all(b"reply").await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"reply");
    }
}

#[tokio::test]
async fn a_native_write_half_refuses_data_after_close_notify() {
    let (client, mut server, splits) = observed(None, false, false).await;
    let client: BoxStream = Box::new(client);
    let (_read, mut write) = client.into_split();
    assert_eq!(splits.load(Ordering::Relaxed), 1);
    write.write_all(b"last").await.unwrap();
    write.shutdown().await.unwrap();
    let err = write.write(b"late").await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(
        write.write(&[]).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let mut sent = Vec::new();
    server.read_to_end(&mut sent).await.unwrap();
    assert_eq!(sent, b"last");
}

struct Sealer {
    encrypter: Box<dyn rustls::crypto::cipher::MessageEncrypter>,
    seq: u64,
}

impl Sealer {
    fn seal(&mut self, typ: rustls::ContentType, payload: &[u8]) -> Vec<u8> {
        let message = rustls::crypto::cipher::OutboundPlainMessage {
            typ,
            version: rustls::ProtocolVersion::TLSv1_2,
            payload: rustls::crypto::cipher::OutboundChunks::Single(payload),
        };
        let sealed = self.encrypter.encrypt(message, self.seq).unwrap().encode();
        self.seq += 1;
        sealed
    }
}

async fn tls12_read_half_and_server_records() -> (BoxRead, BoxWrite, TcpStream, Sealer) {
    read_half_and_server_records(
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &rustls::version::TLS12,
    )
    .await
}

/// A native read half, and the server's socket with its traffic keys to write records by hand.
async fn read_half_and_server_records(
    suite: rustls::SupportedCipherSuite,
    version: &'static rustls::SupportedProtocolVersion,
) -> (BoxRead, BoxWrite, TcpStream, Sealer) {
    let splits = Arc::new(AtomicUsize::new(0));
    let seen = splits.clone();
    let (client, server) = connect_typed(
        None,
        |leaf| {
            let provider = rustls::crypto::CryptoProvider {
                cipher_suites: vec![suite],
                ..(*crate::policy::provider()).clone()
            };
            let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(leaf.chain.clone(), leaf.key())
                .unwrap();
            config.enable_secret_extraction = true;
            config.send_tls13_tickets = 0;
            Arc::new(config)
        },
        false,
        move |io| {
            Box::new(SplitObserved {
                io,
                splits: seen,
                pause_shutdown: false,
            })
        },
    )
    .await;
    let client: BoxStream = Box::new(client);
    let (read, write) = client.into_split();
    assert_eq!(splits.load(Ordering::Relaxed), 1);
    let suite = server.get_ref().1.negotiated_cipher_suite().unwrap();
    let (tcp, conn) = server.into_inner();
    let (seq, secrets) = conn.dangerous_extract_secrets().unwrap().tx;
    let encrypter = crate::record::test_encrypter(suite, secrets, seq).unwrap();
    (read, write, tcp, Sealer { encrypter, seq })
}

#[tokio::test]
async fn tls12_warning_alerts_are_skipped_up_to_go_s_limit() {
    let (mut read, _write, mut tcp, mut sealer) = tls12_read_half_and_server_records().await;
    let no_renegotiation = [1, 100];
    let mut wire = sealer.seal(rustls::ContentType::Alert, &no_renegotiation);
    wire.extend(sealer.seal(rustls::ContentType::ApplicationData, b"after"));
    tcp.write_all(&wire).await.unwrap();
    let mut got = [0; 5];
    read.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"after");
    let mut wire = Vec::new();
    for _ in 0..17 {
        wire.extend(sealer.seal(rustls::ContentType::Alert, &no_renegotiation));
    }
    tcp.write_all(&wire).await.unwrap();
    let err = read.read(&mut got).await.unwrap_err();
    assert!(
        err.to_string().contains("too many ignored records"),
        "{err}"
    );
}

#[tokio::test]
async fn an_eof_inside_a_handshake_message_is_not_a_clean_end() {
    let (mut read, _write, mut tcp, mut sealer) = tls12_read_half_and_server_records().await;
    let partial = [
        u8::from(rustls::HandshakeType::NewSessionTicket),
        0,
        0,
        10,
        1,
        2,
    ];
    tcp.write_all(&sealer.seal(rustls::ContentType::Handshake, &partial))
        .await
        .unwrap();
    tcp.shutdown().await.unwrap();
    let mut got = Vec::new();
    let err = read.read_to_end(&mut got).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn a_tls12_fatal_alert_still_fails_the_read() {
    let (mut read, _write, mut tcp, mut sealer) = tls12_read_half_and_server_records().await;
    tcp.write_all(&sealer.seal(rustls::ContentType::Alert, &[2, 40]))
        .await
        .unwrap();
    let mut got = [0; 1];
    let err = read.read(&mut got).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn a_tls13_user_canceled_alert_is_skipped_and_other_warnings_fail() {
    let (mut read, _write, mut tcp, mut sealer) = read_half_and_server_records(
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    )
    .await;
    let mut wire = sealer.seal(rustls::ContentType::Alert, &[1, 90]);
    wire.extend(sealer.seal(rustls::ContentType::ApplicationData, b"after"));
    wire.extend(sealer.seal(rustls::ContentType::Alert, &[1, 100]));
    tcp.write_all(&wire).await.unwrap();
    let mut got = [0; 5];
    read.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"after");
    let err = read.read(&mut got).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
}

#[tokio::test]
async fn aes_gcm_handoff_after_writing_keeps_the_nonce_mask_across_many_records() {
    use rustls::crypto::aws_lc_rs::cipher_suite as cs;
    for suite in [cs::TLS13_AES_128_GCM_SHA256, cs::TLS13_AES_256_GCM_SHA384] {
        for fingerprint in [None, Some(ClientFingerprint::Chrome)] {
            let splits = Arc::new(AtomicUsize::new(0));
            let seen = splits.clone();
            let (mut client, mut server) = connect_typed(
                fingerprint,
                |leaf| {
                    let provider = rustls::crypto::CryptoProvider {
                        cipher_suites: vec![suite],
                        ..(*crate::policy::provider()).clone()
                    };
                    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
                        .with_protocol_versions(&[&rustls::version::TLS13])
                        .unwrap()
                        .with_no_client_auth()
                        .with_single_cert(leaf.chain.clone(), leaf.key())
                        .unwrap();
                    config.send_tls13_tickets = 0;
                    Arc::new(config)
                },
                false,
                move |io| {
                    Box::new(SplitObserved {
                        io,
                        splits: seen,
                        pause_shutdown: false,
                    })
                },
            )
            .await;
            client.write_all(b"before").await.unwrap();
            client.flush().await.unwrap();
            let mut before = [0; 6];
            server.read_exact(&mut before).await.unwrap();
            assert_eq!(&before, b"before");
            let (mut read, mut write) = (Box::new(client) as BoxStream).into_split();
            assert_eq!(splits.load(Ordering::Relaxed), 1);
            for _ in 0..8 {
                write.write_all(b"after").await.unwrap();
            }
            write.shutdown().await.unwrap();
            let mut got = Vec::new();
            server.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"after".repeat(8));
            server.write_all(b"reply").await.unwrap();
            server.shutdown().await.unwrap();
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"reply");
        }
    }
}

#[tokio::test]
async fn late_split_retains_buffered_plaintext_and_uses_the_fallback() {
    for fingerprint in [None, Some(ClientFingerprint::Chrome)] {
        let (mut client, mut server, splits) = observed(fingerprint, false, false).await;
        let expected = vec![31; 16384];
        server.write_all(&expected).await.unwrap();
        server.flush().await.unwrap();
        let mut first = [0; 3];
        client.read_exact(&mut first).await.unwrap();
        assert_eq!(first, [31; 3]);
        assert!(client.has_pending_plaintext());
        if let crate::TlsConn::Buffered(ref stream) = client
            && fingerprint.is_none()
        {
            assert!(!stream.test_kernel_ready());
        }
        let client: BoxStream = Box::new(client);
        let (mut read, mut write) = client.into_split();
        assert_eq!(splits.load(Ordering::Relaxed), 0);
        write.shutdown().await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, expected[3..]);
    }
}

#[tokio::test]
async fn late_split_keeps_the_upstream_key_update_state() {
    let (mut client, mut server, splits) = observed(None, false, false).await;
    server.get_mut().1.refresh_traffic_keys().unwrap();
    server.write_all(b"key-update").await.unwrap();
    server.flush().await.unwrap();
    let mut first = [0; 1];
    client.read_exact(&mut first).await.unwrap();
    let client: BoxStream = Box::new(client);
    let (mut read, mut write) = client.into_split();
    assert_eq!(splits.load(Ordering::Relaxed), 0);
    write.write_all(b"answer").await.unwrap();
    write.shutdown().await.unwrap();
    let mut sent = Vec::new();
    server.read_to_end(&mut sent).await.unwrap();
    assert_eq!(sent, b"answer");
    server.shutdown().await.unwrap();
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"ey-update");
}

/// A server may send KeyUpdate(update_requested) right behind its Finished, so the client handles it
/// inside the handshake, before any read would rule a handoff out.
#[test]
fn a_queued_key_update_answer_rules_out_a_handoff() {
    macro_rules! pass {
        ($from:expr, $to:expr) => {{
            let mut wire = Vec::new();
            while $from.wants_write() {
                $from.write_tls(&mut wire).unwrap();
            }
            let mut slice = &wire[..];
            while !slice.is_empty() {
                $to.read_tls(&mut slice).unwrap();
            }
            $to.process_new_packets().unwrap();
        }};
    }
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let mut server_config = (*server_config(&leaf, &ServerSpec::default())).clone();
    server_config.send_tls13_tickets = 0;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der.clone()).unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.enable_secret_extraction = true;
    let name = rustls_pki_types::ServerName::try_from("node.test").unwrap();
    let mut client = rustls::ClientConnection::new(Arc::new(client_config), name).unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        pass!(client, server);
        pass!(server, client);
    }
    assert!(client.can_handoff_to_kernel());
    server.refresh_traffic_keys().unwrap();
    pass!(server, client);
    assert!(!client.can_handoff_to_kernel());
    std::io::Write::write_all(&mut client.writer(), b"answer").unwrap();
    pass!(client, server);
    assert!(client.can_handoff_to_kernel());
    let mut got = [0; 6];
    std::io::Read::read_exact(&mut server.reader(), &mut got).unwrap();
    assert_eq!(&got, b"answer");
}

#[tokio::test]
async fn splitting_during_shutdown_keeps_the_pending_close_and_reader() {
    let (mut client, mut server, splits) = observed(None, false, true).await;
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());
    let client: BoxStream = Box::new(client);
    let (mut read, mut write) = client.into_split();
    assert_eq!(splits.load(Ordering::Relaxed), 0);
    write.shutdown().await.unwrap();
    let mut sent = Vec::new();
    server.read_to_end(&mut sent).await.unwrap();
    assert!(sent.is_empty());
    server.write_all(b"still-reading").await.unwrap();
    server.shutdown().await.unwrap();
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"still-reading");
}

#[tokio::test]
async fn reality_record_owner_keeps_cached_plaintext_and_key_update_on_late_split() {
    let (client, mut server, splits) = observed(None, true, false).await;
    let crate::TlsConn::Record(record) = client else {
        panic!("aligned TLS must own its records");
    };
    let mut client =
        crate::TlsConn::Reality(Box::new(crate::reality::RealityStream::new(*record, 29)));
    server.get_mut().1.refresh_traffic_keys().unwrap();
    let expected = vec![43; 32768];
    server.write_all(&expected).await.unwrap();
    server.flush().await.unwrap();
    let mut first = [0; 5];
    client.read_exact(&mut first).await.unwrap();
    assert!(client.has_pending_plaintext());
    let client: BoxStream = Box::new(client);
    let (mut read, mut write) = client.into_split();
    assert_eq!(splits.load(Ordering::Relaxed), 1);
    write.write_all(b"ok").await.unwrap();
    write.shutdown().await.unwrap();
    let mut sent = Vec::new();
    server.read_to_end(&mut sent).await.unwrap();
    assert_eq!(sent, b"ok");
    server.shutdown().await.unwrap();
    let mut got = Vec::new();
    read.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, expected[5..]);
}
