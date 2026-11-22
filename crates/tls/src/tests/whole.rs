//! A connection that stays whole on the native record engine, against rustls as the server.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use concord_common::BoxStream;
use concord_common::sync::lock;
use rustls::{ServerConfig, SupportedProtocolVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use super::support::{Ca, Leaf};
use crate::{TlsConn, TlsConnector, TlsOptions};

const TOTAL: usize = 4 << 20;
const VERSIONS: [&SupportedProtocolVersion; 2] = [&rustls::version::TLS13, &rustls::version::TLS12];

fn server(leaf: &Leaf, version: &'static SupportedProtocolVersion) -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(crate::policy::provider())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(leaf.chain.clone(), leaf.key())
            .unwrap(),
    )
}

async fn connect(
    version: &'static SupportedProtocolVersion,
    whole: bool,
    wrap: impl FnOnce(TcpStream) -> BoxStream,
) -> (TlsConn, TlsStream<TcpStream>) {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();
    let (client, accepted) = concord_test_support::tcp_pair().await;
    let client = wrap(client);
    let connecting = async {
        if whole {
            super::support::connect_whole(&connector, client, "node.test").await
        } else {
            connector.connect_unaligned(client, "node.test").await
        }
    };
    let (client, server) = tokio::join!(
        connecting,
        tokio_rustls::TlsAcceptor::from(server(&leaf, version)).accept(accepted)
    );
    (client.unwrap(), server.unwrap())
}

async fn whole(version: &'static SupportedProtocolVersion) -> (TlsConn, TlsStream<TcpStream>) {
    let (client, server) = connect(version, true, |io| Box::new(io)).await;
    assert!(matches!(client, TlsConn::Record(_)), "{version:?}");
    (client, server)
}

fn pattern(total: usize) -> Vec<u8> {
    (0..total).map(|i| (i % 251) as u8).collect()
}

/// Writes in sizes that leave records short, full and split across socket reads.
async fn send(mut write: impl AsyncWrite + Unpin, data: &[u8]) {
    let mut sent = 0;
    for size in [1usize, 1500, 16_384, 16_385, 70_000, 5, 33_000]
        .iter()
        .cycle()
    {
        if sent == data.len() {
            break;
        }
        let end = (sent + size).min(data.len());
        write.write_all(&data[sent..end]).await.unwrap();
        sent = end;
    }
    write.flush().await.unwrap();
}

async fn receive(mut read: impl AsyncRead + Unpin, total: usize) -> Vec<u8> {
    let mut got = vec![0u8; total];
    read.read_exact(&mut got).await.unwrap();
    got
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_connection_carries_bulk_both_ways_on_tls13_and_tls12() {
    for version in VERSIONS {
        let (client, server) = whole(version).await;
        let data = pattern(TOTAL);
        let (client_read, client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server);
        let (_, _, down, up) = tokio::join!(
            send(server_write, &data),
            send(client_write, &data),
            receive(client_read, TOTAL),
            receive(server_read, TOTAL),
        );
        assert!(down == data, "{version:?}: the client's bytes differ");
        assert!(up == data, "{version:?}: the server's bytes differ");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_connection_follows_and_answers_server_key_updates() {
    let (mut client, mut server) = whole(&rustls::version::TLS13).await;
    let burst = pattern(300 * 1500);
    for round in 0..4 {
        let (_, got) = tokio::join!(
            async {
                send(&mut server, &burst).await;
                server.get_mut().1.refresh_traffic_keys().unwrap();
                server.flush().await.unwrap();
            },
            receive(&mut client, burst.len()),
        );
        assert!(got == burst, "round {round}: the client's bytes differ");
        let (_, got) = tokio::join!(send(&mut client, &burst), receive(&mut server, burst.len()));
        assert!(got == burst, "round {round}: the server's bytes differ");
    }
}

#[tokio::test]
async fn a_whole_connection_reads_on_after_it_shuts_its_writes() {
    for version in VERSIONS {
        let (mut client, mut server) = whole(version).await;
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"request", "{version:?}");
        let reply = pattern(50_000);
        server.write_all(&reply).await.unwrap();
        server.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert!(got == reply, "{version:?}");
    }
}

#[tokio::test]
async fn a_whole_connection_writes_on_after_the_server_s_close_notify() {
    for version in VERSIONS {
        let (mut client, server) = whole(version).await;
        let (mut server_read, mut server_write) = tokio::io::split(server);
        server_write.write_all(b"last words").await.unwrap();
        server_write.shutdown().await.unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"last words", "{version:?}");
        let more = pattern(50_000);
        client.write_all(&more).await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        server_read.read_to_end(&mut got).await.unwrap();
        assert!(got == more, "{version:?}");
    }
}

struct Recorded {
    io: TcpStream,
    sent: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Recorded {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, out)
    }
}

impl AsyncWrite for Recorded {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.io).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = written {
            lock(&this.sent).extend_from_slice(&data[..n]);
        }
        written
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.io).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = written {
            let mut left = n;
            let mut sent = lock(&this.sent);
            for buf in bufs {
                let take = left.min(buf.len());
                sent.extend_from_slice(&buf[..take]);
                left -= take;
            }
        }
        written
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl concord_common::Stream for Recorded {
    concord_common::stream_policy!(default: all);
}

/// The lengths of the application-data records the client put on the wire for one script of writes.
async fn records_written(version: &'static SupportedProtocolVersion, whole: bool) -> Vec<usize> {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let recorded = sent.clone();
    let (mut client, mut server) = connect(version, whole, move |io| {
        Box::new(Recorded { io, sent: recorded })
    })
    .await;
    let handshake = lock(&sent).len();
    let data = pattern(200_000);
    let mut expected = Vec::new();
    for write in [&data[..5], &data[..], &data[..3000], &data[..16_385]] {
        client.write_all(write).await.unwrap();
        client.flush().await.unwrap();
        expected.extend_from_slice(write);
    }
    let head = [9u8; 58];
    let body = [8u8; 1400];
    let mut slices = [IoSlice::new(&head), IoSlice::new(&body)];
    let mut left: &mut [IoSlice<'_>] = &mut slices;
    while !left.is_empty() {
        let n = client.write_vectored(left).await.unwrap();
        IoSlice::advance_slices(&mut left, n);
    }
    client.flush().await.unwrap();
    expected.extend_from_slice(&head);
    expected.extend_from_slice(&body);
    assert!(receive(&mut server, expected.len()).await == expected);

    let wire = lock(&sent);
    let mut lengths = Vec::new();
    let mut at = handshake;
    while at + 5 <= wire.len() {
        let length = usize::from(u16::from_be_bytes([wire[at + 3], wire[at + 4]]));
        if wire[at] == 23 {
            lengths.push(length);
        }
        at += 5 + length;
    }
    assert_eq!(at, wire.len(), "the wire ends inside a record");
    lengths
}

#[tokio::test]
async fn a_whole_connection_puts_the_records_of_a_buffered_one_on_the_wire() {
    for version in VERSIONS {
        let buffered = records_written(version, false).await;
        let whole = records_written(version, true).await;
        assert_eq!(whole, buffered, "{version:?}");
    }
}
