use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::time::Duration;

use concord_common::stream_buffer::COPY_BUFFER_SIZE;
use concord_test_support::tcp_pair;
use rustls::crypto::cipher::{MessageEncrypter, OutboundChunks, OutboundPlainMessage};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::net::TcpStream;

use super::support::{Ca, ServerSpec, connect_whole, server_config};
use crate::{TlsConn, TlsConnector, TlsOptions};

const MAX_WRITE: usize = 7 * 16 * 1024;

struct Sealer {
    encrypter: Box<dyn MessageEncrypter>,
    seq: u64,
}

impl Sealer {
    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let message = OutboundPlainMessage {
            typ: rustls::ContentType::ApplicationData,
            version: rustls::ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::Single(payload),
        };
        let sealed = self.encrypter.encrypt(message, self.seq).unwrap().encode();
        self.seq += 1;
        sealed
    }
}

async fn connect_record() -> (
    crate::record::RecordStream,
    tokio_rustls::server::TlsStream<TcpStream>,
) {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();
    let (client, server) = tcp_pair().await;
    let mut cfg = (*server_config(&leaf, &ServerSpec::default())).clone();
    cfg.send_tls13_tickets = 0;
    let (client, server) = tokio::join!(
        connect_whole(&connector, Box::new(client), "node.test"),
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg)).accept(server)
    );
    let TlsConn::Record(record) = client.unwrap() else {
        panic!("expected native RecordStream");
    };
    (*record, server.unwrap())
}

async fn connect_raw_server() -> (crate::record::TlsRead, TcpStream, Sealer) {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();
    let (client, server) = tcp_pair().await;
    let mut cfg = (*server_config(
        &leaf,
        &ServerSpec {
            tls13_only: true,
            ..ServerSpec::default()
        },
    ))
    .clone();
    cfg.enable_secret_extraction = true;
    cfg.send_tls13_tickets = 0;
    let (client, server) = tokio::join!(
        connect_whole(&connector, Box::new(client), "node.test"),
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg)).accept(server)
    );
    let (read, _write) = client.unwrap().into_halves().ok().expect("native halves");
    let server = server.unwrap();
    let suite = server.get_ref().1.negotiated_cipher_suite().unwrap();
    let (tcp, conn) = server.into_inner();
    let (seq, secrets) = conn.dangerous_extract_secrets().unwrap().tx;
    let encrypter = crate::record::test_encrypter(suite, secrets, seq).unwrap();
    (read, tcp, Sealer { encrypter, seq })
}

async fn connect_raw_duplex_server() -> (crate::record::TlsRead, DuplexStream, Sealer) {
    let ca = Ca::new();
    let leaf = ca.leaf(&["node.test"]);
    let options = TlsOptions {
        server_name: Some("node.test".into()),
        ..TlsOptions::default()
    };
    let connector = TlsConnector::new(options, ca.trust()).unwrap();
    let (client, server) = duplex(1 << 20);
    let mut cfg = (*server_config(
        &leaf,
        &ServerSpec {
            tls13_only: true,
            ..ServerSpec::default()
        },
    ))
    .clone();
    cfg.enable_secret_extraction = true;
    cfg.send_tls13_tickets = 0;
    let (client, server) = tokio::join!(
        connect_whole(&connector, Box::new(client), "node.test"),
        tokio_rustls::TlsAcceptor::from(Arc::new(cfg)).accept(server)
    );
    let (read, _write) = client.unwrap().into_halves().ok().expect("native halves");
    let server = server.unwrap();
    let suite = server.get_ref().1.negotiated_cipher_suite().unwrap();
    let (stream, conn) = server.into_inner();
    let (seq, secrets) = conn.dangerous_extract_secrets().unwrap().tx;
    let encrypter = crate::record::test_encrypter(suite, secrets, seq).unwrap();
    (read, stream, Sealer { encrypter, seq })
}

async fn write_vectored_once<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bufs: &[IoSlice<'_>],
) -> io::Result<usize> {
    poll_fn(|cx| Pin::new(&mut *writer).poll_write_vectored(cx, bufs)).await
}

async fn exercise_vectored<W: AsyncWrite + Unpin>(
    writer: &mut W,
    server: &mut tokio_rustls::server::TlsStream<TcpStream>,
) {
    assert!(writer.is_write_vectored());
    assert_eq!(
        write_vectored_once(writer, &[IoSlice::new(&[]), IoSlice::new(&[])])
            .await
            .unwrap(),
        0
    );

    let short = [
        IoSlice::new(&[]),
        IoSlice::new(b"alpha-"),
        IoSlice::new(&[]),
        IoSlice::new(b"beta-"),
        IoSlice::new(b"gamma"),
    ];
    let n = write_vectored_once(writer, &short).await.unwrap();
    assert_eq!(n, 16);
    writer.flush().await.unwrap();
    let mut got = [0u8; 16];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"alpha-beta-gamma");

    // More than MAX_WRITE_SLICES (8) non-empty small slices under MAX_WRITE.
    let pieces: Vec<Vec<u8>> = (0..12u8).map(|i| vec![i.wrapping_add(1); 64]).collect();
    let mut many = Vec::with_capacity(15);
    for (idx, piece) in pieces.iter().enumerate() {
        if idx % 4 == 0 {
            many.push(IoSlice::new(&[]));
        }
        many.push(IoSlice::new(piece));
    }
    let expected_many: Vec<u8> = pieces.iter().flatten().copied().collect();
    let n = write_vectored_once(writer, &many).await.unwrap();
    assert_eq!(n, expected_many.len());
    writer.flush().await.unwrap();
    let mut got_many = vec![0u8; expected_many.len()];
    server.read_exact(&mut got_many).await.unwrap();
    assert_eq!(got_many, expected_many);

    // Slices totaling more than MAX_WRITE (10 * 16 KiB > 7 * 16 KiB).
    let blocks: Vec<Vec<u8>> = (0..10u8)
        .map(|i| vec![i.wrapping_add(0x20); 16 * 1024])
        .collect();
    let big: Vec<IoSlice<'_>> = blocks.iter().map(|b| IoSlice::new(b)).collect();
    let expected_big: Vec<u8> = blocks.iter().flatten().copied().collect();
    let reader = async {
        let mut received = vec![0u8; expected_big.len()];
        server.read_exact(&mut received).await.unwrap();
        received
    };
    let sender = async {
        let first = write_vectored_once(writer, &big).await.unwrap();
        assert_eq!(first, MAX_WRITE);
        let rest: Vec<IoSlice<'_>> = blocks[7..].iter().map(|b| IoSlice::new(b)).collect();
        let second = write_vectored_once(writer, &rest).await.unwrap();
        assert_eq!(second, expected_big.len() - MAX_WRITE);
        writer.flush().await.unwrap();
    };
    let (_, received) = tokio::join!(sender, reader);
    assert_eq!(received, expected_big);
}

#[tokio::test]
async fn poll_write_vectored_handles_empty_short_many_and_oversized_slices() {
    let (mut record, mut server) = connect_record().await;
    exercise_vectored(&mut record, &mut server).await;

    let (record, mut server) = connect_record().await;
    let (_read, mut write) = record.into_halves();
    exercise_vectored(&mut write, &mut server).await;
}

#[tokio::test]
async fn partial_record_fills_within_and_across_copy_buffer_preserve_order() {
    let (mut read, mut tcp, mut sealer) = connect_raw_server().await;

    let plain1: Vec<u8> = (0..16 * 1024).map(|i| ((i * 3) % 251) as u8).collect();
    let wire1 = sealer.seal(&plain1);
    assert!(wire1.len() < COPY_BUFFER_SIZE);
    let cuts = [100usize, 4_100, 10_100, wire1.len()];
    let mut prev = 0;
    for &cut in &cuts[..3] {
        tcp.write_all(&wire1[prev..cut]).await.unwrap();
        prev = cut;
        tokio::time::sleep(Duration::from_millis(15)).await;
        let mut scratch = [0u8; 64];
        let mut buf = ReadBuf::new(&mut scratch);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            Pin::new(&mut read)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
    }
    tcp.write_all(&wire1[prev..]).await.unwrap();
    let mut got1 = vec![0u8; plain1.len()];
    read.read_exact(&mut got1).await.unwrap();
    assert_eq!(got1, plain1);

    let plain2: Vec<u8> = (0..16 * 1024).map(|i| ((i * 5 + 1) % 251) as u8).collect();
    let plain3: Vec<u8> = (0..16 * 1024).map(|i| ((i * 7 + 2) % 251) as u8).collect();
    let plain4: Vec<u8> = (0..16 * 1024).map(|i| ((i * 11 + 3) % 251) as u8).collect();
    let mut wire_straddle = sealer.seal(&plain2);
    wire_straddle.extend(sealer.seal(&plain3));
    wire_straddle.extend(sealer.seal(&plain4));
    assert!(wire_straddle.len() > COPY_BUFFER_SIZE);

    tcp.write_all(&wire_straddle[..COPY_BUFFER_SIZE])
        .await
        .unwrap();
    let mut got2 = vec![0u8; plain2.len()];
    read.read_exact(&mut got2).await.unwrap();
    assert_eq!(got2, plain2);

    tokio::time::sleep(Duration::from_millis(15)).await;
    let mut scratch = [0u8; 64];
    let mut buf = ReadBuf::new(&mut scratch);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(
        Pin::new(&mut read)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );

    tcp.write_all(&wire_straddle[COPY_BUFFER_SIZE..])
        .await
        .unwrap();
    let mut got34 = vec![0u8; plain3.len() + plain4.len()];
    read.read_exact(&mut got34).await.unwrap();
    assert_eq!(&got34[..plain3.len()], plain3.as_slice());
    assert_eq!(&got34[plain3.len()..], plain4.as_slice());

    let plain5 = b"split-header-first";
    let plain6 = b"following-record";
    let mut wire_hdr = sealer.seal(plain5);
    wire_hdr.extend(sealer.seal(plain6));
    tcp.write_all(&wire_hdr[..3]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(15)).await;
    let mut buf = ReadBuf::new(&mut scratch);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(
        Pin::new(&mut read)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );
    tcp.write_all(&wire_hdr[3..]).await.unwrap();
    let mut got56 = vec![0u8; plain5.len() + plain6.len()];
    read.read_exact(&mut got56).await.unwrap();
    assert_eq!(&got56[..plain5.len()], plain5.as_slice());
    assert_eq!(&got56[plain5.len()..], plain6.as_slice());
}

#[tokio::test]
async fn duplex_partial_record_and_split_header_fills_preserve_order() {
    let (mut read, mut stream, mut sealer) = connect_raw_duplex_server().await;

    let plain_hdr = b"duplex-split-header";
    let plain_next = b"duplex-following-record";
    let mut wire_hdr = sealer.seal(plain_hdr);
    wire_hdr.extend(sealer.seal(plain_next));
    stream.write_all(&wire_hdr[..3]).await.unwrap();
    let mut scratch = [0u8; 64];
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut buf = ReadBuf::new(&mut scratch);
    assert!(
        Pin::new(&mut read)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );
    stream.write_all(&wire_hdr[3..]).await.unwrap();
    let mut got_hdr = vec![0u8; plain_hdr.len() + plain_next.len()];
    read.read_exact(&mut got_hdr).await.unwrap();
    assert_eq!(&got_hdr[..plain_hdr.len()], plain_hdr.as_slice());
    assert_eq!(&got_hdr[plain_hdr.len()..], plain_next.as_slice());

    let plain1: Vec<u8> = (0..16 * 1024).map(|i| ((i * 5 + 3) % 251) as u8).collect();
    let wire1 = sealer.seal(&plain1);
    assert!(wire1.len() < COPY_BUFFER_SIZE);
    let before = crate::record::record_buffer_takes();
    let cuts = [100usize, 4_100, 10_100, wire1.len()];
    let mut prev = 0;
    for &cut in &cuts[..3] {
        stream.write_all(&wire1[prev..cut]).await.unwrap();
        prev = cut;
        let mut buf = ReadBuf::new(&mut scratch);
        assert!(
            Pin::new(&mut read)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
    }
    stream.write_all(&wire1[prev..]).await.unwrap();
    let mut got1 = vec![0u8; plain1.len()];
    read.read_exact(&mut got1).await.unwrap();
    assert_eq!(got1, plain1);
    assert!(crate::record::record_buffer_takes() - before <= 1);

    let plain2: Vec<u8> = (0..16 * 1024).map(|i| ((i * 7 + 1) % 251) as u8).collect();
    let plain3: Vec<u8> = (0..16 * 1024).map(|i| ((i * 11 + 2) % 251) as u8).collect();
    let plain4: Vec<u8> = (0..16 * 1024).map(|i| ((i * 13 + 3) % 251) as u8).collect();
    let mut wire_straddle = sealer.seal(&plain2);
    wire_straddle.extend(sealer.seal(&plain3));
    wire_straddle.extend(sealer.seal(&plain4));
    assert!(wire_straddle.len() > COPY_BUFFER_SIZE);
    stream
        .write_all(&wire_straddle[..COPY_BUFFER_SIZE])
        .await
        .unwrap();
    let mut got2 = vec![0u8; plain2.len()];
    read.read_exact(&mut got2).await.unwrap();
    assert_eq!(got2, plain2);
    let mut buf = ReadBuf::new(&mut scratch);
    assert!(
        Pin::new(&mut read)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );
    stream
        .write_all(&wire_straddle[COPY_BUFFER_SIZE..])
        .await
        .unwrap();
    let mut got34 = vec![0u8; plain3.len() + plain4.len()];
    read.read_exact(&mut got34).await.unwrap();
    assert_eq!(&got34[..plain3.len()], plain3.as_slice());
    assert_eq!(&got34[plain3.len()..], plain4.as_slice());
}

#[tokio::test]
async fn unaligned_record_stream_rejects_short_tcp_close_and_keeps_clean_eof() {
    let (mut read, mut tcp, mut sealer) = connect_raw_server().await;
    let wire = sealer.seal(b"clean");
    tcp.write_all(&wire).await.unwrap();
    tcp.shutdown().await.unwrap();
    let mut out = Vec::new();
    read.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"clean");

    let (mut read, mut tcp, mut sealer) = connect_raw_server().await;
    let wire = sealer.seal(b"truncated-payload");
    tcp.write_all(&wire[..wire.len() - 4]).await.unwrap();
    tcp.shutdown().await.unwrap();
    let mut out = Vec::new();
    let err = read.read_to_end(&mut out).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn partial_record_within_copy_buffer_does_not_take_a_second_buffer() {
    let (mut read, mut tcp, mut sealer) = connect_raw_server().await;
    let plain: Vec<u8> = (0..16 * 1024).map(|i| ((i * 13) % 251) as u8).collect();
    let wire = sealer.seal(&plain);
    assert!(wire.len() < COPY_BUFFER_SIZE);

    let before = crate::record::record_buffer_takes();
    let cuts = [64usize, 2_000, 9_000, wire.len()];
    let mut prev = 0;
    for &cut in &cuts[..3] {
        tcp.write_all(&wire[prev..cut]).await.unwrap();
        prev = cut;
        tokio::time::sleep(Duration::from_millis(15)).await;
        let mut scratch = [0u8; 64];
        let mut buf = ReadBuf::new(&mut scratch);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            Pin::new(&mut read)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
    }
    tcp.write_all(&wire[prev..]).await.unwrap();
    let mut got = vec![0u8; plain.len()];
    read.read_exact(&mut got).await.unwrap();
    assert_eq!(got, plain);
    assert_eq!(crate::record::record_buffer_takes() - before, 1);
}

#[tokio::test]
async fn pending_straddling_tcp_fill_does_not_take_a_second_buffer() {
    let (mut read, mut tcp, mut sealer) = connect_raw_server().await;
    let plain1: Vec<u8> = (0..16 * 1024).map(|i| ((i * 3 + 7) % 251) as u8).collect();
    let plain2: Vec<u8> = (0..16 * 1024).map(|i| ((i * 5 + 9) % 251) as u8).collect();
    let plain3: Vec<u8> = (0..16 * 1024).map(|i| ((i * 7 + 11) % 251) as u8).collect();
    let mut wire = sealer.seal(&plain1);
    wire.extend(sealer.seal(&plain2));
    wire.extend(sealer.seal(&plain3));
    assert!(wire.len() > COPY_BUFFER_SIZE);

    tcp.write_all(&wire[..COPY_BUFFER_SIZE]).await.unwrap();
    let mut got1 = vec![0u8; plain1.len()];
    read.read_exact(&mut got1).await.unwrap();
    assert_eq!(got1, plain1);

    // Clear any leftover readiness from the initial 32 KiB read so the socket is parked Pending.
    let mut scratch = [0u8; 64];
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut buf = ReadBuf::new(&mut scratch);
    assert!(
        Pin::new(&mut read)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );

    let takes_while_pending = crate::record::record_buffer_takes();
    for _ in 0..5 {
        let mut buf = ReadBuf::new(&mut scratch);
        assert!(
            Pin::new(&mut read)
                .poll_read(&mut cx, &mut buf)
                .is_pending()
        );
    }
    assert_eq!(
        crate::record::record_buffer_takes(),
        takes_while_pending,
        "pending straddling polls must not borrow pooled buffers"
    );

    tcp.write_all(&wire[COPY_BUFFER_SIZE..]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(15)).await;
    let mut got23 = vec![0u8; plain2.len() + plain3.len()];
    read.read_exact(&mut got23).await.unwrap();
    assert_eq!(&got23[..plain2.len()], plain2.as_slice());
    assert_eq!(&got23[plain2.len()..], plain3.as_slice());
    assert!(crate::record::record_buffer_takes() <= takes_while_pending + 1);
}
