//! The ShadowTLS server against the client in front of a real rustls handshake server, a
//! stranger's plain TLS client, and records written by hand where neither can write them.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::BoxStream;
use concord_common::sync::lock;
use concord_test_support::tcp_pair;
use concord_tls::{TlsOptions, TrustStore};
use concord_transport::{
    HandshakeTarget, Layer, ShadowTlsAccepted, ShadowTlsClient, ShadowTlsOptions, ShadowTlsServer,
    ShadowTlsServerOptions, ShadowTlsUser, ShadowTlsVersion, TransportStack, WildcardSni,
};
use hmac::{Hmac, KeyInit, Mac};
use rcgen::{CertificateParams, KeyPair};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::net::TcpStream;

struct Decoy {
    config: Arc<ServerConfig>,
    der: CertificateDer<'static>,
}

fn decoy(versions: &[&'static rustls::SupportedProtocolVersion]) -> Arc<Decoy> {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["decoy.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let der = cert.der().clone();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    Arc::new(Decoy {
        config: Arc::new(config),
        der,
    })
}

impl Decoy {
    /// A connection to the handshake server, which echoes what it decrypts.
    fn connect(&self) -> DuplexStream {
        let (near, far) = duplex(1 << 20);
        let acceptor = tokio_rustls::TlsAcceptor::from(self.config.clone());
        tokio::spawn(async move {
            if let Ok(mut stream) = acceptor.accept(far).await {
                let mut buf = [0u8; 4096];
                while let Ok(read @ 1..) = stream.read(&mut buf).await {
                    if stream.write_all(&buf[..read]).await.is_err() {
                        return;
                    }
                }
            }
        });
        near
    }

    fn trust(&self) -> Arc<TrustStore> {
        TrustStore::new(b"", vec![self.der.clone()])
    }

    /// A browser's view of the listener: TLS to the handshake server, which echoes.
    async fn browse(&self, io: TcpStream, lines: usize) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = ServerName::try_from("decoy.test").unwrap();
        let mut tls = connector.connect(name, io).await.unwrap();
        for line in 0..lines {
            let sent = format!("line {line}");
            tls.write_all(sent.as_bytes()).await.unwrap();
            let mut got = vec![0u8; sent.len()];
            tls.read_exact(&mut got).await.unwrap();
            assert_eq!(got, sent.as_bytes());
        }
    }
}

type Dialed = Arc<Mutex<Vec<HandshakeTarget>>>;

fn options(version: ShadowTlsVersion) -> ShadowTlsServerOptions {
    ShadowTlsServerOptions {
        version,
        password: "pw".into(),
        users: vec![
            ShadowTlsUser {
                name: "alice".into(),
                password: "one".into(),
            },
            ShadowTlsUser {
                name: "bob".into(),
                password: "two".into(),
            },
        ],
        handshake: HandshakeTarget {
            server: "decoy.test:443".into(),
            proxy: None,
        },
        handshake_for_server_name: Default::default(),
        strict_mode: false,
        wildcard_sni: WildcardSni::Off,
    }
}

/// Serves one connection, dialing `upstream` for every handshake, and echoes what reaches
/// the protocol.
async fn serve(
    server: ShadowTlsServer,
    io: TcpStream,
    upstream: impl Fn() -> BoxStream + Sync,
    dialed: Dialed,
) -> io::Result<Option<Option<String>>> {
    let dial = |target: &HandshakeTarget| -> io::Result<BoxStream> {
        lock(&dialed).push(target.clone());
        Ok(upstream())
    };
    let Some(ShadowTlsAccepted { mut stream, user }) = server.accept(io, &dial).await? else {
        return Ok(None);
    };
    let mut buf = [0u8; 8192];
    while let Ok(read @ 1..) = stream.read(&mut buf).await {
        stream.write_all(&buf[..read]).await?;
    }
    Ok(Some(user))
}

fn client(version: u8, password: &str, decoy: &Decoy) -> TransportStack {
    let options = ShadowTlsOptions {
        password: password.into(),
        version,
        tls: TlsOptions {
            server_name: Some("decoy.test".into()),
            ..TlsOptions::default()
        },
    };
    let client = ShadowTlsClient::new(options, decoy.trust()).unwrap();
    TransportStack::new(vec![Layer::ShadowTls(Arc::new(client))], Default::default())
}

async fn through(version: ShadowTlsVersion, client_version: u8, password: &str) -> Option<String> {
    let decoy = decoy(&[&rustls::version::TLS13, &rustls::version::TLS12]);
    let (near, far) = tcp_pair().await;
    let dialed = Dialed::default();
    let upstream = {
        let decoy = decoy.clone();
        move || -> BoxStream { Box::new(decoy.connect()) }
    };
    let served = tokio::spawn(serve(
        ShadowTlsServer::new(options(version)),
        far,
        upstream,
        dialed.clone(),
    ));
    let mut io = client(client_version, password, &decoy)
        .apply(Box::new(near), "decoy.test")
        .await
        .unwrap();
    let big: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = tokio::io::split(&mut io);
    let mut echoed = vec![0u8; big.len()];
    let (sent, got) = tokio::join!(write.write_all(&big), read.read_exact(&mut echoed));
    sent.unwrap();
    got.unwrap();
    assert_eq!(echoed, big);
    drop(io);
    assert_eq!(lock(&dialed).len(), 1);
    served.await.unwrap().unwrap().unwrap()
}

#[tokio::test]
async fn each_version_carries_the_client_past_the_handshake() {
    assert_eq!(through(ShadowTlsVersion::V1, 1, "").await, None);
    assert_eq!(through(ShadowTlsVersion::V2, 2, "pw").await, None);
    assert_eq!(
        through(ShadowTlsVersion::V3, 3, "two").await.as_deref(),
        Some("bob")
    );
}

async fn stranger(version: ShadowTlsVersion, lines: usize) -> io::Result<Option<Option<String>>> {
    let decoy = decoy(&[&rustls::version::TLS13]);
    let (near, far) = tcp_pair().await;
    let upstream = {
        let decoy = decoy.clone();
        move || -> BoxStream { Box::new(decoy.connect()) }
    };
    let served = tokio::spawn(serve(
        ShadowTlsServer::new(options(version)),
        far,
        upstream,
        Dialed::default(),
    ));
    decoy.browse(near, lines).await;
    served.await.unwrap()
}

#[tokio::test]
async fn a_stranger_talks_to_the_handshake_server_to_the_end() {
    assert!(stranger(ShadowTlsVersion::V3, 6).await.unwrap().is_none());
    assert!(stranger(ShadowTlsVersion::V2, 6).await.unwrap().is_none());
}

#[tokio::test]
async fn a_v3_client_with_another_password_reaches_only_the_handshake_server() {
    let decoy = decoy(&[&rustls::version::TLS13]);
    let (near, far) = tcp_pair().await;
    let upstream = {
        let decoy = decoy.clone();
        move || -> BoxStream { Box::new(decoy.connect()) }
    };
    let served = tokio::spawn(serve(
        ShadowTlsServer::new(options(ShadowTlsVersion::V3)),
        far,
        upstream,
        Dialed::default(),
    ));
    let applied = client(3, "three", &decoy)
        .apply(Box::new(near), "decoy.test")
        .await;
    assert!(applied.is_err());
    drop(applied);
    assert!(served.await.unwrap().unwrap().is_none());
}

type HmacSha1 = Hmac<Sha1>;

/// A ClientHello record naming `sni`, its session ID signed with `password` when one is
/// given, as `generateSessionID` signs it.
fn client_hello(sni: &str, password: Option<&str>) -> Vec<u8> {
    let mut name = vec![0];
    name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    name.extend_from_slice(sni.as_bytes());
    let mut list = (name.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&name);
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&list);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.push(32);
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut hello = vec![1];
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    let mut frame = vec![22, 3, 1];
    frame.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    frame.extend_from_slice(&hello);
    if let Some(password) = password {
        frame[72..76].fill(0);
        let mut mac = HmacSha1::new_from_slice(password.as_bytes()).unwrap();
        mac.update(&frame[5..]);
        let tag = mac.finalize().into_bytes();
        frame[72..76].copy_from_slice(&tag[..4]);
    }
    frame
}

/// A ServerHello record, with `supported_versions` naming TLS 1.3 when `tls13`.
fn server_hello(tls13: bool) -> Vec<u8> {
    let extensions: &[u8] = if tls13 { &[0, 43, 0, 2, 3, 4] } else { &[] };
    let mut body = vec![3, 3];
    body.extend_from_slice(&[5; 32]);
    body.push(0);
    body.extend_from_slice(&[0x13, 0x01, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);
    let mut hello = vec![2];
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    let mut frame = vec![22, 3, 3];
    frame.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    frame.extend_from_slice(&hello);
    frame
}

/// An application record whose HMAC a v3 server takes for the client's (`v3.go:281-303`).
fn signed_record(password: &str, server_random: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(password.as_bytes()).unwrap();
    mac.update(server_random);
    mac.update(b"C");
    mac.update(payload);
    let tag = mac.finalize().into_bytes();
    let mut frame = vec![23, 3, 3];
    frame.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
    frame.extend_from_slice(&tag[..4]);
    frame.extend_from_slice(payload);
    frame
}

struct Scripted {
    dialed: Dialed,
    /// The handshake server's ends, in the order they were dialed.
    upstreams: Arc<Mutex<Vec<DuplexStream>>>,
}

/// Serves one connection whose handshake servers the test plays itself.
fn scripted(
    options: ShadowTlsServerOptions,
    io: TcpStream,
) -> (
    Scripted,
    tokio::task::JoinHandle<io::Result<Option<Option<String>>>>,
) {
    let scripted = Scripted {
        dialed: Dialed::default(),
        upstreams: Arc::default(),
    };
    let upstreams = scripted.upstreams.clone();
    let upstream = move || -> BoxStream {
        let (near, far) = duplex(1 << 16);
        lock(&upstreams).push(far);
        Box::new(near)
    };
    let served = tokio::spawn(serve(
        ShadowTlsServer::new(options),
        io,
        upstream,
        scripted.dialed.clone(),
    ));
    (scripted, served)
}

impl Scripted {
    async fn upstream(&self) -> DuplexStream {
        loop {
            if let Some(upstream) = lock(&self.upstreams).pop() {
                return upstream;
            }
            tokio::task::yield_now().await;
        }
    }
}

/// A v3 client past a handshake server that answers in `tls13` or not.
async fn v3_over(strict: bool, tls13: bool) -> Option<Vec<u8>> {
    let (mut near, far) = tcp_pair().await;
    let mut options = options(ShadowTlsVersion::V3);
    options.strict_mode = strict;
    let (scripted, served) = scripted(options, far);
    near.write_all(&client_hello("decoy.test", Some("one")))
        .await
        .unwrap();
    let mut upstream = scripted.upstream().await;
    let mut hello = vec![0u8; client_hello("decoy.test", None).len()];
    upstream.read_exact(&mut hello).await.unwrap();
    upstream.write_all(&server_hello(tls13)).await.unwrap();
    let mut answered = vec![0u8; server_hello(tls13).len()];
    near.read_exact(&mut answered).await.unwrap();
    near.write_all(&signed_record("one", &[5; 32], b"request"))
        .await
        .unwrap();
    if strict && !tls13 {
        let mut relayed = vec![0u8; signed_record("one", &[5; 32], b"request").len()];
        upstream.read_exact(&mut relayed).await.unwrap();
        drop((near, upstream));
        assert!(served.await.unwrap().unwrap().is_none());
        return None;
    }
    let mut echoed = vec![0u8; 4 + 5 + 7];
    near.read_exact(&mut echoed).await.unwrap();
    drop(near);
    assert_eq!(
        served.await.unwrap().unwrap(),
        Some(Some("alice".to_owned()))
    );
    Some(echoed[9..].to_vec())
}

#[tokio::test]
async fn strict_mode_relays_a_handshake_server_that_is_not_tls13() {
    assert_eq!(v3_over(true, true).await.as_deref(), Some(&b"request"[..]));
    assert_eq!(v3_over(true, false).await, None);
    assert_eq!(
        v3_over(false, false).await.as_deref(),
        Some(&b"request"[..])
    );
}

/// Where a v3 connection whose hello names `sni` dials its handshake.
async fn v3_dials(
    signed: bool,
    sni: &str,
    wildcard: WildcardSni,
    by_name: &[(&str, &str)],
) -> String {
    let (mut near, far) = tcp_pair().await;
    let mut options = options(ShadowTlsVersion::V3);
    options.wildcard_sni = wildcard;
    options.handshake_for_server_name = by_name
        .iter()
        .map(|(name, server)| {
            let target = HandshakeTarget {
                server: (*server).into(),
                proxy: Some("via".into()),
            };
            ((*name).to_owned(), target)
        })
        .collect();
    let (scripted, served) = scripted(options, far);
    near.write_all(&client_hello(sni, signed.then_some("two")))
        .await
        .unwrap();
    drop(scripted.upstream().await);
    drop(near);
    let _ = served.await.unwrap();
    let dialed = lock(&scripted.dialed);
    assert_eq!(dialed.len(), 1);
    dialed[0].server.clone()
}

#[tokio::test]
async fn v3_dials_the_handshake_its_server_name_and_wildcard_pick() {
    let named = [("named.test", "named.example:8443")];
    for signed in [false, true] {
        assert_eq!(
            v3_dials(signed, "named.test", WildcardSni::All, &named).await,
            "named.example:8443"
        );
        assert_eq!(
            v3_dials(signed, "other.test", WildcardSni::Off, &named).await,
            "decoy.test:443"
        );
        assert_eq!(
            v3_dials(signed, "other.test", WildcardSni::All, &named).await,
            "other.test:443"
        );
    }
    assert_eq!(
        v3_dials(false, "other.test", WildcardSni::Authed, &[]).await,
        "decoy.test:443"
    );
    assert_eq!(
        v3_dials(true, "other.test", WildcardSni::Authed, &[]).await,
        "other.test:443"
    );
}

#[tokio::test]
async fn an_ip_literal_server_name_takes_no_wildcard() {
    for literal in ["127.0.0.1", "::1", "[::1]"] {
        assert_eq!(
            v3_dials(true, literal, WildcardSni::All, &[]).await,
            "decoy.test:443"
        );
    }
    assert_eq!(
        v3_dials(false, "odd:name", WildcardSni::All, &[]).await,
        "[odd:name]:443"
    );
}

/// `v2.go:39-80`: a client that sent its hash before the handshake server's last write
/// reached it.
#[tokio::test]
async fn a_v2_client_may_hash_what_came_before_the_last_write() {
    let (mut near, far) = tcp_pair().await;
    let (scripted, served) = scripted(options(ShadowTlsVersion::V2), far);
    let hello = client_hello("decoy.test", None);
    near.write_all(&hello).await.unwrap();
    let mut upstream = scripted.upstream().await;
    let mut relayed = vec![0u8; hello.len()];
    upstream.read_exact(&mut relayed).await.unwrap();
    let mut seen = [0u8; 5];
    for write in [b"first", b"later"] {
        upstream.write_all(write).await.unwrap();
        near.read_exact(&mut seen).await.unwrap();
    }
    let mut mac = HmacSha1::new_from_slice(b"pw").unwrap();
    mac.update(b"first");
    let mut payload = mac.finalize().into_bytes()[..8].to_vec();
    payload.extend_from_slice(b"request");
    let mut record = vec![23, 3, 3];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);
    near.write_all(&record).await.unwrap();
    let mut echoed = [0u8; 5 + 7];
    tokio::time::timeout(Duration::from_secs(5), near.read_exact(&mut echoed))
        .await
        .expect("the client's hash was not taken")
        .unwrap();
    assert_eq!(&echoed[5..], b"request");
    drop(near);
    assert_eq!(served.await.unwrap().unwrap(), Some(None));
}

/// A prober that replays a client's hello gets a new server random, so the records it
/// replays with it are signed for another and go on to the handshake server.
#[tokio::test]
async fn records_signed_for_another_server_random_reach_only_the_handshake_server() {
    let (mut near, far) = tcp_pair().await;
    let (scripted, served) = scripted(options(ShadowTlsVersion::V3), far);
    near.write_all(&client_hello("decoy.test", Some("one")))
        .await
        .unwrap();
    let mut upstream = scripted.upstream().await;
    let mut hello = vec![0u8; client_hello("decoy.test", None).len()];
    upstream.read_exact(&mut hello).await.unwrap();
    upstream.write_all(&server_hello(true)).await.unwrap();
    let mut answered = vec![0u8; server_hello(true).len()];
    near.read_exact(&mut answered).await.unwrap();
    let replayed = signed_record("one", &[9; 32], b"request");
    near.write_all(&replayed).await.unwrap();
    let mut relayed = vec![0u8; replayed.len()];
    upstream.read_exact(&mut relayed).await.unwrap();
    assert_eq!(relayed, replayed);
    drop((near, upstream));
    assert!(!matches!(served.await.unwrap(), Ok(Some(_))));
}

#[tokio::test(start_paused = true)]
async fn a_signed_hello_that_stalls_stays_with_the_handshake_server() {
    let (mut near, far) = tcp_pair().await;
    let (scripted, served) = scripted(options(ShadowTlsVersion::V3), far);
    near.write_all(&client_hello("decoy.test", Some("one")))
        .await
        .unwrap();
    let mut upstream = scripted.upstream().await;
    let mut hello = vec![0u8; client_hello("decoy.test", None).len()];
    upstream.read_exact(&mut hello).await.unwrap();
    upstream.write_all(&server_hello(true)).await.unwrap();
    let mut answered = vec![0u8; server_hello(true).len()];
    near.read_exact(&mut answered).await.unwrap();
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert!(!served.is_finished(), "closed where mihomo relays on");
    near.write_all(&signed_record("one", &[5; 32], b"request"))
        .await
        .unwrap();
    let mut echoed = vec![0u8; 4 + 5 + 7];
    near.read_exact(&mut echoed).await.unwrap();
    drop(near);
    assert_eq!(
        served.await.unwrap().unwrap(),
        Some(Some("alice".to_owned()))
    );
}

#[tokio::test(start_paused = true)]
async fn a_client_that_sends_no_hello_is_closed() {
    for version in [ShadowTlsVersion::V2, ShadowTlsVersion::V3] {
        let (near, far) = tcp_pair().await;
        let (scripted, served) = scripted(options(version), far);
        let ended = tokio::time::timeout(Duration::from_secs(60), served).await;
        let ended = ended.expect("the server is still waiting").unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(lock(&scripted.dialed).is_empty());
        drop(near);
    }
}
