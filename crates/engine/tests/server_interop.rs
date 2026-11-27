#![allow(
    clippy::disallowed_methods,
    reason = "the harness talks to loopback listeners and sockets directly"
)]

//! mihomo's clients against Concord's protocol servers. Run with
//! `CONCORD_MIHOMO=<path to the mihomo binary> cargo test -p concord-engine --test server_interop -- --ignored`;
//! `CONCORD_CASE=<name>[,<name>…]` runs those cases, `CONCORD_BYTES` sets the TCP echo size and
//! `CONCORD_MIHOMO_LOG` mihomo's log level.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::{CoreEvent, CoreOptions, EventSink};
use concord_engine::{Engine, EngineConfig, SetupRequest};
use concord_platform::NativePlatform;
use concord_test_support::{port_to_bind_later, tcp_echo, udp_echo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(10);
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const KEY: &str = "AAECAwQFBgcICQoLDA0ODw==";
const USER_KEY: &str = "EBESExQVFhcYGRobHB0eHw==";

struct Quiet;

impl EventSink for Quiet {
    fn enabled(&self) -> bool {
        false
    }

    fn publish(&self, _: CoreEvent) {}
}

struct Case {
    name: &'static str,
    /// The Concord listener, without its name and port.
    server: String,
    /// The mihomo proxy, without its name, server and port.
    client: String,
    user: Option<&'static str>,
    udp: bool,
}

fn case(name: &'static str, server: &str, client: &str, user: Option<&'static str>) -> Case {
    Case {
        name,
        server: server.to_owned(),
        client: client.to_owned(),
        user,
        udp: true,
    }
}

fn cases() -> Vec<Case> {
    let tls = "certificate: server.crt, private-key: server.key";
    let trust = "servername: localhost, skip-cert-verify: true";
    let mut all = vec![
        case(
            "ss-aead",
            "type: shadowsocks, cipher: aes-128-gcm, password: secret",
            "type: ss, cipher: aes-128-gcm, password: secret, udp: true",
            None,
        ),
        case(
            "ss-aead-users",
            "type: shadowsocks, cipher: aes-256-gcm, password: '', users: {alice: one, bob: two}",
            "type: ss, cipher: aes-256-gcm, password: two, udp: true",
            Some("bob"),
        ),
        case(
            "ss-2022",
            &format!("type: shadowsocks, cipher: 2022-blake3-aes-128-gcm, password: '{KEY}'"),
            &format!("type: ss, cipher: 2022-blake3-aes-128-gcm, password: '{KEY}', udp: true"),
            None,
        ),
        case(
            "ss-2022-users",
            &format!(
                "type: shadowsocks, cipher: 2022-blake3-aes-128-gcm, password: '{KEY}', users: {{carol: '{USER_KEY}'}}"
            ),
            &format!(
                "type: ss, cipher: 2022-blake3-aes-128-gcm, password: '{KEY}:{USER_KEY}', udp: true"
            ),
            Some("carol"),
        ),
        case(
            "vmess",
            &format!("type: vmess, users: [{{username: dave, uuid: {UUID}, alterId: 0}}]"),
            &format!("type: vmess, uuid: {UUID}, alterId: 0, cipher: auto, udp: true"),
            Some("dave"),
        ),
        case(
            "vmess-cfb",
            &format!("type: vmess, users: [{{uuid: {UUID}, alterId: 0}}]"),
            &format!("type: vmess, uuid: {UUID}, alterId: 0, cipher: aes-128-cfb, udp: true"),
            None,
        ),
        case(
            "vmess-xudp",
            &format!("type: vmess, users: [{{uuid: {UUID}, alterId: 0}}]"),
            &format!(
                "type: vmess, uuid: {UUID}, alterId: 0, cipher: chacha20-poly1305, udp: true, packet-encoding: xudp"
            ),
            None,
        ),
        case(
            "vmess-zero-ws",
            &format!("type: vmess, ws-path: /ws, users: [{{uuid: {UUID}, alterId: 0}}]"),
            &format!(
                "type: vmess, uuid: {UUID}, alterId: 0, cipher: zero, udp: true, network: ws, ws-opts: {{path: /ws}}"
            ),
            None,
        ),
        case(
            "vmess-tls-grpc",
            &format!(
                "type: vmess, {tls}, grpc-service-name: gun, users: [{{uuid: {UUID}, alterId: 0}}]"
            ),
            &format!(
                "type: vmess, uuid: {UUID}, alterId: 0, cipher: aes-128-gcm, udp: true, tls: true, {trust}, network: grpc, grpc-opts: {{grpc-service-name: gun}}"
            ),
            None,
        ),
        case(
            "vless",
            &format!(
                "type: vless, allow-insecure: true, users: [{{username: erin, uuid: {UUID}}}]"
            ),
            &format!("type: vless, uuid: {UUID}, udp: true"),
            Some("erin"),
        ),
        case(
            "vless-packetaddr",
            &format!("type: vless, allow-insecure: true, users: [{{uuid: {UUID}}}]"),
            &format!("type: vless, uuid: {UUID}, udp: true, packet-encoding: packetaddr"),
            None,
        ),
        case(
            "vless-tls-ws",
            &format!("type: vless, {tls}, ws-path: /v, users: [{{uuid: {UUID}}}]"),
            &format!(
                "type: vless, uuid: {UUID}, udp: true, tls: true, {trust}, network: ws, ws-opts: {{path: /v}}"
            ),
            None,
        ),
        case(
            "vless-grpc",
            &format!(
                "type: vless, allow-insecure: true, grpc-service-name: vg, users: [{{uuid: {UUID}}}]"
            ),
            &format!(
                "type: vless, uuid: {UUID}, udp: true, network: grpc, grpc-opts: {{grpc-service-name: vg}}"
            ),
            None,
        ),
        case(
            "trojan",
            &format!("type: trojan, {tls}, users: [{{username: frank, password: pw}}]"),
            "type: trojan, password: pw, udp: true, sni: localhost, skip-cert-verify: true",
            Some("frank"),
        ),
        case(
            "trojan-grpc",
            &format!("type: trojan, {tls}, grpc-service-name: tg, users: [{{password: pw}}]"),
            "type: trojan, password: pw, udp: true, sni: localhost, skip-cert-verify: true, network: grpc, grpc-opts: {grpc-service-name: tg}",
            None,
        ),
    ];
    all.push(Case {
        udp: false,
        ..case(
            "socks-users",
            "type: socks, users: [{username: gina, password: pw}]",
            "type: socks5, username: gina, password: pw",
            Some("gina"),
        )
    });
    match std::env::var("CONCORD_CASE") {
        Ok(only) => all
            .into_iter()
            .filter(|case| only.split(',').any(|name| name == case.name))
            .collect(),
        Err(_) => all,
    }
}

struct Mihomo {
    child: Child,
    log: PathBuf,
}

impl Drop for Mihomo {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Mihomo {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

fn start_mihomo(binary: &str, dir: &Path, cases: &[Case], ports: &[(u16, u16)]) -> Mihomo {
    let mut config = format!(
        "log-level: {}\nipv6: false\nproxies:\n",
        std::env::var("CONCORD_MIHOMO_LOG").unwrap_or_else(|_| "info".to_owned())
    );
    for (case, (server, _)) in cases.iter().zip(ports) {
        let _ = writeln!(
            config,
            "  - {{name: {}, server: 127.0.0.1, port: {server}, {}}}",
            case.name, case.client
        );
    }
    config.push_str("listeners:\n");
    for (case, (_, client)) in cases.iter().zip(ports) {
        let _ = writeln!(
            config,
            "  - {{name: in-{}, type: mixed, listen: 127.0.0.1, port: {client}, udp: true, proxy: {}}}",
            case.name, case.name
        );
    }
    config.push_str("rules:\n  - MATCH,DIRECT\n");
    std::fs::write(dir.join("config.yaml"), config).unwrap();
    let log = dir.join("mihomo.log");
    let out = std::fs::File::create(&log).unwrap();
    let child = Command::new(binary)
        .env("DISABLE_LOOPBACK_DETECTOR", "true")
        .arg("-d")
        .arg(dir)
        .arg("-f")
        .arg(dir.join("config.yaml"))
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .unwrap();
    Mihomo { child, log }
}

/// Every port, since mihomo opens its listeners in map order, which Go randomises.
async fn wait_listening(mihomo: &mut Mihomo, ports: impl Iterator<Item = u16>) {
    for port in ports {
        let mut listening = false;
        for _ in 0..300 {
            if let Ok(Some(status)) = mihomo.child.try_wait() {
                panic!("mihomo exited early ({status}):\n{}", mihomo.log());
            }
            if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
            {
                listening = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            listening,
            "mihomo never listened on {port}:\n{}",
            mihomo.log()
        );
    }
}

/// What the engine logs at warning level and above: a listener that cannot be built or
/// bound is logged only, as mihomo logs it, and the cases would then fail with no reason.
#[derive(Clone, Default)]
struct Logged(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logged {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logged {
    fn install() -> Logged {
        let logged = Logged::default();
        let writer = logged.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        logged
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn write_certificate(home: &Path) {
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(home.join("server.crt"), made.cert.pem()).unwrap();
    std::fs::write(home.join("server.key"), made.signing_key.serialize_pem()).unwrap();
}

async fn start_concord(home: &Path, cases: &[Case], ports: &[(u16, u16)]) -> Arc<Engine> {
    let mut config = format!("mixed-port: {}\nlisteners:\n", port_to_bind_later());
    for (case, (server, _)) in cases.iter().zip(ports) {
        let _ = writeln!(
            config,
            "  - {{name: {}, listen: 127.0.0.1, port: {server}, {}}}",
            case.name, case.server
        );
    }
    config.push_str("rules:\n  - MATCH,DIRECT\n");
    std::fs::write(home.join("config.yaml"), config).unwrap();
    let engine = Engine::new(EngineConfig {
        sink: Arc::new(Quiet),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    engine.init(home.to_str().unwrap(), 0).unwrap();
    engine
        .setup(SetupRequest {
            base: None,
            selected: BTreeMap::new(),
            options: CoreOptions::default(),
        })
        .await
        .unwrap();
    engine.start_listeners().await;
    engine
}

/// Holds the write half open: mihomo's gun conn has no `CloseWrite` (`transport/gun/gun.go:189`), so
/// a half-close would end its reply as well, whatever the server.
async fn socks_tcp(
    port: u16,
    target: SocketAddr,
    len: usize,
) -> std::io::Result<(OwnedReadHalf, OwnedWriteHalf)> {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 expected")
    };
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS reply {}", reply[1])));
    }
    let data: Vec<u8> = (0..len)
        .map(|i| u8::try_from(i * 7 % 251).unwrap_or(0))
        .collect();
    let (mut rd, mut wr) = stream.into_split();
    let sent = data.clone();
    let writer = tokio::spawn(async move { wr.write_all(&sent).await.map(|()| wr) });
    let mut got = vec![0u8; data.len()];
    rd.read_exact(&mut got).await?;
    let wr = writer.await.map_err(std::io::Error::other)??;
    if got != data {
        return Err(std::io::Error::other("the echo differs"));
    }
    Ok((rd, wr))
}

/// A SOCKS5 UDP association: the control stream that holds it, the client socket and the
/// relay to send to.
struct Association {
    _control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

async fn associate(port: u16) -> std::io::Result<Association> {
    let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    control.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    control.read_exact(&mut method).await?;
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await?;
    let relay = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    Ok(Association {
        _control: control,
        socket,
        relay,
    })
}

fn socks_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(target) = target else {
        panic!("IPv4 expected")
    };
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&target.ip().octets());
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

async fn socks_udp(port: u16, target: SocketAddr) -> std::io::Result<()> {
    let association = associate(port).await?;
    let packet = socks_packet(target, b"datagram");
    let mut buf = [0u8; 512];
    for _ in 0..5 {
        association
            .socket
            .send_to(&packet, association.relay)
            .await?;
        if let Ok(Ok((len, _))) = timeout(
            Duration::from_secs(1),
            association.socket.recv_from(&mut buf),
        )
        .await
            && buf[..len].ends_with(b"datagram")
        {
            return Ok(());
        }
    }
    Err(std::io::Error::other("no UDP echo"))
}

/// Two associations at once, which mihomo carries over one connection to the server when
/// the transport multiplexes, each to `targets` in turn: every reply must come back to the
/// association that sent its datagram.
async fn socks_udp_pair(port: u16, targets: [SocketAddr; 2]) -> std::io::Result<()> {
    let pair = [associate(port).await?, associate(port).await?];
    let mut answered = [false; 2];
    let mut buf = [0u8; 512];
    for round in 0..5u8 {
        for (index, association) in pair.iter().enumerate() {
            let payload = [b'a' + index as u8, round];
            let target = targets[(index + usize::from(round)) % 2];
            association
                .socket
                .send_to(&socks_packet(target, &payload), association.relay)
                .await?;
        }
        for (index, association) in pair.iter().enumerate() {
            while let Ok(Ok((len, _))) = timeout(
                Duration::from_millis(500),
                association.socket.recv_from(&mut buf),
            )
            .await
            {
                let Some(&[mark, _]) = buf.get(..len).and_then(|got| got.last_chunk::<2>()) else {
                    continue;
                };
                if mark != b'a' + index as u8 {
                    return Err(std::io::Error::other(format!(
                        "association {index} got the reply of association {}",
                        mark.wrapping_sub(b'a')
                    )));
                }
                answered[index] = true;
            }
        }
        if answered == [true; 2] {
            return Ok(());
        }
    }
    Err(std::io::Error::other(format!(
        "replies came back to {answered:?}"
    )))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs CONCORD_MIHOMO"]
async fn mihomo_clients_reach_every_concord_server() {
    let binary = concord_test_support::peer("CONCORD_MIHOMO");
    let cases = cases();
    let len = std::env::var("CONCORD_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256 * 1024);
    let ports: Vec<(u16, u16)> = cases
        .iter()
        .map(|_| (port_to_bind_later(), port_to_bind_later()))
        .collect();
    let home = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    write_certificate(home.path());
    let logged = Logged::install();
    let engine = start_concord(home.path(), &cases, &ports).await;
    let started = logged.text();
    assert!(
        !started.contains("ERROR") && !started.contains("is not started"),
        "a Concord listener did not start:\n{started}"
    );
    let mut mihomo = start_mihomo(&binary, client_dir.path(), &cases, &ports);
    wait_listening(&mut mihomo, ports.iter().map(|(_, client)| *client)).await;

    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    let other_udp = udp_echo().await;
    let mut failures = Vec::new();
    for (case, (_, client)) in cases.iter().zip(&ports) {
        let mut held = None;
        match timeout(PATIENCE, socks_tcp(*client, tcp, len)).await {
            Ok(Ok(halves)) => held = Some(halves),
            Ok(Err(err)) => failures.push(format!("{} tcp: {err}", case.name)),
            Err(_) => failures.push(format!("{} tcp: timed out", case.name)),
        }
        if case.udp {
            match timeout(PATIENCE, socks_udp(*client, udp)).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => failures.push(format!("{} udp: {err}", case.name)),
                Err(_) => failures.push(format!("{} udp: timed out", case.name)),
            }
            for targets in [[udp, udp], [udp, other_udp]] {
                match timeout(PATIENCE, socks_udp_pair(*client, targets)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => failures.push(format!("{} two udp: {err}", case.name)),
                    Err(_) => failures.push(format!("{} two udp: timed out", case.name)),
                }
            }
        }
        let records = engine.connections();
        let served: Vec<_> = records
            .iter()
            .filter(|record| &*record.meta.inbound.name == case.name)
            .collect();
        if served.is_empty() {
            failures.push(format!("{}: no connection came in", case.name));
        } else if served
            .iter()
            .any(|record| record.meta.inbound.user.as_deref() != case.user)
        {
            failures.push(format!("{}: the user is not {:?}", case.name, case.user));
        }
        drop(held);
    }
    engine.shutdown().await;
    assert!(
        failures.is_empty(),
        "{failures:#?}\n--- concord ---\n{}\n--- mihomo ---\n{}",
        logged.text(),
        mihomo.log()
    );
}
