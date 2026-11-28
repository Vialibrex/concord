use super::*;

async fn closed(port: u16) -> bool {
    TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .is_err()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_listeners_and_tunnels_open_and_close_with_the_listeners() {
    let echo = tcp_echo().await;
    let (side, tunnel) = (port_to_bind_later(), port_to_bind_later());
    let rig = Rig::new();
    rig.apply(&format!(
        "listeners:\n  - {{name: side, type: mixed, listen: 127.0.0.1, port: {side}}}\ntunnels:\n  - tcp,127.0.0.1:{tunnel},{echo}\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    assert!(
        closed(side).await && closed(tunnel).await,
        "a config alone opens no port"
    );

    rig.engine.start_listeners().await;
    let mut through_side = socks_connect(side, echo).await.unwrap();
    round_trip(&mut through_side).await;
    let mut through_tunnel = TcpStream::connect((Ipv4Addr::LOCALHOST, tunnel))
        .await
        .unwrap();
    round_trip(&mut through_tunnel).await;

    rig.engine.stop_listeners().await;
    assert!(
        closed(side).await && closed(tunnel).await,
        "stop left a profile inbound open"
    );
    rig.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_routes_by_its_proxy_and_by_its_name() {
    let echo = tcp_echo().await;
    let (upstream, seen) = upstream_socks().await;
    let (pinned, named) = (port_to_bind_later(), port_to_bind_later());
    let rig = Rig::new();
    rig.apply(&format!(
        "proxies:\n  - {{name: up, type: socks5, server: 127.0.0.1, port: {upstream}}}\nlisteners:\n  - {{name: pinned, type: socks, listen: 127.0.0.1, port: {pinned}, proxy: up}}\n  - {{name: named, type: socks, listen: 127.0.0.1, port: {named}}}\nrules:\n  - IN-NAME,named,REJECT\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    rig.engine.start_listeners().await;

    let mut pinned_stream = socks_connect(pinned, echo).await.unwrap();
    round_trip(&mut pinned_stream).await;
    assert_eq!(*lock(&seen), vec![echo.to_string()]);
    assert!(refused(named, echo).await);
    let mut default = socks_connect(rig.mixed, echo).await.unwrap();
    round_trip(&mut default).await;

    let records = rig.engine.connections();
    let record = records
        .iter()
        .find(|record| &*record.meta.inbound.name == "pinned")
        .expect("the pinned listener's connection is listed");
    assert_eq!(record.meta.special_proxy, "up");
    rig.engine.shutdown().await;
}

#[cfg(feature = "server")]
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

#[cfg(feature = "server")]
fn protocol_cases(port: u16) -> Vec<(String, String, Option<&'static str>)> {
    let ss = |cipher: &str, server: &str, users: &str, client: &str| {
        (
            format!(
                "{{name: in, type: shadowsocks, listen: 127.0.0.1, port: {port}, cipher: {cipher}, password: '{server}'{users}}}"
            ),
            format!(
                "{{name: out, type: ss, server: 127.0.0.1, port: {port}, cipher: {cipher}, password: '{client}', udp: true}}"
            ),
        )
    };
    let key = "AAECAwQFBgcICQoLDA0ODw==";
    let user_key = "EBESExQVFhcYGRobHB0eHw==";
    let mut cases = Vec::new();
    let (listener, client) = ss("aes-128-gcm", "secret", "", "secret");
    cases.push((listener, client, None));
    let (listener, client) = ss("aes-256-gcm", "", ", users: {alice: one, bob: two}", "two");
    cases.push((listener, client, Some("bob")));
    let (listener, client) = ss("2022-blake3-aes-128-gcm", key, "", key);
    cases.push((listener, client, None));
    let (listener, client) = ss(
        "2022-blake3-aes-128-gcm",
        key,
        &format!(", users: {{carol: '{user_key}'}}"),
        &format!("{key}:{user_key}"),
    );
    cases.push((listener, client, Some("carol")));
    cases.push((
        format!("{{name: in, type: vmess, listen: 127.0.0.1, port: {port}, users: [{{username: dave, uuid: {UUID}, alterId: 0}}]}}"),
        format!("{{name: out, type: vmess, server: 127.0.0.1, port: {port}, uuid: {UUID}, alterId: 0, cipher: auto, udp: true}}"),
        Some("dave"),
    ));
    cases.push((
        format!("{{name: in, type: vmess, listen: 127.0.0.1, port: {port}, ws-path: /ws, users: [{{uuid: {UUID}, alterId: 0}}]}}"),
        format!("{{name: out, type: vmess, server: 127.0.0.1, port: {port}, uuid: {UUID}, alterId: 0, cipher: aes-128-gcm, udp: true, network: ws, ws-opts: {{path: /ws}}}}"),
        None,
    ));
    cases.push((
        format!("{{name: in, type: vless, listen: 127.0.0.1, port: {port}, allow-insecure: true, users: [{{username: erin, uuid: {UUID}}}]}}"),
        format!("{{name: out, type: vless, server: 127.0.0.1, port: {port}, uuid: {UUID}, udp: true}}"),
        Some("erin"),
    ));
    cases.push((
        format!("{{name: in, type: vless, listen: 127.0.0.1, port: {port}, allow-insecure: true, grpc-service-name: gun, users: [{{uuid: {UUID}}}]}}"),
        format!("{{name: out, type: vless, server: 127.0.0.1, port: {port}, uuid: {UUID}, udp: true, network: grpc, grpc-opts: {{grpc-service-name: gun}}}}"),
        None,
    ));
    let tuic = format!(
        "name: out, type: tuic, server: 127.0.0.1, port: {port}, skip-cert-verify: true, udp: true"
    );
    for mode in ["native", "quic"] {
        cases.push((
            format!("{{name: in, type: tuic, listen: 127.0.0.1, port: {port}, users: {{{UUID}: secret}}}}"),
            format!("{{{tuic}, uuid: {UUID}, password: secret, udp-relay-mode: {mode}}}"),
            Some(UUID),
        ));
    }
    cases.push((
        format!("{{name: in, type: tuic, listen: 127.0.0.1, port: {port}, token: [secret]}}"),
        format!("{{{tuic}, token: secret}}"),
        None,
    ));
    let hy2 = format!(
        "name: out, type: hysteria2, server: 127.0.0.1, port: {port}, password: secret, skip-cert-verify: true"
    );
    for obfs in ["", ", obfs: salamander, obfs-password: salt"] {
        cases.push((
            format!("{{name: in, type: hysteria2, listen: 127.0.0.1, port: {port}, users: {{alice: secret}}{obfs}}}"),
            format!("{{{hy2}{obfs}}}"),
            Some("alice"),
        ));
    }
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    cases.push((
        format!(
            "{{name: in, type: anytls, listen: 127.0.0.1, port: {port}, users: {{alice: secret}}, certificate: {:?}, private-key: {:?}}}",
            made.cert.pem(),
            made.signing_key.serialize_pem()
        ),
        format!("{{name: out, type: anytls, server: 127.0.0.1, port: {port}, password: secret, skip-cert-verify: true, udp: true}}"),
        Some("alice"),
    ));
    cases.push((
        format!(
            "{{name: in, type: vless, listen: 127.0.0.1, port: {port}, certificate: {:?}, private-key: {:?}, users: [{{username: erin, uuid: {UUID}, flow: xtls-rprx-vision}}]}}",
            made.cert.pem(),
            made.signing_key.serialize_pem()
        ),
        format!("{{name: out, type: vless, server: 127.0.0.1, port: {port}, uuid: {UUID}, flow: xtls-rprx-vision, tls: true, skip-cert-verify: true, udp: true}}"),
        Some("erin"),
    ));
    cases
}

#[cfg(feature = "server")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_listeners_serve_concord_clients_over_tcp_and_udp() {
    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    for (listener, client, user) in protocol_cases(port_to_bind_later()) {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            serves_a_concord_client(&listener, &client, [user, user], tcp, udp),
        )
        .await
        .unwrap_or_else(|_| panic!("{listener}: timed out"));
    }
}

#[cfg(feature = "server")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shadow_tls_listeners_serve_concord_clients_past_a_real_handshake() {
    let tcp = tcp_echo().await;
    let udp = udp_echo().await;
    let (decoy, _, _) = tls13_echo().await;
    let port = port_to_bind_later();
    let handshake = format!("handshake: {{dest: '{decoy}', proxy: DIRECT}}");
    let v3 = format!(
        "shadow-tls: {{enable: true, version: 3, users: [{{name: sam, password: one}}], {handshake}}}"
    );
    let decoy_tls = "sni: inner.test, servername: inner.test, skip-cert-verify: true";
    let cases = [
        (
            format!(
                "{{name: in, type: trojan, listen: 127.0.0.1, port: {port}, users: [{{username: tina, password: secret}}], {v3}}}"
            ),
            format!(
                "{{name: out, type: trojan, server: 127.0.0.1, port: {port}, password: secret, {decoy_tls}, udp: true, shadow-tls-opts: {{password: one, version: 3}}}}"
            ),
            [Some("tina"); 2],
        ),
        (
            format!(
                "{{name: in, type: shadowsocks, listen: 127.0.0.1, port: {port}, cipher: aes-128-gcm, password: secret, {v3}}}"
            ),
            format!(
                "{{name: out, type: ss, server: 127.0.0.1, port: {port}, cipher: aes-128-gcm, password: secret, udp: true, plugin: shadow-tls, plugin-opts: {{host: inner.test, password: one, version: 3, skip-cert-verify: true}}}}"
            ),
            // The listener's UDP socket has no ShadowTLS in front, so no user signs it.
            [Some("sam"), None],
        ),
        (
            format!(
                "{{name: in, type: vmess, listen: 127.0.0.1, port: {port}, ws-path: /ws, users: [{{uuid: {UUID}, alterId: 0}}], shadow-tls: {{enable: true, version: 2, password: pw, {handshake}}}}}"
            ),
            format!(
                "{{name: out, type: vmess, server: 127.0.0.1, port: {port}, uuid: {UUID}, alterId: 0, cipher: auto, udp: true, tls: true, {decoy_tls}, network: ws, ws-opts: {{path: /ws}}, shadow-tls-opts: {{password: pw, version: 2}}}}"
            ),
            [None; 2],
        ),
    ];
    for (listener, client, users) in cases {
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            serves_a_concord_client(&listener, &client, users, tcp, udp),
        )
        .await
        .unwrap_or_else(|_| panic!("{listener}: timed out"));
    }
}

#[cfg(feature = "server")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shadow_tls_handshake_that_comes_back_to_its_listener_goes_no_further() {
    let port = port_to_bind_later();
    let rig = Rig::new();
    rig.apply(&format!(
        "listeners:\n  - {{name: in, type: trojan, listen: 127.0.0.1, port: {port}, users: [{{username: tina, password: secret}}], shadow-tls: {{enable: true, version: 3, users: [{{name: sam, password: one}}], handshake: {{dest: '127.0.0.1:{port}', proxy: DIRECT}}}}}}\nrules:\n  - MATCH,DIRECT\n"
    ))
    .await
    .unwrap();
    rig.engine.start_listeners().await;
    let hello = client_hello("loop.test");
    let mut stranger = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    stranger.write_all(&hello).await.unwrap();
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(10), stranger.read_to_end(&mut rest))
        .await
        .expect("the stranger is still held");
    let (up, _) = rig.engine.traffic_total(false);
    let hello = i64::try_from(hello.len()).unwrap();
    assert!(up <= 2 * hello, "the hello went round {} times", up / hello);
    rig.engine.shutdown().await;
}

#[cfg(feature = "server")]
fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let u16_of = |n: usize| u16::try_from(n).unwrap().to_be_bytes();
    let mut extension = vec![0, 0];
    extension.extend(u16_of(name.len() + 5));
    extension.extend(u16_of(name.len() + 3));
    extension.push(0);
    extension.extend(u16_of(name.len()));
    extension.extend(name);
    let mut body = vec![3, 3];
    body.extend([7; 32]);
    body.push(32);
    body.extend([9; 32]);
    body.extend([0, 2, 0x13, 0x01, 1, 0]);
    body.extend(u16_of(extension.len()));
    body.extend(extension);
    let mut record = vec![22, 3, 1];
    record.extend(u16_of(body.len() + 4));
    record.push(1);
    record.extend(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
    record.extend(body);
    record
}

/// `users` are the users of the TCP flows, then of the UDP ones.
#[cfg(feature = "server")]
async fn serves_a_concord_client(
    listener: &str,
    client: &str,
    users: [Option<&str>; 2],
    tcp: std::net::SocketAddr,
    udp: std::net::SocketAddr,
) {
    let rig = Rig::new();
    rig.apply(&format!(
        "proxies:\n  - {client}\nlisteners:\n  - {listener}\nrules:\n  - IN-NAME,in,DIRECT\n  - MATCH,out\n"
    ))
    .await
    .unwrap_or_else(|err| panic!("{listener}: {err:?}"));
    rig.engine.start_listeners().await;

    let mut stream = socks_connect(rig.mixed, tcp).await.unwrap();
    round_trip(&mut stream).await;
    let session = associate(rig.mixed).await;
    assert!(session.echoes(udp).await, "{listener}: no UDP echo");

    let served = rig
        .engine
        .connections()
        .into_iter()
        .filter(|record| &*record.meta.inbound.name == "in")
        .collect::<Vec<_>>();
    assert!(!served.is_empty(), "{listener}: nothing came in");
    assert!(
        served.iter().all(|record| {
            let user = match record.meta.network {
                concord_common::Network::Tcp => users[0],
                concord_common::Network::Udp => users[1],
            };
            record.meta.inbound.user.as_deref() == user
        }),
        "{listener}: wrong user"
    );
    rig.engine.shutdown().await;
}

#[cfg(feature = "server")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_quic_listener_whose_obfuscation_changes_serves_the_new_key_after_a_reload() {
    let tcp = tcp_echo().await;
    let port = port_to_bind_later();
    let rig = Rig::new();
    let profile = |salt: &str| {
        format!(
            "proxies:\n  - {{name: out, type: hysteria2, server: 127.0.0.1, port: {port}, password: secret, skip-cert-verify: true, obfs: salamander, obfs-password: {salt}}}\nlisteners:\n  - {{name: in, type: hysteria2, listen: 127.0.0.1, port: {port}, users: {{alice: secret}}, obfs: salamander, obfs-password: {salt}}}\nrules:\n  - IN-NAME,in,DIRECT\n  - MATCH,out\n"
        )
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        rig.apply(&profile("first")).await.unwrap();
        rig.engine.start_listeners().await;
        let mut open = socks_connect(rig.mixed, tcp).await.unwrap();
        round_trip(&mut open).await;

        rig.apply(&profile("second")).await.unwrap();
        let mut stream = socks_connect(rig.mixed, tcp).await.unwrap();
        round_trip(&mut stream).await;
        drop(open);
    })
    .await
    .expect("the reloaded listener serves the new key");
    rig.engine.shutdown().await;
}

/// A TLS 1.3 echo server, so that a Vision flow to it hands both directions to the socket,
/// and the records it read and wrote.
#[cfg(feature = "server")]
async fn tls13_echo() -> (
    SocketAddr,
    rustls_pki_types::CertificateDer<'static>,
    concord_test_support::tap::Seen,
) {
    let made = rcgen::generate_simple_self_signed(vec!["inner.test".to_owned()]).unwrap();
    let key = rustls_pki_types::PrivateKeyDer::try_from(made.signing_key.serialize_der()).unwrap();
    let config = tokio_rustls::rustls::ServerConfig::builder_with_protocol_versions(&[
        &tokio_rustls::rustls::version::TLS13,
    ])
    .with_no_client_auth()
    .with_single_cert(vec![made.cert.der().clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = concord_test_support::tap::Seen::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let stream = concord_test_support::tap::Recorded::new(stream, &kept);
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let (mut read, mut write) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut read, &mut write).await;
                let _ = write.shutdown().await;
            });
        }
    });
    (addr, made.cert.der().clone(), seen)
}

#[cfg(feature = "server")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_vision_listener_carries_an_inner_tls13_connection_both_ways() {
    let (echo, inner, echoed) = tls13_echo().await;
    let port = port_to_bind_later();
    let (relay, outer) =
        concord_test_support::tap::tap(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await;
    let relay = relay.port();
    let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let rig = Rig::new();
    rig.apply(&format!(
        "proxies:\n  - {{name: out, type: vless, server: 127.0.0.1, port: {relay}, uuid: {UUID}, flow: xtls-rprx-vision, tls: true, skip-cert-verify: true}}\nlisteners:\n  - {{name: in, type: vless, listen: 127.0.0.1, port: {port}, certificate: {:?}, private-key: {:?}, users: [{{username: erin, uuid: {UUID}, flow: xtls-rprx-vision}}]}}\nrules:\n  - IN-NAME,in,DIRECT\n  - MATCH,out\n",
        made.cert.pem(),
        made.signing_key.serialize_pem()
    ))
    .await
    .unwrap();
    rig.engine.start_listeners().await;

    let stream = socks_connect(rig.mixed, echo).await.unwrap();
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.add(inner).unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let name = rustls_pki_types::ServerName::try_from("inner.test").unwrap();
    let secured = timeout(Duration::from_secs(10), tls.connect(name, stream))
        .await
        .expect("the inner handshake stalled")
        .unwrap();
    let (mut read, mut write) = tokio::io::split(secured);
    let sent: Vec<u8> = (0..1u32 << 20).map(|i| (i % 251) as u8).collect();
    let sending = {
        let sent = sent.clone();
        tokio::spawn(async move {
            write.write_all(&sent).await.unwrap();
            write.flush().await.unwrap();
            write
        })
    };
    let mut got = vec![0u8; sent.len()];
    timeout(Duration::from_secs(20), read.read_exact(&mut got))
        .await
        .expect("the echo stalled")
        .unwrap();
    assert!(got == sent, "the echo differs from what was sent");
    drop(sending.await.unwrap());
    let middle = |bytes: Vec<u8>| bytes[bytes.len() / 2..][..1024].to_vec();
    assert!(
        concord_test_support::tap::carries(&outer.read(), &middle(echoed.read())),
        "the client's inner records were not sent to the socket as they are"
    );
    assert!(
        concord_test_support::tap::carries(&outer.written(), &middle(echoed.written())),
        "the server's inner records were not sent to the socket as they are"
    );
    let served = rig
        .engine
        .connections()
        .into_iter()
        .filter(|record| &*record.meta.inbound.name == "in")
        .collect::<Vec<_>>();
    assert!(
        served
            .iter()
            .any(|record| record.meta.inbound.user.as_deref() == Some("erin"))
    );
    rig.engine.shutdown().await;
}
