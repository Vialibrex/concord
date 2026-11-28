use serde_json::{Value, json};

use super::*;
use crate::Map;
use crate::report::LoadReport;

fn maps(items: Value) -> Vec<Map> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_object().unwrap().clone())
        .collect()
}

fn load(listeners: Value) -> (InboundDefs, LoadReport) {
    let mut report = LoadReport::default();
    let defs = read(&maps(listeners), &[], "", "", &mut report).unwrap();
    (defs, report)
}

fn one(listener: Value) -> ListenerDef {
    let (defs, report) = load(json!([listener]));
    assert!(
        report.warnings.iter().all(|w| w.code != "listener_skipped"),
        "{report:?}"
    );
    defs.listeners.into_iter().next().unwrap()
}

fn error(listeners: Value) -> String {
    let mut report = LoadReport::default();
    read(&maps(listeners), &[], "", "", &mut report)
        .unwrap_err()
        .to_string()
}

fn skipped(listener: Value) -> String {
    let (defs, report) = load(json!([listener]));
    assert!(defs.listeners.is_empty());
    let warning = report
        .warnings
        .iter()
        .find(|w| w.code == "listener_skipped")
        .expect("a listener_skipped warning");
    warning.message.clone()
}

#[test]
fn the_base_follows_mihomo_defaults() {
    let def = one(json!({"name": "in", "type": "mixed", "port": "7000-7001,7005"}));
    assert_eq!(
        def.binds.addrs(),
        ["0.0.0.0:7000", "0.0.0.0:7001", "0.0.0.0:7005"]
            .map(|a| a.parse().unwrap())
            .to_vec()
    );
    let ListenerKind::Mixed(server) = def.kind else {
        panic!("mixed")
    };
    assert_eq!(server.users, ProxyUsers::Global);
    assert!(server.udp);
    assert_eq!(server.tls, None);
    let empty = one(json!({"name": "x", "type": "socks", "listen": "::1"}));
    assert_eq!(empty.binds.addrs(), vec!["[::1]:0".parse().unwrap()]);
}

#[test]
fn keys_fold_case_and_underscores_as_mihomo_decodes_them() {
    let def = one(
        json!({"Name": "in", "type": "tproxy", "port": 1, "UDP": false,
        "routing_mark": 7}),
    );
    assert_eq!(def.name, "in");
    assert_eq!(def.kind, ListenerKind::TProxy { udp: false });
    assert_eq!(def.routing_mark, 7);
}

#[test]
fn malformed_listeners_reject_the_profile() {
    assert!(error(json!([{"type": "mixed"}])).contains("has unset fields: name"));
    assert!(error(json!([{"type": "tun"}])).contains("has unset fields: name"));
    assert!(error(json!([{"name": "a"}])).contains("missing type"));
    assert!(error(json!([{"name": "a", "type": "nope"}])).contains("unsupport proxy type: nope"));
    assert!(
        error(json!([{"name": "a", "type": "http", "listen": "localhost"}])).contains("ParseAddr")
    );
    assert!(error(json!([{"name": "a", "type": "http", "port": "x"}])).contains("intRanges"));
    let duplicate = json!([{"name": "a", "type": "http"}, {"name": "a", "type": "socks"}]);
    assert!(error(duplicate).contains("listener a is the duplicate name"));
    assert!(
        error(json!([{"name": "s", "type": "shadowsocks", "cipher": "aes-128-gcm"}]))
            .contains("shadowsocks: missing password")
    );
    assert!(error(json!([{"name": "v", "type": "vmess"}])).contains("users"));
    assert!(
        error(json!([{"name": "v", "type": "vmess", "users": [{"username": "a"}]}]))
            .contains("uuid")
    );
}

#[test]
fn listeners_this_core_does_not_serve_are_skipped_with_a_warning() {
    for (listener, reason) in [
        (json!({"name": "t", "type": "tun"}), "not supported"),
        (
            json!({"name": "s", "type": "sudoku", "key": "k"}),
            "not supported",
        ),
        (
            json!({"name": "m", "type": "mieru", "users": {"u": "pw"}}),
            "not implemented yet",
        ),
        (
            json!({"name": "e", "type": "vmess", "users": [{"uuid": "u"}], "ech-key": "k"}),
            "ech-key",
        ),
        (
            json!({"name": "k", "type": "vmess", "users": [{"uuid": "u"}], "mkcp-config": {"enable": true}}),
            "mkcp-config",
        ),
        (
            json!({"name": "r", "type": "vless", "users": [{"uuid": "u"}],
            "reality-config": {"dest": "a:443", "private-key": "k", "short-id": [""], "server-names": ["a"]}}),
            "reality-config",
        ),
        (
            json!({"name": "p", "type": "vless", "users": [{"uuid": "u"}]}),
            "disallow using Vless",
        ),
        (
            json!({"name": "q", "type": "trojan", "users": [{"password": "p"}]}),
            "disallow using Trojan",
        ),
        (
            json!({"name": "s", "type": "mixed", "certificate": "c", "private-key": "k"}),
            "TLS on an HTTP or SOCKS",
        ),
    ] {
        let message = skipped(listener.clone());
        assert!(message.contains(reason), "{listener}: {message}");
    }
}

#[test]
fn only_one_security_layer_is_allowed() {
    let both = json!([{"name": "v", "type": "vmess", "users": [{"uuid": "u"}],
        "certificate": "c", "private-key": "k", "shadow-tls": {"enable": true}}]);
    assert!(error(both).contains("security modes are mutually exclusive: certificate, shadow-tls"));
    let off = one(
        json!({"name": "v", "type": "vmess", "users": [{"uuid": "u"}],
        "shadow-tls": {"enable": false}}),
    );
    assert_eq!(off.kind.type_name(), "vmess");
}

#[test]
fn proxy_users_have_three_states() {
    let server = |users: Value| match one(json!({"name": "h", "type": "http", "users": users})).kind
    {
        ListenerKind::Http(server) => server.users,
        other => panic!("{other:?}"),
    };
    assert_eq!(server(Value::Null), ProxyUsers::Global);
    assert_eq!(server(json!([])), ProxyUsers::Open);
    assert_eq!(
        server(json!([{"username": "a", "password": "b"}])),
        ProxyUsers::Own(vec![("a".into(), "b".into())])
    );
}

#[test]
fn a_vless_user_keeps_its_flow() {
    let def = one(
        json!({"name": "f", "type": "vless", "certificate": "c", "private-key": "k",
        "users": [{"uuid": "u", "flow": "xtls-rprx-vision"}, {"uuid": "w"}]}),
    );
    let ListenerKind::Vless(server) = def.kind else {
        panic!("vless")
    };
    let flows: Vec<&str> = server.users.iter().map(|user| user.flow.as_str()).collect();
    assert_eq!(flows, ["xtls-rprx-vision", ""]);
}

#[test]
fn tls_needs_both_halves_and_client_auth_needs_a_certificate() {
    let def = one(
        json!({"name": "v", "type": "vmess", "users": [{"uuid": "u"}],
        "certificate": "c", "private-key": "k", "client-auth-cert": "ca"}),
    );
    let ListenerKind::Vmess(server) = def.kind else {
        panic!("vmess")
    };
    let tls = server.tls.unwrap();
    assert_eq!(tls.client_auth, ClientAuth::RequireAndVerify);
    let (defs, report) = load(
        json!([{"name": "v", "type": "vmess", "users": [{"uuid": "u"}],
        "certificate": "c"}]),
    );
    assert_eq!(defs.listeners.len(), 1);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.message.contains("private-key"))
    );
    let message = skipped(
        json!({"name": "v", "type": "vmess", "users": [{"uuid": "u"}],
        "client-auth-type": "request"}),
    );
    assert!(message.contains("client-auth requires certificate"));
}

#[test]
fn stream_protocols_read_their_users_and_carriers() {
    let def = one(json!({"name": "v", "type": "vmess", "ws-path": "/ws",
        "users": [{"username": "a", "uuid": "u1", "alterId": 2}, {"uuid": "u2"}]}));
    let ListenerKind::Vmess(server) = def.kind else {
        panic!("vmess")
    };
    assert_eq!(server.users[0].alter_id, 2);
    assert_eq!(server.users[1].username, "");
    assert_eq!(server.carriers.ws_path.as_deref(), Some("/ws"));
    let def = one(
        json!({"name": "t", "type": "trojan", "allow-insecure": true,
        "grpc-service-name": "g", "users": [{"username": "a", "password": "p"}]}),
    );
    let ListenerKind::Trojan(server) = def.kind else {
        panic!("trojan")
    };
    assert_eq!(server.users[0].password, "p");
    assert_eq!(server.carriers.grpc_service_name.as_deref(), Some("g"));
    let def = one(
        json!({"name": "s", "type": "shadowsocks", "cipher": "2022-blake3-aes-128-gcm",
        "password": "ipsk", "users": {"alice": "upsk"}, "udp": false}),
    );
    let ListenerKind::Shadowsocks(server) = def.kind else {
        panic!("ss")
    };
    assert_eq!(server.users.get("alice").map(String::as_str), Some("upsk"));
    assert!(!server.udp);
}

#[test]
fn tunnel_listeners_warn_on_unknown_networks() {
    let (defs, report) = load(json!([{"name": "t", "type": "tunnel", "port": 53,
        "network": ["udp", "sctp"], "target": "1.1.1.1:53", "proxy": "DIRECT"}]));
    let def = &defs.listeners[0];
    assert_eq!(def.proxy.as_deref(), Some("DIRECT"));
    assert_eq!(
        def.kind,
        ListenerKind::Tunnel {
            networks: Networks {
                tcp: false,
                udp: true
            },
            target: "1.1.1.1:53".into(),
        }
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.message.contains("unknown network type sctp"))
    );
}

#[test]
fn ss_config_and_vmess_config_become_default_listeners() {
    let mut report = LoadReport::default();
    let defs = read(
        &[],
        &[json!("tcp,:6553,1.1.1.1:53")],
        "ss://2022-blake3-aes-256-gcm:vlmpIPSy+/w==@:23456,[::1]:23457",
        "vmess://1:9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68@:12345",
        &mut report,
    )
    .unwrap();
    let [ss, vmess] = defs.listeners.as_slice() else {
        panic!("{defs:?}")
    };
    assert_eq!(ss.name, "DEFAULT-SHADOWSOCKS");
    assert_eq!(
        ss.binds.addrs(),
        ["0.0.0.0:23456", "[::1]:23457"]
            .map(|a| a.parse().unwrap())
            .to_vec()
    );
    let ListenerKind::Shadowsocks(server) = &ss.kind else {
        panic!("ss")
    };
    assert_eq!(server.password, "vlmpIPSy+/w==");
    assert!(server.udp);
    let ListenerKind::Vmess(server) = &vmess.kind else {
        panic!("vmess")
    };
    assert_eq!(server.users[0].alter_id, 1);
    assert_eq!(server.users[0].username, "1");
    assert_eq!(defs.tunnels.len(), 1);
    assert_eq!(ss.default_of, Some("ss-config"));
    let mut report = LoadReport::default();
    let defs = read(&[], &[], "ss-no-at", "", &mut report).unwrap();
    assert!(defs.listeners.is_empty());
    assert!(report.warnings.iter().any(|w| w.path == "ss-config"));
}

#[test]
fn a_default_listener_url_is_percent_decoded() {
    let mut report = LoadReport::default();
    let defs = read(
        &[],
        &[],
        "ss://aes-128-gcm:p%40ss%2Fw@:23456",
        "",
        &mut report,
    )
    .unwrap();
    let ListenerKind::Shadowsocks(server) = &defs.listeners[0].kind else {
        panic!("{defs:?}")
    };
    assert_eq!(server.password, "p@ss/w");
    let mut report = LoadReport::default();
    let defs = read(&[], &[], "ss://aes-128-gcm:p%zz@:23456", "", &mut report).unwrap();
    assert!(defs.listeners.is_empty());
}

#[test]
fn a_listener_named_like_a_default_one_is_its_own() {
    let mut report = LoadReport::default();
    let listeners =
        maps(json!([{"name": "DEFAULT-VMESS", "type": "vmess", "users": [{"uuid": "u"}]}]));
    let defs = read(
        &listeners,
        &[],
        "",
        "vmess://1:9d0cb9d0-964f-4ef6-897d-6c6b3ccf9e68@:12345",
        &mut report,
    )
    .unwrap();
    let defaults: Vec<_> = defs.listeners.iter().map(|def| def.default_of).collect();
    assert_eq!(defaults, [None, Some("vmess-config")]);
}

#[test]
fn a_tunnel_line_ending_in_an_empty_proxy_has_none() {
    let mut report = LoadReport::default();
    let defs = read(&[], &[json!("tcp,:6553,1.1.1.1:53,")], "", "", &mut report).unwrap();
    assert_eq!(defs.tunnels[0].proxy, None);
}

#[test]
fn a_tuic_listener_reads_tokens_users_and_its_own_certificate() {
    let def = one(json!({
        "name": "in", "type": "tuic", "port": 443,
        "token": ["t"], "users": {"b831381d-6324-4d53-ad4f-8cda48b30811": "pw"},
        "congestion-controller": "bbr", "bbr-profile": "aggressive", "max-idle-time": 20000,
    }));
    let ListenerKind::Tuic(server) = def.kind else {
        panic!("tuic")
    };
    assert_eq!(server.tokens, ["t"]);
    assert_eq!(server.users["b831381d-6324-4d53-ad4f-8cda48b30811"], "pw");
    assert!(server.tls.certificate.is_empty() && server.tls.private_key.is_empty());
    assert_eq!(
        (server.congestion.as_str(), server.bbr_profile.as_str()),
        ("bbr", "aggressive")
    );
    assert_eq!((server.max_idle_ms, server.auth_timeout_ms), (20000, 0));
    assert!(
        skipped(json!({"name": "in", "type": "tuic", "port": 443, "ech-key": "k"}))
            .contains("ech-key")
    );
}

#[test]
fn a_hysteria2_listener_reads_users_rates_obfs_and_windows() {
    let (defs, report) = load(json!([{
        "name": "in", "type": "hysteria2", "port": 443,
        "users": {"alice": "pw"}, "up": "30 Mbps", "down": "100",
        "ignore-client-bandwidth": true, "obfs": "salamander", "obfs-password": "salt",
        "udp-mtu": 1400, "cwnd": 16, "max-stream-receive-window": 1024,
        "masquerade": "https://example.com",
    }]));
    let [def] = defs.listeners.as_slice() else {
        panic!("one listener: {report:?}")
    };
    let ListenerKind::Hysteria2(server) = &def.kind else {
        panic!("hysteria2")
    };
    assert_eq!(server.users["alice"], "pw");
    assert_eq!(
        (server.up.as_str(), server.down.as_str()),
        ("30 Mbps", "100")
    );
    assert!(server.ignore_client_bandwidth);
    assert_eq!(server.salamander.as_deref(), Some("salt"));
    assert_eq!((server.udp_mtu, server.cwnd), (1400, 16));
    assert_eq!(
        (server.initial_stream_window, server.max_stream_window),
        (0, 1024)
    );
    assert!(server.tls.certificate.is_empty() && server.tls.private_key.is_empty());
    assert_eq!(
        server.masquerade,
        Some(Masquerade::Proxy("https://example.com".parse().unwrap()))
    );
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.message.contains("masquerade")),
        "{report:?}"
    );
}

#[test]
fn a_hysteria2_listener_this_batch_cannot_serve_is_skipped() {
    for (listener, reason) in [
        (json!({"obfs": "gecko", "obfs-password": "p"}), "gecko"),
        (json!({"obfs": "salamander"}), "missing obfs password"),
        (
            json!({"obfs": "other", "obfs-password": "p"}),
            "unknown obfs type",
        ),
        (json!({"realm-opts": {"enable": true}}), "realm-opts"),
    ] {
        let mut listener = listener;
        let fields = listener.as_object_mut().unwrap();
        fields.insert("name".into(), json!("in"));
        fields.insert("type".into(), json!("hysteria2"));
        fields.insert("port".into(), json!(443));
        let message = skipped(listener);
        assert!(message.contains(reason), "{message}");
    }
    let def = one(json!({
        "name": "in", "type": "hysteria2", "port": 443, "realm-opts": {"enable": false},
    }));
    assert!(matches!(def.kind, ListenerKind::Hysteria2(_)));
}

fn general(tuic: Value) -> (InboundDefs, LoadReport) {
    let mut report = LoadReport::default();
    let general = json!({ "tuic-server": tuic });
    let defs = from_general(general.as_object().unwrap(), &mut report).unwrap();
    (defs, report)
}

#[test]
fn tuic_server_becomes_a_default_listener_on_each_address() {
    let (defs, _) = general(json!({
        "enable": true, "listen": "127.0.0.1:10443,:10444",
        "users": {"b831381d-6324-4d53-ad4f-8cda48b30811": "pw"},
        "client-auth-type": "require-any", "bbr-profile": "aggressive",
    }));
    let [def] = defs.listeners.as_slice() else {
        panic!("one listener: {:?}", defs.listeners)
    };
    assert_eq!(
        (def.name.as_str(), def.default_of),
        ("DEFAULT-TUIC", Some("tuic-server"))
    );
    assert_eq!(
        def.binds.addrs(),
        ["127.0.0.1:10443", "0.0.0.0:10444"]
            .map(|a| a.parse().unwrap())
            .to_vec()
    );
    let ListenerKind::Tuic(server) = &def.kind else {
        panic!("tuic")
    };
    assert_eq!(server.tls.client_auth, ClientAuth::None);
    assert!(server.bbr_profile.is_empty());

    let (defs, _) = general(json!({"enable": false, "listen": ":10443"}));
    assert!(defs.listeners.is_empty());
    let (defs, report) = general(json!({"enable": true, "listen": "nowhere"}));
    assert!(defs.listeners.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.code == "listener_skipped" && w.path == "tuic-server")
    );
}

#[test]
fn an_anytls_listener_reads_users_padding_and_tls() {
    let (defs, report) = load(json!([{
        "name": "in", "type": "anytls", "port": 443,
        "users": {"alice": "pw"}, "padding-scheme": "stop=1\n0=10-20",
        "certificate": "c.pem", "private-key": "k.pem",
    }, {
        "name": "plain", "type": "anytls", "port": 444,
        "users": {"bob": "pw"}, "allow-insecure": true,
    }]));
    let [tls, plain] = defs.listeners.as_slice() else {
        panic!("two listeners: {report:?}")
    };
    let ListenerKind::AnyTls(server) = &tls.kind else {
        panic!("anytls")
    };
    assert_eq!(server.users["alice"], "pw");
    assert_eq!(server.padding_scheme, "stop=1\n0=10-20");
    assert!(server.tls.is_some());
    let ListenerKind::AnyTls(server) = &plain.kind else {
        panic!("anytls")
    };
    assert!(server.padding_scheme.is_empty() && server.tls.is_none());
}

#[test]
fn an_anytls_listener_without_a_security_layer_is_skipped() {
    for (listener, reason) in [
        (json!({}), "disallow using AnyTLS"),
        (json!({"shadow-tls": {"enable": true}}), "shadow-tls"),
    ] {
        let mut listener = listener;
        let fields = listener.as_object_mut().unwrap();
        fields.insert("name".into(), json!("in"));
        fields.insert("type".into(), json!("anytls"));
        fields.insert("port".into(), json!(443));
        fields.insert("users".into(), json!({"u": "pw"}));
        let message = skipped(listener);
        assert!(message.contains(reason), "{message}");
    }
}

#[test]
fn mux_option_sets_padding_and_an_enabled_brutal() {
    let vmess = |mux: Value| {
        let def = one(json!({
            "name": "v", "type": "vmess", "port": 1, "users": [{"uuid": "u"}], "mux-option": mux
        }));
        match def.kind {
            ListenerKind::Vmess(server) => server.mux,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(vmess(json!({})), MuxServer::default());
    assert_eq!(
        vmess(json!({"padding": true, "brutal": {"enabled": false, "up": "10 Mbps"}})),
        MuxServer {
            padding: true,
            brutal: None
        }
    );
    let brutal = json!({"brutal": {"enabled": true, "up": "10 Mbps", "down": "20 Mbps"}});
    if cfg!(any(target_os = "linux", target_os = "android")) {
        assert_eq!(
            vmess(brutal).brutal,
            Some(MuxBrutal {
                up: "10 Mbps".into(),
                down: "20 Mbps".into()
            })
        );
    } else {
        let reason = skipped(json!({
            "name": "v", "type": "vmess", "port": 1, "users": [{"uuid": "u"}], "mux-option": brutal
        }));
        assert!(
            reason.contains("TCP Brutal is only supported on Linux"),
            "{reason}"
        );
    }
}

#[test]
fn a_hysteria2_masquerade_takes_a_file_path_or_an_http_url_and_nothing_else() {
    let masquerade = |url: &str| {
        let (defs, report) = load(json!([{
            "name": "in", "type": "hysteria2", "port": 443, "masquerade": url,
        }]));
        let [def] = defs.listeners.as_slice() else {
            panic!("one listener: {report:?}")
        };
        let ListenerKind::Hysteria2(server) = &def.kind else {
            panic!("hysteria2")
        };
        server.masquerade.clone()
    };
    assert_eq!(
        masquerade("file:///srv/www"),
        Some(Masquerade::File("/srv/www".into()))
    );
    assert_eq!(
        masquerade("file://host/www"),
        Some(Masquerade::File("/www".into()))
    );
    assert_eq!(
        masquerade("file:///my%20site?x#y"),
        Some(Masquerade::File("/my site".into()))
    );
    assert_eq!(
        masquerade("http://127.0.0.1:8080/base?x=1"),
        Some(Masquerade::Proxy(
            "http://127.0.0.1:8080/base?x=1".parse().unwrap()
        ))
    );
    assert_eq!(masquerade(""), None);
    let refused = |url: &str| {
        skipped(json!({"name": "in", "type": "hysteria2", "port": 443, "masquerade": url}))
    };
    assert!(refused("ftp://example.com").contains("unknown masquerade URL scheme: ftp"));
    assert!(refused("example.com").contains("unknown masquerade URL scheme"));
    assert!(refused("https://").contains("parse masquerade URL"));
    assert!(refused("file:site").contains("names no directory"));
}
