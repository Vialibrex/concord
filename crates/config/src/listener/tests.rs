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
            json!({"name": "h", "type": "hysteria2", "certificate": "", "private-key": ""}),
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
            json!({"name": "f", "type": "vless", "users": [{"uuid": "u", "flow": "xtls-rprx-vision"}]}),
            "xtls-rprx-vision",
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
