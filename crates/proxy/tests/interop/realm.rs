//! `hysteria2` realm-opts against mihomo's own realm control server and a hysteria2 server that
//! registers with it. A STUN responder runs in the test, so both ends learn their loopback
//! address and punch toward each other on 127.0.0.1.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::UdpSocket;

use super::{Case, Certs, Udp, listener, merge, port_to_bind_later, tls_lines};

pub const TOKEN: &str = "realm-token";

fn ports() -> &'static (u16, u16) {
    static PORTS: OnceLock<(u16, u16)> = OnceLock::new();
    PORTS.get_or_init(|| (port_to_bind_later(), port_to_bind_later()))
}

pub fn stun_port() -> u16 {
    ports().0
}

fn control_port() -> u16 {
    ports().1
}

fn realm_opts(id: &str) -> Value {
    json!({
        "enable": true,
        "server-url": format!("https://127.0.0.1:{}", control_port()),
        "token": TOKEN,
        "realm-id": id,
        "stun-servers": [format!("127.0.0.1:{}", stun_port())],
        "skip-cert-verify": true,
    })
}

fn server_realm_lines(id: &str) -> String {
    format!(
        "    realm-opts:\n      enable: true\n      server-url: https://127.0.0.1:{}\n      token: {TOKEN}\n      realm-id: {id}\n      stun-servers:\n        - 127.0.0.1:{}\n      skip-cert-verify: true\n",
        control_port(),
        stun_port()
    )
}

fn realm_case(
    name: &str,
    id: &str,
    server_extra: &str,
    client_extra: Value,
    certs: &Certs,
) -> Case {
    let port = port_to_bind_later();
    let body = format!(
        "    users:\n      user: hy2-pw\n{}{}{server_extra}",
        tls_lines(certs),
        server_realm_lines(id)
    );
    let client = merge(
        json!({
            "name": name, "type": "hysteria2", "server": "127.0.0.1", "port": 9, "udp": true,
            "password": "hy2-pw", "sni": "localhost", "skip-cert-verify": true,
            "realm-opts": realm_opts(id),
        }),
        client_extra,
    );
    Case {
        name: name.to_string(),
        listener: listener(name, "hysteria2", port, &body),
        proxy: client,
        udp: Udp::Many,
    }
}

pub fn cases(certs: &Certs) -> Vec<Case> {
    let control = format!(
        "    token: {TOKEN}\n{}    max-realms-per-ip: 16\n",
        tls_lines(certs)
    );
    vec![
        Case {
            name: "realm-control".to_string(),
            listener: listener("realm-control", "hysteria2-realm", control_port(), &control),
            proxy: Value::Null,
            udp: Udp::No,
        },
        realm_case("hy2-realm", "plain", "", json!({}), certs),
        realm_case(
            "hy2-realm-salamander",
            "salted",
            "    obfs: salamander\n    obfs-password: salt-pw\n",
            json!({"obfs": "salamander", "obfs-password": "salt-pw"}),
            certs,
        ),
    ]
}

pub async fn stun_server() -> tokio::task::JoinHandle<()> {
    let socket = UdpSocket::bind(("127.0.0.1", stun_port())).await.unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((read, from)) = socket.recv_from(&mut buf).await {
            if let Some(reply) = binding_response(&buf[..read], from) {
                let _ = socket.send_to(&reply, from).await;
            }
        }
    })
}

fn binding_response(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    const COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
    if request.len() < 20 || request[4..8] != COOKIE || request[..2] != [0, 1] {
        return None;
    }
    let SocketAddr::V4(from) = from else {
        return None;
    };
    let mut value = vec![0u8, 1];
    value.extend_from_slice(&(from.port() ^ 0x2112).to_be_bytes());
    for (octet, key) in from.ip().octets().iter().zip(COOKIE) {
        value.push(octet ^ key);
    }
    let mut out = vec![0x01, 0x01];
    out.extend_from_slice(&(value.len() as u16 + 4).to_be_bytes());
    out.extend_from_slice(&request[4..20]);
    out.extend_from_slice(&[0x00, 0x20]);
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    Some(out)
}

/// The hysteria2 servers register with the control server a moment after mihomo starts listening.
pub async fn wait_registered(log: &Path, realms: usize) {
    for _ in 0..150 {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.matches("re-registered with control").count() >= realms {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "the realm servers never registered:\n{}",
        std::fs::read_to_string(log).unwrap_or_default()
    );
}

/// A client that points at the live control server with something wrong in it, and what it must say.
pub fn failures() -> Vec<(&'static str, Value, &'static str)> {
    let base = |id: &str| -> Value {
        json!({
            "name": "bad", "type": "hysteria2", "server": "127.0.0.1", "port": 9, "udp": true,
            "password": "hy2-pw", "sni": "localhost", "skip-cert-verify": true,
            "realm-opts": realm_opts(id),
        })
    };
    let mut wrong_token = base("plain");
    wrong_token["realm-opts"]["token"] = json!("nope");
    let unknown = base("never-registered");
    let mut no_stun = base("plain");
    no_stun["realm-opts"]["stun-servers"] = json!([]);
    let mut dead_stun = base("plain");
    dead_stun["realm-opts"]["stun-servers"] = json!(["127.0.0.1:9"]);
    let mut strict_tls = base("plain");
    strict_tls["realm-opts"]["skip-cert-verify"] = json!(false);
    vec![
        ("wrong token", wrong_token, "control 401/invalid_token"),
        ("unknown realm", unknown, "control 404/realm_not_found"),
        ("no STUN servers", no_stun, "no STUN servers resolved"),
        (
            "silent STUN server",
            dead_stun,
            "no STUN responses received",
        ),
        ("untrusted control certificate", strict_tls, "certificate"),
    ]
}
