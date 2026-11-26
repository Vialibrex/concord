//! Puts the same profile in front of `concord run` and mihomo and compares the
//! JSON shape each controller answers with:
//! `CONCORD_MIHOMO=<path to the mihomo binary> cargo test -p concord-desktop --test controller -- --ignored`.

#![allow(
    clippy::disallowed_methods,
    reason = "the dashboard here is the test's own, not the core's dials"
)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use concord_test_support::port_to_bind_later;
use serde_json::Value;

const BINARY: &str = env!("CARGO_BIN_EXE_concord");
const SECRET: &str = "shape";

fn profile(controller: u16) -> String {
    format!(
        "mixed-port: {mixed}
external-controller: 127.0.0.1:{controller}
secret: {SECRET}
log-level: info
proxies:
  - {{name: local, type: socks5, server: 127.0.0.1, port: 1, udp: true}}
proxy-groups:
  - {{name: G, type: select, proxies: [DIRECT, local, REJECT]}}
  - {{name: auto, type: url-test, proxies: [DIRECT, local], url: 'http://127.0.0.1:1/', lazy: true}}
  - {{name: F, type: fallback, proxies: [local, DIRECT], url: 'http://127.0.0.1:1/', lazy: true}}
rules:
  - DOMAIN-SUFFIX,example.test,REJECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - MATCH,G
",
        mixed = port_to_bind_later()
    )
}

struct Core(Child);

impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(program: &str, run: bool, dir: &Path, controller: u16) -> Core {
    let config = dir.join("profile.yaml");
    std::fs::write(&config, profile(controller)).unwrap();
    let mut command = Command::new(program);
    if run {
        command.arg("run").arg("-c").arg(&config).arg("-d").arg(dir);
    } else {
        command
            .env("DISABLE_LOOPBACK_DETECTOR", "true")
            .arg("-f")
            .arg(&config)
            .arg("-d")
            .arg(dir);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect((Ipv4Addr::LOCALHOST, controller)).is_err() {
        assert!(
            Instant::now() < deadline,
            "{program} did not open {controller}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    Core(child)
}

fn unchunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(end) = body.windows(2).position(|pair| pair == b"\r\n") else {
            return out;
        };
        let size = std::str::from_utf8(&body[..end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.split(';').next()?.trim(), 16).ok())
            .unwrap_or(0);
        if size == 0 || body.len() < end + 2 + size {
            return out;
        }
        out.extend_from_slice(&body[end + 2..end + 2 + size]);
        body = &body[end + 2 + size..];
        body = body.strip_prefix(b"\r\n").unwrap_or(body);
    }
}

/// The whole body, or the first line of a pushed one.
fn get(port: u16, path: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(read) => bytes.extend_from_slice(&buf[..read]),
        }
        if bytes.ends_with(b"}\n") || bytes.ends_with(b"}\n\r\n") {
            break;
        }
    }
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&bytes[..split]).to_ascii_lowercase();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let mut body = bytes[split + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        body = unchunk(&body);
    }
    let text = String::from_utf8_lossy(&body);
    let first = text.lines().next().unwrap_or_default();
    (status, serde_json::from_str(first).unwrap_or(Value::Null))
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Objects at these paths are keyed by names, which differ by design (mihomo
/// has built-ins Concord lacks); only their shared names are compared.
const NAMED: [&str; 3] = ["/proxies", "/providers", "/providers/default/proxies"];

fn compare(path: &str, theirs: &Value, ours: &Value, out: &mut Vec<String>) {
    match (theirs, ours) {
        (Value::Object(a), Value::Object(b)) => {
            let named = NAMED.contains(&path);
            let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
            for key in keys {
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => compare(&format!("{path}/{key}"), x, y, out),
                    (Some(_), None) if !named => out.push(format!("{path}/{key}: only mihomo")),
                    (None, Some(_)) if !named => out.push(format!("{path}/{key}: only Concord")),
                    _ => {}
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            if let Some(x) = a.first()
                && let Some(y) = b
                    .iter()
                    .find(|y| x.get("name").is_some() && y.get("name") == x.get("name"))
                    .or(b.first())
            {
                compare(&format!("{path}/0"), x, y, out);
            }
        }
        (Value::Null, Value::Null) => {}
        (Value::Null, _) | (_, Value::Null) if path.is_empty() => {
            out.push(format!("{path}: no JSON from one side"));
        }
        (Value::Null, Value::Array(empty)) if empty.is_empty() => {}
        _ if kind(theirs) != kind(ours) => {
            out.push(format!(
                "{path}: mihomo {} Concord {}",
                kind(theirs),
                kind(ours)
            ));
        }
        _ => {}
    }
}

/// Differences `docs/compatibility.md` lists. A list mihomo leaves `null` where
/// Concord writes `[]` is not compared.
const ACCEPTED: [&str; 7] = [
    "/rules/rules/0/extra: only mihomo",
    "/configs/lan-allowed-ips: mihomo array Concord null",
    "/configs/lan-disallowed-ips: mihomo array Concord null",
    "/configs/tun/inet4-address: only mihomo",
    "/configs/tun/inet6-address: only mihomo",
    "/configs/tun/recvmsgx: only mihomo",
    "/configs/tun/processors-per-channel: only mihomo",
];

#[test]
#[ignore = "needs CONCORD_MIHOMO"]
fn the_controller_answers_in_mihomos_shapes() {
    let Ok(mihomo) = std::env::var("CONCORD_MIHOMO") else {
        eprintln!("CONCORD_MIHOMO is not set; skipping");
        return;
    };
    let (their_dir, our_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (their_port, our_port) = (port_to_bind_later(), port_to_bind_later());
    let _theirs = start(&mihomo, false, their_dir.path(), their_port);
    let _ours = start(BINARY, true, our_dir.path(), our_port);

    let mut differences = Vec::new();
    for path in [
        "/",
        "/version",
        "/configs",
        "/proxies",
        "/proxies/G",
        "/proxies/auto",
        "/proxies/local",
        "/group",
        "/group/F",
        "/rules",
        "/connections",
        "/providers/proxies",
        "/providers/rules",
        "/traffic",
        "/memory",
        "/nowhere",
    ] {
        let (their_status, theirs) = get(their_port, path);
        let (our_status, ours) = get(our_port, path);
        if their_status != our_status {
            differences.push(format!(
                "{path}: status mihomo {their_status} Concord {our_status}"
            ));
        }
        let mut found = Vec::new();
        compare("", &theirs, &ours, &mut found);
        let route = path.trim_end_matches('/');
        differences.extend(
            found
                .into_iter()
                .map(|difference| format!("{route}{difference}"))
                .filter(|difference| !ACCEPTED.contains(&difference.as_str())),
        );
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}
