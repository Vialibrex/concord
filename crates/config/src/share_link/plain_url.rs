use std::collections::HashMap;

use serde_json::{Value, json};

use super::decode::into_map;
use super::urlx::{Link, unique_name};
use crate::Map;

const NAIVE_PORT: &str = "443";

fn remarks(link: &Link, port: &str) -> String {
    if link.fragment.is_empty() {
        format!("{}:{port}", link.host)
    } else {
        link.fragment.clone()
    }
}

pub(super) fn anytls(line: &str, names: &mut HashMap<String, u32>, out: &mut Vec<Map>) {
    let Some(link) = Link::parse(line) else {
        return;
    };
    if link.host.is_empty() || link.port.is_empty() {
        return;
    }
    let username = link.username().to_string();
    let password = link.password.clone().unwrap_or_else(|| username.clone());
    out.push(into_map(json!({
        "name": unique_name(names, &remarks(&link, &link.port)),
        "type": "anytls",
        "server": link.host,
        "port": link.port,
        "username": username,
        "password": password,
        "sni": link.get("sni"),
        "fingerprint": link.get("hpkp"),
        "skip-cert-verify": link.get("insecure") == "1",
        "udp": true,
    })));
}

/// DuckSoft's NaiveProxy URI: `naive+https://` or `naive+quic://`, port 443 when left out,
/// `extra-headers` as `Name: value` lines joined by CRLF, and the `sni` and `insecure-concurrency`
/// v2rayN and NekoBox add. `padding` is ignored: the node negotiates padding with its server.
pub(super) fn naive(
    scheme: &str,
    line: &str,
    names: &mut HashMap<String, u32>,
    out: &mut Vec<Map>,
) {
    let Some(link) = Link::parse(line) else {
        return;
    };
    if link.host.is_empty() {
        return;
    }
    let port = if link.port.is_empty() {
        NAIVE_PORT
    } else {
        link.port.as_str()
    };
    let mut map = into_map(json!({
        "name": unique_name(names, &remarks(&link, port)),
        "type": "naive",
        "server": link.host,
        "port": port,
        "username": link.username(),
        "password": link.password.as_deref().unwrap_or_default(),
        "quic": scheme == "naive+quic",
    }));
    let headers: Map = link
        .get("extra-headers")
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), Value::from(value.trim())))
        .filter(|(name, _)| !name.is_empty())
        .collect();
    if !headers.is_empty() {
        map.insert("headers".into(), Value::Object(headers));
    }
    if !link.get("sni").is_empty() {
        map.insert("sni".into(), Value::from(link.get("sni")));
    }
    if let Ok(count) = link.get("insecure-concurrency").parse::<u32>() {
        map.insert("insecure-concurrency".into(), Value::from(count));
    }
    out.push(map);
}
