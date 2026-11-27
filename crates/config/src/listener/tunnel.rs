use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde_json::Value;

use super::Networks;
use crate::Map;
use crate::error::{ConfigError, Result};
use crate::lenient::Fields;

/// One entry of the top-level `tunnels`: connections to `address` go to `target`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelDef {
    pub networks: Networks,
    pub address: SocketAddr,
    pub target: HostPort,
    pub proxy: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

/// The string form `tcp/udp,address,target[,proxy]` or the map form, both held to the checks
/// mihomo gives the string form (`listener/config/tunnel.go:21-69`); it skips them for a map.
pub(super) fn parse_tunnel(value: &Value) -> Result<TunnelDef> {
    match value {
        Value::String(text) => parse_line(text),
        Value::Object(map) => parse_map(map),
        _ => Err(ConfigError::new("invalid tunnel config")),
    }
}

fn parse_line(text: &str) -> Result<TunnelDef> {
    let parts: Vec<&str> = text.split(',').map(str::trim).collect();
    let [network, address, target, rest @ ..] = parts.as_slice() else {
        return Err(ConfigError::new(format!("invalid tunnel config {text}")));
    };
    if rest.len() > 1 {
        return Err(ConfigError::new(format!("invalid tunnel config {text}")));
    }
    let networks = parse_networks(network.split('/'))?;
    Ok(TunnelDef {
        networks,
        address: bind_addr(address)?,
        target: host_port(target)?,
        proxy: rest
            .first()
            .filter(|proxy| !proxy.is_empty())
            .map(|proxy| (*proxy).to_owned()),
    })
}

fn parse_map(map: &Map) -> Result<TunnelDef> {
    let mut f = Fields::new(map, "tunnel", false);
    let networks = f.strings("network")?;
    let address = f.string("address")?;
    let target = f.string("target")?;
    let proxy = f.opt_string("proxy")?.filter(|proxy| !proxy.is_empty());
    Ok(TunnelDef {
        networks: parse_networks(networks.iter().map(String::as_str))?,
        address: bind_addr(&address)?,
        target: host_port(&target)?,
        proxy,
    })
}

pub(super) fn parse_networks<'a>(names: impl Iterator<Item = &'a str>) -> Result<Networks> {
    let mut networks = Networks::default();
    for name in names {
        match name {
            "tcp" => networks.tcp = true,
            "udp" => networks.udp = true,
            other => return Err(ConfigError::new(format!("invalid tunnel network {other}"))),
        }
    }
    Ok(networks)
}

/// `net.SplitHostPort`, then the host mihomo's listen config accepts: an IP literal,
/// `localhost` or nothing (`adapter/inbound/listen.go:83-105`).
pub(super) fn bind_addr(text: &str) -> Result<SocketAddr> {
    let invalid = || ConfigError::new(format!("invalid tunnel target or address {text}"));
    let HostPort { host, port } = host_port(text)?;
    let ip = match host.as_str() {
        "" => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
        other => other.parse().map_err(|_| invalid())?,
    };
    Ok(SocketAddr::new(ip, port))
}

pub(super) fn host_port(text: &str) -> Result<HostPort> {
    let invalid = || ConfigError::new(format!("invalid tunnel target or address {text}"));
    let (host, port) = text.rsplit_once(':').ok_or_else(invalid)?;
    let host = match host.strip_prefix('[') {
        Some(inner) => inner.strip_suffix(']').ok_or_else(invalid)?,
        None if host.contains(':') => return Err(invalid()),
        None => host,
    };
    Ok(HostPort {
        host: host.to_owned(),
        port: port.parse().map_err(|_| invalid())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_string_form_is_checked_and_takes_an_optional_proxy() {
        let def = parse_tunnel(&json!("tcp/udp,127.0.0.1:6553,114.114.114.114:53,proxy")).unwrap();
        assert!(def.networks.tcp && def.networks.udp);
        assert_eq!(def.address, "127.0.0.1:6553".parse().unwrap());
        assert_eq!(def.target.host, "114.114.114.114");
        assert_eq!(def.proxy.as_deref(), Some("proxy"));
        let plain = parse_tunnel(&json!("tcp, :7777 , example.com:22")).unwrap();
        assert_eq!(plain.address, "0.0.0.0:7777".parse().unwrap());
        assert_eq!(plain.proxy, None);
    }

    #[test]
    fn bad_strings_name_what_is_wrong() {
        let err = |v: Value| parse_tunnel(&v).unwrap_err().to_string();
        assert!(err(json!("tcp,1.1.1.1:1")).contains("invalid tunnel config"));
        assert!(err(json!("sctp,:1,a:1")).contains("invalid tunnel network sctp"));
        assert!(err(json!("tcp,:1,nohost")).contains("invalid tunnel target or address nohost"));
        assert!(err(json!("tcp,a.b:1,c:1")).contains("invalid tunnel target or address a.b:1"));
        assert!(err(json!("tcp,:1,c:1,p,extra")).contains("invalid tunnel config"));
    }

    #[test]
    fn the_map_form_gets_the_same_checks() {
        let ok = json!({"network": ["udp"], "address": "[::1]:53", "target": "1.1.1.1:53"});
        let def = parse_tunnel(&ok).unwrap();
        assert!(!def.networks.tcp && def.networks.udp);
        assert_eq!(def.address, "[::1]:53".parse().unwrap());
        let bad = json!({"network": ["quic"], "address": ":1", "target": "a:1"});
        assert!(parse_tunnel(&bad).is_err());
    }
}
