//! Inbound listeners a profile opens: `listeners`, `tunnels`, `ss-config` and `vmess-config`,
//! read as mihomo's `listener/inbound` options and `listener/config/tunnel.go`.

mod parse;
mod tunnel;

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use indexmap::IndexMap;

use crate::error::{ConfigError, Result};

use crate::net::PortRange;

pub use parse::{LISTENER_TYPES, from_general, read};
pub use tunnel::{HostPort, TunnelDef};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerDef {
    pub name: String,
    pub binds: Binds,
    /// A `sub-rules` list the flows start from (`rule:`).
    pub rule: Option<String>,
    /// The proxy every flow takes, past the rules (`proxy:`).
    pub proxy: Option<String>,
    pub routing_mark: u32,
    pub kind: ListenerKind,
    /// The top-level key a default listener comes from: `ss-config`, `vmess-config` or
    /// `tuic-server`;
    /// `None` for an entry of `listeners`. mihomo keeps the two apart, so a listener of the
    /// same name does not replace a default one.
    pub default_of: Option<&'static str>,
}

/// An unspecified address binds the dual-stack wildcard, as Go's `net.Listen` does for
/// `0.0.0.0` and `::` alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binds {
    /// `listen` and `port`. No ranges binds one port the system chooses, as an empty mihomo
    /// `port` does.
    Ports { ip: IpAddr, ports: Vec<PortRange> },
    /// The comma-separated `host:port` list of `ss-config`, `vmess-config` and
    /// `tuic-server`.
    Addrs(Vec<SocketAddr>),
}

impl Binds {
    pub fn addrs(&self) -> Vec<SocketAddr> {
        match self {
            Binds::Ports { ip, ports } if ports.is_empty() => vec![SocketAddr::new(*ip, 0)],
            Binds::Ports { ip, ports } => ports
                .iter()
                .flat_map(|range| range.start..=range.end)
                .map(|port| SocketAddr::new(*ip, port))
                .collect(),
            Binds::Addrs(addrs) => addrs.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerKind {
    Http(ProxyServer),
    Socks(ProxyServer),
    Mixed(ProxyServer),
    Redir,
    TProxy { udp: bool },
    Tunnel { networks: Networks, target: String },
    Shadowsocks(SsServer),
    Vmess(VmessServer),
    Vless(VlessServer),
    Trojan(TrojanServer),
    Tuic(TuicServer),
    Hysteria2(Hysteria2Server),
    AnyTls(AnyTlsServer),
}

impl ListenerKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            ListenerKind::Http(_) => "http",
            ListenerKind::Socks(_) => "socks",
            ListenerKind::Mixed(_) => "mixed",
            ListenerKind::Redir => "redir",
            ListenerKind::TProxy { .. } => "tproxy",
            ListenerKind::Tunnel { .. } => "tunnel",
            ListenerKind::Shadowsocks(_) => "shadowsocks",
            ListenerKind::Vmess(_) => "vmess",
            ListenerKind::Vless(_) => "vless",
            ListenerKind::Trojan(_) => "trojan",
            ListenerKind::Tuic(_) => "tuic",
            ListenerKind::Hysteria2(_) => "hysteria2",
            ListenerKind::AnyTls(_) => "anytls",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Networks {
    pub tcp: bool,
    pub udp: bool,
}

/// Who an HTTP or SOCKS listener lets in (`listener/inbound/auth.go:15-31`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyUsers {
    /// No `users` key: the profile's `authentication`, and with it the LAN lists and
    /// `skip-auth-prefixes`.
    Global,
    /// `users: []`: nobody is asked.
    Open,
    /// Its own `username`/`password` pairs, which the LAN lists do not narrow.
    Own(Vec<(String, String)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyServer {
    pub users: ProxyUsers,
    /// SOCKS and mixed only; `true` unless the profile says otherwise.
    pub udp: bool,
    pub tls: Option<ServerTls>,
}

/// A certificate is inline PEM or a path the engine resolves within the home directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTls {
    pub certificate: String,
    pub private_key: String,
    pub client_auth: ClientAuth,
    pub client_auth_cert: String,
}

/// mihomo's `component/ca/auth.go:17-30`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClientAuth {
    #[default]
    None,
    Request,
    RequireAny,
    VerifyIfGiven,
    RequireAndVerify,
}

/// The HTTP carriers a stream protocol listener can serve beside its plain stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpCarriers {
    pub ws_path: Option<String>,
    pub grpc_service_name: Option<String>,
}

/// `mux-option` (`listener/inbound/mux.go`). A listener that takes it serves sing-mux
/// streams whether or not it is written; it says what the server asks of them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MuxServer {
    /// Refuse a session whose client does not pad.
    pub padding: bool,
    /// `brutal` when `enabled`, with its rates as written.
    pub brutal: Option<MuxBrutal>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuxBrutal {
    pub up: String,
    pub down: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SsServer {
    pub cipher: String,
    pub password: String,
    /// By user name, the password (AEAD) or the user PSK (2022).
    pub users: IndexMap<String, String>,
    pub udp: bool,
    pub mux: MuxServer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmessUser {
    pub username: String,
    pub uuid: String,
    pub alter_id: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmessServer {
    pub users: Vec<VmessUser>,
    pub tls: Option<ServerTls>,
    pub carriers: HttpCarriers,
    pub mux: MuxServer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlessUser {
    pub username: String,
    pub uuid: String,
    pub flow: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlessServer {
    pub users: Vec<VlessUser>,
    pub tls: Option<ServerTls>,
    pub carriers: HttpCarriers,
    pub mux: MuxServer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrojanUser {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrojanServer {
    pub users: Vec<TrojanUser>,
    pub tls: Option<ServerTls>,
    pub carriers: HttpCarriers,
    pub mux: MuxServer,
}

/// mihomo's `listener/inbound/anytls.go`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnyTlsServer {
    /// By name, the password.
    pub users: IndexMap<String, String>,
    /// As written; empty for the default scheme.
    pub padding_scheme: String,
    pub tls: Option<ServerTls>,
}

/// mihomo's `listener/config/tuic.go`. The numbers are as written, 0 where absent: the
/// server applies mihomo's defaults (`listener/tuic/server.go:84-127`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TuicServer {
    /// v4 tokens.
    pub tokens: Vec<String>,
    /// v5 users: by UUID, the password.
    pub users: IndexMap<String, String>,
    /// Empty certificate and key make the server sign its own.
    pub tls: ServerTls,
    pub alpn: Vec<String>,
    pub congestion: String,
    pub cwnd: u32,
    pub bbr_profile: String,
    pub max_idle_ms: u64,
    pub auth_timeout_ms: u64,
    pub max_udp_relay_packet: u64,
    pub mux: MuxServer,
}

/// mihomo's `listener/inbound/hysteria2.go`. Rates and windows are as written, empty or 0
/// where absent; the server applies sing-quic's defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hysteria2Server {
    /// By name, the password.
    pub users: IndexMap<String, String>,
    /// The Salamander password, when the listener obfuscates.
    pub salamander: Option<String>,
    pub up: String,
    pub down: String,
    pub ignore_client_bandwidth: bool,
    /// Empty certificate and key make the server sign its own.
    pub tls: ServerTls,
    pub alpn: Vec<String>,
    pub udp_mtu: u32,
    pub cwnd: u32,
    pub bbr_profile: String,
    pub initial_stream_window: u64,
    pub max_stream_window: u64,
    pub initial_conn_window: u64,
    pub max_conn_window: u64,
    pub masquerade: Option<Masquerade>,
    pub mux: MuxServer,
}

/// What a hysteria2 listener answers a request that is not a client's authentication
/// with, in place of the 404 (`listener/sing_hysteria2/server.go:120-157`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Masquerade {
    /// The files under this directory, as Go's `http.FileServer`.
    File(String),
    /// A reverse proxy to this `http` or `https` URL.
    Proxy(http::Uri),
}

/// Everything a profile opens besides the fixed ports of the general section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InboundDefs {
    pub listeners: Vec<ListenerDef>,
    pub tunnels: Vec<TunnelDef>,
}

/// A `proxy` or `rule` naming nothing in the profile is refused, where mihomo falls back to
/// the main rules or fails each connection (`tunnel/tunnel.go:318-325,716-723`); a tunnel's
/// `proxy` is refused there too (`config/config.go:737-745`). A quarantined proxy still
/// exists: its flows are refused when they arrive.
pub fn check_refs<V>(
    defs: &InboundDefs,
    known: &HashSet<String>,
    quarantined: &HashSet<String>,
    sub_rules: &IndexMap<String, V>,
) -> Result<()> {
    let exists = |name: &str| known.contains(name) || quarantined.contains(name);
    for def in &defs.listeners {
        if let Some(proxy) = def.proxy.as_deref().filter(|name| !exists(name)) {
            return Err(ConfigError::new(format!(
                "listener {}: proxy {proxy} not found",
                def.name
            )));
        }
        if let Some(rule) = def
            .rule
            .as_deref()
            .filter(|name| !sub_rules.contains_key(*name))
        {
            return Err(ConfigError::new(format!(
                "listener {}: sub-rule {rule} not found",
                def.name
            )));
        }
    }
    for tunnel in &defs.tunnels {
        if let Some(proxy) = tunnel.proxy.as_deref().filter(|name| !exists(name)) {
            return Err(ConfigError::new(format!("tunnel proxy {proxy} not found")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
