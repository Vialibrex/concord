use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use indexmap::IndexMap;
use serde_json::Value;

use super::tunnel::{bind_addr, parse_networks, parse_tunnel};
use super::*;
use crate::Map;
use crate::error::{ConfigError, Result};
use crate::lenient::Fields;
use crate::net::parse_port_ranges;
use crate::report::LoadReport;

/// Every `type` mihomo's `listener/parse.go` knows. Those this core does not serve yet are
/// skipped with a warning rather than refused, since a listener left closed changes no route.
pub const LISTENER_TYPES: &[&str] = &[
    "socks",
    "http",
    "tproxy",
    "redir",
    "mixed",
    "tunnel",
    "tun",
    "shadowsocks",
    "snell",
    "vmess",
    "vless",
    "trojan",
    "hysteria2",
    "hysteria2-realm",
    "tuic",
    "shadowquic",
    "anytls",
    "mieru",
    "sudoku",
    "trusttunnel",
];

const UNSUPPORTED_TYPES: &[&str] = &["tun", "sudoku", "trusttunnel"];

/// The listener options that pick another security layer than plain TLS; mihomo allows one.
const SECURITY_KEYS: &[&str] = &[
    "reality-config",
    "shadow-tls",
    "res-tls",
    "jls-config",
    "tlsmirror-config",
];

/// `listener/anytls/server.go:86-97`.
const ANYTLS_SECURITY_KEYS: &[&str] = &["shadow-tls", "res-tls", "jls-config"];

const UNSUPPORTED_KEYS: &[&str] = &[
    "res-tls",
    "tlsmirror-config",
    "mkcp-config",
    "mekya-config",
    "kcp-tun",
    "ech-key",
];

/// Why a listener stays closed while the rest of the profile loads.
struct Skip(String);

enum Fail {
    Hard(ConfigError),
    Skip(Skip),
}

impl From<ConfigError> for Fail {
    fn from(err: ConfigError) -> Self {
        Fail::Hard(err)
    }
}

type R<T> = std::result::Result<T, Fail>;

fn skip<T>(reason: impl Into<String>) -> R<T> {
    Err(Fail::Skip(Skip(reason.into())))
}

/// The inbound keys of the general section, which keeps them as written.
pub fn from_general(general: &Map, report: &mut LoadReport) -> Result<InboundDefs> {
    let listeners = match general.get("listeners") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| match item {
                Value::Object(map) => Ok(map.clone()),
                _ => Err(ConfigError::new(format!(
                    "yaml: unmarshal errors: listeners[{index}]: cannot unmarshal into map[string]interface {{}}"
                ))),
            })
            .collect::<Result<Vec<Map>>>()?,
        Some(_) => {
            return Err(ConfigError::new(
                "yaml: unmarshal errors: cannot unmarshal into []map[string]interface {} (listeners)",
            ));
        }
    };
    let tunnels = match general.get("tunnels") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(items)) => items.as_slice(),
        Some(_) => {
            return Err(ConfigError::new(
                "yaml: unmarshal errors: tunnels is not a list",
            ));
        }
    };
    let text = |key: &str| general.get(key).and_then(Value::as_str).unwrap_or_default();
    let mut defs = read(
        &listeners,
        tunnels,
        text("ss-config"),
        text("vmess-config"),
        report,
    )?;
    if let Some(Value::Object(tuic)) = general.get("tuic-server") {
        let mut f = Fields::new(tuic, "tuic-server", true);
        match default_tuic(&mut f) {
            Ok(def) => defs.listeners.extend(def),
            Err(err) => report.warn("listener_skipped", "tuic-server", err.to_string()),
        }
        report.warn_ignored("", &f.take_ignored());
    }
    Ok(defs)
}

/// The top-level `tuic-server` (`config/config.go:334-347`), which has no client-auth,
/// `bbr-profile` or `mux-option`, and which mihomo opens as
/// `DEFAULT-TUIC` on every address of its comma-separated `listen`; one that fails is
/// logged and left closed (`listener/listener.go:352-394`).
fn default_tuic(f: &mut Fields<'_>) -> Result<Option<ListenerDef>> {
    if !f.boolean("enable")? {
        return Ok(None);
    }
    let listen = f.string("listen")?;
    let addrs = listen
        .split(',')
        .map(bind_addr)
        .collect::<Result<Vec<SocketAddr>>>()?;
    let tls = ServerTls {
        certificate: f.string("certificate")?,
        private_key: f.string("private-key")?,
        client_auth: ClientAuth::None,
        client_auth_cert: String::new(),
    };
    let server = tuic_server(f, tls, String::new(), MuxServer::default())?;
    Ok(Some(ListenerDef {
        name: "DEFAULT-TUIC".to_owned(),
        binds: Binds::Addrs(addrs),
        rule: None,
        proxy: None,
        routing_mark: 0,
        kind: ListenerKind::Tuic(server),
        default_of: Some("tuic-server"),
    }))
}

pub fn read(
    listeners: &[Map],
    tunnels: &[Value],
    ss_config: &str,
    vmess_config: &str,
    report: &mut LoadReport,
) -> Result<InboundDefs> {
    let mut defs = InboundDefs::default();
    let mut names = HashSet::new();
    for (index, map) in listeners.iter().enumerate() {
        let path = format!("listeners[{index}]");
        let parsed = parse_listener(map).map_err(|err| match err {
            Fail::Hard(err) => Fail::Hard(err.prefixed(&format!("listener {index}: "))),
            skip => skip,
        });
        match parsed {
            Ok((def, ignored)) => {
                if !names.insert(def.name.clone()) {
                    return Err(ConfigError::new(format!(
                        "listener {} is the duplicate name",
                        def.name
                    )));
                }
                for note in ignored {
                    report.warn("listener_option", path.clone(), note);
                }
                defs.listeners.push(def);
            }
            Err(Fail::Skip(Skip(reason))) => {
                let name = map.get("name").and_then(Value::as_str).unwrap_or_default();
                report.warn("listener_skipped", path, format!("{name}: {reason}"));
            }
            Err(Fail::Hard(err)) => return Err(err),
        }
    }
    let globals: [(&str, &str, &str, GlobalParse); 2] = [
        ("DEFAULT-SHADOWSOCKS", "ss-config", ss_config, global_ss),
        ("DEFAULT-VMESS", "vmess-config", vmess_config, global_vmess),
    ];
    for (name, key, text, kind) in globals {
        if text.is_empty() {
            continue;
        }
        match global_url(text) {
            Ok((user, secret, binds)) => defs.listeners.push(ListenerDef {
                name: name.to_owned(),
                binds,
                rule: None,
                proxy: None,
                routing_mark: 0,
                kind: kind(user, secret),
                default_of: Some(key),
            }),
            Err(err) => report.warn("listener_skipped", key, err.to_string()),
        }
    }
    for (index, value) in tunnels.iter().enumerate() {
        defs.tunnels
            .push(parse_tunnel(value).map_err(|err| err.prefixed(&format!("tunnel {index}: ")))?);
    }
    Ok(defs)
}

type GlobalParse = fn(String, String) -> ListenerKind;

fn global_ss(cipher: String, password: String) -> ListenerKind {
    ListenerKind::Shadowsocks(SsServer {
        cipher,
        password,
        users: IndexMap::new(),
        udp: true,
        mux: MuxServer::default(),
    })
}

/// `listener.go:326-331` serves the URL's one user with `AlterID: 1`.
fn global_vmess(username: String, uuid: String) -> ListenerKind {
    ListenerKind::Vmess(VmessServer {
        users: vec![VmessUser {
            username,
            uuid,
            alter_id: 1,
        }],
        tls: None,
        carriers: HttpCarriers::default(),
        mux: MuxServer::default(),
    })
}

/// `scheme://user:secret@host:port[,host:port...]`, read as mihomo's `mhurl` does
/// (`listener/shadowsocks/utils.go:51-63`): the scheme is not checked, and the user and
/// secret are percent-decoded, a malformed escape refused.
fn global_url(text: &str) -> Result<(String, String, Binds)> {
    let invalid = || ConfigError::new(format!("invalid listener url {text}"));
    let (_, rest) = text.split_once("://").ok_or_else(invalid)?;
    let (userinfo, hosts) = rest.rsplit_once('@').ok_or_else(invalid)?;
    let (user, secret) = userinfo.split_once(':').ok_or_else(invalid)?;
    let decode = |part: &str| unescape(part).ok_or_else(invalid);
    let (user, secret) = (decode(user)?, decode(secret)?);
    let addrs = hosts
        .trim_end_matches('/')
        .split(',')
        .map(bind_addr)
        .collect::<Result<Vec<SocketAddr>>>()
        .map_err(|_| invalid())?;
    Ok((user, secret, Binds::Addrs(addrs)))
}

fn unescape(part: &str) -> Option<String> {
    let bytes = part.as_bytes();
    let escapes_whole = bytes.iter().enumerate().all(|(at, byte)| {
        *byte != b'%'
            || bytes
                .get(at + 1..at + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
    });
    if !escapes_whole {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(part)
        .decode_utf8()
        .ok()?;
    Some(decoded.into_owned())
}

fn parse_listener(map: &Map) -> R<(ListenerDef, Vec<String>)> {
    let Some(Value::String(type_name)) = map.get("type") else {
        return Err(ConfigError::new("missing type").into());
    };
    if !LISTENER_TYPES.contains(&type_name.as_str()) {
        return Err(ConfigError::new(format!("unsupport proxy type: {type_name}")).into());
    }
    let mut f = Fields::new(map, "", true);
    f.require("name");
    f.unset()?;
    let name = f.string("name")?;
    let binds = base_binds(&mut f)?;
    let rule = f.opt_string("rule")?.filter(|rule| !rule.is_empty());
    let proxy = f.opt_string("proxy")?.filter(|proxy| !proxy.is_empty());
    let routing_mark = f.mark("routing-mark")?;
    if UNSUPPORTED_TYPES.contains(&type_name.as_str()) {
        return skip(format!(
            "listener type '{type_name}' is not supported by this core"
        ));
    }
    for key in UNSUPPORTED_KEYS {
        if asks_for(&f, key) {
            return skip(format!("option '{key}' is not supported by this core"));
        }
    }
    let kind = match type_name.as_str() {
        "http" => ListenerKind::Http(proxy_server(&mut f, false)?),
        "socks" => ListenerKind::Socks(proxy_server(&mut f, true)?),
        "mixed" => ListenerKind::Mixed(proxy_server(&mut f, true)?),
        "redir" => ListenerKind::Redir,
        "tproxy" => ListenerKind::TProxy {
            udp: f.opt_bool("udp")?.unwrap_or(true),
        },
        "tunnel" => tunnel_listener(&mut f)?,
        "shadowsocks" => ListenerKind::Shadowsocks(ss_server(&mut f)?),
        "vmess" => ListenerKind::Vmess(vmess_server(&mut f)?),
        "vless" => ListenerKind::Vless(vless_server(&mut f)?),
        "trojan" => ListenerKind::Trojan(trojan_server(&mut f)?),
        "hysteria2" => ListenerKind::Hysteria2(hysteria2_server(&mut f)?),
        "anytls" => ListenerKind::AnyTls(anytls_server(&mut f)?),
        "tuic" => {
            let tls = quic_tls(&mut f)?;
            let bbr_profile = f.string("bbr-profile")?;
            let mux = mux_option(&mut f)?;
            ListenerKind::Tuic(tuic_server(&mut f, tls, bbr_profile, mux)?)
        }
        other => return skip(format!("listener type '{other}' is not implemented yet")),
    };
    let ignored = f.take_ignored().iter().map(ToString::to_string).collect();
    f.finish()?;
    Ok((
        ListenerDef {
            name,
            binds,
            rule,
            proxy,
            routing_mark,
            kind,
            default_of: None,
        },
        ignored,
    ))
}

/// `inbound/base.go:23-35`: an empty `listen` is `0.0.0.0`, anything else an IP literal.
fn base_binds(f: &mut Fields<'_>) -> Result<Binds> {
    let listen = f.string("listen")?;
    let ip = if listen.is_empty() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        listen
            .parse()
            .map_err(|_| ConfigError::new(format!("ParseAddr({listen:?}): unable to parse IP")))?
    };
    let ports = parse_port_ranges(&f.string("port")?)?;
    Ok(Binds::Ports { ip, ports })
}

fn asks_for(f: &Fields<'_>, key: &str) -> bool {
    match f.raw(key) {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Object(map)) => match map.get("enable") {
            Some(enable) => enable.as_bool().unwrap_or(true),
            None => !map.is_empty(),
        },
        Some(Value::Array(items)) => !items.is_empty(),
        Some(_) => true,
    }
}

/// `securityModes`: at most one layer besides plain TLS, and the one this core serves today
/// is plain TLS (`sing_vmess/server.go:138-163`).
fn security(f: &mut Fields<'_>, tls: &Option<ServerTls>) -> R<()> {
    security_among(f, tls, SECURITY_KEYS)
}

fn security_among(f: &mut Fields<'_>, tls: &Option<ServerTls>, keys: &[&str]) -> R<()> {
    let mut chosen: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|key| asks_for(f, key))
        .collect();
    if tls.is_some() {
        chosen.insert(0, "certificate");
    }
    if chosen.len() > 1 {
        return Err(ConfigError::new(format!(
            "security modes are mutually exclusive: {}",
            chosen.join(", ")
        ))
        .into());
    }
    match chosen.first() {
        Some(&key) if key != "certificate" => skip(format!("option '{key}' is not served yet")),
        _ => Ok(()),
    }
}

fn server_tls(f: &mut Fields<'_>) -> R<Option<ServerTls>> {
    let certificate = f.string("certificate")?;
    let private_key = f.string("private-key")?;
    let (client_auth, client_auth_cert) = client_auth(f)?;
    if certificate.is_empty() || private_key.is_empty() {
        if client_auth != ClientAuth::None {
            return skip("client-auth requires certificate");
        }
        if !certificate.is_empty() || !private_key.is_empty() {
            f.warn(
                "certificate",
                "TLS needs both certificate and private-key; served without TLS",
            );
        }
        return Ok(None);
    }
    Ok(Some(ServerTls {
        certificate,
        private_key,
        client_auth,
        client_auth_cert,
    }))
}

/// A QUIC listener always serves TLS; with neither part named it signs its own
/// (`component/ca/keypair.go:25-33`).
fn quic_tls(f: &mut Fields<'_>) -> Result<ServerTls> {
    let certificate = f.string("certificate")?;
    let private_key = f.string("private-key")?;
    let (client_auth, client_auth_cert) = client_auth(f)?;
    Ok(ServerTls {
        certificate,
        private_key,
        client_auth,
        client_auth_cert,
    })
}

fn client_auth(f: &mut Fields<'_>) -> Result<(ClientAuth, String)> {
    let kind = f.string("client-auth-type")?;
    let client_auth_cert = f.string("client-auth-cert")?;
    let mut client_auth = match kind.as_str() {
        "request" => ClientAuth::Request,
        "require-any" => ClientAuth::RequireAny,
        "verify-if-given" => ClientAuth::VerifyIfGiven,
        "require-and-verify" => ClientAuth::RequireAndVerify,
        _ => ClientAuth::None,
    };
    if kind.is_empty() && !client_auth_cert.is_empty() {
        client_auth = ClientAuth::RequireAndVerify;
    }
    Ok((client_auth, client_auth_cert))
}

fn carriers(f: &mut Fields<'_>) -> Result<HttpCarriers> {
    let some = |text: String| (!text.is_empty()).then_some(text);
    Ok(HttpCarriers {
        ws_path: some(f.string("ws-path")?),
        grpc_service_name: some(f.string("grpc-service-name")?),
    })
}

/// Brutal needs Linux's tcp-brutal module: mihomo fails to build such a listener elsewhere
/// (sing-mux `server.go:39-41`).
fn mux_option(f: &mut Fields<'_>) -> R<MuxServer> {
    let Some(mut mux) = f.sub("mux-option")? else {
        return Ok(MuxServer::default());
    };
    let padding = mux.boolean("padding")?;
    let brutal = match mux.sub("brutal")? {
        Some(mut brutal) => {
            let enabled = brutal.boolean("enabled")?;
            let rates = MuxBrutal {
                up: brutal.string("up")?,
                down: brutal.string("down")?,
            };
            enabled.then_some(rates)
        }
        None => None,
    };
    let linux = cfg!(any(target_os = "linux", target_os = "android"));
    if brutal.is_some() && !linux {
        return skip("TCP Brutal is only supported on Linux");
    }
    Ok(MuxServer { padding, brutal })
}

fn proxy_server(f: &mut Fields<'_>, has_udp: bool) -> R<ProxyServer> {
    let users = match f.raw("users") {
        None | Some(Value::Null) => ProxyUsers::Global,
        Some(_) => {
            let pairs = user_list(f, "users", &["!username", "!password"])?;
            if pairs.is_empty() {
                ProxyUsers::Open
            } else {
                ProxyUsers::Own(
                    pairs
                        .into_iter()
                        .map(|mut user| (user.remove(0), user.remove(0)))
                        .collect(),
                )
            }
        }
    };
    let udp = has_udp && f.opt_bool("udp")?.unwrap_or(true);
    let tls = server_tls(f)?;
    if asks_for(f, "reality-config") {
        if tls.is_some() {
            return Err(ConfigError::new("certificate is unavailable in reality").into());
        }
        return skip("option 'reality-config' is not served yet");
    }
    if tls.is_some() {
        return skip("TLS on an HTTP or SOCKS listener is not served yet");
    }
    Ok(ProxyServer { users, udp, tls })
}

/// Each item of a list of maps, with `fields` read as strings in order; a field without
/// `omitempty` in mihomo's struct is required there.
fn user_list(f: &mut Fields<'_>, key: &str, fields: &[&str]) -> Result<Vec<Vec<String>>> {
    let items = match f.raw(key) {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(ConfigError::new(format!("'{key}' expected type 'slice'"))),
    };
    let mut users = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Value::Object(map) = item else {
            return Err(ConfigError::new(format!("'{key}[{index}]' expected a map")));
        };
        let mut u = Fields::new(map, &format!("{key}[{index}]"), true);
        let mut values = Vec::with_capacity(fields.len());
        for field in fields {
            if let Some(required) = field.strip_prefix('!') {
                u.require(required);
                values.push(u.string(required)?);
            } else {
                values.push(u.string(field)?);
            }
        }
        u.finish()?;
        users.push(values);
    }
    Ok(users)
}

fn tunnel_listener(f: &mut Fields<'_>) -> R<ListenerKind> {
    f.require("network");
    f.require("target");
    let networks = f.strings("network")?;
    let target = f.string("target")?;
    let mut known = Vec::new();
    for name in &networks {
        if matches!(name.as_str(), "tcp" | "udp") {
            known.push(name.as_str());
        } else {
            f.warn("network", &format!("unknown network type {name}"));
        }
    }
    Ok(ListenerKind::Tunnel {
        networks: parse_networks(known.into_iter())?,
        target,
    })
}

fn ss_server(f: &mut Fields<'_>) -> R<SsServer> {
    f.require("cipher");
    let cipher = f.string("cipher")?;
    let password = f.string("password")?;
    let users = f.string_map("users")?;
    if password.is_empty() && users.is_empty() {
        return Err(ConfigError::new("shadowsocks: missing password").into());
    }
    let udp = f.opt_bool("udp")?.unwrap_or(true);
    if asks_for(f, "simple-obfs") {
        return skip("option 'simple-obfs' is not served yet");
    }
    security(f, &None)?;
    let mux = mux_option(f)?;
    Ok(SsServer {
        cipher,
        password,
        users,
        udp,
        mux,
    })
}

fn vmess_server(f: &mut Fields<'_>) -> R<VmessServer> {
    f.require("users");
    let users = user_list(f, "users", &["username", "!uuid", "alterId"])?
        .into_iter()
        .map(|mut user| {
            let alter = user.remove(2);
            let alter_id = if alter.is_empty() {
                0
            } else {
                alter
                    .parse()
                    .map_err(|_| ConfigError::new(format!("invalid alterId {alter}")))?
            };
            Ok(VmessUser {
                username: user.remove(0),
                uuid: user.remove(0),
                alter_id,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let tls = server_tls(f)?;
    security(f, &tls)?;
    let mux = mux_option(f)?;
    Ok(VmessServer {
        users,
        tls,
        carriers: carriers(f)?,
        mux,
    })
}

fn vless_server(f: &mut Fields<'_>) -> R<VlessServer> {
    f.require("users");
    let users: Vec<VlessUser> = user_list(f, "users", &["username", "!uuid", "flow"])?
        .into_iter()
        .map(|mut user| VlessUser {
            username: user.remove(0),
            uuid: user.remove(0),
            flow: user.remove(0),
        })
        .collect();
    let decryption = f.string("decryption")?;
    if !decryption.is_empty() && decryption != "none" {
        return skip("option 'decryption' is not served yet");
    }
    if asks_for(f, "xhttp-config") {
        return skip("option 'xhttp-config' is not served yet");
    }
    let tls = server_tls(f)?;
    security(f, &tls)?;
    if tls.is_none() && !f.boolean("allow-insecure")? {
        return skip(
            "disallow using Vless without any certificates/shadow-tls/res-tls/jls/reality/decryption/allow-insecure config",
        );
    }
    let mux = mux_option(f)?;
    Ok(VlessServer {
        users,
        tls,
        carriers: carriers(f)?,
        mux,
    })
}

fn trojan_server(f: &mut Fields<'_>) -> R<TrojanServer> {
    f.require("users");
    let users = user_list(f, "users", &["username", "!password"])?
        .into_iter()
        .map(|mut user| TrojanUser {
            username: user.remove(0),
            password: user.remove(0),
        })
        .collect();
    if asks_for(f, "ss-option") {
        return skip("option 'ss-option' is not served yet");
    }
    let tls = server_tls(f)?;
    security(f, &tls)?;
    if tls.is_none() && !f.boolean("allow-insecure")? {
        return skip(
            "disallow using Trojan without any certificates/shadow-tls/res-tls/jls/reality/ss/allow-insecure config",
        );
    }
    let mux = mux_option(f)?;
    Ok(TrojanServer {
        users,
        tls,
        carriers: carriers(f)?,
        mux,
    })
}

/// anytls has no `reality-config`, `tlsmirror-config` or `mux-option`
/// (`listener/inbound/anytls.go:12-25`), so they are not read.
fn anytls_server(f: &mut Fields<'_>) -> R<AnyTlsServer> {
    let users = f.string_map("users")?;
    let padding_scheme = f.string("padding-scheme")?;
    let tls = server_tls(f)?;
    security_among(f, &tls, ANYTLS_SECURITY_KEYS)?;
    if tls.is_none() && !f.boolean("allow-insecure")? {
        return skip(
            "disallow using AnyTLS without certificates/shadow-tls/res-tls/jls/allow-insecure config",
        );
    }
    Ok(AnyTlsServer {
        users,
        padding_scheme,
        tls,
    })
}

fn tuic_server(
    f: &mut Fields<'_>,
    tls: ServerTls,
    bbr_profile: String,
    mux: MuxServer,
) -> Result<TuicServer> {
    Ok(TuicServer {
        tokens: f.strings("token")?,
        users: f.string_map("users")?,
        tls,
        alpn: f.strings("alpn")?,
        congestion: f.string("congestion-controller")?,
        cwnd: f.loose("cwnd", 0)?,
        bbr_profile,
        max_idle_ms: f.loose("max-idle-time", 0)?,
        auth_timeout_ms: f.loose("authentication-timeout", 0)?,
        max_udp_relay_packet: f.loose("max-udp-relay-packet-size", 0)?,
        mux,
    })
}

/// `realm-opts` and the Gecko obfuscation wait for a later batch; `masquerade` is answered
/// with 404 as when it is unset, and `max-idle-time`, which mihomo reads but never applies,
/// is not read.
fn hysteria2_server(f: &mut Fields<'_>) -> R<Hysteria2Server> {
    if asks_for(f, "realm-opts") {
        return skip("option 'realm-opts' is not served yet");
    }
    let salamander = match f.string("obfs")?.as_str() {
        "" => None,
        "salamander" => {
            let password = f.string("obfs-password")?;
            if password.is_empty() {
                return skip("missing obfs password");
            }
            Some(password)
        }
        "gecko" => return skip("obfs 'gecko' is not served yet"),
        other => return skip(format!("unknown obfs type: {other}")),
    };
    f.ignore("masquerade", "answered with 404 until masquerade is served");
    let tls = quic_tls(f)?;
    let mux = mux_option(f)?;
    Ok(Hysteria2Server {
        users: f.string_map("users")?,
        salamander,
        up: f.string("up")?,
        down: f.string("down")?,
        ignore_client_bandwidth: f.boolean("ignore-client-bandwidth")?,
        tls,
        alpn: f.strings("alpn")?,
        udp_mtu: f.loose("udp-mtu", 0)?,
        cwnd: f.loose("cwnd", 0)?,
        bbr_profile: f.string("bbr-profile")?,
        initial_stream_window: f.u64("initial-stream-receive-window")?,
        max_stream_window: f.u64("max-stream-receive-window")?,
        initial_conn_window: f.u64("initial-connection-receive-window")?,
        max_conn_window: f.u64("max-connection-receive-window")?,
        mux,
    })
}
