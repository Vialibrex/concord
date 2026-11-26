use indexmap::IndexMap;
use serde_json::Value;

use crate::error::{ConfigError, Result};
use crate::lenient::Fields;

pub const OPENVPN_CIPHERS: [&str; 7] = [
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "AES-128-CBC",
    "AES-192-CBC",
    "AES-256-CBC",
    "CHACHA20-POLY1305",
];
pub const OPENVPN_AUTHS: [&str; 5] = ["MD5", "SHA1", "SHA256", "SHA384", "SHA512"];

/// An `openvpn` node with mihomo's names and normalization applied: `proto` is `udp` or `tcp`,
/// `cipher` and `auth` are upper case, and the durations are in seconds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenVpnOpts {
    pub server: String,
    pub port: u16,
    pub tcp: bool,
    pub cipher: String,
    pub data_ciphers: Vec<String>,
    pub data_ciphers_fallback: String,
    pub auth: String,
    pub comp_lzo: bool,
    pub ca: String,
    pub cert: String,
    pub key: String,
    pub tls_auth: String,
    pub key_direction: String,
    pub tls_crypt: String,
    pub tls_crypt_v2: String,
    pub username: String,
    pub password: String,
    pub peer_info: IndexMap<String, String>,
    pub ping: u64,
    pub ping_restart: u64,
    pub tran_window: Option<u64>,
    pub handshake_timeout: u64,
    pub mtu: u32,
    pub ip_stack_congestion_controller: String,
    pub remote_dns_resolve: bool,
    pub dns: Vec<String>,
}

/// mihomo's `normalizeCipher`: empty is AES-128-GCM and the bare `AES-CBC` is AES-128-CBC.
pub fn normalize_openvpn_cipher(cipher: &str) -> String {
    match cipher.trim().to_ascii_uppercase().as_str() {
        "" => "AES-128-GCM".to_string(),
        "AES-CBC" => "AES-128-CBC".to_string(),
        other => other.to_string(),
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(ConfigError::new(message))
}

fn seconds(f: &mut Fields<'_>, key: &str, what: &str) -> Result<u64> {
    let value = f.i64(key)?;
    u64::try_from(value).or_else(|_| invalid(format!("openvpn {what} must be non-negative")))
}

/// mihomo's `ClientConfig.Prepare` and `ValidateInstallScriptSubset`; every refusal there fails
/// the node, so each is a hard error here.
pub(super) fn parse(f: &mut Fields<'_>) -> Result<OpenVpnOpts> {
    let server = f.req_string("server")?.trim().to_string();
    let port = f.req_u16("port")?;
    if server.is_empty() || port == 0 {
        return invalid("openvpn config requires remote host and port");
    }
    let tcp = match f.string("proto")?.trim().to_ascii_lowercase().as_str() {
        "" | "udp" | "udp4" => false,
        "tcp" | "tcp-client" | "tcp4" | "tcp4-client" => true,
        other => {
            return invalid(format!(
                "unsupported openvpn proto {other:?}: only udp and tcp are supported"
            ));
        }
    };
    let dev = f.string("dev")?.trim().to_ascii_lowercase();
    if !dev.is_empty() && dev != "tun" {
        return invalid(format!(
            "unsupported openvpn dev {dev:?}: only dev tun is supported"
        ));
    }
    let cipher = normalize_openvpn_cipher(&f.string("cipher")?);
    if !OPENVPN_CIPHERS.contains(&cipher.as_str()) {
        return invalid(format!("unsupported openvpn cipher {cipher:?}"));
    }
    let auth = match f.string("auth")?.trim().to_ascii_uppercase().as_str() {
        "" => "SHA256".to_string(),
        "SHA-1" => "SHA1".to_string(),
        other => other.to_string(),
    };
    if !OPENVPN_AUTHS.contains(&auth.as_str()) {
        return invalid(format!("unsupported openvpn auth {auth:?}"));
    }
    let key_direction = f.string("key-direction")?;
    if !matches!(key_direction.as_str(), "" | "0" | "1") {
        return invalid(format!(
            "unsupported openvpn key-direction {key_direction:?}: only '1' and '0' are supported"
        ));
    }
    let tran_window = if f.has("tran-window") {
        Some(seconds(f, "tran-window", "tran-window")?)
    } else {
        None
    };
    let mut out = OpenVpnOpts {
        server,
        port,
        tcp,
        cipher,
        data_ciphers: f
            .strings("data-ciphers")?
            .iter()
            .flat_map(|list| list.split(':'))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect(),
        data_ciphers_fallback: f.string("data-ciphers-fallback")?,
        auth,
        comp_lzo: matches!(
            f.string("comp-lzo")?.trim().to_ascii_lowercase().as_str(),
            "yes" | "adaptive"
        ),
        ca: f.req_string("ca")?,
        cert: f.string("cert")?,
        key: f.string("key")?,
        tls_auth: f.string("tls-auth")?,
        key_direction,
        tls_crypt: f.string("tls-crypt")?,
        tls_crypt_v2: f.string("tls-crypt-v2")?,
        username: f.string("username")?,
        password: f.string("password")?,
        peer_info: f.string_map("peer-info")?,
        ping: seconds(f, "ping", "ping interval")?,
        ping_restart: seconds(f, "ping-restart", "ping restart")?,
        tran_window,
        handshake_timeout: seconds(f, "handshake-timeout", "handshake timeout")?,
        mtu: f.u32("mtu")?,
        remote_dns_resolve: f.boolean("remote-dns-resolve")?,
        dns: f.strings("dns")?,
        ..OpenVpnOpts::default()
    };
    if let Some(mut stack) = f.sub("ip-stack")? {
        out.ip_stack_congestion_controller = stack.string("congestion-controller")?;
    }
    if f.raw("udp") == Some(&Value::Bool(false)) {
        f.warn("udp", "an OpenVPN node always carries UDP, as in mihomo");
    }
    check_credentials(&out)?;
    Ok(out)
}

fn check_credentials(out: &OpenVpnOpts) -> Result<()> {
    let set = |text: &str| !text.trim().is_empty();
    if set(&out.tls_auth) && set(&out.tls_crypt) {
        return invalid("openvpn tls-auth and tls-crypt are mutually exclusive");
    }
    if set(&out.tls_crypt_v2) && (set(&out.tls_auth) || set(&out.tls_crypt)) {
        return invalid("openvpn tls-crypt-v2 is mutually exclusive with tls-auth and tls-crypt");
    }
    if !set(&out.ca) {
        return invalid("openvpn config requires inline <ca> block");
    }
    if set(&out.cert) || set(&out.key) {
        if !set(&out.cert) || !set(&out.key) {
            return invalid(
                "openvpn cert and key must both be set when using client certificate auth",
            );
        }
    } else if !set(&out.username) {
        return invalid("openvpn requires either cert+key or username (auth-user-pass)");
    }
    Ok(())
}
