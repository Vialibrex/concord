use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{ConfigError, Result};

#[derive(Clone, Copy)]
enum Mode {
    Host,
    Zone,
}

fn valid_optional_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
}

fn is_host_ascii(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]<>\"".contains(&b)
}

fn hex_value(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

fn escape_slice(s: &str, bytes: &[u8], start: usize) -> String {
    let end = (start + 3).min(bytes.len());
    s.get(start..end).map_or_else(
        || String::from_utf8_lossy(bytes.get(start..end).unwrap_or_default()).into_owned(),
        str::to_owned,
    )
}

fn unescape_host_part(s: &str, mode: Mode) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let Some((hi, lo)) = bytes.get(i + 1..i + 3).and_then(|pair| match pair {
                [first, second] => Some((hex_value(*first)?, hex_value(*second)?)),
                _ => None,
            }) else {
                let esc = escape_slice(s, bytes, i);
                return Err(ConfigError::new(format!("invalid URL escape {esc:?}")));
            };
            let decoded = (hi << 4) | lo;
            let allowed = match mode {
                Mode::Host => hi >= 8 || decoded == b'%',
                Mode::Zone => decoded == b'%' || decoded == b' ' || is_host_ascii(decoded),
            };
            if !allowed {
                let esc = escape_slice(s, bytes, i);
                return Err(ConfigError::new(format!("invalid URL escape {esc:?}")));
            }
            out.push(decoded);
            i += 3;
        } else {
            if b < 0x80 && !is_host_ascii(b) {
                let ch = s.get(i..i + 1).unwrap_or_default();
                return Err(ConfigError::new(format!(
                    "invalid character {ch:?} in host name"
                )));
            }
            out.push(b);
            i += 1;
        }
    }
    // Deliberate difference from Go's net/url: Concord rejects decoded bytes that are not valid
    // UTF-8 at load time because Rust Strings and YAML proxy names are UTF-8, so such a host can
    // never match a node.
    String::from_utf8(out).map_err(|_| ConfigError::new("invalid UTF-8 in host name"))
}

/// Decodes a URL authority host the way Go's `net/url.Parse` (`parseHost` and
/// `unescape(..., encodeHost)`) does when mihomo reads `u.Host`.
pub(super) fn parse_url_host(host: &str) -> Result<String> {
    if host.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ConfigError::new(
            "net/url: invalid control character in URL",
        ));
    }
    if let Some(open) = host.rfind('[') {
        if open > 0 {
            return Err(ConfigError::new("invalid IP-literal"));
        }
        let Some(close) = host.rfind(']') else {
            return Err(ConfigError::new("missing ']' in host"));
        };
        let colon_port = host.get(close + 1..).unwrap_or_default();
        if !valid_optional_port(colon_port) {
            return Err(ConfigError::new(format!(
                "invalid port {colon_port:?} after host"
            )));
        }
        let unescaped_port = unescape_host_part(colon_port, Mode::Host)?;
        let inner = host.get(1..close).unwrap_or_default();
        let (host_part, zone_part) = match inner.find("%25") {
            Some(zone_idx) => (
                unescape_host_part(inner.get(..zone_idx).unwrap_or_default(), Mode::Host)?,
                unescape_host_part(inner.get(zone_idx..).unwrap_or_default(), Mode::Zone)?,
            ),
            None => (unescape_host_part(inner, Mode::Host)?, String::new()),
        };
        if !zone_part.is_empty() && zone_part.len() <= 1 {
            return Err(ConfigError::new("invalid host"));
        }
        if zone_part.is_empty() && host_part.parse::<Ipv4Addr>().is_ok() {
            return Err(ConfigError::new("invalid IP-literal"));
        }
        host_part
            .parse::<Ipv6Addr>()
            .map_err(|_| ConfigError::new("invalid host"))?;
        return Ok(format!("[{host_part}{zone_part}]{unescaped_port}"));
    }
    if let Some(colon) = host.rfind(':') {
        let colon_port = host.get(colon..).unwrap_or_default();
        if !valid_optional_port(colon_port) {
            return Err(ConfigError::new(format!(
                "invalid port {colon_port:?} after host"
            )));
        }
    }
    unescape_host_part(host, Mode::Host)
}
