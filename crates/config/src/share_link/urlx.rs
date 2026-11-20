use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use percent_encoding::percent_decode_str;

const LENIENT: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);

pub const STD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT);
pub const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT);

pub fn decode_base64_std(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    STD.decode(cleaned.as_bytes()).ok()
}

pub fn decode_base64_url(text: &str) -> Option<Vec<u8>> {
    let cleaned: String = text.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    URL_SAFE.decode(cleaned.as_bytes()).ok()
}

pub fn try_decode_base64(text: &str) -> Option<Vec<u8>> {
    STD.decode(text.as_bytes())
        .ok()
        .or_else(|| URL_SAFE.decode(text.as_bytes()).ok())
}

pub fn unescape(text: &str) -> String {
    percent_decode_str(text).decode_utf8_lossy().into_owned()
}

pub fn query_unescape(text: &str) -> String {
    unescape(&text.replace('+', " "))
}

#[derive(Clone, Debug, Default)]
pub struct Link {
    pub user: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub fragment: String,
}

impl Link {
    pub fn parse(text: &str) -> Option<Link> {
        if text.chars().any(char::is_control) {
            return None;
        }
        let (scheme, rest) = text.split_once("://")?;
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        {
            return None;
        }
        let (rest, fragment) = match rest.split_once('#') {
            Some((rest, fragment)) => (rest, unescape(fragment)),
            None => (rest, String::new()),
        };
        let (rest, query_text) = match rest.split_once('?') {
            Some((rest, query)) => (rest, Some(query)),
            None => (rest, None),
        };
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = rest.get(..authority_end)?;
        let path = rest.get(authority_end..)?.to_string();
        let (userinfo, hostport) = match authority.rsplit_once('@') {
            Some((user, host)) => (Some(user), host),
            None => (None, authority),
        };
        let (user, password) = match userinfo {
            Some(info) => match info.split_once(':') {
                Some((user, pass)) => (Some(unescape(user)), Some(unescape(pass))),
                None => (Some(unescape(info)), None),
            },
            None => (None, None),
        };
        let (host, port) = split_host_port(hostport)?;
        if hostport.chars().any(|c| c.is_control() || c == ' ') {
            return None;
        }
        let query = match query_text {
            Some(query) => parse_query(query)?,
            None => Vec::new(),
        };
        Some(Link {
            user,
            password,
            host,
            port,
            path,
            query,
            fragment,
        })
    }

    pub fn get(&self, key: &str) -> &str {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_default()
    }

    pub fn all(&self, key: &str) -> Vec<&str> {
        self.query
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn username(&self) -> &str {
        self.user.as_deref().unwrap_or_default()
    }
}

fn split_host_port(hostport: &str) -> Option<(String, String)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        return match after.strip_prefix(':') {
            Some(port) if port.bytes().all(|b| b.is_ascii_digit()) => {
                Some((host.to_string(), port.to_string()))
            }
            None if after.is_empty() => Some((host.to_string(), String::new())),
            _ => None,
        };
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => {
            if host.contains(':') {
                return Some((hostport.to_string(), String::new()));
            }
            Some((host.to_string(), port.to_string()))
        }
        Some(_) => None,
        None => Some((hostport.to_string(), String::new())),
    }
}

pub fn parse_query(query: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if pair.contains(';') {
            return None;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        out.push((query_unescape(key), query_unescape(value)));
    }
    Some(out)
}

pub fn unique_name(names: &mut std::collections::HashMap<String, u32>, name: &str) -> String {
    match names.get_mut(name) {
        Some(index) => {
            *index += 1;
            format!("{name}-{:02}", *index)
        }
        None => {
            names.insert(name.to_string(), 0);
            name.to_string()
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EscapeMode {
    UserPassword,
    Fragment,
    Query,
}

pub fn escape(text: &str, mode: EscapeMode) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        let keep = match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => true,
            b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
                EscapeMode::UserPassword => !matches!(byte, b'@' | b'/' | b'?' | b':'),
                EscapeMode::Fragment => true,
                EscapeMode::Query => false,
            },
            b'!' | b'(' | b')' | b'*' => mode == EscapeMode::Fragment,
            _ => false,
        };
        if keep {
            out.push(char::from(byte));
        } else if byte == b' ' && mode == EscapeMode::Query {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn encode_query(pairs: &std::collections::BTreeMap<String, String>) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                escape(k, EscapeMode::Query),
                escape(v, EscapeMode::Query)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}
