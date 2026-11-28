use std::io;
use std::sync::atomic::{AtomicU8, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use concord_common::{Address, CoreError};
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, StatusCode};
use indexmap::IndexMap;
use rand::RngExt;

use super::padding::PaddingType;
use crate::ctx::BuildError;

const PADDING: &str = "padding";
const PADDING_TYPE_REQUEST: &str = "padding-type-request";
const PADDING_TYPE_REPLY: &str = "padding-type-reply";
/// Variant1 first, then none, as naiveproxy offers them.
const OFFERED: &str = "1, 0";
/// The first 17 printable characters, by code, that HPACK's Huffman code spends at least 8 bits
/// on, so the value goes out as its length in raw octets; the 17th fills the tail
/// (naiveproxy `padding_utils.cc`, `InitializeNonindexCodes`).
pub(super) const NON_INDEX: &[u8; 17] = b"!\"#$&'()*+,;<>?@X";
const PADDING_MIN: usize = 16;
const PADDING_MAX: usize = 32;
const PADDING_UNIQUE: usize = 16;

/// naiveproxy's `padding` request value: up to 16 characters picked by 4 random bits each,
/// the rest the 17th character.
pub(super) fn padding_value() -> String {
    let mut rng = rand::rng();
    let len = rng.random_range(PADDING_MIN..=PADDING_MAX);
    let mut bits: u64 = rng.random();
    (0..len)
        .map(|i| {
            let index = if i < PADDING_UNIQUE {
                let index = (bits & 0b1111) as usize;
                bits >>= 4;
                index
            } else {
                NON_INDEX.len() - 1
            };
            char::from(NON_INDEX.get(index).copied().unwrap_or(b'X'))
        })
        .collect()
}

/// The fixed part of every CONNECT a node sends, in the order naiveproxy sends it: `padding`,
/// the node's own headers, `padding-type-request`, then `proxy-authorization`, which Chromium's
/// proxy auth adds after the tunnel's extra headers.
pub(super) struct Template {
    authorization: Option<HeaderValue>,
    extra: Vec<(HeaderName, HeaderValue)>,
}

impl Template {
    pub(super) fn new(
        username: &str,
        password: &str,
        headers: &IndexMap<String, String>,
    ) -> Result<Template, BuildError> {
        let authorization = (!username.is_empty())
            .then(|| {
                let token = STANDARD.encode(format!("{username}:{password}"));
                HeaderValue::try_from(format!("Basic {token}"))
            })
            .transpose()
            .map_err(|err| BuildError::invalid(format!("invalid naive credentials: {err}")))?;
        let extra = headers
            .iter()
            .map(|(name, value)| {
                let name = HeaderName::try_from(name.to_ascii_lowercase()).map_err(|err| {
                    BuildError::invalid(format!("invalid header name {name:?}: {err}"))
                })?;
                let value = HeaderValue::try_from(value.as_str()).map_err(|err| {
                    BuildError::invalid(format!("invalid value for header {name}: {err}"))
                })?;
                Ok((name, value))
            })
            .collect::<Result<_, BuildError>>()?;
        Ok(Template {
            authorization,
            extra,
        })
    }

    /// A user header of the same name replaces a built-in one in place, as cronet-go's map does.
    pub(super) fn request(&self, dst: &Address) -> io::Result<Request<()>> {
        let mut headers = HeaderMap::new();
        let padding = HeaderValue::try_from(padding_value()).map_err(io::Error::other)?;
        headers.insert(HeaderName::from_static(PADDING), padding);
        for (name, value) in &self.extra {
            headers.insert(name.clone(), value.clone());
        }
        if !headers.contains_key(PADDING_TYPE_REQUEST) {
            headers.insert(
                HeaderName::from_static(PADDING_TYPE_REQUEST),
                HeaderValue::from_static(OFFERED),
            );
        }
        if let Some(authorization) = &self.authorization
            && !headers.contains_key(http::header::PROXY_AUTHORIZATION)
        {
            headers.insert(http::header::PROXY_AUTHORIZATION, authorization.clone());
        }
        let mut request = Request::builder()
            .method(Method::CONNECT)
            .uri(dst.to_string())
            .body(())
            .map_err(io::Error::other)?;
        *request.headers_mut() = headers;
        Ok(request)
    }
}

/// What a CONNECT's answer says: the padding the server agreed to, or why the tunnel failed.
pub(super) fn reply(status: StatusCode, headers: &HeaderMap) -> io::Result<PaddingType> {
    match status {
        StatusCode::OK => {}
        StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "naive server refused the credentials (407)",
            ));
        }
        other => {
            return Err(CoreError::TargetRefused(format!("naive CONNECT failed: {other}")).into());
        }
    }
    match headers.get(PADDING_TYPE_REPLY) {
        None if headers.contains_key(PADDING) => Ok(PaddingType::Variant1),
        None => Ok(PaddingType::None),
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|text| PaddingType::parse(text.trim()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("naive server replied an unknown padding type {value:?}"),
                )
            }),
    }
}

/// The padding a node's server last agreed to; unknown until its first answer.
#[derive(Default)]
pub(super) struct Negotiated(AtomicU8);

const UNKNOWN: u8 = 0;
const NONE: u8 = 1;
const VARIANT1: u8 = 2;

impl Negotiated {
    pub(super) fn get(&self) -> Option<PaddingType> {
        match self.0.load(Ordering::Acquire) {
            NONE => Some(PaddingType::None),
            VARIANT1 => Some(PaddingType::Variant1),
            _ => None,
        }
    }

    pub(super) fn set(&self, padding: PaddingType) {
        let value = match padding {
            PaddingType::None => NONE,
            PaddingType::Variant1 => VARIANT1,
        };
        self.0.store(value, Ordering::Release);
    }

    pub(super) fn forget(&self) {
        self.0.store(UNKNOWN, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn padding_values_follow_naiveproxy() {
        for _ in 0..200 {
            let value = padding_value();
            assert!((PADDING_MIN..=PADDING_MAX).contains(&value.len()));
            assert!(value.bytes().all(|b| NON_INDEX.contains(&b)));
            assert!(value.bytes().skip(PADDING_UNIQUE).all(|b| b == b'X'));
            assert!(value.bytes().take(PADDING_UNIQUE).all(|b| b != b'X'));
        }
    }

    #[test]
    fn recorded_naiveproxy_padding_uses_the_same_characters() {
        let recorded: Vec<&str> = include_str!("testdata/naiveproxy-h2.txt")
            .lines()
            .filter_map(|line| line.strip_prefix("field 2 padding: "))
            .collect();
        assert_eq!(recorded.len(), 3);
        for value in recorded {
            assert!((PADDING_MIN..=PADDING_MAX).contains(&value.len()));
            let (unique, fill) = value.as_bytes().split_at(PADDING_UNIQUE);
            assert!(
                unique
                    .iter()
                    .all(|b| NON_INDEX[..PADDING_UNIQUE].contains(b))
            );
            assert!(fill.iter().all(|&b| b == NON_INDEX[PADDING_UNIQUE]));
        }
    }

    #[test]
    fn requests_carry_naiveproxy_headers_in_order() {
        let mut extra = IndexMap::new();
        extra.insert("X-Foo".to_string(), "bar".to_string());
        let template = Template::new("user", "pass", &extra).unwrap();
        let request = template
            .request(&Address::Domain("a.example.com".into(), 443))
            .unwrap();
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(request.uri().to_string(), "a.example.com:443");
        let names: Vec<&str> = request.headers().keys().map(HeaderName::as_str).collect();
        assert_eq!(
            names,
            [
                "padding",
                "x-foo",
                "padding-type-request",
                "proxy-authorization"
            ]
        );
        assert_eq!(
            request.headers()["proxy-authorization"],
            "Basic dXNlcjpwYXNz"
        );
        assert_eq!(request.headers()[PADDING_TYPE_REQUEST], OFFERED);
    }

    #[test]
    fn ipv6_targets_are_bracketed_and_anonymous_nodes_send_no_credentials() {
        let template = Template::new("", "", &IndexMap::new()).unwrap();
        let request = template
            .request(&Address::Socket("[2001:db8::1]:8443".parse().unwrap()))
            .unwrap();
        assert_eq!(request.uri().to_string(), "[2001:db8::1]:8443");
        assert!(!request.headers().contains_key("proxy-authorization"));
    }

    #[test]
    fn replies_negotiate_like_naiveproxy() {
        let mut headers = HeaderMap::new();
        assert_eq!(reply(StatusCode::OK, &headers).unwrap(), PaddingType::None);
        headers.insert(PADDING, HeaderValue::from_static("~~~"));
        assert_eq!(
            reply(StatusCode::OK, &headers).unwrap(),
            PaddingType::Variant1
        );
        headers.insert(PADDING_TYPE_REPLY, HeaderValue::from_static("0"));
        assert_eq!(reply(StatusCode::OK, &headers).unwrap(), PaddingType::None);
        headers.insert(PADDING_TYPE_REPLY, HeaderValue::from_static("7"));
        assert_eq!(
            reply(StatusCode::OK, &headers).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            reply(StatusCode::PROXY_AUTHENTICATION_REQUIRED, &headers)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(reply(StatusCode::BAD_GATEWAY, &headers).is_err());
    }
}
