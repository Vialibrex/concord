use std::io;

use rand::RngExt;

use crate::http1::invalid;

pub(crate) const PLACEMENT_QUERY_IN_HEADER: &str = "queryInHeader";
pub(crate) const PLACEMENT_COOKIE: &str = "cookie";
pub(crate) const PLACEMENT_HEADER: &str = "header";
pub(crate) const PLACEMENT_QUERY: &str = "query";
pub(crate) const PLACEMENT_PATH: &str = "path";
pub(crate) const PLACEMENT_BODY: &str = "body";
pub(crate) const PLACEMENT_AUTO: &str = "auto";

/// Everything `xhttp-opts` sets, as the strings the YAML carries; ranges and
/// defaults are resolved when the client is built.
#[derive(Clone, Debug, Default)]
pub struct XhttpOptions {
    /// The `Host` of every request: `host`, else the SNI, else the server, with
    /// IPv6 literals in brackets.
    pub host: String,
    pub path: String,
    pub mode: String,
    pub headers: Vec<(String, String)>,
    pub no_grpc_header: bool,
    pub x_padding_bytes: String,
    pub x_padding_obfs_mode: bool,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_placement: String,
    pub x_padding_method: String,
    pub uplink_http_method: String,
    pub session_placement: String,
    pub session_key: String,
    pub session_table: String,
    pub session_length: String,
    pub seq_placement: String,
    pub seq_key: String,
    pub uplink_data_placement: String,
    pub uplink_data_key: String,
    pub uplink_chunk_size: String,
    pub sc_max_each_post_bytes: String,
    pub sc_min_posts_interval_ms: String,
    pub reuse: Option<XhttpReuse>,
    /// `reuse-settings.h-keep-alive-period` in seconds: 0 for the default, negative to disable.
    pub keep_alive_period: i64,
    /// `alpn` is exactly `[http/1.1]`.
    pub http1: bool,
    /// The TLS layer is REALITY, which makes `auto` pick a streaming mode.
    pub has_reality: bool,
}

/// XMUX: how connections are shared between dials.
#[derive(Clone, Debug, Default)]
pub struct XhttpReuse {
    pub max_concurrency: String,
    pub max_connections: String,
    pub c_max_reuse_times: String,
    pub h_max_request_times: String,
    pub h_max_reusable_secs: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Range {
    pub min: usize,
    pub max: usize,
}

impl Range {
    pub fn rand(self) -> usize {
        if self.min == self.max {
            return self.min;
        }
        rand::rng().random_range(self.min..=self.max)
    }
}

pub(crate) fn parse_range(text: &str, fallback: &str) -> io::Result<Range> {
    let text = if text.trim().is_empty() {
        fallback
    } else {
        text
    };
    let number = |s: &str| {
        s.trim()
            .parse::<usize>()
            .map_err(|_| invalid(format!("invalid range: {text}")))
    };
    let parts: Vec<&str> = text.trim().split('-').collect();
    match parts.as_slice() {
        [one] => {
            let value = number(one)?;
            Ok(Range {
                min: value,
                max: value,
            })
        }
        [lo, hi] => {
            let (min, max) = (number(lo)?, number(hi)?);
            if max < min {
                return Err(invalid(format!("invalid range: {text}")));
            }
            Ok(Range { min, max })
        }
        _ => Err(invalid(format!("invalid range: {text}"))),
    }
}

fn nonzero(range: Range, name: &str) -> io::Result<Range> {
    if range.max == 0 {
        return Err(invalid(format!(
            "invalid {name}: must be greater than zero"
        )));
    }
    Ok(range)
}

/// `xhttp.Config` after its `GetNormalized*` helpers.
#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub x_padding_bytes: Range,
    pub sc_max_each_post_bytes: Range,
    pub sc_min_posts_interval_ms: Range,
    pub uplink_chunk_size: Range,
    pub session_placement: String,
    pub seq_placement: String,
    pub data_placement: String,
    pub session_key: String,
    pub seq_key: String,
    pub method: String,
}

impl Settings {
    pub fn resolve(opts: &XhttpOptions) -> io::Result<Settings> {
        let x_padding_bytes = parse_range(&opts.x_padding_bytes, "100-1000")
            .map_err(|e| invalid(format!("invalid x-padding-bytes: {e}")))?;
        let sc_max_each_post_bytes = nonzero(
            parse_range(&opts.sc_max_each_post_bytes, "1000000")
                .map_err(|e| invalid(format!("invalid sc-max-each-post-bytes: {e}")))?,
            "sc-max-each-post-bytes",
        )?;
        let sc_min_posts_interval_ms = nonzero(
            parse_range(&opts.sc_min_posts_interval_ms, "30")
                .map_err(|e| invalid(format!("invalid sc-min-posts-interval-ms: {e}")))?,
            "sc-min-posts-interval-ms",
        )?;
        let or = |value: &str, fallback: &str| {
            if value.is_empty() { fallback } else { value }.to_string()
        };
        let session_placement = or(&opts.session_placement, PLACEMENT_PATH);
        let seq_placement = or(&opts.seq_placement, PLACEMENT_PATH);
        let data_placement = or(&opts.uplink_data_placement, PLACEMENT_BODY);
        let key_for = |explicit: &str, placement: &str, header: &str| {
            if !explicit.is_empty() {
                return explicit.to_string();
            }
            match placement {
                PLACEMENT_HEADER => header.to_string(),
                PLACEMENT_COOKIE | PLACEMENT_QUERY => header.replace("X-", "x_").to_lowercase(),
                _ => String::new(),
            }
        };
        let session_key = key_for(&opts.session_key, &session_placement, "X-Session");
        let seq_key = key_for(&opts.seq_key, &seq_placement, "X-Seq");
        let uplink_chunk_size = {
            let range = parse_range(&opts.uplink_chunk_size, "0")
                .map_err(|e| invalid(format!("invalid uplink-chunk-size: {e}")))?;
            if range.max == 0 {
                match data_placement.as_str() {
                    PLACEMENT_COOKIE => Range {
                        min: 2 * 1024,
                        max: 3 * 1024,
                    },
                    PLACEMENT_HEADER => Range {
                        min: 3 * 1024,
                        max: 4 * 1024,
                    },
                    _ => sc_max_each_post_bytes,
                }
            } else if range.min < 64 {
                Range {
                    min: 64,
                    max: range.max.max(64),
                }
            } else {
                range
            }
        };
        let method = or(&opts.uplink_http_method, "POST");
        Ok(Settings {
            x_padding_bytes,
            sc_max_each_post_bytes,
            sc_min_posts_interval_ms,
            uplink_chunk_size,
            session_placement,
            seq_placement,
            data_placement,
            session_key,
            seq_key,
            method,
        })
    }
}

pub(crate) fn effective_mode(opts: &XhttpOptions, has_download: bool) -> &str {
    match opts.mode.as_str() {
        "" | "auto" => {
            if opts.has_reality {
                if has_download {
                    "stream-up"
                } else {
                    "stream-one"
                }
            } else {
                "packet-up"
            }
        }
        other => other,
    }
}

pub(crate) fn normalized_path(opts: &XhttpOptions, settings: &Settings) -> String {
    let mut path = if opts.path.is_empty() {
        "/".to_string()
    } else {
        opts.path.clone()
    };
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if (settings.session_placement == PLACEMENT_PATH || settings.seq_placement == PLACEMENT_PATH)
        && !path.ends_with('/')
    {
        path.push('/');
    }
    path
}

const PREDEFINED_TABLES: [(&str, &str); 9] = [
    ("ALPHABET", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    (
        "Alphabet",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    ),
    ("BASE36", "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    (
        "Base62",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    ),
    ("HEX", "0123456789ABCDEF"),
    ("alphabet", "abcdefghijklmnopqrstuvwxyz"),
    ("base36", "0123456789abcdefghijklmnopqrstuvwxyz"),
    ("hex", "0123456789abcdef"),
    ("number", "0123456789"),
];

/// Builds `GetGenerateSessionID`: 32 hex characters, a UUID, or characters drawn
/// from a table.
pub(crate) fn session_id_generator(opts: &XhttpOptions) -> io::Result<SessionIds> {
    match opts.session_table.as_str() {
        "" => Ok(SessionIds::Hex),
        "uuid" => Ok(SessionIds::Uuid),
        table => {
            let table = PREDEFINED_TABLES
                .iter()
                .find(|(name, _)| *name == table)
                .map_or(table, |(_, chars)| chars);
            let length = parse_range(&opts.session_length, "16-32")
                .map_err(|e| invalid(format!("invalid session-length: {e}")))?;
            let base = table.len() as u128;
            let mut room: u128 = 0;
            for k in length.min..=length.max {
                room = room.saturating_add(base.saturating_pow(k.min(64) as u32));
            }
            if room < (2u128 << 30) {
                return Err(invalid("session-table or session-length is too small"));
            }
            if length.min == 0 {
                return Err(invalid("session-length must be greater than 0"));
            }
            if !table.is_ascii() {
                return Err(invalid("session-table must contain only ASCII characters"));
            }
            Ok(SessionIds::Table {
                table: table.as_bytes().to_vec(),
                length,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum SessionIds {
    Hex,
    Uuid,
    Table { table: Vec<u8>, length: Range },
}

impl SessionIds {
    pub fn generate(&self) -> String {
        let mut rng = rand::rng();
        match self {
            SessionIds::Hex => {
                let bytes: [u8; 16] = rng.random();
                bytes.iter().map(|b| format!("{b:02x}")).collect()
            }
            SessionIds::Uuid => {
                let mut bytes: [u8; 16] = rng.random();
                if let Some(b) = bytes.get_mut(6) {
                    *b = (*b & 0x0F) | 0x40;
                }
                if let Some(b) = bytes.get_mut(8) {
                    *b = (*b & 0x3F) | 0x80;
                }
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                format!(
                    "{}-{}-{}-{}-{}",
                    hex.get(0..8).unwrap_or_default(),
                    hex.get(8..12).unwrap_or_default(),
                    hex.get(12..16).unwrap_or_default(),
                    hex.get(16..20).unwrap_or_default(),
                    hex.get(20..32).unwrap_or_default()
                )
            }
            SessionIds::Table { table, length } => (0..length.rand())
                .filter_map(|_| table.get(rng.random_range(0..table.len())))
                .map(|b| char::from(*b))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_like_go() {
        assert_eq!(
            parse_range("", "100-1000").unwrap(),
            Range {
                min: 100,
                max: 1000
            }
        );
        assert_eq!(parse_range("5", "0").unwrap(), Range { min: 5, max: 5 });
        assert_eq!(
            parse_range(" 2 - 4 ", "0").unwrap(),
            Range { min: 2, max: 4 }
        );
        assert!(parse_range("4-2", "0").is_err());
        assert!(parse_range("a", "0").is_err());
        assert!(parse_range("1-2-3", "0").is_err());
        assert!(parse_range("-1", "0").is_err());
    }

    #[test]
    fn defaults_and_keys_follow_the_client() {
        let settings = Settings::resolve(&XhttpOptions::default()).unwrap();
        assert_eq!(
            settings.sc_max_each_post_bytes,
            Range {
                min: 1_000_000,
                max: 1_000_000
            }
        );
        assert_eq!(
            settings.sc_min_posts_interval_ms,
            Range { min: 30, max: 30 }
        );
        assert_eq!(settings.session_placement, "path");
        assert_eq!(settings.data_placement, "body");
        assert_eq!(settings.session_key, "");
        assert_eq!(settings.method, "POST");

        let opts = XhttpOptions {
            session_placement: "header".into(),
            seq_placement: "cookie".into(),
            uplink_data_placement: "header".into(),
            ..XhttpOptions::default()
        };
        let settings = Settings::resolve(&opts).unwrap();
        assert_eq!(settings.session_key, "X-Session");
        assert_eq!(settings.seq_key, "x_seq");
        assert_eq!(
            settings.uplink_chunk_size,
            Range {
                min: 3072,
                max: 4096
            }
        );
    }

    #[test]
    fn path_gets_a_trailing_slash_only_when_the_path_carries_ids() {
        let opts = XhttpOptions {
            path: "xh".into(),
            ..XhttpOptions::default()
        };
        let settings = Settings::resolve(&opts).unwrap();
        assert_eq!(normalized_path(&opts, &settings), "/xh/");
        let opts = XhttpOptions {
            path: "/xh".into(),
            session_placement: "query".into(),
            seq_placement: "header".into(),
            ..XhttpOptions::default()
        };
        let settings = Settings::resolve(&opts).unwrap();
        assert_eq!(normalized_path(&opts, &settings), "/xh");
    }

    #[test]
    fn auto_mode_depends_on_reality_and_download_settings() {
        let mut opts = XhttpOptions::default();
        assert_eq!(effective_mode(&opts, false), "packet-up");
        opts.has_reality = true;
        assert_eq!(effective_mode(&opts, false), "stream-one");
        assert_eq!(effective_mode(&opts, true), "stream-up");
        opts.mode = "packet-up".into();
        assert_eq!(effective_mode(&opts, true), "packet-up");
    }

    #[test]
    fn session_ids() {
        let hex = SessionIds::Hex.generate();
        assert_eq!(hex.len(), 32);
        let uuid = SessionIds::Uuid.generate();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.as_bytes().get(14), Some(&b'4'));
        let opts = XhttpOptions {
            session_table: "number".into(),
            session_length: "12".into(),
            ..XhttpOptions::default()
        };
        let id = session_id_generator(&opts).unwrap().generate();
        assert_eq!(id.len(), 12);
        assert!(id.bytes().all(|b| b.is_ascii_digit()));
        let small = XhttpOptions {
            session_table: "number".into(),
            session_length: "2".into(),
            ..XhttpOptions::default()
        };
        assert!(session_id_generator(&small).is_err());
    }
}
