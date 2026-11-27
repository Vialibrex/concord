use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, ReadBuf};

const MAX_HEAD: usize = 10 << 20;
const READ_CHUNK: usize = 4096;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) fn canonical_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut upper = true;
    for ch in key.chars() {
        if upper {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push(ch.to_ascii_lowercase());
        }
        upper = ch == '-';
    }
    out
}

/// Headers as `net/http` writes them: canonical keys, sorted, values of one key
/// in insertion order.
#[derive(Clone, Debug, Default)]
pub(crate) struct HeaderMap {
    entries: Vec<(String, String)>,
}

impl HeaderMap {
    pub fn add(&mut self, key: &str, value: &str) {
        self.entries.push((canonical_key(key), value.to_string()));
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.remove(key);
        self.add(key, value);
    }

    pub fn set_exact(&mut self, key: &str, value: &str) {
        self.remove(key);
        self.entries.push((key.to_string(), value.to_string()));
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn write_sorted(&self, out: &mut Vec<u8>, skip: &[&str]) {
        let mut order: Vec<usize> = (0..self.entries.len()).collect();
        order.sort_by(|a, b| {
            let ka = self.entries.get(*a).map(|(k, _)| k.as_str());
            let kb = self.entries.get(*b).map(|(k, _)| k.as_str());
            ka.cmp(&kb).then(a.cmp(b))
        });
        for idx in order {
            let Some((key, value)) = self.entries.get(idx) else {
                continue;
            };
            if skip.iter().any(|s| s.eq_ignore_ascii_case(key)) {
                continue;
            }
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(clean_value(value).as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
}

fn clean_value(value: &str) -> String {
    value
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

pub(crate) struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    pub fn parse(head: &[u8]) -> io::Result<ResponseHead> {
        let text = std::str::from_utf8(head).map_err(|_| invalid("response head is not UTF-8"))?;
        let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        let status_line = lines.next().ok_or_else(|| invalid("empty response"))?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/") {
            return Err(invalid(format!("malformed HTTP response {status_line:?}")));
        }
        let status = parts
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| invalid(format!("malformed HTTP status {status_line:?}")))?;
        let reason = parts.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| invalid(format!("malformed MIME header line {line:?}")))?;
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
        Ok(ResponseHead {
            status,
            reason,
            headers,
        })
    }
}

/// Reads up to the blank line that ends an HTTP head and keeps whatever was read
/// past it, so a stream can carry on from there.
pub(crate) struct HeadReader {
    buf: Vec<u8>,
    scan: HeadScan,
    limit: usize,
}

impl Default for HeadReader {
    fn default() -> Self {
        HeadReader::with_limit(MAX_HEAD)
    }
}

impl HeadReader {
    pub fn with_limit(limit: usize) -> Self {
        HeadReader {
            buf: Vec::new(),
            scan: HeadScan::default(),
            limit,
        }
    }

    pub fn poll_head<S: AsyncRead + Unpin + ?Sized>(
        &mut self,
        cx: &mut Context<'_>,
        io: &mut S,
    ) -> Poll<io::Result<Vec<u8>>> {
        loop {
            if let Some(end) = self.scan.advance(&self.buf) {
                let rest = self.buf.split_off(end);
                let head = std::mem::replace(&mut self.buf, rest);
                self.scan = HeadScan::default();
                return Poll::Ready(Ok(head));
            }
            if self.buf.len() > self.limit {
                return Poll::Ready(Err(invalid("HTTP head too large")));
            }
            let mut chunk = [0u8; READ_CHUNK];
            let mut read = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut *io).poll_read(cx, &mut read))?;
            let filled = read.filled();
            if filled.is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.buf.extend_from_slice(filled);
        }
    }

    pub async fn read_head<S: AsyncRead + Unpin>(&mut self, io: &mut S) -> io::Result<Vec<u8>> {
        std::future::poll_fn(|cx| self.poll_head(cx, io)).await
    }

    pub fn into_rest(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
fn find_head_end(buf: &[u8]) -> Option<usize> {
    HeadScan::default().advance(buf)
}

/// Where a head scan stopped, so a head that arrives over many reads is scanned once.
struct HeadScan {
    line_start: usize,
    first: bool,
}

impl Default for HeadScan {
    fn default() -> Self {
        HeadScan {
            line_start: 0,
            first: true,
        }
    }
}

impl HeadScan {
    fn advance(&mut self, buf: &[u8]) -> Option<usize> {
        let from = self.line_start;
        for (offset, byte) in buf.get(from..)?.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            let idx = from + offset;
            let line = buf.get(self.line_start..idx)?;
            let blank = line.is_empty() || line == b"\r";
            if blank && !self.first {
                return Some(idx + 1);
            }
            self.first = false;
            self.line_start = idx + 1;
        }
        None
    }
}

pub(crate) fn percent_decode(input: &str) -> io::Result<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while let Some(&byte) = bytes.get(idx) {
        if byte == b'%' {
            let hi = bytes.get(idx + 1).and_then(|b| hex_val(*b));
            let lo = bytes.get(idx + 2).and_then(|b| hex_val(*b));
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(invalid(format!("invalid URL escape in {input:?}")));
            };
            out.push((hi << 4) | lo);
            idx += 3;
        } else {
            out.push(byte);
            idx += 1;
        }
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn push_escaped(out: &mut String, byte: u8) {
    let digit = |n: u8| {
        char::from_digit(u32::from(n), 16)
            .unwrap_or('0')
            .to_ascii_uppercase()
    };
    out.push('%');
    out.push(digit(byte >> 4));
    out.push(digit(byte & 15));
}

/// Go's `url.URL.EscapedPath` for a path that carries no `RawPath`.
pub(crate) fn escape_path(path: &[u8]) -> String {
    let mut out = String::with_capacity(path.len());
    for &byte in path {
        match byte {
            b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'$'
            | b'&'
            | b'+'
            | b','
            | b'/'
            | b':'
            | b';'
            | b'='
            | b'@' => out.push(char::from(byte)),
            _ => push_escaped(&mut out, byte),
        }
    }
    out
}

pub(crate) fn query_escape(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => push_escaped(&mut out, byte),
        }
    }
    out
}

pub(crate) fn query_unescape(value: &str) -> io::Result<Vec<u8>> {
    percent_decode(&value.replace('+', " "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_keys_follow_mime_rules() {
        assert_eq!(
            canonical_key("sec-websocket-protocol"),
            "Sec-Websocket-Protocol"
        );
        assert_eq!(canonical_key("USER-agent"), "User-Agent");
    }

    #[test]
    fn head_end_accepts_bare_newlines() {
        assert_eq!(
            find_head_end(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nrest"),
            Some(25)
        );
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\nA: b\n\nrest"), Some(22));
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\nA: b\r\n"), None);
    }

    #[test]
    fn response_head_parses() {
        let head =
            ResponseHead::parse(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")
                .unwrap();
        assert_eq!(head.status, 101);
        assert_eq!(head.header("upgrade"), Some("websocket"));
        assert!(ResponseHead::parse(b"garbage\r\n\r\n").is_err());
    }

    #[test]
    fn path_round_trips_like_go() {
        let decoded = percent_decode("/a%20b/%E4%B8%AD").unwrap();
        assert_eq!(escape_path(&decoded), "/a%20b/%E4%B8%AD");
        assert!(percent_decode("/bad%zz").is_err());
        assert_eq!(query_escape(b"a b&c"), "a+b%26c");
    }
}
