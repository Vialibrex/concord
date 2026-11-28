use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngExt;

const MAX_PACKET: usize = 65_535;
const MAX_RANDOM: usize = 1000;
const MAX_WAIT_MS: u64 = 5000;
const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const DIGITS: &[u8] = b"0123456789";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Piece {
    Bytes(Vec<u8>),
    Counter,
    Time(usize),
    Random(usize),
    Chars(usize, &'static [u8]),
    Wait(Duration),
}

impl Piece {
    fn len(&self) -> usize {
        match self {
            Piece::Bytes(bytes) => bytes.len(),
            Piece::Counter => 8,
            Piece::Time(width) => *width,
            Piece::Random(n) | Piece::Chars(n, _) => *n,
            Piece::Wait(_) => 0,
        }
    }
}

/// One of the I1 to I5 or J1 to J3 packets: a chain of generated pieces that is sent as a datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Template {
    pieces: Vec<Piece>,
}

impl Template {
    pub(super) fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }

    pub(super) async fn render(&self, counter: &AtomicU64) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.pieces.iter().map(Piece::len).sum());
        for piece in &self.pieces {
            match piece {
                Piece::Bytes(bytes) => out.extend_from_slice(bytes),
                Piece::Counter => {
                    out.extend_from_slice(&counter.load(Ordering::Relaxed).to_be_bytes())
                }
                Piece::Time(width) => {
                    let secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |elapsed| elapsed.as_secs());
                    let bytes = secs.to_be_bytes();
                    let start = bytes.len().saturating_sub(*width);
                    out.extend_from_slice(bytes.get(start..).unwrap_or_default());
                }
                Piece::Random(n) => {
                    let at = out.len();
                    out.resize(at + n, 0);
                    if let Some(slot) = out.get_mut(at..) {
                        rand::rng().fill(slot);
                    }
                }
                Piece::Chars(n, alphabet) => push_chars(&mut out, *n, alphabet),
                Piece::Wait(delay) => tokio::time::sleep(*delay).await,
            }
        }
        out
    }
}

fn push_chars(out: &mut Vec<u8>, n: usize, alphabet: &[u8]) {
    let mut rng = rand::rng();
    for _ in 0..n {
        let pick = rng.random_range(0..alphabet.len());
        out.push(alphabet.get(pick).copied().unwrap_or(b'0'));
    }
}

fn hex_bytes(text: &str, what: &str) -> Result<Vec<u8>, String> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let padded;
    let digits = if digits.len() % 2 == 1 {
        padded = format!("0{digits}");
        padded.as_str()
    } else {
        digits
    };
    hex::decode(digits).map_err(|err| format!("{what}: {err}"))
}

fn size(param: &str, limit: usize, what: &str) -> Result<usize, String> {
    let n: usize = param
        .trim()
        .parse()
        .map_err(|_| format!("{what}: {param:?} is not a size"))?;
    if n > limit {
        return Err(format!("{what}: size must not exceed {limit}"));
    }
    Ok(n)
}

fn finish(pieces: Vec<Piece>) -> Result<Template, String> {
    let total: usize = pieces.iter().map(Piece::len).sum();
    if total > MAX_PACKET {
        return Err("the packet is larger than a UDP datagram".to_string());
    }
    Ok(Template { pieces })
}

/// The tag language of AmneziaWG 1.x: `<b 0x..><c><t><r 10><rc 5><rd 5><wt 100>`.
pub(super) fn parse_legacy(value: &str) -> Result<Template, String> {
    let mut parts = value.split('<');
    parts.next();
    let parts: Vec<&str> = parts.collect();
    if parts.is_empty() {
        return Err(format!("empty input: {value}"));
    }
    let mut pieces = Vec::with_capacity(parts.len());
    let (mut counter, mut time) = (false, false);
    for part in parts {
        if part.len() <= 1 {
            return Err(format!("empty tag in input: {value}"));
        }
        if part.matches('>').count() != 1 {
            return Err(format!("ill formated input: {value}"));
        }
        let body = part.split('>').next().unwrap_or_default();
        let body = body.trim_start_matches(|c: char| !c.is_ascii_alphabetic());
        let name_end = body
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(body.len());
        let (name, rest) = body.split_at(name_end);
        let param = rest.trim();
        let once = |seen: &mut bool| {
            if std::mem::replace(seen, true) {
                Err(format!("tag {name} needs to be unique"))
            } else {
                Ok(())
            }
        };
        pieces.push(match name {
            "b" => {
                if !(param.starts_with("0x") || param.starts_with("0X")) {
                    return Err(format!("not correct hex: {param}"));
                }
                Piece::Bytes(hex_bytes(param, "hexToBytes")?)
            }
            "c" => {
                once(&mut counter)?;
                if !param.is_empty() {
                    return Err(format!("packet counter param needs to be empty: {param}"));
                }
                Piece::Counter
            }
            "t" => {
                once(&mut time)?;
                if !param.is_empty() {
                    return Err(format!("timestamp param needs to be empty: {param}"));
                }
                Piece::Time(8)
            }
            "r" => Piece::Random(size(param, MAX_RANDOM, "random bytes")?),
            "rc" => Piece::Chars(size(param, MAX_RANDOM, "random ascii")?, ALPHANUMERIC),
            "rd" => Piece::Chars(size(param, MAX_RANDOM, "random digit")?, DIGITS),
            "wt" => {
                let ms: u64 = param
                    .parse()
                    .map_err(|_| format!("timeout parse int: {param:?}"))?;
                if ms > MAX_WAIT_MS {
                    return Err("timeout must be less than 5000ms".to_string());
                }
                Piece::Wait(Duration::from_millis(ms))
            }
            other => return Err(format!("invalid tag: {other}")),
        });
    }
    finish(pieces)
}

/// The obfuscation chains of AmneziaWG 2 and later: `<b 0x..><t><r 10><rc 5><rd 5><dz 2>`. The
/// data tags carry nothing in the packets that precede a handshake.
pub(super) fn parse_chain(value: &str) -> Result<Template, String> {
    let mut pieces = Vec::new();
    let mut errors = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let Some(end) = rest.get(start..).and_then(|tail| tail.find('>')) else {
            return Err("missing enclosing >".to_string());
        };
        let end = start + end;
        let tag = rest.get(start + 1..end).unwrap_or_default();
        rest = rest.get(end + 1..).unwrap_or_default();
        let mut fields = tag.split_whitespace();
        let Some(name) = fields.next() else {
            errors.push("empty tag".to_string());
            continue;
        };
        let param = fields.next().unwrap_or_default();
        let built = match name {
            "b" => {
                let digits = param.strip_prefix("0x").unwrap_or(param);
                if digits.is_empty() {
                    Err("empty argument".to_string())
                } else if digits.len() % 2 != 0 {
                    Err("odd amount of symbols".to_string())
                } else {
                    hex::decode(digits)
                        .map(Piece::Bytes)
                        .map_err(|err| err.to_string())
                }
            }
            "t" => Ok(Piece::Time(4)),
            "r" => size(param, MAX_PACKET, "r").map(Piece::Random),
            "rc" => size(param, MAX_PACKET, "rc").map(|n| Piece::Chars(n, LETTERS)),
            "rd" => size(param, MAX_PACKET, "rd").map(|n| Piece::Chars(n, DIGITS)),
            "dz" => size(param, MAX_PACKET, "dz").map(|n| Piece::Bytes(vec![0; n])),
            "d" | "ds" => Ok(Piece::Bytes(Vec::new())),
            other => Err(format!("unknown tag <{other}>")),
        };
        match built {
            Ok(piece) => pieces.push(piece),
            Err(err) => errors.push(format!("failed to build <{name}>: {err}")),
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    finish(pieces)
}
