use std::io;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::RngExt;
use sha2::{Digest, Sha256};

const MAX_PADDING: i64 = 255;
const MAX_NONCE_LEN: i64 = 12;
const ROTATION_COUNT: i64 = 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NonceKind {
    Random,
    Printable,
    PrintableSubset,
    Fixed,
}

#[derive(Clone, Debug)]
pub(super) struct NoncePattern {
    pub(super) kind: NonceKind,
    pub(super) min_len: usize,
    pub(super) max_len: usize,
    pub(super) fixed: Vec<Vec<u8>>,
    pub(super) every_udp_packet: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Fragment {
    pub(super) enable: bool,
    pub(super) max_sleep_ms: u32,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LowEntropy {
    pub(super) mode: u8,
    pub(super) rotation: u8,
}

#[derive(Clone, Debug)]
pub(super) struct Pattern {
    pub(super) fragment: Fragment,
    pub(super) nonce: NoncePattern,
    pub(super) max_middle: usize,
    pub(super) max_end: usize,
    pub(super) low_entropy: Option<LowEntropy>,
}

#[derive(Default)]
struct Raw {
    seed: Option<i32>,
    unlock_all: bool,
    fragment_enable: Option<bool>,
    fragment_sleep: Option<i32>,
    nonce_kind: Option<i32>,
    nonce_every_udp: Option<bool>,
    nonce_min: Option<i32>,
    nonce_max: Option<i32>,
    nonce_hex: Vec<String>,
    pad_middle: Option<i32>,
    pad_end: Option<i32>,
    low_mode: Option<i32>,
    low_rotation: Option<i32>,
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

struct Fields<'a>(&'a [u8]);

fn bad(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("TrafficPattern is invalid: {message}"),
    )
}

impl<'a> Fields<'a> {
    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let (&byte, rest) = self.0.split_first()?;
            self.0 = rest;
            value |= u64::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn next(&mut self) -> io::Result<Option<(u64, Value<'a>)>> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let truncated = || bad("truncated protobuf");
        let tag = self.varint().ok_or_else(truncated)?;
        let value = match tag & 7 {
            0 => Value::Varint(self.varint().ok_or_else(truncated)?),
            1 => {
                self.take(8).ok_or_else(truncated)?;
                Value::Varint(0)
            }
            2 => {
                let len = usize::try_from(self.varint().ok_or_else(truncated)?)
                    .map_err(|_| truncated())?;
                Value::Bytes(self.take(len).ok_or_else(truncated)?)
            }
            5 => {
                self.take(4).ok_or_else(truncated)?;
                Value::Varint(0)
            }
            _ => return Err(bad("unsupported protobuf wire type")),
        };
        Ok(Some((tag >> 3, value)))
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }
}

fn int(value: &Value<'_>) -> Option<i32> {
    match value {
        Value::Varint(v) => Some(*v as i32),
        Value::Bytes(_) => None,
    }
}

fn parse_raw(bytes: &[u8]) -> io::Result<Raw> {
    let mut raw = Raw::default();
    let mut fields = Fields(bytes);
    while let Some((number, value)) = fields.next()? {
        match (number, &value) {
            (1, _) => raw.seed = int(&value),
            (2, Value::Varint(v)) => raw.unlock_all = *v != 0,
            (3, Value::Bytes(inner)) => {
                let mut inner = Fields(inner);
                while let Some((number, value)) = inner.next()? {
                    match number {
                        1 => raw.fragment_enable = int(&value).map(|v| v != 0),
                        2 => raw.fragment_sleep = int(&value),
                        _ => {}
                    }
                }
            }
            (4, Value::Bytes(inner)) => {
                let mut inner = Fields(inner);
                while let Some((number, value)) = inner.next()? {
                    match (number, &value) {
                        (1, _) => raw.nonce_kind = int(&value),
                        (2, _) => raw.nonce_every_udp = int(&value).map(|v| v != 0),
                        (3, _) => raw.nonce_min = int(&value),
                        (4, _) => raw.nonce_max = int(&value),
                        (5, Value::Bytes(text)) => raw
                            .nonce_hex
                            .push(String::from_utf8_lossy(text).into_owned()),
                        _ => {}
                    }
                }
            }
            (5, Value::Bytes(inner)) => {
                let mut inner = Fields(inner);
                while let Some((number, value)) = inner.next()? {
                    match number {
                        1 => raw.pad_middle = int(&value),
                        2 => raw.pad_end = int(&value),
                        _ => {}
                    }
                }
            }
            (6, Value::Bytes(inner)) => {
                let mut inner = Fields(inner);
                while let Some((number, value)) = inner.next()? {
                    match number {
                        1 => raw.low_mode = int(&value),
                        2 => raw.low_rotation = int(&value),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Ok(raw)
}

fn valid_rotation(value: i32) -> bool {
    (0..=15).contains(&value) || (value % 16 == 0 && (16..=240).contains(&value))
}

fn validate(raw: &Raw) -> io::Result<()> {
    if let Some(sleep) = raw.fragment_sleep
        && !(0..=100).contains(&sleep)
    {
        return Err(bad(&format!(
            "TCPFragment maxSleepMs {sleep} is out of range"
        )));
    }
    for (label, value) in [("minLen", raw.nonce_min), ("maxLen", raw.nonce_max)] {
        if let Some(v) = value
            && !(0..=MAX_NONCE_LEN as i32).contains(&v)
        {
            return Err(bad(&format!("NoncePattern {label} {v} is out of range")));
        }
    }
    if let (Some(min), Some(max)) = (raw.nonce_min, raw.nonce_max)
        && min > max
    {
        return Err(bad(&format!(
            "NoncePattern minLen {min} is greater than maxLen {max}"
        )));
    }
    for text in &raw.nonce_hex {
        let decoded = hex::decode(text).map_err(|_| {
            bad(&format!(
                "NoncePattern customHexStrings {text:?} is not a valid hex string"
            ))
        })?;
        if decoded.len() > MAX_NONCE_LEN as usize {
            return Err(bad("NoncePattern customHexStrings is longer than 12 bytes"));
        }
    }
    for (label, value) in [
        ("maxMiddlePaddingLen", raw.pad_middle),
        ("maxEndPaddingLen", raw.pad_end),
    ] {
        if let Some(v) = value
            && !(0..=MAX_PADDING as i32).contains(&v)
        {
            return Err(bad(&format!("PaddingPattern {label} {v} is out of range")));
        }
    }
    if let Some(mode) = raw.low_mode
        && !(0..=4).contains(&mode)
    {
        return Err(bad(&format!("LowEntropyPattern mode {mode} is invalid")));
    }
    if let Some(rotation) = raw.low_rotation
        && !valid_rotation(rotation)
    {
        return Err(bad(&format!(
            "LowEntropyPattern maskRotation {rotation} is invalid"
        )));
    }
    Ok(())
}

fn fixed_int(n: i64, hint: &str) -> i64 {
    if n <= 0 {
        return 0;
    }
    let digest = Sha256::digest(hint.as_bytes());
    let mut head = [0u8; 4];
    head.copy_from_slice(digest.get(..4).unwrap_or_default());
    head[0] &= 0x7f;
    i64::from(u32::from_be_bytes(head)) % n
}

impl Pattern {
    pub(super) fn parse(encoded: &str) -> io::Result<Pattern> {
        let bytes = if encoded.is_empty() {
            Vec::new()
        } else {
            STANDARD.decode(encoded).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("decode base64 string failed: {err}"),
                )
            })?
        };
        let raw = parse_raw(&bytes)?;
        validate(&raw)?;
        Ok(Pattern::effective(&raw))
    }

    fn effective(raw: &Raw) -> Pattern {
        let seed = i64::from(
            raw.seed
                .unwrap_or_else(|| rand::rng().random_range(0..i32::MAX)),
        );
        let unlock = raw.unlock_all;
        let hint = |label: &str| format!("{seed}:{label}");

        let fragment = Fragment {
            enable: raw
                .fragment_enable
                .unwrap_or_else(|| unlock && fixed_int(2, &hint("tcpFragment.enable")) == 1),
            max_sleep_ms: match raw.fragment_sleep {
                Some(v) => u32::try_from(v).unwrap_or(0),
                None if unlock => {
                    u32::try_from(fixed_int(100, &hint("tcpFragment.maxSleepMs")) + 1).unwrap_or(1)
                }
                None => 0,
            },
        };

        let kind = match raw.nonce_kind {
            Some(1) => NonceKind::Printable,
            Some(2) => NonceKind::PrintableSubset,
            Some(3) => NonceKind::Fixed,
            Some(_) => NonceKind::Random,
            None if unlock => match fixed_int(3, &hint("nonce.type")) {
                1 => NonceKind::Printable,
                2 => NonceKind::PrintableSubset,
                _ => NonceKind::Random,
            },
            None => {
                if fixed_int(2, &hint("nonce.type")) + 1 == 1 {
                    NonceKind::Printable
                } else {
                    NonceKind::PrintableSubset
                }
            }
        };
        let min_len = match raw.nonce_min {
            Some(v) => i64::from(v),
            None if unlock => fixed_int(13, &hint("nonce.minLen")),
            None => fixed_int(7, &hint("nonce.minLen")) + 6,
        };
        let max_len = match raw.nonce_max {
            Some(v) => i64::from(v),
            None => min_len + fixed_int(13 - min_len, &hint("nonce.maxLen")),
        };
        let nonce = NoncePattern {
            kind,
            min_len: usize::try_from(min_len).unwrap_or(0),
            max_len: usize::try_from(max_len).unwrap_or(0),
            fixed: raw
                .nonce_hex
                .iter()
                .filter_map(|text| hex::decode(text).ok())
                .collect(),
            every_udp_packet: raw
                .nonce_every_udp
                .unwrap_or_else(|| fixed_int(2, &hint("nonce.applyToAllUDPPacket")) == 1),
        };

        let max_middle = match raw.pad_middle {
            Some(v) => i64::from(v),
            None => (fixed_int(MAX_PADDING + 1, &hint("padding.maxMiddlePaddingLen")) - 128).max(0),
        };
        let max_end = match raw.pad_end {
            Some(v) => i64::from(v),
            None if unlock => fixed_int(MAX_PADDING + 1, &hint("padding.maxEndPaddingLen")),
            None => MAX_PADDING,
        };

        let mode = match raw.low_mode {
            Some(v) => v,
            None if unlock => fixed_int(5, &hint("lowEntropy.mode")) as i32,
            None => 0,
        };
        let rotation = match raw.low_rotation {
            Some(v) => v,
            None => {
                let index = fixed_int(ROTATION_COUNT, &hint("lowEntropy.maskRotation"));
                if index <= 15 {
                    index as i32
                } else {
                    (index as i32 - 15) * 16
                }
            }
        };
        Pattern {
            fragment,
            nonce,
            max_middle: usize::try_from(max_middle).unwrap_or(0),
            max_end: usize::try_from(max_end).unwrap_or(0),
            low_entropy: u8::try_from(mode)
                .ok()
                .filter(|mode| *mode != 0)
                .map(|mode| LowEntropy {
                    mode,
                    rotation: u8::try_from(rotation).unwrap_or(0),
                }),
        }
    }
}
