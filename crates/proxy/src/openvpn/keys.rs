use std::io;

use hmac::{Hmac, Mac};
use indexmap::IndexMap;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::wire::{Reader, SessionId, malformed};

const PRE_MASTER_LEN: usize = 48;
const RANDOM_LEN: usize = 32;
pub(super) const KEY_HALF: usize = 64;
const KEY_METHOD_2: u8 = 2;
const IV_PROTO: u32 = (1 << 1) | (1 << 2) | (1 << 4);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Digest {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    pub(super) fn parse(name: &str) -> Option<Digest> {
        Some(match name {
            "MD5" => Digest::Md5,
            "SHA1" => Digest::Sha1,
            "SHA256" => Digest::Sha256,
            "SHA384" => Digest::Sha384,
            "SHA512" => Digest::Sha512,
            _ => return None,
        })
    }

    pub(super) fn len(self) -> usize {
        match self {
            Digest::Md5 => 16,
            Digest::Sha1 => 20,
            Digest::Sha256 => 32,
            Digest::Sha384 => 48,
            Digest::Sha512 => 64,
        }
    }

    pub(super) fn mac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        fn run<M: Mac + hmac::digest::KeyInit>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let Ok(mut mac) = <M as hmac::digest::KeyInit>::new_from_slice(key) else {
                return Vec::new();
            };
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        }
        match self {
            Digest::Md5 => run::<Hmac<Md5>>(key, parts),
            Digest::Sha1 => run::<Hmac<Sha1>>(key, parts),
            Digest::Sha256 => run::<Hmac<Sha256>>(key, parts),
            Digest::Sha384 => run::<Hmac<Sha384>>(key, parts),
            Digest::Sha512 => run::<Hmac<Sha512>>(key, parts),
        }
    }
}

/// The client's half of key method 2: what it sends and the secrets it keeps.
pub(super) struct ClientRecord {
    pre_master: [u8; PRE_MASTER_LEN],
    random1: [u8; RANDOM_LEN],
    random2: [u8; RANDOM_LEN],
}

pub(super) struct ServerRecord {
    random1: [u8; RANDOM_LEN],
    random2: [u8; RANDOM_LEN],
}

/// Both directions' keys, each the full 64 bytes OpenVPN derives; callers cut them to the
/// cipher and digest in use.
pub(super) struct KeyMaterial {
    pub(super) send_cipher: [u8; KEY_HALF],
    pub(super) send_hmac: [u8; KEY_HALF],
    pub(super) recv_cipher: [u8; KEY_HALF],
    pub(super) recv_hmac: [u8; KEY_HALF],
}

pub(super) struct Credentials<'a> {
    pub(super) options: &'a str,
    pub(super) username: &'a str,
    pub(super) password: &'a str,
    pub(super) peer_info: &'a str,
}

impl ClientRecord {
    pub(super) fn random() -> ClientRecord {
        let mut record = ClientRecord {
            pre_master: [0; PRE_MASTER_LEN],
            random1: [0; RANDOM_LEN],
            random2: [0; RANDOM_LEN],
        };
        rand::fill(&mut record.pre_master);
        rand::fill(&mut record.random1);
        rand::fill(&mut record.random2);
        record
    }

    pub(super) fn encode(&self, credentials: &Credentials<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + PRE_MASTER_LEN + 2 * RANDOM_LEN + 256);
        out.extend_from_slice(&[0, 0, 0, 0, KEY_METHOD_2]);
        out.extend_from_slice(&self.pre_master);
        out.extend_from_slice(&self.random1);
        out.extend_from_slice(&self.random2);
        for text in [
            credentials.options,
            credentials.username,
            credentials.password,
            credentials.peer_info,
        ] {
            put_string(&mut out, text);
        }
        out
    }

    pub(super) fn derive(
        &self,
        server: &ServerRecord,
        client_session: &SessionId,
        server_session: &SessionId,
    ) -> KeyMaterial {
        let mut master = [0; PRE_MASTER_LEN];
        prf(
            &self.pre_master,
            &[b"OpenVPN master secret", &self.random1, &server.random1],
            &mut master,
        );
        let mut block = [[0; KEY_HALF]; 4];
        prf(
            &master,
            &[
                b"OpenVPN key expansion",
                &self.random2,
                &server.random2,
                client_session,
                server_session,
            ],
            block.as_flattened_mut(),
        );
        let [send_cipher, send_hmac, recv_cipher, recv_hmac] = block;
        KeyMaterial {
            send_cipher,
            send_hmac,
            recv_cipher,
            recv_hmac,
        }
    }
}

fn put_string(out: &mut Vec<u8>, text: &str) {
    let bytes = text.as_bytes();
    let bytes = bytes.get(..0xfffe).unwrap_or(bytes);
    if bytes.is_empty() {
        out.extend_from_slice(&[0, 0]);
        return;
    }
    let len = u16::try_from(bytes.len() + 1).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    out.push(0);
}

enum Field {
    Value(usize),
    Truncated,
}

/// Reads one length-prefixed string starting at `at`, giving the offset after it.
fn string_end(buf: &[u8], at: usize) -> Field {
    let Some(len) = buf.get(at..).and_then(<[u8]>::first_chunk::<2>) else {
        return Field::Truncated;
    };
    let end = at + 2 + usize::from(u16::from_be_bytes(*len));
    if end > buf.len() {
        Field::Truncated
    } else {
        Field::Value(end)
    }
}

/// Control messages that may follow a server record whose optional strings were left out.
fn starts_control_message(rest: &[u8]) -> bool {
    let rest = rest
        .get(rest.iter().take_while(|b| **b == 0).count()..)
        .unwrap_or_default();
    [
        "PUSH_REPLY",
        "AUTH_FAILED",
        "PUSH_REQUEST",
        "AUTH_PENDING",
        "INFO",
        "RESTART",
        "HALT",
        "EXIT",
        "CR_RESPONSE",
    ]
    .iter()
    .any(|word| rest.starts_with(word.as_bytes()))
}

/// Parses the server's key method 2 record from the front of the TLS plaintext. `None` asks
/// for more bytes; the count is how many the record took. OpenVPN 2.6 may end the record
/// after its options string when a control message follows, as mihomo's
/// `ParseServerKeyMethod2RecordConsumed` accepts.
pub(super) fn parse_server(buf: &[u8]) -> io::Result<Option<(ServerRecord, usize)>> {
    let fixed = 5 + 2 * RANDOM_LEN;
    if buf.len() < fixed {
        return Ok(None);
    }
    let mut reader = Reader(buf);
    if reader.array::<4>()? != [0; 4] {
        return Err(malformed("key method 2 prefix"));
    }
    let method = reader.u8()?;
    if method & 0x0f != KEY_METHOD_2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported OpenVPN key method {method}"),
        ));
    }
    let record = ServerRecord {
        random1: reader.array()?,
        random2: reader.array()?,
    };
    let mut at = match string_end(buf, fixed) {
        Field::Value(end) => end,
        Field::Truncated => return Ok(None),
    };
    for _ in 0..3 {
        match string_end(buf, at) {
            Field::Value(end) => at = end,
            Field::Truncated if starts_control_message(buf.get(at..).unwrap_or_default()) => break,
            Field::Truncated => return Ok(None),
        }
    }
    Ok(Some((record, at)))
}

/// TLS 1.0's PRF as OpenVPN keeps it: P_MD5 over the first half of the secret XOR P_SHA1 over
/// the second.
fn prf(secret: &[u8], seed: &[&[u8]], out: &mut [u8]) {
    let seed = seed.concat();
    let split = secret.len().div_ceil(2);
    let (first, _) = secret.split_at(split);
    let (_, second) = secret.split_at(secret.len() - split);
    let md5 = p_hash(Digest::Md5, first, &seed, out.len());
    let sha1 = p_hash(Digest::Sha1, second, &seed, out.len());
    for ((out, a), b) in out.iter_mut().zip(md5).zip(sha1) {
        *out = a ^ b;
    }
}

fn p_hash(digest: Digest, secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + digest.len());
    let mut a = digest.mac(secret, &[seed]);
    while out.len() < len {
        out.extend(digest.mac(secret, &[&a, seed]));
        a = digest.mac(secret, &[&a]);
    }
    out.truncate(len);
    out
}

/// mihomo's `InstallScriptOptionsString`, the options string the server compares with its own.
pub(super) fn options_string(tcp: bool, cipher: &str, auth: &str, comp_lzo: bool) -> String {
    let proto = if tcp { "TCPv4_CLIENT" } else { "UDPv4" };
    let keysize = if matches!(cipher, "AES-256-GCM" | "AES-256-CBC" | "CHACHA20-POLY1305") {
        256
    } else {
        128
    };
    let (mtu, comp) = if comp_lzo {
        (1544, "comp-lzo,")
    } else {
        (1550, "")
    };
    format!(
        "V4,dev-type tun,link-mtu {mtu},tun-mtu 1500,proto {proto},{comp}cipher {cipher},auth {auth},keysize {keysize},key-method 2,tls-client"
    )
}

/// mihomo's `InstallScriptPeerInfo`: the built-in variables, then the node's own in key order.
pub(super) fn peer_info(
    ciphers: &[String],
    comp_lzo: bool,
    extra: &IndexMap<String, String>,
) -> String {
    let version = extra.get("IV_VER").map_or("mihomo-openvpn", String::as_str);
    let lzo = if comp_lzo { "IV_LZO=1\n" } else { "" };
    let mut out = format!(
        "IV_VER={version}\nIV_PROTO={IV_PROTO}\n{lzo}IV_CIPHERS={}\n",
        ciphers.join(":")
    );
    let mut keys: Vec<&String> = extra
        .keys()
        .filter(|key| {
            !matches!(key.as_str(), "IV_VER" | "IV_PROTO" | "IV_CIPHERS")
                && !(comp_lzo && key.as_str() == "IV_LZO")
        })
        .collect();
    keys.sort();
    for key in keys {
        out.push_str(&format!("{key}={}\n", extra[key]));
    }
    out
}

#[cfg(test)]
impl ClientRecord {
    pub(super) fn fixed(
        pre_master: [u8; PRE_MASTER_LEN],
        random1: [u8; 32],
        random2: [u8; 32],
    ) -> Self {
        ClientRecord {
            pre_master,
            random1,
            random2,
        }
    }
}
