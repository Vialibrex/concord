use std::io;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::{Buf, BytesMut};
use concord_common::PacketBuf;
use concord_common::sync::lock;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

use super::chain::{Chain, ChainKind, chain_open_packet, chain_seal_packet};
use super::cipher::kdf;
use super::stream::{BoxLayer, Layer};
use crate::ctx::{BuildError, Clock};
use crate::util::invalid_data;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Hash {
    Md5,
    Sha1,
}

pub(super) fn hmac(hash: Hash, key: &[u8], data: &[u8]) -> Vec<u8> {
    match hash {
        Hash::Md5 => hmac_md5(key, data).to_vec(),
        Hash::Sha1 => {
            let Ok(mut mac) = <Hmac<Sha1> as KeyInit>::new_from_slice(key) else {
                return Vec::new();
            };
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

pub(super) fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let Ok(mut mac) = <Hmac<Md5> as KeyInit>::new_from_slice(key) else {
        return [0; 16];
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn digest(hash: Hash, data: &[u8]) -> Vec<u8> {
    use md5::Digest;
    match hash {
        Hash::Md5 => Md5::digest(data).to_vec(),
        Hash::Sha1 => Sha1::digest(data).to_vec(),
    }
}

pub(super) fn rand_below(max: usize) -> usize {
    if max == 0 {
        0
    } else {
        rand::random_range(0..max)
    }
}

pub(super) fn rand_bytes(out: &mut Vec<u8>, len: usize) {
    let start = out.len();
    out.resize(start + len, 0);
    if let Some(tail) = out.get_mut(start..) {
        rand::fill(tail);
    }
}

fn le16(bytes: &[u8]) -> usize {
    bytes
        .get(..2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map_or(0, |b| usize::from(u16::from_le_bytes(b)))
}

fn be16(bytes: &[u8]) -> usize {
    bytes
        .get(..2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map_or(0, |b| usize::from(u16::from_be_bytes(b)))
}

pub(super) fn le32(bytes: &[u8]) -> u32 {
    bytes
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_le_bytes)
}

fn put16le(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u16::try_from(value).unwrap_or(u16::MAX).to_le_bytes());
}

fn put16be(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u16::try_from(value).unwrap_or(u16::MAX).to_be_bytes());
}

pub(super) fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

pub(super) struct Base {
    pub(super) key: Vec<u8>,
    pub(super) overhead: usize,
}

pub(super) struct UserData {
    pub(super) key: Vec<u8>,
    pub(super) id: [u8; 4],
}

pub(super) struct AuthData {
    client_id: [u8; 4],
    connection_id: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Auth {
    pub(super) client_id: [u8; 4],
    pub(super) connection_id: u32,
}

impl AuthData {
    fn next(&mut self) -> Auth {
        if self.connection_id > 0xff00_0000 || self.connection_id == 0 {
            rand::fill(&mut self.client_id[..]);
            self.connection_id = rand::random::<u32>() & 0x00ff_ffff;
        }
        self.connection_id += 1;
        Auth {
            client_id: self.client_id,
            connection_id: self.connection_id,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Origin,
    Sha1V4,
    Aes(Hash),
    Chain(ChainKind),
}

/// The per-node half of a protocol: what every connection and every packet shares.
pub(super) struct ProtocolFactory {
    pub(super) kind: Kind,
    pub(super) base: Base,
    pub(super) user: UserData,
    pub(super) auth: Mutex<AuthData>,
    pub(super) clock: Clock,
    pub(super) sizes: Option<(Vec<usize>, Vec<usize>)>,
}

fn user_data(param: &str, key: &[u8], derive: impl Fn(&str) -> Vec<u8>) -> UserData {
    let mut parts = param.split(':');
    let id = parts.next().and_then(|id| id.parse::<u32>().ok());
    let secret = parts.next().map(derive).filter(|key| !key.is_empty());
    match (id, secret) {
        (Some(id), Some(key)) => UserData {
            key,
            id: id.to_le_bytes(),
        },
        _ => {
            if id.is_none() && param.contains(':') {
                tracing::warn!("wrong ssr protocol-param, only digits are expected before ':'");
            }
            let mut id = [0u8; 4];
            rand::fill(&mut id[..]);
            UserData {
                key: key.to_vec(),
                id,
            }
        }
    }
}

impl ProtocolFactory {
    pub(super) fn pick(
        name: &str,
        key: Vec<u8>,
        obfs_overhead: usize,
        param: &str,
        clock: Clock,
    ) -> Result<Self, BuildError> {
        let (kind, overhead) = match name {
            "origin" => (Kind::Origin, 0),
            "auth_sha1_v4" => (Kind::Sha1V4, 7),
            "auth_aes128_md5" => (Kind::Aes(Hash::Md5), 9),
            "auth_aes128_sha1" => (Kind::Aes(Hash::Sha1), 9),
            "auth_chain_a" => (Kind::Chain(ChainKind::A), 4),
            "auth_chain_b" => (Kind::Chain(ChainKind::B), 4),
            other => {
                return Err(BuildError::invalid(format!(
                    "ssr initialize protocol error: protocol {other} not supported"
                )));
            }
        };
        let user = match kind {
            Kind::Aes(hash) => user_data(param, &key, |secret| digest(hash, secret.as_bytes())),
            Kind::Chain(_) => user_data(param, &key, |secret| secret.as_bytes().to_vec()),
            _ => UserData {
                key: key.clone(),
                id: [0; 4],
            },
        };
        let base = Base {
            key,
            overhead: obfs_overhead + overhead,
        };
        let sizes =
            (kind == Kind::Chain(ChainKind::B)).then(|| super::chain::data_sizes(&base.key));
        Ok(ProtocolFactory {
            kind,
            base,
            user,
            auth: Mutex::new(AuthData {
                client_id: [0; 4],
                connection_id: 0,
            }),
            clock,
            sizes,
        })
    }

    fn now(&self) -> u32 {
        (self.clock)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX)
            })
    }

    pub(super) fn stream(&self, iv: Vec<u8>) -> ProtocolLayer {
        let auth = lock(&self.auth).next();
        let now = self.now();
        match self.kind {
            Kind::Origin => ProtocolLayer::Origin,
            Kind::Sha1V4 => ProtocolLayer::Sha1V4(Sha1V4 {
                key: self.base.key.clone(),
                iv,
                auth,
                now,
                sent_header: false,
                raw: false,
            }),
            Kind::Aes(hash) => ProtocolLayer::Aes(Box::new(Aes {
                hash,
                salt: if hash == Hash::Md5 {
                    "auth_aes128_md5"
                } else {
                    "auth_aes128_sha1"
                },
                key: self.base.key.clone(),
                overhead: self.base.overhead,
                user_key: self.user.key.clone(),
                user_id: self.user.id,
                iv,
                auth,
                now,
                sent_header: false,
                raw: false,
                pack_id: 1,
                recv_id: 1,
            })),
            Kind::Chain(kind) => ProtocolLayer::Chain(Box::new(Chain::new(
                kind,
                &self.base,
                &self.user.key,
                self.user.id,
                iv,
                auth,
                now,
                self.sizes.clone(),
            ))),
        }
    }

    pub(super) fn packet(&self) -> PacketProtocol {
        match self.kind {
            Kind::Aes(hash) => PacketProtocol::Aes {
                hash,
                key: self.base.key.clone(),
                user_key: self.user.key.clone(),
                user_id: self.user.id,
            },
            Kind::Chain(_) => PacketProtocol::Chain {
                key: self.base.key.clone(),
                user_key: self.user.key.clone(),
                user_id: self.user.id,
            },
            Kind::Origin | Kind::Sha1V4 => PacketProtocol::Plain,
        }
    }
}

pub(super) enum PacketProtocol {
    Plain,
    Aes {
        hash: Hash,
        key: Vec<u8>,
        user_key: Vec<u8>,
        user_id: [u8; 4],
    },
    Chain {
        key: Vec<u8>,
        user_key: Vec<u8>,
        user_id: [u8; 4],
    },
}

impl PacketProtocol {
    pub(super) fn seal(&self, pkt: &mut PacketBuf) {
        match self {
            PacketProtocol::Plain => {}
            PacketProtocol::Aes {
                hash,
                user_key,
                user_id,
                ..
            } => {
                pkt.extend_from_slice(user_id);
                let mac = hmac(*hash, user_key, pkt.as_slice());
                pkt.extend_from_slice(mac.get(..4).unwrap_or_default());
            }
            PacketProtocol::Chain {
                key,
                user_key,
                user_id,
            } => chain_seal_packet(key, user_key, *user_id, pkt),
        }
    }

    pub(super) fn open(&self, pkt: &mut PacketBuf) -> io::Result<()> {
        match self {
            PacketProtocol::Plain => Ok(()),
            PacketProtocol::Aes { hash, key, .. } => {
                let len = pkt.len();
                let body = pkt
                    .as_slice()
                    .get(
                        ..len
                            .checked_sub(4)
                            .ok_or_else(|| invalid_data("short ssr packet"))?,
                    )
                    .ok_or_else(|| invalid_data("short ssr packet"))?;
                let mac = hmac(*hash, key, body);
                if mac.get(..4) != pkt.as_slice().get(len - 4..) {
                    return Err(invalid_data("auth_aes128 decode data wrong checksum"));
                }
                pkt.truncate(len - 4);
                Ok(())
            }
            PacketProtocol::Chain { key, user_key, .. } => chain_open_packet(key, user_key, pkt),
        }
    }
}

pub(super) enum ProtocolLayer {
    Origin,
    Sha1V4(Sha1V4),
    Aes(Box<Aes>),
    Chain(Box<Chain>),
}

impl Layer for ProtocolLayer {
    fn encode(&mut self, out: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
        match self {
            ProtocolLayer::Origin => out.extend_from_slice(data),
            ProtocolLayer::Sha1V4(layer) => layer.encode(out, data),
            ProtocolLayer::Aes(layer) => layer.encode(out, data),
            ProtocolLayer::Chain(layer) => layer.encode(out, data),
        }
        Ok(())
    }

    fn decode(
        &mut self,
        input: &mut BytesMut,
        decoded: &mut BytesMut,
        _reply: &mut Vec<u8>,
    ) -> io::Result<()> {
        match self {
            ProtocolLayer::Origin => {
                decoded.extend_from_slice(input);
                input.clear();
                Ok(())
            }
            ProtocolLayer::Sha1V4(layer) => layer.decode(input, decoded),
            ProtocolLayer::Aes(layer) => layer.decode(input, decoded),
            ProtocolLayer::Chain(layer) => layer.decode(input, decoded),
        }
    }

    fn split(self) -> (BoxLayer, BoxLayer) {
        match self {
            ProtocolLayer::Origin => (
                Box::new(ProtocolLayer::Origin),
                Box::new(ProtocolLayer::Origin),
            ),
            ProtocolLayer::Sha1V4(layer) => (
                Box::new(ProtocolLayer::Sha1V4(layer.clone())),
                Box::new(ProtocolLayer::Sha1V4(layer)),
            ),
            ProtocolLayer::Aes(layer) => (
                Box::new(ProtocolLayer::Aes(layer.clone())),
                Box::new(ProtocolLayer::Aes(layer)),
            ),
            ProtocolLayer::Chain(layer) => {
                let (decode, encode) = layer.split();
                (
                    Box::new(ProtocolLayer::Chain(decode)),
                    Box::new(ProtocolLayer::Chain(encode)),
                )
            }
        }
    }
}

pub(super) fn head_size(data: &[u8], default: usize) -> usize {
    let (Some(&kind), Some(&len)) = (data.first(), data.get(1)) else {
        return default;
    };
    match kind & 7 {
        1 => 7,
        4 => 19,
        3 => 4 + usize::from(len),
        _ => default,
    }
}

pub(super) fn first_chunk_len(data: &[u8]) -> usize {
    (head_size(data, 30) + rand_below(32)).min(data.len())
}

/// The AES-CBC block with a zero IV that carries the connection identity.
pub(super) fn encrypted_auth(
    user_key: &[u8],
    auth: Auth,
    now: u32,
    paddings: (usize, usize),
    salt: &str,
) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&now.to_le_bytes());
    block[4..8].copy_from_slice(&auth.client_id);
    block[8..12].copy_from_slice(&auth.connection_id.to_le_bytes());
    block[12..14].copy_from_slice(&u16::try_from(paddings.0).unwrap_or(u16::MAX).to_le_bytes());
    block[14..16].copy_from_slice(&u16::try_from(paddings.1).unwrap_or(u16::MAX).to_le_bytes());
    let secret = format!("{}{salt}", STANDARD.encode(user_key));
    let key = kdf(secret.as_bytes(), 16);
    if let Ok(cipher) = Aes128::new_from_slice(&key) {
        let mut generic = aes::Block::from(block);
        cipher.encrypt_block(&mut generic);
        block = generic.into();
    }
    block
}

pub(super) fn pack_rand_data(out: &mut Vec<u8>, size: usize, big_endian: bool) {
    if size < 128 {
        out.push(u8::try_from(size + 1).unwrap_or(u8::MAX));
    } else {
        out.push(255);
        if big_endian {
            put16be(out, size + 3);
        } else {
            put16le(out, size + 3);
        }
    }
    rand_bytes(out, size);
}

/// The offset of the payload inside a frame whose random padding sits in front of it.
fn payload_start(frame: &[u8], big_endian: bool) -> usize {
    let first = usize::from(frame.get(4).copied().unwrap_or(0));
    if first < 255 {
        first + 4
    } else if big_endian {
        be16(frame.get(5..).unwrap_or_default()) + 4
    } else {
        le16(frame.get(5..).unwrap_or_default()) + 4
    }
}

#[derive(Clone)]
pub(super) struct Aes {
    pub(super) hash: Hash,
    pub(super) salt: &'static str,
    pub(super) key: Vec<u8>,
    pub(super) overhead: usize,
    pub(super) user_key: Vec<u8>,
    pub(super) user_id: [u8; 4],
    pub(super) iv: Vec<u8>,
    pub(super) auth: Auth,
    pub(super) now: u32,
    pub(super) sent_header: bool,
    pub(super) raw: bool,
    pub(super) pack_id: u32,
    pub(super) recv_id: u32,
}

impl Aes {
    fn mac_key(&self, id: u32) -> Vec<u8> {
        let mut key = self.user_key.clone();
        key.extend_from_slice(&id.to_le_bytes());
        key
    }

    fn encode(&mut self, out: &mut Vec<u8>, mut data: &[u8]) {
        let full = data.len();
        if !self.sent_header {
            let take = first_chunk_len(data);
            let (head, rest) = data.split_at(take);
            self.pack_auth_data(out, head);
            data = rest;
            self.sent_header = true;
        }
        while data.len() > 8100 {
            let (chunk, rest) = data.split_at(8100);
            self.pack_data(out, chunk, full);
            data = rest;
        }
        if !data.is_empty() {
            self.pack_data(out, data, full);
        }
    }

    fn rand_len_for_data(&self, data_len: usize, full: usize) -> usize {
        if full >= 32 * 1024 - self.overhead {
            return 0;
        }
        let rev = 1451 - i64::try_from(data_len).unwrap_or(i64::MAX);
        if rev == 0 {
            return 0;
        }
        if rev < 0 {
            if rev > -1460 {
                return rand_below(usize::try_from(rev + 1460).unwrap_or(0));
            }
            return rand_below(32);
        }
        // Go's trapezoidRandom(_, -0.3) takes its uniform branch, so no curve is needed.
        rand_below(usize::try_from(rev).unwrap_or(0))
    }

    fn pack_data(&mut self, out: &mut Vec<u8>, data: &[u8], full: usize) {
        let rand_len = self.rand_len_for_data(data.len(), full);
        let mut packed = 2 + 2 + 3 + rand_len + data.len() + 4;
        if rand_len < 128 {
            packed -= 2;
        }
        let mac_key = self.mac_key(self.pack_id);
        self.pack_id = self.pack_id.wrapping_add(1);
        let start = out.len();
        put16le(out, packed);
        let mac = hmac(self.hash, &mac_key, out.get(start..).unwrap_or_default());
        out.extend_from_slice(mac.get(..2).unwrap_or_default());
        pack_rand_data(out, rand_len, false);
        out.extend_from_slice(data);
        let tail = hmac(self.hash, &mac_key, out.get(start..).unwrap_or_default());
        out.extend_from_slice(tail.get(..4).unwrap_or_default());
    }

    fn pack_auth_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let rand_len = if data.len() > 400 {
            rand_below(512)
        } else {
            rand_below(1024)
        };
        let packed = 7 + 4 + 16 + 4 + rand_len + data.len() + 4;
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);

        let start = out.len();
        out.push(u8::try_from(rand_below(256)).unwrap_or(0));
        let head = hmac(self.hash, &mac_key, out.get(start..).unwrap_or_default());
        out.extend_from_slice(head.get(..6).unwrap_or_default());
        out.extend_from_slice(&self.user_id);
        out.extend_from_slice(&encrypted_auth(
            &self.user_key,
            self.auth,
            self.now,
            (packed, rand_len),
            self.salt,
        ));
        let check = hmac(
            self.hash,
            &mac_key,
            out.get(start + 7..).unwrap_or_default(),
        );
        out.extend_from_slice(check.get(..4).unwrap_or_default());
        rand_bytes(out, rand_len);
        out.extend_from_slice(data);
        let tail = hmac(
            self.hash,
            &self.user_key,
            out.get(start..).unwrap_or_default(),
        );
        out.extend_from_slice(tail.get(..4).unwrap_or_default());
    }

    fn decode(&mut self, input: &mut BytesMut, decoded: &mut BytesMut) -> io::Result<()> {
        if self.raw {
            decoded.extend_from_slice(input);
            input.clear();
            return Ok(());
        }
        while input.len() > 4 {
            let mac_key = self.mac_key(self.recv_id);
            let mac = hmac(self.hash, &mac_key, input.get(..2).unwrap_or_default());
            if mac.get(..2) != input.get(2..4) {
                input.clear();
                return Err(invalid_data("auth_aes128 decode data wrong mac"));
            }
            let length = le16(input);
            if !(7..8192).contains(&length) {
                self.raw = true;
                input.clear();
                return Err(invalid_data("auth_aes128 decode data wrong length"));
            }
            if length > input.len() {
                break;
            }
            let frame = input.get(..length).unwrap_or_default();
            let check = hmac(
                self.hash,
                &mac_key,
                frame.get(..length - 4).unwrap_or_default(),
            );
            if check.get(..4) != frame.get(length - 4..) {
                self.raw = true;
                input.clear();
                return Err(invalid_data("auth_aes128 decode data wrong checksum"));
            }
            self.recv_id = self.recv_id.wrapping_add(1);
            let start = payload_start(frame, false);
            let Some(payload) = frame.get(start..length - 4) else {
                input.clear();
                return Err(invalid_data("auth_aes128 decode data wrong length"));
            };
            decoded.extend_from_slice(payload);
            input.advance(length);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct Sha1V4 {
    pub(super) key: Vec<u8>,
    pub(super) iv: Vec<u8>,
    pub(super) auth: Auth,
    pub(super) now: u32,
    pub(super) sent_header: bool,
    pub(super) raw: bool,
}

impl Sha1V4 {
    fn rand_len(size: usize) -> usize {
        if size > 1200 {
            0
        } else if size > 400 {
            rand_below(256)
        } else {
            rand_below(512)
        }
    }

    fn encode(&mut self, out: &mut Vec<u8>, mut data: &[u8]) {
        if !self.sent_header {
            let take = first_chunk_len(data);
            let (head, rest) = data.split_at(take);
            self.pack_auth_data(out, head);
            data = rest;
            self.sent_header = true;
        }
        while data.len() > 8100 {
            let (chunk, rest) = data.split_at(8100);
            Self::pack_data(out, chunk);
            data = rest;
        }
        if !data.is_empty() {
            Self::pack_data(out, data);
        }
    }

    fn pack_data(out: &mut Vec<u8>, data: &[u8]) {
        let rand_len = Self::rand_len(data.len());
        let mut packed = 2 + 2 + 3 + rand_len + data.len() + 4;
        if rand_len < 128 {
            packed -= 2;
        }
        let start = out.len();
        put16be(out, packed);
        let crc = crc32fast::hash(out.get(start..).unwrap_or_default());
        put16le(out, (crc & 0xffff) as usize);
        pack_rand_data(out, rand_len, true);
        out.extend_from_slice(data);
        let sum = adler32(out.get(start..).unwrap_or_default());
        out.extend_from_slice(&sum.to_le_bytes());
    }

    fn pack_auth_data(&mut self, out: &mut Vec<u8>, data: &[u8]) {
        let rand_len = Self::rand_len(12 + data.len());
        let mut packed = 2 + 4 + 3 + rand_len + 12 + data.len() + 10;
        if rand_len < 128 {
            packed -= 2;
        }
        let mut crc_data = Vec::new();
        put16be(&mut crc_data, packed);
        crc_data.extend_from_slice(b"auth_sha1_v4");
        crc_data.extend_from_slice(&self.key);
        let mut mac_key = self.iv.clone();
        mac_key.extend_from_slice(&self.key);

        let start = out.len();
        out.extend_from_slice(crc_data.get(..2).unwrap_or_default());
        out.extend_from_slice(&crc32fast::hash(&crc_data).to_le_bytes());
        pack_rand_data(out, rand_len, true);
        out.extend_from_slice(&self.now.to_le_bytes());
        out.extend_from_slice(&self.auth.client_id);
        out.extend_from_slice(&self.auth.connection_id.to_le_bytes());
        out.extend_from_slice(data);
        let tail = hmac(Hash::Sha1, &mac_key, out.get(start..).unwrap_or_default());
        out.extend_from_slice(tail.get(..10).unwrap_or_default());
    }

    fn decode(&mut self, input: &mut BytesMut, decoded: &mut BytesMut) -> io::Result<()> {
        if self.raw {
            decoded.extend_from_slice(input);
            input.clear();
            return Ok(());
        }
        while input.len() > 4 {
            let crc = crc32fast::hash(input.get(..2).unwrap_or_default()) & 0xffff;
            if crc as usize != le16(input.get(2..).unwrap_or_default()) {
                input.clear();
                return Err(invalid_data("auth_sha1_v4 decode data wrong crc32"));
            }
            let length = be16(input);
            if !(7..8192).contains(&length) {
                self.raw = true;
                input.clear();
                return Err(invalid_data("auth_sha1_v4 decode data wrong length"));
            }
            if length > input.len() {
                break;
            }
            let frame = input.get(..length).unwrap_or_default();
            let sum = adler32(frame.get(..length - 4).unwrap_or_default());
            if sum != le32(frame.get(length - 4..).unwrap_or_default()) {
                self.raw = true;
                input.clear();
                return Err(invalid_data("auth_sha1_v4 decode data wrong adler32"));
            }
            let start = payload_start(frame, true);
            let Some(payload) = frame.get(start..length - 4) else {
                input.clear();
                return Err(invalid_data("auth_sha1_v4 decode data wrong length"));
            };
            decoded.extend_from_slice(payload);
            input.advance(length);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_user_key_falls_back_to_the_node_key() {
        let user = user_data("123:", b"node", |secret| secret.as_bytes().to_vec());
        assert_eq!(user.key, b"node");
        let user = user_data("123:pw", b"node", |secret| secret.as_bytes().to_vec());
        assert_eq!(
            (user.key.as_slice(), user.id),
            (&b"pw"[..], 123u32.to_le_bytes())
        );
    }
}
