use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use chacha20::cipher::consts::U10;
use chacha20poly1305::ChaCha8Poly1305;
use chacha20poly1305::aead::AeadInPlace;
use concord_common::sync::lock;
use concord_common::{Address, PacketBuf};
use rand::Rng;
use shadowsocks::crypto::CipherKind;
use shadowsocks::crypto::v1::Cipher;

use super::window::SlidingWindow;
use crate::addr_codec::{MAX_ADDR_LEN, SOCKS};
use crate::ctx::Clock;
use crate::dgram::{Encoder, Opener};
use crate::util::invalid_data;

const MAX_SALT: usize = 32;
const NONCE_2022: usize = 24;
const MAX_SKEW_SECS: u64 = 30;
/// A new server session replaces the current one only once the previous has been silent this long.
const SERVER_SESSION_SECS: u64 = 60;
const TYPE_CLIENT: u8 = 0;
const TYPE_SERVER: u8 = 1;
const MAX_DNS_PADDING: usize = 900;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Plain,
    Aead,
    Stream,
    Aes2022,
    Chacha2022,
}

struct Session2022 {
    id: u64,
    packet: AtomicU64,
    cipher: Cipher2022,
    server: Mutex<ServerSessions>,
}

#[derive(Clone, Copy)]
struct PacketIds {
    server: u64,
    packet: u64,
}

impl PacketIds {
    fn read(header: &[u8]) -> io::Result<Self> {
        Ok(PacketIds {
            server: u64::from_be_bytes(first8(header)?),
            packet: u64::from_be_bytes(first8(header.get(8..).unwrap_or_default())?),
        })
    }
}

struct ServerSession {
    id: u64,
    window: SlidingWindow,
    /// `None` for the ChaCha ciphers, which seal every session with the key itself.
    cipher: Option<Cipher2022>,
}

/// The server session replies come from and the one before it, as sing-shadowsocks2 keeps
/// them (`shadowaead_2022/method.go:539-547`, `:589-608`). A session is taken on only after
/// one of its packets passed every check.
#[derive(Default)]
struct ServerSessions {
    current: Option<ServerSession>,
    previous: Option<ServerSession>,
    previous_seen: u64,
}

impl ServerSessions {
    fn get(&self, id: u64) -> Option<&ServerSession> {
        [&self.current, &self.previous]
            .into_iter()
            .flatten()
            .find(|session| session.id == id)
    }

    fn check(&self, ids: PacketIds) -> io::Result<()> {
        match self.get(ids.server) {
            Some(session) if !session.window.check(ids.packet) => {
                Err(invalid_data("packet id not unique"))
            }
            _ => Ok(()),
        }
    }

    fn accept(&mut self, ids: PacketIds, fresh: Option<Cipher2022>, now: u64) -> io::Result<()> {
        if let Some(current) = self.current.as_mut().filter(|s| s.id == ids.server) {
            current.window.add(ids.packet);
            return Ok(());
        }
        if let Some(previous) = self.previous.as_mut().filter(|s| s.id == ids.server) {
            previous.window.add(ids.packet);
            self.previous_seen = now;
            return Ok(());
        }
        if self.current.is_some() {
            if now.saturating_sub(self.previous_seen) < SERVER_SESSION_SECS {
                return Err(invalid_data("too many server sessions"));
            }
            self.previous = self.current.take();
            self.previous_seen = now;
        }
        let mut window = SlidingWindow::default();
        window.add(ids.packet);
        self.current = Some(ServerSession {
            id: ids.server,
            window,
            cipher: fresh,
        });
        Ok(())
    }
}

pub(crate) struct SsUdp {
    kind: CipherKind,
    key: Box<[u8]>,
    /// Each iPSK with the 16-byte BLAKE3 prefix of the key after it, for 2022 EIH.
    identity: Vec<(Box<[u8]>, [u8; 16])>,
    scheme: Scheme,
    session: Option<Session2022>,
    clock: Clock,
}

impl SsUdp {
    pub(crate) fn new(kind: CipherKind, key: &[u8], clock: Clock) -> Self {
        let scheme = if kind.is_none() {
            Scheme::Plain
        } else if kind.is_aead() {
            Scheme::Aead
        } else if kind.is_stream() {
            Scheme::Stream
        } else if matches!(
            kind,
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305
                | CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305
        ) {
            Scheme::Chacha2022
        } else {
            Scheme::Aes2022
        };
        let session = matches!(scheme, Scheme::Aes2022 | Scheme::Chacha2022).then(|| {
            let id: u64 = rand::rng().random();
            Session2022 {
                id,
                packet: AtomicU64::new(0),
                cipher: Cipher2022::new(kind, key, id),
                server: Mutex::new(ServerSessions::default()),
            }
        });
        SsUdp {
            kind,
            key: key.into(),
            identity: Vec::new(),
            scheme,
            session,
            clock,
        }
    }

    /// sing-shadowsocks2 EIH: the packet header goes out under the first iPSK, and after
    /// it one identity header per iPSK, the next key's hash XOR the plain header.
    pub(crate) fn with_identity(mut self, keys: &[bytes::Bytes]) -> Self {
        let user = self.key.clone();
        self.identity = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let next = keys.get(index + 1).map_or(&*user, |next| &next[..]);
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&blake3::hash(next).as_bytes()[..16]);
                (Box::<[u8]>::from(&key[..]), hash)
            })
            .collect();
        self
    }

    fn now(&self) -> u64 {
        (self.clock)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }

    fn seal_addr(pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        let len = SOCKS.len(dst);
        SOCKS.write_into(dst, pkt.prepend(len))?;
        Ok(())
    }

    fn open_addr(pkt: &mut PacketBuf) -> io::Result<Address> {
        let (addr, used) = SOCKS
            .parse(pkt.as_slice())?
            .ok_or_else(|| invalid_data("short shadowsocks udp packet"))?;
        pkt.consume(used);
        Ok(addr)
    }

    fn seal_v1(&self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        Self::seal_addr(pkt, dst)?;
        let aead = self.scheme == Scheme::Aead;
        let (prefix, tag) = if aead {
            (self.kind.salt_len(), self.kind.tag_len())
        } else {
            (self.kind.iv_len(), 0)
        };
        let mut salt = [0u8; MAX_SALT];
        let salt = salt
            .get_mut(..prefix)
            .ok_or_else(|| invalid_data("salt too long"))?;
        rand::rng().fill(&mut *salt);
        pkt.advance(tag);
        let mut cipher = Cipher::new(self.kind, &self.key, salt);
        cipher.encrypt_packet(pkt.as_mut_slice());
        pkt.prepend(prefix).copy_from_slice(salt);
        Ok(())
    }

    fn open_v1(&self, pkt: &mut PacketBuf) -> io::Result<Address> {
        let aead = self.scheme == Scheme::Aead;
        let (prefix, tag) = if aead {
            (self.kind.salt_len(), self.kind.tag_len())
        } else {
            (self.kind.iv_len(), 0)
        };
        let total = pkt.len();
        if total < prefix + tag {
            return Err(invalid_data("short shadowsocks udp packet"));
        }
        let (salt, body) = pkt.as_mut_slice().split_at_mut(prefix);
        let mut cipher = Cipher::new(self.kind, &self.key, salt);
        if !cipher.decrypt_packet(body) {
            return Err(invalid_data("decrypt payload failed"));
        }
        pkt.truncate(total - tag);
        pkt.consume(prefix);
        Self::open_addr(pkt)
    }

    fn seal_2022(
        &self,
        pkt: &mut PacketBuf,
        dst: &Address,
        session: &Session2022,
    ) -> io::Result<()> {
        let padding = dns_padding(dst, pkt.len());
        Self::seal_addr(pkt, dst)?;
        pkt.prepend(padding).fill(0);
        pkt.prepend(2)
            .copy_from_slice(&(padding as u16).to_be_bytes());
        pkt.prepend(8).copy_from_slice(&self.now().to_be_bytes());
        pkt.prepend(1).fill(TYPE_CLIENT);
        let packet = session.packet.fetch_add(1, Ordering::Relaxed);
        let mut ids = [0u8; 16];
        let (sid, pid) = ids.split_at_mut(8);
        sid.copy_from_slice(&session.id.to_be_bytes());
        pid.copy_from_slice(&packet.to_be_bytes());
        let tag = self.kind.tag_len();
        if self.scheme == Scheme::Chacha2022 {
            pkt.prepend(16).copy_from_slice(&ids);
            pkt.advance(tag);
            let mut nonce = [0u8; NONCE_2022];
            rand::rng().fill(&mut nonce);
            session.cipher.encrypt_packet(&nonce, pkt.as_mut_slice());
            pkt.prepend(NONCE_2022).copy_from_slice(&nonce);
            return Ok(());
        }
        pkt.advance(tag);
        let (_, nonce) = ids.split_at(4);
        session.cipher.encrypt_packet(nonce, pkt.as_mut_slice());
        for (key, hash) in self.identity.iter().rev() {
            let mut header = [0u8; 16];
            for ((out, h), id) in header.iter_mut().zip(hash).zip(&ids) {
                *out = h ^ id;
            }
            ecb(key, &mut header, true)?;
            pkt.prepend(16).copy_from_slice(&header);
        }
        let first = self.identity.first().map_or(&self.key, |(key, _)| key);
        ecb(first, &mut ids, true)?;
        pkt.prepend(16).copy_from_slice(&ids);
        Ok(())
    }

    fn open_2022(&self, pkt: &mut PacketBuf, session: &Session2022) -> io::Result<Address> {
        let tag = self.kind.tag_len();
        let aes = self.scheme == Scheme::Aes2022;
        let prefix = if aes { 16 } else { NONCE_2022 };
        let total = pkt.len();
        if total < prefix + tag + 1 + 8 + 8 + 2 {
            return Err(invalid_data("short shadowsocks 2022 udp packet"));
        }
        let data = pkt.as_mut_slice();
        let (head, body) = data.split_at_mut(prefix);
        let mut servers = lock(&session.server);
        let (ids, fresh) = if aes {
            ecb(&self.key, head, false)?;
            let ids = PacketIds::read(head)?;
            servers.check(ids)?;
            let known = servers.get(ids.server).and_then(|s| s.cipher.as_ref());
            let fresh = known
                .is_none()
                .then(|| Cipher2022::new(self.kind, &self.key, ids.server));
            let nonce = head
                .get(4..16)
                .ok_or_else(|| invalid_data("short header"))?;
            let opened = match known.or(fresh.as_ref()) {
                Some(cipher) => cipher.decrypt_packet(nonce, body),
                None => false,
            };
            if !opened {
                return Err(invalid_data("decrypt payload failed"));
            }
            (ids, fresh)
        } else {
            if !session.cipher.decrypt_packet(head, body) {
                return Err(invalid_data("decrypt payload failed"));
            }
            let ids = PacketIds::read(body)?;
            servers.check(ids)?;
            (ids, None)
        };
        let plain_len = body.len() - tag;
        let plain = body
            .get(..plain_len)
            .ok_or_else(|| invalid_data("short packet"))?;
        let mut cursor = Cursor {
            buf: plain,
            pos: if aes { 0 } else { 16 },
        };
        let kind = cursor.take(1)?.first().copied().unwrap_or(0);
        if kind != TYPE_SERVER {
            return Err(invalid_data("invalid socket type"));
        }
        let stamp = u64::from_be_bytes(first8(cursor.take(8)?)?);
        let now = self.now();
        if now.abs_diff(stamp) > MAX_SKEW_SECS {
            return Err(invalid_data("invalid timestamp"));
        }
        let client = u64::from_be_bytes(first8(cursor.take(8)?)?);
        if client != session.id {
            return Err(invalid_data("unexpected client session id"));
        }
        let pad = cursor.take(2)?;
        let pad = usize::from(u16::from_be_bytes([
            pad.first().copied().unwrap_or(0),
            pad.get(1).copied().unwrap_or(0),
        ]));
        cursor.take(pad)?;
        servers.accept(ids, fresh, now)?;
        drop(servers);
        let consumed = cursor.pos;
        pkt.truncate(prefix + plain_len);
        pkt.consume(prefix + consumed);
        Self::open_addr(pkt)
    }
}

/// sing-shadowsocks2 seals 2022-blake3-chacha8-poly1305 datagrams with an XChaCha8 whose
/// subkey comes from a full 20-round HChaCha; RustCrypto's XChaCha8 uses an 8-round
/// HChaCha, which the server cannot open.
enum Cipher2022 {
    Crate(shadowsocks::crypto::v2::udp::UdpCipher),
    Chacha8(chacha20::Key),
}

impl Cipher2022 {
    fn new(kind: CipherKind, key: &[u8], session: u64) -> Self {
        if kind == CipherKind::AEAD2022_BLAKE3_CHACHA8_POLY1305 {
            return Cipher2022::Chacha8(*chacha20::Key::from_slice(key));
        }
        Cipher2022::Crate(shadowsocks::crypto::v2::udp::UdpCipher::new(
            kind, key, session,
        ))
    }

    fn chacha8(key: &chacha20::Key, nonce: &[u8]) -> Option<(ChaCha8Poly1305, [u8; 12])> {
        let (head, tail) = (nonce.get(..16)?, nonce.get(16..24)?);
        let subkey = chacha20::hchacha::<U10>(key, head.into());
        let mut short = [0u8; 12];
        short.get_mut(4..)?.copy_from_slice(tail);
        Some((ChaCha8Poly1305::new(&subkey), short))
    }

    fn encrypt_packet(&self, nonce: &[u8], buf: &mut [u8]) {
        match self {
            Cipher2022::Crate(cipher) => cipher.encrypt_packet(nonce, buf),
            Cipher2022::Chacha8(key) => {
                let Some((cipher, short)) = Self::chacha8(key, nonce) else {
                    return;
                };
                let plain_len = buf.len().saturating_sub(TAG_LEN);
                let (plain, tag_out) = buf.split_at_mut(plain_len);
                if let Ok(tag) = cipher.encrypt_in_place_detached(&short.into(), &[], plain) {
                    tag_out.copy_from_slice(&tag);
                }
            }
        }
    }

    fn decrypt_packet(&self, nonce: &[u8], buf: &mut [u8]) -> bool {
        match self {
            Cipher2022::Crate(cipher) => cipher.decrypt_packet(nonce, buf),
            Cipher2022::Chacha8(key) => {
                let Some((cipher, short)) = Self::chacha8(key, nonce) else {
                    return false;
                };
                let Some(plain_len) = buf.len().checked_sub(TAG_LEN) else {
                    return false;
                };
                let (body, tag) = buf.split_at_mut(plain_len);
                cipher
                    .decrypt_in_place_detached(&short.into(), &[], body, (&*tag).into())
                    .is_ok()
            }
        }
    }
}

const TAG_LEN: usize = 16;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let out = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or_else(|| invalid_data("short shadowsocks 2022 udp packet"))?;
        self.pos += n;
        Ok(out)
    }
}

fn first8(data: &[u8]) -> io::Result<[u8; 8]> {
    data.get(..8)
        .and_then(|head| <[u8; 8]>::try_from(head).ok())
        .ok_or_else(|| invalid_data("short packet"))
}

fn ecb(key: &[u8], header: &mut [u8], encrypt: bool) -> io::Result<()> {
    let array = <[u8; 16]>::try_from(&*header).map_err(|_| invalid_data("bad header length"))?;
    let mut block = Block::from(array);
    match key.len() {
        16 => {
            let cipher = Aes128::new_from_slice(key).map_err(|_| invalid_data("bad key length"))?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        32 => {
            let cipher = Aes256::new_from_slice(key).map_err(|_| invalid_data("bad key length"))?;
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
        }
        _ => return Err(invalid_data("bad key length")),
    }
    header.copy_from_slice(block.as_slice());
    Ok(())
}

impl Encoder for SsUdp {
    fn headroom(&self) -> usize {
        NONCE_2022 + 16 * (1 + self.identity.len()) + 11 + MAX_ADDR_LEN + MAX_SALT
    }

    fn encode(&self, pkt: &mut PacketBuf, dst: &Address) -> io::Result<()> {
        match (&self.session, self.scheme) {
            (_, Scheme::Plain) => Self::seal_addr(pkt, dst),
            (Some(session), Scheme::Aes2022 | Scheme::Chacha2022) => {
                self.seal_2022(pkt, dst, session)
            }
            _ => self.seal_v1(pkt, dst),
        }
    }
}

impl Opener for SsUdp {
    fn open(&self, pkt: &mut PacketBuf) -> io::Result<Address> {
        match (&self.session, self.scheme) {
            (_, Scheme::Plain) => Self::open_addr(pkt),
            (Some(session), Scheme::Aes2022 | Scheme::Chacha2022) => self.open_2022(pkt, session),
            _ => self.open_v1(pkt),
        }
    }
}

/// sing-shadowsocks2 pads a small packet to port 53 so a DNS query does not show by its size.
fn dns_padding(dst: &Address, payload: usize) -> usize {
    if dst.port() == 53 && payload < MAX_DNS_PADDING {
        rand::rng().random_range(1..=MAX_DNS_PADDING - payload)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use super::*;

    fn clock() -> Clock {
        Arc::new(SystemTime::now)
    }

    fn at(secs: &Arc<AtomicU64>) -> Clock {
        let secs = secs.clone();
        Arc::new(move || UNIX_EPOCH + Duration::from_secs(secs.load(Ordering::Relaxed)))
    }

    /// A reply as a Shadowsocks 2022 server seals it in server session `server`.
    fn from_server(codec: &SsUdp, server: u64, packet: u64) -> Vec<u8> {
        let session = codec.session.as_ref().unwrap();
        let tag = codec.kind.tag_len();
        let mut pkt = PacketBuf::with_headroom(codec.headroom());
        pkt.extend_from_slice(b"answer");
        SsUdp::seal_addr(&mut pkt, &Address::new("203.0.113.5", 53)).unwrap();
        pkt.prepend(2).fill(0);
        pkt.prepend(8).copy_from_slice(&session.id.to_be_bytes());
        pkt.prepend(8).copy_from_slice(&codec.now().to_be_bytes());
        pkt.prepend(1).fill(TYPE_SERVER);
        let mut ids = [0u8; 16];
        ids[..8].copy_from_slice(&server.to_be_bytes());
        ids[8..].copy_from_slice(&packet.to_be_bytes());
        if codec.scheme == Scheme::Chacha2022 {
            pkt.prepend(16).copy_from_slice(&ids);
            pkt.advance(tag);
            let mut nonce = [0u8; NONCE_2022];
            rand::rng().fill(&mut nonce);
            session.cipher.encrypt_packet(&nonce, pkt.as_mut_slice());
            pkt.prepend(NONCE_2022).copy_from_slice(&nonce);
        } else {
            pkt.advance(tag);
            Cipher2022::new(codec.kind, &codec.key, server)
                .encrypt_packet(&ids[4..], pkt.as_mut_slice());
            ecb(&codec.key, &mut ids, true).unwrap();
            pkt.prepend(16).copy_from_slice(&ids);
        }
        pkt.as_slice().to_vec()
    }

    fn open(codec: &SsUdp, bytes: &[u8]) -> io::Result<Address> {
        codec.open(&mut PacketBuf::from_slice(bytes))
    }

    const AES: CipherKind = CipherKind::AEAD2022_BLAKE3_AES_128_GCM;

    #[test]
    fn a_replayed_server_packet_is_dropped() {
        for kind in [AES, CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305] {
            let codec = SsUdp::new(kind, &key_for(kind), clock());
            let first = from_server(&codec, 1, 0);
            assert!(open(&codec, &first).is_ok());
            assert!(open(&codec, &first).is_err());
            assert!(open(&codec, &from_server(&codec, 1, 1)).is_ok());
        }
    }

    #[test]
    fn a_third_server_session_within_a_minute_is_refused() {
        let secs = Arc::new(AtomicU64::new(1_000_000));
        let codec = SsUdp::new(AES, &key_for(AES), at(&secs));
        assert!(open(&codec, &from_server(&codec, 1, 0)).is_ok());
        assert!(open(&codec, &from_server(&codec, 2, 0)).is_ok());
        assert!(open(&codec, &from_server(&codec, 1, 1)).is_ok());
        assert!(open(&codec, &from_server(&codec, 3, 0)).is_err());
        secs.fetch_add(60, Ordering::Relaxed);
        assert!(open(&codec, &from_server(&codec, 3, 0)).is_ok());
        assert!(open(&codec, &from_server(&codec, 2, 1)).is_ok());
        assert!(open(&codec, &from_server(&codec, 1, 2)).is_err());
    }

    #[test]
    fn a_packet_that_fails_does_not_take_a_server_session_slot() {
        let codec = SsUdp::new(AES, &key_for(AES), clock());
        assert!(open(&codec, &from_server(&codec, 1, 0)).is_ok());
        let mut forged = from_server(&codec, 2, 0);
        *forged.last_mut().unwrap() ^= 1;
        assert!(open(&codec, &forged).is_err());
        assert!(open(&codec, &from_server(&codec, 3, 0)).is_ok());
        assert!(open(&codec, &from_server(&codec, 1, 1)).is_ok());
    }

    fn key_for(kind: CipherKind) -> Vec<u8> {
        vec![7u8; kind.key_len()]
    }

    fn round_trip_v1(kind: CipherKind) {
        let key = key_for(kind);
        let client = SsUdp::new(kind, &key, clock());
        let dst = Address::new("203.0.113.5", 53);
        let mut pkt = PacketBuf::with_headroom(client.headroom());
        pkt.extend_from_slice(b"query");
        client.encode(&mut pkt, &dst).unwrap();
        if !kind.is_none() {
            assert_ne!(pkt.as_slice().get(pkt.len() - 5..), Some(&b"query"[..]));
        }
        let from = client.open(&mut pkt).unwrap();
        assert_eq!(from, dst);
        assert_eq!(pkt.as_slice(), b"query");
    }

    #[test]
    fn v1_ciphers_round_trip_in_place() {
        for kind in [
            CipherKind::AES_128_GCM,
            CipherKind::AES_256_GCM,
            CipherKind::CHACHA20_POLY1305,
            CipherKind::AES_256_CTR,
            CipherKind::NONE,
        ] {
            round_trip_v1(kind);
        }
    }

    #[test]
    fn a_tampered_packet_is_rejected() {
        let kind = CipherKind::AES_128_GCM;
        let codec = SsUdp::new(kind, &key_for(kind), clock());
        let mut pkt = PacketBuf::with_headroom(codec.headroom());
        pkt.extend_from_slice(b"query");
        codec
            .encode(&mut pkt, &Address::new("1.1.1.1", 53))
            .unwrap();
        let last = pkt.len() - 1;
        pkt.as_mut_slice()[last] ^= 1;
        assert!(codec.open(&mut pkt).is_err());
    }
}
