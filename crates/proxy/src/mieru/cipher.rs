use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use chacha20::R20;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};

use super::meta::{NONCE_LEN, invalid};
use super::pattern::{NonceKind, NoncePattern};

const KEY_ITERATIONS: u32 = 64;
const REFRESH_SECS: i64 = 120;
const HINT_PREFIX: usize = 16;
const SUBKEY_INPUT: usize = 16;
const HINT_LEN: usize = 4;
const COMMON64: &[u8; 64] = b"CCOzB3KKr9NDAgVnJcCn9ib37T1JH6vRSVx8YaNnXbfo6yFU1EHPy2r3D5LM1Qi4";

pub(super) fn hash_password(password: &str, user: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update([0u8]);
    hasher.update(user.as_bytes());
    hasher.finalize().into()
}

fn pbkdf2(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let prf = |data: &[u8]| -> [u8; 32] {
        let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(password) else {
            return [0; 32];
        };
        mac.update(data);
        mac.finalize().into_bytes().into()
    };
    let mut first = salt.to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut block = prf(&first);
    let mut out = block;
    for _ in 1..KEY_ITERATIONS {
        block = prf(&block);
        for (acc, byte) in out.iter_mut().zip(block) {
            *acc ^= byte;
        }
    }
    out
}

pub(super) fn derive_key(hashed: &[u8; 32], unix_secs: i64) -> [u8; 32] {
    let rounded = (unix_secs + REFRESH_SECS / 2).div_euclid(REFRESH_SECS) * REFRESH_SECS;
    let salt = Sha256::digest((u64::try_from(rounded).unwrap_or(0)).to_be_bytes());
    pbkdf2(hashed, &salt)
}

fn increment(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn printable(bytes: &mut [u8]) {
    let mut rng = rand::rng();
    for byte in bytes {
        if (0x20..=0x7e).contains(byte) {
            continue;
        }
        let low = *byte & 0x7f;
        *byte = if *byte & 0x80 != 0 && (0x20..=0x7e).contains(&low) {
            low
        } else {
            0x20 + u8::try_from(rng.next_u32() % 95).unwrap_or(0)
        };
    }
}

fn apply_pattern(nonce: &mut [u8; NONCE_LEN], pattern: &NoncePattern) {
    let max = pattern.max_len.min(NONCE_LEN);
    let min = pattern.min_len.min(max);
    let rewrite = if min == max {
        min
    } else {
        min + usize::try_from(rand::rng().next_u32()).unwrap_or(0) % (max - min + 1)
    };
    match pattern.kind {
        NonceKind::Random => {}
        NonceKind::Printable => {
            if let Some(head) = nonce.get_mut(..rewrite) {
                printable(head);
            }
        }
        NonceKind::PrintableSubset => {
            for byte in nonce.iter_mut().take(rewrite) {
                *byte = COMMON64
                    .get(usize::from(*byte & 0x3f))
                    .copied()
                    .unwrap_or(b'C');
            }
        }
        NonceKind::Fixed => {
            if !pattern.fixed.is_empty() {
                let pick =
                    usize::try_from(rand::rng().next_u32()).unwrap_or(0) % pattern.fixed.len();
                if let Some(prefix) = pattern.fixed.get(pick) {
                    let len = prefix.len().min(NONCE_LEN);
                    if let (Some(target), Some(source)) = (nonce.get_mut(..len), prefix.get(..len))
                    {
                        target.copy_from_slice(source);
                    }
                }
            }
        }
    }
}

fn add_hint(nonce: &mut [u8; NONCE_LEN], user: &str) {
    if user.is_empty() {
        return;
    }
    let mut hasher = Sha256::new();
    hasher.update(user.as_bytes());
    hasher.update(nonce.get(..HINT_PREFIX).unwrap_or_default());
    let digest = hasher.finalize();
    if let (Some(target), Some(source)) = (
        nonce.get_mut(NONCE_LEN - HINT_LEN..),
        digest.get(..HINT_LEN),
    ) {
        target.copy_from_slice(source);
    }
}

/// XChaCha20-Poly1305 as HChaCha20 over the nonce's first 16 bytes plus IETF
/// ChaCha20-Poly1305, which aws-lc runs with vector code on every target.
struct XChaCha {
    master: chacha20::Key,
    keyed: Option<([u8; SUBKEY_INPUT], LessSafeKey)>,
}

impl XChaCha {
    fn new(key: &[u8; 32]) -> XChaCha {
        XChaCha {
            master: (*key).into(),
            keyed: None,
        }
    }

    fn subkey(&self, input: &[u8; SUBKEY_INPUT]) -> io::Result<LessSafeKey> {
        let derived = chacha20::hchacha::<R20>(&self.master, &(*input).into());
        UnboundKey::new(&CHACHA20_POLY1305, &derived)
            .map(LessSafeKey::new)
            .map_err(|_| invalid("cipher key"))
    }

    fn split(nonce: &[u8; NONCE_LEN]) -> ([u8; SUBKEY_INPUT], Nonce) {
        let mut input = [0u8; SUBKEY_INPUT];
        input.copy_from_slice(nonce.get(..SUBKEY_INPUT).unwrap_or_default());
        let mut short = [0u8; 12];
        if let (Some(target), Some(source)) = (short.get_mut(4..), nonce.get(SUBKEY_INPUT..)) {
            target.copy_from_slice(source);
        }
        (input, Nonce::assume_unique_for_key(short))
    }

    /// A stream's nonce only steps its last bytes, so its subkey is derived once.
    fn key_for(&mut self, nonce: &[u8; NONCE_LEN]) -> io::Result<(&LessSafeKey, Nonce)> {
        let (input, short) = XChaCha::split(nonce);
        if self
            .keyed
            .as_ref()
            .is_none_or(|(cached, _)| *cached != input)
        {
            self.keyed = Some((input, self.subkey(&input)?));
        }
        let (_, key) = self.keyed.as_ref().ok_or_else(|| invalid("cipher key"))?;
        Ok((key, short))
    }

    fn seal_with(
        key: &LessSafeKey,
        nonce: Nonce,
        out: &mut Vec<u8>,
        plain: &[u8],
    ) -> io::Result<()> {
        let start = out.len();
        out.extend_from_slice(plain);
        let body = out.get_mut(start..).unwrap_or_default();
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::empty(), body)
            .map_err(|_| invalid("encryption failed"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn open_with(key: &LessSafeKey, nonce: Nonce, sealed: &[u8]) -> io::Result<Vec<u8>> {
        let mut plain = sealed.to_vec();
        let len = key
            .open_in_place(nonce, Aad::empty(), &mut plain)
            .map_err(|_| invalid("authentication failed"))?
            .len();
        plain.truncate(len);
        Ok(plain)
    }

    fn seal(&mut self, nonce: &[u8; NONCE_LEN], out: &mut Vec<u8>, plain: &[u8]) -> io::Result<()> {
        let (key, short) = self.key_for(nonce)?;
        XChaCha::seal_with(key, short, out, plain)
    }

    fn open(&mut self, nonce: &[u8; NONCE_LEN], sealed: &[u8]) -> io::Result<Vec<u8>> {
        let (key, short) = self.key_for(nonce)?;
        XChaCha::open_with(key, short, sealed)
    }

    fn seal_once(
        &self,
        nonce: &[u8; NONCE_LEN],
        out: &mut Vec<u8>,
        plain: &[u8],
    ) -> io::Result<()> {
        let (input, short) = XChaCha::split(nonce);
        XChaCha::seal_with(&self.subkey(&input)?, short, out, plain)
    }

    fn open_once(&self, nonce: &[u8; NONCE_LEN], sealed: &[u8]) -> io::Result<Vec<u8>> {
        let (input, short) = XChaCha::split(nonce);
        XChaCha::open_with(&self.subkey(&input)?, short, sealed)
    }
}

pub(super) trait Seal {
    fn seal(&mut self, out: &mut Vec<u8>, plain: &[u8]) -> io::Result<()>;
}

pub(super) struct Sealer {
    aead: XChaCha,
    nonce: Option<[u8; NONCE_LEN]>,
    user: String,
    pattern: NoncePattern,
}

impl Sealer {
    pub(super) fn new(key: &[u8; 32], user: &str, pattern: NoncePattern) -> Sealer {
        Sealer {
            aead: XChaCha::new(key),
            nonce: None,
            user: user.to_string(),
            pattern,
        }
    }
}

impl Seal for Sealer {
    fn seal(&mut self, out: &mut Vec<u8>, plain: &[u8]) -> io::Result<()> {
        let nonce = match &mut self.nonce {
            Some(nonce) => {
                increment(nonce);
                *nonce
            }
            None => {
                let mut fresh = [0u8; NONCE_LEN];
                rand::rng().fill_bytes(&mut fresh);
                apply_pattern(&mut fresh, &self.pattern);
                add_hint(&mut fresh, &self.user);
                out.extend_from_slice(&fresh);
                self.nonce = Some(fresh);
                fresh
            }
        };
        self.aead.seal(&nonce, out, plain)
    }
}

pub(super) struct Opener {
    aead: XChaCha,
    nonce: Option<[u8; NONCE_LEN]>,
    fresh: bool,
}

impl Opener {
    pub(super) fn new(key: &[u8; 32]) -> Opener {
        Opener {
            aead: XChaCha::new(key),
            nonce: None,
            fresh: false,
        }
    }

    pub(super) fn started(&self) -> bool {
        self.nonce.is_some()
    }

    pub(super) fn start(&mut self, nonce: &[u8]) -> io::Result<()> {
        let mut first = [0u8; NONCE_LEN];
        if nonce.len() != NONCE_LEN {
            return Err(invalid("nonce length"));
        }
        first.copy_from_slice(nonce);
        self.nonce = Some(first);
        self.fresh = true;
        Ok(())
    }

    /// The first `open` after `start` uses the nonce as read; later ones step it first.
    pub(super) fn open(&mut self, sealed: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self
            .nonce
            .as_mut()
            .ok_or_else(|| invalid("nonce not read"))?;
        if self.fresh {
            self.fresh = false;
        } else {
            increment(nonce);
        }
        let nonce = *nonce;
        self.aead.open(&nonce, sealed)
    }
}

/// The cipher of a datagram underlay: every datagram starts with a fresh nonce, which
/// seals both its metadata and its payload.
pub(super) struct PacketCipher {
    aead: XChaCha,
    user: String,
    pattern: NoncePattern,
    patterned: AtomicBool,
}

pub(super) struct PacketSealer<'a> {
    cipher: &'a PacketCipher,
    nonce: Option<[u8; NONCE_LEN]>,
}

impl PacketCipher {
    pub(super) fn new(key: &[u8; 32], user: &str, pattern: NoncePattern) -> PacketCipher {
        PacketCipher {
            aead: XChaCha::new(key),
            user: user.to_string(),
            pattern,
            patterned: AtomicBool::new(false),
        }
    }

    pub(super) fn sealer(&self) -> PacketSealer<'_> {
        PacketSealer {
            cipher: self,
            nonce: None,
        }
    }

    pub(super) fn open(&self, nonce: &[u8], sealed: &[u8]) -> io::Result<Vec<u8>> {
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| invalid("nonce length"))?;
        self.aead.open_once(nonce, sealed)
    }

    /// The pattern shapes the first nonce only, unless it asks for every datagram.
    fn fresh_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        if self.pattern.every_udp_packet || !self.patterned.swap(true, Ordering::Relaxed) {
            apply_pattern(&mut nonce, &self.pattern);
        }
        add_hint(&mut nonce, &self.user);
        nonce
    }
}

impl Seal for PacketSealer<'_> {
    fn seal(&mut self, out: &mut Vec<u8>, plain: &[u8]) -> io::Result<()> {
        let nonce = match self.nonce {
            Some(nonce) => nonce,
            None => {
                let fresh = self.cipher.fresh_nonce();
                out.extend_from_slice(&fresh);
                self.nonce = Some(fresh);
                fresh
            }
        };
        self.cipher.aead.seal_once(&nonce, out, plain)
    }
}
