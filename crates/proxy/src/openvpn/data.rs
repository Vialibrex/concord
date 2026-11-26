use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::cipher::{
    AES_128, AES_192, AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext,
    UnboundCipherKey,
};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::hmac;
use aws_lc_rs::iv::FixedLength;

use super::keys::{Digest, KEY_HALF, KeyMaterial};
use super::push::PEER_ID_UNSET;
use super::wire::{DATA_V1, DATA_V2, KEY_ID_MASK, malformed};
use crate::util::lock;

const TAG_LEN: usize = 16;
const PID_LEN: usize = 4;
const BLOCK: usize = 16;
const IMPLICIT_IV: usize = 8;
/// mihomo's `dataPacketIDRekeyThreshold`, OpenVPN's packet_id_close_to_wrapping: the client
/// cannot start a rekey, so the tunnel ends here instead of nearing a nonce reuse.
const SEND_PID_LIMIT: u32 = 0xFF00_0000;
const REPLAY_WINDOW: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cipher {
    Aead(&'static aead::Algorithm),
    Cbc(&'static aws_lc_rs::cipher::Algorithm, usize),
}

impl Cipher {
    pub(super) fn parse(name: &str) -> Option<Cipher> {
        Some(match name {
            "AES-128-GCM" => Cipher::Aead(&aead::AES_128_GCM),
            "AES-192-GCM" => Cipher::Aead(&aead::AES_192_GCM),
            "AES-256-GCM" => Cipher::Aead(&aead::AES_256_GCM),
            "CHACHA20-POLY1305" => Cipher::Aead(&aead::CHACHA20_POLY1305),
            "AES-128-CBC" => Cipher::Cbc(&AES_128, 16),
            "AES-192-CBC" => Cipher::Cbc(&AES_192, 24),
            "AES-256-CBC" => Cipher::Cbc(&AES_256, 32),
            _ => return None,
        })
    }

    fn key_len(self) -> usize {
        match self {
            Cipher::Aead(alg) => alg.key_len(),
            Cipher::Cbc(_, len) => len,
        }
    }
}

enum DataMac {
    Aws(Box<hmac::Key>),
    Md5(Vec<u8>),
}

impl DataMac {
    fn new(digest: Digest, key: &[u8]) -> DataMac {
        let alg = match digest {
            Digest::Md5 => return DataMac::Md5(key.to_vec()),
            Digest::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Digest::Sha256 => hmac::HMAC_SHA256,
            Digest::Sha384 => hmac::HMAC_SHA384,
            Digest::Sha512 => hmac::HMAC_SHA512,
        };
        DataMac::Aws(Box::new(hmac::Key::new(alg, key)))
    }

    fn sign(&self, data: &[u8], out: &mut [u8]) {
        match self {
            DataMac::Aws(key) => out.copy_from_slice(hmac::sign(key, data).as_ref()),
            DataMac::Md5(key) => out.copy_from_slice(&Digest::Md5.mac(key, &[data])),
        }
    }
}

enum Crypt {
    Aead {
        send: LessSafeKey,
        recv: LessSafeKey,
        send_iv: [u8; IMPLICIT_IV],
        recv_iv: [u8; IMPLICIT_IV],
    },
    Cbc {
        send: Box<EncryptingKey>,
        recv: Box<DecryptingKey>,
        send_mac: DataMac,
        recv_mac: DataMac,
        mac_len: usize,
    },
}

/// mihomo's `acceptPacketID`: a 64-packet window behind the highest packet ID seen.
#[derive(Default)]
struct Window {
    high: u32,
    bits: u64,
    seen: bool,
}

impl Window {
    fn accept(&mut self, pid: u32) -> bool {
        if !self.seen {
            *self = Window {
                high: pid,
                bits: 1,
                seen: true,
            };
            return true;
        }
        if pid > self.high {
            let shift = pid - self.high;
            self.bits = if shift >= REPLAY_WINDOW {
                1
            } else {
                (self.bits << shift) | 1
            };
            self.high = pid;
            return true;
        }
        let behind = self.high - pid;
        let mask = 1u64.checked_shl(behind).unwrap_or(0);
        if behind >= REPLAY_WINDOW || self.bits & mask != 0 {
            return false;
        }
        self.bits |= mask;
        true
    }
}

pub(super) struct DataKey {
    pub(super) key_id: u8,
    header: [u8; 4],
    header_len: usize,
    crypt: Crypt,
    send_pid: AtomicU32,
    window: Mutex<Window>,
    peer_active: AtomicBool,
}

fn nonce(implicit: &[u8; IMPLICIT_IV], pid: u32) -> Nonce {
    let mut bytes = [0; 12];
    bytes[..4].copy_from_slice(&pid.to_be_bytes());
    bytes[4..].copy_from_slice(implicit);
    Nonce::assume_unique_for_key(bytes)
}

fn failed(_: aws_lc_rs::error::Unspecified) -> io::Error {
    io::Error::other("OpenVPN data key setup failed")
}

impl DataKey {
    pub(super) fn new(
        keys: &KeyMaterial,
        cipher: Cipher,
        digest: Digest,
        peer_id: u32,
        key_id: u8,
    ) -> io::Result<DataKey> {
        let len = cipher.key_len();
        let crypt = match cipher {
            Cipher::Aead(alg) => {
                let key = |bytes: &[u8; KEY_HALF]| {
                    UnboundKey::new(alg, bytes.get(..len).unwrap_or_default())
                        .map(LessSafeKey::new)
                        .map_err(failed)
                };
                let iv = |bytes: &[u8; KEY_HALF]| {
                    let mut out = [0; IMPLICIT_IV];
                    out.copy_from_slice(&bytes[..IMPLICIT_IV]);
                    out
                };
                Crypt::Aead {
                    send: key(&keys.send_cipher)?,
                    recv: key(&keys.recv_cipher)?,
                    send_iv: iv(&keys.send_hmac),
                    recv_iv: iv(&keys.recv_hmac),
                }
            }
            Cipher::Cbc(alg, _) => {
                let unbound = |bytes: &[u8; KEY_HALF]| {
                    UnboundCipherKey::new(alg, bytes.get(..len).unwrap_or_default()).map_err(failed)
                };
                let mac_key = |bytes: &[u8; KEY_HALF]| {
                    DataMac::new(digest, bytes.get(..digest.len()).unwrap_or_default())
                };
                let mac_len = digest.len();
                Crypt::Cbc {
                    send: Box::new(
                        EncryptingKey::cbc(unbound(&keys.send_cipher)?).map_err(failed)?,
                    ),
                    recv: Box::new(
                        DecryptingKey::cbc(unbound(&keys.recv_cipher)?).map_err(failed)?,
                    ),
                    send_mac: mac_key(&keys.send_hmac),
                    recv_mac: mac_key(&keys.recv_hmac),
                    mac_len,
                }
            }
        };
        let key_id = key_id & KEY_ID_MASK;
        let (header, header_len) = if peer_id == PEER_ID_UNSET {
            ([DATA_V1 << 3 | key_id, 0, 0, 0], 1)
        } else {
            let id = peer_id.to_be_bytes();
            ([DATA_V2 << 3 | key_id, id[1], id[2], id[3]], 4)
        };
        Ok(DataKey {
            key_id,
            header,
            header_len,
            crypt,
            send_pid: AtomicU32::new(0),
            window: Mutex::new(Window::default()),
            peer_active: AtomicBool::new(false),
        })
    }

    pub(super) fn peer_active(&self) -> bool {
        self.peer_active.load(Ordering::Relaxed)
    }

    fn next_pid(&self) -> io::Result<u32> {
        let pid = self.send_pid.fetch_add(1, Ordering::Relaxed);
        if pid >= SEND_PID_LIMIT {
            return Err(io::Error::other(
                "OpenVPN data packet id reached the rekey threshold",
            ));
        }
        Ok(pid + 1)
    }

    /// Writes the sealed packet for `prefix` then `payload` into `out`, replacing what it held.
    pub(super) fn seal(&self, prefix: &[u8], payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let pid = self.next_pid()?.to_be_bytes();
        out.clear();
        out.extend_from_slice(self.header());
        match &self.crypt {
            Crypt::Aead { send, send_iv, .. } => {
                out.extend_from_slice(&pid);
                out.extend_from_slice(&[0; TAG_LEN]);
                out.extend_from_slice(prefix);
                out.extend_from_slice(payload);
                let (head, body) = out.split_at_mut(self.header_len + PID_LEN + TAG_LEN);
                let (authenticated, tag_slot) = head.split_at_mut(self.header_len + PID_LEN);
                let tag = send
                    .seal_in_place_separate_tag(
                        nonce(send_iv, u32::from_be_bytes(pid)),
                        Aad::from(aad(authenticated, self.header_len)),
                        body,
                    )
                    .map_err(|_| io::Error::other("OpenVPN data seal failed"))?;
                tag_slot.copy_from_slice(tag.as_ref());
            }
            Crypt::Cbc {
                send,
                send_mac,
                mac_len,
                ..
            } => {
                let mut iv = [0; BLOCK];
                rand::fill(&mut iv);
                out.resize(self.header_len + mac_len, 0);
                out.extend_from_slice(&iv);
                out.extend_from_slice(&pid);
                out.extend_from_slice(prefix);
                out.extend_from_slice(payload);
                let plain = PID_LEN + prefix.len() + payload.len();
                let pad = BLOCK - plain % BLOCK;
                out.resize(out.len() + pad, u8::try_from(pad).unwrap_or(0));
                let (head, signed) = out.split_at_mut(self.header_len + mac_len);
                let (_, ciphertext) = signed.split_at_mut(BLOCK);
                send.less_safe_encrypt(ciphertext, EncryptionContext::Iv128(FixedLength::from(iv)))
                    .map_err(|_| io::Error::other("OpenVPN data seal failed"))?;
                let (_, mac) = head.split_at_mut(self.header_len);
                send_mac.sign(signed, mac);
            }
        }
        Ok(())
    }

    fn header(&self) -> &[u8] {
        self.header.get(..self.header_len).unwrap_or_default()
    }

    /// Authenticates and decrypts `packet` into `out`, which must hold at least as many bytes
    /// as the packet, and returns where the payload lies in `out`.
    pub(super) fn open(&self, packet: &[u8], out: &mut [u8]) -> io::Result<(usize, usize)> {
        let header_len = match super::wire::opcode(packet.first().copied().unwrap_or(0)) {
            DATA_V2 => 4,
            _ => 1,
        };
        let (_, rest) = packet
            .split_at_checked(header_len)
            .ok_or_else(|| malformed("data packet"))?;
        let (pid, range) = match &self.crypt {
            Crypt::Aead { recv, recv_iv, .. } => {
                let (pid_bytes, rest) = rest
                    .split_first_chunk::<PID_LEN>()
                    .ok_or_else(|| malformed("data packet"))?;
                let (tag, ciphertext) = rest
                    .split_first_chunk::<TAG_LEN>()
                    .filter(|(_, ciphertext)| !ciphertext.is_empty())
                    .ok_or_else(|| malformed("data packet"))?;
                let pid = u32::from_be_bytes(*pid_bytes);
                let authenticated = packet.get(..header_len + PID_LEN).unwrap_or_default();
                let target = out
                    .get_mut(..ciphertext.len())
                    .ok_or_else(|| malformed("data packet length"))?;
                recv.open_separate_gather(
                    nonce(recv_iv, pid),
                    Aad::from(aad(authenticated, header_len)),
                    ciphertext,
                    tag,
                    target,
                )
                .map_err(|_| malformed("data packet authentication"))?;
                (pid, (0, ciphertext.len()))
            }
            Crypt::Cbc {
                recv,
                recv_mac,
                mac_len,
                ..
            } => open_cbc(rest, recv, recv_mac, *mac_len, out)?,
        };
        if !lock(&self.window).accept(pid) {
            return Err(malformed("replayed data packet"));
        }
        Ok(range)
    }

    pub(super) fn mark_peer_active(&self) {
        if !self.peer_active.load(Ordering::Relaxed) {
            self.peer_active.store(true, Ordering::Relaxed);
        }
    }
}

/// The part of a CBC packet after its header: HMAC, then IV and ciphertext, which hold the
/// packet ID, the payload and PKCS#7 padding.
fn open_cbc(
    rest: &[u8],
    recv: &DecryptingKey,
    recv_mac: &DataMac,
    mac_len: usize,
    out: &mut [u8],
) -> io::Result<(u32, (usize, usize))> {
    let bad = || malformed("CBC data packet");
    let (tag, signed) = rest.split_at_checked(mac_len).ok_or_else(bad)?;
    if signed.len() < 2 * BLOCK || !signed.len().is_multiple_of(BLOCK) {
        return Err(bad());
    }
    let mut expected = [0; 64];
    let expected = expected.get_mut(..mac_len).ok_or_else(bad)?;
    recv_mac.sign(signed, expected);
    verify_slices_are_equal(tag, expected).map_err(|_| malformed("data packet authentication"))?;
    let (iv, ciphertext) = signed.split_first_chunk::<BLOCK>().ok_or_else(bad)?;
    let target = out
        .get_mut(..ciphertext.len())
        .ok_or_else(|| malformed("data packet length"))?;
    target.copy_from_slice(ciphertext);
    recv.decrypt(target, DecryptionContext::Iv128(FixedLength::from(*iv)))
        .map_err(|_| bad())?;
    let pad = usize::from(target.last().copied().unwrap_or(0));
    let end = target.len().checked_sub(pad).ok_or_else(bad)?;
    let padding = target.get(end..).unwrap_or_default();
    if pad == 0 || pad > BLOCK || padding.iter().any(|b| usize::from(*b) != pad) || end < PID_LEN {
        return Err(malformed("CBC padding"));
    }
    let pid = target.first_chunk::<PID_LEN>().ok_or_else(bad)?;
    Ok((u32::from_be_bytes(*pid), (PID_LEN, end)))
}

/// OpenVPN authenticates the 4-byte P_DATA_V2 header but not P_DATA_V1's opcode byte;
/// `authenticated` is the header and packet ID.
fn aad(authenticated: &[u8], header_len: usize) -> &[u8] {
    if header_len == 4 {
        authenticated
    } else {
        authenticated.split_at(header_len).1
    }
}

/// The data keys in use: the newest epoch and, after a rekey, the one it replaced.
pub(super) struct Keys {
    pub(super) primary: std::sync::Arc<DataKey>,
    lame: Option<std::sync::Arc<DataKey>>,
    /// The end of the transition window, when the replaced epoch stops being accepted.
    lame_until: Instant,
    /// mihomo's auth_deferred_expire: when sending moves to the new epoch without waiting to
    /// see the peer use it.
    promote_at: Instant,
    /// Set while a rekey runs: past it, the current epoch may no longer carry data.
    primary_until: Option<Instant>,
}

impl Keys {
    pub(super) fn first(primary: std::sync::Arc<DataKey>) -> Keys {
        let now = Instant::now();
        Keys {
            primary,
            lame: None,
            lame_until: now,
            promote_at: now,
            primary_until: None,
        }
    }

    /// The table while a rekey that the peer started at `accepted` runs.
    pub(super) fn rekeying(&self, until: Instant) -> Keys {
        Keys {
            primary: self.primary.clone(),
            lame: self.lame.clone(),
            lame_until: self.lame_until,
            promote_at: self.promote_at,
            primary_until: Some(until),
        }
    }

    /// The table after a rekey: the current epoch becomes the lame duck until `lame_until`,
    /// and stays the sending key until the peer shows it uses `primary` or `promote_at`.
    pub(super) fn rekeyed(
        &self,
        primary: std::sync::Arc<DataKey>,
        lame_until: Instant,
        promote_at: Instant,
    ) -> Keys {
        Keys {
            lame: Some(self.primary.clone()),
            primary,
            lame_until,
            promote_at,
            primary_until: None,
        }
    }

    pub(super) fn sender(&self, now: Instant) -> Option<&DataKey> {
        if self.primary_until.is_some_and(|until| now > until) {
            return None;
        }
        match &self.lame {
            Some(lame)
                if !self.primary.peer_active()
                    && now <= self.promote_at
                    && now <= self.lame_until =>
            {
                Some(lame)
            }
            _ => Some(&self.primary),
        }
    }

    pub(super) fn receiver(&self, key_id: u8, now: Instant) -> Option<(&DataKey, bool)> {
        if self.primary_until.is_some_and(|until| now > until) {
            return None;
        }
        if self.primary.key_id == key_id {
            return Some((&self.primary, true));
        }
        self.lame
            .as_deref()
            .filter(|lame| lame.key_id == key_id && now <= self.lame_until)
            .map(|lame| (lame, false))
    }
}
