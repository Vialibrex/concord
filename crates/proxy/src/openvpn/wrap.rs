use std::io;
use std::time::{Duration, Instant};

use aws_lc_rs::cipher::{
    AES_256, DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext, UnboundCipherKey,
};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::iv::FixedLength;

use super::keys::{Digest, KEY_HALF};
use super::wire::{HEADER_LEN, Reader, malformed};

pub(super) const STATIC_KEY_LEN: usize = 256;
const SLOT: usize = 2 * KEY_HALF;
/// A static key file's two slots, each a cipher key half then an HMAC key half.
pub(super) type StaticKey = [[u8; SLOT]; 2];
const PID_LEN: usize = 8;
const CRYPT_TAG: usize = 32;
const CRYPT_KEY: usize = 32;
const REPLAY_WINDOW: usize = 64;
const REPLAY_TIME_BACKTRACK: Duration = Duration::from_secs(15);

/// The protection around control packets: `--tls-auth`, or `--tls-crypt` and its v2 form,
/// which encrypts exactly like v1 and adds the wrapped client key to the first reset.
pub(super) enum Wrap {
    Auth {
        digest: Digest,
        send: Vec<u8>,
        recv: Vec<u8>,
    },
    Crypt {
        send_cipher: [u8; CRYPT_KEY],
        send_hmac: [u8; CRYPT_KEY],
        recv_cipher: [u8; CRYPT_KEY],
        recv_hmac: [u8; CRYPT_KEY],
        wrapped_key: Option<Vec<u8>>,
    },
}

pub(super) struct Unwrapped {
    pub(super) header: [u8; HEADER_LEN],
    pub(super) packet_id: u32,
    pub(super) time: u32,
    pub(super) plain: Vec<u8>,
}

pub(super) fn static_key(bytes: &[u8]) -> Option<StaticKey> {
    let (slots, rest) = bytes.as_chunks::<SLOT>();
    match (slots, rest) {
        ([first, second], []) => Some([*first, *second]),
        _ => None,
    }
}

fn pid_bytes(packet_id: u32, time: u32) -> [u8; PID_LEN] {
    let mut out = [0; PID_LEN];
    out[..4].copy_from_slice(&packet_id.to_be_bytes());
    out[4..].copy_from_slice(&time.to_be_bytes());
    out
}

fn read_pid(pid: [u8; PID_LEN]) -> (u32, u32) {
    let [a, b, c, d, e, f, g, h] = pid;
    (
        u32::from_be_bytes([a, b, c, d]),
        u32::from_be_bytes([e, f, g, h]),
    )
}

/// tls-crypt's IV: the first 16 bytes of the HMAC-SHA256 tag.
fn crypt_iv(tag: &[u8]) -> io::Result<FixedLength<16>> {
    let iv = tag
        .first_chunk::<16>()
        .ok_or_else(|| malformed("tls-crypt IV"))?;
    Ok(FixedLength::from(*iv))
}

fn ctr_failed(_: aws_lc_rs::error::Unspecified) -> io::Error {
    io::Error::other("AES-256-CTR failed")
}

fn ctr_decrypt(key: &[u8; CRYPT_KEY], tag: &[u8], data: &mut [u8]) -> io::Result<()> {
    let iv = crypt_iv(tag)?;
    let key = UnboundCipherKey::new(&AES_256, key).map_err(ctr_failed)?;
    DecryptingKey::ctr(key)
        .map_err(ctr_failed)?
        .decrypt(data, DecryptionContext::Iv128(iv))
        .map_err(ctr_failed)?;
    Ok(())
}

fn ctr_encrypt(key: &[u8; CRYPT_KEY], tag: &[u8], data: &mut [u8]) -> io::Result<()> {
    let iv = crypt_iv(tag)?;
    let key = UnboundCipherKey::new(&AES_256, key).map_err(ctr_failed)?;
    EncryptingKey::ctr(key)
        .map_err(ctr_failed)?
        .less_safe_encrypt(data, EncryptionContext::Iv128(iv))
        .map_err(ctr_failed)?;
    Ok(())
}

fn cipher_half(slot: &[u8; SLOT]) -> [u8; CRYPT_KEY] {
    let mut out = [0; CRYPT_KEY];
    out.copy_from_slice(&slot[..CRYPT_KEY]);
    out
}

fn hmac_half(slot: &[u8; SLOT]) -> [u8; CRYPT_KEY] {
    let mut out = [0; CRYPT_KEY];
    out.copy_from_slice(&slot[KEY_HALF..KEY_HALF + CRYPT_KEY]);
    out
}

impl Wrap {
    /// mihomo's `NewTLSAuth`: direction 1 sends with slot 1, direction 0 with slot 0, and no
    /// direction uses slot 0 both ways; the HMAC key is the digest-length start of the slot's
    /// HMAC half.
    pub(super) fn auth(key: &StaticKey, direction: &str, digest: Digest) -> Wrap {
        let [zero, one] = key;
        let (send, recv) = match direction {
            "1" => (one, zero),
            "0" => (zero, one),
            _ => (zero, zero),
        };
        let hmac = |slot: &[u8; SLOT]| {
            slot[KEY_HALF..]
                .iter()
                .take(digest.len())
                .copied()
                .collect()
        };
        Wrap::Auth {
            digest,
            send: hmac(send),
            recv: hmac(recv),
        }
    }

    /// The client side of `--tls-crypt`: it sends with slot 1 and receives with slot 0.
    pub(super) fn crypt(key: &StaticKey, wrapped_key: Option<Vec<u8>>) -> Wrap {
        let [recv, send] = key;
        Wrap::Crypt {
            send_cipher: cipher_half(send),
            send_hmac: hmac_half(send),
            recv_cipher: cipher_half(recv),
            recv_hmac: hmac_half(recv),
            wrapped_key,
        }
    }

    pub(super) fn wrapped_key(&self) -> Option<&[u8]> {
        match self {
            Wrap::Crypt { wrapped_key, .. } => wrapped_key.as_deref(),
            Wrap::Auth { .. } => None,
        }
    }

    pub(super) fn seal(
        &self,
        header: &[u8; HEADER_LEN],
        packet_id: u32,
        time: u32,
        plain: &[u8],
    ) -> io::Result<Vec<u8>> {
        let pid = pid_bytes(packet_id, time);
        match self {
            Wrap::Auth { digest, send, .. } => {
                let tag = digest.mac(send, &[&pid, header, plain]);
                Ok([&header[..], &tag, &pid, plain].concat())
            }
            Wrap::Crypt {
                send_cipher,
                send_hmac,
                ..
            } => {
                let tag = Digest::Sha256.mac(send_hmac, &[header, &pid, plain]);
                let mut body = plain.to_vec();
                ctr_encrypt(send_cipher, &tag, &mut body)?;
                Ok([&header[..], &pid, &tag, &body].concat())
            }
        }
    }

    pub(super) fn open(&self, packet: &[u8]) -> io::Result<Unwrapped> {
        let mut reader = Reader(packet);
        let header = reader.array::<HEADER_LEN>()?;
        match self {
            Wrap::Auth { digest, recv, .. } => {
                let tag = reader.take(digest.len())?;
                let pid = reader.array::<PID_LEN>()?;
                let plain = reader.0;
                if plain.is_empty() {
                    return Err(malformed("tls-auth packet"));
                }
                let expected = digest.mac(recv, &[&pid, &header, plain]);
                verify_slices_are_equal(tag, &expected)
                    .map_err(|_| malformed("tls-auth authentication"))?;
                let (packet_id, time) = read_pid(pid);
                Ok(Unwrapped {
                    header,
                    packet_id,
                    time,
                    plain: plain.to_vec(),
                })
            }
            Wrap::Crypt {
                recv_cipher,
                recv_hmac,
                ..
            } => {
                let pid = reader.array::<PID_LEN>()?;
                let tag = reader.array::<CRYPT_TAG>()?;
                let mut plain = reader.0.to_vec();
                ctr_decrypt(recv_cipher, &tag, &mut plain)?;
                let expected = Digest::Sha256.mac(recv_hmac, &[&header, &pid, &plain]);
                verify_slices_are_equal(&tag, &expected)
                    .map_err(|_| malformed("tls-crypt authentication"))?;
                let (packet_id, time) = read_pid(pid);
                Ok(Unwrapped {
                    header,
                    packet_id,
                    time,
                    plain,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
enum Slot {
    #[default]
    Empty,
    Accepted(Instant),
    Expired,
}

/// mihomo's control `replayState`: OpenVPN's long-form packet-id window, where a newer time
/// restarts the window and gaps expire after the time backtrack. Slot `n` is the packet `n`
/// behind the highest.
pub(super) struct Replay {
    time: u32,
    high: u32,
    slots: [Slot; REPLAY_WINDOW],
    seen: bool,
}

impl Default for Replay {
    fn default() -> Replay {
        Replay {
            time: 0,
            high: 0,
            slots: [Slot::Empty; REPLAY_WINDOW],
            seen: false,
        }
    }
}

impl Replay {
    pub(super) fn check(&mut self, packet_id: u32, time: u32, now: Instant) -> bool {
        if packet_id == 0 {
            return false;
        }
        if !self.seen || time > self.time {
            *self = Replay {
                time,
                high: packet_id,
                seen: true,
                ..Replay::default()
            };
            self.slots[0] = Slot::Accepted(now);
            return true;
        }
        if time < self.time {
            return false;
        }
        self.reap(now);
        if packet_id > self.high {
            let shift = usize::try_from(packet_id - self.high).unwrap_or(REPLAY_WINDOW);
            if shift >= REPLAY_WINDOW {
                self.slots = [Slot::Empty; REPLAY_WINDOW];
            } else {
                self.slots.rotate_right(shift);
                self.slots
                    .iter_mut()
                    .take(shift)
                    .for_each(|slot| *slot = Slot::Empty);
            }
            self.high = packet_id;
            self.slots[0] = Slot::Accepted(now);
            return true;
        }
        let behind = usize::try_from(self.high - packet_id).unwrap_or(REPLAY_WINDOW);
        match self.slots.get_mut(behind) {
            Some(slot @ Slot::Empty) => {
                *slot = Slot::Accepted(now);
                true
            }
            _ => false,
        }
    }

    /// Expires every slot from the first one older than the backtrack onward, up to a slot
    /// already expired, as mihomo's `reap` does.
    fn reap(&mut self, now: Instant) {
        let mut expire = false;
        for slot in &mut self.slots {
            match *slot {
                Slot::Expired => break,
                Slot::Accepted(at) if at + REPLAY_TIME_BACKTRACK < now => expire = true,
                _ => {}
            }
            if expire {
                *slot = Slot::Expired;
            }
        }
    }
}
