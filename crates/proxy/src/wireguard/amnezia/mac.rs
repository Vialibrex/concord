use std::sync::Mutex;
use std::time::{Duration, Instant};

use blake2::digest::consts::U16;
use blake2::digest::{Digest, Mac};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use concord_common::sync::lock;

pub(super) const INITIATION: usize = 148;
pub(super) const RESPONSE: usize = 92;
pub(super) const COOKIE_REPLY: usize = 64;
const MAC: usize = 16;
const COOKIE_LIFETIME: Duration = Duration::from_secs(120);

fn derive(label: &[u8], public: &[u8; 32]) -> [u8; 32] {
    let mut hash = Blake2s256::new();
    hash.update(label);
    hash.update(public);
    hash.finalize().into()
}

fn keyed_mac(key: &[u8], parts: &[u8]) -> Option<Blake2sMac<U16>> {
    let mut state = Blake2sMac::<U16>::new_from_slice(key).ok()?;
    state.update(parts);
    Some(state)
}

fn mac(key: &[u8], parts: &[u8]) -> Option<[u8; MAC]> {
    Some(keyed_mac(key, parts)?.finalize().into_bytes().into())
}

/// The MACs of a handshake message cover its type, which AmneziaWG replaces, so they are
/// recomputed whenever the type is swapped in either direction.
pub(super) struct Macs {
    mac1: [u8; 32],
    cookie: [u8; 32],
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    last_mac1: Option<[u8; MAC]>,
    cookie: Option<(Instant, [u8; MAC])>,
}

impl Macs {
    pub(super) fn new(public: &[u8; 32]) -> Self {
        Macs {
            mac1: derive(b"mac1----", public),
            cookie: derive(b"cookie--", public),
            state: Mutex::new(State::default()),
        }
    }

    /// Writes mac1 and mac2 into a handshake message. Returns false for any other length.
    pub(super) fn stamp(&self, message: &mut [u8], remember: bool) -> bool {
        let Some(mac2_at) = message.len().checked_sub(MAC) else {
            return false;
        };
        let Some(mac1_at) = mac2_at.checked_sub(MAC) else {
            return false;
        };
        let Some(mac1) = message
            .get(..mac1_at)
            .and_then(|body| mac(&self.mac1, body))
        else {
            return false;
        };
        if let Some(slot) = message.get_mut(mac1_at..mac2_at) {
            slot.copy_from_slice(&mac1);
        }
        let mac2 = {
            let mut state = lock(&self.state);
            if remember {
                state.last_mac1 = Some(mac1);
            }
            state
                .cookie
                .filter(|(set, _)| set.elapsed() <= COOKIE_LIFETIME)
                .map(|(_, cookie)| cookie)
        };
        let tail = match mac2 {
            Some(cookie) => message
                .get(..mac2_at)
                .and_then(|body| mac(&cookie, body))
                .unwrap_or_default(),
            None => [0; MAC],
        };
        if let Some(slot) = message.get_mut(mac2_at..) {
            slot.copy_from_slice(&tail);
        }
        true
    }

    pub(super) fn check_mac1(&self, message: &[u8]) -> bool {
        let Some(mac2_at) = message.len().checked_sub(MAC) else {
            return false;
        };
        let Some(mac1_at) = mac2_at.checked_sub(MAC) else {
            return false;
        };
        let (Some(body), Some(claimed)) = (message.get(..mac1_at), message.get(mac1_at..mac2_at))
        else {
            return false;
        };
        keyed_mac(&self.mac1, body).is_some_and(|state| state.verify_slice(claimed).is_ok())
    }

    /// Takes the cookie out of a cookie reply to the last initiation sent to this peer.
    pub(super) fn take_cookie(&self, reply: &[u8]) -> bool {
        let (Some(nonce), Some(sealed)) = (reply.get(8..32), reply.get(32..COOKIE_REPLY)) else {
            return false;
        };
        let mut state = lock(&self.state);
        let Some(last) = state.last_mac1 else {
            return false;
        };
        let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&self.cookie) else {
            return false;
        };
        let Ok(nonce) = XNonce::try_from(nonce) else {
            return false;
        };
        let opened = cipher.decrypt(
            &nonce,
            Payload {
                msg: sealed,
                aad: &last,
            },
        );
        match opened
            .ok()
            .and_then(|cookie| <[u8; MAC]>::try_from(cookie).ok())
        {
            Some(cookie) => {
                state.cookie = Some((Instant::now(), cookie));
                true
            }
            None => false,
        }
    }
}
