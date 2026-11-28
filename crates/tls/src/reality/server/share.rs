use std::io;

use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};
use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};

use super::hello::ClientHello;
use crate::error::invalid_data;
use crate::fingerprints::{GROUP_X25519, GROUP_X25519_MLKEM768};

pub(crate) const X25519_KEY: usize = 32;
pub(crate) const MLKEM768_KEY: usize = 1184;

/// `reality.go:236-259`: the server's share and the shared secret for the group `dest`
/// chose, ML-KEM first in both for X25519MLKEM768.
pub(crate) fn server_share(group: u16, hello: &ClientHello<'_>) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let missing = || invalid_data("REALITY: the client has no share of the chosen group");
    let share = hello.share(group).ok_or_else(missing)?;
    let (encapsulation, peer) = match group {
        GROUP_X25519 => (None, share),
        GROUP_X25519_MLKEM768 => {
            let (key, peer) = share.split_at_checked(MLKEM768_KEY).ok_or_else(missing)?;
            (Some(key), peer)
        }
        _ => return Err(invalid_data("REALITY: unsupported key exchange group")),
    };
    let private = agreement::PrivateKey::generate(&X25519)
        .map_err(|_| invalid_data("REALITY: key generation"))?;
    let public = private
        .compute_public_key()
        .map_err(|_| invalid_data("REALITY: key generation"))?;
    let x25519 = agreement::agree(&private, UnparsedPublicKey::new(&X25519, peer), (), |s| {
        Ok(s.to_vec())
    })
    .map_err(|()| invalid_data("REALITY: key agreement"))?;
    let Some(key) = encapsulation else {
        return Ok((public.as_ref().to_vec(), x25519));
    };
    let (ciphertext, secret) = EncapsulationKey::new(&ML_KEM_768, key)
        .map_err(encapsulation_failed)?
        .encapsulate()
        .map_err(encapsulation_failed)?;
    let mut share = ciphertext.as_ref().to_vec();
    share.extend_from_slice(public.as_ref());
    let mut shared = secret.as_ref().to_vec();
    shared.extend_from_slice(&x25519);
    Ok((share, shared))
}

fn encapsulation_failed<E>(_: E) -> io::Error {
    invalid_data("REALITY: ML-KEM encapsulation")
}
