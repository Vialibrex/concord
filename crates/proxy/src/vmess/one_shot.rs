//! The one-shot AES-128-GCM seals of VMess's AEAD header, used by the client and the server.

use std::io;

use aws_lc_rs::aead::{Aad, Nonce};

use super::crypto::gcm;
use crate::util::invalid_data;

pub(crate) fn one_shot_seal(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
) -> io::Result<Vec<u8>> {
    let cipher = gcm(key)?;
    let nonce = <[u8; 12]>::try_from(nonce).map_err(|_| invalid_data("bad nonce"))?;
    let mut out = plain.to_vec();
    let tag = cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut out,
        )
        .map_err(|_| invalid_data("seal failed"))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

pub(crate) fn one_shot_open(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    sealed: &mut [u8],
) -> io::Result<usize> {
    let cipher = gcm(key)?;
    let nonce = <[u8; 12]>::try_from(nonce).map_err(|_| invalid_data("bad nonce"))?;
    cipher
        .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), sealed)
        .map(|plain| plain.len())
        .map_err(|_| invalid_data("vmess header authentication failed"))
}
