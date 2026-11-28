use std::io;

use aws_lc_rs::hmac;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

use super::super::schedule::hmac_sign;
use crate::error::invalid_data;

const SIGNATURE_LEN: usize = 64;

/// `reality.go:200-205`, `:271-284`: each client's copy carries, where the signature was,
/// the HMAC-SHA512 of the public key under that client's auth key.
pub(crate) struct RealityCert {
    unsigned: Vec<u8>,
    key: Ed25519KeyPair,
}

impl RealityCert {
    pub(crate) fn new(mut der: Vec<u8>, pkcs8: &[u8]) -> io::Result<Self> {
        let key = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| invalid_data("REALITY: certificate key"))?;
        let public = key.public_key().as_ref();
        let holds_key = der.windows(public.len()).any(|window| window == public);
        let signed_at = der.len().checked_sub(SIGNATURE_LEN).filter(|_| holds_key);
        let signed_at =
            signed_at.ok_or_else(|| invalid_data("REALITY: certificate is not for its key"))?;
        der.truncate(signed_at);
        Ok(RealityCert { unsigned: der, key })
    }

    pub(crate) fn for_client(&self, auth_key: &[u8]) -> Vec<u8> {
        let mut der = self.unsigned.clone();
        der.extend_from_slice(&hmac_sign(
            hmac::HMAC_SHA512,
            auth_key,
            self.key.public_key().as_ref(),
        ));
        der
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(message).as_ref().to_vec()
    }
}
