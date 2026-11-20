use std::io;

use aws_lc_rs::cipher::{
    AES_128, DecryptionContext, EncryptionContext, StreamingDecryptingKey, StreamingEncryptingKey,
    UnboundCipherKey,
};
use aws_lc_rs::iv::FixedLength;

use crate::util::invalid_data;

/// `less_safe_update` wants output room up to the next block boundary, though CFB128 writes
/// exactly the input's length.
fn room(len: usize) -> usize {
    len + AES_128.block_len()
}

fn key(key: &[u8; 16]) -> io::Result<UnboundCipherKey> {
    UnboundCipherKey::new(&AES_128, key).map_err(|_| invalid_data("bad cfb key"))
}

/// AES-128-CFB of VMess's legacy security, one stream per direction.
pub(crate) struct CfbEncryptor {
    key: StreamingEncryptingKey,
    plain: Vec<u8>,
}

impl CfbEncryptor {
    pub(crate) fn new(secret: &[u8; 16], iv: &[u8; 16]) -> io::Result<Self> {
        let context = EncryptionContext::Iv128(FixedLength::from(iv));
        Ok(CfbEncryptor {
            key: StreamingEncryptingKey::less_safe_cfb128(key(secret)?, context)
                .map_err(|_| invalid_data("bad cfb key"))?,
            plain: Vec::new(),
        })
    }

    /// Appends to `out` the ciphertext of what `frame` writes into an emptied plaintext buffer.
    pub(crate) fn seal(
        &mut self,
        out: &mut Vec<u8>,
        frame: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.plain.clear();
        frame(&mut self.plain)?;
        let start = out.len();
        out.resize(start + room(self.plain.len()), 0);
        let tail = out.get_mut(start..).unwrap_or_default();
        let written = self
            .key
            .less_safe_update(&self.plain, tail)
            .map_err(|_| invalid_data("cfb encrypt failed"))?
            .written()
            .len();
        if written != self.plain.len() {
            return Err(invalid_data("cfb encrypt failed"));
        }
        out.truncate(start + written);
        Ok(())
    }
}

pub(crate) struct CfbDecryptor {
    key: StreamingDecryptingKey,
    plain: Vec<u8>,
}

impl CfbDecryptor {
    pub(crate) fn new(secret: &[u8; 16], iv: &[u8; 16]) -> io::Result<Self> {
        let context = DecryptionContext::Iv128(FixedLength::from(iv));
        Ok(CfbDecryptor {
            key: StreamingDecryptingKey::cfb128(key(secret)?, context)
                .map_err(|_| invalid_data("bad cfb key"))?,
            plain: Vec::new(),
        })
    }

    /// Decrypts in place; aws-lc-rs decrypts into another buffer, copied back.
    pub(crate) fn decrypt(&mut self, data: &mut [u8]) -> io::Result<()> {
        let needed = room(data.len());
        if self.plain.len() < needed {
            self.plain.resize(needed, 0);
        }
        let update = self
            .key
            .less_safe_update(data, &mut self.plain)
            .map_err(|_| invalid_data("cfb decrypt failed"))?;
        let plain = update.written();
        if plain.len() != data.len() {
            return Err(invalid_data("cfb decrypt failed"));
        }
        data.copy_from_slice(plain);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // NIST SP 800-38A F.3.13, CFB128-AES128.Encrypt.
    const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const IV: &str = "000102030405060708090a0b0c0d0e0f";
    const PLAIN: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                         30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    const CIPHER: &str = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b\
                          26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6";

    fn secrets() -> ([u8; 16], [u8; 16]) {
        (hex(KEY).try_into().unwrap(), hex(IV).try_into().unwrap())
    }

    #[test]
    fn the_stream_matches_the_nist_vector_across_unaligned_calls() {
        let (key, iv) = secrets();
        let plain = hex(PLAIN);
        for split in [[1, 15, 17, 31], [7, 9, 3, 45], [64, 0, 0, 0]] {
            let mut encryptor = CfbEncryptor::new(&key, &iv).unwrap();
            let mut out = Vec::new();
            let mut at = 0;
            for take in split {
                let piece = &plain[at..at + take];
                encryptor
                    .seal(&mut out, |frame| {
                        frame.extend_from_slice(piece);
                        Ok(())
                    })
                    .unwrap();
                at += take;
            }
            assert_eq!(out, hex(CIPHER), "{split:?}");

            let mut decryptor = CfbDecryptor::new(&key, &iv).unwrap();
            let mut at = 0;
            for take in split {
                decryptor.decrypt(&mut out[at..at + take]).unwrap();
                at += take;
            }
            assert_eq!(out, plain, "{split:?}");
        }
    }
}
