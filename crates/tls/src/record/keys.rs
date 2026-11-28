use std::io;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use aws_lc_rs::aead;
use concord_common::sync::lock;
use rustls::crypto::cipher::{AeadKey, Iv, MessageDecrypter, MessageEncrypter};
use rustls::kernel::KernelConnection;
use rustls::{
    ConnectionTrafficSecrets, ExtractedSecrets, ProtocolVersion, SupportedCipherSuite,
    Tls12CipherSuite,
};

use crate::ciphers::Tls12GcmSeal;

pub(super) fn tls_error(err: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn key_iv(secrets: ConnectionTrafficSecrets) -> io::Result<(AeadKey, Iv)> {
    match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv }
        | ConnectionTrafficSecrets::Aes256Gcm { key, iv }
        | ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => Ok((key, iv)),
        _ => Err(invalid("tls: cipher suite has no record layer")),
    }
}

/// ConnectionTrafficSecrets joins TLS 1.2's fixed IV and explicit nonce part; the suite's
/// key block shape splits them again.
fn tls12_iv(suite: &Tls12CipherSuite, iv: &Iv) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let shape = suite.aead_alg.key_block_shape();
    let iv = iv.as_ref();
    let fixed = iv.get(..shape.fixed_iv_len);
    let explicit = iv.get(shape.fixed_iv_len..shape.fixed_iv_len + shape.explicit_nonce_len);
    match (fixed, explicit) {
        (Some(fixed), Some(explicit)) => Ok((fixed.to_vec(), explicit.to_vec())),
        _ => Err(invalid("tls: short iv")),
    }
}

/// The suite's own AEAD, as rustls builds it for itself.
fn encrypter(
    suite: SupportedCipherSuite,
    secrets: ConnectionTrafficSecrets,
    seq: u64,
) -> io::Result<Box<dyn MessageEncrypter>> {
    let gcm: Option<&'static aead::Algorithm> = match &secrets {
        ConnectionTrafficSecrets::Aes128Gcm { .. } => Some(&aead::AES_128_GCM),
        ConnectionTrafficSecrets::Aes256Gcm { .. } => Some(&aead::AES_256_GCM),
        _ => None,
    };
    let (key, iv) = key_iv(secrets)?;
    Ok(match (suite, gcm) {
        (SupportedCipherSuite::Tls13(_), Some(algorithm)) if seq != 0 => {
            crate::ciphers::tls13_sealer(algorithm, key.as_ref(), iv)?
        }
        (SupportedCipherSuite::Tls13(suite), _) => suite.aead_alg.encrypter(key, iv),
        (SupportedCipherSuite::Tls12(_), Some(algorithm)) => {
            Box::new(Tls12GcmSeal::new(algorithm, key.as_ref(), iv.as_ref())?)
        }
        (SupportedCipherSuite::Tls12(suite), None) => {
            let (fixed, explicit) = tls12_iv(suite, &iv)?;
            suite.aead_alg.encrypter(key, &fixed, &explicit)
        }
    })
}

#[cfg(test)]
pub(crate) fn test_encrypter(
    suite: SupportedCipherSuite,
    secrets: ConnectionTrafficSecrets,
    seq: u64,
) -> io::Result<Box<dyn MessageEncrypter>> {
    encrypter(suite, secrets, seq)
}

fn decrypter(
    suite: SupportedCipherSuite,
    secrets: ConnectionTrafficSecrets,
) -> io::Result<Box<dyn MessageDecrypter>> {
    let (key, iv) = key_iv(secrets)?;
    Ok(match suite {
        SupportedCipherSuite::Tls13(suite) => suite.aead_alg.decrypter(key, iv),
        SupportedCipherSuite::Tls12(suite) => {
            let (fixed, _) = tls12_iv(suite, &iv)?;
            suite.aead_alg.decrypter(key, &fixed)
        }
    })
}

/// Derives the next traffic key of one direction for a TLS 1.3 KeyUpdate; sequence numbers
/// restart at zero.
pub(crate) trait KeySchedule: std::marker::Send {
    fn next_tx(&mut self) -> io::Result<Box<dyn MessageEncrypter>>;
    fn next_rx(&mut self) -> io::Result<Box<dyn MessageDecrypter>>;
}

struct RustlsSchedule<D> {
    kernel: KernelConnection<D>,
    suite: SupportedCipherSuite,
}

impl<D: std::marker::Send> KeySchedule for RustlsSchedule<D> {
    fn next_tx(&mut self) -> io::Result<Box<dyn MessageEncrypter>> {
        let (_, secrets) = self.kernel.update_tx_secret().map_err(tls_error)?;
        encrypter(self.suite, secrets, 0)
    }

    fn next_rx(&mut self) -> io::Result<Box<dyn MessageDecrypter>> {
        let (_, secrets) = self.kernel.update_rx_secret().map_err(tls_error)?;
        decrypter(self.suite, secrets)
    }
}

/// Each direction's cipher and next sequence number at transport handoff.
pub(crate) struct Keys {
    pub(crate) tls13: bool,
    /// Records one key may seal before it must be replaced.
    pub(crate) limit: u64,
    pub(crate) tx: (u64, Box<dyn MessageEncrypter>),
    pub(crate) rx: (u64, Box<dyn MessageDecrypter>),
    pub(crate) schedule: Box<dyn KeySchedule>,
}

impl Keys {
    pub(crate) fn from_rustls<D: std::marker::Send + 'static>(
        secrets: ExtractedSecrets,
        kernel: KernelConnection<D>,
    ) -> io::Result<Self> {
        let suite = kernel.negotiated_cipher_suite();
        let limit = match suite {
            SupportedCipherSuite::Tls13(suite) => suite.common.confidentiality_limit,
            SupportedCipherSuite::Tls12(suite) => suite.common.confidentiality_limit,
        };
        let (tx_seq, tx) = secrets.tx;
        let (rx_seq, rx) = secrets.rx;
        Ok(Keys {
            tls13: kernel.protocol_version() == ProtocolVersion::TLSv1_3,
            limit,
            tx: (tx_seq, encrypter(suite, tx, tx_seq)?),
            rx: (rx_seq, decrypter(suite, rx)?),
            schedule: Box::new(RustlsSchedule { kernel, suite }),
        })
    }
}

/// What both directions share. The key schedule is touched only on a KeyUpdate.
pub(super) struct Shared {
    pub(super) schedule: Mutex<Box<dyn KeySchedule>>,
    /// The peer asked for a KeyUpdate; RFC 8446 4.6.3 wants ours before our next record.
    pub(super) answer_key_update: AtomicBool,
}

impl Shared {
    pub(super) fn schedule(&self) -> std::sync::MutexGuard<'_, Box<dyn KeySchedule>> {
        lock(&self.schedule)
    }
}
