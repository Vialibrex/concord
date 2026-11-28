//! A small REALITY server for tests: authenticates the session id like
//! `utls.RealityServer`, then speaks just enough TLS 1.3 to echo.

use std::collections::HashSet;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::agreement::{self, X25519};
use aws_lc_rs::rand::fill;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::fingerprints::{GROUP_X25519, GROUP_X25519_MLKEM768};
use crate::reality::server::{ClientHello, RealityAuth, RealityCert, ServerFlight, server_share};
use crate::reality::{CT_APPLICATION_DATA, CT_HANDSHAKE, RecordKey, Suite, put_u24};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    BadFinished,
    NoSessionIdEcho,
    HelloRetry,
    BadHmac,
    BadCertificateVerify,
    UnsupportedCipher,
    HugeRecord,
    Garbage,
}

pub struct MockReality {
    private_key: [u8; 32],
    cert: RealityCert,
    other_cert: RealityCert,
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub hybrid: bool,
    pub fault: Fault,
    pub alpn: Option<&'static [u8]>,
    pub suite: u16,
    pub jls: bool,
    pub fragmented: bool,
}

impl MockReality {
    pub fn new() -> Self {
        let mut private_key = [0; 32];
        fill(&mut private_key).unwrap();
        let public_key = agreement::PrivateKey::from_private_key(&X25519, &private_key)
            .unwrap()
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        Self {
            private_key,
            cert: reality_cert(),
            other_cert: reality_cert(),
            public_key,
            short_id: [0xab, 0xcd, 0, 0, 0, 0, 0, 0],
            hybrid: false,
            fault: Fault::None,
            alpn: Some(b"h2"),
            suite: 0x1301,
            jls: false,
            fragmented: false,
        }
    }
}

fn reality_cert() -> RealityCert {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let params = rcgen::CertificateParams::new(vec!["reality.test".into()]).unwrap();
    let der = params.self_signed(&key).unwrap().der().to_vec();
    RealityCert::new(der, &key.serialize_der()).unwrap()
}

async fn read_record<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
    io.read_exact(&mut body).await?;
    Ok((header, body))
}

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 3, 3];
    out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    put_u24(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

fn bad(text: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, text.to_owned())
}

impl MockReality {
    pub async fn serve<S: AsyncRead + AsyncWrite + Unpin>(&self, mut io: S) -> io::Result<()> {
        let (_, hello) = read_record(&mut io).await?;
        let parsed = ClientHello::parse(&hello)?;

        if self.fault == Fault::Garbage {
            io.write_all(&[0x99; 600]).await?;
            return Ok(());
        }
        if self.fault == Fault::HugeRecord {
            io.write_all(&[22, 3, 3, 0xff, 0xff]).await?;
            io.write_all(&vec![0u8; 70_000]).await?;
            return Ok(());
        }

        let auth_key = if self.jls {
            use aes_gcm::aead::{Aead, KeyInit, array::typenum::U32};
            use sha2::{Digest, Sha256};
            let mut zeroed = hello.clone();
            zeroed[6..38].fill(0);
            let key = Sha256::digest([b"secret".as_slice(), &zeroed].concat());
            let nonce = Sha256::digest([b"name".as_slice(), &zeroed].concat());
            let cipher = aes_gcm::AesGcm::<aes_gcm::aes::Aes256, U32>::new(&key);
            if cipher.decrypt(&nonce, &hello[6..38]).is_err() {
                return Err(bad("jls client random does not authenticate"));
            }
            vec![0; 32]
        } else {
            let auth = RealityAuth::new(
                &self.private_key,
                HashSet::from(["cover.test".to_owned()]),
                HashSet::from([self.short_id]),
                Duration::ZERO,
                Default::default(),
            )?;
            let unix_now = || {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
            };
            auth.authenticate(&parsed, unix_now)
                .ok_or_else(|| bad("unknown client"))?
                .auth_key
        };

        let group = if self.hybrid && parsed.share(GROUP_X25519_MLKEM768).is_some() {
            GROUP_X25519_MLKEM768
        } else {
            GROUP_X25519
        };
        let (share, shared) = server_share(group, &parsed)?;

        let mut random = [0u8; 32];
        fill(&mut random).unwrap();
        if self.fault == Fault::HelloRetry {
            random = [
                0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
                0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
                0xc8, 0xa8, 0x33, 0x9c,
            ];
        }
        let cipher = if self.fault == Fault::UnsupportedCipher {
            0x00ff
        } else {
            self.suite
        };
        let mut sh = vec![3, 3];
        sh.extend_from_slice(&random);
        sh.push(32);
        if self.fault == Fault::NoSessionIdEcho {
            sh.extend_from_slice(&[0u8; 32]);
        } else {
            sh.extend_from_slice(parsed.session_id());
        }
        sh.extend_from_slice(&cipher.to_be_bytes());
        sh.push(0);
        let mut exts = vec![0, 43, 0, 2, 3, 4, 0, 51];
        exts.extend_from_slice(&u16::try_from(4 + share.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&group.to_be_bytes());
        exts.extend_from_slice(&u16::try_from(share.len()).unwrap().to_be_bytes());
        exts.extend_from_slice(&share);
        sh.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        sh.extend_from_slice(&exts);
        let mut server_hello = message(2, &sh);
        if self.jls && self.fault != Fault::HelloRetry {
            use aes_gcm::aead::{Aead, KeyInit, array::typenum::U32};
            use sha2::{Digest, Sha256};
            server_hello[6..38].fill(0);
            let key = Sha256::digest([b"secret".as_slice(), &server_hello].concat());
            let nonce = Sha256::digest([b"name".as_slice(), &server_hello].concat());
            let cipher = aes_gcm::AesGcm::<aes_gcm::aes::Aes256, U32>::new(&key);
            let random = cipher.encrypt(&nonce, [7; 16].as_slice()).unwrap();
            server_hello[6..38].copy_from_slice(&random);
        }
        for chunk in server_hello.chunks(if self.fragmented {
            1
        } else {
            server_hello.len()
        }) {
            io.write_all(&record(CT_HANDSHAKE, chunk)).await?;
        }
        io.write_all(&[20, 3, 3, 0, 1, 1]).await?;
        let Some(suite) = Suite::from_id(cipher) else {
            return Ok(());
        };
        if self.fault == Fault::HelloRetry {
            return Ok(());
        }

        let flight = ServerFlight::new(suite, &shared, &hello, &server_hello);
        let mut server_key = flight.server_key()?;
        let mut client_key = flight.client_key()?;

        let mut extensions = Vec::new();
        if let Some(alpn) = self.alpn {
            let mut list = vec![u8::try_from(alpn.len()).unwrap()];
            list.extend_from_slice(alpn);
            extensions.extend_from_slice(&[0, 16]);
            extensions.extend_from_slice(&u16::try_from(list.len() + 2).unwrap().to_be_bytes());
            extensions.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
            extensions.extend_from_slice(&list);
        }
        let mut der = self.cert.for_client(&auth_key);
        if self.fault == Fault::BadHmac {
            let at = der.len() - 64;
            der[at] ^= 1;
        }
        let signer = if self.fault == Fault::BadCertificateVerify {
            &self.other_cert
        } else {
            &self.cert
        };
        let (mut messages, flight) = flight.messages(&extensions, &der, signer)?;
        if self.fault == Fault::BadFinished {
            messages[3][4] ^= 1;
        }
        for msg in &messages {
            io.write_all(&server_key.seal(CT_HANDSHAKE, msg)?).await?;
        }
        io.flush().await?;

        let (header, mut body) = loop {
            let (header, body) = read_record(&mut io).await?;
            if header[0] != 20 {
                break (header, body);
            }
        };
        let (kind, len) = client_key.open_in_place(&header, &mut body)?;
        if kind != CT_HANDSHAKE {
            return Err(bad("client finished mismatch"));
        }
        let secrets = flight.client_finished(&body[..len])?;

        let mut read_key = RecordKey::new(suite, &secrets.client)?;
        let mut write_key = RecordKey::new(suite, &secrets.server)?;
        loop {
            let (header, mut body) = match read_record(&mut io).await {
                Ok(record) => record,
                Err(_) => return Ok(()),
            };
            let (kind, len) = read_key.open_in_place(&header, &mut body)?;
            if kind == CT_APPLICATION_DATA {
                io.write_all(&write_key.seal(CT_APPLICATION_DATA, &body[..len])?)
                    .await?;
                io.flush().await?;
            } else if kind == 21 {
                io.write_all(&write_key.seal(21, &[1, 0])?).await?;
                return Ok(());
            }
        }
    }
}
