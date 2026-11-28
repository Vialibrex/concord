use std::any::Any;
use std::cell::RefCell;
use std::sync::Arc;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::generic_array::typenum::U32;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, aes::Aes256};
use quinn::crypto::rustls::QuicClientConfig;
use quinn_proto::crypto::{
    ClientConfig, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use rand::RngExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    ActiveKeyExchange, GetRandomFailed, SecureRandom, SharedSecret, SupportedKxGroup,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, NamedGroup, SignatureScheme};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

type Gcm = AesGcm<Aes256, U32>;

const RANDOM_LEN: usize = 32;
const SEED_LEN: usize = 16;
const HELLO_RANDOM_AT: usize = 6;
const HELLO_HEADER: usize = 4;
const SERVER_HELLO: u8 = 2;
fn refusal(code: TransportErrorCode, reason: &str) -> TransportError {
    TransportError {
        code,
        frame: None,
        reason: reason.to_string(),
    }
}

const DOWNGRADE_CANARIES: [[u8; 8]; 2] = [
    [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01],
    [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00],
];
const HELLO_RETRY_TAIL: [u8; 8] = [0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c];

/// A ShadowQUIC user: the name keys the nonce, the password the AES key.
#[derive(Clone, Debug)]
pub(super) struct JlsUser {
    pub(super) username: String,
    pub(super) password: String,
}

fn digest(first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

fn cipher(user: &JlsUser, auth: &[u8]) -> Gcm {
    let key = digest(user.password.as_bytes(), auth);
    Gcm::new(GenericArray::from_slice(&key))
}

fn nonce(user: &JlsUser, auth: &[u8]) -> GenericArray<u8, U32> {
    GenericArray::clone_from_slice(&digest(user.username.as_bytes(), auth))
}

fn forbidden_tail(random: &[u8]) -> bool {
    random.last_chunk::<8>().is_some_and(|tail| {
        tail == &HELLO_RETRY_TAIL || DOWNGRADE_CANARIES.iter().any(|canary| canary == tail)
    })
}

/// The ClientHello random: a sealed random seed, keyed by the hello itself
/// with its random field zeroed.
fn fake_random(user: &JlsUser, auth: &[u8]) -> Option<[u8; RANDOM_LEN]> {
    let cipher = cipher(user, auth);
    let nonce = nonce(user, auth);
    loop {
        let mut seed = [0u8; SEED_LEN];
        rand::rng().fill(&mut seed);
        let sealed = cipher.encrypt(&nonce, seed.as_slice()).ok()?;
        let sealed: [u8; RANDOM_LEN] = sealed.try_into().ok()?;
        if !forbidden_tail(&sealed) {
            return Some(sealed);
        }
    }
}

fn check_random(user: &JlsUser, random: &[u8], auth: &[u8]) -> bool {
    random.len() == RANDOM_LEN
        && cipher(user, auth)
            .decrypt(&nonce(user, auth), random)
            .is_ok_and(|plain| plain.len() == SEED_LEN)
}

fn zero_random(message: &mut [u8]) -> Option<()> {
    message
        .get_mut(HELLO_RANDOM_AT..HELLO_RANDOM_AT + RANDOM_LEN)?
        .fill(0);
    Some(())
}

/// What a ServerHello that is still arriving has shown so far.
enum Verdict {
    Incomplete,
    Authenticated,
    Rejected,
}

fn judge_server_hello(user: &JlsUser, received: &[u8]) -> Verdict {
    let Some(&[kind, a, b, c]) = received.get(..HELLO_HEADER) else {
        return Verdict::Incomplete;
    };
    if kind != SERVER_HELLO {
        return Verdict::Rejected;
    }
    let len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
    let Some(hello) = received.get(..HELLO_HEADER + len) else {
        return Verdict::Incomplete;
    };
    let mut auth = hello.to_vec();
    let random = hello
        .get(HELLO_RANDOM_AT..HELLO_RANDOM_AT + RANDOM_LEN)
        .map(<[u8]>::to_vec);
    match (zero_random(&mut auth), random) {
        (Some(()), Some(random)) if check_random(user, &random, &auth) => Verdict::Authenticated,
        _ => Verdict::Rejected,
    }
}

struct Script {
    random: [u8; RANDOM_LEN],
    filler: [u8; RANDOM_LEN],
    secret: [u8; 32],
}

thread_local! {
    // rustls takes its randomness from a `&'static dyn SecureRandom`, so the values for
    // one synchronous ClientHello construction can only reach it through the thread.
    static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
}

struct Scripted;

impl std::fmt::Debug for Scripted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Scripted")
    }
}

static SCRIPTED: Scripted = Scripted;
static SCRIPTED_X25519: ScriptedX25519 = ScriptedX25519;

impl SecureRandom for Scripted {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let scripted = SCRIPT.with(|slot| {
            slot.borrow().as_ref().map(|script| {
                if buf.len() == RANDOM_LEN {
                    buf.copy_from_slice(&script.random);
                } else {
                    for (byte, from) in buf.iter_mut().zip(script.filler.iter().cycle()) {
                        *byte = *from;
                    }
                }
            })
        });
        if scripted.is_none() {
            rand::rng().fill(buf);
        }
        Ok(())
    }
}

struct Restore(Option<Script>);

impl Drop for Restore {
    fn drop(&mut self) {
        SCRIPT.with(|slot| *slot.borrow_mut() = self.0.take());
    }
}

fn with_script<T>(script: Script, build: impl FnOnce() -> T) -> T {
    let previous = SCRIPT.with(|slot| slot.borrow_mut().replace(script));
    let _restore = Restore(previous);
    build()
}

#[derive(Debug)]
struct ScriptedX25519;

struct ActiveX25519 {
    secret: StaticSecret,
    public: [u8; 32],
}

impl SupportedKxGroup for ScriptedX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let bytes = SCRIPT
            .with(|slot| slot.borrow().as_ref().map(|script| script.secret))
            .unwrap_or_else(|| rand::rng().random());
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Box::new(ActiveX25519 { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::General("invalid x25519 public key".into()))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::Error::General("x25519 low order point".into()));
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// The server proves itself in its ServerHello random, so the certificate it
/// presents is only camouflage. The session refuses a server that did not.
#[derive(Debug)]
struct Camouflage(Vec<SignatureScheme>);

impl ServerCertVerifier for Camouflage {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.clone()
    }
}

/// QUIC client crypto that adds ShadowQUIC's JLS authentication to a TLS 1.3 handshake.
pub(super) struct JlsClient {
    quic: Arc<QuicClientConfig>,
    user: JlsUser,
}

impl JlsClient {
    pub(super) fn new(user: JlsUser, alpn: &[String]) -> Result<Self, String> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![&SCRIPTED_X25519];
        provider.secure_random = &SCRIPTED;
        let schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|err| err.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Camouflage(schemes)))
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
        config.resumption = rustls::client::Resumption::disabled();
        let quic = QuicClientConfig::try_from(Arc::new(config)).map_err(|err| err.to_string())?;
        Ok(JlsClient {
            quic: Arc::new(quic),
            user,
        })
    }
}

impl ClientConfig for JlsClient {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        let mut rng = rand::rng();
        let (filler, secret): ([u8; RANDOM_LEN], [u8; 32]) = (rng.random(), rng.random());
        let script = |random| Script {
            random,
            filler,
            secret,
        };
        let start = || {
            self.quic
                .clone()
                .start_session(version, server_name, params)
        };
        let mut probe = with_script(script([0; RANDOM_LEN]), start)?;
        let mut hello = Vec::new();
        probe.write_handshake(&mut hello);
        let random = fake_random(&self.user, &hello).unwrap_or([0; RANDOM_LEN]);
        let inner = with_script(script(random), start)?;
        Ok(Box::new(JlsSession {
            inner,
            user: self.user.clone(),
            probe: Some(hello),
            server_hello: Some(Vec::new()),
            broken: false,
        }))
    }
}

struct JlsSession {
    inner: Box<dyn Session>,
    user: JlsUser,
    /// The ClientHello the random was derived from, until the real one is written.
    probe: Option<Vec<u8>>,
    /// What has arrived of the first server flight, until it is judged.
    server_hello: Option<Vec<u8>>,
    broken: bool,
}

impl Session for JlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if self.broken {
            return Err(refusal(
                TransportErrorCode::INTERNAL_ERROR,
                "jls: the ClientHello changed after its random was derived",
            ));
        }
        if let Some(received) = &mut self.server_hello {
            received.extend_from_slice(buf);
            match judge_server_hello(&self.user, received) {
                Verdict::Incomplete => {}
                Verdict::Authenticated => self.server_hello = None,
                Verdict::Rejected => {
                    return Err(refusal(
                        TransportErrorCode::PROTOCOL_VIOLATION,
                        "jls authentication failed",
                    ));
                }
            }
        }
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let start = buf.len();
        let keys = self.inner.write_handshake(buf);
        if let Some(probe) = self.probe.take() {
            let mut sent = buf.get(start..).unwrap_or_default().to_vec();
            self.broken = zero_random(&mut sent).is_none() || sent != probe;
        }
        keys
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> JlsUser {
        JlsUser {
            username: "name".to_string(),
            password: "secret".to_string(),
        }
    }

    #[test]
    fn a_sealed_random_is_accepted_only_for_its_hello() {
        let mut hello = vec![1u8, 0, 0, 40];
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[0; RANDOM_LEN]);
        hello.extend_from_slice(&[7; 4]);
        let random = fake_random(&user(), &hello).unwrap();
        assert!(check_random(&user(), &random, &hello));
        let mut other = hello.clone();
        other[40] ^= 1;
        assert!(!check_random(&user(), &random, &other));
        let stranger = JlsUser {
            password: "other".to_string(),
            ..user()
        };
        assert!(!check_random(&stranger, &random, &hello));
    }

    #[test]
    fn a_server_hello_is_judged_once_it_is_whole() {
        let mut hello = vec![SERVER_HELLO, 0, 0, 34];
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[0; RANDOM_LEN]);
        let sealed = fake_random(&user(), &hello).unwrap();
        let mut wire = hello.clone();
        wire[HELLO_RANDOM_AT..HELLO_RANDOM_AT + RANDOM_LEN].copy_from_slice(&sealed);
        assert!(matches!(
            judge_server_hello(&user(), &wire[..20]),
            Verdict::Incomplete
        ));
        assert!(matches!(
            judge_server_hello(&user(), &wire),
            Verdict::Authenticated
        ));
        wire[10] ^= 1;
        assert!(matches!(
            judge_server_hello(&user(), &wire),
            Verdict::Rejected
        ));
        let mut not_hello = wire.clone();
        not_hello[0] = 1;
        assert!(matches!(
            judge_server_hello(&user(), &not_hello),
            Verdict::Rejected
        ));
    }

    #[test]
    fn the_tails_tls_reserves_are_never_produced() {
        assert!(forbidden_tail(&[
            0, 0, 0, 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01
        ]));
        assert!(forbidden_tail(&[
            1, 2, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
        ]));
        assert!(!forbidden_tail(&[0; 32]));
        for _ in 0..50 {
            let random = fake_random(&user(), b"hello").unwrap();
            assert!(!forbidden_tail(&random));
        }
    }

    #[test]
    fn the_scripted_source_repeats_a_handshake_and_restores_the_thread() {
        let script = || Script {
            random: [9; RANDOM_LEN],
            filler: [5; RANDOM_LEN],
            secret: [3; 32],
        };
        let first = with_script(script(), || {
            let (mut random, mut other) = ([0u8; RANDOM_LEN], [0u8; 2]);
            SCRIPTED.fill(&mut random).unwrap();
            SCRIPTED.fill(&mut other).unwrap();
            let key = SCRIPTED_X25519.start().unwrap().pub_key().to_vec();
            (random, other, key)
        });
        assert_eq!(first.0, [9; RANDOM_LEN]);
        assert_eq!(first.1, [5, 5]);
        let again = with_script(script(), || {
            SCRIPTED_X25519.start().unwrap().pub_key().to_vec()
        });
        assert_eq!(first.2, again);
        assert!(SCRIPT.with(|slot| slot.borrow().is_none()));
    }
}
