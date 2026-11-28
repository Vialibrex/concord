use aws_lc_rs::agreement::{self, X25519};

use super::super::handshake::seal_reality;
use super::super::hello::{SESSION_ID_LEN, SESSION_ID_OFFSET};
use super::hello::{CLIENT_HELLO, KEY_SHARE, SERVER_NAME, SUPPORTED_VERSIONS, TLS13};
use crate::RealityOptions;
use crate::fingerprints::GROUP_X25519;

pub(super) fn u16_bytes(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap().to_be_bytes()
}

pub(super) fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&u16_bytes(data.len()));
    out.extend_from_slice(data);
    out
}

pub(super) fn key_share(shares: &[(u16, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (group, share) in shares {
        list.extend_from_slice(&extension(*group, share));
    }
    let mut data = u16_bytes(list.len()).to_vec();
    data.extend_from_slice(&list);
    extension(KEY_SHARE, &data)
}

pub(super) fn server_name(names: &[(u8, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (kind, name) in names {
        list.push(*kind);
        list.extend_from_slice(&u16_bytes(name.len()));
        list.extend_from_slice(name);
    }
    let mut data = u16_bytes(list.len()).to_vec();
    data.extend_from_slice(&list);
    extension(SERVER_NAME, &data)
}

pub(super) fn supported_versions(versions: &[u16]) -> Vec<u8> {
    let mut data = vec![u8::try_from(versions.len() * 2).unwrap()];
    for version in versions {
        data.extend_from_slice(&version.to_be_bytes());
    }
    extension(SUPPORTED_VERSIONS, &data)
}

pub(super) fn hello(random: [u8; 32], extensions: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&[9; SESSION_ID_LEN]);
    body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
    if let Some(extensions) = extensions {
        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(extensions);
    }
    let mut message = vec![CLIENT_HELLO];
    crate::reality::put_u24(&mut message, body.len());
    message.extend_from_slice(&body);
    message
}

pub(super) fn with_shares(shares: &[(u16, &[u8])]) -> Vec<u8> {
    hello([7; 32], Some(&key_share(shares)))
}

/// Seals `message`'s session ID as the REALITY client does, for the server whose key is
/// the public key `server`, and returns the client's auth key.
pub(super) fn seal(
    message: &mut [u8],
    client: &agreement::PrivateKey,
    server: [u8; 32],
    short_id: [u8; 8],
    unix: u64,
) -> Vec<u8> {
    let session_id = &mut message[SESSION_ID_OFFSET..][..SESSION_ID_LEN];
    session_id.fill(0);
    let options = RealityOptions {
        public_key: server,
        short_id,
        support_x25519mlkem768: false,
    };
    let random: [u8; 32] = message[6..38].try_into().unwrap();
    let (sealed, auth_key) = seal_reality(&options, client, &random, message, unix).unwrap();
    message[SESSION_ID_OFFSET..][..SESSION_ID_LEN].copy_from_slice(&sealed);
    auth_key
}

/// A TLS 1.3 hello naming `name`, with an X25519 share and its session ID sealed.
pub(super) fn sealed_hello(
    server: [u8; 32],
    random: [u8; 32],
    name: &str,
    short_id: [u8; 8],
    unix: u64,
) -> Vec<u8> {
    let client = agreement::PrivateKey::generate(&X25519).unwrap();
    let public = client.compute_public_key().unwrap();
    let mut extensions = server_name(&[(0, name.as_bytes())]);
    extensions.extend_from_slice(&supported_versions(&[TLS13, 0x0303]));
    extensions.extend_from_slice(&key_share(&[(GROUP_X25519, public.as_ref())]));
    let mut message = hello(random, Some(&extensions));
    seal(&mut message, &client, server, short_id, unix);
    message
}
