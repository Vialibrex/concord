use std::io;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};

use super::super::hello::{SESSION_ID_LEN, SESSION_ID_OFFSET};
use super::super::schedule::{Hash, expand, extract};
use super::super::wire::Cursor;
use super::share::{MLKEM768_KEY, X25519_KEY};
use crate::error::invalid_data;
use crate::fingerprints::{GROUP_X25519, GROUP_X25519_MLKEM768};

const CLIENT_HELLO: u8 = 1;
const KEY_SHARE: u16 = 51;
const AUTH_KEY_LEN: usize = 32;
const SEALED_LEN: usize = 16;
const SALT_LEN: usize = 20;

pub(crate) struct ClientHello<'a> {
    message: &'a [u8],
    random: [u8; 32],
    session_id: &'a [u8],
    shares: Vec<(u16, &'a [u8])>,
}

fn malformed() -> io::Error {
    invalid_data("REALITY: malformed ClientHello")
}

impl<'a> ClientHello<'a> {
    /// One handshake message, read as Go's `clientHelloMsg.unmarshal` reads it.
    pub(crate) fn parse(message: &'a [u8]) -> io::Result<Self> {
        let mut outer = Cursor::new(message);
        if outer.u8()? != CLIENT_HELLO {
            return Err(invalid_data("REALITY: not a ClientHello"));
        }
        let mut body = Cursor::new(outer.vec24()?);
        if !outer.is_empty() {
            return Err(malformed());
        }
        body.u16()?;
        let random = body.take(32)?.try_into().map_err(|_| malformed())?;
        let session_id = body.vec8()?;
        body.vec16()?;
        body.vec8()?;
        let mut shares = Vec::new();
        if !body.is_empty() {
            let mut extensions = Cursor::new(body.vec16()?);
            if !body.is_empty() {
                return Err(malformed());
            }
            let mut seen = Vec::new();
            while !extensions.is_empty() {
                let kind = extensions.u16()?;
                let data = extensions.vec16()?;
                if seen.contains(&kind) {
                    return Err(malformed());
                }
                seen.push(kind);
                if kind == KEY_SHARE {
                    shares = key_shares(data)?;
                }
            }
        }
        Ok(ClientHello {
            message,
            random,
            session_id,
            shares,
        })
    }

    pub(crate) fn session_id(&self) -> &'a [u8] {
        self.session_id
    }

    /// The first share of `group`, as `reality.go:237-242` takes it.
    pub(crate) fn share(&self, group: u16) -> Option<&'a [u8]> {
        self.shares
            .iter()
            .find(|(of, _)| *of == group)
            .map(|(_, share)| *share)
    }

    /// `reality.go:388-402`.
    fn auth_share(&self) -> Option<&'a [u8]> {
        let first = |group, len| {
            self.shares
                .iter()
                .find(|(of, share)| *of == group && share.len() == len)
                .map(|(_, share)| *share)
        };
        first(GROUP_X25519, X25519_KEY).or_else(|| {
            first(GROUP_X25519_MLKEM768, MLKEM768_KEY + X25519_KEY)
                .and_then(|share| share.get(MLKEM768_KEY..))
        })
    }
}

fn key_shares(extension: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut extension = Cursor::new(extension);
    let mut list = Cursor::new(extension.vec16()?);
    if !extension.is_empty() {
        return Err(malformed());
    }
    let mut shares = Vec::new();
    while !list.is_empty() {
        let group = list.u16()?;
        let share = list.vec16()?;
        if share.is_empty() {
            return Err(malformed());
        }
        shares.push((group, share));
    }
    Ok(shares)
}

pub(crate) struct Opened {
    pub(crate) auth_key: Vec<u8>,
    pub(crate) sealed: [u8; SEALED_LEN],
}

/// `reality.go:403-425`. A low-order share, for which Go's `curve25519.X25519` fails, opens
/// nothing.
pub(crate) fn open_session_id(
    private: &agreement::PrivateKey,
    hello: &ClientHello<'_>,
) -> Option<Opened> {
    if hello.session_id.len() != SESSION_ID_LEN {
        return None;
    }
    let share = hello.auth_share()?;
    let secret = agreement::agree(private, UnparsedPublicKey::new(&X25519, share), (), |s| {
        Ok(s.to_vec())
    })
    .ok()?;
    if secret.iter().all(|byte| *byte == 0) {
        return None;
    }
    let (salt, nonce) = hello.random.split_at(SALT_LEN);
    let auth_key = expand(
        &extract(Hash::Sha256, salt, &secret),
        b"REALITY",
        AUTH_KEY_LEN,
    );
    let aead = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &auth_key).ok()?);
    let mut aad = hello.message.to_vec();
    aad.get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)?
        .fill(0);
    let mut sealed = hello.session_id.to_vec();
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let opened = aead
        .open_in_place(nonce, Aad::from(aad.as_slice()), &mut sealed)
        .ok()?;
    Some(Opened {
        sealed: opened.try_into().ok()?,
        auth_key,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::handshake::seal_reality;
    use super::*;
    use crate::RealityOptions;

    fn u16_bytes(n: usize) -> [u8; 2] {
        u16::try_from(n).unwrap().to_be_bytes()
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&u16_bytes(data.len()));
        out.extend_from_slice(data);
        out
    }

    fn key_share(shares: &[(u16, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (group, share) in shares {
            list.extend_from_slice(&extension(*group, share));
        }
        let mut data = u16_bytes(list.len()).to_vec();
        data.extend_from_slice(&list);
        extension(KEY_SHARE, &data)
    }

    fn hello(extensions: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
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

    fn with_shares(shares: &[(u16, &[u8])]) -> Vec<u8> {
        hello(Some(&key_share(shares)))
    }

    #[test]
    fn a_low_order_share_opens_no_session_id() {
        let private = agreement::PrivateKey::generate(&X25519).unwrap();
        let message = with_shares(&[(GROUP_X25519, &[0; X25519_KEY])]);
        let hello = ClientHello::parse(&message).unwrap();
        assert_eq!(hello.auth_share(), Some(&[0; X25519_KEY][..]));
        assert!(open_session_id(&private, &hello).is_none());
    }

    #[test]
    fn a_client_with_only_a_hybrid_share_authenticates_with_its_x25519_half() {
        let server = agreement::PrivateKey::generate(&X25519).unwrap();
        let client = agreement::PrivateKey::generate(&X25519).unwrap();
        let mut share = vec![5; MLKEM768_KEY];
        share.extend_from_slice(client.compute_public_key().unwrap().as_ref());
        let mut message = with_shares(&[(GROUP_X25519_MLKEM768, &share)]);
        message[SESSION_ID_OFFSET..][..SESSION_ID_LEN].fill(0);
        let options = RealityOptions {
            public_key: server
                .compute_public_key()
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap(),
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            support_x25519mlkem768: true,
        };
        let (session_id, auth_key) =
            seal_reality(&options, &client, &[7; 32], &message, 1_700_000_000).unwrap();
        message[SESSION_ID_OFFSET..][..SESSION_ID_LEN].copy_from_slice(&session_id);
        let opened = open_session_id(&server, &ClientHello::parse(&message).unwrap()).unwrap();
        assert_eq!(opened.auth_key, auth_key);
        assert_eq!(opened.sealed[8..], options.short_id);
    }

    #[test]
    fn the_first_share_of_a_group_is_the_one_taken() {
        let message = with_shares(&[
            (GROUP_X25519, &[1; 31]),
            (GROUP_X25519, &[2; X25519_KEY]),
            (GROUP_X25519, &[3; X25519_KEY]),
        ]);
        let hello = ClientHello::parse(&message).unwrap();
        assert_eq!(hello.share(GROUP_X25519), Some(&[1; 31][..]));
        assert_eq!(hello.auth_share(), Some(&[2; X25519_KEY][..]));
    }

    #[test]
    fn a_hello_go_would_not_unmarshal_is_refused() {
        let share = key_share(&[(GROUP_X25519, &[2; X25519_KEY])]);
        let mut trailing = hello(Some(&share));
        trailing.push(0);
        let twice = [share.clone(), share.clone()].concat();
        let mut long_share = share.clone();
        long_share.push(0);
        long_share[3] += 1;
        let refused = [
            trailing,
            hello(Some(&twice)),
            hello(Some(&long_share)),
            with_shares(&[(GROUP_X25519, &[])]),
        ];
        for message in refused {
            assert!(ClientHello::parse(&message).is_err(), "{message:?}");
        }
    }

    /// Go takes a hello with no extensions and a session ID of another length, and then
    /// fails to authenticate it, as this does.
    #[test]
    fn a_hello_with_no_extensions_or_a_short_session_id_does_not_authenticate() {
        let private = agreement::PrivateKey::generate(&X25519).unwrap();
        let bare = hello(None);
        let hello = ClientHello::parse(&bare).unwrap();
        assert!(hello.auth_share().is_none());
        assert!(open_session_id(&private, &hello).is_none());
        let mut short = with_shares(&[(GROUP_X25519, &[2; X25519_KEY])]);
        short[SESSION_ID_OFFSET - 1] = 16;
        short.drain(SESSION_ID_OFFSET + 16..SESSION_ID_OFFSET + SESSION_ID_LEN);
        let length = short.len() - 4;
        short[1..4].copy_from_slice(&u32::try_from(length).unwrap().to_be_bytes()[1..]);
        let short = ClientHello::parse(&short).unwrap();
        assert_eq!(short.session_id().len(), 16);
        assert!(open_session_id(&private, &short).is_none());
    }
}
