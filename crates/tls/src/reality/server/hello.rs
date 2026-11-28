use std::collections::HashSet;
use std::io;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};

use super::super::hello::{SESSION_ID_LEN, SESSION_ID_OFFSET};
use super::super::schedule::{Hash, expand, extract};
use super::super::wire::Cursor;
use super::share::{MLKEM768_KEY, X25519_KEY};
use crate::error::invalid_data;
use crate::fingerprints::{GROUP_X25519, GROUP_X25519_MLKEM768};

pub(super) const CLIENT_HELLO: u8 = 1;
pub(super) const SERVER_NAME: u16 = 0;
const HOST_NAME: u8 = 0;
pub(super) const SUPPORTED_VERSIONS: u16 = 43;
pub(super) const KEY_SHARE: u16 = 51;
pub(super) const TLS13: u16 = 0x0304;
const AUTH_KEY_LEN: usize = 32;
const SEALED_LEN: usize = 16;
const SALT_LEN: usize = 20;

pub(crate) struct ClientHello<'a> {
    message: &'a [u8],
    random: [u8; 32],
    session_id: &'a [u8],
    server_name: Option<&'a [u8]>,
    tls13: bool,
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
        let mut hello = ClientHello {
            message,
            random,
            session_id,
            server_name: None,
            tls13: false,
            shares: Vec::new(),
        };
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
                match kind {
                    SERVER_NAME => hello.server_name = Some(host_name(data)?),
                    SUPPORTED_VERSIONS => hello.tls13 = offers_tls13(data)?,
                    KEY_SHARE => hello.shares = key_shares(data)?,
                    _ => {}
                }
            }
        }
        Ok(hello)
    }

    /// Whether Go's `mutualVersion` settles on TLS 1.3 and the host name is one of
    /// `server_names`, the two checks of `reality.go:383` before any key is used.
    pub(crate) fn may_authenticate(&self, server_names: &HashSet<String>) -> bool {
        let name = self.server_name.unwrap_or_default();
        let named = std::str::from_utf8(name).is_ok_and(|name| server_names.contains(name));
        self.tls13 && named
    }

    pub(crate) fn random(&self) -> [u8; 32] {
        self.random
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

/// `handshake_messages.go:505-533`.
fn host_name(extension: &[u8]) -> io::Result<&[u8]> {
    let mut extension = Cursor::new(extension);
    let mut list = Cursor::new(extension.vec16()?);
    if !extension.is_empty() || list.is_empty() {
        return Err(malformed());
    }
    let mut host = None;
    while !list.is_empty() {
        let kind = list.u8()?;
        let name = list.vec16()?;
        if name.is_empty() || (kind == HOST_NAME && host.is_some()) {
            return Err(malformed());
        }
        if kind == HOST_NAME {
            host = Some(name);
        }
    }
    let host = host.unwrap_or_default();
    if host.ends_with(b".") {
        return Err(malformed());
    }
    Ok(host)
}

fn offers_tls13(extension: &[u8]) -> io::Result<bool> {
    let mut extension = Cursor::new(extension);
    let mut list = Cursor::new(extension.vec8()?);
    if !extension.is_empty() || list.is_empty() {
        return Err(malformed());
    }
    let mut tls13 = false;
    while !list.is_empty() {
        tls13 |= list.u16()? == TLS13;
    }
    Ok(tls13)
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
    use super::super::testing::*;
    use super::*;

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
        let short_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let public = server
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let auth_key = seal(&mut message, &client, public, short_id, 1_700_000_000);
        let opened = open_session_id(&server, &ClientHello::parse(&message).unwrap()).unwrap();
        assert_eq!(opened.auth_key, auth_key);
        assert_eq!(opened.sealed[8..], short_id);
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
        let mut trailing = hello([7; 32], Some(&share));
        trailing.push(0);
        let twice = [share.clone(), share.clone()].concat();
        let mut long_share = share.clone();
        long_share.push(0);
        long_share[3] += 1;
        let refused = [
            trailing,
            hello([7; 32], Some(&twice)),
            hello([7; 32], Some(&long_share)),
            with_shares(&[(GROUP_X25519, &[])]),
        ];
        for message in refused {
            assert!(ClientHello::parse(&message).is_err(), "{message:?}");
        }
        let refused_extensions = [
            server_name(&[(HOST_NAME, b"a.test"), (HOST_NAME, b"b.test")]),
            server_name(&[(HOST_NAME, b"a.test.")]),
            server_name(&[(1, b"")]),
            server_name(&[]),
            supported_versions(&[]),
            extension(SUPPORTED_VERSIONS, &[1, 3]),
        ];
        for extension in refused_extensions {
            let message = hello([7; 32], Some(&extension));
            assert!(ClientHello::parse(&message).is_err(), "{extension:?}");
        }
    }

    #[test]
    fn the_host_name_and_tls13_are_read_as_go_reads_them() {
        let names = HashSet::from(["a.test".to_owned()]);
        let mut extensions = server_name(&[(1, b"other"), (HOST_NAME, b"a.test")]);
        extensions.extend_from_slice(&supported_versions(&[0x0a0a, TLS13]));
        let message = hello([7; 32], Some(&extensions));
        assert!(
            ClientHello::parse(&message)
                .unwrap()
                .may_authenticate(&names)
        );
        let unnamed = hello([7; 32], Some(&supported_versions(&[TLS13])));
        assert!(
            !ClientHello::parse(&unnamed)
                .unwrap()
                .may_authenticate(&names)
        );
        let named = HashSet::from([String::new()]);
        assert!(
            ClientHello::parse(&unnamed)
                .unwrap()
                .may_authenticate(&named)
        );
    }

    /// Go takes a hello with no extensions and a session ID of another length, and then
    /// fails to authenticate it, as this does.
    #[test]
    fn a_hello_with_no_extensions_or_a_short_session_id_does_not_authenticate() {
        let private = agreement::PrivateKey::generate(&X25519).unwrap();
        let bare = hello([7; 32], None);
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
