//! What the server reads from a ClientHello record: its server name and, for v3, whether a
//! user's password signed its session ID (`transport/shadowtls/protocol.go:79-152`,
//! `v3.go:255-279`).

use std::io;

use aws_lc_rs::constant_time::verify_slices_are_equal;

use super::conn::{HMAC_SIZE, new_hmac};
use super::frames::{HANDSHAKE, HEADER};
use super::tap::{RANDOM_SIZE, SESSION_ID_LENGTH_INDEX};
use crate::http1::invalid;

const CLIENT_HELLO: u8 = 1;
const SESSION_ID_SIZE: usize = 32;
const SIGNED_MIN: usize = SESSION_ID_LENGTH_INDEX + 1 + SESSION_ID_SIZE;
const TAG_AT: usize = SIGNED_MIN - HMAC_SIZE;
const SERVER_NAME_EXTENSION: u16 = 0;
const HOST_NAME: u8 = 0;

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len).ok_or_else(short)?;
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> io::Result<usize> {
        Ok(usize::from(
            self.take(1)?.first().copied().unwrap_or_default(),
        ))
    }

    fn u16(&mut self) -> io::Result<usize> {
        let bytes = self.take(2)?;
        Ok(bytes.iter().fold(0, |n, b| n << 8 | usize::from(*b)))
    }
}

fn short() -> io::Error {
    io::ErrorKind::UnexpectedEof.into()
}

/// The SNI host name, in the steps Go reads it: a hello that ends right after its
/// compression methods has none.
pub(super) fn server_name(frame: &[u8]) -> io::Result<String> {
    if frame.len() < HEADER + 4
        || frame.first() != Some(&HANDSHAKE)
        || frame.get(HEADER) != Some(&CLIENT_HELLO)
    {
        return Err(invalid("shadow-tls: invalid ClientHello"));
    }
    let mut cursor = Cursor(frame.get(HEADER + 1..).unwrap_or_default());
    let length = cursor
        .take(3)?
        .iter()
        .fold(0, |n, b| n << 8 | usize::from(*b));
    let mut hello = Cursor(cursor.take(length)?);
    hello.take(2 + RANDOM_SIZE)?;
    let session_id = hello.u8()?;
    hello.take(session_id)?;
    let suites = hello.u16()?;
    hello.take(suites)?;
    let methods = hello.u8()?;
    hello.take(methods)?;
    if hello.0.is_empty() {
        return Err(invalid("shadow-tls: ClientHello has no SNI"));
    }
    let extensions = hello.u16()?;
    let mut extensions = Cursor(hello.take(extensions)?);
    while extensions.0.len() >= 4 {
        let kind = extensions.u16()?;
        let length = extensions.u16()?;
        let body = extensions.take(length)?;
        if kind == usize::from(SERVER_NAME_EXTENSION) {
            return host_name(body);
        }
    }
    Err(invalid("shadow-tls: ClientHello has no SNI"))
}

fn host_name(extension: &[u8]) -> io::Result<String> {
    let mut extension = Cursor(extension);
    let length = extension.u16()?;
    let mut list = Cursor(extension.take(length)?);
    while list.0.len() >= 3 {
        let kind = list.u8()?;
        let length = list.u16()?;
        let name = list.take(length)?;
        if kind == usize::from(HOST_NAME) && !name.is_empty() {
            return Ok(String::from_utf8_lossy(name).into_owned());
        }
    }
    Err(invalid("shadow-tls: ClientHello has no host name"))
}

/// Whether the last four bytes of the session ID are the HMAC of the hello, with those four
/// zeroed, under `password`.
pub(super) fn signed_by(frame: &[u8], password: &str) -> bool {
    if frame.len() < SIGNED_MIN
        || frame.first() != Some(&HANDSHAKE)
        || frame.get(HEADER) != Some(&CLIENT_HELLO)
        || frame.get(SESSION_ID_LENGTH_INDEX).map(|n| usize::from(*n)) != Some(SESSION_ID_SIZE)
    {
        return false;
    }
    let (Some(before), Some(tag), Some(after)) = (
        frame.get(HEADER..TAG_AT),
        frame.get(TAG_AT..SIGNED_MIN),
        frame.get(SIGNED_MIN..),
    ) else {
        return false;
    };
    let mut mac = new_hmac(password.as_bytes());
    mac.update(before);
    mac.update(&[0; HMAC_SIZE]);
    mac.update(after);
    let sum = mac.sum();
    sum.get(..HMAC_SIZE)
        .is_some_and(|expected| verify_slices_are_equal(expected, tag).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16_bytes(n: usize) -> [u8; 2] {
        u16::try_from(n).unwrap().to_be_bytes()
    }

    fn hello(session_id: &[u8], extensions: Option<&[u8]>) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; RANDOM_SIZE]);
        body.push(u8::try_from(session_id.len()).unwrap());
        body.extend(session_id);
        body.extend([0, 2, 0x13, 0x01, 1, 0]);
        if let Some(extensions) = extensions {
            body.extend(u16_bytes(extensions.len()));
            body.extend(extensions);
        }
        let mut message = vec![CLIENT_HELLO];
        message.extend(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        message.extend(body);
        let mut frame = vec![HANDSHAKE, 3, 1];
        frame.extend(u16_bytes(message.len()));
        frame.extend(message);
        frame
    }

    fn server_names(entries: &[(u8, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (kind, name) in entries {
            list.push(*kind);
            list.extend(u16_bytes(name.len()));
            list.extend(*name);
        }
        let mut body = u16_bytes(list.len()).to_vec();
        body.extend(list);
        let mut extension = vec![0, 0];
        extension.extend(u16_bytes(body.len()));
        extension.extend(body);
        extension
    }

    fn named(name: &[u8]) -> Vec<u8> {
        hello(
            &[9; SESSION_ID_SIZE],
            Some(&server_names(&[(HOST_NAME, name)])),
        )
    }

    fn sign(frame: &mut [u8], password: &str) {
        frame[TAG_AT..SIGNED_MIN].fill(0);
        let mut mac = new_hmac(password.as_bytes());
        mac.update(&frame[HEADER..]);
        let sum = mac.sum();
        frame[TAG_AT..SIGNED_MIN].copy_from_slice(&sum[..HMAC_SIZE]);
    }

    #[test]
    fn the_host_name_is_found_past_other_extensions_and_names() {
        let mut extensions = vec![0, 43, 0, 3, 2, 3, 4];
        extensions.extend(server_names(&[(1, b"other"), (HOST_NAME, b"decoy.test")]));
        let frame = hello(&[9; SESSION_ID_SIZE], Some(&extensions));
        assert_eq!(server_name(&frame).unwrap(), "decoy.test");
    }

    #[test]
    fn a_hello_cut_anywhere_or_with_a_length_past_its_end_has_no_name() {
        let frame = named(b"decoy.test");
        for len in 0..frame.len() {
            assert!(server_name(&frame[..len]).is_err(), "cut at {len}");
        }
        let session_id_length = SESSION_ID_LENGTH_INDEX;
        let name_length = frame.len() - b"decoy.test".len() - 1;
        for at in [session_id_length, name_length] {
            let mut long = frame.clone();
            long[at] = 0xff;
            assert!(server_name(&long).is_err(), "length at {at}");
        }
    }

    #[test]
    fn a_hello_with_no_extensions_or_no_host_name_has_no_name() {
        let session_id = [9; SESSION_ID_SIZE];
        for extensions in [
            None,
            Some(server_names(&[])),
            Some(server_names(&[(1, b"other")])),
            Some(server_names(&[(HOST_NAME, b"")])),
        ] {
            let frame = hello(&session_id, extensions.as_deref());
            assert!(server_name(&frame).is_err(), "{extensions:?}");
        }
    }

    #[test]
    fn only_a_full_session_id_signed_with_the_password_signs() {
        let mut frame = named(b"decoy.test");
        sign(&mut frame, "one");
        assert!(signed_by(&frame, "one"));
        assert!(!signed_by(&frame, "two"));
        let mut short = hello(&[9; 16], Some(&server_names(&[(HOST_NAME, &[b'd'; 40])])));
        sign(&mut short, "one");
        assert!(!signed_by(&short, "one"));
    }
}
