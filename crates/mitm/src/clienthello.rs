use std::io;

use concord_common::BoxStream;
use tokio::io::AsyncReadExt;

pub(crate) const RECORD_TYPE_HANDSHAKE: u8 = 22;
const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const MAX_CLIENT_HELLO_LEN: usize = 64 * 1024;
const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_ALPN: u16 = 16;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ClientHello {
    pub server_name: String,
    pub protocols: Vec<String>,
}

#[derive(Debug)]
pub(crate) enum HelloError {
    NotClientHello,
    Io(io::Error),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelloError::NotClientHello => f.write_str("not a TLS ClientHello"),
            HelloError::Io(err) => err.fmt(f),
        }
    }
}

impl From<io::Error> for HelloError {
    fn from(err: io::Error) -> Self {
        HelloError::Io(err)
    }
}

/// A stream whose first bytes were read to decide what it carries; `buf` is
/// replayed ahead of it when the connection is not taken.
pub(crate) struct Peeker {
    pub stream: BoxStream,
    pub buf: Vec<u8>,
}

impl Peeker {
    pub fn new(stream: BoxStream, head: Vec<u8>) -> Peeker {
        Peeker { stream, buf: head }
    }

    /// Reads until `n` bytes are buffered; an end of stream is an error.
    pub async fn fill(&mut self, n: usize) -> io::Result<()> {
        while self.buf.len() < n {
            let mut chunk = [0u8; 4096];
            let want = chunk.len().min(n - self.buf.len()).max(1);
            let read = self
                .stream
                .read(chunk.get_mut(..want).unwrap_or_default())
                .await?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.buf
                .extend_from_slice(chunk.get(..read).unwrap_or_default());
        }
        Ok(())
    }

    /// Reads up to `n` bytes, stopping early at the end of the stream.
    pub async fn fill_up_to(&mut self, n: usize) {
        let _ = self.fill(n).await;
    }

    async fn at(&mut self, offset: usize, length: usize) -> Result<&[u8], HelloError> {
        let end = offset + length;
        if end > MAX_CLIENT_HELLO_LEN {
            return Err(HelloError::NotClientHello);
        }
        self.fill(end).await?;
        self.buf.get(offset..end).ok_or(HelloError::NotClientHello)
    }
}

fn record_payload_len(header: &[u8]) -> Result<usize, HelloError> {
    let (kind, major, length) = match header {
        [kind, major, _, hi, lo] => (*kind, *major, usize::from(*hi) << 8 | usize::from(*lo)),
        _ => return Err(HelloError::NotClientHello),
    };
    if kind != RECORD_TYPE_HANDSHAKE || major != 3 || length == 0 {
        return Err(HelloError::NotClientHello);
    }
    Ok(length)
}

fn try_parse_message(message: &[u8]) -> Result<Option<ClientHello>, HelloError> {
    let Some([kind, a, b, c]) = message.get(..HANDSHAKE_HEADER_LEN) else {
        return Ok(None);
    };
    if *kind != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(HelloError::NotClientHello);
    }
    let size =
        HANDSHAKE_HEADER_LEN + (usize::from(*a) << 16 | usize::from(*b) << 8 | usize::from(*c));
    if message.len() < size {
        return Ok(None);
    }
    let body = message
        .get(HANDSHAKE_HEADER_LEN..size)
        .ok_or(HelloError::NotClientHello)?;
    parse_client_hello(body)
        .map(Some)
        .ok_or(HelloError::NotClientHello)
}

/// Leaves the ClientHello in the buffer, so a connection that is not decrypted
/// still reaches the server whole. It may span several records.
pub(crate) async fn peek_client_hello(peeker: &mut Peeker) -> Result<ClientHello, HelloError> {
    let first_len = record_payload_len(peeker.at(0, RECORD_HEADER_LEN).await?)?;
    let first = peeker.at(RECORD_HEADER_LEN, first_len).await?;
    if let Some(hello) = try_parse_message(first)? {
        return Ok(hello);
    }
    let mut message = Vec::from(first);
    let mut offset = RECORD_HEADER_LEN + first_len;
    loop {
        let length = record_payload_len(peeker.at(offset, RECORD_HEADER_LEN).await?)?;
        let payload = peeker.at(offset + RECORD_HEADER_LEN, length).await?;
        message.extend_from_slice(payload);
        offset += RECORD_HEADER_LEN + length;
        if let Some(hello) = try_parse_message(&message)? {
            return Ok(hello);
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.bytes(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        match self.bytes(2)? {
            [hi, lo] => Some(u16::from(*hi) << 8 | u16::from(*lo)),
            _ => None,
        }
    }

    fn prefixed8(&mut self) -> Option<Reader<'a>> {
        let n = usize::from(self.u8()?);
        self.bytes(n).map(Reader)
    }

    fn prefixed16(&mut self) -> Option<Reader<'a>> {
        let n = usize::from(self.u16()?);
        self.bytes(n).map(Reader)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn parse_client_hello(body: &[u8]) -> Option<ClientHello> {
    let mut s = Reader(body);
    s.u16()?;
    s.bytes(32)?;
    s.prefixed8()?;
    s.prefixed16()?;
    s.prefixed8()?;
    let mut hello = ClientHello::default();
    if s.is_empty() {
        return Some(hello);
    }
    let mut extensions = s.prefixed16()?;
    if !s.is_empty() {
        return None;
    }
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let mut data = extensions.prefixed16()?;
        match kind {
            EXTENSION_SERVER_NAME => read_server_name(&mut data, &mut hello)?,
            EXTENSION_ALPN => read_protocols(&mut data, &mut hello)?,
            _ => {}
        }
    }
    Some(hello)
}

fn read_server_name(data: &mut Reader<'_>, hello: &mut ClientHello) -> Option<()> {
    let mut names = data.prefixed16()?;
    while !names.is_empty() {
        let name_type = names.u8()?;
        let name = names.prefixed16()?;
        if name_type == 0 {
            hello.server_name = String::from_utf8_lossy(name.0).into_owned();
        }
    }
    Some(())
}

fn read_protocols(data: &mut Reader<'_>, hello: &mut ClientHello) -> Option<()> {
    let mut protocols = data.prefixed16()?;
    while !protocols.is_empty() {
        let protocol = protocols.prefixed8()?;
        hello
            .protocols
            .push(String::from_utf8_lossy(protocol.0).into_owned());
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    fn hello_body(server_name: &str, protocols: &[&str]) -> Vec<u8> {
        let mut extensions = Vec::new();
        if !server_name.is_empty() {
            let name = server_name.as_bytes();
            let mut entry = vec![0u8];
            entry.extend((name.len() as u16).to_be_bytes());
            entry.extend(name);
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend(entry);
            extensions.extend(EXTENSION_SERVER_NAME.to_be_bytes());
            extensions.extend((list.len() as u16).to_be_bytes());
            extensions.extend(list);
        }
        if !protocols.is_empty() {
            let mut list = Vec::new();
            for protocol in protocols {
                list.push(protocol.len() as u8);
                list.extend(protocol.as_bytes());
            }
            let mut data = (list.len() as u16).to_be_bytes().to_vec();
            data.extend(list);
            extensions.extend(EXTENSION_ALPN.to_be_bytes());
            extensions.extend((data.len() as u16).to_be_bytes());
            extensions.extend(data);
        }
        let mut body = vec![3, 3];
        body.extend([0u8; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 0x01]);
        body.extend([1, 0]);
        body.extend((extensions.len() as u16).to_be_bytes());
        body.extend(extensions);
        body
    }

    fn handshake(body: &[u8]) -> Vec<u8> {
        let mut out = vec![HANDSHAKE_TYPE_CLIENT_HELLO];
        out.extend(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend(body);
        out
    }

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![RECORD_TYPE_HANDSHAKE, 3, 1];
        out.extend((payload.len() as u16).to_be_bytes());
        out.extend(payload);
        out
    }

    async fn peek(wire: Vec<u8>) -> (Result<ClientHello, HelloError>, Peeker) {
        let (mut far, near) = duplex(1 << 18);
        far.write_all(&wire).await.unwrap();
        let mut peeker = Peeker::new(Box::new(near), Vec::new());
        let result = peek_client_hello(&mut peeker).await;
        (result, peeker)
    }

    #[tokio::test]
    async fn reads_the_name_and_protocols_across_records() {
        let message = handshake(&hello_body("split.example.test", &["http/1.1"]));
        let one = record(&message);
        let split = [
            record(message.get(..10).unwrap()),
            record(message.get(10..).unwrap()),
        ]
        .concat();
        let tiny_first = [
            record(message.get(..2).unwrap()),
            record(message.get(2..).unwrap()),
        ]
        .concat();
        for (name, wire) in [
            ("one record", one),
            ("two records", split),
            ("tiny first record", tiny_first),
        ] {
            let (hello, peeker) = peek(wire.clone()).await;
            let hello = hello.unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(hello.server_name, "split.example.test", "{name}");
            assert_eq!(hello.protocols, ["http/1.1"], "{name}");
            assert_eq!(peeker.buf, wire, "{name}: the hello stays buffered");
        }
    }

    #[tokio::test]
    async fn a_hello_without_extensions_has_no_name() {
        let mut body = hello_body("", &[]);
        body.truncate(body.len() - 2);
        let (hello, _) = peek(record(&handshake(&body))).await;
        assert_eq!(hello.unwrap(), ClientHello::default());
    }

    #[tokio::test]
    async fn anything_else_is_not_a_hello() {
        for wire in [
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            record(&[2, 0, 0, 0]),
            vec![22, 3, 1, 0, 0],
        ] {
            let (result, _) = peek(wire).await;
            assert!(matches!(result, Err(HelloError::NotClientHello)));
        }
    }

    #[tokio::test]
    async fn a_hello_past_the_size_limit_is_refused() {
        let mut wire = vec![RECORD_TYPE_HANDSHAKE, 3, 1, 0xff, 0xff];
        wire.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        wire.extend([0xff; 70_000]);
        let (result, _) = peek(wire).await;
        assert!(result.is_err());
    }
}
