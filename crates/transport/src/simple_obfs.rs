use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use concord_common::BoxStream;
use concord_common::layered::{Layered, ReadLayer, WriteLayer, poll_drain};
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::http_obfs::wrap_with;
use crate::http1::HeaderMap;

const CHUNK: usize = 1 << 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObfsMode {
    Http,
    Tls,
}

#[derive(Clone)]
pub struct ObfsOptions {
    pub mode: ObfsMode,
    /// The `host` plugin option, `bing.com` unless set.
    pub host: String,
    /// The node's port as text, which decides whether the `Host` header carries it.
    pub port: String,
    /// The ClientHello's timestamp, mihomo's NTP-corrected clock.
    pub clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl std::fmt::Debug for ObfsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObfsOptions")
            .field("mode", &self.mode)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

pub(crate) fn wrap(io: BoxStream, opts: &ObfsOptions) -> BoxStream {
    match opts.mode {
        ObfsMode::Http => {
            let host = opts.host.clone();
            let port = opts.port.clone();
            wrap_with(io, Box::new(move |body| http_request(&host, &port, body)))
        }
        ObfsMode::Tls => tls_obfs(io, opts.host.clone(), (opts.clock)()),
    }
}

fn http_request(host: &str, port: &str, body: &[u8]) -> Vec<u8> {
    let mut rng = rand::rng();
    let nonce: [u8; 16] = rng.random();
    let mut headers = HeaderMap::default();
    headers.set(
        "User-Agent",
        &format!(
            "curl/7.{}.{}",
            rng.random_range(0..54),
            rng.random_range(0..2)
        ),
    );
    headers.set("Upgrade", "websocket");
    headers.set("Connection", "Upgrade");
    headers.set("Sec-WebSocket-Key", &URL_SAFE.encode(nonce));
    let authority = if port == "80" {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let user_agent = headers.get("User-Agent").unwrap_or_default().to_string();
    let mut out = Vec::with_capacity(body.len() + 256);
    out.extend_from_slice(
        format!(
            "GET / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {user_agent}\r\nContent-Length: {}\r\n",
            body.len()
        )
        .as_bytes(),
    );
    headers.write_sorted(&mut out, &["User-Agent"]);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

fn client_hello(data: &[u8], server: &str, at: SystemTime) -> Vec<u8> {
    let (d, s) = (data.len(), server.len());
    let mut rng = rand::rng();
    let random: [u8; 28] = rng.random();
    let session_id: [u8; 32] = rng.random();
    let now = at
        .duration_since(UNIX_EPOCH)
        .map_or(0, |t| t.as_secs() as u32);

    let mut out = Vec::with_capacity(217 + d + s);
    out.extend_from_slice(&[22, 0x03, 0x01]);
    out.extend_from_slice(&((212 + d + s) as u16).to_be_bytes());
    out.extend_from_slice(&[1, 0]);
    out.extend_from_slice(&((208 + d + s) as u16).to_be_bytes());
    out.extend_from_slice(&[0x03, 0x03]);
    out.extend_from_slice(&now.to_be_bytes());
    out.extend_from_slice(&random);
    out.push(32);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&[0x00, 0x38]);
    out.extend_from_slice(&[
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ]);
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&((79 + d + s) as u16).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x23]);
    out.extend_from_slice(&(d as u16).to_be_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&((s + 5) as u16).to_be_bytes());
    out.extend_from_slice(&((s + 3) as u16).to_be_bytes());
    out.push(0);
    out.extend_from_slice(&(s as u16).to_be_bytes());
    out.extend_from_slice(server.as_bytes());
    out.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
    out.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);
    out.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05,
        0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ]);
    out.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    out
}

enum Read {
    /// A header of this many bytes that has not started; mihomo reads it with `io.ReadFull`,
    /// so the peer closing here is a clean end.
    Header(usize),
    Discard(usize),
    Len {
        buf: [u8; 2],
        have: usize,
    },
    Data(usize),
}

/// Disguises the stream as a TLS session: the first chunk hides in a ClientHello's
/// session ticket, later ones in application data records. Whatever the server
/// sends before its first record's payload is skipped unparsed.
struct TlsWrite {
    server: String,
    at: SystemTime,
    first: bool,
    out: Vec<u8>,
    out_off: usize,
    inflight: Option<usize>,
}

fn tls_obfs(io: BoxStream, server: String, at: SystemTime) -> BoxStream {
    let write = TlsWrite {
        server,
        at,
        first: true,
        out: Vec::new(),
        out_off: 0,
        inflight: None,
    };
    Box::new(Layered::new(io, Read::Header(105), write))
}

impl ReadLayer for Read {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut *self {
                Read::Header(len) => {
                    let len = *len;
                    let mut sink = [0u8; 128];
                    let Some(window) = sink.get_mut(..len) else {
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    *self = if got == len {
                        Read::Len {
                            buf: [0; 2],
                            have: 0,
                        }
                    } else {
                        Read::Discard(len - got)
                    };
                }
                Read::Discard(left) => {
                    let mut sink = [0u8; 128];
                    let take = (*left).min(sink.len());
                    let Some(window) = sink.get_mut(..take) else {
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *left -= got;
                    if *left == 0 {
                        *self = Read::Len {
                            buf: [0; 2],
                            have: 0,
                        };
                    }
                }
                Read::Len { buf: raw, have } => {
                    let Some(window) = raw.get_mut(*have..) else {
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    };
                    let mut window = ReadBuf::new(window);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *have += got;
                    if *have == 2 {
                        *self = Read::Data(usize::from(u16::from_be_bytes(*raw)));
                    }
                }
                Read::Data(left) => {
                    if *left == 0 {
                        *self = Read::Header(3);
                        continue;
                    }
                    let take = (*left).min(buf.remaining());
                    if take == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    let target = buf.initialize_unfilled_to(take);
                    let mut window = ReadBuf::new(target);
                    ready!(Pin::new(&mut *io).poll_read(cx, &mut window))?;
                    let got = window.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    buf.advance(got);
                    *left -= got;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl WriteLayer for TlsWrite {
    fn poll_write<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(done) = self.inflight {
            ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
            self.inflight = None;
            return Poll::Ready(Ok(done));
        }
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        let take = data.len().min(CHUNK);
        let Some(chunk) = data.get(..take).filter(|c| !c.is_empty()) else {
            return Poll::Ready(Ok(0));
        };
        if self.first {
            self.first = false;
            self.out = client_hello(chunk, &self.server, self.at);
        } else {
            self.out.extend_from_slice(&[0x17, 0x03, 0x03]);
            self.out
                .extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            self.out.extend_from_slice(chunk);
        }
        self.inflight = Some(take);
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        self.inflight = None;
        Poll::Ready(Ok(take))
    }

    fn poll_flush<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        Pin::new(io).poll_flush(cx)
    }

    fn poll_shutdown<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        io: &mut W,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        Pin::new(io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn client_hello_lengths_are_self_consistent() {
        for (data, server) in [(&b"x"[..], "bing.com"), (&[7u8; 1000][..], "a.b")] {
            let hello = client_hello(data, server, SystemTime::now());
            assert_eq!(hello.len(), 5 + 212 + data.len() + server.len());
            assert_eq!(
                u16::from_be_bytes([hello[3], hello[4]]) as usize,
                hello.len() - 5
            );
            assert_eq!(
                u16::from_be_bytes([hello[7], hello[8]]) as usize,
                hello.len() - 9
            );
            let ext_len = u16::from_be_bytes([
                hello[5 + 4 + 2 + 32 + 33 + 2 + 56 + 2],
                hello[5 + 4 + 2 + 32 + 33 + 2 + 56 + 3],
            ]);
            assert_eq!(
                ext_len as usize,
                hello.len() - (5 + 4 + 2 + 32 + 33 + 2 + 56 + 2 + 2)
            );
            assert_eq!(&hello[..3], &[22, 3, 1]);
        }
    }

    #[tokio::test]
    async fn tls_obfs_frames_writes_and_unwraps_reads() {
        let (client, mut server) = duplex(1 << 16);
        let mut conn = wrap(
            Box::new(client),
            &ObfsOptions {
                mode: ObfsMode::Tls,
                host: "bing.com".into(),
                port: "443".into(),
                clock: Arc::new(SystemTime::now),
            },
        );
        conn.write_all(b"first").await.unwrap();
        conn.write_all(b"second").await.unwrap();
        let big = vec![9u8; 40_000];
        conn.write_all(&big).await.unwrap();
        conn.flush().await.unwrap();

        let hello_len = 5 + 212 + 5 + 8;
        let mut hello = vec![0u8; hello_len];
        server.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello[..3], &[22, 3, 1]);
        assert!(hello.windows(5).any(|w| w == b"first"));
        let mut rec = [0u8; 5 + 6];
        server.read_exact(&mut rec).await.unwrap();
        assert_eq!(&rec[..5], &[0x17, 3, 3, 0, 6]);
        assert_eq!(&rec[5..], b"second");
        let mut seen = 0;
        while seen < big.len() {
            let mut head = [0u8; 5];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..3], &[0x17, 3, 3]);
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            assert!(len <= CHUNK);
            let mut body = vec![0u8; len];
            server.read_exact(&mut body).await.unwrap();
            seen += len;
        }

        let mut reply = vec![0u8; 105];
        reply.extend_from_slice(&[0, 3]);
        reply.extend_from_slice(b"abc");
        reply.extend_from_slice(&[0x17, 3, 3, 0, 2, b'd', b'e']);
        server.write_all(&reply).await.unwrap();
        let mut got = [0u8; 5];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"abcde");
    }

    async fn read_after_close(reply: &[u8]) -> io::Result<Vec<u8>> {
        let (client, mut server) = duplex(1 << 16);
        let mut conn = wrap(
            Box::new(client),
            &ObfsOptions {
                mode: ObfsMode::Tls,
                host: "bing.com".into(),
                port: "443".into(),
                clock: Arc::new(SystemTime::now),
            },
        );
        server.write_all(reply).await.unwrap();
        drop(server);
        let mut got = Vec::new();
        conn.read_to_end(&mut got).await.map(|_| got)
    }

    #[tokio::test]
    async fn a_close_between_records_ends_the_stream_and_one_inside_a_record_does_not() {
        let mut reply = vec![0u8; 105];
        reply.extend_from_slice(&[0, 2]);
        reply.extend_from_slice(b"hi");
        assert_eq!(read_after_close(&reply).await.unwrap(), b"hi");
        reply.extend_from_slice(&[0x17, 3]);
        let err = read_after_close(&reply).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn http_obfs_request_has_the_simple_obfs_shape() {
        let (client, mut server) = duplex(8192);
        let mut conn = wrap(
            Box::new(client),
            &ObfsOptions {
                mode: ObfsMode::Http,
                host: "bing.com".into(),
                port: "8388".into(),
                clock: Arc::new(SystemTime::now),
            },
        );
        conn.write_all(b"payload").await.unwrap();
        let mut got = vec![0u8; 1024];
        let n = server.read(&mut got).await.unwrap();
        let text = String::from_utf8(got[..n].to_vec()).unwrap();
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(lines[0], "GET / HTTP/1.1");
        assert_eq!(lines[1], "Host: bing.com:8388");
        assert!(lines[2].starts_with("User-Agent: curl/7."));
        assert_eq!(lines[3], "Content-Length: 7");
        assert_eq!(lines[4], "Connection: Upgrade");
        assert!(lines[5].starts_with("Sec-Websocket-Key: "));
        assert_eq!(lines[6], "Upgrade: websocket");
        assert_eq!(lines[7], "");
        assert_eq!(lines[8], "payload");

        server
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nback")
            .await
            .unwrap();
        let mut back = [0u8; 4];
        conn.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"back");
    }

    #[tokio::test]
    async fn port_80_is_left_off_the_host_header() {
        let request = http_request("bing.com", "80", b"");
        assert!(
            String::from_utf8(request)
                .unwrap()
                .contains("Host: bing.com\r\n")
        );
    }

    #[tokio::test]
    async fn tls_halves_move_data_both_ways_and_shutdown_keeps_reading() {
        let (client, server) = duplex(1 << 16);
        let (mut read, mut write) =
            tls_obfs(Box::new(client), "bing.com".into(), SystemTime::now()).into_split();
        let (mut far_read, mut far_write) = tokio::io::split(server);
        let writer = tokio::spawn(async move {
            write.write_all(b"hi").await.unwrap();
            write.shutdown().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            got
        });
        let mut sent = Vec::new();
        far_read.read_to_end(&mut sent).await.unwrap();
        assert_eq!(sent.len(), 5 + 212 + 2 + 8);
        writer.await.unwrap();
        let mut reply = vec![0u8; 105];
        reply.extend_from_slice(&[0, 2]);
        reply.extend_from_slice(b"ok");
        far_write.write_all(&reply).await.unwrap();
        far_write.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), b"ok");
    }
}
