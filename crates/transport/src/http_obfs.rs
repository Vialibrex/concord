use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use concord_common::BoxStream;
use concord_common::layered::{Layered, ReadLayer, WriteLayer, poll_drain};
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::http1::{HeadReader, HeaderMap, escape_path};

#[derive(Clone, Debug, Default)]
pub struct HttpOptions {
    pub method: String,
    pub paths: Vec<String>,
    pub headers: Vec<(String, Vec<String>)>,
}

fn pick(items: &[String]) -> Option<&str> {
    items
        .get(rand::rng().random_range(0..items.len().max(1)))
        .map(String::as_str)
}

pub(crate) type RequestBuilder = Box<dyn Fn(&[u8]) -> Vec<u8> + Send>;

pub(crate) fn wrap(io: BoxStream, opts: &HttpOptions, host: &str) -> BoxStream {
    let opts = opts.clone();
    let host = host.to_string();
    wrap_with(io, Box::new(move |body| request_for(&opts, &host, body)))
}

pub(crate) fn wrap_with(io: BoxStream, build: RequestBuilder) -> BoxStream {
    let read = ResponseHead {
        head: Some(HeadReader::default()),
        rest: Vec::new(),
        rest_off: 0,
    };
    let write = FirstRequest {
        build,
        written: false,
        out: Vec::new(),
        out_off: 0,
        inflight: None,
    };
    Box::new(Layered::new(io, read, write))
}

fn request_for(opts: &HttpOptions, host_default: &str, body: &[u8]) -> Vec<u8> {
    let path = match pick(&opts.paths).map(|path| escape_path(path.as_bytes())) {
        Some(path) if !path.is_empty() => path,
        _ => "/".to_string(),
    };
    let host = opts
        .headers
        .iter()
        .find(|(k, _)| k == "Host")
        .and_then(|(_, values)| pick(values))
        .unwrap_or(host_default);
    let method = if opts.method.is_empty() {
        "GET"
    } else {
        &opts.method
    };
    let mut headers = HeaderMap::default();
    for (key, values) in &opts.headers {
        if let Some(value) = pick(values) {
            headers.set(key, value);
        }
    }
    let user_agent = headers.get("User-Agent").unwrap_or("Go-http-client/1.1");
    let mut out = Vec::with_capacity(body.len() + 256);
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n").as_bytes());
    if !user_agent.is_empty() {
        out.extend_from_slice(format!("User-Agent: {}\r\n", user_agent.trim()).as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    headers.write_sorted(
        &mut out,
        &[
            "Host",
            "User-Agent",
            "Content-Length",
            "Transfer-Encoding",
            "Trailer",
        ],
    );
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// The response head in front of the first read is dropped; everything after is raw.
struct ResponseHead {
    head: Option<HeadReader>,
    rest: Vec<u8>,
    rest_off: usize,
}

impl ReadLayer for ResponseHead {
    fn poll_read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        io: &mut R,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(reader) = self.head.as_mut() {
            ready!(reader.poll_head(cx, io))?;
            self.rest = self
                .head
                .take()
                .map(HeadReader::into_rest)
                .unwrap_or_default();
        }
        if let Some(pending) = self.rest.get(self.rest_off..).filter(|p| !p.is_empty()) {
            let take = pending.len().min(buf.remaining());
            if let Some(chunk) = pending.get(..take) {
                buf.put_slice(chunk);
            }
            self.rest_off += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(io).poll_read(cx, buf)
    }
}

/// The first write goes out as the body of an HTTP/1.1 request; everything after is raw.
struct FirstRequest {
    build: RequestBuilder,
    written: bool,
    out: Vec<u8>,
    out_off: usize,
    inflight: Option<usize>,
}

impl WriteLayer for FirstRequest {
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
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.written {
            return Pin::new(io).poll_write(cx, data);
        }
        self.out = (self.build)(data);
        self.written = true;
        self.inflight = Some(data.len());
        ready!(poll_drain(io, cx, &mut self.out, &mut self.out_off))?;
        self.inflight = None;
        Poll::Ready(Ok(data.len()))
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

    #[tokio::test]
    async fn first_write_is_a_request_and_the_response_head_is_dropped() {
        let (client, mut server) = duplex(8192);
        let opts = HttpOptions {
            method: "POST".into(),
            paths: vec!["/a".into()],
            headers: vec![
                ("Host".into(), vec!["cdn.example.com".into()]),
                ("User-Agent".into(), vec!["curl/8.0".into()]),
                ("Accept".into(), vec!["*/*".into()]),
            ],
        };
        let mut conn = wrap(Box::new(client), &opts, "198.51.100.1");
        conn.write_all(b"vmess-header").await.unwrap();
        conn.write_all(b"-more").await.unwrap();
        conn.flush().await.unwrap();
        let mut got = vec![0u8; 5];
        let expect_head = "POST /a HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: curl/8.0\r\nContent-Length: 12\r\nAccept: */*\r\n\r\nvmess-header-more";
        got.resize(expect_head.len(), 0);
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), expect_head);

        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\npayload")
            .await
            .unwrap();
        let mut back = [0u8; 7];
        conn.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"payload");
    }

    #[tokio::test]
    async fn defaults_follow_net_http() {
        let (client, mut server) = duplex(8192);
        let mut conn = wrap(Box::new(client), &HttpOptions::default(), "198.51.100.1");
        conn.write_all(b"x").await.unwrap();
        let mut got = vec![0u8; 100];
        let n = server.read(&mut got).await.unwrap();
        assert_eq!(
            &got[..n],
            b"GET / HTTP/1.1\r\nHost: 198.51.100.1\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 1\r\n\r\nx"
        );
    }

    #[tokio::test]
    async fn eof_before_the_head_completes_is_an_error() {
        let (client, mut server) = duplex(8192);
        let mut conn = wrap(Box::new(client), &HttpOptions::default(), "h");
        server.write_all(b"HTTP/1.1 200 OK\r\nX: y").await.unwrap();
        drop(server);
        let mut buf = [0u8; 4];
        assert!(conn.read(&mut buf).await.is_err());
    }
}
