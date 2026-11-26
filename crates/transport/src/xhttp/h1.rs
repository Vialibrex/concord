use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll, ready};

use concord_common::BoxStream;
use concord_common::sync::lock;
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::request::Built;
use super::{BoxRead, BoxWrite};
use crate::DialFn;
use crate::http1::{HeadReader, ResponseHead, invalid};

const MAX_LINE: usize = 4096;

#[derive(Clone, Copy)]
enum Framing {
    None,
    Length(usize),
    Chunked,
}

fn write_head(req: &Built, framing: Framing) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\n",
            req.method,
            req.path_and_query(),
            req.host
        )
        .as_bytes(),
    );
    let user_agent = req
        .headers
        .get("User-Agent")
        .unwrap_or("Go-http-client/1.1");
    if !user_agent.is_empty() {
        out.extend_from_slice(format!("User-Agent: {}\r\n", user_agent.trim()).as_bytes());
    }
    match framing {
        Framing::None => {}
        Framing::Length(n) => out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes()),
        Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
    }
    req.headers.write_sorted(
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
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkState {
    Size,
    Data(u64),
    DataEnd,
    Trailer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Length(u64),
    Chunked(ChunkState),
    UntilClose,
    Done,
}

/// A response body as `net/http` frames it: by length, chunked, or until the
/// peer closes.
pub(crate) struct H1Body<R> {
    io: R,
    inbuf: Vec<u8>,
    pos: usize,
    kind: Kind,
}

impl<R: AsyncRead + Unpin> H1Body<R> {
    fn new(io: R, rest: Vec<u8>, head: &ResponseHead) -> H1Body<R> {
        let chunked = head
            .header("Transfer-Encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = head
            .header("Content-Length")
            .and_then(|v| v.trim().parse::<u64>().ok());
        let kind = if head.status == 204 || head.status == 304 || head.status / 100 == 1 {
            Kind::Done
        } else if chunked {
            Kind::Chunked(ChunkState::Size)
        } else if let Some(n) = length {
            if n == 0 { Kind::Done } else { Kind::Length(n) }
        } else {
            Kind::UntilClose
        };
        H1Body {
            io,
            inbuf: rest,
            pos: 0,
            kind,
        }
    }

    fn buffered(&self) -> &[u8] {
        self.inbuf.get(self.pos..).unwrap_or_default()
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.pos >= self.inbuf.len() {
            self.inbuf.clear();
            self.pos = 0;
        }
        let mut chunk = [0u8; 4096];
        let mut read = ReadBuf::new(&mut chunk);
        ready!(Pin::new(&mut self.io).poll_read(cx, &mut read))?;
        self.inbuf.extend_from_slice(read.filled());
        Poll::Ready(Ok(read.filled().len()))
    }

    fn poll_line(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        loop {
            if let Some(offset) = self.buffered().iter().position(|b| *b == b'\n') {
                let line = self.buffered().get(..offset).unwrap_or_default();
                let line = line.strip_suffix(b"\r").unwrap_or(line).to_vec();
                self.pos += offset + 1;
                return Poll::Ready(Ok(line));
            }
            if self.buffered().len() > MAX_LINE {
                return Poll::Ready(Err(invalid("chunk line too long")));
            }
            if ready!(self.poll_fill(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    }

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        limit: Option<u64>,
    ) -> Poll<io::Result<usize>> {
        let cap = limit
            .map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX))
            .min(buf.remaining());
        if let Some(pending) = Some(self.buffered()).filter(|p| !p.is_empty()) {
            let take = pending.len().min(cap);
            if let Some(chunk) = pending.get(..take) {
                buf.put_slice(chunk);
            }
            self.pos += take;
            return Poll::Ready(Ok(take));
        }
        let target = buf.initialize_unfilled_to(cap);
        let mut window = ReadBuf::new(target);
        ready!(Pin::new(&mut self.io).poll_read(cx, &mut window))?;
        let got = window.filled().len();
        buf.advance(got);
        Poll::Ready(Ok(got))
    }

    /// The connection back, once the body ended exactly where the buffer ends.
    fn into_reusable(self) -> Option<R> {
        (self.kind == Kind::Done && self.buffered().is_empty()).then_some(self.io)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for H1Body<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.kind {
                Kind::Done => return Poll::Ready(Ok(())),
                Kind::Length(0) => this.kind = Kind::Done,
                Kind::Length(left) => {
                    let got = ready!(this.poll_data(cx, buf, Some(left)))?;
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    this.kind = Kind::Length(left - got as u64);
                    return Poll::Ready(Ok(()));
                }
                Kind::UntilClose => {
                    let got = ready!(this.poll_data(cx, buf, None))?;
                    if got == 0 {
                        this.kind = Kind::Done;
                    }
                    return Poll::Ready(Ok(()));
                }
                Kind::Chunked(ChunkState::Size) => {
                    let line = ready!(this.poll_line(cx))?;
                    let text = String::from_utf8_lossy(&line);
                    let digits = text.split(';').next().unwrap_or_default().trim();
                    let size = u64::from_str_radix(digits, 16)
                        .map_err(|_| invalid("invalid chunk size"))?;
                    this.kind = Kind::Chunked(if size == 0 {
                        ChunkState::Trailer
                    } else {
                        ChunkState::Data(size)
                    });
                }
                Kind::Chunked(ChunkState::Data(left)) => {
                    let got = ready!(this.poll_data(cx, buf, Some(left)))?;
                    if got == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    let left = left - got as u64;
                    this.kind = Kind::Chunked(if left == 0 {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left)
                    });
                    return Poll::Ready(Ok(()));
                }
                Kind::Chunked(ChunkState::DataEnd) => {
                    let line = ready!(this.poll_line(cx))?;
                    if !line.is_empty() {
                        return Poll::Ready(Err(invalid("missing chunk terminator")));
                    }
                    this.kind = Kind::Chunked(ChunkState::Size);
                }
                Kind::Chunked(ChunkState::Trailer) => {
                    let line = ready!(this.poll_line(cx))?;
                    if line.is_empty() {
                        this.kind = Kind::Done;
                    }
                }
            }
        }
    }
}

struct Chunked<W> {
    inner: W,
    out: Vec<u8>,
    out_off: usize,
    inflight: Option<usize>,
    finished: bool,
}

impl<W: AsyncWrite + Unpin> Chunked<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(pending) = self.out.get(self.out_off..) {
            if pending.is_empty() {
                break;
            }
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_off += n;
        }
        self.out.clear();
        self.out_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Chunked<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(done) = this.inflight {
            ready!(this.poll_drain(cx))?;
            this.inflight = None;
            return Poll::Ready(Ok(done));
        }
        if this.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.out
            .extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
        this.out.extend_from_slice(data);
        this.out.extend_from_slice(b"\r\n");
        this.inflight = Some(data.len());
        ready!(this.poll_drain(cx))?;
        this.inflight = None;
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.finished {
            this.finished = true;
            this.out.extend_from_slice(b"0\r\n\r\n");
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

/// HTTP/1.1 requests over connections from `dial`; finished request/response
/// pairs hand their connection back for the next fixed-length request.
pub(crate) struct H1Transport {
    dial: DialFn,
    idle: Mutex<Vec<BoxStream>>,
}

impl H1Transport {
    pub fn new(dial: DialFn) -> H1Transport {
        H1Transport {
            dial,
            idle: Mutex::new(Vec::new()),
        }
    }

    async fn connection(&self, allow_idle: bool) -> io::Result<(BoxStream, bool)> {
        if allow_idle {
            let reused = lock(&self.idle).pop();
            if let Some(conn) = reused {
                return Ok((conn, true));
            }
        }
        Ok(((self.dial)().await?, false))
    }

    async fn exchange(
        &self,
        req: &Built,
        body: &[u8],
        mut conn: BoxStream,
    ) -> io::Result<(u16, H1Body<BoxStream>, bool)> {
        let mut wire = write_head(req, Framing::Length(body.len()));
        wire.extend_from_slice(body);
        conn.write_all(&wire).await?;
        conn.flush().await?;
        let mut reader = HeadReader::default();
        let head = reader.read_head(&mut conn).await?;
        let head = ResponseHead::parse(&head)?;
        let keep_alive = !head
            .header("Connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"));
        let status = head.status;
        Ok((
            status,
            H1Body::new(conn, reader.into_rest(), &head),
            keep_alive,
        ))
    }

    pub async fn fixed(&self, req: &Built, body: Vec<u8>) -> io::Result<u16> {
        let mut attempts = 0;
        let (status, mut response, keep_alive) = loop {
            let (conn, reused) = self.connection(true).await?;
            match self.exchange(req, &body, conn).await {
                Ok(done) => break done,
                Err(err) if reused && attempts == 0 => {
                    attempts += 1;
                    tracing::debug!("retrying on a fresh connection after {err}");
                }
                Err(err) => return Err(err),
            }
        };
        let mut sink = [0u8; 1024];
        while response.read(&mut sink).await? > 0 {}
        if keep_alive && let Some(conn) = response.into_reusable() {
            lock(&self.idle).push(conn);
        }
        Ok(status)
    }

    pub async fn download(
        &self,
        req: &Built,
    ) -> io::Result<BoxFuture<'static, io::Result<(u16, BoxRead)>>> {
        let (mut conn, _) = self.connection(true).await?;
        conn.write_all(&write_head(req, Framing::None)).await?;
        conn.flush().await?;
        Ok(Box::pin(async move {
            let mut reader = HeadReader::default();
            let head = reader.read_head(&mut conn).await?;
            let head = ResponseHead::parse(&head)?;
            let status = head.status;
            let body: BoxRead = Box::new(H1Body::new(conn, reader.into_rest(), &head));
            Ok((status, body))
        }))
    }

    pub async fn stream(
        &self,
        req: &Built,
    ) -> io::Result<(BoxWrite, BoxFuture<'static, io::Result<(u16, BoxRead)>>)> {
        let (mut conn, _) = self.connection(false).await?;
        conn.write_all(&write_head(req, Framing::Chunked)).await?;
        conn.flush().await?;
        let (mut read, write) = conn.into_split();
        let response = Box::pin(async move {
            let mut reader = HeadReader::default();
            let head = reader.read_head(&mut read).await?;
            let head = ResponseHead::parse(&head)?;
            let status = head.status;
            let body: BoxRead = Box::new(H1Body::new(read, reader.into_rest(), &head));
            Ok((status, body))
        });
        let writer: BoxWrite = Box::new(Chunked {
            inner: write,
            out: Vec::new(),
            out_off: 0,
            inflight: None,
            finished: false,
        });
        Ok((writer, response))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::duplex;

    use super::*;

    fn head(text: &str) -> ResponseHead {
        ResponseHead::parse(text.as_bytes()).unwrap()
    }

    async fn read_all(mut body: impl AsyncRead + Unpin) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        body.read_to_end(&mut out).await?;
        Ok(out)
    }

    #[tokio::test]
    async fn chunked_bodies_decode_across_arbitrary_splits() {
        let (client, mut server) = duplex(64);
        let h = head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        let body = H1Body::new(client, b"5\r\nhel".to_vec(), &h);
        let writer = tokio::spawn(async move {
            server.write_all(b"lo\r\n").await.unwrap();
            server
                .write_all(b"A;ext=1\r\n0123456789\r\n0\r\n")
                .await
                .unwrap();
            server.write_all(b"X-Trailer: 1\r\n\r\n").await.unwrap();
            server
        });
        assert_eq!(read_all(body).await.unwrap(), b"hello0123456789");
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn length_and_close_delimited_bodies() {
        let (client, mut server) = duplex(64);
        let body = H1Body::new(
            client,
            Vec::new(),
            &head("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"),
        );
        server.write_all(b"abcdEXTRA").await.unwrap();
        assert_eq!(read_all(body).await.unwrap(), b"abcd");

        let (client, mut server) = duplex(64);
        let body = H1Body::new(client, Vec::new(), &head("HTTP/1.1 200 OK\r\n\r\n"));
        server.write_all(b"until-close").await.unwrap();
        drop(server);
        assert_eq!(read_all(body).await.unwrap(), b"until-close");
    }

    #[tokio::test]
    async fn malformed_chunking_and_truncation_are_errors() {
        for wire in [&b"zz\r\nabc\r\n"[..], b"3\r\nabcXX", b"5\r\nab"] {
            let (client, mut server) = duplex(64);
            let body = H1Body::new(
                client,
                Vec::new(),
                &head("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
            );
            server.write_all(wire).await.unwrap();
            drop(server);
            assert!(read_all(body).await.is_err(), "{wire:?}");
        }
    }

    #[tokio::test]
    async fn fixed_requests_reuse_the_connection() {
        let (client, server) = duplex(1 << 16);
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slot = Arc::new(Mutex::new(Some(client)));
        let counter = dials.clone();
        let dial: DialFn = Arc::new(move || {
            let slot = slot.clone();
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let conn = lock(&slot)
                    .take()
                    .ok_or_else(|| io::Error::other("only one connection"))?;
                Ok(Box::new(conn) as BoxStream)
            })
        });
        let transport = H1Transport::new(dial);
        let server_task = tokio::spawn(async move {
            let mut server = server;
            let mut seen = Vec::new();
            for _ in 0..2 {
                let mut reader = HeadReader::default();
                let head = reader.read_head(&mut server).await.unwrap();
                let text = String::from_utf8(head).unwrap();
                let len: usize = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = reader.into_rest();
                while body.len() < len {
                    let mut buf = [0u8; 64];
                    let n = server.read(&mut buf).await.unwrap();
                    body.extend_from_slice(&buf[..n]);
                }
                seen.push((text, body));
                server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
            }
            seen
        });
        let factory_req = {
            let mut headers = crate::http1::HeaderMap::default();
            headers.set("User-Agent", "test");
            let mut req =
                super::super::request::Built::test_new("POST", "h.example", "/p/1", headers);
            req.finish();
            req
        };
        assert_eq!(
            transport
                .fixed(&factory_req, b"one".to_vec())
                .await
                .unwrap(),
            200
        );
        assert_eq!(
            transport
                .fixed(&factory_req, b"two!".to_vec())
                .await
                .unwrap(),
            200
        );
        assert_eq!(dials.load(std::sync::atomic::Ordering::SeqCst), 1);
        let seen = server_task.await.unwrap();
        assert!(seen[0].0.starts_with(
            "POST /p/1 HTTP/1.1\r\nHost: h.example\r\nUser-Agent: test\r\nContent-Length: 3\r\n"
        ));
        assert_eq!(seen[0].1, b"one");
        assert_eq!(seen[1].1, b"two!");
    }

    #[tokio::test]
    async fn a_large_write_is_one_chunk() {
        let (near, mut far) = duplex(1 << 18);
        let mut chunked = Chunked {
            inner: near,
            out: Vec::new(),
            out_off: 0,
            inflight: None,
            finished: false,
        };
        let payload = vec![9u8; 100_000];
        assert_eq!(chunked.write(&payload).await.unwrap(), payload.len());
        let mut wire = vec![0u8; 7 + payload.len() + 2];
        far.read_exact(&mut wire).await.unwrap();
        assert_eq!(&wire[..7], b"186a0\r\n");
        assert_eq!(&wire[7..7 + payload.len()], &payload[..]);
        assert_eq!(&wire[7 + payload.len()..], b"\r\n");
    }

    #[tokio::test]
    async fn stream_requests_are_chunked_both_ways() {
        let (client, server) = duplex(1 << 16);
        let slot = Arc::new(Mutex::new(Some(client)));
        let dial: DialFn = Arc::new(move || {
            let slot = slot.clone();
            Box::pin(async move {
                Ok(
                    Box::new(lock(&slot).take().ok_or_else(|| io::Error::other("one"))?)
                        as BoxStream,
                )
            })
        });
        let transport = H1Transport::new(dial);
        let req = {
            let mut req = super::super::request::Built::test_new(
                "POST",
                "h",
                "/s",
                crate::http1::HeaderMap::default(),
            );
            req.finish();
            req
        };
        let (mut writer, response) = transport.stream(&req).await.unwrap();
        let mut server = server;
        writer.write_all(b"up-data").await.unwrap();
        writer.flush().await.unwrap();
        let mut reader = HeadReader::default();
        let head = reader.read_head(&mut server).await.unwrap();
        assert!(
            String::from_utf8(head)
                .unwrap()
                .contains("Transfer-Encoding: chunked\r\n")
        );
        let mut rest = reader.into_rest();
        while rest.len() < "7\r\nup-data\r\n".len() {
            let mut buf = [0u8; 32];
            let n = server.read(&mut buf).await.unwrap();
            rest.extend_from_slice(&buf[..n]);
        }
        assert_eq!(rest, b"7\r\nup-data\r\n");
        server
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndown\r\n")
            .await
            .unwrap();
        let (status, mut body) = response.await.unwrap();
        assert_eq!(status, 200);
        let mut got = [0u8; 4];
        body.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"down");
        writer.shutdown().await.unwrap();
        let mut tail = vec![0u8; 5];
        server.read_exact(&mut tail).await.unwrap();
        assert_eq!(tail, b"0\r\n\r\n");
    }
}
