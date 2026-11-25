use std::sync::Arc;

use bytes::Bytes;
use concord_common::{Address, BoxStream, Tasks};
use concord_tls::{TlsConnector, TlsOptions, TrustStore};
use http::{HeaderMap, Method};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("{0}")]
    Url(String),
    #[error("{0}")]
    Tls(String),
    #[error("{0}")]
    Protocol(String),
}

fn protocol(err: impl std::fmt::Display) -> HttpError {
    HttpError::Protocol(err.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Target {
    pub fn parse(text: &str) -> Result<Target, HttpError> {
        let url = url::Url::parse(text).map_err(|err| HttpError::Url(err.to_string()))?;
        let tls = match url.scheme() {
            "https" => true,
            "http" => false,
            _ => return Err(HttpError::Url(format!("{text} scheme not Support"))),
        };
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| HttpError::Url(format!("{text} has no host")))?;
        let mut path = url.path().to_string();
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok(Target {
            tls,
            host: host.trim_matches(['[', ']']).to_string(),
            port: url
                .port_or_known_default()
                .unwrap_or(if tls { 443 } else { 80 }),
            path,
        })
    }

    pub fn address(&self) -> Address {
        Address::new(&self.host, self.port)
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

pub struct Response {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A response whose body is read as it arrives.
pub struct Streaming {
    pub status: u16,
    pub headers: HeaderMap,
    body: Limited<Incoming>,
}

impl Streaming {
    /// The next piece of the body, `None` past its end. A body longer than the limit
    /// `open` was given is an error.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, HttpError> {
        while let Some(frame) = self.body.frame().await {
            if let Ok(data) = frame.map_err(protocol)?.into_data() {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }
}

/// HTTP/1.1 as mihomo's downloads and URL tests speak it: their `http.Transport` sets its own
/// dialer and TLS config and so never turns HTTP/2 on (metacubex/http v0.1.8 `transport.go:471`),
/// which leaves the hello without ALPN, and Go writes header names in canonical case.
pub struct Connection {
    sender: http1::SendRequest<Full<Bytes>>,
    target: Target,
}

#[derive(Clone)]
pub struct TlsSettings {
    pub trust: Arc<TrustStore>,
    pub skip_cert_verify: bool,
}

/// Runs the TLS handshake when the target is `https`, then the HTTP one. The
/// connection driver ends when the returned value is dropped.
pub async fn connect(
    io: BoxStream,
    target: &Target,
    tls: &TlsSettings,
    tasks: &Tasks,
) -> Result<Connection, HttpError> {
    if !target.tls {
        return handshake(io, target, tasks).await;
    }
    let connector = TlsConnector::new(
        TlsOptions {
            skip_cert_verify: tls.skip_cert_verify,
            ..TlsOptions::default()
        },
        tls.trust.clone(),
    )
    .map_err(|err| HttpError::Tls(err.to_string()))?;
    let stream = connector
        .connect(io, &target.host)
        .await
        .map_err(|err| HttpError::Tls(err.to_string()))?;
    handshake(Box::new(stream), target, tasks).await
}

async fn handshake(io: BoxStream, target: &Target, tasks: &Tasks) -> Result<Connection, HttpError> {
    let (sender, conn) = http1::Builder::new()
        .title_case_headers(true)
        .handshake(TokioIo::new(io))
        .await
        .map_err(protocol)?;
    tasks.spawn(async move {
        let _ = conn.await;
    });
    Ok(Connection {
        sender,
        target: target.clone(),
    })
}

impl Connection {
    /// Redirects are not followed. A body longer than `limit` is an error.
    pub async fn send(
        &mut self,
        method: Method,
        headers: &[(String, String)],
        body: Bytes,
        limit: usize,
    ) -> Result<Response, HttpError> {
        let response = self.open(method, headers, body, limit).await?;
        Ok(Response {
            status: response.status,
            headers: response.headers,
            body: response.body.collect().await.map_err(protocol)?.to_bytes(),
        })
    }

    /// As [send](Self::send), handing the body over unread.
    pub async fn open(
        &mut self,
        method: Method,
        headers: &[(String, String)],
        body: Bytes,
        limit: usize,
    ) -> Result<Streaming, HttpError> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(self.target.path.as_str())
            .header(http::header::HOST, self.target.authority());
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder.body(Full::new(body)).map_err(protocol)?;
        let response = self.sender.send_request(request).await.map_err(protocol)?;
        let (parts, body) = response.into_parts();
        Ok(Streaming {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: Limited::new(body, limit),
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[test]
    fn urls_read_like_the_url_test_wants() {
        let target = Target::parse("https://www.gstatic.com/generate_204?x=1").unwrap();
        assert_eq!(
            (target.tls, target.host.as_str(), target.port),
            (true, "www.gstatic.com", 443)
        );
        assert_eq!(target.path, "/generate_204?x=1");
        assert_eq!(
            Target::parse("http://[::1]:8080").unwrap().authority(),
            "[::1]:8080"
        );
        assert_eq!(Target::parse("http://a.b").unwrap().path, "/");
        assert!(Target::parse("ftp://a.b").is_err());
    }

    #[tokio::test]
    async fn two_head_requests_share_one_connection() {
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            for _ in 0..2 {
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = server.read(&mut buf).await.unwrap();
                    seen.extend_from_slice(&buf[..n]);
                }
                assert!(seen.starts_with(b"HEAD /generate_204 HTTP/1.1\r\n"));
                server
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let target = Target::parse("http://probe.test/generate_204").unwrap();
        let mut conn = handshake(Box::new(client), &target, &Default::default())
            .await
            .unwrap();
        for _ in 0..2 {
            let response = conn
                .send(Method::HEAD, &[], Bytes::new(), 1024)
                .await
                .unwrap();
            assert_eq!(response.status, 204);
        }
    }

    #[tokio::test]
    async fn a_request_goes_out_as_go_writes_it() {
        let (client, mut server) = duplex(4096);
        let seen = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut buf = vec![0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = server.read(&mut buf).await.unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            server
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
            String::from_utf8(seen).unwrap()
        });
        let target = Target::parse("http://files.test:8080/list?a=1").unwrap();
        let mut conn = handshake(Box::new(client), &target, &Default::default())
            .await
            .unwrap();
        let headers = [("user-agent".to_string(), "probe".to_string())];
        conn.send(Method::GET, &headers, Bytes::new(), 16)
            .await
            .unwrap();
        assert_eq!(
            seen.await.unwrap(),
            "GET /list?a=1 HTTP/1.1\r\nHost: files.test:8080\r\nUser-Agent: probe\r\n\r\n"
        );
    }

    /// The extension types of the ClientHello in the first TLS record.
    fn hello_extensions(record: &[u8]) -> Vec<u16> {
        let u16_at = |at: usize| u16::from_be_bytes([record[at], record[at + 1]]);
        let mut at = 5 + 4 + 2 + 32;
        at += 1 + usize::from(record[at]);
        at += 2 + usize::from(u16_at(at));
        at += 1 + usize::from(record[at]);
        let end = at + 2 + usize::from(u16_at(at));
        at += 2;
        let mut types = Vec::new();
        while at < end {
            types.push(u16_at(at));
            at += 4 + usize::from(u16_at(at + 2));
        }
        types
    }

    #[tokio::test]
    async fn the_tls_hello_offers_no_alpn() {
        let (client, mut server) = duplex(1 << 16);
        let hello = tokio::spawn(async move {
            let mut record = vec![0u8; 5];
            server.read_exact(&mut record).await.unwrap();
            let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
            record.resize(5 + len, 0);
            server.read_exact(&mut record[5..]).await.unwrap();
            record
        });
        let target = Target::parse("https://files.test/list").unwrap();
        let tls = TlsSettings {
            trust: TrustStore::new(b"", Vec::new()),
            skip_cert_verify: false,
        };
        let _ = connect(Box::new(client), &target, &tls, &Default::default()).await;
        let extensions = hello_extensions(&hello.await.unwrap());
        assert!(extensions.contains(&0), "{extensions:?} carries SNI");
        assert!(!extensions.contains(&16), "{extensions:?} has no ALPN");
    }

    #[tokio::test]
    async fn an_opened_body_is_read_in_pieces_up_to_the_limit() {
        let (client, mut server) = duplex(4096);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            for body in ["0123456789", "0123456789"] {
                let mut seen = Vec::new();
                while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = server.read(&mut buf).await.unwrap();
                    seen.extend_from_slice(&buf[..n]);
                }
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                server.write_all(head.as_bytes()).await.unwrap();
                server.write_all(body.as_bytes()).await.unwrap();
            }
        });
        let target = Target::parse("http://files.test/big").unwrap();
        let mut conn = handshake(Box::new(client), &target, &Default::default())
            .await
            .unwrap();
        let mut whole = conn.open(Method::GET, &[], Bytes::new(), 10).await.unwrap();
        let mut read = Vec::new();
        while let Some(chunk) = whole.chunk().await.unwrap() {
            read.extend_from_slice(&chunk);
        }
        assert_eq!(read, b"0123456789");
        let mut cut = conn.open(Method::GET, &[], Bytes::new(), 4).await.unwrap();
        let mut outcome = cut.chunk().await;
        while let Ok(Some(_)) = outcome {
            outcome = cut.chunk().await;
        }
        assert!(outcome.is_err());
    }
}
