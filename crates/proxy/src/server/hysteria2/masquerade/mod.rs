//! What a hysteria2 listener answers a request that does not authenticate a client: Go's
//! 404, the files under a directory or a reverse proxy, as `masquerade` names
//! (`listener/sing_hysteria2/server.go:120-157`). Go's HTTP here is the net/http backport
//! mihomo serves it with, `github.com/metacubex/http` v0.1.8; a bare `fs.go`,
//! `transport.go` or `httputil/reverseproxy.go` line is in it.

mod content_type;
mod file;
mod gunzip;
mod reverse;

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use concord_common::serve::InboundCx;
use concord_config::listener::Masquerade as Config;
use concord_platform::HomeDir;
use futures_util::future::BoxFuture;
use h3::server::RequestStream;
use http::header::{self, HeaderName};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use time::OffsetDateTime;
use time::format_description::FormatItem;
use time::macros::format_description;
use tokio::io::AsyncReadExt;

use super::dispatch::Bidi;
use crate::server::ServerError;

/// The buffer Go's `io.CopyN` moves a file through.
const CHUNK: usize = 32 * 1024;

/// quic-go's `maxSmallResponseSize`: a handler that writes less than this has its body held
/// until it returns, and given a `Content-Length`.
const SMALL_RESPONSE: usize = 4096;

pub(super) const HTTP_DATE: &[FormatItem<'static>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

pub(super) type H3Stream = RequestStream<Bidi<Bytes>, Bytes>;

pub(super) fn http_date(time: SystemTime) -> Option<String> {
    OffsetDateTime::from(time).format(HTTP_DATE).ok()
}

/// The `Date` quic-go gives every final response that has none, as net/http does
/// (`http3/response_writer.go:100-105`).
pub(super) fn stamp_date(headers: &mut HeaderMap) {
    if !headers.contains_key(header::DATE)
        && let Some(Ok(now)) = http_date(SystemTime::now()).map(HeaderValue::try_from)
    {
        headers.insert(header::DATE, now);
    }
}

pub(super) enum Masquerade {
    NotFound,
    Files(file::Files),
    Proxy(reverse::Reverse),
}

impl Masquerade {
    pub(super) fn new(config: Option<&Config>, home: &Arc<HomeDir>) -> Result<Self, ServerError> {
        Ok(match config {
            None => Masquerade::NotFound,
            Some(Config::File(root)) => {
                Masquerade::Files(file::Files::new(root, home).map_err(|source| {
                    ServerError::File {
                        path: root.clone(),
                        source,
                    }
                })?)
            }
            Some(Config::Proxy(target)) => Masquerade::Proxy(reverse::Reverse::new(target)?),
        })
    }

    /// Takes the request and the listener by value and boxes the answer: rustc cannot prove
    /// `Send` for a request task whose future borrows them across the answer's awaits.
    pub(super) fn answer(
        &self,
        request: Request<()>,
        stream: H3Stream,
        cx: Arc<InboundCx>,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move { self.reply(&request, stream, &cx).await })
    }

    async fn reply(&self, request: &Request<()>, mut stream: H3Stream, cx: &Arc<InboundCx>) {
        let reply = match self {
            Masquerade::NotFound => Reply::error(StatusCode::NOT_FOUND, "404 page not found"),
            Masquerade::Files(files) => files.answer(request, cx.tasks.clone()).await,
            Masquerade::Proxy(proxy) => return proxy.answer(request, stream, cx).await,
        };
        reply
            .send(&mut stream, request.method() == Method::HEAD)
            .await;
    }
}

/// A response the server makes itself, not one it relays.
pub(super) struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
}

pub(super) enum Body {
    Empty,
    Bytes(Bytes),
    File { file: tokio::fs::File, length: u64 },
}

impl Reply {
    fn new(status: StatusCode) -> Self {
        Reply {
            status,
            headers: HeaderMap::new(),
            body: Body::Empty,
        }
    }

    /// Go's `http.Error`.
    fn error(status: StatusCode, text: &str) -> Self {
        Reply::new(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
            .body(Body::Bytes(Bytes::from(format!("{text}\n"))))
    }

    fn header(mut self, name: HeaderName, value: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(value) {
            self.headers.insert(name, value);
        }
        self
    }

    fn body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }

    /// The head as quic-go finishes it for a handler: a `Date`, and the `Content-Length` of a
    /// body it still holds when the handler returns, any for HEAD, whose body it drops
    /// (`http3/response_writer.go:100-105,151-160`, `server_conn.go:235-240`).
    async fn send<S: h3::quic::SendStream<Bytes>>(
        mut self,
        stream: &mut RequestStream<S, Bytes>,
        head_only: bool,
    ) {
        let held = match &self.body {
            Body::Empty => Some(0),
            Body::Bytes(bytes) => Some(bytes.len()),
            Body::File { .. } => None,
        };
        if let Some(held) = held
            && (head_only || held < SMALL_RESPONSE)
            && !self.headers.contains_key(header::CONTENT_LENGTH)
        {
            self.headers
                .insert(header::CONTENT_LENGTH, HeaderValue::from(held));
        }
        stamp_date(&mut self.headers);
        if head_only {
            self.body = Body::Empty;
        }
        let mut head = Response::new(());
        *head.status_mut() = self.status;
        *head.headers_mut() = self.headers;
        if stream.send_response(head).await.is_err() {
            return;
        }
        match self.body {
            Body::Empty => {}
            Body::Bytes(bytes) => {
                if stream.send_data(bytes).await.is_err() {
                    return;
                }
            }
            Body::File {
                mut file,
                mut length,
            } => {
                let mut chunk = vec![0u8; CHUNK];
                while length > 0 {
                    let want = usize::try_from(length).unwrap_or(CHUNK).min(CHUNK);
                    let Some(buf) = chunk.get_mut(..want) else {
                        return;
                    };
                    let Ok(n) = file.read(buf).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    if stream
                        .send_data(Bytes::copy_from_slice(chunk.get(..n).unwrap_or_default()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    length -= n as u64;
                }
            }
        }
        let _ = stream.finish().await;
    }
}
