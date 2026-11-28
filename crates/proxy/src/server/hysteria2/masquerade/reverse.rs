//! mihomo's `httputil.ReverseProxy` in its Rewrite mode, dialling through the tunnel as
//! `inner.HandleTcp` does (`listener/sing_hysteria2/server.go:129-153`), over HTTP/1.1 only.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use concord_common::serve::InboundCx;
use concord_common::{Address, BoxStream};
use concord_tls::{TlsConnector, TlsOptions, TrustStore};
use h3::server::RequestStream;
use http::header::{self, HeaderName};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::{Body as _, Frame, Incoming};
use hyper_util::rt::TokioIo;

use super::gunzip::Gunzip;
use super::{H3Stream, Reply, stamp_date};
use crate::server::{ServerError, inner};

/// `http.Transport.TLSHandshakeTimeout` as mihomo sets it.
const TLS_HANDSHAKE: Duration = Duration::from_secs(10);

/// Go's `hopHeaders`, which the proxy drops both ways.
const HOP_HEADERS: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// What the Rewrite mode takes off a request before it rewrites it.
const FORWARDED: [&str; 4] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
];

type Outgoing = UnsyncBoxBody<Bytes, io::Error>;

pub(in crate::server::hysteria2) struct Reverse {
    target: Uri,
    authority: String,
    host: String,
    port: u16,
    tls: Option<Arc<TlsConnector>>,
}

impl Reverse {
    pub(super) fn new(target: &Uri) -> Result<Self, ServerError> {
        let https = target.scheme_str() == Some("https");
        let authority = target
            .authority()
            .ok_or_else(|| ServerError::Invalid("masquerade URL names no host".into()))?;
        let host = authority.host();
        let tls = if https {
            let options = TlsOptions {
                skip_cert_verify: true,
                alpn: vec!["http/1.1".into()],
                ..TlsOptions::default()
            };
            let connector = TlsConnector::new(options, TrustStore::new(&[], Vec::new()))
                .map_err(|err| ServerError::Invalid(format!("masquerade TLS: {err}")))?;
            Some(Arc::new(connector))
        } else {
            None
        };
        Ok(Reverse {
            target: target.clone(),
            authority: authority.as_str().to_owned(),
            host: host.to_owned(),
            port: authority.port_u16().unwrap_or(if https { 443 } else { 80 }),
            tls,
        })
    }

    /// A CONNECT is answered 502 without a dial, where mihomo's metacubex/http forwards it as
    /// `CONNECT /` (its `ServeHTTP` has no CONNECT case, `httputil/reverseproxy.go:403-566`):
    /// a stranger's request opens nothing upstream.
    pub(super) async fn answer(
        &self,
        request: &Request<()>,
        mut stream: H3Stream,
        cx: &Arc<InboundCx>,
    ) {
        if request.method() == Method::CONNECT {
            Reply::new(StatusCode::BAD_GATEWAY)
                .send(&mut stream, false)
                .await;
            return;
        }
        let (mut send, recv) = stream.split();
        let body = request_body(request, recv);
        if self.exchange(request, body, cx, &mut send).await.is_err() {
            let head = request.method() == Method::HEAD;
            Reply::new(StatusCode::BAD_GATEWAY)
                .send(&mut send, head)
                .await;
        }
    }

    /// Fails only before the response has started, when Go's `ErrorHandler` answers 502.
    async fn exchange<S: h3::quic::SendStream<Bytes>>(
        &self,
        request: &Request<()>,
        body: Outgoing,
        cx: &Arc<InboundCx>,
        send: &mut RequestStream<S, Bytes>,
    ) -> io::Result<()> {
        let io = inner::dial(cx, Address::new(&self.host, self.port), None, None);
        let io: BoxStream = match &self.tls {
            None => io,
            Some(tls) => Box::new(handshake(tls.clone(), io, &self.host, cx).await?),
        };
        let (out, gzip) = self.outgoing(request, body)?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(io::Error::other)?;
        let relay = async move {
            let response = sender.send_request(out).await.map_err(io::Error::other);
            drop(sender);
            relay(response?, gzip, send).await;
            Ok(())
        };
        tokio::join!(conn, relay).1
    }

    /// Go's `ProxyRequest.SetURL` with `Out.Host = In.Host`, on what is left once the
    /// hop-by-hop and forwarding headers are gone, and whether it asks for gzip itself.
    fn outgoing(
        &self,
        request: &Request<()>,
        body: Outgoing,
    ) -> io::Result<(Request<Outgoing>, bool)> {
        let path = join_path(self.target.path(), request.uri().path());
        let query = join_query(
            self.target.query().unwrap_or_default(),
            request.uri().query().unwrap_or_default(),
        );
        let target = if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        };
        let host = request
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .filter(|authority| !authority.is_empty())
            .unwrap_or(&self.authority);
        let uri = Uri::builder()
            .path_and_query(target)
            .build()
            .map_err(io::Error::other)?;
        let mut headers = request.headers().clone();
        let trailers = carries_token(request.headers(), header::TE, "trailers");
        strip_hop_headers(&mut headers);
        if trailers {
            headers.insert(header::TE, HeaderValue::from_static("trailers"));
        }
        for name in FORWARDED {
            headers.remove(name);
        }
        headers.insert(
            header::HOST,
            HeaderValue::from_str(host).map_err(io::Error::other)?,
        );
        let gzip = asks_for_gzip(request.method(), &headers);
        if gzip {
            headers.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        }
        let mut out = Request::new(body);
        *out.method_mut() = request.method().clone();
        *out.uri_mut() = uri;
        *out.headers_mut() = headers;
        Ok((out, gzip))
    }
}

/// The TLS handshake on a task of its own, which owns what it uses: awaited in place, the
/// connector's borrow keeps rustc from proving the request task `Send`.
async fn handshake(
    tls: Arc<TlsConnector>,
    io: BoxStream,
    host: &str,
    cx: &InboundCx,
) -> io::Result<concord_tls::TlsConn> {
    let sni = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let shaking = cx.tasks.spawn_returning(async move {
        tokio::time::timeout(TLS_HANDSHAKE, tls.connect(io, &sni)).await
    });
    match shaking.await {
        Ok(Some(Ok(conn))) => conn,
        Ok(Some(Err(_))) => Err(io::Error::new(io::ErrorKind::TimedOut, "tls handshake")),
        Ok(None) | Err(_) => Err(io::Error::other("tls handshake stopped")),
    }
}

/// The client's body as it arrives. Go probes a bodiless method's body for 200 ms before it
/// sends one; a request of such a method without a length goes out without a body here.
fn request_body<R>(request: &Request<()>, recv: RequestStream<R, Bytes>) -> Outgoing
where
    R: h3::quic::RecvStream + Send + 'static,
{
    let length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.parse::<u64>().ok());
    let bodiless = [Method::GET, Method::HEAD, Method::DELETE, Method::OPTIONS]
        .contains(request.method())
        || ["PROPFIND", "SEARCH"].contains(&request.method().as_str());
    if length == Some(0) || (length.is_none() && bodiless) {
        return Empty::new().map_err(|never| match never {}).boxed_unsync();
    }
    let frames = futures_util::stream::unfold(Some(recv), |recv| async move {
        let mut recv = recv?;
        match recv.recv_data().await {
            Ok(Some(mut data)) => {
                let data = data.copy_to_bytes(data.remaining());
                Some((Ok(Frame::data(data)), Some(recv)))
            }
            Ok(None) => None,
            Err(err) => Some((Err(io::Error::other(err)), None)),
        }
    });
    let frames: Pin<Box<dyn futures_util::Stream<Item = io::Result<Frame<Bytes>>> + Send>> =
        Box::pin(frames);
    StreamBody::new(frames).boxed_unsync()
}

/// Go's transport asks for gzip itself when the request names no encoding and no range and
/// is not HEAD (`transport.go:2842-2865`).
fn asks_for_gzip(method: &Method, headers: &HeaderMap) -> bool {
    method != Method::HEAD
        && [header::ACCEPT_ENCODING, header::RANGE]
            .iter()
            .all(|name| headers.get(name).is_none_or(HeaderValue::is_empty))
}

/// Go unpacks an answer only when it asked for gzip itself and the answer has a body and says
/// gzip (`transport.go:2376`, `2439-2445`).
fn unpacks(asked: bool, headers: &HeaderMap, has_body: bool) -> bool {
    asked
        && has_body
        && headers
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"))
}

/// The upstream's response, its hop-by-hop headers gone and unpacked where Go unpacks it,
/// with the `Date` and empty body's `Content-Length` quic-go gives what a handler writes. A
/// body that breaks off or does not unpack resets the stream, as Go's `ErrAbortHandler` does
/// (`httputil/reverseproxy.go:605-616`).
async fn relay<S: h3::quic::SendStream<Bytes>>(
    response: Response<Incoming>,
    gzip: bool,
    send: &mut RequestStream<S, Bytes>,
) {
    let (parts, mut body) = response.into_parts();
    let mut head = Response::new(());
    *head.status_mut() = parts.status;
    *head.headers_mut() = parts.headers;
    strip_hop_headers(head.headers_mut());
    let mut gunzip = unpacks(gzip, head.headers(), !body.is_end_stream()).then(Gunzip::new);
    if gunzip.is_some() {
        head.headers_mut().remove(header::CONTENT_ENCODING);
        head.headers_mut().remove(header::CONTENT_LENGTH);
    }
    if body.is_end_stream() && !head.headers().contains_key(header::CONTENT_LENGTH) {
        head.headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from(0));
    }
    stamp_date(head.headers_mut());
    if send.send_response(head).await.is_err() {
        return;
    }
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            abort(send);
            return;
        };
        match frame.into_data() {
            Ok(data) => {
                let sent = match &mut gunzip {
                    None => send.send_data(data).await.is_ok(),
                    Some(gunzip) => unpack(gunzip, &data, send).await,
                };
                if !sent {
                    return;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    if finish(gunzip, send).await {
                        let _ = send.send_trailers(trailers).await;
                    }
                    return;
                }
            }
        }
    }
    if finish(gunzip, send).await {
        let _ = send.finish().await;
    }
}

/// Sends what `data` unpacks to; false once the stream is gone or reset.
async fn unpack<S: h3::quic::SendStream<Bytes>>(
    gunzip: &mut Gunzip,
    mut data: &[u8],
    send: &mut RequestStream<S, Bytes>,
) -> bool {
    while !data.is_empty() {
        let Ok((taken, out)) = gunzip.write(data) else {
            abort(send);
            return false;
        };
        data = data.get(taken..).unwrap_or_default();
        if !out.is_empty() && send.send_data(out).await.is_err() {
            return false;
        }
    }
    true
}

/// Sends the end of what was unpacking; false once the stream is gone or reset.
async fn finish<S: h3::quic::SendStream<Bytes>>(
    gunzip: Option<Gunzip>,
    send: &mut RequestStream<S, Bytes>,
) -> bool {
    match gunzip.map(Gunzip::finish) {
        None => true,
        Some(Ok(out)) => out.is_empty() || send.send_data(out).await.is_ok(),
        Some(Err(_)) => {
            abort(send);
            false
        }
    }
}

fn abort<S: h3::quic::SendStream<Bytes>>(send: &mut RequestStream<S, Bytes>) {
    send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
}

/// Go's `removeHopByHopHeaders`: the headers `Connection` names, then `hopHeaders`.
fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_HEADERS {
        headers.remove(name);
    }
}

fn carries_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| item.trim().eq_ignore_ascii_case(token))
}

/// Go's `singleJoiningSlash` on the escaped paths.
fn join_path(target: &str, request: &str) -> String {
    match (target.ends_with('/'), request.starts_with('/')) {
        (true, true) => format!("{target}{}", &request[1..]),
        (false, false) => format!("{target}/{request}"),
        _ => format!("{target}{request}"),
    }
}

fn join_query(target: &str, request: &str) -> String {
    if target.is_empty() || request.is_empty() {
        format!("{target}{request}")
    } else {
        format!("{target}&{request}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_queries_join_as_set_url_joins_them() {
        assert_eq!(join_path("/", "/a/b"), "/a/b");
        assert_eq!(join_path("/base", "/a"), "/base/a");
        assert_eq!(join_path("/base/", "/a"), "/base/a");
        assert_eq!(join_path("/base", "a"), "/base/a");
        assert_eq!(join_query("", "x=1"), "x=1");
        assert_eq!(join_query("k=v", ""), "k=v");
        assert_eq!(join_query("k=v", "x=1"), "k=v&x=1");
    }

    #[test]
    fn hop_headers_and_those_connection_names_are_dropped() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("x-secret, keep-alive"),
        );
        headers.insert("x-secret", HeaderValue::from_static("1"));
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        strip_hop_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert!(headers.contains_key(header::ACCEPT));
    }

    fn reverse(target: &str) -> Reverse {
        Reverse::new(&target.parse().unwrap()).unwrap()
    }

    fn request(uri: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut request = Request::new(());
        *request.uri_mut() = uri.parse().unwrap();
        for (name, value) in headers {
            request.headers_mut().append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        request
    }

    fn empty() -> Outgoing {
        Empty::new().map_err(|never| match never {}).boxed_unsync()
    }

    #[test]
    fn an_http1_request_keeps_the_clients_host_and_loses_its_forwarding() {
        let proxy = reverse("http://10.0.0.1:8080/site?k=v");
        let incoming = request(
            "https://masq.example/page?x=1",
            &[
                ("x-forwarded-for", "1.2.3.4"),
                ("forwarded", "for=1.2.3.4"),
                ("te", "trailers, deflate"),
                ("user-agent", "probe"),
            ],
        );
        let (out, _) = proxy.outgoing(&incoming, empty()).unwrap();
        assert_eq!(out.uri(), "/site/page?k=v&x=1");
        assert_eq!(out.headers()[header::HOST], "masq.example");
        assert_eq!(out.headers()[header::TE], "trailers");
        assert_eq!(out.headers()[header::USER_AGENT], "probe");
        assert!(!out.headers().contains_key("x-forwarded-for"));
        assert!(!out.headers().contains_key("forwarded"));
    }

    #[test]
    fn an_https_target_offers_only_http1_on_its_default_port() {
        let proxy = reverse("https://upstream.test");
        assert_eq!((proxy.host.as_str(), proxy.port), ("upstream.test", 443));
        let (out, _) = proxy
            .outgoing(&request("https://masq.example/a", &[]), empty())
            .unwrap();
        assert_eq!(out.uri(), "/a");
        assert_eq!(out.headers()[header::HOST], "masq.example");
    }

    #[test]
    fn gzip_is_asked_for_only_without_an_encoding_a_range_or_head() {
        let proxy = reverse("http://upstream.test");
        let asked = |method: Method, headers: &[(&str, &str)]| {
            let mut incoming = request("https://masq.example/a", headers);
            *incoming.method_mut() = method;
            let (out, gzip) = proxy.outgoing(&incoming, empty()).unwrap();
            let sent = out.headers().get(header::ACCEPT_ENCODING).cloned();
            (gzip, sent.map(|value| value.to_str().unwrap().to_owned()))
        };
        let gzip = Some("gzip".to_owned());
        assert_eq!(asked(Method::GET, &[]), (true, gzip.clone()));
        assert_eq!(
            asked(Method::POST, &[("accept-encoding", "")]),
            (true, gzip.clone())
        );
        assert_eq!(
            asked(Method::GET, &[("accept-encoding", "br")]),
            (false, Some("br".to_owned()))
        );
        assert_eq!(asked(Method::GET, &[("range", "bytes=0-1")]), (false, None));
        assert_eq!(asked(Method::HEAD, &[]), (false, None));
        let named = [("connection", "accept-encoding"), ("accept-encoding", "br")];
        assert_eq!(asked(Method::GET, &named), (true, gzip));
    }

    #[test]
    fn only_a_gzip_answer_with_a_body_to_a_request_that_asked_unpacks() {
        let encoded = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_ENCODING,
                HeaderValue::from_str(value).unwrap(),
            );
            headers
        };
        assert!(unpacks(true, &encoded("gzip"), true));
        assert!(unpacks(true, &encoded("GZip"), true));
        assert!(!unpacks(false, &encoded("gzip"), true));
        assert!(!unpacks(true, &encoded("gzip"), false));
        assert!(!unpacks(true, &encoded("br"), true));
        assert!(!unpacks(true, &encoded("gzip, br"), true));
        assert!(!unpacks(true, &HeaderMap::new(), true));
    }
}
