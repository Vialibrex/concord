//! The accepting ends of the HTTP carriers a profile's listeners serve, as mihomo's
//! listeners mount them on one HTTP server: a websocket upgrade at `ws-path`, gun streams
//! at the `grpc-service-name` path over HTTP/2, either with or without TLS beneath.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::digest;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use concord_common::{BoxStream, PeekedStream, Tasks};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::gun::{gun_framed, service_path};
use crate::h2io::{H2Body, Incoming};
use crate::http1::HeadReader;
use crate::ws::WsStream;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const SETTINGS_FRAME: u8 = 0x4;

/// Go's `firstSettingsTimeout` (`net/http/internal/http2/server.go:59`): how long the
/// client's SETTINGS may trail its preface.
const FIRST_SETTINGS: Duration = Duration::from_secs(2);
/// mihomo's `http.Server{IdleTimeout}` for these carriers (`listener/sing_vmess/server.go:96`,
/// `listener/sing_vless/server.go:86`, `listener/trojan/server.go:82`), which Go's HTTP/2
/// server runs from the last stream's close (`server.go:804-806`, `:1590-1595`).
const IDLE: Duration = Duration::from_secs(30);
/// Go's `defaultMaxStreams` (`server.go:61`), the SETTINGS a Go server advertises.
const MAX_STREAMS: u32 = 250;
/// The HTTP/2 server receive buffers of metacubex/http `v0.1.8`, which mihomo's gun and ws
/// servers run on, per connection and per stream (`http2/config.go:104`, `:109`): what a
/// client may send that the server has not read. The client's larger windows
/// (`h2io::STREAM_WINDOW`, `h2io::CONN_WINDOW`) would let one user park a gigabyte.
const CONN_WINDOW: u32 = 1 << 20;
const STREAM_WINDOW: u32 = 1 << 20;
/// metacubex/http `v0.1.8`'s `DefaultMaxHeaderBytes` and the 4096 bytes past it its
/// `http.Server` reads before refusing a request head (`server.go:896`, `:905-906`).
const MAX_REQUEST_HEAD: usize = (1 << 20) + 4096;
/// Go's `goAwayTimeout` (`server.go:1345`): how long a connection told to go away lingers.
const GOAWAY_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default)]
pub struct HttpCarriers {
    pub ws_path: Option<String>,
    pub grpc_service_name: Option<String>,
}

impl HttpCarriers {
    pub fn is_empty(&self) -> bool {
        self.ws_path.is_none() && self.grpc_service_name.is_none()
    }

    /// What TLS offers in ALPN for these carriers, as mihomo sets `NextProtos`.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        let mut alpn = Vec::new();
        if self.grpc_service_name.is_some() {
            alpn.push(b"h2".to_vec());
        }
        if self.ws_path.is_some() {
            alpn.push(b"http/1.1".to_vec());
        }
        alpn
    }
}

pub type OnStream = Arc<dyn Fn(BoxStream) + Send + Sync>;

/// Serves the carriers on one accepted connection. A websocket hands its one stream to
/// `on_stream` before this returns; an HTTP/2 connection runs on `tasks` and hands on a
/// stream for each gun request.
pub async fn accept(
    mut stream: BoxStream,
    carriers: &HttpCarriers,
    tasks: &Tasks,
    on_stream: OnStream,
) -> io::Result<()> {
    let mut head = vec![0u8; H2_PREFACE.len()];
    let mut have = 0;
    while have < head.len() {
        let n = stream
            .read(head.get_mut(have..).unwrap_or_default())
            .await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        have += n;
        if head.get(..have) != H2_PREFACE.get(..have) {
            break;
        }
    }
    head.truncate(have);
    if head.as_slice() == H2_PREFACE {
        let Some(name) = &carriers.grpc_service_name else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP/2 is not served",
            ));
        };
        first_settings(&mut stream, &mut head).await?;
        let stream: BoxStream = Box::new(PeekedStream::new(head, stream));
        let path = service_path(name);
        tasks.spawn(serve_h2(stream, path, on_stream));
        return Ok(());
    }
    let stream: BoxStream = Box::new(PeekedStream::new(head, stream));
    match &carriers.ws_path {
        Some(path) => {
            let upgraded = upgrade(stream, path).await?;
            on_stream(upgraded);
            Ok(())
        }
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP/1 is not served",
        )),
    }
}

struct RequestHead<'a> {
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> RequestHead<'a> {
    fn parse(text: &'a str) -> io::Result<Self> {
        let mut lines = text.split("\r\n");
        let line = lines.next().unwrap_or_default();
        let mut parts = line.split(' ');
        let (_method, target) = (parts.next(), parts.next().unwrap_or_default());
        let path = target.split(['?', '#']).next().unwrap_or_default();
        if !path.starts_with('/') {
            return Err(invalid("not an HTTP request"));
        }
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect();
        Ok(RequestHead { path, headers })
    }

    fn header(&self, key: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| *value)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// Go's `ServeMux`: a pattern ending in `/` takes the paths under it, any other only itself.
fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern.ends_with('/') {
        path.starts_with(pattern)
    } else {
        path == pattern
    }
}

/// mihomo's `StreamUpgradedWebsocketConn`: any request at the path is upgraded; one
/// without `Sec-WebSocket-Key` is v2ray's HTTP upgrade and carries raw bytes after, and
/// `Sec-WebSocket-Protocol` may carry the first bytes as Xray's early data.
async fn upgrade(mut stream: BoxStream, pattern: &str) -> io::Result<BoxStream> {
    let mut reader = HeadReader::with_limit(MAX_REQUEST_HEAD);
    let raw = reader.read_head(&mut stream).await?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let head = RequestHead::parse(&text)?;
    if !path_matches(pattern, head.path) {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 19\r\nConnection: close\r\n\r\n404 page not found\n")
            .await;
        return Err(invalid("no websocket at this path"));
    }
    let key = head
        .header("Sec-WebSocket-Key")
        .filter(|key| !key.is_empty());
    let mut response = String::from(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n",
    );
    if let Some(key) = key {
        response.push_str(&format!("Sec-Websocket-Accept: {}\r\n", accept_key(key)));
    }
    response.push_str("\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    let early = head
        .header("Sec-WebSocket-Protocol")
        .and_then(decode_early_data)
        .unwrap_or_default();
    let rest = reader.into_rest();
    let inner: BoxStream = if rest.is_empty() {
        stream
    } else {
        Box::new(PeekedStream::new(rest, stream))
    };
    let carried: BoxStream = if key.is_some() {
        Box::new(WsStream::new(inner, false))
    } else {
        inner
    };
    Ok(if early.is_empty() {
        carried
    } else {
        Box::new(PeekedStream::new(early, carried))
    })
}

fn accept_key(key: &str) -> String {
    let mut context = digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(key.as_bytes());
    context.update(WS_GUID);
    STANDARD.encode(context.finish().as_ref())
}

fn decode_early_data(value: &str) -> Option<Vec<u8>> {
    let url_safe: String = value
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    URL_SAFE_NO_PAD.decode(url_safe).ok()
}

/// Reads the frame header after the preface, which must open a SETTINGS frame
/// (RFC 9113 §3.4), as Go refuses any other first frame (`server.go:1442-1446`).
async fn first_settings(stream: &mut BoxStream, head: &mut Vec<u8>) -> io::Result<()> {
    let mut frame = [0u8; 9];
    timeout(FIRST_SETTINGS, stream.read_exact(&mut frame))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no HTTP/2 SETTINGS"))??;
    let [.., kind, _, a, b, c, d] = frame;
    if kind != SETTINGS_FRAME || [a, b, c, d] != [0; 4] {
        return Err(invalid("the first HTTP/2 frame is not SETTINGS"));
    }
    head.extend_from_slice(&frame);
    Ok(())
}

fn server_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_concurrent_streams(MAX_STREAMS);
    builder
}

/// Resolves once no stream has been open for [`IDLE`].
async fn idle(open: &mut watch::Receiver<usize>) {
    loop {
        if *open.borrow_and_update() == 0 {
            if timeout(IDLE, open.changed()).await.is_err() {
                return;
            }
        } else {
            let _ = open.changed().await;
        }
    }
}

/// mihomo's gun server handler: a POST at the service path with a gRPC content type is a
/// stream; any other request gets a 404.
async fn serve_h2(stream: BoxStream, path: String, on_stream: OnStream) {
    let handshake = server_builder().handshake::<_, Bytes>(stream);
    let Ok(Ok(mut connection)) = timeout(FIRST_SETTINGS, handshake).await else {
        return;
    };
    let (count, mut open) = watch::channel(0usize);
    let count = Arc::new(count);
    loop {
        let accepted = tokio::select! {
            accepted = connection.accept() => accepted,
            () = idle(&mut open) => break,
        };
        let Some(Ok((request, mut respond))) = accepted else {
            return;
        };
        let (parts, body) = request.into_parts();
        let grpc = parts.method == http::Method::POST
            && parts.uri.path() == path
            && parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("application/grpc"));
        if !grpc {
            if let Ok(response) = http::Response::builder().status(404).body(()) {
                let _ = respond.send_response(response, true);
            }
            continue;
        }
        let Ok(response) = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header("te", "trailers")
            .body(())
        else {
            continue;
        };
        let Ok(send) = respond.send_response(response, false) else {
            continue;
        };
        count.send_modify(|n| *n += 1);
        let closed = Arc::clone(&count);
        let body = H2Body::new(send, Incoming::Body(body))
            .on_drop(move || closed.send_modify(|n| *n = n.saturating_sub(1)));
        on_stream(gun_framed(body));
    }
    connection.graceful_shutdown();
    let _ = timeout(
        GOAWAY_GRACE,
        std::future::poll_fn(|cx| connection.poll_closed(cx)),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_accept_key_is_rfc_6455s() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn paths_match_as_gos_serve_mux_does() {
        assert!(path_matches("/ws", "/ws"));
        assert!(!path_matches("/ws", "/ws/x"));
        assert!(path_matches("/ws/", "/ws/x"));
    }

    fn grpc(name: &str) -> HttpCarriers {
        HttpCarriers {
            ws_path: None,
            grpc_service_name: Some(name.to_owned()),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_sends_only_the_preface_is_closed() {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(H2_PREFACE).await.unwrap();
        let on_stream: OnStream = Arc::new(|_| panic!("no stream was opened"));
        let err = accept(Box::new(server), &grpc("g"), &Tasks::default(), on_stream)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_http2_connection_closes_once_no_stream_has_been_open_for_the_idle_timeout() {
        let (client, server) = tokio::io::duplex(1 << 16);
        let (streams, mut opened) = tokio::sync::mpsc::unbounded_channel();
        let on_stream: OnStream = Arc::new(move |stream| drop(streams.send(stream)));
        let tasks = Tasks::default();
        let (mut requests, connection) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(connection);
        accept(Box::new(server), &grpc("g"), &tasks, on_stream)
            .await
            .unwrap();
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://x{}", service_path("g")))
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let (response, _upload) = requests.send_request(request, false).unwrap();
        assert_eq!(response.await.unwrap().status(), 200);
        let stream = opened.recv().await.unwrap();

        tokio::time::sleep(IDLE * 3).await;
        assert!(!driver.is_finished());
        drop(stream);
        let quiet = tokio::time::Instant::now();
        driver.await.unwrap().unwrap();
        assert!(quiet.elapsed() >= IDLE);
        assert!(quiet.elapsed() < IDLE + GOAWAY_GRACE * 2);
    }

    #[tokio::test]
    async fn an_upgrade_head_past_gos_limit_is_refused() {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let writer = tokio::spawn(async move {
            let filler = format!("X-Pad: {}\r\n", "a".repeat(1000));
            let _ = client.write_all(b"GET /ws HTTP/1.1\r\nHost: x\r\n").await;
            for _ in 0..MAX_REQUEST_HEAD / filler.len() + 1 {
                if client.write_all(filler.as_bytes()).await.is_err() {
                    break;
                }
            }
            client
        });
        let Err(err) = upgrade(Box::new(server), "/ws").await else {
            panic!("an oversized head was upgraded");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        drop(writer.await.unwrap());
    }

    #[test]
    fn early_data_decodes_either_base64_alphabet() {
        assert_eq!(decode_early_data("aGk"), Some(b"hi".to_vec()));
        assert_eq!(decode_early_data("+/8="), Some(vec![0xfb, 0xff]));
    }
}
