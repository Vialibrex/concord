//! What a download sends and how it reads the answer: the headers Go's `Transport` and curl add
//! when a request names none, a gzip body unpacked only when the download asked for it, and
//! redirects followed to the answer that is not one.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_group::{FetchRequest, Fetcher as _};
use flate2::Compression;
use flate2::write::GzEncoder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::tests::running;

const PROFILE: &str = "global-ua: ua-of-the-profile\nrules:\n  - MATCH,DIRECT\n";

fn gzip(text: &str) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(text.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

/// An HTTP/1.1 server that answers each path with its canned reply and keeps every request head.
async fn server(replies: BTreeMap<&'static str, Vec<u8>>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = socket.read(&mut buf).await.unwrap();
                head.extend_from_slice(&buf[..read]);
            }
            let head = String::from_utf8(head).unwrap();
            let path = head.split(' ').nth(1).unwrap().to_string();
            lock(&seen).push(head);
            socket.write_all(&replies[path.as_str()]).await.unwrap();
        }
    });
    (port, heads)
}

fn reply(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn request(port: u16, path: &str, headers: &[(&str, &str)]) -> FetchRequest {
    FetchRequest {
        url: format!("http://127.0.0.1:{port}{path}"),
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
        via_proxy: None,
        size_limit: None,
        timeout: Duration::from_secs(10),
    }
}

/// The head's header lines, names lowercased, without the request line.
fn lines(head: &str) -> Vec<(String, String)> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(": "))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_asks_for_any_type_and_gzip_and_unpacks_the_gzip_it_asked_for() {
    let (port, heads) = server(BTreeMap::from([(
        "/sub",
        reply(
            "200 OK",
            "Content-Encoding: gzip\r\n",
            &gzip("proxies: []\n"),
        ),
    )]))
    .await;
    let (engine, _, _home) = running(PROFILE).await;
    let response = engine
        .shared
        .fetcher
        .get(request(port, "/sub", &[]))
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"proxies: []\n");
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.header("content-length"), None);
    let sent = lines(&lock(&heads)[0]);
    for wanted in [
        ("user-agent", "ua-of-the-profile"),
        ("accept", "*/*"),
        ("accept-encoding", "gzip"),
    ] {
        assert!(
            sent.iter()
                .any(|(name, value)| (name.as_str(), value.as_str()) == wanted),
            "{wanted:?} in {sent:?}"
        );
    }
    engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headers_a_download_names_itself_win_and_its_gzip_stays_packed() {
    let packed = gzip("rules: []\n");
    let (port, heads) = server(BTreeMap::from([(
        "/rules",
        reply("200 OK", "Content-Encoding: gzip\r\n", &packed),
    )]))
    .await;
    let (engine, _, _home) = running(PROFILE).await;
    let own = [
        ("user-agent", "own-ua"),
        ("ACCEPT", "text/yaml"),
        ("Accept-Encoding", "gzip"),
    ];
    let response = engine
        .shared
        .fetcher
        .get(request(port, "/rules", &own))
        .await
        .unwrap();
    assert_eq!(response.body, packed);
    assert_eq!(response.header("content-encoding"), Some("gzip"));
    let sent = lines(&lock(&heads)[0]);
    for (name, value) in own {
        let name = name.to_ascii_lowercase();
        let named: Vec<_> = sent.iter().filter(|(key, _)| *key == name).collect();
        assert_eq!(named, [&(name.clone(), value.to_string())], "{sent:?}");
    }
    engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_body_and_a_refusal_after_a_redirect_read_as_sent() {
    let (port, _) = server(BTreeMap::from([
        ("/plain", reply("200 OK", "", b"payload: 1\n")),
        ("/moved", reply("302 Found", "Location: /refused\r\n", b"")),
        (
            "/refused",
            reply(
                "403 Forbidden",
                "Content-Encoding: gzip\r\n",
                &gzip("<html>blocked</html>"),
            ),
        ),
    ]))
    .await;
    let (engine, _, _home) = running(PROFILE).await;
    let plain = engine
        .shared
        .fetcher
        .get(request(port, "/plain", &[]))
        .await
        .unwrap();
    assert_eq!(plain.body, b"payload: 1\n");
    assert_eq!(plain.header("content-length"), Some("11"));
    let refused = engine
        .shared
        .fetcher
        .get(request(port, "/moved", &[]))
        .await
        .unwrap();
    assert_eq!(refused.status, 403);
    assert_eq!(refused.body, b"<html>blocked</html>");
    engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_size_limit_holds_the_unpacked_body() {
    let (port, _) = server(BTreeMap::from([(
        "/big",
        reply(
            "200 OK",
            "Content-Encoding: gzip\r\n",
            &gzip(&"x".repeat(4096)),
        ),
    )]))
    .await;
    let (engine, _, _home) = running(PROFILE).await;
    let mut limited = request(port, "/big", &[]);
    limited.size_limit = Some(1024);
    let err = engine.shared.fetcher.get(limited).await.err().unwrap();
    assert_eq!(err.message, "length limit exceeded");
    engine.shutdown().await;
}
