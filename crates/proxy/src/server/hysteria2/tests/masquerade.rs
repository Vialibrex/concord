use std::net::SocketAddr;

use super::*;

fn masqueraded(
    masquerade: concord_config::listener::Masquerade,
    home: &Arc<HomeDir>,
) -> Arc<Hysteria2> {
    let mut config = config(&[("alice", "secret")]);
    config.masquerade = Some(masquerade);
    Arc::new(Hysteria2::new(&config, tls_setup(), home).unwrap())
}

fn proxied(target: &str) -> Arc<Hysteria2> {
    let target = concord_config::listener::Masquerade::Proxy(target.parse().unwrap());
    masqueraded(target, &home())
}

/// A request's status, headers and whole body.
async fn fetch(
    requests: &mut Requests,
    method: http::Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, http::HeaderMap, Vec<u8>) {
    let exchange = async {
        let mut request = http::Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut exchange = requests
            .send_request(request.body(()).unwrap())
            .await
            .unwrap();
        if !body.is_empty() {
            exchange
                .send_data(Bytes::copy_from_slice(body))
                .await
                .unwrap();
        }
        exchange.finish().await.unwrap();
        let response = exchange.recv_response().await.unwrap();
        let mut got = Vec::new();
        while let Some(mut chunk) = exchange.recv_data().await.unwrap() {
            let remaining = bytes::Buf::remaining(&chunk);
            got.extend_from_slice(&bytes::Buf::copy_to_bytes(&mut chunk, remaining));
        }
        (response.status().as_u16(), response.headers().clone(), got)
    };
    tokio::time::timeout(Duration::from_secs(10), exchange)
        .await
        .expect("the masquerade did not answer")
}

/// An HTTP/1 server that answers each request, after `delay`, with what it saw of it, and
/// the most requests it held at once.
#[allow(
    clippy::disallowed_methods,
    reason = "the upstream is a loopback test server"
)]
async fn upstream(delay: Duration) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;

    use http_body_util::{BodyExt, Full};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let counted = most.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (held, most) = (held.clone(), counted.clone());
            let service =
                hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    let (held, most) = (held.clone(), most.clone());
                    async move {
                        most.fetch_max(held.fetch_add(1, SeqCst) + 1, SeqCst);
                        tokio::time::sleep(delay).await;
                        let (parts, body) = request.into_parts();
                        let body = body
                            .collect()
                            .await
                            .map(|body| body.to_bytes())
                            .unwrap_or_default();
                        held.fetch_sub(1, SeqCst);
                        let header = |name: &str| {
                            parts
                                .headers
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or("")
                                .to_owned()
                        };
                        let seen = format!(
                            "{} {} host={} xff={} body={}",
                            parts.method,
                            parts.uri,
                            header("host"),
                            header("x-forwarded-for"),
                            String::from_utf8_lossy(&body)
                        );
                        Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                            Bytes::from(seen),
                        )))
                    }
                });
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    (addr, most)
}

#[tokio::test]
async fn a_masquerade_directory_is_served_before_authentication() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("index.html"), "<p>hi</p>").unwrap();
    std::fs::write(dir.path().join("notes.txt"), "0123456789").unwrap();
    let root =
        concord_config::listener::Masquerade::File(dir.path().to_string_lossy().into_owned());
    let running = Running::start(masqueraded(root, &Arc::new(HomeDir::new(dir.path()))));
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let get = http::Method::GET;

    let (status, headers, body) =
        fetch(&mut requests, get.clone(), "https://masq.test/", &[], b"").await;
    assert_eq!((status, body.as_slice()), (200, b"<p>hi</p>".as_slice()));
    assert_eq!(
        headers[http::header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let range = [("range", "bytes=2-4")];
    let (status, headers, body) = fetch(
        &mut requests,
        get.clone(),
        "https://masq.test/notes.txt",
        &range,
        b"",
    )
    .await;
    assert_eq!((status, body.as_slice()), (206, b"234".as_slice()));
    assert_eq!(headers[http::header::CONTENT_RANGE], "bytes 2-4/10");
    let (status, _, body) = fetch(&mut requests, get, "https://masq.test/missing", &[], b"").await;
    assert_eq!(
        (status, body.as_slice()),
        (404, b"404 page not found\n".as_slice())
    );

    assert_eq!(authenticate(&mut requests, "secret").await, AUTH_OK);
}

#[tokio::test]
async fn a_masquerade_proxy_goes_through_the_tunnel_with_the_clients_host() {
    let (upstream, _) = upstream(Duration::ZERO).await;
    let running = Running::start(proxied(&format!("http://{upstream}/base")));
    running.flows.forward();
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;

    let headers = [("x-forwarded-for", "1.2.3.4"), ("content-length", "2")];
    let uri = "https://masq.example/page?x=1";
    let (status, _, body) = fetch(&mut requests, http::Method::POST, uri, &headers, b"hi").await;
    assert_eq!(status, 200);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "POST /base/page?x=1 host=masq.example xff= body=hi"
    );
    assert_eq!(running.flows.opened(), [(Address::Socket(upstream), None)]);
    assert_eq!(running.flows.kinds(), [InboundKind::Inner]);
}

#[tokio::test]
async fn a_masquerade_proxy_that_reaches_nothing_answers_502() {
    let running = Running::start(proxied("http://127.0.0.1:9/"));
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let (status, _, body) = fetch(
        &mut requests,
        http::Method::GET,
        "https://masq.test/",
        &[],
        b"",
    )
    .await;
    assert_eq!((status, body.len()), (502, 0));
}

/// Before a connection authenticates its requests are answered one at a time, so a
/// stranger's connection holds one upstream request at most.
#[tokio::test]
async fn masquerade_requests_before_authentication_reach_the_upstream_one_at_a_time() {
    let (upstream, most) = upstream(Duration::from_millis(200)).await;
    let running = Running::start(proxied(&format!("http://{upstream}")));
    running.flows.forward();
    let conn = running.connect(b"h3").await;
    let requests = h3(&conn).await;
    let one = |path: &'static str| {
        let mut requests = requests.clone();
        async move {
            fetch(&mut requests, http::Method::GET, path, &[], b"")
                .await
                .0
        }
    };
    let statuses = tokio::join!(
        one("https://masq.test/a"),
        one("https://masq.test/b"),
        one("https://masq.test/c")
    );
    assert_eq!(statuses, (200, 200, 200));
    assert_eq!(most.load(std::sync::atomic::Ordering::SeqCst), 1);
}

/// A name under the directory that passes through a symlink answers 404, as a provider path
/// through one is refused, and `..` stays inside the directory, so a stranger reads nothing
/// else in or out of the home directory.
#[cfg(unix)]
#[tokio::test]
async fn a_masquerade_directory_serves_nothing_through_a_symlink_or_above_itself() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();
    std::fs::write(home.path().join("beside.txt"), "beside").unwrap();
    let site = home.path().join("site");
    std::fs::create_dir(&site).unwrap();
    std::fs::write(site.join("plain.txt"), "plain").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret.txt"), site.join("leak.txt")).unwrap();
    let root = concord_config::listener::Masquerade::File(site.to_string_lossy().into_owned());
    let running = Running::start(masqueraded(root, &Arc::new(HomeDir::new(home.path()))));
    let conn = running.connect(b"h3").await;
    let requests = h3(&conn).await;
    let get = |path: &'static str| {
        let mut requests = requests.clone();
        async move {
            let (status, _, body) = fetch(&mut requests, http::Method::GET, path, &[], b"").await;
            (status, String::from_utf8(body).unwrap())
        }
    };

    assert_eq!(
        get("https://masq.test/plain.txt").await,
        (200, "plain".to_owned())
    );
    let refused = (404, "404 page not found\n".to_owned());
    assert_eq!(get("https://masq.test/leak.txt").await, refused);
    assert_eq!(get("https://masq.test/%2e%2e/beside.txt").await, refused);
}

/// An HTTP/1 server that answers every request with a gzip body saying `hello, masquerade`,
/// or one that is not gzip at all for `/broken`, and the `Accept-Encoding` it saw.
#[allow(
    clippy::disallowed_methods,
    reason = "the upstream is a loopback test server"
)]
async fn gzip_upstream() -> SocketAddr {
    use std::io::Write as _;

    use http_body_util::Full;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"hello, masquerade").unwrap();
    let packed = Bytes::from(encoder.finish().unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let packed = packed.clone();
            let service =
                hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    let seen = request
                        .headers()
                        .get(http::header::ACCEPT_ENCODING)
                        .map_or("none", |value| value.to_str().unwrap_or("?"))
                        .to_owned();
                    let body = if request.uri().path() == "/broken" {
                        Bytes::from_static(b"not gzip at all")
                    } else {
                        packed.clone()
                    };
                    let response = http::Response::builder()
                        .header(http::header::CONTENT_ENCODING, "gzip")
                        .header("x-seen-accept-encoding", seen)
                        .body(Full::new(body))
                        .unwrap();
                    async move { Ok::<_, std::convert::Infallible>(response) }
                });
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    addr
}

/// Go's transport asks for gzip itself only when the request names no encoding and no range
/// and is not HEAD, and unpacks only an answer it asked for (metacubex/http v0.1.8
/// `transport.go:2376`, `2439-2445`, `2842-2865`).
#[tokio::test]
async fn a_masquerade_proxy_unpacks_gzip_only_where_it_asked_for_it() {
    let upstream = gzip_upstream().await;
    let running = Running::start(proxied(&format!("http://{upstream}")));
    running.flows.forward();
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let uri = "https://masq.test/page";
    let header = |headers: &http::HeaderMap, name: &str| {
        headers
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
    };
    let gzip = Some("gzip".to_owned());
    let packed = |body: &[u8]| body.starts_with(&[0x1f, 0x8b]);

    let (status, headers, body) = fetch(&mut requests, http::Method::GET, uri, &[], b"").await;
    assert_eq!(
        (status, body.as_slice()),
        (200, b"hello, masquerade".as_slice())
    );
    assert_eq!(header(&headers, "x-seen-accept-encoding"), gzip);
    assert_eq!(header(&headers, "content-encoding"), None);
    assert_eq!(header(&headers, "content-length"), None);

    let own = [("accept-encoding", "gzip")];
    let (_, headers, body) = fetch(&mut requests, http::Method::GET, uri, &own, b"").await;
    assert_eq!(header(&headers, "content-encoding"), gzip);
    assert!(packed(&body));

    let range = [("range", "bytes=0-3")];
    let (_, headers, body) = fetch(&mut requests, http::Method::GET, uri, &range, b"").await;
    assert_eq!(
        header(&headers, "x-seen-accept-encoding").as_deref(),
        Some("none")
    );
    assert_eq!(header(&headers, "content-encoding"), gzip);
    assert!(packed(&body));

    let (_, headers, body) = fetch(&mut requests, http::Method::HEAD, uri, &[], b"").await;
    assert_eq!(
        header(&headers, "x-seen-accept-encoding").as_deref(),
        Some("none")
    );
    assert_eq!(header(&headers, "content-encoding"), gzip);
    assert!(header(&headers, "content-length").is_some());
    assert!(body.is_empty());
}

/// An answer that says gzip but does not unpack resets the stream, as Go's copy aborts the
/// handler (metacubex/http v0.1.8 `httputil/reverseproxy.go:605-616`); the reset may
/// overtake the head.
#[tokio::test]
async fn a_masquerade_proxy_resets_a_stream_whose_gzip_breaks() {
    let upstream = gzip_upstream().await;
    let running = Running::start(proxied(&format!("http://{upstream}")));
    running.flows.forward();
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let exchange = async {
        let request = http::Request::get("https://masq.test/broken")
            .body(())
            .unwrap();
        let mut exchange = requests.send_request(request).await.unwrap();
        exchange.finish().await.unwrap();
        match exchange.recv_response().await {
            Ok(response) => {
                assert_eq!(response.status(), http::StatusCode::OK);
                exchange.recv_data().await.is_err()
            }
            Err(_) => true,
        }
    };
    let answer = tokio::time::timeout(Duration::from_secs(10), exchange).await;
    assert!(
        answer.expect("the masquerade did not answer"),
        "the stream ended cleanly"
    );
}

/// A HEAD request gets the head alone, whatever the masquerade answers it with.
#[tokio::test]
async fn a_head_request_gets_no_body_from_the_masquerade() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("sub")).unwrap();
    std::fs::write(dir.path().join("sub").join("a.txt"), "a").unwrap();
    let root =
        concord_config::listener::Masquerade::File(dir.path().to_string_lossy().into_owned());
    let files = Running::start(masqueraded(root, &Arc::new(HomeDir::new(dir.path()))));
    let none = Running::start(server(&[("alice", "secret")]));
    for (running, path, status) in [
        (&files, "/sub/", 200),
        (&files, "/missing", 404),
        (&none, "/", 404),
    ] {
        let conn = running.connect(b"h3").await;
        let mut requests = h3(&conn).await;
        let uri = format!("https://masq.test{path}");
        let (got, headers, body) = fetch(&mut requests, http::Method::HEAD, &uri, &[], b"").await;
        assert_eq!((got, body.len()), (status, 0), "{path}");
        assert!(headers.contains_key(http::header::CONTENT_TYPE), "{path}");
    }
}

/// Every answer carries the `Date` quic-go gives it, and one whose handler wrote little or
/// nothing the `Content-Length` quic-go adds when the handler returns: the 404, the 502 and
/// the authentication's 233 alike.
#[tokio::test]
async fn masquerade_answers_and_the_authentication_carry_quic_go_s_date_and_length() {
    let length = |headers: &http::HeaderMap| {
        assert!(headers.contains_key(http::header::DATE));
        headers[http::header::CONTENT_LENGTH]
            .to_str()
            .unwrap()
            .to_owned()
    };
    for (running, length_wanted) in [
        (Running::start(server(&[("alice", "secret")])), "19"),
        (Running::start(proxied("http://127.0.0.1:9/")), "0"),
    ] {
        let conn = running.connect(b"h3").await;
        let mut requests = h3(&conn).await;
        let (_, headers, _) = fetch(
            &mut requests,
            http::Method::GET,
            "https://masq.test/",
            &[],
            b"",
        )
        .await;
        assert_eq!(length(&headers), length_wanted);
    }

    let running = Running::start(server(&[("alice", "secret")]));
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let request = http::Request::post("https://hysteria/auth")
        .header("Hysteria-Auth", "secret")
        .header("Hysteria-CC-RX", "0")
        .body(())
        .unwrap();
    let mut exchange = requests.send_request(request).await.unwrap();
    exchange.finish().await.unwrap();
    let response = exchange.recv_response().await.unwrap();
    assert_eq!(response.status().as_u16(), AUTH_OK);
    assert_eq!(length(response.headers()), "0");
}

/// An upstream that never answers sees the proxied request's connection end once the
/// client's QUIC connection goes, as quic-go's request context ends with it.
#[allow(
    clippy::disallowed_methods,
    reason = "the upstream is a loopback test server"
)]
#[tokio::test]
async fn a_masquerade_proxy_lets_go_of_the_upstream_when_the_connection_closes() {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (asked, mut got_request) = tokio::sync::mpsc::channel(1);
    let (ended, mut got_end) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let mut seen = Vec::new();
        while !seen.windows(4).any(|end| end == b"\r\n\r\n") {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.extend_from_slice(buf.get(..n).unwrap_or_default()),
            }
        }
        let _ = asked.send(()).await;
        let end = matches!(stream.read(&mut buf).await, Ok(0) | Err(_));
        let _ = ended.send(end).await;
    });
    let running = Running::start(proxied(&format!("http://{upstream}")));
    running.flows.forward();
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let request = http::Request::get("https://masq.test/events")
        .body(())
        .unwrap();
    let mut exchange = requests.send_request(request).await.unwrap();
    exchange.finish().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), got_request.recv())
        .await
        .expect("the request did not reach the upstream");

    conn.close(quinn::VarInt::from_u32(0), b"");
    let end = tokio::time::timeout(Duration::from_secs(5), got_end.recv()).await;
    assert_eq!(end.ok().flatten(), Some(true), "the upstream was held");
    drop(exchange);
}

#[tokio::test]
async fn a_masquerade_proxy_answers_connect_with_502_and_dials_nothing() {
    let (upstream, _) = upstream(Duration::ZERO).await;
    let running = Running::start(proxied(&format!("http://{upstream}")));
    running.flows.forward();
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let (status, _, body) = fetch(
        &mut requests,
        http::Method::CONNECT,
        "masq.test:443",
        &[],
        b"",
    )
    .await;
    assert_eq!((status, body.len()), (502, 0));
    assert!(running.flows.opened().is_empty());
}

/// A file or a directory the server may not read answers 403, as `toHTTPError` maps Go's
/// open, and a directory whose `index.html` it may not read is listed instead.
#[cfg(unix)]
#[tokio::test]
async fn a_masquerade_directory_refuses_what_it_may_not_read_as_go_does() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let locked = |path: std::path::PathBuf| {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    };
    std::fs::write(dir.path().join("secret.txt"), "s").unwrap();
    locked(dir.path().join("secret.txt"));
    std::fs::create_dir(dir.path().join("closed")).unwrap();
    locked(dir.path().join("closed"));
    std::fs::create_dir(dir.path().join("site")).unwrap();
    std::fs::write(dir.path().join("site").join("index.html"), "i").unwrap();
    locked(dir.path().join("site").join("index.html"));
    if std::fs::File::open(dir.path().join("secret.txt")).is_ok() {
        return;
    }
    let root =
        concord_config::listener::Masquerade::File(dir.path().to_string_lossy().into_owned());
    let running = Running::start(masqueraded(root, &Arc::new(HomeDir::new(dir.path()))));
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let mut get = async |path: &str| {
        let uri = format!("https://masq.test{path}");
        let (status, _, body) = fetch(&mut requests, http::Method::GET, &uri, &[], b"").await;
        (status, String::from_utf8(body).unwrap())
    };

    let forbidden = (403, "403 Forbidden\n".to_owned());
    assert_eq!(get("/secret.txt").await, forbidden);
    assert_eq!(get("/closed/").await, forbidden);
    let (status, listing) = get("/site/").await;
    assert_eq!(status, 200);
    assert!(
        listing.contains("<a href=\"index.html\">index.html</a>"),
        "{listing}"
    );
}

/// An `https://` upstream that offers HTTP/2 is still spoken to over HTTP/1.1, through the
/// tunnel, with the client's host.
#[allow(
    clippy::disallowed_methods,
    reason = "the upstream is a loopback test server"
)]
#[tokio::test]
async fn a_masquerade_proxy_reaches_an_https_upstream_over_http1() {
    use http_body_util::Full;

    let (mut tls, _) = concord_test_support::localhost_tls(rustls::DEFAULT_VERSIONS);
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let alpn = tls.get_ref().1.alpn_protocol().unwrap_or_default().to_vec();
                let alpn = String::from_utf8(alpn).unwrap();
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let host = request.headers()[http::header::HOST].to_str().unwrap();
                        let seen = format!(
                            "{} {} host={host} alpn={alpn}",
                            request.method(),
                            request.uri()
                        );
                        async move {
                            Ok::<_, std::convert::Infallible>(http::Response::new(Full::new(
                                Bytes::from(seen),
                            )))
                        }
                    },
                );
                let io = hyper_util::rt::TokioIo::new(tls);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });
    let running = Running::start(proxied(&format!("https://{upstream}/base")));
    running.flows.forward();
    let conn = running.connect(b"h3").await;
    let mut requests = h3(&conn).await;
    let uri = "https://masq.example/page?x=1";
    let (status, _, body) = fetch(&mut requests, http::Method::GET, uri, &[], b"").await;
    assert_eq!(status, 200);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "GET /base/page?x=1 host=masq.example alpn=http/1.1"
    );
    assert_eq!(running.flows.opened(), [(Address::Socket(upstream), None)]);
}
