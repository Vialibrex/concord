use std::borrow::Cow;
use std::io;
use std::sync::Arc;

use bytes::Bytes;

use http::header::{
    ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;

use crate::body::{Body, Buffered, Tap, buffer_body, empty, failing, file_body, full, full_with};
use crate::capture::{Cap, PHASE_REQUEST, PHASE_RESPONSE};
use crate::exchange::{
    OutRequest, ReplyError, Sent, Target, Unsent, has_response_body, set_length,
};
use crate::headers::{
    head_text, is_grpc, parse_head, remove_hop_by_hop, response_head, text, version_text, with_host,
};
use crate::heads::Heads;
use crate::limits::{BODY_WAIT, PRESSURE_NO_BODIES};
use crate::pattern::Pattern;
use crate::rules::{BodyRewrite, HeaderRewrite, LocalBody, RequestScan, ResponsePlan};
use crate::script::DEFAULT_SCRIPT_TIMEOUT;
use crate::session::{PoolKey, Routed, Sender, Session};
use crate::target::TargetUrl;
use http_body_util::BodyExt;

impl Session {
    /// Applies the rules to a request about to go upstream and prepares the response-phase plan
    /// for the final sent URL.
    pub(crate) async fn rewrite_request(
        self: &Arc<Self>,
        out: &mut OutRequest,
        target: &mut Target,
        scan: &RequestScan,
    ) -> ResponsePlan {
        let plan = self.apply_request_rules(out, target, scan).await;
        let cap = &target.cap;
        if !cap.is_some() {
            return plan;
        }
        cap.set_request_length(
            out.length
                .and_then(|length| i64::try_from(length).ok())
                .unwrap_or(-1),
        );
        if out.has_body {
            let kept = cap.clone();
            let body = std::mem::replace(&mut out.body, empty());
            out.body = Tap::new(
                body,
                Some(Box::new(move |data| kept.keep_request(data))),
                None,
            )
            .boxed_unsync();
        }
        cap.sent(&out.url.raw, || with_host(&out.headers, &out.host_header()));
        plan
    }

    /// Header Rewrite comes first, as in Surge, so a URL rewrite and Map Local see its result.
    /// Returns `true` when a whole-head rewrite may have changed `out.url`.
    pub(crate) fn rewrite_request_headers(
        &self,
        out: &mut OutRequest,
        target: &Target,
        scan: &RequestScan,
    ) -> bool {
        if scan.headers.is_empty() {
            return false;
        }
        let header_rules = {
            let request = || request_text(out, target.version);
            let heads = Heads::new(Some(&request), None);
            self.core
                .config
                .rules
                .request_header_rewrites_from(scan, &out.url.raw, &heads)
        };
        if header_rules.is_empty() {
            return false;
        }
        let mut url_changed = false;
        let rewritten =
            apply_header_rules(header_rules, &target.cap, PHASE_REQUEST, |rule| match rule
                .whole_head()
            {
                Some((pattern, with)) => {
                    let changed = replace_request_head(out, target.version, pattern, with);
                    url_changed |= changed;
                    changed
                }
                None => rule.apply(&mut out.headers),
            });
        if rewritten {
            tracing::info!("[MITM] rewrite request headers of {}", out.url.raw);
        }
        url_changed
    }

    async fn apply_request_rules(
        self: &Arc<Self>,
        out: &mut OutRequest,
        target: &mut Target,
        scan: &RequestScan,
    ) -> ResponsePlan {
        let rules = &self.core.config.rules;
        let max_body = self.core.config.limits.max_body_size;
        let address = out.url.raw.clone();
        let (mock, body_rules, script) =
            if scan.request_mocks.is_empty() && scan.bodies.is_empty() && scan.scripts.is_empty() {
                (None, Vec::new(), None)
            } else {
                let request = || request_text(out, target.version);
                let heads = Heads::new(Some(&request), None);
                (
                    rules.request_mock_from(scan, &address, &heads),
                    rules.request_body_rewrites_from(scan, &address, &heads),
                    rules.request_script_from(scan, &address, &heads),
                )
            };
        if let Some(mock) = mock {
            mock_body(out, &mock.header, &mock.body).await;
            target.cap.note(
                "request-body-mock",
                PHASE_REQUEST,
                "",
                mock.module.as_deref(),
            );
            tracing::info!("[MITM] mock the request body of {address}");
        }
        let grpc = is_grpc(&out.headers);
        let mut pre = None;
        if !body_rules.is_empty()
            && !grpc
            && out.has_body
            && self.core.shared.pressure.level() < PRESSURE_NO_BODIES
            && let Some(reserved) = self
                .reserve_body(target, &address, &out.headers, out.length, max_body)
                .await
        {
            let body = std::mem::replace(&mut out.body, empty());
            let notes = body_notes(&target.cap, &body_rules);
            let keep = script.is_some_and(|s| s.requires_body);
            match rewrite_body(
                &mut out.headers,
                body,
                out.length,
                max_body,
                body_rules,
                keep,
            )
            .await
            {
                Ok((body, length, buffered)) => {
                    out.set_body(body, length);
                    note_body(&target.cap, PHASE_REQUEST, notes);
                    tracing::info!("[MITM] rewrite request body of {address}");
                    pre = buffered.map(|(data, trailers)| PreBuffered {
                        data,
                        trailers,
                        reserved,
                    });
                }
                Err(err) => {
                    out.body = failing(err);
                    return rules.prepare_response(&out.url.raw);
                }
            }
        }
        if let Some(script) = script {
            self.run_request_script(out, target, script, pre).await;
        }
        let plan = rules.prepare_response(&out.url.raw);
        if !grpc && rules.response_plan_rewrites_body(&plan) {
            out.headers
                .insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        }
        plan
    }

    /// Makes room for a body about to be read whole: its length, or the size
    /// limit when that is unknown or the body is to be decoded. A body that finds
    /// none within a while passes on as it came. Returns the permits reserved.
    pub(crate) async fn reserve_body(
        &self,
        target: &mut Target,
        address: &str,
        headers: &HeaderMap,
        length: Option<u64>,
        limit: i64,
    ) -> Option<u64> {
        let cap = u64::try_from(limit).unwrap_or(0);
        if length.is_some_and(|length| length > cap) {
            return Some(0);
        }
        let encoding = text(headers, CONTENT_ENCODING).trim().to_ascii_lowercase();
        let size = match length {
            Some(length) if encoding.is_empty() || encoding == "identity" => length,
            _ => cap,
        };
        if size == 0 {
            return Some(0);
        }
        self.reserve_extra_body(target, address, size).await
    }

    pub(crate) async fn reserve_extra_body(
        &self,
        target: &mut Target,
        address: &str,
        size: u64,
    ) -> Option<u64> {
        let permits = u32::try_from(size).unwrap_or(u32::MAX);
        let acquired = tokio::time::timeout(
            BODY_WAIT,
            self.core.bodies.clone().acquire_many_owned(permits),
        )
        .await;
        match acquired {
            Ok(Ok(permit)) => {
                target.reserved.push(permit);
                Some(u64::from(permits))
            }
            _ => {
                tracing::info!(
                    "[MITM] the body of {address} passes on as it came: the bodies being worked on fill the buffer"
                );
                None
            }
        }
    }

    pub(crate) async fn rewrite_response(
        self: &Arc<Self>,
        head: &mut http::response::Parts,
        body: &mut Body,
        sent: &Sent,
        target: &mut Target,
        plan: &ResponsePlan,
    ) -> Result<(), ReplyError> {
        if plan.headers.is_empty() && plan.bodies.is_empty() && plan.scripts.is_empty() {
            return Ok(());
        }
        let rules = &self.core.config.rules;
        let max_body = self.core.config.limits.max_body_size;
        let address = sent.url.raw.clone();
        let (header_rules, body_rules, script) = {
            let request = || {
                request_head_text(
                    &sent.method,
                    &sent.url,
                    target.version,
                    &sent.host,
                    &sent.headers,
                )
            };
            let response = || response_head(head.status, version_text(head.version), &head.headers);
            let heads = Heads::new(Some(&request), Some(&response));
            rules.response_rules_from(plan, &heads)
        };
        let rewritten =
            apply_header_rules(header_rules, &target.cap, PHASE_RESPONSE, |rule| match rule
                .whole_head()
            {
                Some((pattern, with)) => replace_response_head(head, pattern, with),
                None => rule.apply(&mut head.headers),
            });
        if rewritten {
            tracing::info!("[MITM] rewrite response headers of {address}");
        }
        if head.status == StatusCode::SWITCHING_PROTOCOLS {
            return Ok(());
        }
        let length = hyper::body::Body::size_hint(body).exact();
        let mut pre = None;
        if !body_rules.is_empty()
            && has_response_body(&sent.method, head.status)
            && !is_grpc(&head.headers)
            && self.core.shared.pressure.level() < PRESSURE_NO_BODIES
            && let Some(reserved) = self
                .reserve_body(target, &address, &head.headers, length, max_body)
                .await
        {
            let source = std::mem::replace(body, empty());
            let notes = body_notes(&target.cap, &body_rules);
            let keep = script.is_some_and(|s| s.requires_body);
            let (rewritten, length, buffered) = rewrite_body(
                &mut head.headers,
                source,
                length,
                max_body,
                body_rules,
                keep,
            )
            .await?;
            *body = rewritten;
            set_length(&mut head.headers, length);
            note_body(&target.cap, PHASE_RESPONSE, notes);
            tracing::info!("[MITM] rewrite response body of {address}");
            pre = buffered.map(|(data, trailers)| PreBuffered {
                data,
                trailers,
                reserved,
            });
        }
        if let Some(script) = script {
            self.run_response_script(head, body, sent, target, script, pre)
                .await?;
        }
        Ok(())
    }

    /// Sends a request upstream by its own route when it needs one.
    pub(crate) async fn round_trip(
        &self,
        out: OutRequest,
        target: &Target,
    ) -> Result<(Response<Incoming>, Option<OnUpgrade>), Unsent> {
        let routed = self.route_request(&out, target).await?;
        self.send_upstream(out, target, routed)
            .await
            .map_err(|err| Unsent::Failed(err.to_string()))
    }

    /// Sends the request to its server on a connection from the pool, a fresh
    /// one if a reused one turns out to be gone.
    async fn send_upstream(
        &self,
        out: OutRequest,
        target: &Target,
        mut routed: Option<Routed>,
    ) -> io::Result<(Response<Incoming>, Option<OnUpgrade>)> {
        let key = PoolKey {
            https: out.url.https,
            host: out.url.host.to_ascii_lowercase(),
            port: out.url.port,
            route: routed
                .as_ref()
                .and_then(|routed| routed.route.as_ref())
                .map(|route| route.chain.clone()),
        };
        let cap = &target.cap;
        let authority = out.host_header();
        let path = out.url.path_and_query.clone();
        let https = out.url.https;
        let mut request = build_request(out, target.http1)?;
        let mut attempt = 0;
        loop {
            let (mut conn, reused) = self
                .connection_for(&key, target.http1, cap, routed.as_mut())
                .await?;
            adapt(&mut request, conn.is_h2(), https, &authority, &path)?;
            let sent = match &mut conn.sender {
                Sender::H1(sender) => sender.try_send_request(request).await,
                Sender::H2(sender) => {
                    sender.ready().await.map_err(io::Error::other)?;
                    sender.try_send_request(request).await
                }
            };
            match sent {
                Ok(mut response) => {
                    let upgrade = (response.status() == StatusCode::SWITCHING_PROTOCOLS)
                        .then(|| hyper::upgrade::on(&mut response));
                    if upgrade.is_none() {
                        self.give_back(&key, conn);
                    }
                    return Ok((response, upgrade));
                }
                Err(mut err) => match err.take_message() {
                    Some(returned) if reused && attempt == 0 => {
                        request = returned;
                        attempt += 1;
                    }
                    _ => return Err(io::Error::other(err.into_error())),
                },
            }
        }
    }
}

/// Sends `body` in place of the request's own, a request that had none included.
async fn mock_body(out: &mut OutRequest, header: &HeaderMap, body: &LocalBody) {
    let (body, len) = match body {
        LocalBody::Bytes(bytes) => (full(bytes.clone()), bytes.len() as u64),
        LocalBody::File(path) => match file_body(path).await {
            Ok(opened) => opened,
            Err(err) => {
                tracing::warn!(
                    "[MITM] request-body-mock {} cannot be read: {err}",
                    path.display()
                );
                return;
            }
        },
    };
    for name in header.keys() {
        out.headers.remove(name);
    }
    for (name, value) in header {
        out.headers.append(name.clone(), value.clone());
    }
    out.headers.remove(CONTENT_ENCODING);
    out.headers.remove(TRANSFER_ENCODING);
    out.set_body(body, Some(len));
    out.has_body = true;
}

/// The head of a request as Quantumult X's `url-and-header` reads it: the request line, the
/// host, then every header as `Name: value`, each line ending in CRLF, and the blank line.
pub(crate) fn request_text(out: &OutRequest, version: &str) -> String {
    request_head_text(
        &out.method,
        &out.url,
        version,
        &out.host_header(),
        &out.headers,
    )
}

fn request_head_text(
    method: &Method,
    url: &TargetUrl,
    version: &str,
    host: &str,
    headers: &HeaderMap,
) -> String {
    let line = format!("{method} {} {version}", url.path_and_query);
    head_text(&line, host, headers)
}

/// The rewritten request line moves the request to another method and path on the same
/// host, which a `Host` line cannot change: one that names another host is put back.
fn replace_request_head(
    out: &mut OutRequest,
    version: &str,
    pattern: &Pattern,
    with: &str,
) -> bool {
    let Some((line, mut headers)) = rewritten_head(&request_text(out, version), pattern, with)
    else {
        return false;
    };
    let mut words = line.split(' ');
    let method = words
        .next()
        .and_then(|word| Method::from_bytes(word.as_bytes()).ok());
    let url = words
        .next()
        .filter(|path| path.starts_with('/'))
        .and_then(|path| TargetUrl::from_request(out.url.https, &out.url.authority, path));
    let (Some(method), Some(url)) = (method, url) else {
        tracing::debug!("[MITM] the rewritten request line {line:?} is not one; the head is kept");
        return false;
    };
    let host = out.host_header();
    if let Some(named) = headers.remove(HOST)
        && named.as_bytes() != host.as_bytes()
    {
        tracing::debug!(
            "[MITM] a head rewrite named the host {named:?}; the request keeps going to {host}"
        );
    }
    keep_framing(&out.headers, &mut headers);
    out.method = method;
    out.url = url;
    out.headers = headers;
    true
}

fn replace_response_head(head: &mut http::response::Parts, pattern: &Pattern, with: &str) -> bool {
    let text = response_head(head.status, version_text(head.version), &head.headers);
    let Some((line, mut headers)) = rewritten_head(&text, pattern, with) else {
        return false;
    };
    let Some(status) = line
        .split(' ')
        .nth(1)
        .and_then(|code| StatusCode::from_bytes(code.as_bytes()).ok())
    else {
        tracing::debug!("[MITM] the rewritten status line {line:?} is not one; the head is kept");
        return false;
    };
    keep_framing(&head.headers, &mut headers);
    head.status = status;
    head.headers = headers;
    true
}

/// `None` when the rule changes nothing or leaves what is not a head.
fn rewritten_head(text: &str, pattern: &Pattern, with: &str) -> Option<(String, HeaderMap)> {
    let replaced = pattern
        .replace(text, with, true)
        .filter(|replaced| replaced != text)?;
    let parsed = parse_head(&replaced);
    if parsed.is_none() {
        tracing::debug!("[MITM] a head rewrite gave {replaced:?}, which is not a head; it is kept");
    }
    parsed
}

/// What frames the message stays the body's, as a header rewrite cannot change it.
fn keep_framing(from: &HeaderMap, to: &mut HeaderMap) {
    for name in [CONTENT_LENGTH, TRANSFER_ENCODING] {
        to.remove(&name);
        for value in from.get_all(&name) {
            to.append(name.clone(), value.clone());
        }
    }
}

/// A request with an absolute URI and a `Host` header, which `adapt` fits to the
/// connection it goes out on.
fn build_request(out: OutRequest, upgrading: bool) -> io::Result<Request<Body>> {
    let mut headers = out.headers;
    let upgrade_type = text(&headers, UPGRADE).to_string();
    remove_hop_by_hop(&mut headers, false);
    if upgrading && !upgrade_type.is_empty() {
        headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        if let Ok(value) = HeaderValue::from_str(&upgrade_type) {
            headers.insert(UPGRADE, value);
        }
    }
    let mut request = Request::new(out.body);
    *request.method_mut() = out.method;
    *request.headers_mut() = headers;
    Ok(request)
}

fn adapt(
    request: &mut Request<Body>,
    h2: bool,
    https: bool,
    authority: &str,
    path: &str,
) -> io::Result<()> {
    let headers = request.headers_mut();
    let uri = if h2 {
        headers.remove(HOST);
        Uri::builder()
            .scheme(if https { "https" } else { "http" })
            .authority(authority)
            .path_and_query(path)
            .build()
    } else {
        let host = HeaderValue::from_str(authority).map_err(io::Error::other)?;
        headers.insert(HOST, host);
        path.parse::<Uri>().map_err(Into::into)
    }
    .map_err(io::Error::other)?;
    *request.uri_mut() = uri;
    *request.version_mut() = if h2 {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    Ok(())
}

/// Applies each rule with `apply`, noting the ones that changed the head; true if any did.
fn apply_header_rules(
    rules: Vec<&HeaderRewrite>,
    cap: &Cap,
    phase: &str,
    mut apply: impl FnMut(&HeaderRewrite) -> bool,
) -> bool {
    let mut rewritten = false;
    for rule in rules {
        if apply(rule) {
            rewritten = true;
            if cap.is_some() {
                cap.note(
                    "header-rewrite",
                    phase,
                    &rule.note(),
                    rule.module.as_deref(),
                );
            }
        }
    }
    rewritten
}

/// Read before the rules go to the rewrite, and only while capture is on.
fn body_notes(cap: &Cap, rules: &[Arc<BodyRewrite>]) -> Vec<(String, Option<Arc<str>>)> {
    if !cap.is_some() {
        return Vec::new();
    }
    rules
        .iter()
        .map(|rule| (rule.note(), rule.module.clone()))
        .collect()
}

fn note_body(cap: &Cap, phase: &str, notes: Vec<(String, Option<Arc<str>>)>) {
    for (detail, module) in notes {
        cap.note("body-rewrite", phase, &detail, module.as_deref());
    }
}

/// A body already buffered and rewritten in this phase, handed to a following script
/// so it reuses the same `Bytes` and accounts only for any growth past `reserved`.
pub(crate) struct PreBuffered {
    pub data: Bytes,
    pub trailers: Option<HeaderMap>,
    pub reserved: u64,
}

/// A body over the limit, not UTF-8, or in an encoding it cannot decode is
/// passed on unchanged.
pub(crate) async fn rewrite_body(
    headers: &mut HeaderMap,
    body: Body,
    length: Option<u64>,
    limit: i64,
    rules: Vec<Arc<BodyRewrite>>,
    keep_buffered: bool,
) -> io::Result<(Body, Option<u64>, Option<(Bytes, Option<HeaderMap>)>)> {
    match buffer_body(headers, body, length, limit).await? {
        Buffered::Rest { body, length } => Ok((body, length, None)),
        Buffered::Whole(data, trailers) => {
            let data = apply_off_runtime(data, rules, DEFAULT_SCRIPT_TIMEOUT).await;
            let length = data.len() as u64;
            let buffered = keep_buffered.then(|| (data.clone(), trailers.clone()));
            Ok((full_with(data, trailers), Some(length), buffered))
        }
    }
}

/// Rewrites run on the blocking pool, as a jq filter may run for long or never end. One that
/// outlives `budget` leaves the body as it came; its thread runs on until the filter returns.
pub(crate) async fn apply_off_runtime(
    data: Bytes,
    rules: Vec<Arc<BodyRewrite>>,
    budget: std::time::Duration,
) -> Bytes {
    let input = data.clone();
    let work = tokio::task::spawn_blocking(move || {
        let text = std::str::from_utf8(&input).ok()?;
        match rules
            .iter()
            .fold(Cow::Borrowed(text), |body, rule| rule.apply(body))
        {
            Cow::Borrowed(_) => None,
            Cow::Owned(out) => Some(out),
        }
    });
    match tokio::time::timeout(budget, work).await {
        Ok(Ok(Some(text))) => Bytes::from(text),
        Ok(Ok(None)) => data,
        Ok(Err(err)) => {
            tracing::warn!("[MITM] a body rewrite failed: {err}");
            data
        }
        Err(_) => {
            tracing::warn!(
                "[MITM] a body rewrite ran past {budget:?}, the body passes on as it came"
            );
            data
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_body_rewrite;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    fn rules(lines: &[&str]) -> Vec<Arc<BodyRewrite>> {
        lines
            .iter()
            .map(|line| Arc::new(parse_body_rewrite(line).unwrap()))
            .collect()
    }

    const SLOW: &str =
        r"http-response-jq ^http:// '.n = (reduce range(3000000) as $i (0; . + $i))'";

    #[tokio::test]
    async fn a_long_rewrite_leaves_the_runtime_free() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let ticker = tokio::spawn({
            let ticks = ticks.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        let started = Instant::now();
        let out = apply_off_runtime(
            Bytes::from_static(b"{}"),
            rules(&[SLOW]),
            Duration::from_secs(600),
        )
        .await;
        ticker.abort();
        assert_eq!(&out[..], br#"{"n":4499998500000}"#);
        assert!(
            ticks.load(Ordering::Relaxed) > 0,
            "the ticker on the same thread never ran in {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_rewrite_past_its_budget_keeps_the_body() {
        let out = apply_off_runtime(
            Bytes::from_static(b"{}"),
            rules(&[SLOW]),
            Duration::from_millis(1),
        )
        .await;
        assert_eq!(&out[..], b"{}");
        let out = apply_off_runtime(
            Bytes::from_static(b"{\"ad\":1}"),
            rules(&[
                r"http-response ^http:// ad noad",
                "http-response-jq ^http:// '.x = 1'",
            ]),
            Duration::from_secs(600),
        )
        .await;
        assert_eq!(&out[..], br#"{"noad":1,"x":1}"#);
        let raw = Bytes::from_static(&[0xff, 0xfe]);
        assert_eq!(
            apply_off_runtime(raw.clone(), rules(&[SLOW]), Duration::from_secs(600)).await,
            raw
        );
    }

    #[test]
    fn a_request_adapts_to_http1_and_http2() {
        let mut out = http::Request::new(empty());
        *out.method_mut() = http::Method::GET;
        adapt(&mut out, true, true, "example.test:8443", "/p?q=1").unwrap();
        assert_eq!(out.uri().to_string(), "https://example.test:8443/p?q=1");
        assert!(out.headers().get(HOST).is_none());
        adapt(&mut out, false, true, "example.test:8443", "/p?q=1").unwrap();
        assert_eq!(out.uri().to_string(), "/p?q=1");
        assert_eq!(out.headers().get(HOST).unwrap(), "example.test:8443");
        assert_eq!(out.version(), Version::HTTP_11);
    }

    #[tokio::test]
    async fn zero_hit_body_rewrite_reuses_input_bytes() {
        let input = Bytes::from("plain text without any token".repeat(64));
        let ptr = input.as_ptr();
        let out = apply_off_runtime(
            input.clone(),
            rules(&[
                r"http-response ^http:// never_matches replaced",
                "http-response-jq ^http:// '.x = 1'",
            ]),
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(out, input);
        assert_eq!(out.as_ptr(), ptr);

        let chained = apply_off_runtime(
            Bytes::from_static(b"alpha beta"),
            rules(&[
                r"http-response ^http:// missing hit",
                r"http-response ^http:// beta gamma",
                r"http-response ^http:// also_missing hit",
            ]),
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(&chained[..], b"alpha gamma");
    }
}
