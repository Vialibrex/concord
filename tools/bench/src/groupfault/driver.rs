//! The workload: an open-loop stream of requests, each on a fresh SOCKS5 connection with the site name sent
//! to the proxy (`socks5h`), a TLS handshake and one HTTP/1.1 request, at a fixed rate spread over the sites.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;

use super::net::{Node, SITES, site_name};
use super::record::{Clock, Event, Recorder};
use super::sites::HTTPS_PORT;

const STAGES: [&str; 4] = ["dial", "socks", "tls", "http"];

pub struct Load {
    pub proxy: SocketAddr,
    pub tls: Arc<rustls::ClientConfig>,
    pub timeout: Duration,
    pub nodes: Vec<Node>,
}

pub fn client_config(ca_pem: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    let ca = CertificateDer::from_pem_slice(ca_pem.as_bytes()).map_err(|e| e.to_string())?;
    roots.add(ca).map_err(|e| e.to_string())?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

struct Failure {
    stage: usize,
    class: String,
}

struct Reply {
    node: Option<usize>,
    ttfb: Duration,
}

fn io_class(err: &io::Error) -> &'static str {
    match err.kind() {
        io::ErrorKind::ConnectionReset => "reset",
        io::ErrorKind::ConnectionRefused => "refused",
        io::ErrorKind::UnexpectedEof => "eof",
        io::ErrorKind::BrokenPipe => "pipe",
        io::ErrorKind::TimedOut => "timed_out",
        io::ErrorKind::InvalidData => "invalid",
        _ => "io",
    }
}

async fn socks_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    let io = |e: io::Error| io_class(&e).to_string();
    stream.write_all(&[5, 1, 0]).await.map_err(io)?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.map_err(io)?;
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(io)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io)?;
    if head[1] != 0 {
        return Err(format!("reply_{}", head[1]));
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        _ => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io)?;
            usize::from(len[0]) + 2
        }
    };
    let mut tail = vec![0u8; rest];
    stream.read_exact(&mut tail).await.map_err(io)?;
    Ok(())
}

async fn fetch(load: &Load, site: usize, stage: &AtomicU8) -> Result<Reply, Failure> {
    let fail = |s: usize, class: String| Failure { stage: s, class };
    let host = site_name(site);
    let started = Instant::now();
    stage.store(0, Ordering::Relaxed);
    let mut stream = TcpStream::connect(load.proxy)
        .await
        .map_err(|e| fail(0, io_class(&e).into()))?;
    stage.store(1, Ordering::Relaxed);
    socks_connect(&mut stream, &host, HTTPS_PORT)
        .await
        .map_err(|c| fail(1, c))?;
    stage.store(2, Ordering::Relaxed);
    let name = ServerName::try_from(host.clone()).map_err(|e| fail(2, e.to_string()))?;
    let mut tls = TlsConnector::from(load.tls.clone())
        .connect(name, stream)
        .await
        .map_err(|e| fail(2, io_class(&e).into()))?;
    stage.store(3, Ordering::Relaxed);
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| fail(3, io_class(&e).into()))?;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut ttfb = None;
    loop {
        let n = tls
            .read(&mut chunk)
            .await
            .map_err(|e| fail(3, io_class(&e).into()))?;
        if n == 0 {
            break;
        }
        ttfb.get_or_insert_with(|| started.elapsed());
        seen.extend_from_slice(&chunk[..n]);
    }
    let text = String::from_utf8_lossy(&seen);
    let ok = text.starts_with("HTTP/1.1 200");
    let source = text
        .split("src=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next());
    match (ok, ttfb) {
        (true, Some(ttfb)) => Ok(Reply {
            node: load
                .nodes
                .iter()
                .find(|n| source.is_some_and(|s| s == n.egress.to_string()))
                .map(|n| n.index),
            ttfb,
        }),
        _ => Err(fail(3, "bad_response".into())),
    }
}

async fn one(load: Arc<Load>, site: usize, t: f64, phase: &'static str, events: Recorder) {
    let stage = AtomicU8::new(0);
    let started = Instant::now();
    let result = tokio::time::timeout(load.timeout, fetch(&load, site, &stage)).await;
    let total_ms = started.elapsed().as_secs_f64() * 1e3;
    let (ok, class, ttfb_ms, node) = match result {
        Ok(Ok(reply)) => (true, None, Some(reply.ttfb.as_secs_f64() * 1e3), reply.node),
        Ok(Err(f)) => (
            false,
            Some(format!("{}_{}", STAGES[f.stage], f.class)),
            None,
            None,
        ),
        Err(_) => {
            let at = usize::from(stage.load(Ordering::Relaxed)).min(STAGES.len() - 1);
            (false, Some(format!("timeout_{}", STAGES[at])), None, None)
        }
    };
    events.record(Event::Request {
        t,
        site,
        ok,
        class,
        total_ms,
        ttfb_ms,
        node,
        phase: phase.to_string(),
    });
}

/// Issues `rate` requests a second until `stop` is set, skipping the ticks while `paused`, then waits for
/// the ones still in flight.
pub async fn run(
    load: Arc<Load>,
    rate: f64,
    clock: Arc<Clock>,
    events: Recorder,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut flight = JoinSet::new();
    let mut next = 0usize;
    while !stop.load(Ordering::Relaxed) {
        tick.tick().await;
        if paused.load(Ordering::Relaxed) {
            continue;
        }
        let site = next % SITES + 1;
        next += 1;
        flight.spawn(one(
            load.clone(),
            site,
            clock.seconds(),
            clock.phase_name(),
            events.clone(),
        ));
        while flight.try_join_next().is_some() {}
    }
    while flight.join_next().await.is_some() {}
}
