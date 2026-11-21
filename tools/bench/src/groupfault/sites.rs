//! The origin: eight HTTPS sites, each on an address of its own, whose body names the source address the
//! request came from, plus a plain HTTP endpoint for the group's health checks and an echo for readiness.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener as StdListener};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::net::{INFRA, SITES, Topology, site_ip};
use super::record::{Clock, Event, Recorder};
use crate::isolate;

pub const ECHO_PORT: u16 = 7;
pub const HEALTH_PORT: u16 = 80;
pub const HTTPS_PORT: u16 = 443;

fn bind(address: SocketAddr) -> Result<StdListener, String> {
    let listener = StdListener::bind(address).map_err(|e| format!("bind {address}: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(listener)
}

/// Binds in the origin namespace, so every accepted socket belongs to it, and serves from the caller's runtime.
pub fn serve(
    topo: &Topology,
    tls: Arc<rustls::ServerConfig>,
    clock: Arc<Clock>,
    events: Recorder,
) -> Result<Vec<JoinHandle<()>>, String> {
    let bound = isolate::in_netns(&topo.origin, || -> Result<_, String> {
        let sites = (1..=SITES)
            .map(|s| bind(SocketAddr::new(site_ip(s).into(), HTTPS_PORT)))
            .collect::<Result<Vec<_>, _>>()?;
        let health = bind(SocketAddr::new(INFRA.into(), HEALTH_PORT))?;
        let echo = bind(SocketAddr::new(INFRA.into(), ECHO_PORT))?;
        Ok((sites, health, echo))
    })
    .ok_or("could not enter the origin namespace")??;
    let (sites, health, echo) = bound;
    let mut tasks = Vec::new();
    for (i, listener) in sites.into_iter().enumerate() {
        let tls = tls.clone();
        tasks.push(tokio::spawn(accept(listener, move |stream, peer| {
            let tls = tls.clone();
            async move { https(stream, peer, tls, i + 1).await }
        })));
    }
    tasks.push(tokio::spawn(accept(health, move |stream, peer| {
        let (clock, events) = (clock.clone(), events.clone());
        async move { health_check(stream, peer, &clock, &events).await }
    })));
    tasks.push(tokio::spawn(accept(echo, |stream, _| async move {
        echo_flow(stream).await
    })));
    Ok(tasks)
}

async fn accept<F, Fut>(listener: StdListener, flow: F)
where
    F: Fn(TcpStream, IpAddr) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = io::Result<()>> + Send + 'static,
{
    let Ok(listener) = TcpListener::from_std(listener) else {
        return;
    };
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            continue;
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(flow(stream, peer.ip()));
    }
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> io::Result<()> {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        seen.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

async fn https(
    stream: TcpStream,
    peer: IpAddr,
    tls: Arc<rustls::ServerConfig>,
    site: usize,
) -> io::Result<()> {
    let mut tls = tokio_rustls::TlsAcceptor::from(tls).accept(stream).await?;
    read_head(&mut tls).await?;
    let body = format!("src={peer} site={site}\n");
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(head.as_bytes()).await?;
    tls.shutdown().await
}

async fn health_check(
    mut stream: TcpStream,
    peer: IpAddr,
    clock: &Clock,
    events: &Recorder,
) -> io::Result<()> {
    events.record(Event::Probe {
        t: clock.seconds(),
        src: peer.to_string(),
        phase: clock.phase_name().into(),
    });
    read_head(&mut stream).await?;
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await
}

async fn echo_flow(mut stream: TcpStream) -> io::Result<()> {
    let mut buf = [0u8; 64];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        stream.write_all(&buf[..n]).await?;
    }
}

pub fn health_url() -> String {
    format!("http://{INFRA}/")
}

pub fn echo_target() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(INFRA), ECHO_PORT)
}
