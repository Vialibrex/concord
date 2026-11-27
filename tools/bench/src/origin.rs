//! The far end, in its own process so its CPU is neither the harness's nor the
//! core's. It exits when its standard input closes, so it never outlives the harness.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::mitm;

pub const CHUNK: usize = 64 * 1024;
pub const REPORT_EVERY: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Ports {
    pub source: u16,
    pub sink: u16,
    pub echo: u16,
    pub crr: u16,
    pub udp: u16,
    pub https: u16,
    pub http: u16,
}

impl Ports {
    pub fn from_base(base: u16) -> Ports {
        Ports {
            source: base,
            sink: base + 1,
            echo: base + 2,
            crr: base + 3,
            udp: base + 4,
            https: base + 5,
            http: base + 6,
        }
    }
}

pub async fn serve(bind: IpAddr, base: Option<u16>, rate_mbit: Option<f64>) -> std::io::Result<()> {
    let port = |offset: u16| base.map_or(0, |b| b + offset);
    let source = TcpListener::bind((bind, port(0))).await?;
    let sink = TcpListener::bind((bind, port(1))).await?;
    let echo = TcpListener::bind((bind, port(2))).await?;
    let crr = TcpListener::bind((bind, port(3))).await?;
    let udp = UdpSocket::bind((bind, port(4))).await?;
    let https = TcpListener::bind((bind, port(5))).await?;
    let http = TcpListener::bind((bind, port(6))).await?;
    let _ = socket2::SockRef::from(&udp).set_recv_buffer_size(8 << 20);
    let _ = socket2::SockRef::from(&udp).set_send_buffer_size(8 << 20);
    let ports = Ports {
        source: source.local_addr()?.port(),
        sink: sink.local_addr()?.port(),
        echo: echo.local_addr()?.port(),
        crr: crr.local_addr()?.port(),
        udp: udp.local_addr()?.port(),
        https: https.local_addr()?.port(),
        http: http.local_addr()?.port(),
    };
    let (authority, tls) = mitm::authority().map_err(std::io::Error::other)?;
    for line in [
        serde_json::to_string(&ports),
        serde_json::to_string(&authority),
    ] {
        println!("{}", line.map_err(std::io::Error::other)?);
    }

    tokio::spawn(accept(source, move |s| async move {
        source_flow(s, rate_mbit).await
    }));
    tokio::spawn(accept(sink, |s| async move { sink_flow(s).await }));
    tokio::spawn(accept(echo, |s| async move { echo_flow(s).await }));
    tokio::spawn(accept(crr, |s| async move { crr_flow(s).await }));
    tokio::spawn(udp_echo(udp));
    tokio::spawn(accept(https, move |s| mitm::serve_https(s, tls.clone())));
    tokio::spawn(accept(http, |s| mitm::serve_http(s, false)));

    let mut stdin = tokio::io::stdin();
    let mut buf = [0u8; 64];
    while stdin.read(&mut buf).await.is_ok_and(|n| n > 0) {}
    Ok(())
}

async fn accept<F, Fut>(listener: TcpListener, flow: F)
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
{
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(flow(stream));
    }
}

async fn source_flow(mut stream: TcpStream, rate_mbit: Option<f64>) -> std::io::Result<()> {
    crate::pace::send_chunks(&mut stream, 0x5a, rate_mbit).await
}

/// Reports the running total so the uploader learns the receiver's rate, not its own buffers'.
async fn sink_flow(stream: TcpStream) -> std::io::Result<()> {
    let (mut read, mut write) = stream.into_split();
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    let mut tick = tokio::time::interval(REPORT_EVERY);
    loop {
        tokio::select! {
            read = read.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    write.write_all(&total.to_le_bytes()).await?;
                    return Ok(());
                }
                total += n as u64;
            }
            _ = tick.tick() => write.write_all(&total.to_le_bytes()).await?,
        }
    }
}

async fn echo_flow(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        stream.write_all(&buf[..n]).await?;
    }
}

/// One byte back, then the origin closes first, so TIME_WAIT lands on its
/// listening port and not on the proxies' ephemeral ones.
async fn crr_flow(mut stream: TcpStream) -> std::io::Result<()> {
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await?;
    stream.write_all(&byte).await?;
    Ok(())
}

async fn udp_echo(socket: UdpSocket) {
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok((n, peer)): std::io::Result<(usize, SocketAddr)> = socket.recv_from(&mut buf).await
        else {
            continue;
        };
        let _ = socket.send_to(&buf[..n], peer).await;
    }
}
