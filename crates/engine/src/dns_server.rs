use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use concord_common::{Initiator, Tasks};
use concord_dns::{Admission, Resolver, admit};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const STREAM_IDLE: Duration = Duration::from_secs(8);
const MAX_DATAGRAM: usize = 512;

/// `dns.listen`: the same answers the TUN hijack gives, for clients that ask directly.
pub(crate) struct DnsServer {
    address: String,
    mark: u32,
    resolver: Arc<ArcSwap<Resolver>>,
    stop: CancellationToken,
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn listen_address(address: &str) -> io::Result<SocketAddr> {
    let full = match address.strip_prefix(':') {
        Some(port) => format!("[::]:{port}"),
        None => address.to_string(),
    };
    if let Ok(addr) = full.parse() {
        return Ok(addr);
    }
    // A lookup here would go through getaddrinfo, ahead of the resolver being served.
    match full.rsplit_once(':') {
        Some(("localhost", port)) => port
            .parse()
            .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput)),
        _ => Err(io::Error::from(io::ErrorKind::InvalidInput)),
    }
}

fn bound_socket(addr: SocketAddr, ty: Type, protocol: Protocol, mark: u32) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), ty, Some(protocol))?;
    if mark != 0 {
        concord_platform::set_routing_mark(&socket, mark)?;
    }
    let wildcard = addr.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    concord_platform::prepare_listener(&socket, wildcard)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

impl DnsServer {
    pub fn start(
        address: &str,
        mark: u32,
        resolver: Arc<Resolver>,
        tasks: &Tasks,
    ) -> io::Result<Self> {
        let addr = listen_address(address)?;
        let _runtime = tasks.enter();
        let udp =
            UdpSocket::from_std(bound_socket(addr, Type::DGRAM, Protocol::UDP, mark)?.into())?;
        let stream = bound_socket(addr, Type::STREAM, Protocol::TCP, mark)?;
        stream.listen(128)?;
        let tcp = TcpListener::from_std(stream.into())?;

        let resolver = Arc::new(ArcSwap::new(resolver));
        let stop = CancellationToken::new();
        let tasks = tasks.with_stop(stop.clone());
        tasks.spawn(serve_udp(Arc::new(udp), resolver.clone(), tasks.clone()));
        tasks.spawn(serve_tcp(tcp, resolver.clone(), tasks.clone()));
        Ok(DnsServer {
            address: address.to_string(),
            mark,
            resolver,
            stop,
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn mark(&self) -> u32 {
        self.mark
    }

    pub fn set_resolver(&self, resolver: Arc<Resolver>) {
        self.resolver.store(resolver);
    }
}

/// Runs on `tasks`, whose stop is the server's, as are the answers it starts.
async fn serve_udp(socket: Arc<UdpSocket>, resolver: Arc<ArcSwap<Resolver>>, tasks: Tasks) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let received = socket.recv_from(&mut buf).await;
        let Ok((len, peer)) = received else {
            continue;
        };
        let Some(query) = buf.get(..len).map(<[u8]>::to_vec) else {
            continue;
        };
        let resolver = resolver.load_full();
        let socket = socket.clone();
        tasks.spawn(async move {
            let answer = match admit(&query) {
                Admission::Ignore => return,
                Admission::Reply(reply) => Some(reply),
                Admission::Accept => resolver.handle_query_udp(&query, Initiator::App).await,
            };
            if let Some(answer) = answer {
                let _ = socket.send_to(&answer, peer).await;
            }
        });
    }
}

async fn serve_tcp(listener: TcpListener, resolver: Arc<ArcSwap<Resolver>>, tasks: Tasks) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let resolver = resolver.clone();
                tasks.spawn(async move {
                    let _ = serve_stream(stream, &resolver).await;
                });
            }
            Err(err) => {
                tracing::debug!("[DNS] accept: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn serve_stream(mut stream: TcpStream, resolver: &ArcSwap<Resolver>) -> io::Result<()> {
    loop {
        let mut prefix = [0u8; 2];
        tokio::time::timeout(STREAM_IDLE, stream.read_exact(&mut prefix))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        tokio::time::timeout(STREAM_IDLE, stream.read_exact(&mut query))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)??;
        let answer = match admit(&query) {
            Admission::Ignore => continue,
            Admission::Reply(reply) => reply,
            Admission::Accept => resolver
                .load_full()
                .handle_query(&query, Initiator::App)
                .await
                .ok_or(io::ErrorKind::InvalidData)?,
        };
        let len = u16::try_from(answer.len()).map_err(|_| io::ErrorKind::InvalidData)?;
        let mut framed = Vec::with_capacity(answer.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&answer);
        stream.write_all(&framed).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_port_listens_on_every_address() {
        assert_eq!(
            listen_address(":1053").unwrap(),
            "[::]:1053".parse().unwrap()
        );
        assert_eq!(
            listen_address("127.0.0.1:53").unwrap(),
            "127.0.0.1:53".parse().unwrap()
        );
        assert!(listen_address("nonsense").is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn the_listen_routing_mark_is_set_on_the_socket() {
        let addr = "127.0.0.1:0".parse().unwrap();
        match bound_socket(addr, Type::DGRAM, Protocol::UDP, 0x1234) {
            Ok(socket) => assert_eq!(socket.mark().unwrap(), 0x1234),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::PermissionDenied),
        }
    }
}
