use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

use crate::transparent::Transparent;

/// The kernel lowers it to its own limit (Linux and macOS `somaxconn`; Windows `SOMAXCONN`
/// asks the provider for its maximum), the limit Go reads for every listener.
const LISTEN_BACKLOG: i32 = i32::MAX;

/// Where a listener is asked to bind, before the port is resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BindHost {
    Wildcard,
    Ip(IpAddr),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BindKey {
    pub host: BindHost,
    pub port: u16,
    pub mptcp: bool,
    /// `SO_MARK` on the listening socket, a listener's `routing-mark`; zero sets none.
    pub mark: u32,
}

/// `listener.go`'s `genAddr`: loopback unless the LAN is allowed, and `*` is the
/// dual-stack wildcard.
pub(crate) fn resolve_host(allow_lan: bool, bind_address: &str) -> io::Result<BindHost> {
    if !allow_lan {
        return Ok(BindHost::Ip(Ipv4Addr::LOCALHOST.into()));
    }
    let host = bind_address.trim();
    match host {
        "*" | "" => Ok(BindHost::Wildcard),
        "localhost" => Ok(BindHost::Ip(Ipv4Addr::LOCALHOST.into())),
        _ => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map(BindHost::Ip)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid network address: {host}"),
                )
            }),
    }
}

fn candidates(host: BindHost, port: u16) -> Vec<SocketAddr> {
    match host {
        BindHost::Ip(ip) => vec![SocketAddr::new(ip, port)],
        BindHost::Wildcard => vec![
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port),
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
        ],
    }
}

/// A wildcard that cannot be bound as IPv6 falls back to IPv4; a taken port
/// does not, because the IPv4 attempt would only hide the conflict.
fn first_bound<T>(
    host: BindHost,
    port: u16,
    mut bind: impl FnMut(SocketAddr) -> io::Result<T>,
) -> io::Result<T> {
    let mut last = None;
    for addr in candidates(host, port) {
        match bind(addr) {
            Ok(bound) => return Ok(bound),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Err(err);
            }
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable)))
}

fn new_socket(
    addr: SocketAddr,
    ty: Type,
    protocol: Option<Protocol>,
    wildcard: bool,
    mark: u32,
) -> io::Result<Socket> {
    let domain = Domain::for_address(addr);
    let socket = match Socket::new(domain, ty, protocol) {
        Ok(socket) => socket,
        Err(_) if protocol.is_some() => Socket::new(domain, ty, None)?,
        Err(err) => return Err(err),
    };
    concord_platform::prepare_listener(&socket, addr.is_ipv6() && wildcard)?;
    if mark != 0 {
        concord_platform::set_routing_mark(&socket, mark)?;
    }
    Ok(socket)
}

pub(crate) fn bind_tcp(
    key: &BindKey,
    transparent: Option<&dyn Transparent>,
) -> io::Result<TcpListener> {
    let protocol = key
        .mptcp
        .then(concord_platform::mptcp_protocol)
        .flatten()
        .filter(|_| transparent.is_none());
    first_bound(key.host, key.port, |addr| {
        let wildcard = key.host == BindHost::Wildcard;
        let socket = new_socket(addr, Type::STREAM, protocol, wildcard, key.mark)?;
        if let Some(transparent) = transparent {
            transparent.make_transparent(&socket, addr.is_ipv6())?;
        }
        socket.bind(&SockAddr::from(addr))?;
        socket.listen(LISTEN_BACKLOG)?;
        socket.set_nonblocking(true)?;
        TcpListener::from_std(socket.into())
    })
}

/// Binds the address the TCP listener actually got, so the SOCKS5 reply that
/// names the TCP local address also names the UDP port.
pub(crate) fn bind_udp(
    tcp_local: SocketAddr,
    transparent: Option<&dyn Transparent>,
    mark: u32,
) -> io::Result<UdpSocket> {
    let wildcard = tcp_local.ip().is_unspecified();
    let socket = new_socket(tcp_local, Type::DGRAM, None, wildcard, mark)?;
    finish_udp(socket, tcp_local, transparent)
}

fn finish_udp(
    socket: Socket,
    tcp_local: SocketAddr,
    transparent: Option<&dyn Transparent>,
) -> io::Result<UdpSocket> {
    concord_platform::prepare_udp_socket(&socket)?;
    if let Some(transparent) = transparent {
        transparent.prepare_udp(&socket, tcp_local.is_ipv6())?;
    }
    socket.bind(&SockAddr::from(tcp_local))?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// A UDP port with no TCP port beside it, such as a UDP-only tunnel. No TCP port holds the
/// address, so SO_REUSEADDR stays off: on Linux it would let a second process share it.
pub(crate) fn bind_udp_alone(key: &BindKey) -> io::Result<UdpSocket> {
    first_bound(key.host, key.port, |addr| {
        let socket = new_socket(
            addr,
            Type::DGRAM,
            None,
            addr.ip().is_unspecified(),
            key.mark,
        )?;
        socket.set_reuse_address(false)?;
        finish_udp(socket, addr, None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_unless_the_lan_is_allowed() {
        assert_eq!(
            resolve_host(false, "0.0.0.0").unwrap(),
            BindHost::Ip(Ipv4Addr::LOCALHOST.into())
        );
        assert_eq!(resolve_host(true, "*").unwrap(), BindHost::Wildcard);
        assert_eq!(
            resolve_host(true, "[::1]").unwrap(),
            BindHost::Ip(Ipv6Addr::LOCALHOST.into())
        );
        assert_eq!(
            resolve_host(true, "localhost").unwrap(),
            BindHost::Ip(Ipv4Addr::LOCALHOST.into())
        );
    }

    #[test]
    fn a_hostname_is_not_an_address() {
        let err = resolve_host(true, "example.com").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn the_udp_socket_takes_the_tcp_port() {
        let key = BindKey {
            host: BindHost::Ip(Ipv4Addr::LOCALHOST.into()),
            port: 0,
            mptcp: false,
            mark: 0,
        };
        let tcp = bind_tcp(&key, None).unwrap();
        let local = tcp.local_addr().unwrap();
        let udp = bind_udp(local, None, 0).unwrap();
        assert_eq!(udp.local_addr().unwrap(), local);
    }

    /// Only Linux lets two unicast UDP sockets that set SO_REUSEADDR share a port; BSD
    /// refuses the second either way.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_udp_only_port_cannot_be_bound_twice() {
        let key = |port| BindKey {
            host: BindHost::Ip(Ipv4Addr::LOCALHOST.into()),
            port,
            mptcp: false,
            mark: 0,
        };
        let first = bind_udp_alone(&key(0)).unwrap();
        let port = first.local_addr().unwrap().port();
        assert!(bind_udp_alone(&key(port)).is_err());
    }

    #[tokio::test]
    async fn a_taken_port_is_reported_not_skipped() {
        let first = bind_tcp(
            &BindKey {
                host: BindHost::Ip(Ipv4Addr::LOCALHOST.into()),
                port: 0,
                mptcp: false,
                mark: 0,
            },
            None,
        )
        .unwrap();
        let port = first.local_addr().unwrap().port();
        let err = bind_tcp(
            &BindKey {
                host: BindHost::Ip(Ipv4Addr::LOCALHOST.into()),
                port,
                mptcp: false,
                mark: 0,
            },
            None,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }
}
