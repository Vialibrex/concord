use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use concord_common::addr::unmap;
use concord_common::{BoxRead, BoxStream, BoxWrite, CoreError, OwnedTcp, Stream};
use dashmap::{DashMap, DashSet};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpStream, UdpSocket};

/// Remembers the local and peer address of every DIRECT socket so a flow that comes
/// back into the core with one of them as its source, having arrived at the socket's
/// peer, is recognised as the core's own traffic. Disabled it records and refuses
/// nothing, which is what Android wants.
pub struct LoopbackGuard {
    enabled: bool,
    tcp: DashMap<SocketAddr, Vec<Option<SocketAddr>>>,
    udp_ports: DashSet<u16>,
}

impl LoopbackGuard {
    pub fn new(enabled: bool) -> Arc<Self> {
        Arc::new(LoopbackGuard {
            enabled,
            tcp: DashMap::new(),
            udp_ports: DashSet::new(),
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Pass an inbound flow's source and the address it arrived at. Linux hands two sockets
    /// the same local port when their peers differ, so the source alone would refuse an
    /// unrelated client. Without an arrival address the source alone decides.
    pub fn check_flow(&self, src: SocketAddr, arrived_at: Option<SocketAddr>) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let src = unmapped(src);
        let arrived_at = arrived_at.map(unmapped);
        let own = self.tcp.get(&src).is_some_and(|peers| {
            peers
                .iter()
                .any(|peer| peer.is_none_or(|peer| arrived_at.is_none_or(|at| at == peer)))
        });
        if own {
            return Err(CoreError::Loopback(src.to_string()).into());
        }
        Ok(())
    }

    /// Only a source on this machine can be the core's own socket, so a remote
    /// client that happens to use the same port is not refused.
    pub fn check_udp_source(
        &self,
        src: SocketAddr,
        is_local_ip: impl FnOnce(IpAddr) -> bool,
    ) -> io::Result<()> {
        let ip = unmap(src.ip());
        let local = ip.is_loopback() || ip.is_unspecified() || is_local_ip(ip);
        if self.enabled && local && self.udp_ports.contains(&src.port()) {
            return Err(CoreError::Loopback(src.to_string()).into());
        }
        Ok(())
    }

    pub fn track_tcp(self: &Arc<Self>, stream: TcpStream) -> TrackedTcp {
        let key = stream
            .local_addr()
            .ok()
            .map(|local| (unmapped(local), stream.peer_addr().ok().map(unmapped)))
            .filter(|_| self.enabled);
        if let Some((local, peer)) = key {
            self.tcp.entry(local).or_default().push(peer);
        }
        TrackedTcp {
            registered: key.map(|(local, peer)| Held {
                guard: Arc::clone(self),
                local,
                peer,
            }),
            inner: stream,
        }
    }

    pub fn track_udp(self: &Arc<Self>, socket: &UdpSocket) -> UdpTicket {
        let port = socket
            .local_addr()
            .ok()
            .map(|addr| addr.port())
            .filter(|_| self.enabled);
        if let Some(port) = port {
            self.udp_ports.insert(port);
        }
        UdpTicket {
            registered: port.map(|port| (Arc::clone(self), port)),
        }
    }
}

fn unmapped(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(unmap(addr.ip()), addr.port())
}

/// A DIRECT TCP socket whose local address leaves the table when it is dropped.
pub struct TrackedTcp {
    registered: Option<Held>,
    inner: TcpStream,
}

struct Held {
    guard: Arc<LoopbackGuard>,
    local: SocketAddr,
    peer: Option<SocketAddr>,
}

impl Drop for Held {
    fn drop(&mut self) {
        let peer = self.peer;
        self.guard.tcp.remove_if_mut(&self.local, |_, peers| {
            if let Some(at) = peers.iter().position(|held| *held == peer) {
                peers.swap_remove(at);
            }
            peers.is_empty()
        });
    }
}

impl AsyncRead for TrackedTcp {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrackedTcp {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl Stream for TrackedTcp {
    concord_common::stream_policy!(inner;
        forward: poll_read_buffer, peer_addr;
        own: into_split, tcp, into_tcp;
        default: read_requirements, write_requirements, poll_write_buffer, needs_handshake, direct);

    fn tcp(&self) -> Option<&TcpStream> {
        Some(&self.inner)
    }

    fn into_tcp(self: Box<Self>) -> Result<OwnedTcp, BoxStream> {
        let TrackedTcp { inner, registered } = *self;
        Ok(OwnedTcp::new(
            inner,
            registered.map(|ticket| Arc::new(ticket) as Arc<dyn Send + Sync>),
        ))
    }

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        let TrackedTcp { registered, inner } = *self;
        let (read, write) = inner.into_split();
        let held = registered.map(Arc::new);
        (
            Box::new(TrackedRead {
                _held: held.clone(),
                inner: read,
            }),
            Box::new(TrackedWrite {
                _held: held,
                inner: write,
            }),
        )
    }
}

struct TrackedRead {
    _held: Option<Arc<Held>>,
    inner: OwnedReadHalf,
}

impl AsyncRead for TrackedRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

struct TrackedWrite {
    _held: Option<Arc<Held>>,
    inner: OwnedWriteHalf,
}

impl AsyncWrite for TrackedWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Keeps a DIRECT UDP socket's port in the table for as long as it is held.
pub struct UdpTicket {
    registered: Option<(Arc<LoopbackGuard>, u16)>,
}

impl Drop for UdpTicket {
    fn drop(&mut self) {
        if let Some((guard, port)) = self.registered.take() {
            guard.udp_ports.remove(&port);
        }
    }
}

#[cfg(test)]
mod tests {
    use concord_common::CoreError;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::test_support::{loopback_pair, loopback_udp};

    #[tokio::test]
    async fn a_flow_from_a_tracked_socket_that_arrived_at_its_peer_is_refused_until_it_is_dropped()
    {
        let guard = LoopbackGuard::new(true);
        let (client, server) = loopback_pair().await;
        let local = client.local_addr().unwrap();
        let peer = client.peer_addr().unwrap();
        let tracked = guard.track_tcp(client);

        let err = guard.check_flow(local, Some(peer)).unwrap_err();
        assert!(matches!(CoreError::of(&err), Some(CoreError::Loopback(_))));
        assert!(
            guard
                .check_flow("127.0.0.1:1".parse().unwrap(), Some(peer))
                .is_ok()
        );

        drop(tracked);
        assert!(guard.check_flow(local, Some(peer)).is_ok());
        assert!(guard.tcp.is_empty());
        drop(server);
    }

    #[tokio::test]
    async fn a_transferred_ticket_holds_the_address_after_the_stream_is_dropped() {
        let guard = LoopbackGuard::new(true);
        let (client, _server) = loopback_pair().await;
        let local = client.local_addr().unwrap();
        let peer = client.peer_addr().unwrap();
        let mut tracked = guard.track_tcp(client);
        let ticket = tracked.registered.take().unwrap();

        drop(tracked);
        assert!(guard.check_flow(local, Some(peer)).is_err());
        drop(ticket);
        assert!(guard.check_flow(local, Some(peer)).is_ok());
        assert!(guard.tcp.is_empty());
    }

    #[tokio::test]
    async fn the_same_source_that_arrived_elsewhere_is_not_the_core() {
        let guard = LoopbackGuard::new(true);
        let (client, _server) = loopback_pair().await;
        let local = client.local_addr().unwrap();
        let peer = client.peer_addr().unwrap();
        let _tracked = guard.track_tcp(client);

        let elsewhere: SocketAddr = "127.0.0.1:7890".parse().unwrap();
        assert_ne!(peer, elsewhere);
        assert!(guard.check_flow(local, Some(elsewhere)).is_ok());
        assert!(guard.check_flow(local, Some(peer)).is_err());
    }

    #[tokio::test]
    async fn a_flow_without_an_arrival_address_is_judged_by_its_source() {
        let guard = LoopbackGuard::new(true);
        let (client, _server) = loopback_pair().await;
        let local = client.local_addr().unwrap();
        let _tracked = guard.track_tcp(client);
        assert!(guard.check_flow(local, None).is_err());
    }

    #[tokio::test]
    async fn sockets_sharing_a_local_address_are_released_one_at_a_time() {
        let guard = LoopbackGuard::new(true);
        let local: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let first: SocketAddr = "198.51.100.1:80".parse().unwrap();
        let second: SocketAddr = "198.51.100.2:80".parse().unwrap();
        let held = |peer| {
            guard.tcp.entry(local).or_default().push(Some(peer));
            Held {
                guard: Arc::clone(&guard),
                local,
                peer: Some(peer),
            }
        };
        let (client, _server) = loopback_pair().await;
        let one = TrackedTcp {
            inner: client,
            registered: Some(held(first)),
        };
        let (client, _server) = loopback_pair().await;
        let two = TrackedTcp {
            inner: client,
            registered: Some(held(second)),
        };

        assert!(guard.check_flow(local, Some(first)).is_err());
        assert!(guard.check_flow(local, Some(second)).is_err());
        assert!(
            guard
                .check_flow(local, Some("203.0.113.1:80".parse().unwrap()))
                .is_ok()
        );

        drop(one);
        assert!(guard.check_flow(local, Some(first)).is_ok());
        assert!(guard.check_flow(local, Some(second)).is_err());
        drop(two);
        assert!(guard.tcp.is_empty());
    }

    #[tokio::test]
    async fn a_disabled_guard_records_nothing() {
        let guard = LoopbackGuard::new(false);
        let (client, _server) = loopback_pair().await;
        let local = client.local_addr().unwrap();
        let peer = client.peer_addr().unwrap();
        let _tracked = guard.track_tcp(client);
        assert!(guard.tcp.is_empty());
        assert!(guard.check_flow(local, Some(peer)).is_ok());
    }

    #[tokio::test]
    async fn the_wrapper_still_carries_bytes() {
        let guard = LoopbackGuard::new(true);
        let (client, mut server) = loopback_pair().await;
        let mut tracked = guard.track_tcp(client);
        tracked.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        assert!(tracked.tcp().is_some());
    }

    #[tokio::test]
    async fn the_registration_lasts_until_the_last_half_drops() {
        let guard = LoopbackGuard::new(true);
        let (client, mut server) = loopback_pair().await;
        let local = client.local_addr().unwrap();
        let peer = client.peer_addr().unwrap();
        let stream: concord_common::BoxStream = Box::new(guard.track_tcp(client));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            (got, read)
        });
        server.write_all(b"down").await.unwrap();
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        let mut sent = [0u8; 2];
        server.read_exact(&mut sent).await.unwrap();
        assert_eq!(&sent, b"up");
        server.shutdown().await.unwrap();
        let (got, read) = reader.await.unwrap();
        assert_eq!(got, b"down");
        drop(write);
        assert!(guard.check_flow(local, Some(peer)).is_err());
        drop(read);
        assert!(guard.check_flow(local, Some(peer)).is_ok());
        assert!(guard.tcp.is_empty());
    }

    #[tokio::test]
    async fn udp_ports_are_refused_only_for_local_sources() {
        let guard = LoopbackGuard::new(true);
        let socket = loopback_udp().await;
        let port = socket.local_addr().unwrap().port();
        let ticket = guard.track_udp(&socket);

        let local: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert!(guard.check_udp_source(local, |_| false).is_err());
        let lan: SocketAddr = format!("192.168.1.9:{port}").parse().unwrap();
        assert!(guard.check_udp_source(lan, |_| false).is_ok());
        assert!(guard.check_udp_source(lan, |ip| ip == lan.ip()).is_err());

        drop(ticket);
        assert!(guard.check_udp_source(local, |_| true).is_ok());
    }
}
