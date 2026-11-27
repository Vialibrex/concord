use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    Address, BoxRead, BoxStream, BoxWrite, DialCx, Outbound, OutboundInfo, OutboundKind, PacketBuf,
    PacketSession, Stream,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

const DROP_TIME: Duration = Duration::from_secs(60);

pub(crate) struct Reject {
    info: OutboundInfo,
    drop: bool,
}

impl Reject {
    pub(crate) fn new(name: &str, kind: OutboundKind) -> Self {
        Reject {
            info: crate::direct::info(name, kind),
            drop: kind == OutboundKind::RejectDrop,
        }
    }
}

#[async_trait]
impl Outbound for Reject {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, _cx: &DialCx<'_>, _dst: &Address) -> io::Result<BoxStream> {
        Ok(Box::new(Closed {
            delay: self
                .drop
                .then(|| Box::pin(sleep_until(Instant::now() + DROP_TIME))),
        }))
    }

    async fn associate(
        &self,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Ok(Arc::new(Blackhole))
    }

    async fn resolve_udp(&self, _cx: &DialCx<'_>, _host: &str) -> Option<io::Result<IpAddr>> {
        Some(Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
    }
}

/// Reads end at once, and for `REJECT-DROP` only after `DROP_TIME`, so the client sees a hang.
struct Closed {
    delay: Option<Pin<Box<Sleep>>>,
}

impl AsyncRead for Closed {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut().delay.as_mut() {
            Some(delay) => delay.as_mut().poll(cx).map(|()| Ok(())),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl AsyncWrite for Closed {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for Closed {
    concord_common::stream_policy!(own: into_split;
        default: read_requirements, write_requirements, poll_read_buffer, poll_write_buffer, tcp, peer_addr, needs_handshake, direct, into_tcp);

    fn into_split(self: Box<Self>) -> (BoxRead, BoxWrite) {
        (Box::new(*self), Box::new(Closed { delay: None }))
    }
}

struct Blackhole;

impl PacketSession for Blackhole {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        _pkt: &mut PacketBuf,
        _dst: &Address,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_recv(&self, _cx: &mut Context<'_>, _buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }
}

#[cfg(test)]
mod tests {
    use concord_common::{Initiator, send_packet};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::testing::test_env;

    #[tokio::test]
    async fn reject_reads_eof_and_refuses_writes() {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let reject = Reject::new("REJECT", OutboundKind::Reject);
        let mut stream = reject
            .connect(&cx, &Address::new("a.test", 80))
            .await
            .unwrap();
        assert!(stream.write_all(b"x").await.is_err());
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn reject_halves_read_eof_and_refuse_writes() {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let reject = Reject::new("REJECT", OutboundKind::Reject);
        let stream = reject
            .connect(&cx, &Address::new("a.test", 80))
            .await
            .unwrap();
        let (mut read, mut write) = stream.into_split();
        assert!(write.write_all(b"x").await.is_err());
        assert!(write.shutdown().await.is_ok());
        let mut buf = [0u8; 1];
        assert_eq!(read.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn reject_drop_hangs_before_it_ends() {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let drop = Reject::new("REJECT-DROP", OutboundKind::RejectDrop);
        let mut stream = drop
            .connect(&cx, &Address::new("a.test", 80))
            .await
            .unwrap();
        let mut buf = [0u8; 1];
        let early = tokio::time::timeout(Duration::from_secs(30), stream.read(&mut buf)).await;
        assert!(early.is_err());
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn reject_resolves_udp_names_without_a_lookup() {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        for kind in [
            OutboundKind::Reject,
            OutboundKind::RejectDrop,
            OutboundKind::PassRule,
        ] {
            let reject = Reject::new("R", kind);
            let ip = reject.resolve_udp(&cx, "a.test").await.unwrap().unwrap();
            assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        }
    }

    #[tokio::test]
    async fn reject_udp_swallows_packets() {
        let env = test_env();
        let cx = DialCx::new(&env, Initiator::Other, None);
        let reject = Reject::new("REJECT", OutboundKind::Reject);
        let session = reject
            .associate(&cx, &Address::new("a.test", 53))
            .await
            .unwrap();
        let mut packet = PacketBuf::from_slice(b"hello");
        send_packet(session.as_ref(), &mut packet, &Address::new("a.test", 53))
            .await
            .unwrap();
        assert!(concord_common::recv_packet(session.as_ref()).await.is_err());
    }
}
