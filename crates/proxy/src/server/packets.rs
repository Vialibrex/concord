use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};

use concord_common::serve::InboundCx;
use concord_common::{
    Address, BoxStream, InboundInfo, PacketBuf, PacketSession, UdpFlow, UdpPayload, UdpReply,
};

use crate::dgram::{Decoded, Decoder, Encoder, StreamSession};

/// The datagrams a client sends over one stream, each handed on as a UDP flow whose
/// replies go back over the same stream. Ends when the stream does.
pub(super) async fn serve<E: Encoder, D: Decoder>(
    stream: BoxStream,
    encoder: E,
    decoder: D,
    remote: Address,
    inbound: InboundInfo,
    src: SocketAddr,
    cx: Arc<InboundCx>,
) {
    let session = Arc::new(StreamSession::new(
        stream, encoder, decoder, remote, &cx.tasks,
    ));
    serve_session(session, inbound.over_tcp(), src, cx).await;
}

/// The same for a protocol whose stream is already a packet session.
pub(super) async fn serve_session(
    session: Arc<dyn PacketSession>,
    inbound: InboundInfo,
    src: SocketAddr,
    cx: Arc<InboundCx>,
) {
    let reply: Arc<dyn UdpReply> = Arc::new(SessionReply {
        session: session.clone(),
    });
    let conn = concord_common::next_conn();
    loop {
        let mut packet = PacketBuf::take();
        let dst = match poll_fn(|poll| session.poll_recv(poll, &mut packet)).await {
            Ok(dst) => dst,
            Err(_) => break,
        };
        let flow = UdpFlow {
            inbound: &inbound,
            src,
            conn,
            dst,
            dscp: 0,
        };
        cx.handler
            .handle_udp(flow, UdpPayload::Owned(packet), &reply);
    }
    session.close();
}

struct SessionReply {
    session: Arc<dyn PacketSession>,
}

impl UdpReply for SessionReply {
    fn poll_write_back(
        &self,
        cx: &mut Context<'_>,
        payload: &[u8],
        from: &Address,
    ) -> Poll<io::Result<()>> {
        let mut packet = PacketBuf::with_headroom(self.session.headroom());
        packet.extend_from_slice(payload);
        self.session.poll_send(cx, &mut packet, from)
    }
}

/// `[2-byte length][payload]` to the destination the request named, as a VLESS UDP
/// request without packet addresses frames its datagrams.
pub(super) struct LengthFrames;

impl Encoder for LengthFrames {
    fn headroom(&self) -> usize {
        2
    }

    fn encode(&self, pkt: &mut PacketBuf, _dst: &Address) -> io::Result<()> {
        let len = u16::try_from(pkt.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too long"))?;
        pkt.prepend(2).copy_from_slice(&len.to_be_bytes());
        Ok(())
    }
}

impl Decoder for LengthFrames {
    fn decode(&mut self, input: &mut [u8]) -> io::Result<Decoded> {
        let Some(&[hi, lo]) = input.get(..2) else {
            return Ok(Decoded::NeedMore);
        };
        let len = usize::from(u16::from_be_bytes([hi, lo]));
        if input.len() < 2 + len {
            return Ok(Decoded::NeedMore);
        }
        Ok(Decoded::Packet {
            addr: None,
            payload: 2..2 + len,
            consumed: 2 + len,
        })
    }
}
