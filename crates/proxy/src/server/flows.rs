//! What a protocol server hands on once it has read a request, as mihomo's sing listener
//! handler takes it (`listener/sing/sing.go`): a few destinations name a carrier for
//! datagrams or streams rather than a host.

use std::sync::Arc;

use concord_common::serve::{InboundCx, Peer};
use concord_common::{Address, BoxStream, FlowMeta, InboundInfo, Network};
use tokio::io::AsyncReadExt;

use super::mux::{self, Mux};
use super::muxcool;
use super::packets::{self, LengthFrames};
use crate::addr_codec::{SOCKS, UOT};
use crate::uot::AddrFrames;

const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
const UOT_LEGACY_MAGIC: &str = "sp.udp-over-tcp.arpa";
const SING_MUX: &str = "sp.mux.sing-box.arpa";
const MUX_COOL: &str = "v1.mux.cool";
pub(super) const PACKET_ADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";

/// One request for `dst` over `stream`. What carries datagrams runs on `cx.tasks` for as
/// long as the stream lasts.
pub(super) fn tcp(
    stream: BoxStream,
    dst: Address,
    inbound: InboundInfo,
    peer: Peer,
    cx: &Arc<InboundCx>,
    mux: &Mux,
) {
    let host = match &dst {
        Address::Domain(host, _) => host.as_str(),
        Address::Socket(_) => "",
    };
    match host {
        MUX_COOL => {
            let session = muxcool::serve(stream, inbound, peer, cx.clone(), mux.nested());
            cx.tasks.spawn(session);
        }
        UOT_MAGIC => {
            cx.tasks.spawn(uot(stream, inbound, peer, cx.clone()));
        }
        UOT_LEGACY_MAGIC => {
            cx.tasks.spawn(packets::serve(
                stream,
                AddrFrames(UOT),
                AddrFrames(UOT),
                dst,
                inbound,
                peer.src,
                cx.clone(),
            ));
        }
        SING_MUX => {
            let session = mux::serve(stream, inbound, peer, cx.clone(), mux.clone());
            cx.tasks.spawn(session);
        }
        _ => cx.handler.handle_tcp(
            FlowMeta {
                network: Network::Tcp,
                inbound,
                src: peer.src,
                dst,
                dscp: 0,
            },
            stream,
        ),
    }
}

/// sing's UoT v2 request: whether the stream connects to one destination, then that
/// destination (`common/uot/protocol.go`).
async fn uot(mut stream: BoxStream, inbound: InboundInfo, peer: Peer, cx: Arc<InboundCx>) {
    let Ok(connect) = stream.read_u8().await else {
        return;
    };
    let Ok(dst) = SOCKS.read(&mut stream).await else {
        return;
    };
    if connect != 0 {
        packets::serve(
            stream,
            LengthFrames,
            LengthFrames,
            dst,
            inbound,
            peer.src,
            cx,
        )
        .await;
    } else {
        packets::serve(
            stream,
            AddrFrames(UOT),
            AddrFrames(UOT),
            dst,
            inbound,
            peer.src,
            cx,
        )
        .await;
    }
}

/// A UDP request: datagrams to `dst`, or to the address of each when `dst` is the
/// packet-address magic name.
pub(super) fn udp(
    stream: BoxStream,
    dst: Address,
    inbound: InboundInfo,
    peer: Peer,
    cx: &Arc<InboundCx>,
) {
    let packet_addr =
        matches!(&dst, Address::Domain(host, _) if host.as_str() == PACKET_ADDR_MAGIC);
    if packet_addr {
        cx.tasks.spawn(packets::serve(
            stream,
            crate::vless::PacketAddrFrames,
            crate::vless::PacketAddrFrames,
            dst,
            inbound,
            peer.src,
            cx.clone(),
        ));
    } else {
        cx.tasks.spawn(packets::serve(
            stream,
            LengthFrames,
            LengthFrames,
            dst,
            inbound,
            peer.src,
            cx.clone(),
        ));
    }
}
