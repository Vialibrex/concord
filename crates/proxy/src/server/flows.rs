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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use concord_common::sync::lock;
    use concord_common::{FlowHandler, InboundKind, Tasks, UdpFlow, UdpPayload, UdpReply};
    use concord_config::listener::MuxServer;
    use concord_transport::{MuxDialFn, MuxProtocol, SingMuxClient, SingMuxOptions};
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Notify;

    use super::*;
    use crate::server::mux::MuxServe;

    #[derive(Default)]
    struct SeenUdp {
        flows: Mutex<Vec<(InboundKind, bool, Address)>>,
        arrived: Notify,
    }

    impl SeenUdp {
        async fn wait_for(&self, count: usize) -> Vec<(InboundKind, bool, Address)> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let notified = self.arrived.notified();
                {
                    let flows = lock(&self.flows);
                    if flows.len() >= count {
                        return flows.clone();
                    }
                }
                tokio::time::timeout_at(deadline, notified)
                    .await
                    .expect("expected UDP flow did not arrive");
            }
        }
    }

    impl FlowHandler for SeenUdp {
        fn handle_tcp(&self, _meta: FlowMeta, _stream: BoxStream) {}

        fn handle_udp(
            &self,
            flow: UdpFlow<'_>,
            _payload: UdpPayload<'_>,
            _reply: &Arc<dyn UdpReply>,
        ) {
            lock(&self.flows).push((flow.inbound.kind, flow.inbound.tcp_carried, flow.dst));
            self.arrived.notify_waiters();
        }
    }

    #[tokio::test]
    async fn ss_uot_and_mux_mark_udp_flows_as_tcp_carried() {
        let peer = Peer {
            src: "127.0.0.1:41234".parse().unwrap(),
            local: "127.0.0.1:8388".parse().unwrap(),
        };
        let target = Address::Socket("1.1.1.1:53".parse().unwrap());
        let mux_serve = MuxServe::new(&MuxServer::default());

        let seen = Arc::new(SeenUdp::default());
        let cx = Arc::new(InboundCx {
            name: "ss".into(),
            special: None,
            handler: seen.clone(),
            tasks: Tasks::default(),
        });

        let (mut uot_v2, far) = tokio::io::duplex(4096);
        let inbound = cx.inbound(InboundKind::Shadowsocks, peer.local, None);
        tcp(
            Box::new(far),
            Address::new(UOT_MAGIC, 0),
            inbound,
            peer,
            &cx,
            &Mux::new(&mux_serve),
        );
        let mut head = vec![1u8];
        head.resize(1 + SOCKS.len(&target), 0);
        SOCKS.write_into(&target, &mut head[1..]).unwrap();
        head.extend_from_slice(&[0, 2, b'o', b'k']);
        uot_v2.write_all(&head).await.unwrap();

        let (mut uot_legacy, far) = tokio::io::duplex(4096);
        let inbound = cx.inbound(InboundKind::Shadowsocks, peer.local, None);
        tcp(
            Box::new(far),
            Address::new(UOT_LEGACY_MAGIC, 0),
            inbound,
            peer,
            &cx,
            &Mux::new(&mux_serve),
        );
        let mut frame = vec![0u8; UOT.len(&target)];
        UOT.write_into(&target, &mut frame).unwrap();
        frame.extend_from_slice(&[0, 2, b'h', b'i']);
        uot_legacy.write_all(&frame).await.unwrap();

        let mux_cx = cx.clone();
        let mux_for_dial = mux_serve.clone();
        let dial: MuxDialFn = Arc::new(move |_| {
            let (near, far) = tokio::io::duplex(1 << 16);
            let inbound = mux_cx.inbound(InboundKind::Shadowsocks, peer.local, None);
            tcp(
                Box::new(far),
                Address::new(SING_MUX, 0),
                inbound,
                peer,
                &mux_cx,
                &Mux::new(&mux_for_dial),
            );
            Box::pin(async move { Ok(Box::new(near) as BoxStream) })
        });
        let smux = SingMuxClient::new(
            SingMuxOptions {
                protocol: MuxProtocol::Smux,
                padding: false,
                max_connections: 1,
                ..SingMuxOptions::default()
            },
            dial,
            Tasks::default(),
        );
        let mut smux_udp = smux.connect_udp(&target).await.unwrap();
        smux_udp.write_all(&[0, 1, b'x']).await.unwrap();

        let got = seen.wait_for(3).await;
        assert_eq!(got.len(), 3);
        for (kind, tcp_carried, dst) in got {
            assert_eq!(kind, InboundKind::Shadowsocks);
            assert!(tcp_carried);
            assert_eq!(dst, target);
        }
    }
}
