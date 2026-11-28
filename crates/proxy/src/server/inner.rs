//! A server's own flows, as mihomo's `inner.HandleTcp` (`listener/inner/tcp.go:21-40`).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use concord_common::serve::InboundCx;
use concord_common::{Address, BoxStream, FlowMeta, InboundInfo, InboundKind, Network, Special};

const PIPE: usize = 1 << 16;

pub(super) fn dial(
    cx: &InboundCx,
    dst: Address,
    proxy: Option<Arc<str>>,
    src: Option<SocketAddr>,
) -> BoxStream {
    let (near, far) = tokio::io::duplex(PIPE);
    let mut inbound = InboundInfo::new(InboundKind::Inner);
    inbound.special = proxy.map(|proxy| {
        Arc::new(Special {
            proxy: Some(proxy),
            rules: None,
        })
    });
    cx.handler.handle_tcp(
        FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound,
            src: src.unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
            dst,
        },
        Box::new(far),
    );
    Box::new(near)
}
