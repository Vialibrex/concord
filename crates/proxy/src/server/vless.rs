use std::collections::HashMap;
use std::sync::Arc;

use concord_common::serve::{InboundCx, Peer, ServeFuture};
use concord_common::{Address, BoxStream, InboundKind};
use concord_config::listener::VlessUser;
use tokio::io::{AsyncReadExt, BufReader};

use super::front::Conn;
use super::mux::{Mux, MuxServe};
use super::{bounded, flows, unread, user};
use crate::addr_codec::VMESS;
use crate::lazy::HeadFirst;
use crate::vless::{CMD_MUX, CMD_TCP, CMD_UDP};
use crate::vmess::crypto::user_id;

const VERSION: u8 = 0;
/// The response header: the version and no addons, sent with the first reply bytes.
const RESPONSE: [u8; 2] = [VERSION, 0];

/// mihomo's VLESS service (`listener/sing_vless/service.go`) without a flow.
pub(super) struct Vless {
    users: HashMap<[u8; 16], Option<Arc<str>>>,
    mux: Arc<MuxServe>,
}

impl Vless {
    pub(super) fn new(users: &[VlessUser]) -> Self {
        Vless {
            users: users
                .iter()
                .map(|entry| (user_id(&entry.uuid), user(&entry.username)))
                .collect(),
            mux: Arc::default(),
        }
    }

    /// The listener's `mux-option`; without it, sing-mux sessions neither pad nor run Brutal.
    pub(super) fn with_mux(mut self, mux: Arc<MuxServe>) -> Self {
        self.mux = mux;
        self
    }
}

struct Request {
    user: Option<Arc<str>>,
    command: u8,
    dst: Address,
}

impl Vless {
    async fn request(&self, buffered: &mut BufReader<BoxStream>) -> Option<Request> {
        if buffered.read_u8().await.ok()? != VERSION {
            return None;
        }
        let mut id = [0u8; 16];
        buffered.read_exact(&mut id).await.ok()?;
        let addons = usize::from(buffered.read_u8().await.ok()?);
        let mut flow = vec![0u8; addons];
        buffered.read_exact(&mut flow).await.ok()?;
        if !addon_flow(&flow).is_empty() {
            return None;
        }
        let command = buffered.read_u8().await.ok()?;
        let dst = if command == CMD_MUX {
            Address::new("v1.mux.cool", 0)
        } else {
            VMESS.read(buffered).await.ok()?
        };
        let user = self.users.get(&id)?.clone();
        Some(Request { user, command, dst })
    }
}

/// The `flow` of the request's addons, protobuf field 1; any other field is skipped.
fn addon_flow(mut addons: &[u8]) -> &[u8] {
    while let [tag, rest @ ..] = addons {
        let Some((&len, rest)) = rest.split_first() else {
            return &[];
        };
        let len = usize::from(len);
        let Some((value, rest)) = rest.split_at_checked(len) else {
            return &[];
        };
        if *tag == 0x0a {
            return value;
        }
        addons = rest;
    }
    &[]
}

impl Conn for Vless {
    fn mux(&self) -> &Arc<MuxServe> {
        &self.mux
    }

    fn handle(
        self: Arc<Self>,
        stream: BoxStream,
        peer: Peer,
        cx: Arc<InboundCx>,
        mux: Mux,
    ) -> ServeFuture {
        Box::pin(async move {
            let mut buffered = BufReader::with_capacity(512, stream);
            let Some(request) = bounded(self.request(&mut buffered)).await else {
                return;
            };
            let stream: BoxStream = Box::new(HeadFirst::new(unread(buffered), RESPONSE.to_vec()));
            let inbound = cx.inbound(InboundKind::Vless, peer.local, request.user);
            match request.command {
                CMD_TCP | CMD_MUX => {
                    flows::tcp(stream, request.dst, inbound, peer, &cx, &mux);
                }
                CMD_UDP => flows::udp(stream, request.dst, inbound, peer, &cx),
                command => tracing::debug!("{}: VLESS command {command} is not served", cx.name),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flow_is_read_from_the_addons() {
        let addons = [0x0a, 3, b'a', b'b', b'c', 0x12, 1, 9];
        assert_eq!(addon_flow(&addons), b"abc");
        assert_eq!(addon_flow(&[0x12, 1, 9, 0x0a, 1, b'x']), b"x");
        assert_eq!(addon_flow(&[0x0a, 9]), b"");
        assert_eq!(addon_flow(&[]), b"");
    }
}
