use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use concord_common::addr::unmap;
use concord_common::serve::InboundCx;
pub(crate) use concord_common::serve::{HANDSHAKE_TIMEOUT, Peer};
use concord_common::sync;
use concord_common::{
    Address, BoxStream, FlowHandler, FlowMeta, InboundInfo, InboundKind, Network, Special, UdpFlow,
    UdpPayload, UdpReply,
};

use crate::listener::Service;
use crate::spec::{Authenticator, Policy};
use crate::udp::Associations;

struct Unset;

impl FlowHandler for Unset {
    fn handle_tcp(&self, _meta: FlowMeta, _stream: BoxStream) {}

    fn handle_udp(&self, _flow: UdpFlow<'_>, _payload: UdpPayload<'_>, _reply: &Arc<dyn UdpReply>) {
    }
}

/// What every listener of one `Listeners` reads at accept time.
pub(crate) struct Shared {
    handler: RwLock<Arc<dyn FlowHandler>>,
    policy: RwLock<Arc<Policy>>,
}

impl Shared {
    pub(crate) fn new(policy: Policy) -> Self {
        Shared {
            handler: RwLock::new(Arc::new(Unset)),
            policy: RwLock::new(Arc::new(policy)),
        }
    }

    pub(crate) fn update(&self, handler: Arc<dyn FlowHandler>, policy: Policy) {
        *sync::write(&self.handler) = handler;
        *sync::write(&self.policy) = Arc::new(policy);
    }

    pub(crate) fn handler(&self) -> Arc<dyn FlowHandler> {
        sync::read(&self.handler).clone()
    }

    pub(crate) fn policy(&self) -> Arc<Policy> {
        sync::read(&self.policy).clone()
    }
}

/// One listener's view: its inbound name (`in-name`), its `rule` and `proxy`, and the UDP
/// associations its SOCKS5 control connections open.
pub(crate) struct ListenCtx {
    pub(crate) shared: Arc<Shared>,
    pub(crate) name: Arc<str>,
    pub(crate) special: Option<Arc<Special>>,
    pub(crate) assoc: Arc<Associations>,
}

pub(crate) enum Auth {
    /// `authentication`, `skip-auth-prefixes`, the LAN lists and the host credential.
    Global,
    Open,
    Own(Authenticator),
}

/// What one port serves now; a reload that keeps the port swaps it whole.
pub(crate) struct Live {
    pub(crate) tcp: Arc<ListenCtx>,
    /// mihomo names the UDP of a global mixed port `DEFAULT-SOCKS` and that of a redirect
    /// port `DEFAULT-TPROXY`.
    pub(crate) udp: Arc<ListenCtx>,
    pub(crate) auth: Auth,
    pub(crate) service: Arc<Service>,
    pub(crate) cx: Arc<InboundCx>,
}

pub(crate) struct Slot(RwLock<Arc<Live>>);

impl Slot {
    pub(crate) fn new(live: Arc<Live>) -> Self {
        Slot(RwLock::new(live))
    }

    pub(crate) fn load(&self) -> Arc<Live> {
        sync::read(&self.0).clone()
    }

    pub(crate) fn store(&self, live: Arc<Live>) {
        *sync::write(&self.0) = live;
    }
}

/// Who a proxy client proved to be: the user it named, or the host itself, which names none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Client {
    pub(crate) user: Option<Arc<str>>,
    pub(crate) host: bool,
}

impl Client {
    pub(crate) fn named(user: &str) -> Self {
        Client {
            user: user_of(user),
            host: false,
        }
    }

    pub(crate) fn host() -> Self {
        Client {
            user: None,
            host: true,
        }
    }
}

pub(crate) fn unmap_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(unmap(addr.ip()), addr.port())
}

impl ListenCtx {
    pub(crate) fn tcp_meta(
        &self,
        kind: InboundKind,
        peer: &Peer,
        dst: Address,
        client: Client,
    ) -> FlowMeta {
        let mut inbound = self.inbound(kind, Some(peer.local), client.user);
        inbound.host = client.host;
        FlowMeta {
            dscp: 0,
            network: Network::Tcp,
            inbound,
            src: peer.src,
            dst,
        }
    }

    pub(crate) fn inbound(
        &self,
        kind: InboundKind,
        local: Option<SocketAddr>,
        user: Option<Arc<str>>,
    ) -> InboundInfo {
        InboundInfo {
            kind,
            name: self.name.clone(),
            addr: local,
            user,
            host: false,
            user_agent: None,
            special: self.special.clone(),
        }
    }

    pub(crate) fn hand_off(&self, meta: FlowMeta, stream: BoxStream) {
        self.shared.handler().handle_tcp(meta, stream);
    }
}

/// A trailing dot is trimmed from a name as the Go inbound does (`#737`).
pub(crate) fn dst_address(host: &str, port: u16) -> Address {
    Address::new(host.trim_end_matches('.'), port)
}

pub(crate) fn user_of(user: &str) -> Option<Arc<str>> {
    (!user.is_empty()).then(|| Arc::from(user))
}
