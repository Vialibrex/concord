use std::net::SocketAddr;
use std::sync::Arc;

use concord_common::serve::{EndpointService, OnUdp, Protocol};
use concord_common::{Address, InboundKind, Special};

use crate::ListenerKind;

/// What a listener is keyed by across reloads: the fixed ports by their kind, a profile's
/// listeners by name, its tunnels by everything they are.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ListenerId {
    Global(ListenerKind),
    Named(Arc<str>),
    /// The listener `ss-config` or `vmess-config` opens, apart from the named ones.
    Default(&'static str),
    Tunnel(Arc<str>),
}

/// One profile listener or tunnel, built by the engine from its definition.
#[derive(Clone)]
pub struct NamedListener {
    pub id: ListenerId,
    /// `in-name`; empty for a top-level tunnel, which mihomo names nothing.
    pub name: Arc<str>,
    /// What the log and the start error call it.
    pub label: String,
    pub binds: Vec<SocketAddr>,
    pub routing_mark: u32,
    pub special: Option<Arc<Special>>,
    pub service: Service,
}

/// Who an HTTP or SOCKS listener asks for credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyAuth {
    /// The profile's `authentication`, with the LAN lists and `skip-auth-prefixes`, which
    /// mihomo applies only to a listener that uses this store.
    Global,
    Open,
    Own(Vec<(String, String)>),
}

#[derive(Clone)]
pub enum Service {
    Http(ProxyAuth),
    Socks {
        auth: ProxyAuth,
        udp: bool,
    },
    Mixed {
        auth: ProxyAuth,
        udp: bool,
    },
    /// `udp` answers UDP beside it as a TProxy port, which mihomo does for the global
    /// redirect port only.
    Redir {
        udp: bool,
    },
    TProxy {
        udp: bool,
    },
    Tunnel {
        tcp: bool,
        udp: bool,
        target: Address,
    },
    Protocol(Protocol),
}

/// The sockets a service needs; a change here or in the address rebinds the port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sockets {
    pub(crate) tcp: Tcp,
    pub(crate) udp: Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tcp {
    None,
    Plain,
    /// Accepts connections NAT redirected to it and asks the kernel where they were going.
    Redirect,
    /// `IP_TRANSPARENT`, accepting connections to any address.
    TProxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Udp {
    None,
    /// Bound beside the TCP port; failing to bind it fails the port.
    Plain,
    /// A transparent socket, whose failure only warns, as mihomo's redirect and TProxy do.
    Transparent,
    /// Handed whole to a protocol of this kind and socket key; another binds the port anew.
    Endpoint(InboundKind, u64),
}

impl Sockets {
    pub(crate) fn needs_transparent(self) -> bool {
        matches!(self.tcp, Tcp::Redirect | Tcp::TProxy) || self.udp == Udp::Transparent
    }
}

impl Service {
    pub(crate) fn sockets(&self) -> Sockets {
        let (tcp, udp) = match self {
            Service::Http(_) => (Tcp::Plain, Udp::None),
            Service::Socks { udp, .. } | Service::Mixed { udp, .. } => (Tcp::Plain, plain(*udp)),
            Service::Redir { udp } => (Tcp::Redirect, transparent(*udp)),
            Service::TProxy { udp } => (Tcp::TProxy, transparent(*udp)),
            Service::Tunnel { tcp, udp, .. } => (stream(*tcp), plain(*udp)),
            Service::Protocol(protocol) => (
                stream(protocol.stream.is_some()),
                match &protocol.udp {
                    None => Udp::None,
                    Some(OnUdp::Datagram(_)) => Udp::Plain,
                    Some(OnUdp::Endpoint(service)) => {
                        Udp::Endpoint(protocol.kind, service.socket_key())
                    }
                },
            ),
        };
        Sockets { tcp, udp }
    }

    pub(crate) fn endpoint(&self) -> Option<&Arc<dyn EndpointService>> {
        match self {
            Service::Protocol(Protocol {
                udp: Some(OnUdp::Endpoint(service)),
                ..
            }) => Some(service),
            _ => None,
        }
    }

    pub(crate) fn auth(&self) -> Option<&ProxyAuth> {
        match self {
            Service::Http(auth) | Service::Socks { auth, .. } | Service::Mixed { auth, .. } => {
                Some(auth)
            }
            _ => None,
        }
    }

    /// The global port of `kind`, as mihomo opens it from the profile's ports.
    pub(crate) fn global(kind: ListenerKind) -> Self {
        let auth = ProxyAuth::Global;
        match kind {
            ListenerKind::Mixed => Service::Mixed { auth, udp: true },
            ListenerKind::Http => Service::Http(auth),
            ListenerKind::Socks => Service::Socks { auth, udp: true },
            ListenerKind::Redir => Service::Redir { udp: true },
            ListenerKind::TProxy => Service::TProxy { udp: true },
        }
    }
}

fn stream(on: bool) -> Tcp {
    if on { Tcp::Plain } else { Tcp::None }
}

fn plain(on: bool) -> Udp {
    if on { Udp::Plain } else { Udp::None }
}

fn transparent(on: bool) -> Udp {
    if on { Udp::Transparent } else { Udp::None }
}
