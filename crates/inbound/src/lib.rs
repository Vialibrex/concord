#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod accept;
mod bind;
mod ctx;
mod http;
mod listener;
mod listeners;
mod socks;
mod socks4;
mod socks5;
mod spec;
mod tproxy_udp;
mod transparent;
mod udp;

use std::io;

pub use concord_common::serve::Protocol;
pub use listener::{ListenerId, NamedListener, ProxyAuth, Service};
pub use listeners::{Bound, Listeners};
pub use spec::{Cidr, ListenSpec, parse_credential};
pub use transparent::{PlatformTransparent, TproxyDatagram, Transparent};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenerKind {
    Mixed,
    Http,
    Socks,
    Redir,
    TProxy,
}

impl ListenerKind {
    pub const ALL: [ListenerKind; 5] = [
        ListenerKind::Mixed,
        ListenerKind::Http,
        ListenerKind::Socks,
        ListenerKind::Redir,
        ListenerKind::TProxy,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ListenerKind::Mixed => "Mixed(http+socks)",
            ListenerKind::Http => "HTTP",
            ListenerKind::Socks => "SOCKS",
            ListenerKind::Redir => "Redirect",
            ListenerKind::TProxy => "TProxy",
        }
    }

    /// The `in-name` a rule's `IN-NAME` matches.
    pub fn inbound_name(self) -> &'static str {
        match self {
            ListenerKind::Mixed => "DEFAULT-MIXED",
            ListenerKind::Http => "DEFAULT-HTTP",
            ListenerKind::Socks => "DEFAULT-SOCKS",
            ListenerKind::Redir => "DEFAULT-REDIR",
            ListenerKind::TProxy => "DEFAULT-TPROXY",
        }
    }
}

impl ListenSpec {
    pub fn port(&self, kind: ListenerKind) -> Option<u16> {
        match kind {
            ListenerKind::Mixed => self.mixed_port,
            ListenerKind::Http => self.http_port,
            ListenerKind::Socks => self.socks_port,
            ListenerKind::Redir => self.redir_port,
            ListenerKind::TProxy => self.tproxy_port,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Start {label} server error: listen {addr}: {source}")]
pub struct ListenError {
    pub id: ListenerId,
    pub label: String,
    pub addr: String,
    #[source]
    pub source: io::Error,
}

impl ListenError {
    fn new(id: ListenerId, label: &str, addr: String, source: io::Error) -> Self {
        ListenError {
            id,
            label: label.to_owned(),
            addr,
            source,
        }
    }

    /// The global port that failed, when it was one.
    pub fn kind(&self) -> Option<ListenerKind> {
        match self.id {
            ListenerId::Global(kind) => Some(kind),
            _ => None,
        }
    }
}
