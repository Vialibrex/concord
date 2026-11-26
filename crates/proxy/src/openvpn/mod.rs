mod config;
mod control;
mod data;
mod keys;
mod link;
mod push;
mod reliable;
mod session;
mod tls;
mod tunnel;
mod wire;
mod wrap;

#[cfg(test)]
mod tests;

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, HostResolver, Initiator, LookupIps, Outbound,
    OutboundInfo, OutboundKind, PacketSession, Tasks,
};
use concord_config::proxy::{OpenVpnOpts, ProxyDef};
use concord_net::dial_found;

use self::config::Config;
use self::tunnel::Tunnel;
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, info_for};
use crate::session_slot::SessionSlot;
use crate::stack::IpStream;

pub(crate) struct Shared {
    info: OutboundInfo,
    egress: Egress,
    config: Arc<Config>,
    slot: SessionSlot<Tunnel>,
    init: tokio::sync::Mutex<()>,
    tasks: Tasks,
}

struct OpenVpn {
    shared: Arc<Shared>,
}

async fn bounded<T>(
    wait: Option<Duration>,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match wait {
        Some(wait) => tokio::time::timeout(wait, future)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
        None => future.await,
    }
}

impl Shared {
    /// The dial's own deadline, cut to `handshake-timeout` when the node sets one.
    fn timeout(&self, cx: &DialCx<'_>) -> Option<Duration> {
        match (cx.remaining(), self.config.handshake_timeout) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    async fn tunnel(&self, cx: &DialCx<'_>) -> io::Result<Arc<Tunnel>> {
        let connect = || {
            bounded(
                self.timeout(cx),
                Tunnel::connect(&self.config, cx, &self.egress, &self.tasks),
            )
        };
        self.slot
            .offer(&self.init, Tunnel::usable, connect, |tunnel| tunnel.close())
            .await
            .map_err(|err| io::Error::new(err.kind(), format!("make OpenVPN handshake: {err}")))
    }
}

impl Tunnel {
    async fn lookup(
        &self,
        shared: &Shared,
        resolver: &dyn HostResolver,
        host: &str,
        initiator: Initiator,
    ) -> io::Result<LookupIps> {
        if shared.config.dns.is_empty() {
            resolver
                .lookup(host, shared.egress.version(), initiator)
                .await
        } else {
            self.dns
                .lookup(&self.stack, host, shared.config.congestion)
                .await
        }
    }

    async fn resolve(
        &self,
        shared: &Shared,
        resolver: &dyn HostResolver,
        host: &str,
        initiator: Initiator,
    ) -> io::Result<IpAddr> {
        self.lookup(shared, resolver, host, initiator)
            .await?
            .first(shared.egress.version())
            .ok_or_else(|| CoreError::IpNotFound(host.to_string()).into())
    }
}

#[async_trait]
impl Outbound for OpenVpn {
    fn info(&self) -> &OutboundInfo {
        &self.shared.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let shared = &self.shared;
        let tunnel = shared.tunnel(cx).await?;
        let open = |target: SocketAddr| {
            let tunnel = &tunnel;
            async move {
                let mut conn = tunnel.stack.connect_tcp(target, shared.config.congestion)?;
                bounded(cx.remaining(), poll_fn(|cx| conn.poll_established(cx))).await?;
                Ok(conn)
            }
        };
        let conn = match dst {
            Address::Socket(addr) => open(*addr).await?,
            Address::Domain(host, _) => {
                let found = tunnel
                    .lookup(shared, &*cx.env.resolver, host, cx.initiator)
                    .await?;
                dial_found(cx, found, dst, shared.egress.version(), open).await?
            }
        };
        Ok(Box::new(IpStream::new(conn, tunnel)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let tunnel = self.shared.tunnel(cx).await?;
        let session = session::open(
            tunnel,
            self.shared.clone(),
            cx.env.resolver.clone(),
            cx.initiator,
        )?;
        if let Address::Domain(host, _) = hint {
            session
                .seed(host)
                .await
                .map_err(|err| io::Error::other(format!("can't resolve ip: {err}")))?;
        }
        Ok(Arc::new(session))
    }

    async fn resolve_udp(&self, cx: &DialCx<'_>, host: &str) -> Option<io::Result<IpAddr>> {
        let shared = &self.shared;
        if shared.config.dns.is_empty() {
            return None;
        }
        let resolved = async {
            let tunnel = shared.tunnel(cx).await?;
            tunnel
                .resolve(shared, &*cx.env.resolver, host, cx.initiator)
                .await
        };
        Some(
            resolved
                .await
                .map_err(|err| io::Error::other(format!("can't resolve ip: {err}"))),
        )
    }

    fn reset_sessions(&self) {
        if let Some(tunnel) = self.shared.slot.reset() {
            tunnel.close();
        }
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &OpenVpnOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let config = Config::new(opts)?;
    Ok(Arc::new(OpenVpn {
        shared: Arc::new(Shared {
            info: info_for(def, OutboundKind::OpenVpn, &opts.server, opts.port, true),
            egress: Egress::new(&def.name, &def.common),
            config: Arc::new(config),
            slot: SessionSlot::default(),
            init: tokio::sync::Mutex::new(()),
            tasks: ctx.tasks.clone(),
        }),
    }))
}
