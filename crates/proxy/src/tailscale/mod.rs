mod inbox;
mod tunnel;
mod via;

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use concord_common::sync::lock;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
    Tasks,
};
use concord_config::proxy::{ProxyDef, TailscaleOpts};
use concord_net::dial_found;
use concord_tsnet::Library;
use serde_json::json;

use self::tunnel::{Launch, Start, Tunnel};
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, info_for};
use crate::stack::{Congestion, IpStream, SessionTunnel, StackSession};

/// mihomo's `applyPrefs` timeout; a dial waits no longer than this, or than its own deadline.
const START_TIMEOUT: Duration = Duration::from_secs(30);

struct Shared {
    info: OutboundInfo,
    egress: Egress,
    config: String,
    launch: Mutex<Option<Arc<Launch>>>,
    tasks: Tasks,
}

struct Tailscale {
    shared: Arc<Shared>,
}

/// Runs `work` on the node's tasks and waits for it on the calling Go thread, which is off the
/// runtime; `None` when the owner stops first.
fn wait_on<F>(tasks: &Tasks, work: F) -> Option<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (done, outcome) = std::sync::mpsc::sync_channel(1);
    tasks.spawn(async move {
        let _ = done.send(work.await);
    });
    outcome.recv().ok()
}

/// The library, loaded off the runtime the first time: that reads, checks and maps some 20 MB.
async fn library() -> io::Result<&'static Library> {
    let loaded = match Library::loaded() {
        Some(loaded) => loaded,
        None => tokio::task::spawn_blocking(Library::get)
            .await
            .map_err(io::Error::other)?,
    };
    loaded.map_err(|err| io::Error::new(io::ErrorKind::Unsupported, err.to_string()))
}

impl Shared {
    async fn tunnel(&self, cx: &DialCx<'_>) -> io::Result<Arc<Tunnel>> {
        let lib = library().await?;
        let launch = {
            let mut current = lock(&self.launch);
            match current.as_ref().filter(|launch| launch.alive()) {
                Some(launch) => launch.clone(),
                None => {
                    let start = Start {
                        name: self.egress.name().clone(),
                        config: self.config.clone(),
                        env: cx.env.clone(),
                        opts: self.egress.sock_opts(cx.env),
                        version: self.egress.version(),
                        via: self.egress.via().map(Arc::from),
                    };
                    let launch = Launch::spawn(start, lib, &self.tasks)?;
                    if let Some(old) = current.replace(launch.clone()) {
                        old.close();
                    }
                    launch
                }
            }
        };
        let wait = cx
            .remaining()
            .map_or(START_TIMEOUT, |left| left.min(START_TIMEOUT));
        launch.tunnel(wait).await
    }

    fn link_changed(&self) {
        let launch = lock(&self.launch).clone();
        if let Some(launch) = launch {
            launch.link_changed();
        }
    }
}

async fn open_tcp(
    tunnel: &Tunnel,
    cx: &DialCx<'_>,
    target: SocketAddr,
) -> io::Result<crate::stack::TcpConn> {
    let mut conn = tunnel.stack.connect_tcp(target, Congestion::default())?;
    match cx.remaining() {
        Some(left) => tokio::time::timeout(left, poll_fn(|c| conn.poll_established(c)))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??,
        None => poll_fn(|c| conn.poll_established(c)).await?,
    }
    Ok(conn)
}

#[async_trait]
impl Outbound for Tailscale {
    fn info(&self) -> &OutboundInfo {
        &self.shared.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let shared = &self.shared;
        let tunnel = shared.tunnel(cx).await?;
        let open = |target: SocketAddr| {
            let tunnel = &tunnel;
            async move { open_tcp(tunnel, cx, target).await }
        };
        let conn = match dst {
            Address::Socket(addr) => open(*addr).await?,
            Address::Domain(host, _) => {
                let found = tunnel.lookup(host).await?;
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
        let session = StackSession::new(
            tunnel.stack.bind_udp()?,
            TailscaleUdp {
                tunnel,
                version: self.shared.egress.version(),
            },
        );
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
        let resolved = async {
            let tunnel = shared.tunnel(cx).await?;
            tunnel
                .lookup(host)
                .await?
                .first(shared.egress.version())
                .ok_or_else(|| CoreError::IpNotFound(host.to_string()).into())
        };
        Some(
            resolved
                .await
                .map_err(|err: io::Error| io::Error::other(format!("can't resolve ip: {err}"))),
        )
    }

    async fn exchange_dns(&self, cx: &DialCx<'_>, query: &[u8]) -> Option<io::Result<Vec<u8>>> {
        Some(async { self.shared.tunnel(cx).await?.exchange(query).await }.await)
    }

    /// The node goes on, as mihomo's does, and reopens its UDP sockets: those of the old network,
    /// or those opened before the TUN, which its routes would take in. Its control and DERP
    /// connections carry on until they fail, as they do in mihomo.
    fn link_changed(&self) {
        self.shared.link_changed();
    }
}

struct TailscaleUdp {
    tunnel: Arc<Tunnel>,
    version: concord_common::IpVersion,
}

impl SessionTunnel for TailscaleUdp {
    fn resolve(&self, host: String) -> impl Future<Output = io::Result<IpAddr>> + Send + 'static {
        let tunnel = self.tunnel.clone();
        let version = self.version;
        async move {
            tunnel
                .lookup(&host)
                .await?
                .first(version)
                .ok_or_else(|| CoreError::IpNotFound(host).into())
        }
    }

    fn usable(&self) -> bool {
        self.tunnel.usable()
    }
}

fn node_config(
    def: &ProxyDef,
    opts: &TailscaleOpts,
    via: bool,
    ctx: &BuildCtx,
) -> Result<String, BuildError> {
    let dir = if opts.state_dir.is_empty() {
        "tailscale"
    } else {
        opts.state_dir.as_str()
    };
    let state_dir = ctx.resolve_file(dir)?;
    let hostname = if opts.hostname.is_empty() {
        def.name.as_str()
    } else {
        opts.hostname.as_str()
    };
    Ok(json!({
        "hostname": hostname,
        "auth_key": opts.auth_key,
        "control_url": opts.control_url,
        "state_dir": state_dir.display().to_string(),
        "ephemeral": opts.ephemeral,
        // An ephemeral node logs out as it shuts down, and a reload starts the next node on this
        // directory before the old one stops: a shared state file would lose the next one's key.
        "state_in_memory": opts.ephemeral,
        "accept_routes": opts.accept_routes,
        "exit_node": opts.exit_node,
        "exit_node_allow_lan_access": opts.exit_node_allow_lan_access,
        "via": via,
        "extra_root_cas": ctx.trust.custom().iter().map(|der| BASE64_STANDARD.encode(der)).collect::<Vec<_>>(),
    })
    .to_string())
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &TailscaleOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    Ok(Arc::new(tailscale(def, opts, ctx)?))
}

fn tailscale(
    def: &ProxyDef,
    opts: &TailscaleOpts,
    ctx: &BuildCtx,
) -> Result<Tailscale, BuildError> {
    let egress = Egress::new(&def.name, &def.common);
    let server = if opts.control_url.is_empty() {
        "tailscale"
    } else {
        opts.control_url.as_str()
    };
    Ok(Tailscale {
        shared: Arc::new(Shared {
            info: info_for(def, OutboundKind::Tailscale, server, 0, opts.udp),
            config: node_config(def, opts, egress.is_via(), ctx)?,
            egress,
            launch: Mutex::new(None),
            tasks: ctx.tasks.clone(),
        }),
    })
}

#[cfg(test)]
mod tests {
    use concord_config::proxy::ProxyKind;
    use concord_config::{Capabilities, ProxyParse, parse_proxy};
    use concord_tls::TrustStore;
    use serde_json::{Value, json};

    use std::sync::Arc;

    use concord_common::Outbound;
    use concord_common::sync::lock;
    use concord_config::proxy::ProxyDef;

    use super::tunnel::Launch;
    use super::{node_config, tailscale};
    use crate::BuildCtx;

    fn parsed(node: Value) -> ProxyDef {
        let Some(map) = node.as_object() else {
            panic!("not an object");
        };
        let Ok(ProxyParse::Ok(def)) = parse_proxy(map, &Capabilities::full()) else {
            panic!("does not parse");
        };
        *def
    }

    fn ctx() -> BuildCtx {
        BuildCtx::new(TrustStore::new(b"", Vec::new()))
    }

    fn config(ephemeral: bool) -> Value {
        let def = parsed(
            json!({"name": "ts", "type": "tailscale", "auth-key": "k", "ephemeral": ephemeral}),
        );
        let ProxyKind::Tailscale(opts) = &def.kind else {
            panic!("not tailscale");
        };
        serde_json::from_str(&node_config(&def, opts, false, &ctx()).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn a_session_reset_or_a_link_change_keeps_the_node() {
        let def = parsed(json!({"name": "ts", "type": "tailscale", "ephemeral": true}));
        let ProxyKind::Tailscale(opts) = &def.kind else {
            panic!("not tailscale");
        };
        let node = tailscale(&def, opts, &ctx()).unwrap();
        let (launch, _ready) = Launch::waiting(&node.shared.tasks);
        *lock(&node.shared.launch) = Some(launch.clone());
        node.reset_sessions();
        node.link_changed();
        assert!(!launch.closed());
        let kept = lock(&node.shared.launch).clone();
        assert!(kept.is_some_and(|kept| Arc::ptr_eq(&kept, &launch)));
    }

    #[test]
    fn the_node_takes_mihomos_fields_as_written_and_its_defaults() {
        let def = parsed(json!({"name": "ts", "type": "tailscale", "exit-node": " auto:any "}));
        let ProxyKind::Tailscale(opts) = &def.kind else {
            panic!("not tailscale");
        };
        assert_eq!(
            (opts.accept_routes, opts.exit_node_allow_lan_access),
            (None, None)
        );
        let node: Value =
            serde_json::from_str(&node_config(&def, opts, false, &ctx()).unwrap()).unwrap();
        assert_eq!(node["exit_node"], " auto:any ");
        assert_eq!(node["hostname"], "ts");
        assert!(node["accept_routes"].is_null());
        assert!(
            node["state_dir"]
                .as_str()
                .is_some_and(|dir| dir.ends_with("tailscale"))
        );
        let def = parsed(json!({"name": "ts", "type": "tailscale", "accept-routes": false}));
        let ProxyKind::Tailscale(opts) = &def.kind else {
            panic!("not tailscale");
        };
        assert_eq!(opts.accept_routes, Some(false));
    }

    #[test]
    fn an_ephemeral_node_keeps_its_state_in_memory() {
        assert_eq!(config(true)["state_in_memory"], true);
        assert_eq!(config(false)["state_in_memory"], false);
    }
}
