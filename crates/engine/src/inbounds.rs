//! A profile's `listeners`, `tunnels`, `ss-config` and `vmess-config`, built into the
//! listeners `concord-inbound` runs.

use std::sync::Arc;

use concord_common::{Address, ClockOffset, Special, Tasks};
use concord_config::listener::{
    InboundDefs, ListenerDef, ListenerKind as Def, ProxyServer, ProxyUsers, TunnelDef,
};
use concord_inbound::{ListenerId, NamedListener, Protocol, ProxyAuth, Service};
use concord_platform::HomeDir;

#[cfg(feature = "server")]
pub(crate) type Carried = concord_proxy::server::Carried;

#[cfg(not(feature = "server"))]
#[derive(Default)]
pub(crate) struct Carried;

/// A listener that cannot be built is left closed and logged, as mihomo logs one that
/// fails to start.
pub(crate) fn build(
    defs: &InboundDefs,
    home: &Arc<HomeDir>,
    carried: &Carried,
    clock: &Arc<ClockOffset>,
    tasks: &Tasks,
) -> Vec<NamedListener> {
    let mut built = Vec::new();
    for def in &defs.listeners {
        let id = match def.default_of {
            Some(key) => ListenerId::Default(key),
            None => ListenerId::Named(Arc::from(def.name.as_str())),
        };
        match service(def, &id, home, carried, clock, tasks) {
            Ok(service) => built.push(NamedListener {
                id,
                name: Arc::from(def.name.as_str()),
                label: format!("{} {}", def.kind.type_name(), def.name),
                binds: def.binds.addrs(),
                routing_mark: def.routing_mark,
                special: special(def.proxy.as_deref(), def.rule.as_deref()),
                service,
            }),
            Err(reason) => tracing::warn!("listener {} is not started: {reason}", def.name),
        }
    }
    for tunnel in &defs.tunnels {
        let key = tunnel_key(tunnel);
        built.push(NamedListener {
            id: ListenerId::Tunnel(Arc::from(key.as_str())),
            name: Arc::from(""),
            label: format!("Tunnel {key}"),
            binds: vec![tunnel.address],
            routing_mark: 0,
            special: special(tunnel.proxy.as_deref(), None),
            service: Service::Tunnel {
                tcp: tunnel.networks.tcp,
                udp: tunnel.networks.udp,
                target: Address::new(&tunnel.target.host, tunnel.target.port),
            },
        });
    }
    built
}

fn special(proxy: Option<&str>, rules: Option<&str>) -> Option<Arc<Special>> {
    (proxy.is_some() || rules.is_some()).then(|| {
        Arc::new(Special {
            proxy: proxy.map(Arc::from),
            rules: rules.map(Arc::from),
        })
    })
}

fn tunnel_key(tunnel: &TunnelDef) -> String {
    let network = match (tunnel.networks.tcp, tunnel.networks.udp) {
        (true, true) => "tcp/udp",
        (true, false) => "tcp",
        (false, true) => "udp",
        (false, false) => "none",
    };
    let target = Address::new(&tunnel.target.host, tunnel.target.port);
    match &tunnel.proxy {
        Some(proxy) => format!("{network},{},{target},{proxy}", tunnel.address),
        None => format!("{network},{},{target}", tunnel.address),
    }
}

#[derive(Debug, thiserror::Error)]
enum ListenerBuildError {
    #[error("invalid target {0}")]
    Target(String),
    #[error("{0} is not served yet")]
    NotServed(&'static str),
    #[cfg(feature = "server")]
    #[error(transparent)]
    Server(#[from] concord_proxy::server::ServerError),
}

fn service(
    def: &ListenerDef,
    id: &ListenerId,
    home: &Arc<HomeDir>,
    carried: &Carried,
    clock: &Arc<ClockOffset>,
    tasks: &Tasks,
) -> Result<Service, ListenerBuildError> {
    Ok(match &def.kind {
        Def::Http(server) => Service::Http(plain(server)),
        Def::Socks(server) => Service::Socks {
            auth: plain(server),
            udp: server.udp,
        },
        Def::Mixed(server) => Service::Mixed {
            auth: plain(server),
            udp: server.udp,
        },
        Def::Redir => Service::Redir { udp: false },
        Def::TProxy { udp } => Service::TProxy { udp: *udp },
        Def::Tunnel { networks, target } => Service::Tunnel {
            tcp: networks.tcp,
            udp: networks.udp,
            target: Address::parse(target)
                .ok_or_else(|| ListenerBuildError::Target(target.clone()))?,
        },
        other => match protocol(other, id, home, carried, clock, tasks)? {
            Some(protocol) => Service::Protocol(protocol),
            None => return Err(ListenerBuildError::NotServed(other.type_name())),
        },
    })
}

/// What a listener's server state is carried under across reloads; `None` for the ports
/// that keep none.
#[cfg(feature = "server")]
pub(crate) fn keep_of(id: &ListenerId) -> Option<concord_proxy::server::Keep> {
    use concord_proxy::server::Keep;
    match id {
        ListenerId::Named(name) => Some(Keep::Named(name.clone())),
        ListenerId::Default(key) => Some(Keep::Default(key)),
        ListenerId::Global(_) | ListenerId::Tunnel(_) => None,
    }
}

#[cfg(feature = "server")]
fn protocol(
    def: &Def,
    id: &ListenerId,
    home: &Arc<HomeDir>,
    carried: &Carried,
    clock: &Arc<ClockOffset>,
    tasks: &Tasks,
) -> Result<Option<Protocol>, ListenerBuildError> {
    let Some(keep) = keep_of(id) else {
        return Ok(None);
    };
    let env = concord_proxy::server::ServerEnv {
        home,
        tasks,
        keep: &keep,
        carried,
        clock,
    };
    Ok(concord_proxy::server::build(def, &env)?)
}

#[cfg(not(feature = "server"))]
fn protocol(
    _: &Def,
    _: &ListenerId,
    _: &Arc<HomeDir>,
    _: &Carried,
    _: &Arc<ClockOffset>,
    _: &Tasks,
) -> Result<Option<Protocol>, ListenerBuildError> {
    Ok(None)
}

fn plain(server: &ProxyServer) -> ProxyAuth {
    match &server.users {
        ProxyUsers::Global => ProxyAuth::Global,
        ProxyUsers::Open => ProxyAuth::Open,
        ProxyUsers::Own(users) => ProxyAuth::Own(users.clone()),
    }
}
