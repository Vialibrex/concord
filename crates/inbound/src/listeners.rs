use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use concord_common::serve::{Current, InboundCx};
use concord_common::{Address, FlowHandler, InboundKind, Special, Tasks};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::accept::accept_loop;
use crate::bind::{BindHost, BindKey, bind_tcp, bind_udp, bind_udp_alone, resolve_host};
use crate::ctx::{
    Auth, Client, HANDSHAKE_TIMEOUT, ListenCtx, Live, Peer, Shared, Slot, unmap_addr,
};
use crate::listener::{ListenerId, NamedListener, ProxyAuth, Service, Sockets, Tcp, Udp};
use crate::spec::{Authenticator, Keepalive, ListenSpec, Policy};
use crate::transparent::{Transparent, handle_redir, handle_tproxy};
use crate::udp::{Associations, UdpOut};
use crate::{ListenError, ListenerKind};
use crate::{http, socks};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    pub kind: ListenerKind,
    pub addr: SocketAddr,
}

/// A port is kept across a reload while both of these stay the same.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PortKey {
    bind: BindKey,
    sockets: Sockets,
}

struct Port {
    key: PortKey,
    local: SocketAddr,
    slot: Arc<Slot>,
    assoc: Arc<Associations>,
    tasks: Tasks,
    cancel: CancellationToken,
    handles: Vec<JoinHandle<()>>,
    /// What the protocol that took the UDP socket whole serves.
    endpoint: Option<watch::Sender<Current>>,
}

impl Port {
    /// Returns once the port's sockets are closed, so it can be bound again; an endpoint
    /// ends when the sender of what it serves is dropped.
    async fn stop(self) {
        drop(self.endpoint);
        self.cancel.cancel();
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

async fn stop_ports(ports: Vec<Port>) {
    futures_util::future::join_all(ports.into_iter().map(Port::stop)).await;
}

/// One listener as this reload asks for it.
struct Want {
    id: ListenerId,
    label: String,
    name: Arc<str>,
    udp_name: Arc<str>,
    special: Option<Arc<Special>>,
    service: Arc<Service>,
    binds: Vec<BindKey>,
}

/// Owns the accept tasks. Connections already accepted outlive their listener,
/// as they do when the Go core closes one, and end when the `Tasks` of the reconcile that
/// started the listener stop.
pub struct Listeners {
    shared: Arc<Shared>,
    transparent: Option<Arc<dyn Transparent>>,
    running: Mutex<HashMap<ListenerId, Vec<Port>>>,
}

impl Default for Listeners {
    fn default() -> Self {
        Self::new()
    }
}

impl Listeners {
    pub fn new() -> Self {
        Listeners {
            shared: Arc::new(Shared::new(Policy::from_spec(&ListenSpec::default()))),
            transparent: None,
            running: Mutex::new(HashMap::new()),
        }
    }

    pub fn native() -> Self {
        Self::with_transparent(Arc::new(crate::transparent::PlatformTransparent))
    }

    pub fn with_transparent(transparent: Arc<dyn Transparent>) -> Self {
        Listeners {
            transparent: Some(transparent),
            ..Self::new()
        }
    }

    /// The global ports of `spec` alone; every other listener closes.
    pub async fn reconcile(
        &self,
        spec: &ListenSpec,
        handler: Arc<dyn FlowHandler>,
        tasks: Tasks,
    ) -> Vec<ListenError> {
        self.reconcile_with(spec, Vec::new(), handler, tasks).await
    }

    /// Brings the listeners in line with `spec` and `named`. A port whose bind address and
    /// sockets are unchanged keeps its socket and its connections and serves what it is
    /// now asked to; a changed one is closed first and then bound again; a port that
    /// cannot be bound is reported, leaves the others as they are and is tried again on
    /// the next reload. Auth, the allow and deny lists and the handler apply to every
    /// listener at once.
    pub async fn reconcile_with(
        &self,
        spec: &ListenSpec,
        named: Vec<NamedListener>,
        handler: Arc<dyn FlowHandler>,
        tasks: Tasks,
    ) -> Vec<ListenError> {
        let mut running = self.running.lock().await;
        self.shared.update(handler, Policy::from_spec(spec));
        let mut errors = Vec::new();
        let mut wants = global_wants(spec, &mut errors);
        wants.extend(named.into_iter().map(|listener| named_want(spec, listener)));
        let mut ids = HashSet::new();
        wants.retain(|want| {
            let first = ids.insert(want.id.clone());
            if !first {
                tracing::warn!("{} is listed twice; the second is not started", want.label);
            }
            first
        });

        let mut old = std::mem::take(&mut *running);
        let mut pending = Vec::new();
        let mut dropped = Vec::new();
        for (index, want) in wants.iter().enumerate() {
            let mut previous = old.remove(&want.id).unwrap_or_default();
            let sockets = want.service.sockets();
            let mut kept = Vec::new();
            for bind in &want.binds {
                let key = PortKey {
                    bind: *bind,
                    sockets,
                };
                match previous.iter().position(|port| port.key == key) {
                    Some(at) => {
                        let port = previous.swap_remove(at);
                        let live = self.live(want, &port.assoc, &port.tasks);
                        if let (Some(current), Some(service)) =
                            (&port.endpoint, want.service.endpoint())
                        {
                            current.send_replace(Current {
                                service: service.clone(),
                                cx: live.cx.clone(),
                            });
                        }
                        port.slot.store(live);
                        kept.push(port);
                    }
                    None => pending.push((index, key)),
                }
            }
            dropped.extend(previous);
            running.insert(want.id.clone(), kept);
        }
        dropped.extend(old.into_values().flatten());
        stop_ports(dropped).await;
        for (want, key) in pending
            .into_iter()
            .filter_map(|(index, key)| wants.get(index).map(|want| (want, key)))
        {
            match self.start(want, key, &tasks) {
                Ok(port) => {
                    tracing::info!("{} proxy listening at: {}", want.label, port.local);
                    running.entry(want.id.clone()).or_default().push(port);
                }
                Err(err) => {
                    let error =
                        ListenError::new(want.id.clone(), &want.label, describe(&key.bind), err);
                    tracing::error!("{error}");
                    errors.push(error);
                }
            }
        }
        running.retain(|_, ports| !ports.is_empty());
        errors
    }

    pub async fn stop_all(&self) {
        let stopped: Vec<Port> = self
            .running
            .lock()
            .await
            .drain()
            .flat_map(|(_, ports)| ports)
            .collect();
        stop_ports(stopped).await;
    }

    pub async fn bound(&self) -> Vec<Bound> {
        let running = self.running.lock().await;
        ListenerKind::ALL
            .into_iter()
            .filter_map(|kind| {
                let port = running.get(&ListenerId::Global(kind))?.first()?;
                Some(Bound {
                    kind,
                    addr: port.local,
                })
            })
            .collect()
    }

    /// The addresses `id` listens on, in the order its ports were bound.
    pub async fn local_addrs(&self, id: &ListenerId) -> Vec<SocketAddr> {
        let running = self.running.lock().await;
        running
            .get(id)
            .map(|ports| ports.iter().map(|port| port.local).collect())
            .unwrap_or_default()
    }

    fn live(&self, want: &Want, assoc: &Arc<Associations>, tasks: &Tasks) -> Arc<Live> {
        let ctx = |name: &Arc<str>| {
            Arc::new(ListenCtx {
                shared: self.shared.clone(),
                name: name.clone(),
                special: want.special.clone(),
                assoc: assoc.clone(),
            })
        };
        let auth = match want.service.auth() {
            None | Some(ProxyAuth::Global) => Auth::Global,
            Some(ProxyAuth::Open) => Auth::Open,
            Some(ProxyAuth::Own(users)) => Authenticator::new(users).map_or(Auth::Open, Auth::Own),
        };
        Arc::new(Live {
            tcp: ctx(&want.name),
            udp: ctx(&want.udp_name),
            auth,
            service: want.service.clone(),
            cx: Arc::new(InboundCx {
                name: want.name.clone(),
                special: want.special.clone(),
                handler: self.shared.handler(),
                tasks: tasks.clone(),
            }),
        })
    }

    fn start(&self, want: &Want, key: PortKey, tasks: &Tasks) -> io::Result<Port> {
        let PortKey { bind, sockets } = key;
        let transparent = if sockets.needs_transparent() {
            Some(self.transparent.clone().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "not supported on this platform")
            })?)
        } else {
            None
        };
        let tcp = match sockets.tcp {
            Tcp::None => None,
            Tcp::TProxy => Some(bind_tcp(&bind, transparent.as_deref())?),
            Tcp::Plain | Tcp::Redirect => Some(bind_tcp(&bind, None)?),
        };
        let tcp_local = tcp.as_ref().map(|tcp| tcp.local_addr()).transpose()?;
        let udp = match (sockets.udp, tcp_local) {
            (Udp::Plain | Udp::Endpoint(..), Some(local)) => {
                Some(bind_udp(local, None, bind.mark)?)
            }
            (Udp::Plain | Udp::Endpoint(..), None) => Some(bind_udp_alone(&bind)?),
            _ => None,
        };
        let local = match (tcp_local, &udp) {
            (Some(local), _) => local,
            (None, Some(udp)) => udp.local_addr()?,
            (None, None) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no network to listen on",
                ));
            }
        };

        let assoc = Arc::new(Associations::default());
        let live = self.live(want, &assoc, tasks);
        let slot = Arc::new(Slot::new(live.clone()));
        let cancel = CancellationToken::new();
        let mut handles = Vec::new();
        let mut endpoint = None;
        match (udp, want.service.endpoint()) {
            (Some(socket), Some(service)) => {
                let (current, serving) = watch::channel(Current {
                    service: service.clone(),
                    cx: live.cx.clone(),
                });
                let run = service.clone().run(socket.into_std()?, serving)?;
                handles.push(tasks.spawn(run));
                endpoint = Some(current);
            }
            (Some(socket), None) => {
                let out = UdpOut::new(Arc::new(socket), tasks.clone());
                handles.push(tasks.spawn(crate::udp::run(slot.clone(), out, cancel.clone())));
            }
            (None, _) => {}
        }
        if let Some(transparent) = transparent
            .clone()
            .filter(|_| sockets.udp == Udp::Transparent)
        {
            match bind_udp(local, Some(transparent.as_ref()), bind.mark) {
                Ok(socket) => handles.push(tasks.spawn(crate::tproxy_udp::run(
                    slot.clone(),
                    socket,
                    transparent,
                    cancel.clone(),
                    tasks.clone(),
                ))),
                Err(err) => tracing::warn!("Failed to start {} UDP Listener: {err}", want.label),
            }
        }
        if let Some(listener) = tcp {
            let accept_slot = slot.clone();
            let connections = tasks.clone();
            handles.push(tasks.spawn(accept_loop(
                listener,
                cancel.clone(),
                move |stream, from| {
                    connections.spawn(serve_conn(
                        accept_slot.load(),
                        stream,
                        from,
                        transparent.clone(),
                        local,
                    ));
                },
            )));
        }
        Ok(Port {
            key,
            local,
            slot,
            assoc,
            tasks: tasks.clone(),
            cancel,
            handles,
            endpoint,
        })
    }
}

fn global_wants(spec: &ListenSpec, errors: &mut Vec<ListenError>) -> Vec<Want> {
    let host = resolve_host(spec.allow_lan, &spec.bind_address);
    let mut wants = Vec::new();
    for kind in ListenerKind::ALL {
        let Some(port) = spec.port(kind) else {
            continue;
        };
        let id = ListenerId::Global(kind);
        let host = match &host {
            Ok(host) => *host,
            Err(err) => {
                errors.push(ListenError::new(
                    id,
                    kind.label(),
                    spec.bind_address.clone(),
                    io::Error::new(err.kind(), err.to_string()),
                ));
                continue;
            }
        };
        let udp_name = match kind {
            ListenerKind::Mixed => ListenerKind::Socks.inbound_name(),
            ListenerKind::Redir => ListenerKind::TProxy.inbound_name(),
            _ => kind.inbound_name(),
        };
        wants.push(Want {
            id,
            label: kind.label().to_owned(),
            name: Arc::from(kind.inbound_name()),
            udp_name: Arc::from(udp_name),
            special: None,
            service: Arc::new(Service::global(kind)),
            binds: vec![BindKey {
                host,
                port,
                mptcp: spec.mptcp && kind != ListenerKind::TProxy,
                mark: 0,
            }],
        });
    }
    wants
}

/// Go's `net.Listen` on an unspecified address takes both families, as the wildcard does.
fn named_want(spec: &ListenSpec, listener: NamedListener) -> Want {
    let service = Arc::new(listener.service);
    let mptcp = spec.mptcp && service.sockets().tcp != Tcp::TProxy;
    let binds = listener
        .binds
        .iter()
        .map(|addr| BindKey {
            host: if addr.ip().is_unspecified() {
                BindHost::Wildcard
            } else {
                BindHost::Ip(addr.ip())
            },
            port: addr.port(),
            mptcp,
            mark: listener.routing_mark,
        })
        .collect();
    Want {
        id: listener.id,
        label: listener.label,
        udp_name: listener.name.clone(),
        name: listener.name,
        special: listener.special,
        service,
        binds,
    }
}

fn describe(key: &BindKey) -> String {
    match key.host {
        BindHost::Wildcard => format!(":{}", key.port),
        BindHost::Ip(ip) => SocketAddr::new(ip, key.port).to_string(),
    }
}

fn configure(stream: &TcpStream, keepalive: Option<Keepalive>) {
    let _ = stream.set_nodelay(true);
    if let Some(Keepalive { idle, interval }) = keepalive {
        let probe = TcpKeepalive::new().with_time(idle).with_interval(interval);
        let _ = SockRef::from(stream).set_tcp_keepalive(&probe);
    }
}

async fn first_byte(stream: &TcpStream) -> Option<u8> {
    let mut first = [0u8; 1];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) => Some(first[0]),
        _ => None,
    }
}

async fn serve_conn(
    live: Arc<Live>,
    stream: TcpStream,
    from: SocketAddr,
    transparent: Option<Arc<dyn Transparent>>,
    listener: SocketAddr,
) {
    let Ok(local) = stream.local_addr() else {
        return;
    };
    let peer = Peer {
        src: unmap_addr(from),
        local: unmap_addr(local),
    };
    let ctx = &live.tcp;
    let policy = ctx.shared.policy();
    let ip = peer.src.ip();
    let proxy = live.service.auth().is_some();
    if proxy && matches!(live.auth, Auth::Global) && !policy.admits(ip) {
        return;
    }
    configure(&stream, policy.keepalive);
    let (auth, host) = match &live.auth {
        Auth::Global => (policy.authenticator(ip), policy.host(ip)),
        Auth::Open => (None, None),
        Auth::Own(own) => (Some(own), None),
    };

    match &*live.service {
        Service::Mixed { .. } => match first_byte(&stream).await {
            Some(4) => socks::handle_socks4(ctx, stream, peer, auth).await,
            Some(5) => socks::handle_socks5(ctx, stream, peer, auth, host).await,
            Some(_) => http::serve(ctx.clone(), stream, peer, auth, host).await,
            None => {}
        },
        Service::Http(_) => http::serve(ctx.clone(), stream, peer, auth, host).await,
        Service::Socks { .. } => match first_byte(&stream).await {
            Some(4) => socks::handle_socks4(ctx, stream, peer, auth).await,
            Some(5) => socks::handle_socks5(ctx, stream, peer, auth, host).await,
            _ => {}
        },
        Service::Redir { .. } => {
            if let Some(transparent) = transparent {
                handle_redir(ctx, stream, peer, transparent.as_ref()).await;
            }
        }
        Service::TProxy { .. } => handle_tproxy(ctx, stream, peer, listener),
        Service::Tunnel { target, .. } => tunnel(ctx, stream, peer, target.clone()),
        Service::Protocol(protocol) => {
            if let Some(service) = protocol.stream.clone() {
                let _ = timeout(
                    HANDSHAKE_TIMEOUT,
                    service.serve(stream, peer, live.cx.clone()),
                )
                .await;
            }
        }
    }
}

fn tunnel(ctx: &ListenCtx, stream: TcpStream, peer: Peer, target: Address) {
    let meta = ctx.tcp_meta(InboundKind::Tunnel, &peer, target, Client::default());
    ctx.hand_off(meta, Box::new(stream));
}
