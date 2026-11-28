//! The Hysteria 2 server: mihomo's `listener/sing_hysteria2/server.go` over sing-quic's
//! `hysteria2/service.go`. HTTP/3 carries the authentication; TCP requests and UDP
//! datagrams are served once a connection has authenticated.

mod dispatch;
mod masquerade;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use bytes::Bytes;
use concord_common::serve::{Current, EndpointService, InboundCx, Peer, ServeFuture};
use concord_common::{Address, InboundKind, PacketBuf, PacketSession};
use concord_config::listener::Hysteria2Server;
use concord_platform::HomeDir;
use concord_quic::{
    BbrProfile, Brutal, CappedFrame, Inbox, ObfsSpec, QuicStream, Sessions, SwitchFactory,
    bbr_factory, bbr_window,
};
use quinn::congestion::ControllerFactory;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Incoming, VarInt};
use tokio::sync::{mpsc, watch};
use tokio::time::Sleep;

use self::dispatch::{Dispatched, ForH3, Route, route};
use self::masquerade::{H3Stream, Masquerade};
use super::certs::ServerCerts;
use super::mux::{Mux, MuxServe};
use super::quic::{self, QuicServer};
use super::{ServerError, TlsSetup, bounded, flows, packets};
use crate::hysteria2::udp::{HEADROOM, Sender};
use crate::hysteria2::wire::{UdpMessage, padding, parse_udp, read_tcp_request, tcp_response};
use crate::hysteria2::{
    AUTH_OK, DATAGRAM_FRAME, DEFAULT_CONN_WINDOW, DEFAULT_STREAM_WINDOW, DEFAULT_UDP_MTU, Side,
    transport, window,
};
use crate::lazy::HeadFirst;
use crate::util::{lock, parse_bps};

/// quic-go's `http.DefaultMaxHeaderBytes`, which sing-quic's HTTP/3 server keeps
/// (`http3/server.go:582-586`).
const MAX_HEADER_BYTES: u64 = 1 << 20;

/// How long a UDP session lasts without a datagram either way: sing-quic's `udpTimeout`
/// (`hysteria2/service_packet.go:52`) as mihomo sets it (`listener/sing/sing.go:32`).
const UDP_IDLE: Duration = Duration::from_secs(300);

pub(super) struct Hysteria2 {
    /// By password, the name `IN-USER` gives.
    users: HashMap<String, Arc<str>>,
    send_bps: u64,
    receive_bps: u64,
    ignore_client_bandwidth: bool,
    udp_mtu: usize,
    bbr: Arc<dyn ControllerFactory + Send + Sync>,
    crypto: Arc<CappedFrame<QuicServerConfig>>,
    stream_window: u64,
    conn_window: u64,
    obfs: ObfsSpec,
    socket_key: u64,
    mux: Arc<MuxServe>,
    masquerade: Masquerade,
    _certs: ServerCerts,
}

impl Hysteria2 {
    pub(super) fn new(
        server: &Hysteria2Server,
        tls: TlsSetup,
        home: &Arc<HomeDir>,
    ) -> Result<Self, ServerError> {
        let crypto = quic::crypto(&tls, &server.alpn, false)?;
        let mut key = DefaultHasher::new();
        server.salamander.hash(&mut key);
        Ok(Hysteria2 {
            users: server
                .users
                .iter()
                .map(|(name, password)| (password.clone(), Arc::from(name.as_str())))
                .collect(),
            send_bps: parse_bps(&server.up),
            receive_bps: parse_bps(&server.down),
            ignore_client_bandwidth: server.ignore_client_bandwidth,
            udp_mtu: match server.udp_mtu {
                0 => DEFAULT_UDP_MTU,
                mtu => usize::try_from(mtu).unwrap_or(usize::MAX),
            },
            bbr: bbr_factory(
                BbrProfile::parse(&server.bbr_profile),
                bbr_window(server.cwnd),
            ),
            crypto: Arc::new(CappedFrame::new(Arc::new(crypto), DATAGRAM_FRAME)),
            stream_window: window(
                server.initial_stream_window,
                server.max_stream_window,
                DEFAULT_STREAM_WINDOW,
            ),
            conn_window: window(
                server.initial_conn_window,
                server.max_conn_window,
                DEFAULT_CONN_WINDOW,
            ),
            obfs: match &server.salamander {
                Some(password) => ObfsSpec::Salamander(password.as_bytes().to_vec()),
                None => ObfsSpec::None,
            },
            socket_key: key.finish(),
            mux: MuxServe::new(&server.mux),
            masquerade: Masquerade::new(server.masquerade.as_ref(), home)?,
            _certs: tls.certs,
        })
    }

    /// A connection runs on quic-go's default controller until it authenticates, then on
    /// the one its authentication picks.
    fn connection_config(&self, controllers: Arc<SwitchFactory>) -> quinn::ServerConfig {
        let mut config = quinn::ServerConfig::with_crypto(self.crypto.clone());
        config.transport_config(transport(
            self.stream_window,
            self.conn_window,
            Side::Server,
            controllers,
        ));
        config
    }

    /// sing-quic's choice for a client that asks to receive at `rx`: `None` when the server
    /// has a rate of its own, ignores the client's, and the client leaves it to the
    /// controller.
    fn pace(&self, rx: u64) -> Option<Pace> {
        if self.receive_bps > 0 && self.ignore_client_bandwidth && rx == 0 {
            return None;
        }
        let leave_to_bbr = self.receive_bps == 0 && self.ignore_client_bandwidth;
        Some(if !leave_to_bbr && rx > 0 {
            Pace::Brutal(match self.send_bps {
                0 => rx,
                send => rx.min(send),
            })
        } else {
            Pace::Bbr
        })
    }

    fn rx_header(&self, rx_auto: bool) -> String {
        if rx_auto {
            "auto".to_owned()
        } else {
            self.receive_bps.to_string()
        }
    }
}

impl EndpointService for Hysteria2 {
    fn run(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        current: watch::Receiver<Current>,
    ) -> std::io::Result<ServeFuture> {
        quic::run(self, socket, current)
    }

    fn socket_key(&self) -> u64 {
        self.socket_key
    }
}

impl QuicServer for Hysteria2 {
    fn config(&self) -> quinn::ServerConfig {
        self.connection_config(SwitchFactory::new(Arc::new(concord_quic::cubic())))
    }

    fn obfs(&self) -> &ObfsSpec {
        &self.obfs
    }

    fn connection(
        self: Arc<Self>,
        incoming: Incoming,
        peer: Peer,
        cx: Arc<InboundCx>,
    ) -> ServeFuture {
        Box::pin(async move {
            let controllers = SwitchFactory::new(Arc::new(concord_quic::cubic()));
            let config = Arc::new(self.connection_config(controllers.clone()));
            let Ok(connecting) = incoming.accept_with(config) else {
                return;
            };
            let Ok(Ok(conn)) = tokio::time::timeout(quic::HANDSHAKE_LIMIT, connecting).await else {
                return;
            };
            let (routed, for_h3) = mpsc::channel(1);
            let conn = Arc::new(Conn {
                server: self,
                conn,
                peer,
                cx,
                controllers,
                user: watch::channel(None).0,
                sessions: Arc::default(),
            });
            tokio::join!(conn.http(for_h3), conn.streams(routed), conn.datagrams());
            conn.sessions.clear();
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Pace {
    Brutal(u64),
    Bbr,
}

/// One client connection: sing-quic's `serverSession`.
struct Conn {
    server: Arc<Hysteria2>,
    conn: quinn::Connection,
    peer: Peer,
    cx: Arc<InboundCx>,
    controllers: Arc<SwitchFactory>,
    /// The name of the user the connection authenticated as; the first stands.
    user: watch::Sender<Option<Arc<str>>>,
    sessions: Arc<Sessions<String>>,
}

impl Conn {
    fn user(&self) -> Option<Arc<str>> {
        self.user.borrow().clone()
    }

    /// Serves HTTP/3 until it ends, which ends the connection, as `ServeQUICConn` returning
    /// does in sing-quic. Until the connection authenticates its requests are taken one at a
    /// time, so a stranger holds one header block at most.
    async fn http(self: &Arc<Self>, routed: mpsc::Receiver<ForH3>) {
        let served = Dispatched::new(self.conn.clone(), routed);
        let h3 = h3::server::builder()
            .max_field_section_size(MAX_HEADER_BYTES)
            .build::<_, Bytes>(served)
            .await;
        if let Ok(mut h3) = h3 {
            while let Ok(Some(resolver)) = h3.accept().await {
                let conn = self.clone();
                let request = async move {
                    let resolved = bounded(async { resolver.resolve_request().await.ok() }).await;
                    if let Some((request, stream)) = resolved {
                        conn.answer(request, stream).await;
                    }
                };
                if self.user().is_some() {
                    self.cx.tasks.spawn(request);
                } else {
                    request.await;
                }
            }
        }
        self.conn.close(VarInt::from_u32(0), b"");
    }

    /// The masquerade's answer ends with the connection, as quic-go's request context does
    /// (`http3/server_conn.go:191-193`), so what it holds of the tunnel goes with it.
    async fn answer(&self, request: http::Request<()>, mut stream: H3Stream) {
        let asks_auth = request.method() == http::Method::POST
            && request.uri().authority().map(|host| host.as_str()) == Some("hysteria")
            && request.uri().path() == "/auth";
        let rx = if asks_auth {
            self.authenticate(&request)
        } else {
            None
        };
        let Some(rx) = rx else {
            let answer = self
                .server
                .masquerade
                .answer(request, stream, self.cx.clone());
            tokio::select! {
                () = answer => {}
                _ = self.conn.closed() => {}
            }
            return;
        };
        let response = http::Response::builder()
            .status(AUTH_OK)
            .header("Hysteria-UDP", "true")
            .header("Hysteria-CC-RX", rx)
            .header("Hysteria-Padding", padding(256, 2048));
        let Ok(mut response) = response.body(()) else {
            return;
        };
        response
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(0));
        masquerade::stamp_date(response.headers_mut());
        if stream.send_response(response).await.is_err() {
            return;
        }
        let _ = stream.finish().await;
    }

    /// sing-quic's `ServeHTTP` for the authentication request: the `Hysteria-CC-RX` to
    /// answer with, or `None` for the masquerade's 404. A server that ignores the client's
    /// bandwidth but has its own refuses a client that leaves it to the controller, yet
    /// counts the connection as authenticated, as sing-quic does.
    fn authenticate(&self, request: &http::Request<()>) -> Option<String> {
        let server = &self.server;
        let leave_to_bbr = server.receive_bps == 0 && server.ignore_client_bandwidth;
        if self.user().is_some() {
            return Some(server.rx_header(leave_to_bbr));
        }
        let header = |name: &str| {
            let value = request.headers().get(name)?;
            std::str::from_utf8(value.as_bytes()).ok()
        };
        let user = server.users.get(header("Hysteria-Auth")?)?;
        self.user.send_replace(Some(user.clone()));
        let rx = header("Hysteria-CC-RX")
            .and_then(|rx| rx.parse::<u64>().ok())
            .unwrap_or(0);
        let pace = server.pace(rx)?;
        if let Some(switch) = self.controllers.handle() {
            match pace {
                Pace::Brutal(rate) => {
                    switch.replace_brutal(Brutal::hysteria2(rate, self.conn.rtt(), Instant::now()));
                }
                Pace::Bbr => switch.rebuild(server.bbr.clone()),
            }
        }
        Some(server.rx_header(pace == Pace::Bbr))
    }

    async fn streams(self: &Arc<Self>, routed: mpsc::Sender<ForH3>) {
        while let Ok((send, mut recv)) = self.conn.accept_bi().await {
            let (conn, routed) = (self.clone(), routed.clone());
            self.cx.tasks.spawn(async move {
                match bounded(async { route(&mut recv).await.ok() }).await {
                    Some(Route::Tcp) => conn.tcp(send, recv).await,
                    Some(Route::H3(raw)) => {
                        let _ = routed.send((send, recv, Bytes::from(raw))).await;
                    }
                    Some(Route::Ended) | None => {}
                }
            });
        }
    }

    /// A TCP request, which only an authenticated connection may make. The answer goes out
    /// with the first data back, as sing-quic's `serverConn` writes it.
    async fn tcp(self: Arc<Self>, send: quinn::SendStream, mut recv: quinn::RecvStream) {
        let Some(user) = self.user() else {
            return;
        };
        let request = bounded(async { read_tcp_request(&mut recv).await.ok() });
        let Some(dst) = request.await.as_deref().and_then(Address::parse) else {
            return;
        };
        let inbound = self
            .cx
            .inbound(InboundKind::Hysteria2, self.peer.local, Some(user));
        let stream = HeadFirst::new(QuicStream::new(send, recv, Box::new(())), tcp_response());
        flows::tcp(
            Box::new(stream),
            dst,
            inbound,
            self.peer,
            &self.cx,
            &Mux::new(&self.server.mux),
        );
    }

    /// Reads datagrams once the connection has authenticated; one that does not parse
    /// closes the connection, as in sing-quic's `loopMessages`.
    async fn datagrams(self: &Arc<Self>) {
        let authed = async {
            let mut user = self.user.subscribe();
            let user = user.wait_for(Option::is_some).await.ok()?;
            user.clone()
        };
        let user = tokio::select! {
            user = authed => user,
            _ = self.conn.closed() => None,
        };
        let Some(user) = user else {
            return;
        };
        while let Ok(datagram) = self.conn.read_datagram().await {
            let Ok(message) = parse_udp(&datagram) else {
                self.conn.close(VarInt::from_u32(0), b"");
                return;
            };
            self.relay(message, &user);
        }
    }

    /// Hands a datagram to its session, which the first datagram of it opens.
    fn relay(self: &Arc<Self>, message: UdpMessage, user: &Arc<str>) {
        let id = message.session;
        if let Some((_, inbox)) = self.sessions.register(|taken| (!taken(id)).then_some(id)) {
            let session = Arc::new(Session::new(
                id,
                Sender::new(id, self.conn.clone(), self.server.udp_mtu),
                inbox,
                &self.sessions,
            ));
            let inbound =
                self.cx
                    .inbound(InboundKind::Hysteria2, self.peer.local, Some(user.clone()));
            self.cx.tasks.spawn(packets::serve_session(
                session,
                inbound,
                self.peer.src,
                self.cx.clone(),
            ));
        }
        self.sessions
            .deliver(id, message.into_fragment(), |addr| Address::parse(&addr));
    }
}

/// The datagrams of one session id. It ends once idle, and the next datagram with its id
/// opens a new one.
struct Session {
    id: u32,
    sender: Sender,
    inbox: Mutex<Inbox>,
    idle: Mutex<Pin<Box<Sleep>>>,
    sessions: Weak<Sessions<String>>,
    closed: AtomicBool,
}

impl Session {
    fn new(id: u32, sender: Sender, inbox: Inbox, sessions: &Arc<Sessions<String>>) -> Self {
        Session {
            id,
            sender,
            inbox: Mutex::new(inbox),
            idle: Mutex::new(Box::pin(tokio::time::sleep(UDP_IDLE))),
            sessions: Arc::downgrade(sessions),
            closed: AtomicBool::new(false),
        }
    }

    fn touch(&self) {
        lock(&self.idle)
            .as_mut()
            .reset(tokio::time::Instant::now() + UDP_IDLE);
    }
}

impl PacketSession for Session {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        self.touch();
        Poll::Ready(self.sender.send(pkt, dst))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        match lock(&self.inbox).poll_recv(cx) {
            Poll::Ready(Some((from, data))) => {
                self.touch();
                buf.extend_from_slice(&data);
                return Poll::Ready(Ok(from));
            }
            Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => {}
        }
        ready!(lock(&self.idle).as_mut().poll(cx));
        if let Some(sessions) = self.sessions.upgrade() {
            sessions.remove(self.id);
        }
        Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
    }

    fn headroom(&self) -> usize {
        HEADROOM
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}
