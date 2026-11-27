//! The TUIC server: mihomo's `listener/tuic/server.go` and `transport/tuic/{server,v4/server,
//! v5/server}.go`. A connection serves v4 tokens and v5 users at once, each command by its
//! version byte, and nothing but authentication before one of them authenticates.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use concord_common::serve::{Current, EndpointService, InboundCx, Peer, ServeFuture};
use concord_common::{Address, InboundKind, PacketBuf, PacketSession};
use concord_config::listener::TuicServer;
use concord_quic::{
    CONN_WINDOW, CappedFrame, Inbox, ObfsSpec, SERVER_STREAMS, STREAM_WINDOW, Sessions, Transport,
};
use quinn::{Incoming, VarInt};
use tokio::sync::watch;

use super::certs::ServerCerts;
use super::quic::{self, QuicServer};
use super::{ServerError, TlsSetup, bounded, flows, packets};
use crate::tuic::conn::MAX_STREAM_PACKET;
use crate::tuic::udp::{Relay, Sender};
use crate::tuic::wire::{
    self, CMD_CONNECT, CMD_RESPONSE, Command, Credential, Incoming as Relayed, V4_OVERHEAD,
    V5_OVERHEAD, Version,
};
use crate::tuic::{MAX_FRAG_V5, controller};
use crate::util::lock;

const MAX_IDLE: Duration = Duration::from_millis(15_000);
const AUTH_TIMEOUT: Duration = Duration::from_millis(1_000);
const UDP_PACKET: usize = 1500;
const MAX_FRAME: usize = 1400;
const AUTH_FAILED: u32 = 0xffff_fff1;
const AUTH_TIMED_OUT: u32 = 0xffff_fff2;
const SUCCEEDED: u8 = 0;

pub(super) struct Tuic {
    tokens: Vec<[u8; 32]>,
    /// By UUID, the password and the UUID as `IN-USER` names it.
    users: HashMap<[u8; 16], (String, Arc<str>)>,
    auth_timeout: Duration,
    max_packet: usize,
    config: quinn::ServerConfig,
    _certs: ServerCerts,
}

impl Tuic {
    pub(super) fn new(server: &TuicServer, tls: TlsSetup) -> Result<Self, ServerError> {
        let users: HashMap<[u8; 16], (String, Arc<str>)> = server
            .users
            .iter()
            .map(|(uuid, password)| {
                let uuid = uuid::Uuid::parse_str(uuid).unwrap_or_default();
                (
                    *uuid.as_bytes(),
                    (password.clone(), Arc::from(uuid.to_string())),
                )
            })
            .collect();
        let tokens: Vec<[u8; 32]> = server
            .tokens
            .iter()
            .map(|token| *blake3::hash(token.as_bytes()).as_bytes())
            .collect();
        let overhead = if tokens.is_empty() {
            V5_OVERHEAD
        } else {
            V4_OVERHEAD
        };
        let requested = match server.max_udp_relay_packet {
            0 => UDP_PACKET,
            size => usize::try_from(size).unwrap_or(usize::MAX),
        };
        let frame = requested.saturating_add(overhead).min(MAX_FRAME);
        let crypto = quic::crypto(&tls, &server.alpn, true)?;
        let frame_u64 = u64::try_from(frame).unwrap_or(u64::MAX);
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(CappedFrame::new(
            Arc::new(crypto),
            frame_u64,
        )));
        let idle = match server.max_idle_ms {
            0 => MAX_IDLE,
            ms => Duration::from_millis(ms),
        };
        config.transport_config(
            Transport {
                stream_window: STREAM_WINDOW,
                conn_window: CONN_WINDOW,
                peer_bounded_send: false,
                idle,
                keep_alive: None,
                datagram_frame: frame_u64,
                streams: Some(SERVER_STREAMS),
                mtu_discovery: true,
                congestion: controller(&server.congestion, &server.bbr_profile, server.cwnd),
            }
            .build(),
        );
        Ok(Tuic {
            tokens,
            users,
            auth_timeout: match server.auth_timeout_ms {
                0 => AUTH_TIMEOUT,
                ms => Duration::from_millis(ms),
            },
            max_packet: frame - overhead,
            config,
            _certs: tls.certs,
        })
    }

    fn serves(&self, version: Version) -> bool {
        match version {
            Version::V4 => !self.tokens.is_empty(),
            Version::V5 => !self.users.is_empty(),
        }
    }

    fn max_packet(&self, version: Version) -> usize {
        match version {
            Version::V4 => self.max_packet,
            Version::V5 => self.max_packet.min(MAX_FRAG_V5),
        }
    }

    /// The `IN-USER` of a credential that passes: none for a v4 token.
    fn check(&self, credential: &Credential, conn: &quinn::Connection) -> Option<Option<Arc<str>>> {
        match credential {
            Credential::V4 { token } => self.tokens.contains(token).then_some(None),
            Credential::V5 { uuid, token } => {
                let (password, name) = self.users.get(uuid)?;
                let mut expected = [0u8; 32];
                conn.export_keying_material(&mut expected, uuid, password.as_bytes())
                    .ok()?;
                (expected == *token).then(|| Some(name.clone()))
            }
        }
    }
}

impl EndpointService for Tuic {
    fn run(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        current: watch::Receiver<Current>,
    ) -> std::io::Result<ServeFuture> {
        quic::run(self, socket, current)
    }
}

impl QuicServer for Tuic {
    fn config(&self) -> quinn::ServerConfig {
        self.config.clone()
    }

    fn obfs(&self) -> &ObfsSpec {
        &ObfsSpec::None
    }

    fn connection(
        self: Arc<Self>,
        incoming: Incoming,
        peer: Peer,
        cx: Arc<InboundCx>,
    ) -> ServeFuture {
        Box::pin(async move {
            let Ok(connecting) = incoming.accept() else {
                return;
            };
            let Ok((conn, established)) = connecting.into_0rtt() else {
                return;
            };
            let conn = Arc::new(Conn {
                server: self,
                conn,
                peer,
                cx,
                auth: watch::channel(Auth::Pending).0,
                sessions: Sessions::default(),
            });
            let timer = deadlines(
                established,
                conn.server.auth_timeout,
                || {
                    if conn.decide(Auth::Failed) {
                        conn.conn
                            .close(VarInt::from_u32(AUTH_TIMED_OUT), b"AuthenticationTimeout");
                    }
                },
                || conn.conn.close(VarInt::from_u32(0), b""),
            );
            tokio::join!(timer, conn.bidi(), conn.uni(), conn.datagrams());
            conn.sessions.clear();
        })
    }
}

/// mihomo's timers (`transport/tuic/server.go:80-110`): the authentication timeout counts
/// from the end of the handshake or from [`quic::HANDSHAKE_IDLE`], whichever comes first,
/// and a handshake not ended by [`quic::HANDSHAKE_LIMIT`] ends the connection, as quic-go's
/// does.
async fn deadlines(
    established: impl Future,
    auth_timeout: Duration,
    auth_expired: impl FnOnce(),
    handshake_expired: impl FnOnce(),
) {
    let mut established = std::pin::pin!(established);
    let unfinished = tokio::time::timeout(quic::HANDSHAKE_IDLE, &mut established)
        .await
        .is_err();
    let auth = async {
        tokio::time::sleep(auth_timeout).await;
        auth_expired();
    };
    let handshake = async {
        let rest = quic::HANDSHAKE_LIMIT.saturating_sub(quic::HANDSHAKE_IDLE);
        if unfinished && tokio::time::timeout(rest, established).await.is_err() {
            handshake_expired();
        }
    };
    tokio::join!(auth, handshake);
}

#[derive(Clone)]
enum Auth {
    Pending,
    Passed(Version, Option<Arc<str>>),
    Failed,
}

/// One client connection: mihomo's `serverHandler`, with its v4 and v5 handlers sharing
/// the outcome of the one authentication a connection makes.
struct Conn {
    server: Arc<Tuic>,
    conn: quinn::Connection,
    peer: Peer,
    cx: Arc<InboundCx>,
    auth: watch::Sender<Auth>,
    sessions: Sessions<Address>,
}

impl Conn {
    /// Whether `outcome` is the first, which stands.
    fn decide(&self, outcome: Auth) -> bool {
        self.auth.send_if_modified(|auth| {
            let pending = matches!(auth, Auth::Pending);
            if pending {
                *auth = outcome;
            }
            pending
        })
    }

    /// The `IN-USER` once the connection has authenticated with `version`; `None` when it
    /// failed or authenticated with the other one.
    async fn authed(&self, version: Version) -> Option<Option<Arc<str>>> {
        let mut auth = self.auth.subscribe();
        let decided = auth
            .wait_for(|auth| !matches!(auth, Auth::Pending))
            .await
            .ok()?
            .clone();
        match decided {
            Auth::Passed(passed, user) if passed == version => Some(user),
            _ => None,
        }
    }

    fn version(&self, byte: Option<&u8>) -> Option<Version> {
        Version::of(*byte?).filter(|version| self.server.serves(*version))
    }

    async fn bidi(self: &Arc<Self>) {
        while let Ok((send, recv)) = self.conn.accept_bi().await {
            self.cx.tasks.spawn(self.clone().connect(send, recv));
        }
    }

    async fn connect(self: Arc<Self>, mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
        let head = bounded(async {
            let mut head = [0u8; 2];
            recv.read_exact(&mut head).await.ok()?;
            let version = self.version(head.first())?;
            if head.get(1) != Some(&CMD_CONNECT) {
                return None;
            }
            Some((version, wire::read_addr(&mut recv).await.ok()?))
        });
        let Some((version, dst)) = head.await else {
            return;
        };
        let Some(user) = self.authed(version).await else {
            return;
        };
        if version == Version::V4
            && send
                .write_all(&[version.byte(), CMD_RESPONSE, SUCCEEDED])
                .await
                .is_err()
        {
            return;
        }
        let inbound = self.cx.inbound(InboundKind::Tuic, self.peer.local, user);
        let stream = concord_quic::QuicStream::new(send, recv, Box::new(()));
        flows::tcp(Box::new(stream), dst, inbound, self.peer, &self.cx);
    }

    async fn uni(self: &Arc<Self>) {
        while let Ok(mut recv) = self.conn.accept_uni().await {
            let conn = self.clone();
            self.cx.tasks.spawn(async move {
                let Ok(data) = recv.read_to_end(MAX_STREAM_PACKET).await else {
                    return;
                };
                conn.command(Bytes::from(data), false).await;
            });
        }
    }

    async fn datagrams(self: &Arc<Self>) {
        while let Ok(datagram) = self.conn.read_datagram().await {
            if matches!(*self.auth.borrow(), Auth::Pending) {
                let conn = self.clone();
                self.cx
                    .tasks
                    .spawn(async move { conn.command(datagram, true).await });
            } else {
                self.command(datagram, true).await;
            }
        }
    }

    async fn command(self: &Arc<Self>, input: Bytes, native: bool) {
        let Some(version) = self.version(input.first()) else {
            return;
        };
        match wire::parse_command(version, &input) {
            Ok(Command::Auth(credential)) if !native => {
                match self.server.check(&credential, &self.conn) {
                    Some(user) => {
                        self.decide(Auth::Passed(version, user));
                    }
                    None => {
                        if self.decide(Auth::Failed) {
                            self.conn
                                .close(VarInt::from_u32(AUTH_FAILED), b"AuthenticationFailed");
                        }
                    }
                }
            }
            Ok(Command::Packet(packet)) => {
                if let Some(user) = self.authed(version).await {
                    self.relay(version, packet, native, user);
                }
            }
            Ok(Command::Dissociate(assoc)) if !native => self.sessions.remove(assoc),
            _ => {}
        }
    }

    /// Hands a datagram to its association, which the first datagram of it opens. Replies
    /// go back the way that one came, in pieces no larger than the server's limit.
    fn relay(
        self: &Arc<Self>,
        version: Version,
        packet: Relayed,
        native: bool,
        user: Option<Arc<str>>,
    ) {
        let assoc = packet.assoc;
        if let Some((_, inbox)) = self
            .sessions
            .register(|taken| (!taken(assoc)).then_some(assoc))
        {
            let relay = Relay {
                version,
                native,
                max_packet: self.server.max_packet(version),
            };
            let session = Arc::new(Association {
                sender: Sender::new(assoc, relay, &self.conn, &self.cx.tasks),
                inbox: Mutex::new(inbox),
                closed: AtomicBool::new(false),
            });
            let inbound = self.cx.inbound(InboundKind::Tuic, self.peer.local, user);
            self.cx.tasks.spawn(packets::serve_session(
                session,
                inbound,
                self.peer.src,
                self.cx.clone(),
            ));
        }
        self.sessions.deliver(assoc, packet.part, Some);
    }
}

/// One UDP association of a client; a Dissociate ends it, as does the connection.
struct Association {
    sender: Sender,
    inbox: Mutex<Inbox>,
    closed: AtomicBool,
}

impl PacketSession for Association {
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(self.sender.send(pkt.as_slice(), dst))
    }

    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
        match lock(&self.inbox).poll_recv(cx) {
            Poll::Ready(Some((from, data))) => {
                buf.extend_from_slice(&data);
                Poll::Ready(Ok(from))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.sender.close();
    }
}

#[cfg(test)]
mod tests {
    use concord_config::listener::TuicServer;
    use indexmap::IndexMap;

    use super::super::quic_testing::{
        Running, close_and_drain, close_code, tls_setup, unnamed_tls,
    };
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn config() -> TuicServer {
        TuicServer {
            tokens: vec!["token".to_owned()],
            users: IndexMap::from([(UUID.to_owned(), "pw".to_owned())]),
            tls: unnamed_tls(),
            alpn: Vec::new(),
            congestion: String::new(),
            cwnd: 0,
            bbr_profile: String::new(),
            max_idle_ms: 0,
            auth_timeout_ms: 300,
            max_udp_relay_packet: 0,
        }
    }

    fn running() -> Running {
        Running::start(Arc::new(Tuic::new(&config(), tls_setup()).unwrap()))
    }

    async fn send_uni(conn: &quinn::Connection, command: &[u8]) {
        let mut send = conn.open_uni().await.unwrap();
        send.write_all(command).await.unwrap();
        send.finish().unwrap();
    }

    fn auth_v5(conn: &quinn::Connection, password: &str) -> Vec<u8> {
        let uuid = *uuid::Uuid::parse_str(UUID).unwrap().as_bytes();
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &uuid, password.as_bytes())
            .unwrap();
        wire::auth_v5(&uuid, &token)
    }

    async fn open_connect(
        conn: &quinn::Connection,
        version: Version,
    ) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut send, recv) = conn.open_bi().await.unwrap();
        let dst = Address::new("1.2.3.4", 80);
        send.write_all(&wire::connect(version, &dst).unwrap())
            .await
            .unwrap();
        (send, recv)
    }

    #[tokio::test]
    async fn a_connection_waits_for_its_version_to_authenticate_and_names_its_user() {
        let running = running();
        let v5 = running.connect(b"h3").await;
        let _early = open_connect(&v5, Version::V5).await;
        send_uni(&v5, &auth_v5(&v5, "pw")).await;
        let opened = running.flows.wait_for(1).await;
        assert_eq!(opened.first().unwrap().1.as_deref(), Some(UUID));
        let _other = open_connect(&v5, Version::V4).await;

        let v4 = running.connect(b"h3").await;
        send_uni(&v4, &wire::auth_v4(blake3::hash(b"token").as_bytes())).await;
        let (_send, mut recv) = open_connect(&v4, Version::V4).await;
        let mut response = [0u8; 3];
        recv.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [4, CMD_RESPONSE, SUCCEEDED]);
        let opened = running.flows.wait_for(2).await;
        assert_eq!(opened.get(1).unwrap().1, None);
        assert_eq!(
            running.flows.opened().len(),
            2,
            "a v4 connect on a v5 connection"
        );
    }

    #[tokio::test]
    async fn a_wrong_token_closes_with_the_failure_code_and_serves_nothing() {
        let running = running();
        let conn = running.connect(b"h3").await;
        let _early = open_connect(&conn, Version::V5).await;
        send_uni(&conn, &auth_v5(&conn, "wrong")).await;
        assert_eq!(close_code(&conn).await, u64::from(AUTH_FAILED));
        assert_eq!(running.flows.opened(), []);
    }

    #[tokio::test]
    async fn only_an_auth_on_a_stream_authenticates_before_the_timeout_closes() {
        let running = running();
        let conn = running.connect(b"h3").await;
        let _early = open_connect(&conn, Version::V5).await;
        conn.send_datagram(Bytes::from(auth_v5(&conn, "pw")))
            .unwrap();
        assert_eq!(close_code(&conn).await, u64::from(AUTH_TIMED_OUT));
        assert_eq!(running.flows.opened(), []);
    }

    #[tokio::test]
    async fn a_stopped_listener_frees_its_port_while_a_udp_reply_is_kept() {
        let running = running();
        let conn = running.connect(b"h3").await;
        send_uni(&conn, &auth_v5(&conn, "pw")).await;
        let dst = Address::new("1.2.3.4", 53);
        let packet = wire::packet(
            Version::V5,
            &wire::Fragment {
                assoc: 7,
                packet: 0,
                total: 1,
                id: 0,
                addr: Some(&dst),
                data: b"query",
            },
        )
        .unwrap();
        conn.send_datagram(Bytes::from(packet)).unwrap();
        running.flows.datagrams(1).await;
        close_and_drain(&conn).await;
        running.stop_and_rebind().await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_auth_timer_starts_when_the_handshake_ends_or_stalls() {
        let auth = Duration::from_secs(1);
        for (handshake, auth_at, ended_at) in [
            (Some(Duration::from_secs(2)), Duration::from_secs(3), None),
            (
                None,
                quic::HANDSHAKE_IDLE + auth,
                Some(quic::HANDSHAKE_LIMIT),
            ),
        ] {
            let start = tokio::time::Instant::now();
            let established = async {
                match handshake {
                    Some(after) => tokio::time::sleep(after).await,
                    None => std::future::pending().await,
                }
            };
            let (expired, ended) = (Mutex::new(None), Mutex::new(None));
            deadlines(
                established,
                auth,
                || *lock(&expired) = Some(start.elapsed()),
                || *lock(&ended) = Some(start.elapsed()),
            )
            .await;
            assert_eq!(*lock(&expired), Some(auth_at));
            assert_eq!(*lock(&ended), ended_at);
        }
    }

    #[test]
    fn a_client_may_open_a_bounded_number_of_streams_at_once() {
        let tuic = Tuic::new(&config(), tls_setup()).unwrap();
        let transport = format!("{:?}", tuic.config.transport);
        let bound = VarInt::from_u64(SERVER_STREAMS).unwrap();
        for direction in ["bidi", "uni"] {
            let field = format!("max_concurrent_{direction}_streams: {bound:?},");
            assert!(transport.contains(&field), "{field} not in {transport}");
        }
    }
}
