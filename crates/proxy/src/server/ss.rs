//! mihomo's shadowsocks listener (`listener/sing_shadowsocks/server.go`), on the vendored
//! crate's server halves.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use concord_common::serve::{
    DatagramSeal, DatagramService, InboundCx, Opened, Peer, ServeFuture, StreamService,
};
use concord_common::{
    Address, BoxStream, ClockOffset, InboundKind, PacketBuf, PeekedStream, Stream,
};
use concord_config::listener::SsServer;
use shadowsocks::config::{ServerType, ServerUser, ServerUserManager};
use shadowsocks::context::{Context as SsContext, SharedContext};
use shadowsocks::crypto::{CipherCategory, CipherKind};
use shadowsocks::relay::socks5::Address as SsAddress;
use shadowsocks::relay::tcprelay::proxy_stream::server::ProxyServerStream;
use shadowsocks::relay::udprelay::crypto_io::{decrypt_client_payload, encrypt_server_payload};
use shadowsocks::relay::udprelay::options::UdpSocketControlData;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::mux::{Mux, MuxServe};
use super::shadowtls::ShadowFront;
use super::{ServerError, bounded, flows, user};
use crate::ss::crypto::{SsKey, parse_method};
use crate::ss::window::SlidingWindow;
use crate::util::lock;

/// sing's `UDPTimeout`, the idle time after which mihomo forgets a UDP session.
const UDP_SESSION_IDLE: Duration = Duration::from_secs(5 * 60);
/// The AEAD-2022 sessions a listener holds; sing-shadowsocks bounds its table by age only.
const MAX_SESSIONS: usize = 16_384;
/// A session unseen this long has sent no packet that would still pass the timestamp
/// check, which takes a stamp up to 30 whole seconds either side of the clock's whole
/// seconds (sing-shadowsocks `shadowaead_2022/service.go:481-482`): a packet that arrived
/// at `t` was stamped by `floor(t) + 30` and passes until just before `floor(t) + 61`.
const REPLAY_WINDOW: Duration = Duration::from_secs(61);

enum Keys {
    One(Bytes),
    /// Legacy AEAD users: nothing in a request names its user, so each key is tried.
    Tried(Vec<(Option<Arc<str>>, Bytes)>),
    /// AEAD-2022 identity headers name the user under the server's PSK.
    Identified {
        psk: Bytes,
        manager: Arc<ServerUserManager>,
    },
}

pub(super) struct Ss {
    kind: CipherKind,
    context: SharedContext,
    sealer: Sealer,
    keys: Keys,
    kept: Arc<Kept>,
    mux: Arc<MuxServe>,
}

/// What a listener's server hands to the one a reload builds: the salts its context has
/// seen and its AEAD-2022 UDP sessions with their packet windows.
pub(super) struct Kept {
    context: SharedContext,
    sessions: Mutex<Sessions>,
}

impl Default for Kept {
    fn default() -> Self {
        Kept {
            context: SsContext::new_shared(ServerType::Server),
            sessions: Mutex::default(),
        }
    }
}

/// An AEAD-2022 server installs `clock` for the vendored crate's timestamps, which is
/// process-wide and the same one its clients install, as mihomo hands `ntp.Now` to its
/// 2022 services (`v1.19.33` `listener/sing_shadowsocks/server.go:79`; `:89` and `:264`,
/// for users, at `fea29264`).
pub(super) fn build(
    server: &SsServer,
    kept: &Arc<Kept>,
    clock: &Arc<ClockOffset>,
) -> Result<Arc<Ss>, ServerError> {
    let kind = parse_method(&server.cipher)?;
    if kind.is_aead_2022() {
        let clock = clock.clone();
        shadowsocks::relay::tcprelay::set_clock(Box::new(move || clock.now()));
    }
    let key = |password: &str| -> Result<Bytes, ServerError> {
        Ok(Bytes::copy_from_slice(SsKey::new(kind, password)?.key()))
    };
    let keys = if server.users.is_empty() {
        Keys::One(key(&server.password)?)
    } else {
        match kind.category() {
            CipherCategory::Aead if server.password.is_empty() => Keys::Tried(
                server
                    .users
                    .iter()
                    .map(|(name, password)| Ok((user(name), key(password)?)))
                    .collect::<Result<_, ServerError>>()?,
            ),
            CipherCategory::Aead => {
                return Err(ServerError::Invalid(format!(
                    "shadowsocks: password must be empty when users is set for method: {}",
                    server.cipher
                )));
            }
            CipherCategory::Aead2022 if !server.cipher.contains("chacha") => {
                let mut manager = ServerUserManager::new();
                for (name, password) in &server.users {
                    manager.add_user(
                        ServerUser::with_encoded_key(name.as_str(), password).map_err(|err| {
                            ServerError::Invalid(format!("shadowsocks: user {name}: {err}"))
                        })?,
                    );
                }
                Keys::Identified {
                    psk: key(&server.password)?,
                    manager: Arc::new(manager),
                }
            }
            _ => {
                return Err(ServerError::Invalid(format!(
                    "shadowsocks: users is not supported for method: {}",
                    server.cipher
                )));
            }
        }
    };
    let context = kept.context.clone();
    Ok(Arc::new(Ss {
        kind,
        sealer: Sealer {
            kind,
            context: context.clone(),
        },
        context,
        keys,
        kept: kept.clone(),
        mux: MuxServe::new(&server.mux),
    }))
}

impl Ss {
    /// The key whose first length chunk opens, with what the trial read.
    async fn tried(
        &self,
        users: &[(Option<Arc<str>>, Bytes)],
        stream: &mut BoxStream,
    ) -> Option<(Option<Arc<str>>, Bytes, Vec<u8>)> {
        let salt = self.kind.salt_len();
        let mut head = vec![0u8; salt + 2 + self.kind.tag_len()];
        stream.read_exact(&mut head).await.ok()?;
        let (nonce, chunk) = head.split_at(salt);
        users.iter().find_map(|(name, key)| {
            let mut trial = chunk.to_vec();
            let mut cipher = shadowsocks::crypto::v1::Cipher::new(self.kind, key, nonce);
            cipher
                .decrypt_packet(&mut trial)
                .then(|| (name.clone(), key.clone(), head.clone()))
        })
    }

    async fn handshake(
        &self,
        mut stream: BoxStream,
    ) -> Option<(SsStream, Address, Option<Arc<str>>)> {
        let (mut server, named) = match &self.keys {
            Keys::One(key) => (
                ProxyServerStream::from_stream(self.context.clone(), stream, self.kind, key),
                None,
            ),
            Keys::Tried(users) => {
                let (name, key, head) = self.tried(users, &mut stream).await?;
                let replayed: BoxStream = Box::new(PeekedStream::new(head, stream));
                let server =
                    ProxyServerStream::from_stream(self.context.clone(), replayed, self.kind, &key);
                (server, name)
            }
            Keys::Identified { psk, manager } => (
                ProxyServerStream::from_stream_with_user_manager(
                    self.context.clone(),
                    stream,
                    self.kind,
                    psk,
                    Some(manager.clone()),
                ),
                None,
            ),
        };
        let dst = server.handshake().await.ok()?;
        let named = match (&self.keys, server.user_key()) {
            (Keys::Identified { manager, .. }, Some(key)) => manager
                .users_iter()
                .find(|candidate| candidate.key() == key)
                .and_then(|candidate| user(candidate.name())),
            _ => named,
        };
        Some((SsStream(server), from_ss(dst), named))
    }
}

fn from_ss(addr: SsAddress) -> Address {
    match addr {
        SsAddress::SocketAddress(addr) => Address::Socket(addr),
        SsAddress::DomainNameAddress(host, port) => Address::new(&host, port),
    }
}

fn to_ss(addr: &Address) -> SsAddress {
    match addr {
        Address::Socket(addr) => SsAddress::SocketAddress(*addr),
        Address::Domain(host, port) => SsAddress::DomainNameAddress(host.to_string(), *port),
    }
}

impl StreamService for Ss {
    fn serve(self: Arc<Self>, stream: TcpStream, peer: Peer, cx: Arc<InboundCx>) -> ServeFuture {
        let mux = Mux::over(&self.mux, &stream);
        Box::pin(self.serve_stream(Box::new(stream), None, peer, cx, mux))
    }
}

impl Ss {
    /// A request's own user wins over `signed` (`listener/sing_shadowsocks/server.go:320-330`).
    async fn serve_stream(
        self: Arc<Self>,
        stream: BoxStream,
        signed: Option<Arc<str>>,
        peer: Peer,
        cx: Arc<InboundCx>,
        mux: Mux,
    ) {
        let Some((stream, dst, named)) = bounded(self.handshake(stream)).await else {
            return;
        };
        let inbound = cx.inbound(InboundKind::Shadowsocks, peer.local, named.or(signed));
        flows::tcp(Box::new(stream), dst, inbound, peer, &cx, &mux);
    }
}

pub(super) struct Shadowed(pub(super) Arc<ShadowFront>, pub(super) Arc<Ss>);

impl StreamService for Shadowed {
    fn serve(self: Arc<Self>, stream: TcpStream, peer: Peer, cx: Arc<InboundCx>) -> ServeFuture {
        let ss = self.1.clone();
        let mux = Mux::over(&ss.mux, &stream);
        self.0
            .clone()
            .serve(stream, peer.src, cx, move |stream, signed, cx| {
                ss.serve_stream(stream, signed, peer, cx, mux)
            });
        Box::pin(async {})
    }
}

struct SsStream(ProxyServerStream<BoxStream>);

impl AsyncRead for SsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The cipher hides what the stream beneath could hand out.
impl Stream for SsStream {
    concord_common::stream_policy!(default: all);
}

/// A client's AEAD-2022 session as the server answers it: the server's own session id and
/// packet counter, under the key the client's packets opened with, and the client's packet
/// ids it accepted, each once (SIP022; sing-shadowsocks `shadowaead_2022/service.go:449`,
/// `:463`).
struct Session {
    conn: u64,
    client_session_id: u64,
    server_session_id: u64,
    packet_id: AtomicU64,
    user: Option<Arc<ServerUser>>,
    key: Bytes,
    sealer: Sealer,
    received: Mutex<SlidingWindow>,
}

impl Session {
    fn receive(&self, packet_id: u64) -> bool {
        let mut received = lock(&self.received);
        let fresh = received.check(packet_id);
        if fresh {
            received.add(packet_id);
        }
        fresh
    }
}

/// A session's id with the cipher and the key its packets opened with, so two users or two
/// ciphers never share a session. The client's address is not part of it: a session keeps
/// its packet window wherever its packets come from, as sing-shadowsocks keys its sessions
/// by id (`shadowaead_2022/service.go:57`, `:429`).
type SessionKey = (u64, CipherKind, Bytes);

/// When a session was last seen, made unique by a count.
type Seen = (Instant, u64);

#[derive(Default)]
struct Sessions {
    by_id: HashMap<SessionKey, (Arc<Session>, Seen)>,
    by_seen: BTreeMap<Seen, SessionKey>,
    count: u64,
}

impl Sessions {
    /// The session `id` names, seen at `now`. A new one takes a full table's place only
    /// from a session past the replay window; with none, it is refused, so no session's
    /// packets can be replayed into a new session under its id.
    fn touch(
        &mut self,
        id: SessionKey,
        now: Instant,
        make: impl FnOnce() -> Arc<Session>,
    ) -> Option<Arc<Session>> {
        self.forget_unseen_for(UDP_SESSION_IDLE, now);
        self.count += 1;
        let seen = (now, self.count);
        if let Some((session, at)) = self.by_id.get_mut(&id) {
            self.by_seen.remove(at);
            *at = seen;
            let session = session.clone();
            self.by_seen.insert(seen, id);
            return Some(session);
        }
        if self.by_id.len() >= MAX_SESSIONS {
            let (&(oldest, _), _) = self.by_seen.first_key_value()?;
            if now.duration_since(oldest) < REPLAY_WINDOW {
                return None;
            }
            self.forget_oldest();
        }
        let session = make();
        self.by_id.insert(id.clone(), (session.clone(), seen));
        self.by_seen.insert(seen, id);
        Some(session)
    }

    fn forget_unseen_for(&mut self, idle: Duration, now: Instant) {
        while self
            .by_seen
            .first_key_value()
            .is_some_and(|(&(seen, _), _)| now.duration_since(seen) >= idle)
        {
            self.forget_oldest();
        }
    }

    fn forget_oldest(&mut self) {
        if let Some((_, id)) = self.by_seen.pop_first() {
            self.by_id.remove(&id);
        }
    }
}

/// Replies under a key with no session state: the legacy ciphers and `none`.
struct Stateless {
    key: Bytes,
    sealer: Sealer,
}

impl DatagramSeal for Stateless {
    fn seal(&self, payload: &[u8], from: &Address) -> io::Result<PacketBuf> {
        self.sealer
            .seal(&self.key, &UdpSocketControlData::default(), payload, from)
    }
}

impl DatagramSeal for Session {
    fn seal(&self, payload: &[u8], from: &Address) -> io::Result<PacketBuf> {
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_session_id;
        control.server_session_id = self.server_session_id;
        control.packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed) + 1;
        control.user.clone_from(&self.user);
        self.sealer.seal(&self.key, &control, payload, from)
    }
}

#[derive(Clone)]
struct Sealer {
    kind: CipherKind,
    context: SharedContext,
}

impl Sealer {
    fn seal(
        &self,
        key: &[u8],
        control: &UdpSocketControlData,
        payload: &[u8],
        from: &Address,
    ) -> io::Result<PacketBuf> {
        let mut out = BytesMut::new();
        encrypt_server_payload(
            &self.context,
            self.kind,
            key,
            &to_ss(from),
            control,
            payload,
            &mut out,
        );
        Ok(PacketBuf::from_slice(&out))
    }
}

/// The datagram side of a shadowsocks listener.
pub(super) struct SsDatagrams(pub(super) Arc<Ss>);

impl DatagramService for SsDatagrams {
    fn open(&self, packet: &mut PacketBuf, _client: SocketAddr) -> Option<Opened> {
        let ss = &self.0;
        let (key, name, control, dst) = match &ss.keys {
            Keys::One(key) => {
                let (dst, control) = open_with(ss, key, None, packet)?;
                (key.clone(), None, control, dst)
            }
            Keys::Tried(users) => users.iter().find_map(|(name, key)| {
                let mut trial = PacketBuf::from_slice(packet.as_slice());
                let (dst, control) = open_with(ss, key, None, &mut trial)?;
                *packet = trial;
                Some((key.clone(), name.clone(), control, dst))
            })?,
            Keys::Identified { psk, manager } => {
                let (dst, control) = open_with(ss, psk, Some(manager), packet)?;
                let named = control
                    .as_ref()
                    .and_then(|control| control.user.as_ref())
                    .and_then(|user_of| user(user_of.name()));
                let key = control
                    .as_ref()
                    .and_then(|control| control.user.as_ref())
                    .map_or_else(
                        || psk.clone(),
                        |user_of| Bytes::copy_from_slice(user_of.key()),
                    );
                (key, named, control, dst)
            }
        };
        let (seal, conn): (Arc<dyn DatagramSeal>, u64) = match control {
            Some(control) => {
                let Some(session) = self.session(&control, key) else {
                    tracing::debug!("shadowsocks: no room for a new UDP session");
                    return None;
                };
                if !session.receive(control.packet_id) {
                    return None;
                }
                let conn = session.conn;
                (session, conn)
            }
            None => (
                Arc::new(Stateless {
                    key,
                    sealer: ss.sealer.clone(),
                }),
                0,
            ),
        };
        Some(Opened {
            dst,
            user: name,
            seal,
            conn,
        })
    }
}

impl SsDatagrams {
    fn session(&self, control: &UdpSocketControlData, key: Bytes) -> Option<Arc<Session>> {
        let id = (control.client_session_id, self.0.kind, key.clone());
        lock(&self.0.kept.sessions).touch(id, Instant::now(), || {
            Arc::new(Session {
                conn: concord_common::next_conn(),
                client_session_id: control.client_session_id,
                server_session_id: rand::random(),
                packet_id: AtomicU64::new(0),
                user: control.user.clone(),
                key,
                sealer: self.0.sealer.clone(),
                received: Mutex::default(),
            })
        })
    }
}

fn open_with(
    ss: &Ss,
    key: &[u8],
    manager: Option<&Arc<ServerUserManager>>,
    packet: &mut PacketBuf,
) -> Option<(Address, Option<UdpSocketControlData>)> {
    let (len, dst, control) = decrypt_client_payload(
        &ss.context,
        ss.kind,
        key,
        packet.as_mut_slice(),
        manager.map(Arc::as_ref),
    )
    .ok()?;
    packet.truncate(len);
    Some((from_ss(dst), control))
}

#[cfg(test)]
mod tests {
    use shadowsocks::relay::udprelay::crypto_io::{
        cipher_cache_len, decrypt_server_payload, encrypt_client_payload,
    };

    use super::*;

    const CIPHER: &str = "2022-blake3-aes-128-gcm";
    const IPSK: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";
    const ALICE: &str = "AgICAgICAgICAgICAgICAg==";
    const BOB: &str = "AwMDAwMDAwMDAwMDAwMDAw==";

    const WIDE: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";

    fn key_of(cipher: &str, password: &str) -> Bytes {
        let kind = parse_method(cipher).unwrap();
        Bytes::copy_from_slice(SsKey::new(kind, password).unwrap().key())
    }

    fn key(password: &str) -> Bytes {
        key_of(CIPHER, password)
    }

    fn server(users: &[(&str, &str)], kept: &Arc<Kept>) -> SsDatagrams {
        server_of(CIPHER, IPSK, users, kept)
    }

    fn server_of(
        cipher: &str,
        password: &str,
        users: &[(&str, &str)],
        kept: &Arc<Kept>,
    ) -> SsDatagrams {
        let mut def = SsServer {
            cipher: cipher.into(),
            password: password.into(),
            users: Default::default(),
            udp: true,
            shadow_tls: None,
            mux: Default::default(),
        };
        for (name, password) in users {
            def.users.insert((*name).into(), (*password).into());
        }
        SsDatagrams(build(&def, kept, &Arc::default()).unwrap())
    }

    fn packet(password: &str, identities: &[Bytes], packet_id: u64) -> PacketBuf {
        packet_of(CIPHER, password, identities, packet_id)
    }

    fn packet_of(cipher: &str, password: &str, identities: &[Bytes], packet_id: u64) -> PacketBuf {
        let context = SsContext::new_shared(ServerType::Local);
        let mut control = UdpSocketControlData::default();
        control.client_session_id = 7;
        control.packet_id = packet_id;
        let mut out = BytesMut::new();
        encrypt_client_payload(
            &context,
            parse_method(cipher).unwrap(),
            &key_of(cipher, password),
            &SsAddress::SocketAddress("1.1.1.1:53".parse().unwrap()),
            &control,
            identities,
            b"query",
            &mut out,
        );
        PacketBuf::from_slice(&out)
    }

    fn client() -> SocketAddr {
        "127.0.0.1:5353".parse().unwrap()
    }

    #[test]
    fn an_aead_2022_packet_id_passes_once_and_still_after_a_reload() {
        let kept = Arc::default();
        let first = server(&[], &kept);
        for (id, fresh) in [(1, true), (1, false), (3, true), (2, true), (3, false)] {
            let opened = first.open(&mut packet(IPSK, &[], id), client());
            assert_eq!(opened.is_some(), fresh, "packet {id}");
        }
        let reloaded = server(&[], &kept);
        assert!(reloaded.open(&mut packet(IPSK, &[], 2), client()).is_none());
        assert!(reloaded.open(&mut packet(IPSK, &[], 4), client()).is_some());
    }

    #[test]
    fn two_users_behind_one_address_and_session_id_get_their_own_sessions() {
        let ss = server(&[("alice", ALICE), ("bob", BOB)], &Arc::default());
        let context = SsContext::new_shared(ServerType::Local);
        for (name, password) in [("alice", ALICE), ("bob", BOB)] {
            let mut sent = packet(password, &[key(IPSK)], 1);
            let opened = ss.open(&mut sent, client()).expect(name);
            assert_eq!(opened.user.as_deref(), Some(name));
            let reply = opened
                .seal
                .seal(b"answer", &Address::Socket("1.1.1.1:53".parse().unwrap()))
                .unwrap();
            let mut reply = reply.as_slice().to_vec();
            let kind = parse_method(CIPHER).unwrap();
            let (len, _, _) =
                decrypt_server_payload(&context, kind, &key(password), &mut reply).expect(name);
            assert_eq!(reply.get(..len), Some(&b"answer"[..]));
        }
    }

    #[test]
    fn a_session_is_its_id_wherever_its_packets_come_from() {
        let ss = server(&[], &Arc::default());
        let moved: SocketAddr = "127.0.0.1:6464".parse().unwrap();
        let first = ss.open(&mut packet(IPSK, &[], 1), client()).unwrap();
        assert!(ss.open(&mut packet(IPSK, &[], 1), moved).is_none());
        let roamed = ss.open(&mut packet(IPSK, &[], 2), moved).unwrap();
        assert_ne!(first.conn, 0);
        assert_eq!(roamed.conn, first.conn);
    }

    #[test]
    fn a_cipher_changed_under_the_same_key_seals_with_the_new_cipher() {
        let kept = Arc::default();
        let context = SsContext::new_shared(ServerType::Local);
        let mut conns = Vec::new();
        for cipher in ["2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"] {
            let ss = server_of(cipher, WIDE, &[], &kept);
            let opened = ss
                .open(&mut packet_of(cipher, WIDE, &[], 1), client())
                .expect(cipher);
            conns.push(opened.conn);
            let reply = opened
                .seal
                .seal(b"answer", &Address::Socket("1.1.1.1:53".parse().unwrap()))
                .unwrap();
            let mut reply = reply.as_slice().to_vec();
            let kind = parse_method(cipher).unwrap();
            decrypt_server_payload(&context, kind, &key_of(cipher, WIDE), &mut reply)
                .expect(cipher);
        }
        assert_ne!(conns[0], conns[1]);
    }

    #[test]
    fn datagrams_that_do_not_open_leave_no_cipher_and_a_session_keeps_its_one() {
        let before = cipher_cache_len();
        for (cipher, password) in [(CIPHER, IPSK), ("2022-blake3-chacha20-poly1305", WIDE)] {
            let ss = server_of(cipher, password, &[], &Arc::default());
            for _ in 0..1000 {
                let mut junk = PacketBuf::from_slice(&rand::random::<[u8; 96]>());
                assert!(ss.open(&mut junk, client()).is_none());
            }
            assert_eq!(cipher_cache_len(), before, "{cipher}");
        }
        let ss = server(&[], &Arc::default());
        // Sealed on a thread of its own, so this thread's cache holds only what opening adds.
        let sealed = std::thread::spawn(|| {
            (1..=3)
                .map(|id| packet(IPSK, &[], id).as_slice().to_vec())
                .collect::<Vec<_>>()
        });
        for sealed in sealed.join().unwrap() {
            assert!(
                ss.open(&mut PacketBuf::from_slice(&sealed), client())
                    .is_some()
            );
            assert_eq!(cipher_cache_len(), before + 1);
        }
    }

    #[test]
    fn a_full_table_takes_a_new_session_only_in_place_of_one_past_the_replay_window() {
        let mut sessions = Sessions::default();
        let start = Instant::now();
        let sealer = server(&[], &Arc::default()).0.sealer.clone();
        let make = |id: u64| {
            let sealer = sealer.clone();
            move || {
                Arc::new(Session {
                    conn: id,
                    client_session_id: id,
                    server_session_id: 0,
                    packet_id: AtomicU64::new(0),
                    user: None,
                    key: Bytes::new(),
                    sealer,
                    received: Mutex::default(),
                })
            }
        };
        let key = |id: u64| (id, parse_method(CIPHER).unwrap(), Bytes::new());
        let full = MAX_SESSIONS as u64;
        for id in 0..full {
            assert!(sessions.touch(key(id), start, make(id)).is_some());
        }
        let busy = start + REPLAY_WINDOW - Duration::from_secs(1);
        assert!(sessions.touch(key(full), busy, make(full)).is_none());
        assert_eq!(sessions.touch(key(0), busy, make(0)).unwrap().conn, 0);

        let later = start + REPLAY_WINDOW;
        assert!(sessions.touch(key(full), later, make(full)).is_some());
        assert_eq!(sessions.by_id.len(), MAX_SESSIONS);
        assert!(
            sessions.by_id.contains_key(&key(0)),
            "the one seen since stays"
        );
        assert!(
            !sessions.by_id.contains_key(&key(1)),
            "the oldest unseen one goes"
        );

        sessions.touch(key(0), start + UDP_SESSION_IDLE + REPLAY_WINDOW, make(0));
        assert_eq!(sessions.by_id.len(), 1);
        assert_eq!(sessions.by_seen.len(), 1);
    }
}
