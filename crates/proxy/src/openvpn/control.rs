use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

use super::config::Config;
use super::data::{DataKey, Keys};
use super::keys::{ClientRecord, Credentials, parse_server};
use super::link::{Link, Reader};
use super::push::{AUTH_PENDING_MAX, Inbox, Message, PUSH_REQUEST, PushReply};
use super::reliable::Reliable;
use super::wire::{
    CONTROL, ControlPacket, HARD_RESET_CLIENT_V2, HARD_RESET_CLIENT_V3, HARD_RESET_SERVER_V1,
    HARD_RESET_SERVER_V2, HEADER_LEN, SOFT_RESET, SessionId, is_control, next_key_id, opcode,
};
use super::wrap::Replay;

const RETRANSMIT: Duration = Duration::from_secs(1);
const TLS_CHUNK: usize = 1100;
const REKEY_TIMEOUT: Duration = Duration::from_secs(30);
const PROMOTE_AFTER: Duration = Duration::from_secs(60);

pub(super) enum Input {
    Reader(Reader),
    Queue(mpsc::Receiver<Vec<u8>>),
}

impl Input {
    async fn next(&mut self, out: &mut Vec<Vec<u8>>) -> io::Result<()> {
        match self {
            Input::Reader(reader) => {
                while out.is_empty() {
                    reader
                        .recv(|raw| {
                            if raw.first().is_some_and(|first| is_control(opcode(*first))) {
                                out.push(raw.to_vec());
                            }
                        })
                        .await?;
                }
            }
            Input::Queue(rx) => {
                let raw = rx
                    .recv()
                    .await
                    .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
                out.push(raw);
                while let Ok(raw) = rx.try_recv() {
                    out.push(raw);
                }
            }
        }
        Ok(())
    }
}

fn unix_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("OpenVPN {what} timed out"))
}

fn tls_error(err: rustls::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("openvpn tls handshake: {err}"),
    )
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The control channel of one tunnel, owned by a single task: the reliable layer, the
/// wrapper, the TLS session of the current key epoch and the pushed options.
pub(super) struct Control {
    config: Arc<Config>,
    link: Arc<Link>,
    input: Input,
    reliable: Reliable,
    replay: Replay,
    send_pid: u32,
    send_time: u32,
    retransmit_at: Option<Instant>,
    tls: Option<ClientConnection>,
    inbox: Inbox,
    username: String,
    password: String,
    push: Option<PushReply>,
    reset: Option<(ControlPacket, Instant)>,
    keys: Option<Arc<ArcSwap<Keys>>>,
    raw: Vec<Vec<u8>>,
}

pub(super) struct Established {
    pub(super) push: PushReply,
    pub(super) key: DataKey,
}

impl Control {
    pub(super) fn new(config: Arc<Config>, link: Arc<Link>, reader: Reader) -> Control {
        let mut local = SessionId::default();
        rand::fill(&mut local);
        Control {
            reliable: Reliable::new(local, config.wrap.is_some()),
            username: config.username.clone(),
            password: config.password.clone(),
            config,
            link,
            input: Input::Reader(reader),
            replay: Replay::default(),
            send_pid: 0,
            send_time: 0,
            retransmit_at: None,
            tls: None,
            inbox: Inbox::default(),
            push: None,
            reset: None,
            keys: None,
            raw: Vec::new(),
        }
    }

    /// Hands the server reader to the data path; control packets then come through `queue`.
    pub(super) fn attach(
        &mut self,
        keys: Arc<ArcSwap<Keys>>,
        queue: mpsc::Receiver<Vec<u8>>,
    ) -> Option<Reader> {
        self.keys = Some(keys);
        match std::mem::replace(&mut self.input, Input::Queue(queue)) {
            Input::Reader(reader) => Some(reader),
            Input::Queue(_) => None,
        }
    }

    async fn send(&mut self, packet: &ControlPacket) -> io::Result<()> {
        let header = packet.header();
        let plain = packet.plain();
        let mut out = match &self.config.wrap {
            Some(wrap) => {
                if self.send_pid == u32::MAX {
                    return Err(io::Error::other(
                        "openvpn control packet id exhausted; new session required",
                    ));
                }
                if self.send_time == 0 {
                    self.send_time = unix_time();
                }
                self.send_pid += 1;
                wrap.seal(&header, self.send_pid, self.send_time, &plain)?
            }
            None => [&header[..], &plain].concat(),
        };
        if packet.op == HARD_RESET_CLIENT_V3
            && packet.message_id == 0
            && let Some(wrapped) = self.config.wrap.as_deref().and_then(|w| w.wrapped_key())
        {
            out.extend_from_slice(wrapped);
        }
        self.link.send(&out).await
    }

    async fn send_message(&mut self, op: u8, payload: Vec<u8>) -> io::Result<()> {
        let packet = self.reliable.message(op, payload);
        if !self.link.is_tcp() && self.retransmit_at.is_none() {
            self.retransmit_at = Some(Instant::now() + RETRANSMIT);
        }
        self.send(&packet).await
    }

    async fn retransmit(&mut self) -> io::Result<()> {
        let packets = self.reliable.retransmit();
        self.retransmit_at = (!packets.is_empty()).then(|| Instant::now() + RETRANSMIT);
        for packet in &packets {
            self.send(packet).await?;
        }
        Ok(())
    }

    /// Sends what TLS wrote as control messages, then a dedicated ACK for whatever no
    /// message carried.
    async fn flush(&mut self) -> io::Result<()> {
        let mut out = Vec::new();
        if let Some(tls) = &mut self.tls {
            while tls.wants_write() {
                tls.write_tls(&mut out)?;
            }
        }
        for chunk in out.chunks(TLS_CHUNK) {
            self.send_message(CONTROL, chunk.to_vec()).await?;
        }
        if let Some(ack) = self.reliable.ack_packet() {
            self.send(&ack).await?;
        }
        Ok(())
    }

    /// mihomo's control read: a packet counts only from the server's session, on this key
    /// epoch, past the replay check, except the server's first reset and its soft reset of
    /// the next epoch.
    fn accept(&mut self, raw: &[u8]) -> Vec<ControlPacket> {
        let now = Instant::now();
        let opened = match &self.config.wrap {
            Some(wrap) => wrap.open(raw).and_then(|u| {
                ControlPacket::decode(&u.header, &u.plain).map(|p| (p, Some((u.packet_id, u.time))))
            }),
            None => raw
                .split_at_checked(HEADER_LEN)
                .ok_or_else(|| super::wire::malformed("control packet"))
                .and_then(|(header, plain)| {
                    ControlPacket::decode(header, plain).map(|p| (p, None))
                }),
        };
        let Ok((packet, pid)) = opened else {
            return Vec::new();
        };
        if packet.session == SessionId::default()
            || (!packet.acks.is_empty() && packet.ack_session != self.reliable.local)
        {
            return Vec::new();
        }
        let fresh = |replay: &mut Replay| {
            pid.is_none_or(|(id, time)| replay.check(id, time, now.into_std()))
        };
        match self.reliable.remote {
            None => {
                let first = matches!(packet.op, HARD_RESET_SERVER_V2 | HARD_RESET_SERVER_V1)
                    && packet.key_id == self.reliable.key_id
                    && packet.message_id == 0;
                if !first || !fresh(&mut self.replay) {
                    return Vec::new();
                }
                self.reliable.remote = Some(packet.session);
                return self.reliable.receive(packet);
            }
            Some(remote) if remote != packet.session => return Vec::new(),
            Some(_) => {}
        }
        if packet.op == SOFT_RESET
            && packet.key_id == next_key_id(self.reliable.key_id)
            && packet.message_id == 0
        {
            if fresh(&mut self.replay) && self.reset.is_none() {
                self.reset = Some((packet, now));
            }
            return Vec::new();
        }
        if packet.key_id != self.reliable.key_id || !fresh(&mut self.replay) {
            return Vec::new();
        }
        self.reliable.receive(packet)
    }

    fn deliver(&mut self, packet: &ControlPacket) -> io::Result<()> {
        match packet.op {
            HARD_RESET_SERVER_V1 => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "openvpn server replied with unsupported key method 1 reset",
            )),
            CONTROL if !packet.payload.is_empty() => self.feed_tls(&packet.payload),
            _ => Ok(()),
        }
    }

    fn feed_tls(&mut self, mut payload: &[u8]) -> io::Result<()> {
        let Some(tls) = &mut self.tls else {
            return Ok(());
        };
        while !payload.is_empty() {
            if tls.read_tls(&mut payload)? == 0 {
                break;
            }
            tls.process_new_packets().map_err(tls_error)?;
        }
        let mut plain = [0; 4096];
        loop {
            match tls.reader().read(&mut plain) {
                Ok(0) => return Ok(()),
                Ok(len) => self.inbox.extend(plain.get(..len).unwrap_or_default())?,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    }

    /// Waits for packets from the server, the retransmit timer or `deadline`, takes in what
    /// arrived and answers it.
    async fn pump(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        let mut raw = std::mem::take(&mut self.raw);
        raw.clear();
        let retransmit_at = self.retransmit_at;
        tokio::select! {
            got = self.input.next(&mut raw) => got?,
            () = sleep_until(retransmit_at.unwrap_or_else(Instant::now)), if retransmit_at.is_some() => {
                self.raw = raw;
                return self.retransmit().await;
            }
            () = sleep_until(deadline.unwrap_or_else(Instant::now)), if deadline.is_some() => {
                return Err(timed_out("handshake"));
            }
        }
        for datagram in &raw {
            for packet in self.accept(datagram) {
                self.deliver(&packet)?;
            }
        }
        self.raw = raw;
        if self.reliable.unacked() == 0 {
            self.retransmit_at = None;
        }
        self.flush().await
    }

    fn start_tls(&mut self) -> io::Result<()> {
        let name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::UNSPECIFIED).into());
        self.tls = Some(ClientConnection::new(self.config.tls.clone(), name).map_err(tls_error)?);
        self.inbox = Inbox::default();
        Ok(())
    }

    fn write_tls(&mut self, bytes: &[u8]) -> io::Result<()> {
        let tls = self
            .tls
            .as_mut()
            .ok_or_else(|| io::Error::other("OpenVPN TLS session is not open"))?;
        tls.writer().write_all(bytes)
    }

    /// TLS, then key method 2 on the current epoch; returns the derived keys and when the
    /// exchange completed, which anchors AUTH_PENDING.
    async fn key_exchange(
        &mut self,
        deadline: Option<Instant>,
    ) -> io::Result<(super::keys::KeyMaterial, Instant)> {
        self.start_tls()?;
        self.flush().await?;
        while self.tls.as_ref().is_some_and(|tls| tls.is_handshaking()) {
            self.pump(deadline).await?;
        }
        let record = ClientRecord::random();
        let encoded = record.encode(&Credentials {
            options: &self.config.options,
            username: &self.username,
            password: &self.password,
            peer_info: &self.config.peer_info,
        });
        self.write_tls(&encoded)?;
        self.flush().await?;
        let server = loop {
            if let Some((server, used)) = parse_server(self.inbox.buf())? {
                self.inbox.consume(used);
                break server;
            }
            self.pump(deadline).await?;
        };
        let remote = self.reliable.remote.unwrap_or_default();
        Ok((
            record.derive(&server, &self.reliable.local, &remote),
            Instant::now(),
        ))
    }

    /// Reads messages until the final PUSH_REPLY segment. AUTH_PENDING replaces the wait with
    /// its own timeout from `established`; an unfinished continuation waits at most
    /// `continuation` past the segment that announced it.
    async fn read_push(
        &mut self,
        deadline: Option<Instant>,
        established: Instant,
        continuation: Duration,
    ) -> io::Result<PushReply> {
        let mut reply: Option<PushReply> = None;
        let mut pending: Option<Instant> = None;
        let mut continued: Option<Instant> = None;
        loop {
            while let Some(message) = self.inbox.next()? {
                match message {
                    Message::Failed(reason) => {
                        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
                    }
                    Message::AuthPending(timeout) => {
                        pending = Some(established + timeout.min(AUTH_PENDING_MAX))
                    }
                    Message::Push(segment) => {
                        let last = segment.continuation != 2;
                        match &mut reply {
                            Some(reply) => reply.merge(segment),
                            None => reply = Some(segment),
                        }
                        if last {
                            return Ok(reply.unwrap_or_default());
                        }
                        continued.get_or_insert(Instant::now() + continuation);
                    }
                }
            }
            self.pump(earliest(deadline, earliest(pending, continued)))
                .await?;
        }
    }

    fn take_token(&mut self, push: &PushReply) {
        if push.auth_token.is_empty() {
            return;
        }
        if !push.auth_token_user.is_empty() {
            self.username.clone_from(&push.auth_token_user);
        }
        self.password.clone_from(&push.auth_token);
    }

    /// The first handshake: hard reset, TLS, key method 2 and the pushed options.
    pub(super) async fn handshake(&mut self, deadline: Option<Instant>) -> io::Result<Established> {
        let op = if self
            .config
            .wrap
            .as_deref()
            .and_then(|w| w.wrapped_key())
            .is_some()
        {
            HARD_RESET_CLIENT_V3
        } else {
            HARD_RESET_CLIENT_V2
        };
        self.send_message(op, Vec::new()).await?;
        while self.reliable.remote.is_none() {
            self.pump(deadline).await?;
        }
        let (material, established) = self.key_exchange(deadline).await?;
        self.write_tls(PUSH_REQUEST)?;
        self.flush().await?;
        let push = self.read_push(deadline, established, REKEY_TIMEOUT).await?;
        if push.prefixes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "openvpn push reply missing ifconfig address",
            ));
        }
        let cipher = self.config.negotiate(&push.data_ciphers, &push.cipher)?;
        let key = DataKey::new(
            &material,
            cipher,
            self.config.digest,
            push.peer_id,
            self.reliable.key_id,
        )?;
        self.take_token(&push);
        self.push = Some(push.clone());
        Ok(Established { push, key })
    }

    /// The established channel: answers the server, takes in auth-token updates and runs
    /// each rekey the server starts. Returns only on failure.
    pub(super) async fn run(mut self) -> io::Result<()> {
        loop {
            self.on_messages()?;
            if let Some((reset, accepted)) = self.reset.take() {
                self.rekey(reset, accepted).await?;
            }
            self.pump(None).await?;
        }
    }

    fn on_messages(&mut self) -> io::Result<()> {
        while let Some(message) = self.inbox.next()? {
            match message {
                Message::Failed(reason) => {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
                }
                Message::AuthPending(_) => {}
                Message::Push(update) => {
                    self.take_token(&update);
                    if let Some(push) = &mut self.push {
                        push.merge(update);
                    }
                }
            }
        }
        Ok(())
    }

    /// mihomo's `renegotiate`: adopt the server's new key epoch, answer with a soft reset,
    /// and run TLS and key method 2 on it while the old keys keep carrying data.
    async fn rekey(&mut self, reset: ControlPacket, accepted: Instant) -> io::Result<()> {
        let keys = self
            .keys
            .clone()
            .ok_or_else(|| io::Error::other("OpenVPN data keys are not installed"))?;
        let lame_until = accepted + self.config.transition;
        keys.store(Arc::new(keys.load().rekeying(lame_until.into_std())));
        self.reliable.begin_epoch(reset.key_id);
        self.reliable.delivered(reset.message_id);
        self.retransmit_at = None;
        self.send_message(SOFT_RESET, Vec::new()).await?;
        let deadline = Instant::now() + REKEY_TIMEOUT;
        let (material, established) = self.key_exchange(Some(deadline)).await?;
        let push = self
            .push
            .clone()
            .ok_or_else(|| io::Error::other("OpenVPN rekey before the first push"))?;
        let cipher = self.config.negotiate(&push.data_ciphers, &push.cipher)?;
        let key = DataKey::new(
            &material,
            cipher,
            self.config.digest,
            push.peer_id,
            self.reliable.key_id,
        )?;
        let promote_at = accepted + PROMOTE_AFTER;
        keys.store(Arc::new(keys.load().rekeyed(
            Arc::new(key),
            lame_until.into_std(),
            promote_at.into_std(),
        )));
        tracing::debug!(
            "openvpn rekey to key id {} done in {:?}",
            self.reliable.key_id,
            established.saturating_duration_since(accepted)
        );
        Ok(())
    }
}
