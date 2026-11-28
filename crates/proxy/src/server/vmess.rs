//! sing-vmess's `Service.NewConnection` for AEAD requests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use concord_common::serve::{InboundCx, Peer, ServeFuture};
use concord_common::{Address, BoxStream, ClockOffset, InboundKind};
use concord_config::listener::VmessUser;
use tokio::io::{AsyncReadExt, BufReader};

use super::flows::{self, PACKET_ADDR_MAGIC};
use super::front::Conn;
use super::mux::{Mux, MuxServe};
use super::muxcool;
use super::{bounded, packets, unread, user};
use crate::addr_codec::VMESS;
use crate::util::lock;
use crate::vmess::VmessPackets;
use crate::vmess::crypto::{
    CMD_MUX, CMD_TCP, CMD_UDP, Request, Security, VERSION, command_key, kdf, one_shot_open,
    one_shot_seal, user_id,
};
use crate::vmess::stream::VmessStream;

/// How far a request's timestamp may stray from the clock.
const WINDOW: Duration = Duration::from_secs(120);
const SEALED_LENGTH: usize = 2 + 16;

struct Account {
    user: Option<Arc<str>>,
    cmd_key: [u8; 16],
    auth: aes::Aes128,
}

pub(super) struct Vmess {
    accounts: Vec<Account>,
    seen: Arc<AuthIds>,
    clock: Arc<ClockOffset>,
    mux: Arc<MuxServe>,
}

/// The auth ids a listener has accepted, each kept until its own timestamp leaves the
/// window, so an id passes once in all the time it could pass at all. sing-vmess keeps one
/// for 120 s from its arrival (`service.go:70`, sing `common/replay/simple.go`), v2ray for
/// 120–240 s in two swapped pools (`aead/authid.go:69`), xray likewise (`aead/authid.go:71`);
/// either lets an id stamped ahead of the clock pass again within its 240 s of validity.
#[derive(Default)]
pub(super) struct AuthIds(Mutex<Seen>);

#[derive(Default)]
struct Seen {
    until: HashMap<[u8; 16], u64>,
    swept: u64,
}

impl AuthIds {
    /// Whether `id`, stamped `stamp`, is new at `now`, both in Unix seconds.
    fn fresh(&self, id: [u8; 16], stamp: u64, now: u64) -> bool {
        let mut seen = lock(&self.0);
        if now.saturating_sub(seen.swept) >= WINDOW.as_secs() {
            seen.until.retain(|_, until| *until >= now);
            seen.swept = now;
        }
        let until = stamp.saturating_add(WINDOW.as_secs());
        match seen.until.get(&id) {
            Some(kept) if *kept >= now => false,
            _ => {
                seen.until.insert(id, until);
                true
            }
        }
    }
}

impl Vmess {
    pub(super) fn new(users: &[VmessUser], seen: Arc<AuthIds>, clock: Arc<ClockOffset>) -> Self {
        let accounts = users
            .iter()
            .map(|entry| {
                let cmd_key = command_key(&user_id(&entry.uuid));
                let auth_key = head(&kdf(&cmd_key, "AES Auth ID Encryption", &[]));
                let auth = aes::Aes128::new(&auth_key.into());
                Account {
                    user: user(&entry.username),
                    cmd_key,
                    auth,
                }
            })
            .collect();
        Vmess {
            accounts,
            seen,
            clock,
            mux: Arc::default(),
        }
    }

    /// The listener's `mux-option`; without it, sing-mux sessions neither pad nor run Brutal.
    pub(super) fn with_mux(mut self, mux: Arc<MuxServe>) -> Self {
        self.mux = mux;
        self
    }

    fn account(&self, auth_id: &[u8; 16]) -> Option<&Account> {
        let now = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        self.account_at(auth_id, now)
    }

    /// The account whose key opens `auth_id` to a checksummed timestamp within the window
    /// of `now`, an id not seen before.
    fn account_at(&self, auth_id: &[u8; 16], now: u64) -> Option<&Account> {
        let (account, block) = self.accounts.iter().find_map(|account| {
            let mut block = aes::Block::from(*auth_id);
            account.auth.decrypt_block(&mut block);
            let (head, check) = block.split_at(12);
            (check == crc32fast::hash(head).to_be_bytes()).then_some((account, block))
        })?;
        let stamp = u64::from_be_bytes(block.get(..8)?.try_into().ok()?);
        if stamp.abs_diff(now) > WINDOW.as_secs() {
            return None;
        }
        self.seen.fresh(block.into(), stamp, now).then_some(account)
    }

    async fn request(
        &self,
        buffered: &mut BufReader<BoxStream>,
    ) -> Option<(Option<Arc<str>>, Request, Option<Address>)> {
        let mut auth_id = [0u8; 16];
        buffered.read_exact(&mut auth_id).await.ok()?;
        let account = self.account(&auth_id)?;
        let mut sealed_length = [0u8; SEALED_LENGTH];
        buffered.read_exact(&mut sealed_length).await.ok()?;
        let mut nonce = [0u8; 8];
        buffered.read_exact(&mut nonce).await.ok()?;
        let path: [&[u8]; 2] = [&auth_id, &nonce];
        let key = |salt: &str| kdf(&account.cmd_key, salt, &path);
        let opened = one_shot_open(
            key("VMess Header AEAD Key_Length").get(..16)?,
            key("VMess Header AEAD Nonce_Length").get(..12)?,
            &auth_id,
            &mut sealed_length,
        )
        .ok()?;
        let length = u16::from_be_bytes(sealed_length.get(..opened)?.try_into().ok()?);
        let mut header = vec![0u8; usize::from(length) + 16];
        buffered.read_exact(&mut header).await.ok()?;
        let opened = one_shot_open(
            key("VMess Header AEAD Key").get(..16)?,
            key("VMess Header AEAD Nonce").get(..12)?,
            &auth_id,
            &mut header,
        )
        .ok()?;
        let (request, dst) = parse_header(header.get(..opened)?)?;
        Some((account.user.clone(), request, dst))
    }
}

fn head(derived: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.iter_mut()
        .zip(derived)
        .for_each(|(slot, byte)| *slot = *byte);
    out
}

/// The opened request header: version, body nonce and key, response byte, option,
/// padding and security, a reserved byte, the command, then the address, padding and a
/// checksum, which sing-vmess skips unchecked.
fn parse_header(header: &[u8]) -> Option<(Request, Option<Address>)> {
    if header.len() <= 38 || header.first() != Some(&VERSION) {
        return None;
    }
    let nonce = header.get(1..17)?.try_into().ok()?;
    let key = header.get(17..33)?.try_into().ok()?;
    let [response_header, option, mixed, _, command] = *header.get(33..38)? else {
        return None;
    };
    let security = match mixed & 0x0f {
        1 => Security::Legacy,
        3 => Security::Aes128Gcm,
        4 => Security::Chacha20Poly1305,
        5 => Security::None,
        _ => return None,
    };
    if !matches!(command, CMD_TCP | CMD_UDP | CMD_MUX) || (command == CMD_UDP && option == 0) {
        return None;
    }
    let dst = if command == CMD_MUX {
        None
    } else {
        Some(VMESS.parse(header.get(38..)?).ok()??.0)
    };
    let request = Request {
        key,
        nonce,
        response_header,
        security,
        option,
        command,
    };
    Some((request, dst))
}

/// The sealed response header: the request's response byte and option, no command. The
/// option is echoed as sing-vmess, mihomo's server, writes it (`service.go:388`, `:414`);
/// v2ray and xray write a zero option (`encoding/server.go:391`, `:327`, from
/// `inbound/inbound.go:301-303`, `:306-308`), and no client acts on the byte.
fn response_head(request: &Request, key: &[u8; 16], iv: &[u8; 16]) -> Option<Vec<u8>> {
    let derive = |from: &[u8; 16], salt: &str| kdf(from, salt, &[]);
    let mut out = one_shot_seal(
        derive(key, "AEAD Resp Header Len Key").get(..16)?,
        derive(iv, "AEAD Resp Header Len IV").get(..12)?,
        &[],
        &4u16.to_be_bytes(),
    )
    .ok()?;
    out.extend(
        one_shot_seal(
            derive(key, "AEAD Resp Header Key").get(..16)?,
            derive(iv, "AEAD Resp Header IV").get(..12)?,
            &[],
            &[request.response_header, request.option, 0, 0],
        )
        .ok()?,
    );
    Some(out)
}

impl Conn for Vmess {
    fn mux(&self) -> &Arc<MuxServe> {
        &self.mux
    }

    fn handle(
        self: Arc<Self>,
        stream: BoxStream,
        peer: Peer,
        cx: Arc<InboundCx>,
        mux: Mux,
    ) -> ServeFuture {
        Box::pin(async move {
            let mut buffered = BufReader::with_capacity(512, stream);
            let Some((user, request, dst)) = bounded(self.request(&mut buffered)).await else {
                return;
            };
            let (key, iv) = request.response_aead_keys();
            let Some(head) = response_head(&request, &key, &iv) else {
                return;
            };
            let command = request.command;
            let Ok(stream) = VmessStream::server(unread(buffered), request, head, &key, &iv) else {
                return;
            };
            let inbound = cx.inbound(InboundKind::Vmess, peer.local, user);
            match (command, dst) {
                (CMD_TCP, Some(dst)) => {
                    flows::tcp(Box::new(stream), dst, inbound, peer, &cx, &mux);
                }
                (CMD_UDP, Some(dst)) => {
                    let packet_addr = matches!(&dst, Address::Domain(host, _) if host.as_str() == PACKET_ADDR_MAGIC);
                    let session = Arc::new(VmessPackets::new(stream, dst, packet_addr));
                    cx.tasks.spawn(packets::serve_session(
                        session,
                        inbound.over_tcp(),
                        peer.src,
                        cx.clone(),
                    ));
                }
                _ => {
                    let session =
                        muxcool::serve(Box::new(stream), inbound, peer, cx.clone(), mux.nested());
                    cx.tasks.spawn(session);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::vmess::stream::VmessCfg;

    async fn replay(wire: &[u8]) -> BoxStream {
        let (mut near, far) = tokio::io::duplex(wire.len() + 1);
        near.write_all(wire).await.unwrap();
        Box::new(far)
    }

    async fn exchange(security: Security, command: u8, global_padding: bool, authenticated: bool) {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let server = Vmess::new(
            &[VmessUser {
                username: "alice".into(),
                uuid: uuid.into(),
                alter_id: 0,
            }],
            Arc::default(),
            Arc::default(),
        );
        let cfg = Arc::new(VmessCfg::new(
            uuid,
            0,
            security,
            global_padding,
            authenticated,
            Arc::new(SystemTime::now),
        ));
        let (near, far) = tokio::io::duplex(256 * 1024);
        let dst = Address::new("example.com", 443);
        let request = Request::new(security, command, global_padding, authenticated);
        let mut client = VmessStream::new(near, cfg, request, dst.clone()).unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();

        let mut buffered = BufReader::new(Box::new(far) as BoxStream);
        let (user, request, got) = server.request(&mut buffered).await.unwrap();
        assert_eq!(user.as_deref(), Some("alice"));
        assert_eq!(got, Some(dst));
        let (key, iv) = request.response_aead_keys();
        let head = response_head(&request, &key, &iv).unwrap();
        let mut served = VmessStream::server(unread(buffered), request, head, &key, &iv).unwrap();
        let mut ping = [0u8; 4];
        served.read_exact(&mut ping).await.unwrap();
        assert_eq!(&ping, b"ping");
        served.write_all(b"pong").await.unwrap();
        served.flush().await.unwrap();
        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(
            &pong, b"pong",
            "{security:?} {command} {global_padding} {authenticated}"
        );
    }

    #[tokio::test]
    async fn the_client_and_the_server_carry_both_directions() {
        for security in [
            Security::Aes128Gcm,
            Security::Chacha20Poly1305,
            Security::None,
            Security::Legacy,
        ] {
            for (padding, authenticated) in
                [(false, false), (true, false), (false, true), (true, true)]
            {
                exchange(security, CMD_TCP, padding, authenticated).await;
            }
        }
        exchange(Security::Aes128Gcm, CMD_UDP, true, true).await;
    }

    #[tokio::test]
    async fn a_replayed_request_and_a_stranger_are_refused() {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let server = Vmess::new(
            &[VmessUser {
                username: String::new(),
                uuid: uuid.into(),
                alter_id: 0,
            }],
            Arc::default(),
            Arc::default(),
        );
        let cfg = Arc::new(VmessCfg::new(
            uuid,
            0,
            Security::Aes128Gcm,
            false,
            false,
            Arc::new(SystemTime::now),
        ));
        let request = Request::new(Security::Aes128Gcm, CMD_TCP, false, false);
        let (near, far) = tokio::io::duplex(64 * 1024);
        let mut client =
            VmessStream::new(near, cfg, request, Address::new("example.com", 443)).unwrap();
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        drop(client);
        let mut wire = Vec::new();
        let mut far = far;
        far.read_to_end(&mut wire).await.unwrap();
        for fresh in [true, false] {
            let mut buffered = BufReader::new(replay(&wire).await);
            assert_eq!(server.request(&mut buffered).await.is_some(), fresh);
        }
        let users = [VmessUser {
            username: "renamed".into(),
            uuid: uuid.into(),
            alter_id: 0,
        }];
        for (seen, fresh) in [(server.seen.clone(), false), (Arc::default(), true)] {
            let reloaded = Vmess::new(&users, seen, Arc::default());
            let mut buffered = BufReader::new(replay(&wire).await);
            assert_eq!(reloaded.request(&mut buffered).await.is_some(), fresh);
        }
        let other = Vmess::new(
            &[VmessUser {
                username: String::new(),
                uuid: "00000000-0000-0000-0000-000000000001".into(),
                alter_id: 0,
            }],
            Arc::default(),
            Arc::default(),
        );
        let mut buffered = BufReader::new(replay(&wire).await);
        assert!(other.request(&mut buffered).await.is_none());
    }

    #[tokio::test]
    async fn the_time_window_is_the_engines_clock() {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let ahead = Duration::from_secs(300);
        let cfg = Arc::new(VmessCfg::new(
            uuid,
            0,
            Security::Aes128Gcm,
            false,
            false,
            Arc::new(move || SystemTime::now() + ahead),
        ));
        let request = Request::new(Security::Aes128Gcm, CMD_TCP, false, false);
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        let mut client =
            VmessStream::new(near, cfg, request, Address::new("example.com", 443)).unwrap();
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        drop(client);
        let mut wire = Vec::new();
        far.read_to_end(&mut wire).await.unwrap();
        for (offset, accepted) in [(Duration::ZERO, false), (ahead, true)] {
            let clock = Arc::new(ClockOffset::default());
            clock.set(i64::try_from(offset.as_nanos()).unwrap());
            let users = [VmessUser {
                username: String::new(),
                uuid: uuid.into(),
                alter_id: 0,
            }];
            let server = Vmess::new(&users, Arc::default(), clock);
            let mut buffered = BufReader::new(replay(&wire).await);
            assert_eq!(server.request(&mut buffered).await.is_some(), accepted);
        }
    }

    #[test]
    fn an_auth_id_is_refused_for_as_long_as_its_timestamp_is_accepted() {
        let t = 1_800_000_000;
        let window = WINDOW.as_secs();
        let seen = AuthIds::default();
        assert!(seen.fresh([1; 16], t, t - window));
        assert!(!seen.fresh([1; 16], t, t + window - 1));
        assert!(seen.fresh([2; 16], t + window, t + window));
        assert!(!seen.fresh([1; 16], t, t + window));
        assert!(seen.fresh([1; 16], t, t + window + 1));
    }
}
