use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ipnetwork::IpNetwork;

pub(super) const PUSH_REQUEST: &[u8] = b"PUSH_REQUEST\0";
pub(super) const PEER_ID_UNSET: u32 = 0x00ff_ffff;
pub(super) const AUTH_PENDING_DEFAULT: Duration = Duration::from_secs(60);
pub(super) const AUTH_PENDING_MAX: Duration = Duration::from_secs(30 * 60);
const MAX_BUFFERED: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PushReply {
    pub(super) prefixes: Vec<IpNetwork>,
    pub(super) routes: Vec<IpNetwork>,
    pub(super) dns: Vec<IpAddr>,
    pub(super) peer_id: u32,
    pub(super) redirect: bool,
    pub(super) block_ipv6: bool,
    pub(super) data_ciphers: Vec<String>,
    pub(super) cipher: String,
    pub(super) auth_token_user: String,
    pub(super) auth_token: String,
    pub(super) continuation: u8,
    pub(super) ping: Option<u64>,
    pub(super) ping_restart: Option<u64>,
}

impl Default for PushReply {
    fn default() -> Self {
        PushReply {
            prefixes: Vec::new(),
            routes: Vec::new(),
            dns: Vec::new(),
            peer_id: PEER_ID_UNSET,
            redirect: false,
            block_ipv6: false,
            data_ciphers: Vec::new(),
            cipher: String::new(),
            auth_token_user: String::new(),
            auth_token: String::new(),
            continuation: 0,
            ping: None,
            ping_restart: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Message {
    Push(PushReply),
    AuthPending(Duration),
    Failed(String),
}

fn invalid(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

fn append_unique<T: PartialEq + Clone>(into: &mut Vec<T>, from: &[T]) {
    for item in from {
        if !into.contains(item) {
            into.push(item.clone());
        }
    }
}

impl PushReply {
    /// mihomo's `mergePushReply`: lists accumulate in arrival order, and a later segment's
    /// scalar wins only when it set one.
    pub(super) fn merge(&mut self, next: PushReply) {
        append_unique(&mut self.prefixes, &next.prefixes);
        append_unique(&mut self.routes, &next.routes);
        append_unique(&mut self.dns, &next.dns);
        append_unique(&mut self.data_ciphers, &next.data_ciphers);
        if next.peer_id != PEER_ID_UNSET {
            self.peer_id = next.peer_id;
        }
        if !next.cipher.is_empty() {
            self.cipher = next.cipher;
        }
        self.redirect |= next.redirect;
        self.block_ipv6 |= next.block_ipv6;
        if !next.auth_token.is_empty() {
            self.auth_token = next.auth_token;
        }
        if !next.auth_token_user.is_empty() {
            self.auth_token_user = next.auth_token_user;
        }
        self.continuation = next.continuation;
        self.ping = next.ping.or(self.ping);
        self.ping_restart = next.ping_restart.or(self.ping_restart);
    }

    pub(super) fn parse(message: &str) -> io::Result<PushReply> {
        let mut reply = PushReply::default();
        if !message.starts_with("PUSH_REPLY") {
            return Err(invalid(format!(
                "unexpected OpenVPN push message {message:?}"
            )));
        }
        for option in message.split(',').skip(1) {
            let fields: Vec<&str> = option.split_whitespace().collect();
            if let Some((name, args)) = fields.split_first() {
                reply.apply(name, args)?;
            }
        }
        Ok(reply)
    }

    fn apply(&mut self, name: &str, args: &[&str]) -> io::Result<()> {
        match (name, args) {
            ("ifconfig", [addr, mask, ..]) => self.prefixes.push(ifconfig(addr, mask)?),
            ("ifconfig-ipv6", [prefix, ..]) => self.prefixes.push(
                prefix
                    .parse()
                    .map_err(|e| invalid(format!("pushed ipv6 address {prefix:?}: {e}")))?,
            ),
            ("route", [network, mask, ..]) => self.routes.extend(route(network, mask)),
            ("route-ipv6", [prefix, ..]) => self.routes.extend(prefix.parse::<IpNetwork>().ok()),
            ("dhcp-option", ["DNS", addr, ..]) => self.dns.extend(addr.parse::<IpAddr>().ok()),
            ("peer-id", [id, ..]) => {
                self.peer_id = id
                    .parse::<u32>()
                    .ok()
                    .filter(|id| *id <= PEER_ID_UNSET)
                    .ok_or_else(|| invalid(format!("pushed peer-id {id:?}")))?;
            }
            ("redirect-gateway", _) => self.redirect = true,
            ("block-ipv6", _) => self.block_ipv6 = true,
            ("data-ciphers" | "ncp-ciphers", [list, ..]) => self.data_ciphers.extend(
                list.split(':')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(str::to_string),
            ),
            ("cipher", [cipher, ..]) => self.cipher = (*cipher).to_string(),
            ("auth-token", [token, ..]) => self.auth_token = (*token).to_string(),
            ("auth-token-user", [user, ..]) => {
                let decoded = STANDARD
                    .decode(user)
                    .or_else(|_| STANDARD_NO_PAD.decode(user))
                    .map_err(|e| invalid(format!("auth-token-user: {e}")))?;
                self.auth_token_user = String::from_utf8_lossy(&decoded).into_owned();
            }
            ("push-continuation", [n]) => {
                self.continuation = n
                    .parse()
                    .ok()
                    .filter(|n| *n <= 2)
                    .ok_or_else(|| invalid(format!("invalid push-continuation {n:?}")))?;
            }
            ("push-continuation", _) => return Err(invalid("invalid push-continuation".into())),
            ("ping", [secs, ..]) => self.ping = secs.parse().ok(),
            ("ping-restart", [secs, ..]) => self.ping_restart = secs.parse().ok(),
            _ => {}
        }
        Ok(())
    }
}

fn ipv4(text: &str) -> io::Result<Ipv4Addr> {
    text.parse()
        .map_err(|e| invalid(format!("pushed ipv4 address {text:?}: {e}")))
}

fn mask_len(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    (bits.checked_shl(ones).unwrap_or(0) == 0).then_some(ones as u8)
}

/// A netmask gives the prefix; net30 and p2p servers push the peer instead, and that local
/// address stands alone as in mihomo.
fn ifconfig(addr: &str, mask: &str) -> io::Result<IpNetwork> {
    let addr = ipv4(addr)?;
    let len = mask_len(ipv4(mask)?).unwrap_or(32);
    IpNetwork::new(IpAddr::V4(addr), len).map_err(|e| invalid(e.to_string()))
}

fn route(network: &str, mask: &str) -> Option<IpNetwork> {
    let network: Ipv4Addr = network.parse().ok()?;
    let len = mask_len(mask.parse().ok()?)?;
    IpNetwork::new(IpAddr::V4(network), len).ok()
}

fn auth_pending(message: &str) -> Duration {
    let mut timeout = AUTH_PENDING_DEFAULT;
    for part in message.trim_start_matches("AUTH_PENDING").split(',') {
        if let ["timeout", secs] = part.split_whitespace().collect::<Vec<_>>()[..] {
            if let Ok(secs) = secs.parse::<u64>() {
                timeout = Duration::from_secs(secs).min(AUTH_PENDING_MAX);
            } else if secs.bytes().all(|b| b.is_ascii_digit()) {
                timeout = AUTH_PENDING_MAX;
            }
        }
    }
    timeout
}

/// The TLS plaintext after key method 2, cut into OpenVPN's NUL-terminated control messages.
#[derive(Default)]
pub(super) struct Inbox {
    buf: Vec<u8>,
}

impl Inbox {
    pub(super) fn extend(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.buf.len() + bytes.len() > MAX_BUFFERED {
            return Err(io::Error::other("OpenVPN control text is too long"));
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn buf(&self) -> &[u8] {
        &self.buf
    }

    pub(super) fn consume(&mut self, len: usize) {
        self.buf.drain(..len.min(self.buf.len()));
    }

    /// The next complete message that means something to the client; INFO and the like are
    /// read past, as mihomo does.
    pub(super) fn next(&mut self) -> io::Result<Option<Message>> {
        while let Some(end) = self.buf.iter().position(|b| *b == 0) {
            let message: Vec<u8> = self.buf.drain(..=end).collect();
            let text = String::from_utf8_lossy(message.strip_suffix(&[0]).unwrap_or(&message))
                .into_owned();
            if let Some(message) = classify(&text)? {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }
}

fn classify(text: &str) -> io::Result<Option<Message>> {
    if text.starts_with("AUTH_FAILED") {
        return Ok(Some(Message::Failed(format!(
            "OpenVPN authentication failed: {}",
            text.trim()
        ))));
    }
    if ["RESTART", "HALT", "EXIT"]
        .iter()
        .any(|word| text.starts_with(word))
    {
        return Ok(Some(Message::Failed(format!(
            "OpenVPN server terminated the control session: {}",
            text.trim()
        ))));
    }
    if text.starts_with("AUTH_PENDING") {
        return Ok(Some(Message::AuthPending(auth_pending(text))));
    }
    if text.starts_with("PUSH_REPLY") {
        return PushReply::parse(text)
            .map(|reply| Some(Message::Push(reply)))
            .map_err(|e| invalid(format!("invalid OpenVPN push reply: {e}")));
    }
    Ok(None)
}
