use std::io;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use concord_common::Address;
use concord_config::proxy::{OPENVPN_CIPHERS, OpenVpnOpts, normalize_openvpn_cipher};

use super::data::Cipher;
use super::keys::{Digest, options_string, peer_info};
use super::wrap::{STATIC_KEY_LEN, StaticKey, Wrap};
use crate::ctx::BuildError;
use crate::stack::Congestion;
use crate::wireguard::config::{DnsServer, dns_server};

const DEFAULT_MTU: usize = 1500;
const MIN_MTU: usize = 1280;
const MAX_MTU: usize = 65_495;
const TRANSITION_WINDOW: Duration = Duration::from_secs(3600);
const TLS_CRYPT_V2_LABEL: &str = "OpenVPN tls-crypt-v2 client key";

pub(super) struct Config {
    pub(super) server: Address,
    pub(super) tcp: bool,
    pub(super) tls: Arc<rustls::ClientConfig>,
    pub(super) wrap: Option<Arc<Wrap>>,
    pub(super) cipher: String,
    pub(super) data_ciphers: Vec<String>,
    pub(super) fallback: String,
    pub(super) digest: Digest,
    pub(super) comp_lzo: bool,
    pub(super) options: String,
    pub(super) peer_info: String,
    pub(super) username: String,
    pub(super) password: String,
    pub(super) ping: Option<Duration>,
    pub(super) ping_restart: Option<Duration>,
    pub(super) transition: Duration,
    pub(super) handshake_timeout: Option<Duration>,
    pub(super) mtu: usize,
    pub(super) congestion: Congestion,
    pub(super) dns: Vec<DnsServer>,
}

fn invalid(message: String) -> BuildError {
    BuildError::invalid(message)
}

/// mihomo's `DecodeStaticKey`: the hex lines of an `OpenVPN Static key V1` block.
pub(super) fn static_key(text: &str, what: &str) -> Result<StaticKey, BuildError> {
    let hex: String = text
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with('#')
                && !line.starts_with("-----BEGIN OpenVPN Static key")
                && !line.starts_with("-----END OpenVPN Static key")
        })
        .collect();
    let key = hex::decode(hex).map_err(|e| invalid(format!("parse {what} key: {e}")))?;
    super::wrap::static_key(&key).ok_or_else(|| {
        invalid(format!(
            "parse {what} key: invalid static key length {}, expected {STATIC_KEY_LEN} bytes",
            key.len()
        ))
    })
}

/// mihomo's `DecodeTLSCryptV2ClientKey`: a base64 PEM whose first 256 bytes are the key and
/// the rest the wrapped client key the server unwraps.
pub(super) fn tls_crypt_v2(text: &str) -> Result<(StaticKey, Vec<u8>), BuildError> {
    let begin = format!("-----BEGIN {TLS_CRYPT_V2_LABEL}-----");
    let end = format!("-----END {TLS_CRYPT_V2_LABEL}-----");
    let body = text
        .split_once(&begin)
        .and_then(|(_, rest)| rest.split_once(&end))
        .map(|(body, _)| body)
        .ok_or_else(|| {
            invalid("parse tls-crypt-v2 client key: invalid tls-crypt-v2 client PEM".into())
        })?;
    let encoded: String = body.split_whitespace().collect();
    let mut key = STANDARD
        .decode(encoded)
        .map_err(|e| invalid(format!("parse tls-crypt-v2 client key: {e}")))?;
    if key.len() <= STATIC_KEY_LEN {
        return Err(invalid(
            "parse tls-crypt-v2 client key: tls-crypt-v2 client PEM missing wrapped key".into(),
        ));
    }
    let wrapped = key.split_off(STATIC_KEY_LEN);
    let key = super::wrap::static_key(&key)
        .ok_or_else(|| invalid("parse tls-crypt-v2 client key: short key".into()))?;
    Ok((key, wrapped))
}

fn wrap(opts: &OpenVpnOpts, digest: Digest) -> Result<Option<Arc<Wrap>>, BuildError> {
    let set = |text: &str| !text.trim().is_empty();
    Ok(Some(Arc::new(if set(&opts.tls_crypt_v2) {
        let (key, wrapped) = tls_crypt_v2(&opts.tls_crypt_v2)?;
        Wrap::crypt(&key, Some(wrapped))
    } else if set(&opts.tls_crypt) {
        Wrap::crypt(&static_key(&opts.tls_crypt, "tls-crypt")?, None)
    } else if set(&opts.tls_auth) {
        Wrap::auth(
            &static_key(&opts.tls_auth, "tls-auth")?,
            &opts.key_direction,
            digest,
        )
    } else {
        return Ok(None);
    })))
}

fn congestion(opts: &OpenVpnOpts) -> Result<Congestion, BuildError> {
    let name = opts.ip_stack_congestion_controller.to_ascii_lowercase();
    let (congestion, implemented) = Congestion::parse(&name);
    if !implemented {
        if name != "bbr3" {
            return Err(invalid(format!(
                "invalid IP stack congestion controller {name:?}; expected cubic, reno, bbr, or bbr3"
            )));
        }
        tracing::warn!("openvpn congestion-controller {name} is not available, using cubic");
    }
    Ok(congestion)
}

fn remote_dns(opts: &OpenVpnOpts) -> Result<Vec<DnsServer>, BuildError> {
    if !opts.remote_dns_resolve || opts.dns.is_empty() {
        return Ok(Vec::new());
    }
    let servers: Vec<DnsServer> = opts
        .dns
        .iter()
        .filter_map(|text| {
            let parsed = dns_server(text);
            if parsed.is_none() {
                tracing::warn!("openvpn dns server {text} is not supported, skipped");
            }
            parsed
        })
        .collect();
    if servers.is_empty() {
        return Err(BuildError::unsupported(
            "none of the openvpn dns servers is a plain udp or tcp server",
        ));
    }
    Ok(servers)
}

fn seconds(secs: u64) -> Option<Duration> {
    (secs != 0).then(|| Duration::from_secs(secs))
}

impl Config {
    pub(super) fn new(opts: &OpenVpnOpts) -> Result<Config, BuildError> {
        let digest = Digest::parse(&opts.auth)
            .ok_or_else(|| invalid(format!("unsupported openvpn auth {:?}", opts.auth)))?;
        let data_ciphers: Vec<String> = opts
            .data_ciphers
            .iter()
            .map(|c| normalize_openvpn_cipher(c))
            .collect();
        let primary = data_ciphers.first().unwrap_or(&opts.cipher).clone();
        let advertised = if data_ciphers.is_empty() {
            vec![opts.cipher.clone()]
        } else {
            data_ciphers.clone()
        };
        let mtu = match opts.mtu {
            0 => DEFAULT_MTU,
            value => usize::try_from(value).unwrap_or(DEFAULT_MTU),
        };
        Ok(Config {
            server: Address::new(&opts.server, opts.port),
            tcp: opts.tcp,
            tls: super::tls::config(&opts.ca, &opts.cert, &opts.key)?,
            wrap: wrap(opts, digest)?,
            options: options_string(opts.tcp, &primary, &opts.auth, opts.comp_lzo),
            peer_info: peer_info(&advertised, opts.comp_lzo, &opts.peer_info),
            cipher: opts.cipher.clone(),
            data_ciphers,
            fallback: opts.data_ciphers_fallback.clone(),
            digest,
            comp_lzo: opts.comp_lzo,
            username: opts.username.trim().to_string(),
            password: opts.password.clone(),
            ping: seconds(opts.ping),
            ping_restart: seconds(opts.ping_restart),
            transition: opts
                .tran_window
                .map_or(TRANSITION_WINDOW, Duration::from_secs),
            handshake_timeout: seconds(opts.handshake_timeout),
            mtu: mtu.clamp(MIN_MTU, MAX_MTU),
            congestion: congestion(opts)?,
            dns: remote_dns(opts)?,
        })
    }

    /// mihomo's `NegotiateCipher` over what the server pushed.
    pub(super) fn negotiate(&self, pushed: &[String], pushed_cipher: &str) -> io::Result<Cipher> {
        let name = self.negotiated_name(pushed, pushed_cipher)?;
        Cipher::parse(&name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("OpenVPN cipher {name:?} is not supported"),
            )
        })
    }

    pub(super) fn negotiated_name(
        &self,
        pushed: &[String],
        pushed_cipher: &str,
    ) -> io::Result<String> {
        let fallback =
            (!self.fallback.is_empty()).then(|| normalize_openvpn_cipher(&self.fallback));
        if pushed.is_empty() && pushed_cipher.is_empty() {
            return Ok(self.cipher.clone());
        }
        if !self.data_ciphers.is_empty() {
            let server: Vec<&str> = if pushed.is_empty() {
                vec![pushed_cipher]
            } else {
                pushed.iter().map(String::as_str).collect()
            };
            for offered in &server {
                let offered = normalize_openvpn_cipher(offered);
                if self.data_ciphers.contains(&offered) {
                    return Ok(offered);
                }
            }
            return fallback.ok_or_else(|| {
                io::Error::other(format!(
                    "no common data cipher between client {:?} and server {server:?}",
                    self.data_ciphers
                ))
            });
        }
        if !pushed_cipher.is_empty() {
            let offered = normalize_openvpn_cipher(pushed_cipher);
            if offered == self.cipher {
                return Ok(offered);
            }
            if let Some(fallback) = fallback {
                return Ok(fallback);
            }
            if OPENVPN_CIPHERS.contains(&offered.as_str()) {
                return Ok(offered);
            }
            return Err(io::Error::other(format!(
                "server pushed unsupported cipher {pushed_cipher:?}"
            )));
        }
        if pushed
            .iter()
            .any(|offered| OPENVPN_CIPHERS.contains(&normalize_openvpn_cipher(offered).as_str()))
        {
            if let Some(fallback) = fallback {
                return Ok(fallback);
            }
            if let Some(first) = pushed
                .iter()
                .map(|offered| normalize_openvpn_cipher(offered))
                .find(|offered| OPENVPN_CIPHERS.contains(&offered.as_str()))
            {
                return Ok(first);
            }
        }
        Ok(self.cipher.clone())
    }
}
