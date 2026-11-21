use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use tokio_util::sync::CancellationToken;

use crate::addr::{Host, Network};
use crate::error::CoreError;
use crate::meta::{DnsMode, InboundInfo};

#[derive(Clone, Debug)]
pub struct ConnMeta {
    pub network: Network,
    pub inbound: InboundInfo,
    pub src: SocketAddr,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: u16,
    pub host: Host,
    pub sniff_host: Host,
    pub dns_mode: Option<DnsMode>,
    pub uid: Option<u32>,
    pub process: String,
    pub process_path: String,
    pub remote_destination: String,
    pub src_geoip: Option<Vec<String>>,
    pub dst_geoip: Option<Vec<String>>,
    pub src_asn: String,
    pub dst_asn: String,
    pub rematch_name: String,
    pub special_rules: String,
    pub special_proxy: String,
}

static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct ConnRecord {
    pub id: String,
    /// Counts up from 1 in this process, which the typed API uses as the connection id.
    pub seq: u64,
    pub start: SystemTime,
    pub meta: ConnMeta,
    /// Exit first, as on the wire.
    pub chains: Box<[Arc<str>]>,
    pub provider_chains: Box<[Arc<str>]>,
    pub rule: Arc<str>,
    pub rule_payload: Arc<str>,
    /// Decided by the exit's kind, not its name.
    pub direct: bool,
    pub upload: AtomicU64,
    pub download: AtomicU64,
    pub cancel: CancellationToken,
    /// Decided after the dial: a held connection is marked as it is listed.
    pub mitm: AtomicBool,
    pub mitm_refused: AtomicBool,
    /// Set on a connection listed only to report that its dial failed.
    pub failure: OnceLock<ConnFailure>,
    closed: AtomicBool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnFailure {
    pub kind: FailureKind,
    pub message: String,
}

impl ConnFailure {
    pub fn of(err: &io::Error) -> Self {
        ConnFailure {
            kind: FailureKind::of(err),
            message: err.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Timeout,
    Refused,
    Unreachable,
    /// The name had no address the dial could use.
    Dns,
    /// The path to the target was open but the exchange over it failed, as when a proxy
    /// server closes, resets or answers with something its protocol does not allow.
    Handshake,
    Other,
}

impl FailureKind {
    pub fn of(err: &io::Error) -> Self {
        match CoreError::of(err) {
            Some(CoreError::IpNotFound(_)) => return FailureKind::Dns,
            Some(CoreError::Ipv6Disabled) => return FailureKind::Unreachable,
            Some(CoreError::Rejected(_) | CoreError::Loopback(_)) => return FailureKind::Refused,
            Some(_) => return FailureKind::Other,
            None => {}
        }
        match err.kind() {
            io::ErrorKind::TimedOut => FailureKind::Timeout,
            io::ErrorKind::ConnectionRefused => FailureKind::Refused,
            io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::AddrNotAvailable => FailureKind::Unreachable,
            io::ErrorKind::InvalidData
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::WriteZero
            | io::ErrorKind::PermissionDenied => FailureKind::Handshake,
            _ => FailureKind::Other,
        }
    }
}

impl ConnRecord {
    #[allow(clippy::too_many_arguments, reason = "one literal at each call site")]
    pub fn new(
        meta: ConnMeta,
        chains: Box<[Arc<str>]>,
        provider_chains: Box<[Arc<str>]>,
        rule: Arc<str>,
        rule_payload: Arc<str>,
        direct: bool,
        upload: u64,
    ) -> Self {
        ConnRecord {
            id: uuid::Uuid::new_v4().to_string(),
            seq: NEXT_SEQ.fetch_add(1, Ordering::Relaxed),
            start: SystemTime::now(),
            meta,
            chains,
            provider_chains,
            rule,
            rule_payload,
            direct,
            upload: AtomicU64::new(upload),
            download: AtomicU64::new(0),
            cancel: CancellationToken::new(),
            mitm: AtomicBool::new(false),
            mitm_refused: AtomicBool::new(false),
            failure: OnceLock::new(),
            closed: AtomicBool::new(false),
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.cancel.cancel();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dial_error_falls_into_its_failure_kind() {
        for (err, kind) in [
            (
                io::Error::from(io::ErrorKind::TimedOut),
                FailureKind::Timeout,
            ),
            (
                io::Error::from(io::ErrorKind::ConnectionRefused),
                FailureKind::Refused,
            ),
            (
                io::Error::from(io::ErrorKind::HostUnreachable),
                FailureKind::Unreachable,
            ),
            (
                io::Error::from(io::ErrorKind::NetworkUnreachable),
                FailureKind::Unreachable,
            ),
            (
                CoreError::IpNotFound("example.test".into()).into(),
                FailureKind::Dns,
            ),
            (CoreError::Ipv6Disabled.into(), FailureKind::Unreachable),
            (
                CoreError::Loopback("127.0.0.1:80".into()).into(),
                FailureKind::Refused,
            ),
            (CoreError::DialerLoop("a".into()).into(), FailureKind::Other),
            (
                io::Error::from(io::ErrorKind::UnexpectedEof),
                FailureKind::Handshake,
            ),
            (
                io::Error::new(io::ErrorKind::InvalidData, "bad certificate"),
                FailureKind::Handshake,
            ),
            (
                io::Error::from(io::ErrorKind::ConnectionReset),
                FailureKind::Handshake,
            ),
            (io::Error::other("something else"), FailureKind::Other),
        ] {
            assert_eq!(FailureKind::of(&err), kind, "{err}");
        }
        let failure = ConnFailure::of(&CoreError::IpNotFound("example.test".into()).into());
        assert_eq!(failure.message, "no IP found for example.test");
    }
}
