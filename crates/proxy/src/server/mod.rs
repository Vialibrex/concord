//! The protocol servers behind a profile's `listeners`, `ss-config` and `vmess-config`.

mod flows;
mod front;
mod packets;
mod ss;
mod trojan;
mod vless;
mod vmess;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use concord_common::serve::{DatagramService, HANDSHAKE_TIMEOUT, Protocol, StreamService};
use concord_common::{BoxStream, ClockOffset, InboundKind};
use concord_config::listener::{ClientAuth, ListenerKind, ServerTls};
use concord_platform::HomeDir;
use concord_tls::server::{ClientAuth as TlsClientAuth, ServerOptions, ServerTlsError, TlsServer};
use concord_transport::server::HttpCarriers;
use tokio::io::BufReader;

use self::front::{Front, Fronted};
use crate::BuildError;
use crate::util::lock;

/// Why a listener's server could not be built; the listener stays closed.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Build(#[from] BuildError),
    #[error("{path}: {source}")]
    File {
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Tls(#[from] ServerTlsError),
}

/// What a server needs beyond its definition: where relative certificate paths start, and
/// what the listener of this name kept from the servers it ran before.
pub struct ServerEnv<'a> {
    pub home: &'a HomeDir,
    pub keep: &'a Keep,
    pub carried: &'a Carried,
    /// The engine's clock, NTP corrected, as mihomo hands `ntp.Now` to its services.
    pub clock: &'a Arc<ClockOffset>,
}

/// What a listener is kept under across reloads: its name, or the top-level key of a
/// default listener, which a listener named alike must not take.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Keep {
    Named(Arc<str>),
    Default(&'static str),
}

/// What each listener's server hands on to the one a reload builds in its place: the
/// requests and datagrams it has seen, so a reload reopens no replay.
#[derive(Default)]
pub struct Carried(Mutex<HashMap<Keep, Arc<Kept>>>);

#[derive(Default)]
struct Kept {
    vmess: Arc<vmess::AuthIds>,
    ss: Arc<ss::Kept>,
}

impl Carried {
    fn of(&self, keep: &Keep) -> Arc<Kept> {
        lock(&self.0).entry(keep.clone()).or_default().clone()
    }

    pub fn retain(&self, wanted: impl Fn(&Keep) -> bool) {
        lock(&self.0).retain(|keep, _| wanted(keep));
    }
}

/// The server for a listener this crate serves, `None` for one it does not.
pub fn build(kind: &ListenerKind, env: &ServerEnv<'_>) -> Result<Option<Protocol>, ServerError> {
    let (kind, stream) = match kind {
        ListenerKind::Trojan(server) => {
            let front = front(server.tls.as_ref(), &server.carriers, env)?;
            let conn = trojan::Trojan::new(&server.users);
            (InboundKind::Trojan, Fronted::service(front, conn))
        }
        ListenerKind::Vless(server) => {
            let front = front(server.tls.as_ref(), &server.carriers, env)?;
            let conn = vless::Vless::new(&server.users);
            (InboundKind::Vless, Fronted::service(front, conn))
        }
        ListenerKind::Vmess(server) => {
            let front = front(server.tls.as_ref(), &server.carriers, env)?;
            let conn = vmess::Vmess::new(
                &server.users,
                env.carried.of(env.keep).vmess.clone(),
                env.clock.clone(),
            );
            (InboundKind::Vmess, Fronted::service(front, conn))
        }
        ListenerKind::Shadowsocks(server) => {
            let service = ss::build(server, &env.carried.of(env.keep).ss, env.clock)?;
            let datagram: Option<Arc<dyn DatagramService>> = server
                .udp
                .then(|| Arc::new(ss::SsDatagrams(service.clone())) as Arc<dyn DatagramService>);
            return Ok(Some(Protocol {
                kind: InboundKind::Shadowsocks,
                stream: Some(service as Arc<dyn StreamService>),
                datagram,
            }));
        }
        _ => return Ok(None),
    };
    Ok(Some(Protocol {
        kind,
        stream: Some(stream),
        datagram: None,
    }))
}

fn front(
    tls: Option<&ServerTls>,
    carriers: &concord_config::listener::HttpCarriers,
    env: &ServerEnv<'_>,
) -> Result<Front, ServerError> {
    let carriers = HttpCarriers {
        ws_path: carriers.ws_path.clone(),
        grpc_service_name: carriers.grpc_service_name.clone(),
    };
    let tls = tls
        .map(|tls| tls_server(tls, carriers.alpn(), env))
        .transpose()?;
    Ok(Front { tls, carriers })
}

fn tls_server(
    tls: &ServerTls,
    alpn: Vec<Vec<u8>>,
    env: &ServerEnv<'_>,
) -> Result<TlsServer, ServerError> {
    let certificate = pem_or_file(&tls.certificate, env)?;
    let private_key = pem_or_file(&tls.private_key, env)?;
    let client_ca = (!tls.client_auth_cert.is_empty())
        .then(|| pem_or_file(&tls.client_auth_cert, env))
        .transpose()?;
    TlsServer::new(&ServerOptions {
        certificate_pem: &certificate,
        private_key_pem: &private_key,
        client_auth: match tls.client_auth {
            ClientAuth::None => TlsClientAuth::None,
            ClientAuth::Request => TlsClientAuth::Request,
            ClientAuth::RequireAny => TlsClientAuth::RequireAny,
            ClientAuth::VerifyIfGiven => TlsClientAuth::VerifyIfGiven,
            ClientAuth::RequireAndVerify => TlsClientAuth::RequireAndVerify,
        },
        client_ca_pem: client_ca.as_deref(),
        alpn,
    })
    .map_err(ServerError::from)
}

/// mihomo's `ca.NewTLSKeyPairLoader`: the text itself when it is PEM, otherwise a path
/// that must stay inside the home directory.
fn pem_or_file(text: &str, env: &ServerEnv<'_>) -> Result<Vec<u8>, ServerError> {
    if text.contains("-----BEGIN") {
        return Ok(text.as_bytes().to_vec());
    }
    env.home
        .confine_profile_file(text)
        .and_then(|path| env.home.read(path))
        .map_err(|source| ServerError::File {
            path: text.to_owned(),
            source,
        })
}

/// What a request header read through a buffer left unread, put back in front of the
/// stream.
fn unread(buffered: BufReader<BoxStream>) -> BoxStream {
    let ahead = buffered.buffer().to_vec();
    let stream = buffered.into_inner();
    if ahead.is_empty() {
        stream
    } else {
        Box::new(concord_common::PeekedStream::new(ahead, stream))
    }
}

/// A request's user as `IN-USER` matches it; a nameless one matches none.
fn user(name: &str) -> Option<Arc<str>> {
    (!name.is_empty()).then(|| Arc::from(name))
}

/// Bounds reading a request header, as the listener bounds the front.
async fn bounded<T>(work: impl std::future::Future<Output = Option<T>>) -> Option<T> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, work)
        .await
        .ok()
        .flatten()
}
