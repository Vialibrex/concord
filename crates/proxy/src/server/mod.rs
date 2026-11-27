//! The protocol servers behind a profile's `listeners`, `ss-config` and `vmess-config`.

mod anytls;
mod certs;
mod flows;
mod front;
mod hysteria2;
mod mux;
mod muxcool;
mod packets;
mod quic;
#[cfg(test)]
mod quic_testing;
mod ss;
mod trojan;
mod tuic;
mod vless;
mod vmess;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use concord_common::serve::{HANDSHAKE_TIMEOUT, OnUdp, Protocol, StreamService};
use concord_common::{BoxStream, ClockOffset, InboundKind, Tasks};
use concord_config::listener::{ClientAuth, ListenerKind, ServerTls};
use concord_platform::HomeDir;
use concord_tls::server::{ClientAuth as TlsClientAuth, ServerOptions, ServerTlsError, TlsServer};

use self::certs::ServerCerts;
use concord_transport::server::HttpCarriers;
use tokio::io::BufReader;

use self::front::{Front, Fronted};
use self::mux::MuxServe;
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

/// What a server needs beyond its definition: where relative certificate paths start, where
/// the watch on its certificate files runs, and what the listener of this name kept from
/// the servers it ran before.
pub struct ServerEnv<'a> {
    pub home: &'a Arc<HomeDir>,
    pub tasks: &'a Tasks,
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
    self_signed: certs::SelfSigned,
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
            let conn = trojan::Trojan::new(&server.users).with_mux(MuxServe::new(&server.mux));
            (InboundKind::Trojan, Fronted::service(front, conn))
        }
        ListenerKind::Vless(server) => {
            let front = front(server.tls.as_ref(), &server.carriers, env)?;
            let conn = vless::Vless::new(&server.users).with_mux(MuxServe::new(&server.mux));
            (InboundKind::Vless, Fronted::service(front, conn))
        }
        ListenerKind::AnyTls(server) => {
            let front = front(server.tls.as_ref(), &Default::default(), env)?;
            (
                InboundKind::AnyTls,
                Fronted::service(front, anytls::AnyTls::new(server)?),
            )
        }
        ListenerKind::Vmess(server) => {
            let front = front(server.tls.as_ref(), &server.carriers, env)?;
            let conn = vmess::Vmess::new(
                &server.users,
                env.carried.of(env.keep).vmess.clone(),
                env.clock.clone(),
            )
            .with_mux(MuxServe::new(&server.mux));
            (InboundKind::Vmess, Fronted::service(front, conn))
        }
        ListenerKind::Shadowsocks(server) => {
            let service = ss::build(server, &env.carried.of(env.keep).ss, env.clock)?;
            let udp = server
                .udp
                .then(|| OnUdp::Datagram(Arc::new(ss::SsDatagrams(service.clone()))));
            return Ok(Some(Protocol {
                kind: InboundKind::Shadowsocks,
                stream: Some(service as Arc<dyn StreamService>),
                udp,
            }));
        }
        ListenerKind::Tuic(server) => {
            let kept = env.carried.of(env.keep);
            let tls = TlsSetup::new(&server.tls, Some(&kept.self_signed), env)?;
            let service = tuic::Tuic::new(server, tls)?;
            return Ok(Some(Protocol {
                kind: InboundKind::Tuic,
                stream: None,
                udp: Some(OnUdp::Endpoint(Arc::new(service))),
            }));
        }
        ListenerKind::Hysteria2(server) => {
            let kept = env.carried.of(env.keep);
            let tls = TlsSetup::new(&server.tls, Some(&kept.self_signed), env)?;
            let service = hysteria2::Hysteria2::new(server, tls)?;
            return Ok(Some(Protocol {
                kind: InboundKind::Hysteria2,
                stream: None,
                udp: Some(OnUdp::Endpoint(Arc::new(service))),
            }));
        }
        _ => return Ok(None),
    };
    Ok(Some(Protocol {
        kind,
        stream: Some(stream),
        udp: None,
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
    let Some(tls) = tls else {
        return Ok(Front {
            tls: None,
            carriers,
        });
    };
    let setup = TlsSetup::new(tls, None, env)?;
    let server = TlsServer::new(&setup.options(carriers.alpn()))?;
    Ok(Front {
        tls: Some((server, setup.certs)),
        carriers,
    })
}

/// A listener's certificate and how it asks clients for theirs.
struct TlsSetup {
    certs: ServerCerts,
    client_auth: TlsClientAuth,
    client_ca: Option<Vec<u8>>,
}

impl TlsSetup {
    fn new(
        tls: &ServerTls,
        self_signed: Option<&certs::SelfSigned>,
        env: &ServerEnv<'_>,
    ) -> Result<Self, ServerError> {
        let certs = certs::load(&tls.certificate, &tls.private_key, self_signed, env)?;
        let client_ca = (!tls.client_auth_cert.is_empty())
            .then(|| certs::read_pem(&tls.client_auth_cert, env.home))
            .transpose()?;
        Ok(TlsSetup {
            certs,
            client_auth: match tls.client_auth {
                ClientAuth::None => TlsClientAuth::None,
                ClientAuth::Request => TlsClientAuth::Request,
                ClientAuth::RequireAny => TlsClientAuth::RequireAny,
                ClientAuth::VerifyIfGiven => TlsClientAuth::VerifyIfGiven,
                ClientAuth::RequireAndVerify => TlsClientAuth::RequireAndVerify,
            },
            client_ca,
        })
    }

    fn options(&self, alpn: Vec<Vec<u8>>) -> ServerOptions<'_> {
        ServerOptions {
            certs: self.certs.certs.clone(),
            client_auth: self.client_auth,
            client_ca_pem: self.client_ca.as_deref(),
            alpn,
        }
    }
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
