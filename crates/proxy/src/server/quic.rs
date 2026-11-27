//! What the QUIC servers share: an endpoint on the listener's socket, to which a reload
//! hands the settings of new connections without closing the open ones.

use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use concord_common::addr::unmap;
use concord_common::serve::{Current, EndpointService, InboundCx, Peer, ServeFuture};
use concord_quic::{ObfsSpec, Released};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, Incoming, VarInt};
use tokio::sync::watch;

use super::{ServerError, TlsSetup};

pub(super) use crate::quic::HANDSHAKE_IDLE;

/// quic-go drops a connection whose handshake has not completed within twice the handshake
/// idle timeout (`config.go:17-18`, `connection.go:697`), which mihomo's QUIC servers keep.
pub(super) const HANDSHAKE_LIMIT: Duration = HANDSHAKE_IDLE.saturating_mul(2);

pub(super) trait QuicServer: EndpointService {
    fn config(&self) -> quinn::ServerConfig;

    fn obfs(&self) -> &ObfsSpec;

    /// One connection, from the first packet the endpoint took for it.
    fn connection(
        self: Arc<Self>,
        incoming: Incoming,
        peer: Peer,
        cx: Arc<InboundCx>,
    ) -> ServeFuture;
}

/// The TLS side of a QUIC server, offering `alpn` or, when it names none, `h3`.
pub(super) fn crypto(
    tls: &TlsSetup,
    alpn: &[String],
    early_data: bool,
) -> Result<QuicServerConfig, ServerError> {
    let alpn = if alpn.is_empty() {
        vec![b"h3".to_vec()]
    } else {
        alpn.iter().map(|alpn| alpn.as_bytes().to_vec()).collect()
    };
    let mut crypto = concord_tls::server::TlsServer::quic(&tls.options(alpn))?;
    if early_data {
        crypto.max_early_data_size = u32::MAX;
    }
    QuicServerConfig::try_from(Arc::new(crypto))
        .map_err(|err| ServerError::Invalid(format!("QUIC TLS: {err}")))
}

/// How long a stopped endpoint waits for its connections to let go of the port, so the
/// listener built in its place can bind it.
const RELEASE_WAIT: Duration = Duration::from_secs(5);

pub(super) fn run<S: QuicServer>(
    first: Arc<S>,
    socket: std::net::UdpSocket,
    current: watch::Receiver<Current>,
) -> io::Result<ServeFuture> {
    let tasks = current.borrow().cx.tasks.clone();
    let (endpoint, released) =
        concord_quic::server_endpoint(socket, first.config(), first.obfs(), &tasks)?;
    let bound = endpoint.local_addr()?;
    Ok(Box::pin(async move {
        let closing = Closing(Some(endpoint.clone()));
        serve(first, &endpoint, bound, current).await;
        drop(endpoint);
        closing.release(released).await;
    }))
}

async fn serve<S: QuicServer>(
    first: Arc<S>,
    endpoint: &Endpoint,
    bound: SocketAddr,
    mut current: watch::Receiver<Current>,
) {
    let mut serving = first;
    loop {
        tokio::select! {
            changed = current.changed() => {
                if changed.is_err() {
                    return;
                }
                let service = current.borrow_and_update().service.clone();
                let Ok(next) = (service as Arc<dyn Any + Send + Sync>).downcast::<S>() else {
                    return;
                };
                endpoint.set_server_config(Some(next.config()));
                serving = next;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    return;
                };
                let src = incoming.remote_address();
                let local = incoming.local_ip().unwrap_or(bound.ip());
                let peer = Peer {
                    src: SocketAddr::new(unmap(src.ip()), src.port()),
                    local: SocketAddr::new(unmap(local), bound.port()),
                };
                let cx = current.borrow().cx.clone();
                cx.tasks.spawn(serving.clone().connection(incoming, peer, cx.clone()));
            }
        }
    }
}

/// Closes the connections with the listener, as mihomo's `Close` does: at once when the
/// listener's task is dropped, and letting go of the port first when it stops.
struct Closing(Option<Endpoint>);

impl Closing {
    async fn release(mut self, released: Released) {
        if let Some(endpoint) = self.0.take() {
            concord_quic::release_endpoint(endpoint, released, RELEASE_WAIT).await;
        }
    }
}

impl Drop for Closing {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.0 {
            endpoint.close(VarInt::from_u32(0), b"");
        }
    }
}
