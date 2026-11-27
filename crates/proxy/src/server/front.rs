use std::sync::Arc;

use concord_common::BoxStream;
use concord_common::serve::{InboundCx, Peer, ServeFuture, StreamService};
use concord_tls::server::TlsServer;
use concord_transport::server::{self, HttpCarriers, OnStream};

use super::certs::ServerCerts;
use tokio::net::TcpStream;

/// What lies between an accepted connection and the protocol: TLS, then a websocket or
/// gun streams, as the listener's options ask.
pub(super) struct Front {
    pub(super) tls: Option<(TlsServer, ServerCerts)>,
    pub(super) carriers: HttpCarriers,
}

/// One protocol connection over a stream the front opened. It reads the request under its
/// own bound and hands the flow on.
pub(super) trait Conn: Send + Sync + 'static {
    fn handle(self: Arc<Self>, stream: BoxStream, peer: Peer, cx: Arc<InboundCx>) -> ServeFuture;
}

pub(super) struct Fronted<C> {
    front: Front,
    conn: Arc<C>,
}

impl<C: Conn> Fronted<C> {
    pub(super) fn service(front: Front, conn: C) -> Arc<dyn StreamService> {
        Arc::new(Fronted {
            front,
            conn: Arc::new(conn),
        })
    }
}

impl<C: Conn> StreamService for Fronted<C> {
    fn serve(self: Arc<Self>, stream: TcpStream, peer: Peer, cx: Arc<InboundCx>) -> ServeFuture {
        Box::pin(async move {
            let stream: BoxStream = match &self.front.tls {
                Some((tls, _)) => match tls.accept(stream).await {
                    Ok(tls) => Box::new(tls),
                    Err(_) => return,
                },
                None => Box::new(stream),
            };
            if self.front.carriers.is_empty() {
                self.conn.clone().handle(stream, peer, cx).await;
                return;
            }
            let conn = self.conn.clone();
            let carried = cx.clone();
            let on_stream: OnStream = Arc::new(move |stream| {
                carried
                    .tasks
                    .spawn(conn.clone().handle(stream, peer, carried.clone()));
            });
            let _ = server::accept(stream, &self.front.carriers, &cx.tasks, on_stream).await;
        })
    }
}
