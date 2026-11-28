use std::sync::Arc;

use concord_common::BoxStream;
use concord_common::serve::{InboundCx, Peer, ServeFuture, StreamService};
use concord_tls::TlsConn;
use concord_tls::server::TlsServer;
use concord_transport::server::{self, HttpCarriers, OnStream};

use super::certs::ServerCerts;
use super::mux::{Mux, MuxServe};
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
    fn mux(&self) -> &Arc<MuxServe>;

    fn handle(
        self: Arc<Self>,
        stream: BoxStream,
        peer: Peer,
        cx: Arc<InboundCx>,
        mux: Mux,
    ) -> ServeFuture;

    /// Whether the listener's TLS, when nothing is carried over it, comes to
    /// [`Conn::handle_tls`] with its own record layer, for a protocol that may take the
    /// transport beneath (XTLS Vision). The others keep tokio-rustls.
    fn takes_records(&self) -> bool {
        false
    }

    fn handle_tls(
        self: Arc<Self>,
        tls: TlsConn,
        peer: Peer,
        cx: Arc<InboundCx>,
        mux: Mux,
    ) -> ServeFuture {
        self.handle(Box::new(tls), peer, cx, mux)
    }
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
            let bare = self.front.tls.is_none() && self.front.carriers.is_empty();
            let mux = if bare {
                Mux::over(self.conn.mux(), &stream)
            } else {
                Mux::new(self.conn.mux())
            };
            let stream: BoxStream = match &self.front.tls {
                Some((tls, _)) if self.front.carriers.is_empty() && self.conn.takes_records() => {
                    if let Ok(tls) = tls.accept_records(Box::new(stream)).await {
                        self.conn.clone().handle_tls(tls, peer, cx, mux).await;
                    }
                    return;
                }
                Some((tls, _)) => match tls.accept(stream).await {
                    Ok(tls) => Box::new(tls),
                    Err(_) => return,
                },
                None => Box::new(stream),
            };
            if self.front.carriers.is_empty() {
                self.conn.clone().handle(stream, peer, cx, mux).await;
                return;
            }
            let conn = self.conn.clone();
            let carried = cx.clone();
            let on_stream: OnStream = Arc::new(move |stream| {
                carried.tasks.spawn(conn.clone().handle(
                    stream,
                    peer,
                    carried.clone(),
                    mux.clone(),
                ));
            });
            let _ = server::accept(stream, &self.front.carriers, &cx.tasks, on_stream).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use concord_common::Tasks;
    use concord_config::listener::{MuxBrutal, MuxServer};
    use concord_test_support::tcp_pair;
    use concord_tls::server::{Certs, ClientAuth, ServerOptions};

    use super::super::quic_testing::Flows;
    use super::*;
    use crate::util::lock;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Handed {
        Stream,
        Records,
    }

    struct Seen {
        serve: Arc<MuxServe>,
        records: bool,
        got: Arc<Mutex<Vec<(Handed, bool)>>>,
    }

    impl Seen {
        fn note(&self, handed: Handed, mux: &Mux) -> ServeFuture {
            lock(&self.got).push((handed, mux.may_run_brutal()));
            Box::pin(async {})
        }
    }

    impl Conn for Seen {
        fn mux(&self) -> &Arc<MuxServe> {
            &self.serve
        }

        fn handle(
            self: Arc<Self>,
            _: BoxStream,
            _: Peer,
            _: Arc<InboundCx>,
            mux: Mux,
        ) -> ServeFuture {
            self.note(Handed::Stream, &mux)
        }

        fn takes_records(&self) -> bool {
            self.records
        }

        fn handle_tls(
            self: Arc<Self>,
            _: TlsConn,
            _: Peer,
            _: Arc<InboundCx>,
            mux: Mux,
        ) -> ServeFuture {
            self.note(Handed::Records, &mux)
        }
    }

    fn tls_front() -> ((TlsServer, ServerCerts), tokio_rustls::TlsConnector) {
        let made = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certs = Certs::new(
            made.cert.pem().as_bytes(),
            made.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let certs = Arc::new(certs);
        let server = TlsServer::new(&ServerOptions {
            certs: certs.clone(),
            client_auth: ClientAuth::None,
            client_ca_pem: None,
            alpn: Vec::new(),
        })
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(made.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        ((server, ServerCerts::fixed(certs)), connector)
    }

    /// What a listener with Brutal on hands its protocol for one connection, and whether the
    /// mux it hands with it may run Brutal.
    async fn handed(tls: bool, records: bool) -> Vec<(Handed, bool)> {
        let got = Arc::new(Mutex::new(Vec::new()));
        let brutal = MuxServer {
            brutal: Some(MuxBrutal {
                up: "10 Mbps".into(),
                down: "10 Mbps".into(),
            }),
            ..MuxServer::default()
        };
        let conn = Seen {
            serve: MuxServe::new(&brutal),
            records,
            got: got.clone(),
        };
        let (front_tls, connector) = if tls {
            let (front, connector) = tls_front();
            (Some(front), Some(connector))
        } else {
            (None, None)
        };
        let front = Front {
            tls: front_tls,
            carriers: HttpCarriers::default(),
        };
        let service = Fronted::service(front, conn);
        let (client, served) = tcp_pair().await;
        let peer = Peer {
            src: served.peer_addr().unwrap(),
            local: served.local_addr().unwrap(),
        };
        let cx = Arc::new(InboundCx {
            name: "in".into(),
            special: None,
            handler: Arc::new(Flows::default()),
            tasks: Tasks::default(),
        });
        let secure = async move {
            let connector = connector?;
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            Some(connector.connect(name, client).await.unwrap())
        };
        let (secured, ()) = tokio::join!(secure, service.serve(served, peer, cx));
        drop(secured);
        std::mem::take(&mut *lock(&got))
    }

    #[tokio::test]
    async fn only_a_bare_connection_hands_a_mux_that_may_run_brutal() {
        assert_eq!(handed(false, false).await, [(Handed::Stream, cfg!(unix))]);
        assert_eq!(handed(true, false).await, [(Handed::Stream, false)]);
    }

    #[tokio::test]
    async fn a_protocol_that_takes_records_gets_the_listeners_tls_as_records() {
        assert_eq!(handed(true, true).await, [(Handed::Records, false)]);
        assert_eq!(handed(false, true).await, [(Handed::Stream, cfg!(unix))]);
    }
}
