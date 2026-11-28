//! A listener's `shadow-tls` in front of its protocol (`listener/shadowtls/listener.go`).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use concord_common::serve::{HANDSHAKE_TIMEOUT, InboundCx};
use concord_common::{Address, BoxStream};
use concord_config::listener::{
    ShadowTlsHandshake, ShadowTlsServer as ShadowTlsDef, WildcardSni as WildcardDef,
};
use concord_transport::{
    HandshakeTarget, ShadowTlsServer, ShadowTlsServerOptions, ShadowTlsUser, ShadowTlsVersion,
    WildcardSni,
};
use tokio::net::TcpStream;

use super::{inner, user};

pub(super) struct ShadowFront(ShadowTlsServer);

impl ShadowFront {
    pub(super) fn new(def: &ShadowTlsDef) -> Arc<Self> {
        let target = |handshake: &ShadowTlsHandshake| HandshakeTarget {
            server: handshake.dest.clone(),
            proxy: (!handshake.proxy.is_empty()).then(|| Arc::from(handshake.proxy.as_str())),
        };
        let version = match def.version {
            1 => ShadowTlsVersion::V1,
            2 => ShadowTlsVersion::V2,
            _ => ShadowTlsVersion::V3,
        };
        Arc::new(ShadowFront(ShadowTlsServer::new(ShadowTlsServerOptions {
            version,
            password: def.password.clone(),
            users: def
                .users
                .iter()
                .map(|(name, password)| ShadowTlsUser {
                    name: name.clone(),
                    password: password.clone(),
                })
                .collect(),
            handshake: target(&def.handshake),
            handshake_for_server_name: def
                .handshake_for_server_name
                .iter()
                .map(|(name, handshake)| (name.clone(), target(handshake)))
                .collect(),
            strict_mode: def.strict_mode,
            wildcard_sni: match def.wildcard_sni {
                WildcardDef::Off => WildcardSni::Off,
                WildcardDef::Authed => WildcardSni::Authed,
                WildcardDef::All => WildcardSni::All,
            },
        })))
    }

    /// Runs the handshake past the listener's bound, since a stranger's relay to the
    /// handshake server lasts as long as the stranger likes, and hands a client past it to
    /// `then` under a bound of its own, with the v3 user it signed as.
    pub(super) fn serve<F, Fut>(
        self: Arc<Self>,
        stream: TcpStream,
        src: SocketAddr,
        cx: Arc<InboundCx>,
        then: F,
    ) where
        F: FnOnce(BoxStream, Option<Arc<str>>, Arc<InboundCx>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let tasks = cx.tasks.clone();
        tasks.spawn(async move {
            let dial = |target: &HandshakeTarget| -> io::Result<BoxStream> {
                let dst = Address::parse(&target.server).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("shadow-tls: handshake server {:?}", target.server),
                    )
                })?;
                Ok(inner::dial(&cx, dst, target.proxy.clone(), Some(src)))
            };
            let accepted = match self.0.accept(stream, &dial).await {
                Ok(Some(accepted)) => accepted,
                Ok(None) => return,
                Err(err) => {
                    tracing::debug!("shadow-tls: {err}");
                    return;
                }
            };
            let named = accepted.user.as_deref().and_then(user);
            let _ =
                tokio::time::timeout(HANDSHAKE_TIMEOUT, then(accepted.stream, named, cx.clone()))
                    .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use concord_common::Tasks;
    use concord_config::listener::{ShadowTlsHandshake, WildcardSni};
    use concord_test_support::tcp_pair;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::super::quic_testing::{Flows, SHADOW_TLS_V1_RECORDS as RECORDS};
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_client_past_the_handshake_has_the_listeners_bound_for_its_protocol() {
        let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let flows = Arc::new(Flows::default());
        flows.forward();
        let cx = Arc::new(InboundCx {
            name: "in".into(),
            special: None,
            handler: flows,
            tasks: Tasks::default(),
        });
        let front = ShadowFront::new(&ShadowTlsDef {
            version: 1,
            password: String::new(),
            users: Vec::new(),
            handshake: ShadowTlsHandshake {
                dest: decoy.local_addr().unwrap().to_string(),
                proxy: String::new(),
            },
            handshake_for_server_name: Default::default(),
            strict_mode: false,
            wildcard_sni: WildcardSni::Off,
        });
        let (mut client, served) = tcp_pair().await;
        let src = served.peer_addr().unwrap();
        let (held, dropped) = oneshot::channel::<()>();
        front.serve(served, src, cx, move |_, _, _| async move {
            let _held = held;
            std::future::pending::<()>().await;
        });
        client.write_all(&RECORDS).await.unwrap();
        let (mut upstream, _) = decoy.accept().await.unwrap();
        let mut relayed = [0; RECORDS.len()];
        upstream.read_exact(&mut relayed).await.unwrap();
        upstream.write_all(&RECORDS).await.unwrap();
        client.read_exact(&mut relayed).await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(60), dropped).await;
        assert!(ended.expect("the protocol is still waiting").is_err());
    }
}
