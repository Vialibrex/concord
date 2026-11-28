use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use concord_common::{Address, ConnStep, DialCx, Initiator, SockOpts, Tasks};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, Runtime, TokioRuntime};
use rand::RngExt;

use concord_config::proxy::TlsOpts;
use concord_quic::{
    CappedFrame, Hop, ObfsSpec, QuicConn, SessionSocket, TrackedRuntime, close_on_stop, io_error,
    wrap_socket,
};
use concord_tls::{QuicTls, TlsOptions, TrustStore};

use crate::ctx::{BuildCtx, BuildError};
use crate::link::EnvSlot;
use crate::tlsmap::{TlsSpec, tls_options};
use concord_net::dial_each;

use crate::node::{Egress, resolve_server};

/// quic-go's `HandshakeIdleTimeout`; quinn has no separate handshake timer, so a dial
/// without its own deadline gets this as a whole-handshake bound.
pub(crate) const HANDSHAKE_IDLE: Duration = Duration::from_secs(5);
const CLIENT_CID_LENGTH: usize = 0;

fn client_endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config.cid_generator(|| {
        Box::new(quinn_proto::RandomConnectionIdGenerator::new(
            CLIENT_CID_LENGTH,
        ))
    });
    config
}

pub(crate) enum Crypto {
    Rustls(Arc<rustls::ClientConfig>),
    /// The config follows the ECH record looked up through the environment the link was dialed with.
    EchLookup(Arc<QuicTls>, EnvSlot),
    Custom(Arc<dyn quinn::crypto::ClientConfig>),
}

pub(crate) struct QuicLink {
    pub(crate) egress: Egress,
    pub(crate) server: Address,
    /// `None` sends no SNI and names the server by its address.
    pub(crate) server_name: Option<String>,
    pub(crate) crypto: Crypto,
    pub(crate) transport: Arc<quinn::TransportConfig>,
    pub(crate) obfs: ObfsSpec,
    pub(crate) hop: Option<Hop>,
    /// The `max_datagram_frame_size` to advertise instead of the one quinn derives.
    pub(crate) datagram_frame: Option<u64>,
    pub(crate) tasks: Tasks,
}

pub(crate) fn quic_crypto(
    options: &TlsOptions,
    trust: Arc<TrustStore>,
    alpn: &[&str],
    env: EnvSlot,
) -> Result<Crypto, BuildError> {
    if options.ech_lookup.is_some() && options.ech_config_list.is_none() {
        return Ok(Crypto::EchLookup(
            Arc::new(QuicTls::new(options, trust, alpn)?),
            env,
        ));
    }
    Ok(Crypto::Rustls(concord_tls::quic_client_config(
        options, trust, alpn,
    )?))
}

/// The server name and crypto of a QUIC node whose `sni` falls back to its server and whose
/// `alpn` falls back to `default_alpn`.
pub(crate) fn node_crypto(
    tls: &TlsOpts,
    server: &str,
    default_alpn: &str,
    ctx: &BuildCtx,
) -> Result<(String, Crypto), BuildError> {
    let server_name = if tls.server_name.is_empty() {
        server.to_string()
    } else {
        tls.server_name.clone()
    };
    let alpn = if tls.alpn.is_empty() {
        vec![default_alpn.to_string()]
    } else {
        tls.alpn.clone()
    };
    let env_slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let options = tls_options(
        tls,
        TlsSpec {
            sni: server_name.clone(),
            alpn: alpn.clone(),
        },
        ctx,
        Some(&env_slot),
    )?;
    let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
    let crypto = quic_crypto(&options, ctx.trust.clone(), &alpn, env_slot)?;
    Ok((server_name, crypto))
}

pub(crate) fn client_config(
    crypto: &Crypto,
    transport: &Arc<quinn::TransportConfig>,
    datagram_frame: Option<u64>,
) -> Result<quinn::ClientConfig, BuildError> {
    let crypto: Arc<dyn quinn::crypto::ClientConfig> = match crypto {
        Crypto::Rustls(tls) => Arc::new(
            QuicClientConfig::try_from(tls.clone())
                .map_err(|err| BuildError::invalid(format!("quic tls: {err}")))?,
        ),
        Crypto::Custom(custom) => custom.clone(),
        Crypto::EchLookup(..) => {
            return Err(BuildError::invalid("the ECH lookup has not run"));
        }
    };
    let mut config = match datagram_frame {
        Some(frame) => quinn::ClientConfig::new(Arc::new(CappedFrame::new(crypto, frame))),
        None => quinn::ClientConfig::new(crypto),
    };
    config.transport_config(transport.clone());
    Ok(config)
}

impl QuicLink {
    async fn open_socket(
        &self,
        cx: &DialCx<'_>,
        remote: SocketAddr,
    ) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        if let Some(via) = self.egress.via() {
            let inner = cx.enter(self.egress.name())?;
            let session = cx
                .env
                .nodes
                .associate_via(via, &inner, &Address::Socket(remote))
                .await?;
            return Ok(SessionSocket::new(session, remote, &self.tasks));
        }
        let opts = SockOpts {
            tunnel_udp_buffers: true,
            ..self.egress.sock_opts(cx.env)
        };
        let socket = cx.env.sockets.bind_udp(remote.ip(), &opts)?;
        TokioRuntime.wrap_udp_socket(socket.into_std()?)
    }

    /// `remote` with the first port the hopping schedule picked, if any.
    fn first_port(&self, mut remote: SocketAddr) -> SocketAddr {
        if let Some(hop) = &self.hop
            && !hop.ports.is_empty()
        {
            let pick = rand::rng().random_range(0..hop.ports.len());
            if let Some(port) = hop.ports.get(pick) {
                remote.set_port(*port);
            }
        }
        remote
    }

    async fn connect_to(
        &self,
        cx: &DialCx<'_>,
        remote: SocketAddr,
        endpoint: EndpointConfig,
    ) -> io::Result<QuicConn> {
        let remote = self.first_port(remote);
        let raw = self.open_socket(cx, remote).await?;
        self.handshake(cx, raw, remote, endpoint).await
    }

    /// Dials the server's first address and completes the QUIC handshake, as mihomo's
    /// hysteria does. The hop schedule and the obfuscation are cloned, so one link can
    /// connect again after a drop.
    pub(crate) async fn connect(&self, cx: &DialCx<'_>) -> io::Result<QuicConn> {
        self.connect_endpoint(cx, client_endpoint_config()).await
    }

    pub(crate) async fn connect_endpoint(
        &self,
        cx: &DialCx<'_>,
        endpoint: EndpointConfig,
    ) -> io::Result<QuicConn> {
        let proxy_cx = DialCx::new(cx.env, Initiator::Proxy, cx.deadline);
        let remote = resolve_server(&proxy_cx, &self.server, self.egress.version()).await?;
        self.connect_to(cx, remote, endpoint).await
    }

    /// Like `connect`, but over every address of the server the way mihomo's dialer
    /// carries hysteria2, tuic and shadowquic: in order within a family, and the other
    /// family after a short head start.
    pub(crate) async fn connect_any(&self, cx: &DialCx<'_>) -> io::Result<QuicConn> {
        if self.egress.via().is_some() {
            return self.connect(cx).await;
        }
        let proxy_cx = DialCx::new(cx.env, Initiator::Proxy, cx.deadline);
        let sockets = &cx.env.sockets;
        dial_each(&proxy_cx, &self.server, self.egress.version(), |addr| {
            self.connect_to(cx, sockets.ip4p(addr), client_endpoint_config())
        })
        .await
    }

    /// Like `connect`, over a socket that already reaches `remote`.
    pub(crate) async fn connect_on(
        &self,
        cx: &DialCx<'_>,
        socket: std::net::UdpSocket,
        remote: SocketAddr,
    ) -> io::Result<QuicConn> {
        let raw = TokioRuntime.wrap_udp_socket(socket)?;
        self.handshake(cx, raw, remote, client_endpoint_config())
            .await
    }

    async fn handshake(
        &self,
        cx: &DialCx<'_>,
        raw: Arc<dyn AsyncUdpSocket>,
        remote: SocketAddr,
        endpoint_config: EndpointConfig,
    ) -> io::Result<QuicConn> {
        let socket = wrap_socket(
            raw,
            &self.obfs,
            self.hop.as_ref().map(|hop| (remote.port(), hop.clone())),
            &self.tasks,
        );
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            None,
            socket,
            Arc::new(TrackedRuntime(self.tasks.clone())),
        )?;
        let name = self
            .server_name
            .clone()
            .unwrap_or_else(|| remote.ip().to_string());
        let looked_up;
        let crypto = match &self.crypto {
            Crypto::EchLookup(tls, env) => {
                env.store(Some(Arc::new(cx.env.clone())));
                looked_up = Crypto::Rustls(tls.config(&name).await?);
                &looked_up
            }
            other => other,
        };
        let config = client_config(crypto, &self.transport, self.datagram_frame)
            .map_err(io::Error::other)?;
        let connecting = endpoint
            .connect_with(config, remote, &name)
            .map_err(io_error)?;
        let handshake = async { connecting.await.map_err(io_error) };
        let left = cx.remaining().unwrap_or(HANDSHAKE_IDLE);
        let conn = tokio::time::timeout(left, handshake)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        cx.mark(ConnStep::Tls);
        close_on_stop(&self.tasks, conn.clone());
        Ok(QuicConn::new(conn, endpoint, self.tasks.clone()))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "the tests talk to a loopback endpoint directly"
)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use concord_quic::{QuicStream, transport_config};
    use quinn::crypto::rustls::QuicClientConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::testing::quic_server;

    fn initial_source_cid_length(config: EndpointConfig) -> usize {
        let options = TlsOptions {
            skip_cert_verify: true,
            ..TlsOptions::default()
        };
        let tls =
            concord_tls::quic_client_config(&options, TrustStore::new(b"", Vec::new()), &["h3"])
                .unwrap();
        let client =
            quinn_proto::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
        let mut endpoint = quinn_proto::Endpoint::new(Arc::new(config), None, true, Some([1; 32]));
        let now = Instant::now();
        let (_, mut conn) = endpoint
            .connect(now, client, (Ipv4Addr::LOCALHOST, 4433).into(), "localhost")
            .unwrap();
        let mut packet = Vec::new();
        let transmit = conn.poll_transmit(now, 1, &mut packet).unwrap();
        let packet = packet.get(..transmit.size).unwrap();
        assert_ne!(packet.first().copied().unwrap() & 0x80, 0);
        let destination_cid_length = usize::from(*packet.get(5).unwrap());
        usize::from(*packet.get(6 + destination_cid_length).unwrap())
    }

    #[test]
    fn single_connection_client_uses_the_reference_source_cid() {
        assert_eq!(initial_source_cid_length(EndpointConfig::default()), 8);
        assert_eq!(initial_source_cid_length(client_endpoint_config()), 0);
    }

    #[tokio::test]
    async fn the_halves_move_data_both_ways_and_the_hold_outlives_both() {
        let (server, port) = quic_server(b"h3", |socket| socket);
        let echo = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            send.write_all(b"down").await.unwrap();
            let mut got = Vec::new();
            recv.read_to_end(1024)
                .await
                .map(|bytes| got.extend(bytes))
                .unwrap();
            send.finish().unwrap();
            let _ = conn.closed().await;
            got
        });
        let options = TlsOptions {
            server_name: Some("localhost".to_string()),
            alpn: vec!["h3".to_string()],
            skip_cert_verify: true,
            ..TlsOptions::default()
        };
        let tls =
            concord_tls::quic_client_config(&options, TrustStore::new(b"", Vec::new()), &["h3"])
                .unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(tls).unwrap(),
        )));
        let conn = endpoint
            .connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        let witness = Arc::new(());
        let stream: concord_common::BoxStream =
            Box::new(QuicStream::new(send, recv, Box::new(witness.clone())));
        let (mut read, mut write) = stream.into_split();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            read.read_to_end(&mut got).await.unwrap();
            (got, read)
        });
        write.write_all(b"up").await.unwrap();
        write.shutdown().await.unwrap();
        let (got, read) = reader.await.unwrap();
        assert_eq!(got, b"down");
        drop(write);
        assert_eq!(Arc::strong_count(&witness), 2);
        drop(read);
        assert_eq!(Arc::strong_count(&witness), 1);
        conn.close(0u32.into(), b"");
        assert_eq!(echo.await.unwrap(), b"up");
    }

    #[tokio::test]
    async fn a_stop_sends_connection_close_and_the_drivers_end_with_the_connection() {
        let (server, port) = quic_server(b"h3", |socket| socket);
        let peer = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            conn.closed().await
        });
        let tracked = crate::testing::Tracked::new();
        let options = TlsOptions {
            server_name: Some("localhost".to_string()),
            alpn: vec!["h3".to_string()],
            skip_cert_verify: true,
            ..TlsOptions::default()
        };
        let link = QuicLink {
            egress: crate::node::Egress::new("q", &Default::default()),
            server: Address::new("127.0.0.1", port),
            server_name: Some("localhost".to_string()),
            crypto: Crypto::Rustls(
                concord_tls::quic_client_config(
                    &options,
                    TrustStore::new(b"", Vec::new()),
                    &["h3"],
                )
                .unwrap(),
            ),
            transport: Arc::new(transport_config()),
            obfs: ObfsSpec::None,
            hop: None,
            datagram_frame: None,
            tasks: tracked.tasks.clone(),
        };
        let env = crate::testing::test_env();
        let conn = link
            .connect(&DialCx::new(&env, Initiator::Other, None))
            .await
            .unwrap();
        assert!(tracked.running() > 0, "the drivers are not tracked");
        tracked.stop();
        let closed = crate::testing::settled(peer).await;
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(_)),
            "{closed}"
        );
        drop(conn);
        assert!(tracked.ended_within(Duration::from_secs(5)).await);
    }
}
