mod jls;
mod udp;
mod wire;

#[cfg(test)]
mod tests;

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{ProxyDef, ShadowQuicOpts};
use concord_quic::{
    BbrProfile, Brutal, CONN_WINDOW, ObfsSpec, QuicStream, STREAM_WINDOW, SharedConn,
    SwitchFactory, Transport, bbr_factory, bbr_window, io_error, or_default,
};
use quinn::congestion::ControllerFactory;
use quinn::{TransportConfig, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use self::jls::{JlsClient, JlsUser};
use self::udp::{ShadowPackets, Shared};
use self::wire::{
    ASSOCIATE_DATAGRAM, ASSOCIATE_STREAM, CONNECT, brutal_request, read_brutal_response, request,
    unspecified,
};
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Egress, info_for};
use crate::quic::{Crypto, QuicLink};
use crate::session_slot::SessionSlot;
use crate::util::parse_bps;

const DEFAULT_FRAME: u64 = 1400;
const DEFAULT_STREAMS: u64 = 1024;
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);
const BRUTAL_MTU: u16 = 1200;

struct SqConn {
    shared: SharedConn<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for SqConn {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl SqConn {
    fn alive(&self) -> bool {
        self.shared.alive()
    }
}

#[derive(Clone, Copy)]
struct Settings {
    over_stream: bool,
    up: u64,
    down: u64,
    /// The BBR initial window in bytes.
    window: u64,
    profile: BbrProfile,
}

struct ShadowQuic {
    info: OutboundInfo,
    link: QuicLink,
    settings: Settings,
    controllers: Arc<SwitchFactory>,
    current: SessionSlot<SqConn>,
    connecting: tokio::sync::Mutex<()>,
}

async fn read_uni(stream: &mut quinn::RecvStream, shared: &Shared) -> io::Result<()> {
    let id = stream.read_u16().await?;
    let (inbox, addr) = shared.target(id).await?;
    loop {
        let len = usize::from(stream.read_u16().await?);
        let mut payload = vec![0u8; len];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(io::Error::other)?;
        let sender = inbox.upgrade().ok_or(io::ErrorKind::BrokenPipe)?;
        let _ = sender.try_send((addr.clone(), payload));
    }
}

/// The mihomo-private bandwidth exchange: the server answers with the rate it
/// grants, and whether the client should rather stay on a congestion controller.
async fn negotiate(
    conn: quinn::Connection,
    controllers: Arc<SwitchFactory>,
    settings: Arc<Settings>,
) {
    let exchange = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(io_error)?;
        send.write_all(&brutal_request(settings.down)).await?;
        let (rx, auto) = read_brutal_response(&mut recv).await?;
        let _ = send.finish();
        io::Result::Ok((rx, auto))
    };
    let Ok(Ok((rx, auto))) = tokio::time::timeout(NEGOTIATION_TIMEOUT, exchange).await else {
        return;
    };
    let rate = if rx == 0 || rx > settings.up {
        settings.up
    } else {
        rx
    };
    let Some(switch) = controllers.handle() else {
        return;
    };
    if !auto && rate > 0 {
        switch.replace(Box::new(Brutal::new(rate, BRUTAL_MTU, Instant::now())));
    } else {
        switch.replace(
            bbr_factory(settings.profile, settings.window).build(Instant::now(), BRUTAL_MTU),
        );
    }
}

impl ShadowQuic {
    async fn establish(&self, cx: &DialCx<'_>) -> io::Result<Arc<SqConn>> {
        let quic = self.link.connect_any(cx).await?;
        let shared = SharedConn::new(quic, Shared::default());
        let mut tasks = Vec::new();
        {
            let (conn, hub) = (shared.quic.conn.clone(), shared.hub.clone());
            let spawner = shared.quic.tasks.clone();
            tasks.push(shared.quic.tasks.spawn(async move {
                while let Ok(mut stream) = conn.accept_uni().await {
                    let hub = hub.clone();
                    spawner.spawn(async move {
                        let _ = read_uni(&mut stream, &hub).await;
                    });
                }
            }));
        }
        let Settings { up, down, .. } = self.settings;
        if up > 0 || down > 0 {
            let settings = Arc::new(self.settings);
            tasks.push(shared.quic.tasks.spawn(negotiate(
                shared.quic.conn.clone(),
                self.controllers.clone(),
                settings,
            )));
        }
        Ok(Arc::new(SqConn { shared, tasks }))
    }

    async fn offer(&self, cx: &DialCx<'_>) -> io::Result<Arc<SqConn>> {
        self.current
            .offer(
                &self.connecting,
                SqConn::alive,
                || self.establish(cx),
                |conn| conn.shared.close(),
            )
            .await
    }

    fn forget(&self, conn: &Arc<SqConn>) {
        self.current.forget(conn);
    }

    async fn open(
        &self,
        cx: &DialCx<'_>,
        command: u8,
        target: &Address,
    ) -> io::Result<(Arc<SqConn>, QuicStream)> {
        let mut last = None;
        for _ in 0..2 {
            let conn = self.offer(cx).await?;
            match conn.shared.quic.conn.open_bi().await {
                Ok((send, recv)) => {
                    let mut stream = QuicStream::new(send, recv, Box::new(conn.clone()));
                    stream.write_all(&request(command, target)?).await?;
                    return Ok((conn, stream));
                }
                Err(err) => {
                    self.forget(&conn);
                    last = Some(io_error(err));
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::NotConnected)))
    }
}

#[async_trait]
impl Outbound for ShadowQuic {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let (_conn, stream) = self.open(cx, CONNECT, dst).await?;
        Ok(Box::new(stream))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let over_stream = self.settings.over_stream;
        let command = if over_stream {
            ASSOCIATE_STREAM
        } else {
            ASSOCIATE_DATAGRAM
        };
        let (conn, stream) = self.open(cx, command, &unspecified()).await?;
        Ok(Arc::new(ShadowPackets::new(
            conn.shared.quic.conn.clone(),
            conn.shared.hub.clone(),
            stream,
            over_stream,
            conn,
            &self.link.tasks,
        )))
    }

    fn reset_sessions(&self) {
        if let Some(conn) = self.current.reset() {
            conn.shared
                .quic
                .conn
                .close(VarInt::from_u32(0), b"client closed");
        }
    }
}

fn controller(
    name: &str,
    window: u64,
    profile: BbrProfile,
) -> Arc<dyn ControllerFactory + Send + Sync> {
    match name {
        "new_reno" => Arc::new(concord_quic::new_reno()),
        "bbr" | "bbr_meta_v1" | "bbr_meta_v2" => bbr_factory(profile, window),
        _ => Arc::new(concord_quic::cubic()),
    }
}

fn datagram_frame(opts: &ShadowQuicOpts) -> u64 {
    or_default(opts.max_datagram_frame_size, DEFAULT_FRAME)
}

fn transport(opts: &ShadowQuicOpts, controllers: Arc<SwitchFactory>) -> Arc<TransportConfig> {
    Transport {
        stream_window: or_default(opts.recv_window_conn, STREAM_WINDOW),
        conn_window: or_default(opts.recv_window, CONN_WINDOW),
        double_send_window: true,
        keep_alive: (opts.keep_alive_interval > 0)
            .then(|| Duration::from_millis(u64::from(opts.keep_alive_interval))),
        datagram_frame: datagram_frame(opts),
        streams: Some(or_default(opts.max_open_streams, DEFAULT_STREAMS)),
        mtu_discovery: !opts.disable_mtu_discovery,
        congestion: Some(controllers),
    }
    .build()
}

/// `Ok(true)` when QUIC version 1 is among the requested ones.
fn offers_version_one(versions: &[String]) -> Result<bool, BuildError> {
    if versions.is_empty() {
        return Ok(true);
    }
    let mut one = false;
    for name in versions {
        let normalized = name.trim().to_lowercase().replace('_', "-");
        match normalized.as_str() {
            "v1" | "1" | "rfc9000" | "rfc-9000" => one = true,
            "v2" | "2" | "rfc9369" | "rfc-9369" => {}
            _ => {
                return Err(BuildError::invalid(format!(
                    "unsupported QUIC version {name:?} (supported: v1, v2)"
                )));
            }
        }
    }
    Ok(one)
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &ShadowQuicOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    if !offers_version_one(&opts.quic_versions)? {
        return Err(BuildError::unsupported(
            "shadowquic: QUIC version 2 is not supported by this QUIC stack",
        ));
    }
    let alpn = if opts.alpn.is_empty() {
        vec!["h3".to_string()]
    } else {
        opts.alpn.clone()
    };
    let user = JlsUser {
        username: opts.username.clone(),
        password: opts.password.clone(),
    };
    let jls = JlsClient::new(user, &alpn)
        .map_err(|err| BuildError::invalid(format!("shadowquic tls: {err}")))?;
    let window = bbr_window(opts.cwnd);
    let controllers = SwitchFactory::new(controller(
        &opts.congestion_controller,
        window,
        BbrProfile::parse(&opts.bbr_profile),
    ));
    let link = QuicLink {
        egress: Egress::new(&def.name, &def.common),
        server: Address::new(&opts.server, opts.port),
        server_name: Some(if opts.sni.is_empty() {
            opts.server.clone()
        } else {
            opts.sni.clone()
        }),
        crypto: Crypto::Custom(Arc::new(jls)),
        transport: transport(opts, controllers.clone()),
        obfs: ObfsSpec::None,
        hop: None,
        datagram_frame: Some(datagram_frame(opts)),
        tasks: ctx.tasks.clone(),
    };
    Ok(Arc::new(ShadowQuic {
        info: info_for(def, OutboundKind::ShadowQuic, &opts.server, opts.port, true),
        link,
        settings: Settings {
            over_stream: opts.udp_over_stream,
            up: parse_bps(&opts.up),
            down: parse_bps(&opts.down),
            window,
            profile: BbrProfile::parse(&opts.bbr_profile),
        },
        controllers,
        current: SessionSlot::default(),
        connecting: tokio::sync::Mutex::new(()),
    }))
}
