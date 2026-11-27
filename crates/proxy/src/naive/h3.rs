use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ::h3::error::{Code, StreamError};
use bytes::Bytes;
use concord_common::{BoxStream, DialCx};
use concord_config::proxy::NaiveOpts;
use concord_quic::{BbrProfile, ObfsSpec, QuicConn, Transport, bbr_factory, bbr_window};
use concord_transport::h2io::ResponseCheck;
use concord_transport::h3io::{H3Body, H3Response, H3Writer, RecvStream, SendStream, h3_io_error};
use http::Request;
use quinn::congestion::ControllerFactory;
use tokio::task::JoinHandle;

use super::conn;
use crate::ctx::{BuildCtx, BuildError};
use crate::node::Egress;
use crate::quic::{QuicLink, node_crypto};

type Requests = ::h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

const STREAM_WINDOW: u64 = 6 * 1024 * 1024;
const SESSION_WINDOW: u64 = 15 * 1024 * 1024;
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const ALPN: &str = "h3";

pub(super) fn link(
    opts: &NaiveOpts,
    egress: Egress,
    ctx: &BuildCtx,
) -> Result<QuicLink, BuildError> {
    let (server_name, crypto) = node_crypto(&opts.tls, &opts.server, ALPN, ctx)?;
    Ok(QuicLink {
        egress,
        server: concord_common::Address::new(&opts.server, opts.port),
        server_name: Some(server_name),
        crypto,
        transport: transport(opts)?,
        obfs: ObfsSpec::None,
        hop: None,
        datagram_frame: None,
        tasks: ctx.tasks.clone(),
    })
}

/// cronet-go's QUIC windows and congestion control (`naive_client.go:399-408`); Cubic when unset,
/// as Chromium builds it.
fn transport(opts: &NaiveOpts) -> Result<Arc<quinn::TransportConfig>, BuildError> {
    let congestion: Option<Arc<dyn ControllerFactory + Send + Sync>> =
        match opts.quic_congestion_control.as_str() {
            "" | "cubic" => None,
            "reno" => Some(Arc::new(concord_quic::new_reno())),
            "bbr" => Some(bbr_factory(BbrProfile::Standard, bbr_window(0))),
            other => {
                return Err(BuildError::invalid(format!(
                    "unknown quic congestion control: {other}"
                )));
            }
        };
    Ok(Transport {
        stream_window: concord_quic::or_default(opts.stream_receive_window, STREAM_WINDOW),
        conn_window: concord_quic::or_default(opts.quic_session_receive_window, SESSION_WINDOW),
        peer_bounded_send: false,
        idle: concord_quic::MAX_IDLE,
        keep_alive: Some(KEEP_ALIVE),
        datagram_frame: 0,
        streams: None,
        mtu_discovery: true,
        congestion,
    }
    .build())
}

pub(super) struct Session {
    quic: QuicConn,
    requests: Requests,
    driver: JoinHandle<()>,
    going_away: AtomicBool,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub(super) struct Opened {
    send: SendStream,
    recv: RecvStream,
    session: Arc<Session>,
}

impl Session {
    pub(super) async fn connect(link: &QuicLink, cx: &DialCx<'_>) -> io::Result<Arc<Session>> {
        let quic = link.connect(cx).await?;
        let (mut driver, requests) = ::h3::client::builder()
            .build(h3_quinn::Connection::new(quic.conn.clone()))
            .await
            .map_err(h3_io_error)?;
        let driver = link.tasks.spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(Arc::new(Session {
            quic,
            requests,
            driver,
            going_away: AtomicBool::new(false),
        }))
    }

    pub(super) fn usable(&self) -> bool {
        self.quic.conn.close_reason().is_none() && !self.going_away.load(Ordering::Relaxed)
    }

    /// A stream the server never processed (RFC 9114 §5.2, §8.1) may go again; only a GOAWAY
    /// also leaves this connection to the streams it has.
    fn refused(&self, err: StreamError) -> io::Error {
        match &err {
            // `#[non_exhaustive]` on the variant keeps it from matching as a bare path here.
            StreamError::RemoteClosing { .. } => {
                self.going_away.store(true, Ordering::Relaxed);
                conn::unprocessed(h3_io_error(err))
            }
            StreamError::RemoteTerminate { code, .. } if *code == Code::H3_REQUEST_REJECTED => {
                conn::unprocessed(h3_io_error(err))
            }
            _ => h3_io_error(err),
        }
    }

    pub(super) fn close(&self) {
        self.quic
            .conn
            .close(quinn::VarInt::from_u32(0), b"network changed");
    }

    pub(super) async fn open(self: &Arc<Self>, request: Request<()>) -> io::Result<Opened> {
        let stream = self
            .requests
            .clone()
            .send_request(request)
            .await
            .map_err(|err| self.refused(err))?;
        let (send, recv) = stream.split();
        Ok(Opened {
            send,
            recv,
            session: self.clone(),
        })
    }
}

impl Opened {
    pub(super) fn early(self, check: ResponseCheck) -> BoxStream {
        let writer = H3Writer::new(self.send, self.session.clone());
        Box::new(
            H3Body::new(H3Response::new(self.recv, check, self.session), writer)
                .without_half_close(),
        )
    }

    pub(super) async fn answered(
        mut self,
        check: impl FnOnce(&http::response::Parts) -> io::Result<()>,
    ) -> io::Result<BoxStream> {
        let session = self.session.clone();
        let response = self
            .recv
            .recv_response()
            .await
            .map_err(|err| session.refused(err))?;
        check(&response.into_parts().0)?;
        let writer = H3Writer::new(self.send, self.session.clone());
        Ok(Box::new(
            H3Body::new(H3Response::answered(self.recv, self.session), writer).without_half_close(),
        ))
    }
}
