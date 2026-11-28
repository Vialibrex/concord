mod conn;
mod h2;
mod h3;
mod padding;
mod request;

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
};
use concord_config::proxy::{NaiveOpts, ProxyDef};

use self::conn::{Conn, Dialer, Retired, is_unprocessed};
use self::h2::Windows;
use self::padding::PaddingType;
use self::request::{Negotiated, Template, reply};
use crate::ctx::{BuildCtx, BuildError};
use crate::link::simple_link;
use crate::node::{Egress, info_for};
use crate::session_slot::SessionSlot;
use crate::session_slot::{Resets, Ticket};
use crate::uot;
use crate::util::lock;

/// Chrome's ALPN list; the server must pick h2, there is no HTTP/1.1 fallback.
const ALPN: [&str; 2] = ["h2", "http/1.1"];

#[derive(Default)]
struct Slot {
    session: SessionSlot<Conn>,
    dialing: tokio::sync::Mutex<()>,
}

/// Connections a slot moved off while they still carry streams, for a reset to close. `resets`
/// lets a slot that moved off one while a reset ran close it rather than keep it past the reset.
#[derive(Default)]
struct Retirement {
    resets: Resets,
    conns: Vec<Retired>,
}

struct Naive {
    info: OutboundInfo,
    dialer: Dialer,
    template: Template,
    negotiated: Arc<Negotiated>,
    /// Made as the turns reach them, up to `concurrency`.
    slots: Mutex<Vec<Arc<Slot>>>,
    concurrency: usize,
    retired: Mutex<Retirement>,
    next: AtomicUsize,
    uot: Option<u8>,
}

async fn bounded<T>(
    wait: Option<Duration>,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match wait {
        Some(wait) => tokio::time::timeout(wait, future)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
        None => future.await,
    }
}

impl Naive {
    /// One of `insecure-concurrency` connections, taken in turn as cronet-go does.
    async fn session(&self, cx: &DialCx<'_>) -> io::Result<Arc<Conn>> {
        let turn = self.next.fetch_add(1, Ordering::Relaxed) % self.concurrency;
        let slot = {
            let mut slots = lock(&self.slots);
            match slots.get(turn) {
                Some(slot) => slot.clone(),
                None => {
                    slots.resize_with(turn, Arc::default);
                    let slot = Arc::<Slot>::default();
                    slots.push(slot.clone());
                    slot
                }
            }
        };
        let (held, since) = {
            let retired = lock(&self.retired);
            (slot.session.get(|_| true).0, retired.resets.ticket())
        };
        let connect = || bounded(cx.remaining(), self.dialer.connect(cx));
        let conn = slot
            .session
            .offer(&slot.dialing, Conn::usable, connect, |conn| conn.close())
            .await?;
        if let Some(held) = held.filter(|held| !Arc::ptr_eq(held, &conn)) {
            self.retire(&held, since);
        }
        Ok(conn)
    }

    /// Keeps `held`, which a slot moved off, for the next reset to close; closes it now when a
    /// reset ran since `since`, which read `held`.
    fn retire(&self, held: &Conn, since: Ticket) {
        let held = held.retired();
        let mut retired = lock(&self.retired);
        if !retired.resets.none_since(since) {
            held.close();
            return;
        }
        retired.conns.retain(|old| !old.gone());
        if !retired.conns.iter().any(|old| old.same(&held)) {
            retired.conns.push(held);
        }
    }

    /// A tunnel to `dst`, sent once more when the server turned it away unprocessed, as Chromium's
    /// `HttpNetworkTransaction::HandleIOError` (http_network_transaction.cc) retries on
    /// ERR_HTTP2_SERVER_REFUSED_STREAM, which a REFUSED_STREAM and a GOAWAY both end a stream with
    /// (`spdy_session.cc:2937-2938`, `:2977-2988`).
    async fn tunnel(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        match self.try_tunnel(cx, dst).await {
            Err(err) if is_unprocessed(&err) => self.try_tunnel(cx, dst).await,
            done => done,
        }
    }

    /// Once the node's padding is known the tunnel is handed over before the server answers, as
    /// naiveproxy's fast open.
    async fn try_tunnel(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let session = self.session(cx).await?;
        let request = self.template.request(dst)?;
        let opened = bounded(cx.remaining(), session.open(request)).await?;
        let negotiated = self.negotiated.clone();
        match negotiated.get() {
            Some(expected) => {
                let check = Box::new(move |head: &http::response::Parts| {
                    let padding = reply(head.status, &head.headers)?;
                    negotiated.set(padding);
                    if padding == expected {
                        Ok(())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "naive server changed its padding type",
                        ))
                    }
                });
                Ok(expected.wrap(opened.early(check)))
            }
            None => {
                let mut agreed = PaddingType::None;
                let stream = bounded(
                    cx.remaining(),
                    opened.answered(|head| {
                        agreed = reply(head.status, &head.headers)?;
                        Ok(())
                    }),
                )
                .await?;
                negotiated.set(agreed);
                Ok(agreed.wrap(stream))
            }
        }
    }
}

#[async_trait]
impl Outbound for Naive {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        self.tunnel(cx, dst).await
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        let Some(version) = self.uot.filter(|_| self.info.udp) else {
            return Err(CoreError::UdpUnsupported(self.info.name.to_string()).into());
        };
        let stream = self.tunnel(cx, &uot::destination(version)).await?;
        uot::session(stream, version, hint, self.dialer.tasks())
    }

    fn reset_sessions(&self) {
        let mut retired = lock(&self.retired);
        retired.resets.bump();
        for slot in lock(&self.slots).iter() {
            if let Some(session) = slot.session.reset() {
                session.close();
            }
        }
        for conn in retired.conns.drain(..) {
            conn.close();
        }
        drop(retired);
        self.negotiated.forget();
    }
}

fn uot_version(opts: &NaiveOpts) -> Result<Option<u8>, BuildError> {
    if !opts.udp_over_tcp {
        return Ok(None);
    }
    match opts.udp_over_tcp_version {
        0 | 2 => Ok(Some(2)),
        uot::LEGACY_VERSION => Ok(Some(uot::LEGACY_VERSION)),
        other => Err(BuildError::invalid(format!(
            "naive {} unknown udp over tcp protocol version: {other}",
            opts.server
        ))),
    }
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &NaiveOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    Ok(Arc::new(naive(def, opts, ctx)?))
}

fn naive(def: &ProxyDef, opts: &NaiveOpts, ctx: &BuildCtx) -> Result<Naive, BuildError> {
    let uot = uot_version(opts)?;
    let udp = def.common.udp && uot.is_some();
    if def.common.udp && !udp {
        tracing::warn!("naive {}: UDP needs udp-over-tcp; disabling it", def.name);
    }
    let dialer = if opts.quic {
        Dialer::H3(Box::new(h3::link(
            opts,
            Egress::new(&def.name, &def.common),
            ctx,
        )?))
    } else {
        let mut tls = opts.tls.clone();
        tls.client_fingerprint = "chrome".into();
        tls.alpn = ALPN.iter().map(|p| (*p).to_string()).collect();
        Dialer::H2 {
            link: Box::new(simple_link(def, &opts.server, opts.port, &tls, ctx)?),
            windows: Windows::new(opts.stream_receive_window),
            tasks: ctx.tasks.clone(),
        }
    };
    let template = Template::new(&opts.username, &opts.password, &opts.headers)?;
    let concurrency = usize::try_from(opts.insecure_concurrency.max(1)).unwrap_or(usize::MAX);
    Ok(Naive {
        info: info_for(def, OutboundKind::Naive, &opts.server, opts.port, udp),
        dialer,
        template,
        negotiated: Arc::new(Negotiated::default()),
        slots: Mutex::default(),
        concurrency,
        retired: Mutex::default(),
        next: AtomicUsize::new(0),
        uot,
    })
}

#[cfg(test)]
mod h3_tests;
#[cfg(test)]
mod tests;
