use std::io;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, DialEnv, Initiator, Outbound, OutboundInfo, PacketSession, Tasks,
};
use concord_config::proxy::SmuxOpts;
use concord_transport::{Brutal, MuxDialFn, MuxProtocol, SingMuxClient, SingMuxOptions};

use crate::addr_codec::SOCKS;
use crate::ctx::BuildError;
use crate::dgram::StreamSession;
use crate::lazy::Kick;
use crate::link::EnvSlot;
use crate::uot::AddrFrames;
use crate::util::parse_bps;

const TCP_TIMEOUT: Duration = Duration::from_secs(5);

struct Muxed {
    info: OutboundInfo,
    inner: Arc<dyn Outbound>,
    client: Arc<SingMuxClient>,
    slot: EnvSlot,
    only_tcp: bool,
    tasks: Tasks,
}

impl Muxed {
    fn remember(&self, cx: &DialCx<'_>) {
        self.slot.store(Some(Arc::new(cx.env.clone())));
    }
}

#[async_trait]
impl Outbound for Muxed {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        self.remember(cx);
        Ok(Box::new(Kick::new(self.client.connect_tcp(dst).await?)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if self.only_tcp {
            return self.inner.associate(cx, hint).await;
        }
        self.remember(cx);
        let stream = self.client.listen_packet(Some(hint)).await?;
        Ok(Arc::new(StreamSession::new(
            stream,
            AddrFrames(SOCKS),
            AddrFrames(SOCKS),
            hint.clone(),
            &self.tasks,
        )))
    }

    fn multi_destination_udp(&self) -> bool {
        !self.only_tcp || self.inner.multi_destination_udp()
    }

    fn reset_sessions(&self) {
        self.inner.reset_sessions();
        let client = self.client.clone();
        self.tasks
            .spawn_detached(async move { client.close().await });
    }

    fn link_changed(&self) {
        self.inner.link_changed();
    }
}

fn dial_through(inner: Arc<dyn Outbound>, slot: EnvSlot) -> MuxDialFn {
    Arc::new(move |target: Address| {
        let (inner, slot) = (inner.clone(), slot.clone());
        Box::pin(async move {
            let env: Arc<DialEnv> = slot
                .load_full()
                .ok_or_else(|| io::Error::other("smux dial without an environment"))?;
            let cx = DialCx::new(&env, Initiator::Proxy, None);
            inner.connect(&cx, &target).await
        })
    })
}

pub(crate) fn wrap(
    inner: Arc<dyn Outbound>,
    opts: &SmuxOpts,
    tasks: &Tasks,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let brutal = opts
        .brutal
        .as_ref()
        .filter(|brutal| brutal.enabled)
        .map(|brutal| Brutal {
            send_bps: parse_bps(&brutal.up),
            receive_bps: parse_bps(&brutal.down),
        });
    let protocol =
        MuxProtocol::parse(&opts.protocol).map_err(|err| BuildError::invalid(err.to_string()))?;
    let slot: EnvSlot = Arc::new(ArcSwapOption::empty());
    let client = SingMuxClient::new(
        SingMuxOptions {
            protocol,
            max_connections: opts.max_connections as usize,
            min_streams: opts.min_streams as usize,
            max_streams: opts.max_streams as usize,
            padding: opts.padding,
            tcp_timeout: TCP_TIMEOUT,
            brutal,
        },
        dial_through(inner.clone(), slot.clone()),
        tasks.clone(),
    );
    let mut info = inner.info().clone();
    info.udp = info.udp || !opts.only_tcp;
    Ok(Arc::new(Muxed {
        info,
        inner,
        client,
        slot,
        only_tcp: opts.only_tcp,
        tasks: tasks.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use concord_common::OutboundKind;

    use super::*;
    use crate::reject::Reject;

    struct Heard {
        closed: Reject,
        links: AtomicUsize,
    }

    #[async_trait]
    impl Outbound for Heard {
        fn info(&self) -> &OutboundInfo {
            self.closed.info()
        }

        async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
            self.closed.connect(cx, dst).await
        }

        async fn associate(
            &self,
            cx: &DialCx<'_>,
            hint: &Address,
        ) -> io::Result<Arc<dyn PacketSession>> {
            self.closed.associate(cx, hint).await
        }

        fn link_changed(&self) {
            self.links.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_link_change_reaches_the_node_under_the_mux() {
        let tracked = crate::testing::Tracked::new();
        let inner = Arc::new(Heard {
            closed: Reject::new("inner", OutboundKind::Reject),
            links: AtomicUsize::new(0),
        });
        let muxed = wrap(inner.clone(), &SmuxOpts::default(), &tracked.tasks).unwrap();
        muxed.link_changed();
        assert_eq!(inner.links.load(Ordering::SeqCst), 1);
    }
}
