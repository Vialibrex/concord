use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use concord_common::{Address, RouteStamp, Tasks};
use concord_tls::TrustStore;
use concord_tunnel::Tunnel;
use futures_util::FutureExt;

use crate::probe::{Dialed, ProbeEnv};
use crate::proxy_tasks::ProxyTasks;
use crate::resources::TunnelFetcher;
use crate::route::RouteCounters;

pub(crate) struct TunnelProbes {
    pub tunnel: Tunnel,
    pub tasks: Arc<ProxyTasks>,
    pub route: Arc<RouteCounters>,
    pub fetcher: Arc<TunnelFetcher>,
}

#[async_trait]
impl ProbeEnv for TunnelProbes {
    async fn dial(&self, target: &Address, proxy: Option<&str>) -> io::Result<Dialed> {
        let (stream, chains) = self.tunnel.dial_inner_routed(target, proxy).await?;
        Ok(Dialed {
            stream,
            chains: chains.iter().map(ToString::to_string).collect(),
        })
    }

    fn knows(&self, proxy: &str) -> bool {
        self.tunnel
            .runtime()
            .is_some_and(|runtime| runtime.outbounds.node(proxy).is_some())
    }

    /// Runs where a future cannot wait, and a probe's own dial has just resolved the
    /// name, so an answer that is not at hand counts as no exit: the route is checked
    /// again rather than held on a guess.
    fn exit_through(&self, target: &str, proxy: Option<&str>) -> Option<String> {
        if !concord_common::task::in_runtime() {
            return None;
        }
        let target = Address::parse(target)?;
        self.tunnel.exit_of(&target, proxy).now_or_never()?
    }

    async fn resolve_exit(&self, target: &str, proxy: Option<&str>) -> Option<String> {
        let target = Address::parse(target)?;
        self.tunnel.exit_of(&target, proxy).await
    }

    fn exit_of_chains(&self, chains: &[String]) -> Option<String> {
        self.tunnel.runtime()?.outbounds.exit_of_chains(chains)
    }

    fn stamp(&self) -> RouteStamp {
        self.route.stamp()
    }

    fn trust(&self) -> Arc<TrustStore> {
        self.fetcher.identity.load().trust.clone()
    }

    fn tasks(&self) -> Tasks {
        self.tasks.tasks()
    }

    fn suspended(&self) -> bool {
        self.tunnel.is_suspended()
    }
}
