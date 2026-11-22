use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use concord_common::sync::lock;
use futures_util::StreamExt;
use futures_util::future::BoxFuture;
use futures_util::stream::FuturesUnordered;
use tokio::time::{Instant, interval_at};
use tokio_util::sync::CancellationToken;

use super::ctx::{Ctx, ProbeError, Stop};
use super::fetch::ProbeRequest;
use super::hits::{HitRecorder, RouteHit, resolve_exit, with_hit};
use super::{BROWSER_USER_AGENT, DEFAULT_PROBE_TIMEOUT, LookupClaim, Prober, timeout_from_millis};

const STAGGER: Duration = Duration::from_millis(800);
const MAX_BODY: usize = 4096;

#[derive(Debug, Default)]
pub struct OutboundIpResult {
    pub url: String,
    pub body: String,
    pub delay: i64,
    pub chains: Vec<String>,
    pub error: Option<&'static str>,
    pub core_epoch: u64,
    pub route_version: u64,
    pub hits: Vec<RouteHit>,
    pub node_hits: Vec<RouteHit>,
}

type Race<'a> = FuturesUnordered<BoxFuture<'a, Option<OutboundIpResult>>>;

struct ClaimGuard<'a> {
    prober: &'a Prober,
    id: u64,
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        {
            let mut lookups = lock(&self.prober.claims.lookups);
            lookups.retain(|claim| claim.id != self.id);
        }
    }
}

struct Sources<'a> {
    prober: &'a Prober,
    ctx: &'a Ctx,
    urls: &'a [String],
    proxy: &'a str,
    timeout: Duration,
    hits: &'a Arc<HitRecorder>,
    next: usize,
}

impl<'a> Sources<'a> {
    fn start(&mut self, running: &mut Race<'a>) {
        let Some(url) = self.urls.get(self.next) else {
            return;
        };
        self.next += 1;
        running.push(Box::pin(self.prober.outbound_ip_source(
            self.ctx,
            url,
            self.proxy,
            self.timeout,
            self.hits,
        )));
    }
}

impl Prober {
    /// Takes the first usable answer and drops the losers so they stop occupying
    /// probe slots. `url` is the source that was asked, not where it redirected,
    /// and `body` is raw: Dart owns the sources and their parsers.
    pub async fn outbound_ip(
        &self,
        proxy: &str,
        urls: &[String],
        timeout_ms: i64,
    ) -> OutboundIpResult {
        let stamp = self.env.stamp();
        let hits = Arc::new(HitRecorder::default());
        let failure = |kind: ProbeError| OutboundIpResult {
            error: Some(kind.as_str()),
            core_epoch: stamp.epoch,
            route_version: stamp.version,
            hits: hits.list(),
            ..OutboundIpResult::default()
        };
        if urls.is_empty() {
            return failure(ProbeError::Failed);
        }

        let timeout = timeout_from_millis(timeout_ms, DEFAULT_PROBE_TIMEOUT);
        let ctx = Ctx::new(timeout);
        let _claim = self.claim_lookup(stamp.epoch, ctx.token().clone());

        let mut sources = Sources {
            prober: self,
            ctx: &ctx,
            urls,
            proxy,
            timeout,
            hits: &hits,
            next: 0,
        };
        let mut running: Race<'_> = FuturesUnordered::new();
        sources.start(&mut running);
        let mut stagger = interval_at(Instant::now() + STAGGER, STAGGER);
        while !running.is_empty() {
            tokio::select! {
                answer = running.next() => match answer {
                    Some(Some(answer)) => return answer,
                    _ => sources.start(&mut running),
                },
                _ = stagger.tick() => sources.start(&mut running),
                stop = ctx.done() => return failure(stop.kind()),
            }
        }
        failure(ctx.err().map_or(ProbeError::Failed, Stop::kind))
    }

    /// Only an older epoch's lookup is stale; two targets of one epoch can share
    /// a request.
    fn claim_lookup(&self, epoch: u64, token: CancellationToken) -> ClaimGuard<'_> {
        let id = self.claims.id();
        {
            let mut lookups = lock(&self.claims.lookups);
            lookups.retain(|other| {
                let stale = other.epoch < epoch;
                if stale {
                    other.token.cancel();
                }
                !stale
            });
            lookups.push(LookupClaim { id, epoch, token });
        }
        ClaimGuard { prober: self, id }
    }

    async fn outbound_ip_source(
        &self,
        ctx: &Ctx,
        url: &str,
        proxy: &str,
        timeout: Duration,
        hits: &Arc<HitRecorder>,
    ) -> Option<OutboundIpResult> {
        let mut request = ProbeRequest::get(url);
        request.proxy = proxy.to_string();
        request.headers = vec![("User-Agent".to_string(), BROWSER_USER_AGENT.to_string())];
        request.timeout = timeout;
        request.max_body = MAX_BODY;
        request.recorder = Some(hits.clone());
        let result = self.run_probe(ctx, request).await?;
        if result.error.is_some() || result.status != 200 || !mentions_ip(&result.body) {
            return None;
        }
        let node_hits = self.node_hits(&result.chains, proxy, &result.hits);
        Some(OutboundIpResult {
            url: url.to_string(),
            body: result.body,
            delay: result.delay,
            chains: result.chains,
            error: None,
            core_epoch: result.core_epoch,
            route_version: result.route_version,
            hits: result.hits,
            node_hits,
        })
    }

    /// The hits as if the node the answer left through had been asked for: a load
    /// balancer above it is the exit of the target, never of the node.
    fn node_hits(&self, chains: &[String], proxy: &str, hits: &[RouteHit]) -> Vec<RouteHit> {
        let Some(node) = chains.first().filter(|node| node.as_str() != proxy) else {
            return Vec::new();
        };
        let mut through = Vec::new();
        for hit in hits {
            with_hit(
                &mut through,
                RouteHit {
                    host: hit.host.clone(),
                    proxy: node.clone(),
                    exit: resolve_exit(&*self.env, &hit.host, node),
                },
            );
        }
        through
    }
}

/// A rate-limit or captcha page can still answer 200, and Dart cannot fall back
/// once the race is decided, so a body without a public address must not win it.
pub(super) fn mentions_ip(body: &str) -> bool {
    body.split(|ch: char| !(ch == '.' || ch == ':' || ch.is_ascii_alphanumeric()))
        .filter_map(|token| token.parse::<IpAddr>().ok())
        .map(unmap)
        .any(is_public)
}

fn unmap(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(addr, IpAddr::V4),
        IpAddr::V4(_) => addr,
    }
}

/// Global unicast the way Go defines it, minus private, ULA and the RFC 6598
/// space for carrier-grade NAT.
fn is_public(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_private()
                || shared_address_space(v4))
        }
        IpAddr::V6(v6) => {
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unique_local())
        }
    }
}

fn shared_address_space(addr: Ipv4Addr) -> bool {
    let [first, second, ..] = addr.octets();
    first == 100 && (64..128).contains(&second)
}

#[cfg(test)]
mod poisoned {
    use super::super::testing::FakeEnv;
    use super::*;

    #[test]
    fn a_lookup_claim_leaves_after_a_holder_poisoned_the_list() {
        let prober = FakeEnv::new(&[]).prober();
        let claim = prober.claim_lookup(1, CancellationToken::new());
        assert_eq!(lock(&prober.claims.lookups).len(), 1);
        concord_test_support::poison(&prober.claims.lookups);
        drop(claim);
        assert!(lock(&prober.claims.lookups).is_empty());
    }
}
