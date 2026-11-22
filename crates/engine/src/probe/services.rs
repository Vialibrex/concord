use std::net::IpAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use concord_common::sync::lock;
use futures_util::FutureExt;
use futures_util::future::{BoxFuture, join_all};

use super::ctx::{Ctx, ProbeError};
use super::fetch::{ProbeRequest, ProbeResult, Until, acquire};
use super::hits::{HitRecorder, RouteHit};
use super::rules::{self, Patterns};
use super::{BROWSER_USER_AGENT, DEFAULT_PROBE_TIMEOUT, Prober, timeout_from_millis};

/// A sweep runs a few checks at a time so it cannot take every probe slot. It
/// therefore runs in waves, and a rule like Disney+ spends several requests in
/// sequence, so the run gets a multiple of the request budget.
const CHECK_CONCURRENCY: usize = 4;
const SWEEP_BUDGET_FACTOR: u32 = 6;

/// Region markers sit deep inside these pages; endpoints that answer with a few
/// lines get the small cap.
pub const HTML_MAX_BODY: usize = 512 * 1024;
pub const SMALL_MAX_BODY: usize = 16 * 1024;
/// Gemini's region sits past 800 KiB, Prime Video's at times past 4 MiB.
pub const SCAN_MAX_BODY: usize = 8 * 1024 * 1024;

/// Dart maps each status to a localized label, so these strings are part of the
/// contract and cannot be reworded on one side alone.
pub const AVAILABLE: &str = "available";
pub const UNAVAILABLE: &str = "unavailable";
pub const RESTRICTED: &str = "restricted";
pub const DISALLOWED_ISP: &str = "disallowed-isp";
pub const BLOCKED: &str = "blocked";
pub const UNSUPPORTED_REGION: &str = "unsupported-region";
pub const ORIGINALS_ONLY: &str = "originals-only";
pub const COMING_SOON: &str = "coming-soon";
pub const TIMEOUT: &str = "timeout";
pub const FAILED: &str = "failed";

/// A blank status means a rule has yet to judge the answer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ServiceItem {
    pub name: String,
    pub status: &'static str,
    pub region: String,
    pub ip: String,
    pub delay: i64,
    pub chains: Vec<String>,
    pub checked_at: i64,
    pub core_epoch: u64,
    pub route_version: u64,
    pub hits: Vec<RouteHit>,
}

impl ServiceItem {
    pub fn with_status(status: &'static str) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }
}

#[async_trait]
pub trait Requester: Send + Sync {
    async fn request(&self, ctx: &Ctx, request: ProbeRequest) -> Option<ProbeResult>;
}

#[async_trait]
impl Requester for Prober {
    async fn request(&self, ctx: &Ctx, request: ProbeRequest) -> Option<ProbeResult> {
        self.run_probe(ctx, request).await
    }
}

pub struct ServiceEnv<'a> {
    pub requester: &'a dyn Requester,
    pub ctx: &'a Ctx,
    pub proxy: &'a str,
    pub timeout: Duration,
    pub hits: &'a Arc<HitRecorder>,
    pub patterns: &'a Patterns,
}

impl ServiceEnv<'_> {
    pub async fn get(&self, url: &str, max_body: usize) -> Option<ProbeResult> {
        let mut request = ProbeRequest::get(url);
        request.max_body = max_body;
        self.send(request).await
    }

    pub async fn scan(&self, url: &str, until: Until) -> Option<ProbeResult> {
        let mut request = ProbeRequest::get(url);
        request.max_body = SCAN_MAX_BODY;
        request.until = Some(until);
        self.send(request).await
    }

    pub async fn send(&self, mut request: ProbeRequest) -> Option<ProbeResult> {
        request.proxy = self.proxy.to_string();
        request.timeout = self.timeout;
        request.recorder = Some(self.hits.clone());
        let mut headers = vec![("User-Agent".to_string(), BROWSER_USER_AGENT.to_string())];
        for (name, value) in request.headers {
            headers.retain(|(known, _)| !known.eq_ignore_ascii_case(&name));
            headers.push((name, value));
        }
        request.headers = headers;
        self.requester.request(self.ctx, request).await
    }
}

pub type CheckFuture<'a> = BoxFuture<'a, ServiceItem>;
type CheckFn = dyn for<'a, 'b> Fn(&'a ServiceEnv<'b>) -> CheckFuture<'a> + Send + Sync;

pub struct Checker {
    pub name: String,
    pub check: Box<CheckFn>,
}

impl Checker {
    pub fn new<F>(name: &str, check: F) -> Self
    where
        F: for<'a, 'b> Fn(&'a ServiceEnv<'b>) -> CheckFuture<'a> + Send + Sync + 'static,
    {
        Self {
            name: name.to_string(),
            check: Box::new(check),
        }
    }
}

pub fn default_checkers() -> Vec<Checker> {
    vec![
        Checker::new("google", |env| {
            Box::pin(rules::reachable(env, "https://www.google.com/generate_204"))
        }),
        Checker::new("github", |env| {
            Box::pin(rules::reachable(env, "https://github.com/"))
        }),
        Checker::new("youtube", |env| Box::pin(rules::youtube_premium(env))),
        Checker::new("chatgpt", |env| Box::pin(rules::chatgpt(env))),
        Checker::new("claude", |env| Box::pin(rules::claude(env))),
        Checker::new("gemini", |env| Box::pin(rules::gemini(env))),
        Checker::new("netflix", |env| Box::pin(rules::netflix(env))),
        Checker::new("disney-plus", |env| Box::pin(rules::disney_plus(env))),
        Checker::new("prime-video", |env| Box::pin(rules::prime_video(env))),
        Checker::new("spotify", |env| Box::pin(rules::spotify(env))),
        Checker::new("tiktok", |env| Box::pin(rules::tiktok(env))),
        Checker::new("discord", |env| Box::pin(rules::discord(env))),
        Checker::new("bilibili", |env| Box::pin(rules::bilibili(env))),
    ]
}

pub struct Registry {
    checkers: Vec<Checker>,
    pub(super) slots: Arc<tokio::sync::Semaphore>,
    patterns: Patterns,
}

impl Registry {
    pub fn new(checkers: Vec<Checker>) -> Self {
        Self {
            checkers,
            slots: Arc::new(tokio::sync::Semaphore::new(CHECK_CONCURRENCY)),
            patterns: Patterns::new(),
        }
    }

    /// An empty `names` runs every check; unknown names are dropped.
    fn selected(&self, names: &[String]) -> Vec<&Checker> {
        if names.is_empty() {
            return self.checkers.iter().collect();
        }
        names
            .iter()
            .filter_map(|name| self.checkers.iter().find(|checker| checker.name == *name))
            .collect()
    }
}

struct Claimed<'a> {
    prober: &'a Prober,
    claims: Vec<(String, u64, Ctx)>,
}

impl Drop for Claimed<'_> {
    fn drop(&mut self) {
        let mut services = lock(&self.prober.claims.services);
        for (name, id, ctx) in &self.claims {
            ctx.cancel();
            if services.get(name).is_some_and(|(held, _)| held == id) {
                services.remove(name);
            }
        }
    }
}

impl Prober {
    pub async fn services(
        &self,
        proxy: &str,
        names: &[String],
        timeout_ms: i64,
    ) -> Vec<ServiceItem> {
        let wanted = self.services.selected(names);
        if wanted.is_empty() {
            return Vec::new();
        }
        let timeout = timeout_from_millis(timeout_ms, DEFAULT_PROBE_TIMEOUT);
        let sweep = Ctx::new(timeout.checked_mul(SWEEP_BUDGET_FACTOR).unwrap_or(timeout));

        let claimed = self.claim_services(&sweep, &wanted);
        let checks = wanted
            .iter()
            .zip(&claimed)
            .map(|(checker, ctx)| async move {
                let _slot = acquire(&self.services.slots, ctx).await;
                self.run_service_check(ctx, checker, proxy, timeout).await
            });
        join_all(checks).await
    }

    /// Claimed before queueing, so a check waiting for a slot is cancelled the
    /// moment its service is asked again. The host asks for a service again only
    /// once the older answer can no longer be used, so a newer check cancels the
    /// older one and frees its probe slots.
    fn claim_services<'a>(&'a self, sweep: &Ctx, wanted: &[&Checker]) -> ClaimedContexts<'a> {
        let mut claimed = Claimed {
            prober: self,
            claims: Vec::new(),
        };
        let mut contexts = Vec::with_capacity(wanted.len());
        for checker in wanted {
            let known = claimed
                .claims
                .iter()
                .find(|(name, ..)| *name == checker.name)
                .map(|(.., ctx)| ctx.clone());
            let ctx = known.unwrap_or_else(|| {
                let id = self.claims.id();
                let ctx = sweep.fork();
                if let Some((_, previous)) = lock(&self.claims.services)
                    .insert(checker.name.clone(), (id, ctx.token().clone()))
                {
                    previous.cancel();
                }
                claimed.claims.push((checker.name.clone(), id, ctx.clone()));
                ctx
            });
            contexts.push(ctx);
        }
        ClaimedContexts {
            contexts,
            _claimed: claimed,
        }
    }

    async fn run_service_check(
        &self,
        ctx: &Ctx,
        checker: &Checker,
        proxy: &str,
        timeout: Duration,
    ) -> ServiceItem {
        let stamp = self.env.stamp();
        let hits = Arc::new(HitRecorder::default());
        let mut item = ServiceItem::with_status(FAILED);
        if ctx.err().is_none() {
            let env = ServiceEnv {
                requester: self,
                ctx,
                proxy,
                timeout,
                hits: &hits,
                patterns: &self.services.patterns,
            };
            item = run_with_retry(&env, checker, timeout).await;
        }
        item.name = checker.name.clone();
        item.checked_at = now_millis();
        item.core_epoch = stamp.epoch;
        item.route_version = stamp.version;
        item.hits = hits.list();
        item
    }
}

pub struct ClaimedContexts<'a> {
    contexts: Vec<Ctx>,
    _claimed: Claimed<'a>,
}

impl<'a> IntoIterator for &'a ClaimedContexts<'_> {
    type Item = &'a Ctx;
    type IntoIter = std::slice::Iter<'a, Ctx>;

    fn into_iter(self) -> Self::IntoIter {
        self.contexts.iter()
    }
}

/// A misbehaving rule must not take the sweep down with it. A timeout gets one
/// more try when the sweep still has a request budget left.
async fn run_with_retry(env: &ServiceEnv<'_>, checker: &Checker, timeout: Duration) -> ServiceItem {
    let run = AssertUnwindSafe(async {
        let mut item = (checker.check)(env).await;
        if item.status == TIMEOUT && env.ctx.has_budget(timeout) {
            item = (checker.check)(env).await;
        }
        item
    });
    run.catch_unwind()
        .await
        .unwrap_or_else(|_| ServiceItem::with_status(FAILED))
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

pub fn item_from(result: Option<&ProbeResult>) -> ServiceItem {
    let Some(result) = result else {
        return ServiceItem::with_status(FAILED);
    };
    let mut item = ServiceItem {
        delay: result.delay,
        chains: result.chains.clone(),
        ..ServiceItem::default()
    };
    match result.error {
        None => {}
        Some(ProbeError::Timeout) => {
            item.status = TIMEOUT;
            item.delay = 0;
        }
        Some(ProbeError::Failed) => {
            item.status = FAILED;
            item.delay = 0;
        }
    }
    item
}

pub fn status_from_code(code: u16) -> &'static str {
    match code {
        200..=299 => AVAILABLE,
        401 | 403 | 429 | 451 => RESTRICTED,
        _ => UNAVAILABLE,
    }
}

/// The result a rule goes on to judge, when the request got an answer.
pub fn answered<'r>(
    item: &ServiceItem,
    result: &'r Option<ProbeResult>,
) -> Option<&'r ProbeResult> {
    result.as_ref().filter(|_| item.status.is_empty())
}

pub fn trace_value(body: &str, key: &str) -> String {
    body.split('\n')
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default()
}

/// The `ip=` line of a Cloudflare trace, kept only when it is an address.
pub fn trace_ip(body: &str) -> String {
    trace_value(body, "ip")
        .parse::<IpAddr>()
        .map(|addr| addr.to_canonical().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod poisoned {
    use super::super::testing::FakeEnv;
    use super::*;

    #[tokio::test]
    async fn a_service_claim_leaves_after_a_holder_poisoned_the_map() {
        let prober = FakeEnv::new(&[]).prober();
        let checkers = default_checkers();
        let wanted: Vec<&Checker> = checkers.iter().take(1).collect();
        let claimed = prober.claim_services(&Ctx::new(Duration::from_secs(5)), &wanted);
        let ctx = claimed.contexts.first().unwrap().clone();
        assert_eq!(lock(&prober.claims.services).len(), 1);
        concord_test_support::poison(&prober.claims.services);
        drop(claimed);
        assert!(lock(&prober.claims.services).is_empty());
        assert!(ctx.token().is_cancelled());
    }
}
