mod ctx;
mod fetch;
mod hits;
mod outbound_ip;
mod region;
mod rules;
mod services;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{Address, BoxStream, RouteStamp, Tasks};
use concord_tls::TrustStore;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

pub use hits::RouteHit;
pub use outbound_ip::OutboundIpResult;
pub use services::ServiceItem;

const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_CONCURRENCY: usize = 10;

/// Kept in step with `browserUa` in `lib/common/constant.dart`.
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

pub struct Dialed {
    pub stream: BoxStream,
    /// Exit first: the node that dialed out, then the groups above it.
    pub chains: Vec<String>,
}

#[async_trait]
pub trait ProbeEnv: Send + Sync {
    /// `None` routes by the rules as an inbound connection would; `Some` pins the outbound.
    async fn dial(&self, target: &Address, proxy: Option<&str>) -> io::Result<Dialed>;

    fn knows(&self, proxy: &str) -> bool;

    /// `"name" Type addr` of where `target` would leave now, without waking a lazy group.
    /// `None` too when a rule needs a DNS answer that is not at hand.
    fn exit_through(&self, target: &str, proxy: Option<&str>) -> Option<String>;

    /// As `exit_through`, free to wait for the DNS a rule asks for.
    async fn resolve_exit(&self, target: &str, proxy: Option<&str>) -> Option<String> {
        self.exit_through(target, proxy)
    }

    /// The outermost load balancer among `chains[1..]`, else `chains[0]`; never empty.
    fn exit_of_chains(&self, chains: &[String]) -> Option<String>;

    fn stamp(&self) -> RouteStamp;

    fn trust(&self) -> Arc<TrustStore>;

    /// Where a probe's connection is driven; the engine stops it at shutdown.
    fn tasks(&self) -> Tasks;

    /// An apply suspends the tunnel before the route epoch moves, and a refusal in that
    /// window would read as a failure of the current route, so a rule-routed probe waits.
    fn suspended(&self) -> bool {
        false
    }
}

struct LookupClaim {
    id: u64,
    epoch: u64,
    token: CancellationToken,
}

#[derive(Default)]
struct Claims {
    next: AtomicU64,
    lookups: Mutex<Vec<LookupClaim>>,
    services: Mutex<HashMap<String, (u64, CancellationToken)>>,
}

impl Claims {
    fn id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

pub struct Prober {
    env: Arc<dyn ProbeEnv>,
    slots: Arc<Semaphore>,
    claims: Claims,
    services: services::Registry,
}

impl Prober {
    pub fn new(env: Arc<dyn ProbeEnv>) -> Self {
        Self::with_checkers(env, services::default_checkers())
    }

    fn with_checkers(env: Arc<dyn ProbeEnv>, checkers: Vec<services::Checker>) -> Self {
        Self {
            env,
            slots: Arc::new(Semaphore::new(PROBE_CONCURRENCY)),
            claims: Claims::default(),
            services: services::Registry::new(checkers),
        }
    }
}

fn timeout_from_millis(millis: i64, fallback: Duration) -> Duration {
    u64::try_from(millis)
        .ok()
        .filter(|millis| *millis > 0)
        .map_or(fallback, Duration::from_millis)
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn timeouts_fall_back_when_not_positive() {
        let fallback = Duration::from_secs(10);
        assert_eq!(timeout_from_millis(0, fallback), fallback);
        assert_eq!(timeout_from_millis(-5, fallback), fallback);
        assert_eq!(
            timeout_from_millis(250, fallback),
            Duration::from_millis(250)
        );
        assert_eq!(
            timeout_from_millis(i64::MAX, fallback),
            Duration::from_millis(i64::MAX.unsigned_abs())
        );
    }

    #[test]
    fn the_registry_lists_the_services_in_the_order_dart_expects() {
        let names: Vec<String> = services::default_checkers()
            .into_iter()
            .map(|checker| checker.name)
            .collect();
        assert_eq!(
            names,
            [
                "google",
                "github",
                "youtube",
                "chatgpt",
                "claude",
                "gemini",
                "netflix",
                "disney-plus",
                "prime-video",
                "spotify",
                "tiktok",
                "discord",
                "bilibili",
            ]
        );
    }
}
