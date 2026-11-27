use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_common::sync::lock;
use concord_common::{CoreEvent, EventSink};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::deps::{
    DEFAULT_TEST_TIMEOUT, DEFAULT_TEST_URL, GroupDeps, NodeFactory, RouteMoved, TestDefaults,
};
use crate::fetch::Fetcher;
use crate::selection::SelectionStore;

const LOOP_REPORT_INTERVAL: Duration = Duration::from_secs(3);

pub(crate) struct Shared {
    pub events: Arc<dyn EventSink>,
    pub route: Arc<dyn RouteMoved>,
    pub defaults: Arc<dyn TestDefaults>,
    pub selections: Arc<SelectionStore>,
    pub home: Arc<HomeDir>,
    pub fetcher: Arc<dyn Fetcher>,
    pub factory: Arc<dyn NodeFactory>,
    pub trust: Arc<TrustStore>,
    pub tasks: concord_common::Tasks,
    pub refresh: Notify,
    loop_reports: Mutex<HashMap<Arc<str>, Instant>>,
    pub missing_reported: AtomicBool,
}

impl Shared {
    pub fn new(deps: &GroupDeps) -> Arc<Shared> {
        Arc::new(Shared {
            events: deps.events.clone(),
            route: deps.route.clone(),
            defaults: deps.options.clone(),
            selections: deps.selections.clone(),
            home: deps.home.clone(),
            fetcher: deps.fetcher.clone(),
            factory: deps.factory.clone(),
            trust: deps.trust.clone(),
            tasks: deps.tasks.clone(),
            refresh: Notify::new(),
            loop_reports: Mutex::new(HashMap::new()),
            missing_reported: AtomicBool::new(false),
        })
    }

    pub fn default_url(&self) -> String {
        self.defaults
            .test_url()
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| DEFAULT_TEST_URL.to_string())
    }

    pub fn default_timeout(&self) -> Duration {
        self.defaults
            .delay_timeout()
            .filter(|timeout| !timeout.is_zero())
            .unwrap_or(DEFAULT_TEST_TIMEOUT)
    }

    pub fn emit(&self, event: impl FnOnce() -> CoreEvent) {
        if self.events.enabled() {
            self.events.publish(event());
        }
    }

    /// Every dial through a looping dialer fails; one report stands for the burst.
    pub fn report_loop(&self, name: &Arc<str>) {
        let now = Instant::now();
        {
            let mut reports = lock(&self.loop_reports);
            if let Some(last) = reports.get(name)
                && now.duration_since(*last) < LOOP_REPORT_INTERVAL
            {
                return;
            }
            reports.insert(name.clone(), now);
        }
        self.emit(|| CoreEvent::DialerLoop(name.clone()));
    }

    pub fn request_refresh(&self) {
        self.refresh.notify_one();
    }
}
