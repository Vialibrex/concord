use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use concord_platform::HomeDir;
use concord_tls::TrustStore;
use concord_tunnel::{ConnTable, Tunnel};

/// Stands in for the MITM engine in a build without the `mitm` feature: the engine's own
/// calls into it do nothing. `concord-api` needs the feature for the MITM methods.
pub struct MitmService {
    pressure: AtomicI32,
}

impl MitmService {
    pub(crate) const ENABLED: bool = false;

    pub(crate) fn new(
        _table: Arc<ConnTable>,
        _fetcher: Arc<dyn concord_group::Fetcher>,
        _events: Arc<dyn concord_common::EventSink>,
    ) -> Self {
        MitmService {
            pressure: AtomicI32::new(0),
        }
    }

    pub(crate) fn is_started(&self) -> bool {
        false
    }

    pub(crate) fn script_hooks(
        &self,
    ) -> Option<std::sync::Arc<dyn concord_common::scripts::ScriptHooks>> {
        None
    }

    pub(crate) fn start(
        &self,
        _home: &Arc<HomeDir>,
        _tunnel: &Tunnel,
        _running: bool,
        _tasks: concord_common::Tasks,
    ) {
    }

    pub(crate) fn apply(
        &self,
        section: &concord_config::MitmDef,
        _modules: Vec<concord_config::mitm::modules::AppliedModule>,
        _trust: Arc<TrustStore>,
        _tasks: concord_common::Tasks,
    ) {
        if section.enable {
            tracing::warn!("[MITM] this build has no MITM; the section is ignored");
        }
    }

    pub(crate) fn set_running(&self, _running: bool) {}

    pub fn set_pressure(&self, level: i32) {
        self.pressure.store(level.clamp(0, 3), Ordering::Relaxed);
    }

    pub fn pressure(&self) -> i32 {
        self.pressure.load(Ordering::Relaxed)
    }

    pub(crate) fn set_capture(&self, _on: bool) {}

    pub(crate) fn set_trusted_ca(&self, _fingerprint: Option<String>) {}

    pub(crate) fn network_changed(&self) {}

    pub(crate) fn shutdown(&self) {}
}
