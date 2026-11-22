use std::sync::{Arc, Mutex};

use concord_common::ClockOffset;
use concord_common::sync::lock;
use concord_tls::{SystemRoots, TrustStore, parse_certificates};
use rustls_pki_types::CertificateDer;

const CA_BUNDLE: &[u8] = include_bytes!("../../../assets/ca-certificates.crt");

pub(crate) struct TrustCache {
    system: Arc<SystemRoots>,
    current: Mutex<Option<(Vec<String>, Arc<TrustStore>)>>,
    clock: Arc<ClockOffset>,
}

impl TrustCache {
    pub fn new(clock: Arc<ClockOffset>) -> Self {
        TrustCache {
            system: Arc::default(),
            current: Mutex::new(None),
            clock,
        }
    }

    pub fn for_custom(&self, custom: Vec<String>) -> Arc<TrustStore> {
        let mut current = lock(&self.current);
        if let Some((held, store)) = current.as_ref()
            && *held == custom
        {
            return store.clone();
        }
        let mut certs = Vec::new();
        for text in &custom {
            let parsed = parse_certificates(text);
            if parsed.is_empty() {
                tracing::warn!("{text}\nadd error: add certificate failed");
            }
            certs.extend(parsed);
        }
        let store = self.store(certs);
        *current = Some((custom, store.clone()));
        store
    }

    fn store(&self, custom: Vec<CertificateDer<'static>>) -> Arc<TrustStore> {
        TrustStore::with_system_roots(self.clock.clone(), self.system.clone(), CA_BUNDLE, custom)
    }
}
