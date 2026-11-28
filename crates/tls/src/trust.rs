use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, Weak};

use concord_common::ClockOffset;
use concord_common::sync::lock;
use rustls::ClientConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, TrustAnchor};

use crate::TlsError;
use crate::policy::PolicyKey;

pub(crate) fn system_roots() -> Vec<CertificateDer<'static>> {
    concord_platform::system_root_certs()
}

/// Read once, by [`SystemRoots::preload`] or the first handshake; it takes about 90 ms on macOS.
#[derive(Debug, Default)]
pub struct SystemRoots {
    certs: OnceLock<Vec<CertificateDer<'static>>>,
    preloading: AtomicBool,
}

impl SystemRoots {
    pub fn get(&self) -> &[CertificateDer<'static>] {
        self.certs.get_or_init(system_roots)
    }

    pub fn preload(self: &Arc<Self>) {
        if !self.preloading.swap(true, Ordering::Relaxed) {
            let roots = self.clone();
            std::thread::spawn(move || {
                roots.get();
            });
        }
    }
}

type Anchors = Vec<TrustAnchor<'static>>;
type AnchorsInit = Box<dyn FnOnce() -> Anchors + Send>;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct ConfigKey {
    pub(crate) policy: PolicyKey,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) tls13_only: bool,
}

/// Dead configs are pruned once the map doubles past what was live, so a prune costs O(1) per
/// insert however many nodes the profile holds.
#[derive(Debug, Default)]
struct Configs {
    map: HashMap<ConfigKey, Weak<ClientConfig>>,
    prune_at: usize,
}

#[derive(Debug)]
pub struct TrustStore {
    anchors: LazyLock<Anchors, AnchorsInit>,
    /// Nodes that verify alike share a config: a profile can hold 100,000 of them, and
    /// resumption is off, so a config keeps no state from one server for another.
    configs: Mutex<Configs>,
    clock: Arc<ClockOffset>,
    system: Option<Arc<SystemRoots>>,
    custom: Vec<CertificateDer<'static>>,
}

impl TrustStore {
    /// `bundle_pem` is the embedded `ca-certificates.crt`. Entries that do not
    /// parse are skipped, as `AppendCertsFromPEM` does.
    pub fn new(bundle_pem: &[u8], custom: Vec<CertificateDer<'static>>) -> Arc<TrustStore> {
        Self::with_system_roots(Arc::default(), Arc::default(), bundle_pem, custom)
    }

    pub fn from_parts(
        system: Vec<CertificateDer<'static>>,
        bundle_pem: &[u8],
        custom: Vec<CertificateDer<'static>>,
    ) -> Arc<TrustStore> {
        Self::with_clock(Arc::default(), system, bundle_pem, custom)
    }

    /// Certificate validity is judged by `clock`, so an NTP offset applies to every
    /// handshake that uses this store.
    pub fn with_clock(
        clock: Arc<ClockOffset>,
        system: Vec<CertificateDer<'static>>,
        bundle_pem: &[u8],
        custom: Vec<CertificateDer<'static>>,
    ) -> Arc<TrustStore> {
        Self::build(
            clock,
            Box::new(move || anchors_of(&system)),
            None,
            bundle_pem,
            custom,
        )
    }

    /// Never waits for the OS store: its roots join the anchors at the first handshake.
    pub fn with_system_roots(
        clock: Arc<ClockOffset>,
        system: Arc<SystemRoots>,
        bundle_pem: &[u8],
        custom: Vec<CertificateDer<'static>>,
    ) -> Arc<TrustStore> {
        let roots = system.clone();
        Self::build(
            clock,
            Box::new(move || anchors_of(roots.get())),
            Some(system),
            bundle_pem,
            custom,
        )
    }

    fn build(
        clock: Arc<ClockOffset>,
        system: AnchorsInit,
        roots: Option<Arc<SystemRoots>>,
        bundle_pem: &[u8],
        custom: Vec<CertificateDer<'static>>,
    ) -> Arc<TrustStore> {
        let bundle: Vec<_> = CertificateDer::pem_slice_iter(bundle_pem)
            .filter_map(Result::ok)
            .chain(custom.iter().cloned())
            .collect();
        let rest = anchors_of(&bundle);
        let anchors: AnchorsInit = Box::new(move || {
            let mut anchors = system();
            anchors.extend(rest);
            anchors
        });
        Arc::new(TrustStore {
            anchors: LazyLock::new(anchors),
            configs: Mutex::new(Configs::default()),
            clock,
            system: roots,
            custom,
        })
    }

    /// The profile's own certificates, for a library that verifies with roots of its own.
    pub fn custom(&self) -> &[CertificateDer<'static>] {
        &self.custom
    }

    /// Starts reading the OS store for a policy that will check a chain against it,
    /// so `direct` and `skip-cert-verify` profiles never pay for it.
    pub(crate) fn expect_anchors(&self) {
        if let Some(system) = &self.system {
            system.preload();
        }
    }

    pub fn clock(&self) -> &ClockOffset {
        &self.clock
    }

    pub(crate) fn shared_config(
        &self,
        key: ConfigKey,
        build: impl FnOnce() -> Result<Arc<ClientConfig>, TlsError>,
    ) -> Result<Arc<ClientConfig>, TlsError> {
        let mut configs = lock(&self.configs);
        if let Some(config) = configs.map.get(&key).and_then(Weak::upgrade) {
            return Ok(config);
        }
        let config = build()?;
        if configs.map.len() >= configs.prune_at {
            configs.map.retain(|_, config| config.strong_count() > 0);
            configs.prune_at = 2 * configs.map.len();
        }
        configs.map.insert(key, Arc::downgrade(&config));
        Ok(config)
    }

    pub fn anchors(&self) -> &[TrustAnchor<'static>] {
        &self.anchors
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

fn anchors_of(certs: &[CertificateDer<'static>]) -> Anchors {
    certs
        .iter()
        .filter_map(|cert| {
            webpki::anchor_from_trusted_cert(cert)
                .ok()
                .map(|anchor| anchor.to_owned())
        })
        .collect()
}

pub fn parse_certificates(text: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(text.as_bytes())
        .filter_map(Result::ok)
        .collect()
}
