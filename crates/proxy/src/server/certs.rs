//! The certificate a listener serves: inline PEM, files under the home directory that a
//! change reloads, or one made for the listener when it names none
//! (`component/ca/keypair.go:25-75`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};

use concord_platform::{FileWatch, HomeDir};
use concord_tls::server::Certs;
use rcgen::{CertificateParams, KeyPair, PKCS_RSA_SHA256, RsaKeySize, SerialNumber};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::{CancellationToken, DropGuard};

use super::{ServerEnv, ServerError};
use crate::util::lock;

/// A certificate made for a listener, kept across reloads so clients that pinned it still
/// connect, where mihomo makes a new one each time.
#[derive(Default)]
pub(super) struct SelfSigned(Mutex<Option<(String, String)>>);

impl SelfSigned {
    fn pair(&self) -> Result<(String, String), ServerError> {
        let mut made = lock(&self.0);
        if let Some(pair) = made.as_ref() {
            return Ok(pair.clone());
        }
        let pair = self_signed()?;
        *made = Some(pair.clone());
        Ok(pair)
    }
}

/// mihomo's `NewRandomTLSKeyPair(KeyPairTypeRSA)`: RSA 2048, serial 1, no subject or names,
/// valid from a year ago to a year ahead (`keypair.go:116-150`).
fn self_signed() -> Result<(String, String), ServerError> {
    let invalid =
        |err: rcgen::Error| ServerError::Invalid(format!("self-signed certificate: {err}"));
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).map_err(invalid)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serial_number = Some(SerialNumber::from(vec![1]));
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(365);
    params.not_after = now + Duration::days(365);
    let cert = params.self_signed(&key).map_err(invalid)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// A listener's certificate, and the watch on its files, which ends with it.
pub(super) struct ServerCerts {
    pub(super) certs: Arc<Certs>,
    _watch: Option<DropGuard>,
}

#[cfg(test)]
impl ServerCerts {
    pub(super) fn fixed(certs: Arc<Certs>) -> Self {
        ServerCerts {
            certs,
            _watch: None,
        }
    }
}

enum Source {
    Pem(Vec<u8>),
    File(PathBuf),
}

impl Source {
    /// mihomo's `ca.NewTLSKeyPairLoader`: the text itself when it is PEM, otherwise a path
    /// that must stay inside the home directory.
    fn of(text: &str, home: &HomeDir) -> Result<Source, ServerError> {
        if text.contains("-----BEGIN") {
            return Ok(Source::Pem(text.as_bytes().to_vec()));
        }
        home.confine_profile_file(text)
            .map(Source::File)
            .map_err(|source| ServerError::File {
                path: text.to_owned(),
                source,
            })
    }

    fn read(&self, home: &HomeDir) -> Result<Vec<u8>, ServerError> {
        match self {
            Source::Pem(pem) => Ok(pem.clone()),
            Source::File(path) => home.read(path).map_err(|source| ServerError::File {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    fn file(&self) -> Option<PathBuf> {
        match self {
            Source::Pem(_) => None,
            Source::File(path) => Some(path.clone()),
        }
    }
}

pub(super) fn read_pem(text: &str, home: &HomeDir) -> Result<Vec<u8>, ServerError> {
    Source::of(text, home)?.read(home)
}

/// `self_signed` names where a listener that gives neither part keeps the one made for it;
/// without it such a listener has no certificate.
pub(super) fn load(
    certificate: &str,
    private_key: &str,
    self_signed: Option<&SelfSigned>,
    env: &ServerEnv<'_>,
) -> Result<ServerCerts, ServerError> {
    if let Some(made) = self_signed.filter(|_| certificate.is_empty() && private_key.is_empty()) {
        let (certificate, private_key) = made.pair()?;
        return Ok(ServerCerts {
            certs: Arc::new(Certs::new(certificate.as_bytes(), private_key.as_bytes())?),
            _watch: None,
        });
    }
    let sources = [
        Source::of(certificate, env.home)?,
        Source::of(private_key, env.home)?,
    ];
    let [cert, key] = &sources;
    let certs = Arc::new(Certs::new(&cert.read(env.home)?, &key.read(env.home)?)?);
    let watches: Vec<FileWatch> = sources
        .iter()
        .filter_map(Source::file)
        .map(FileWatch::new)
        .collect();
    let watch = (!watches.is_empty()).then(|| {
        let stop = CancellationToken::new();
        env.tasks.spawn(reload(
            Arc::downgrade(&certs),
            sources,
            watches,
            env.home.clone(),
            stop.clone(),
        ));
        stop.drop_guard()
    });
    Ok(ServerCerts {
        certs,
        _watch: watch,
    })
}

/// Reads both parts again when either file changes; a pair that does not load leaves the
/// old certificate in place, as mihomo's watcher does.
async fn reload(
    certs: Weak<Certs>,
    [cert, key]: [Source; 2],
    mut watches: Vec<FileWatch>,
    home: Arc<HomeDir>,
    stop: CancellationToken,
) {
    loop {
        let changed = futures_util::future::select_all(
            watches.iter_mut().map(|watch| Box::pin(watch.changed())),
        );
        tokio::select! {
            () = stop.cancelled() => return,
            _ = changed => {}
        }
        let Some(certs) = certs.upgrade() else {
            return;
        };
        let loaded = cert
            .read(&home)
            .and_then(|cert| Ok((cert, key.read(&home)?)))
            .and_then(|(cert, key)| Ok(certs.replace(&cert, &key)?));
        match loaded {
            Ok(()) => tracing::info!("listener certificate reloaded"),
            Err(err) => tracing::warn!("listener certificate kept, the new one failed: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use concord_common::{ClockOffset, Tasks};
    use rustls::pki_types::CertificateDer;

    use super::super::{Carried, Keep};
    use super::*;

    struct Home {
        dir: tempfile::TempDir,
        home: Arc<HomeDir>,
        tasks: Tasks,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = Arc::new(HomeDir::new(dir.path()));
            Home {
                dir,
                home,
                tasks: Tasks::default(),
            }
        }

        fn load(
            &self,
            certificate: &str,
            key: &str,
            made: Option<&SelfSigned>,
        ) -> Result<ServerCerts, ServerError> {
            let env = ServerEnv {
                home: &self.home,
                tasks: &self.tasks,
                keep: &Keep::Named("in".into()),
                carried: &Carried::default(),
                clock: &Arc::new(ClockOffset::default()),
            };
            load(certificate, key, made, &env)
        }

        fn write(&self, (cert, key): &(String, String)) {
            std::fs::write(self.dir.path().join("server.crt"), cert).unwrap();
            std::fs::write(self.dir.path().join("server.key"), key).unwrap();
        }
    }

    fn leaf(certs: &Certs) -> CertificateDer<'static> {
        certs.current().cert[0].clone()
    }

    fn leaf_of((cert, key): &(String, String)) -> CertificateDer<'static> {
        leaf(&Certs::new(cert.as_bytes(), key.as_bytes()).unwrap())
    }

    #[tokio::test]
    async fn a_listener_naming_neither_part_signs_one_and_keeps_it() {
        let home = Home::new();
        let made = SelfSigned::default();
        let first = home.load("", "", Some(&made)).unwrap();
        let again = home.load("", "", Some(&made)).unwrap();
        assert_eq!(leaf(&first.certs), leaf(&again.certs));
        assert!(home.load("", "", None).is_err());
    }

    #[tokio::test]
    async fn one_part_alone_is_an_error() {
        let home = Home::new();
        let pair = self_signed().unwrap();
        home.write(&pair);
        let made = SelfSigned::default();
        assert!(home.load("server.crt", "", Some(&made)).is_err());
        assert!(home.load("", "server.key", Some(&made)).is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewritten_file_replaces_the_certificate_and_a_broken_one_does_not() {
        let home = Home::new();
        let (old, new) = (self_signed().unwrap(), self_signed().unwrap());
        home.write(&old);
        let loaded = home.load("server.crt", "server.key", None).unwrap();
        assert_eq!(leaf(&loaded.certs), leaf_of(&old));

        home.write(&new);
        let deadline = Instant::now() + Duration::from_secs(10);
        while leaf(&loaded.certs) != leaf_of(&new) {
            assert!(
                Instant::now() < deadline,
                "the new certificate never loaded"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        home.write(&("broken".to_owned(), new.1.clone()));
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(leaf(&loaded.certs), leaf_of(&new));
    }
}
