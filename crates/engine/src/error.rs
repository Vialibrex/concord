use std::io;

use concord_config::ConfigError;
use concord_config::provider::RuleProviderDef;
use concord_dns::QueryError;
use concord_group::FetchError;
use concord_rules::geo::GeoError;
use concord_rules::{CompileSetError, RuleSetError};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Why an engine call failed. A caller branches on the variant; the text is for people.
#[derive(Debug, thiserror::Error)]
pub enum Failure {
    /// The profile did not apply and the built-in default runs in its place.
    #[error("{0}")]
    ConfigRejected(String),
    #[error("{0}")]
    InvalidArguments(String),
    #[error(transparent)]
    InvalidQuery(QueryError),
    #[error("external provider does not exist")]
    ProviderNotFound { provider: String },
    #[error("external provider is updating")]
    ProviderUpdating { provider: String },
    #[error("{source}")]
    ProviderUpdate { provider: String, source: BoxError },
    #[error(transparent)]
    RuleSet(#[from] CompileSetError),
    /// A download got no answer, or one that was not a success. `provider` is the provider it
    /// was for, if any.
    #[error("{source}")]
    Request {
        provider: Option<String>,
        timed_out: bool,
        source: BoxError,
    },
    #[error("open {path}: {}", io_message(source))]
    Open { path: String, source: io::Error },
    #[error("unknown geo resource: {0}")]
    UnknownGeo(String),
    #[error("geo update already in progress: {0}")]
    GeoUpdating(String),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Core(String),
}

impl Failure {
    pub fn core(message: impl Into<String>) -> Self {
        Failure::Core(message.into())
    }
}

fn io_message(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::NotFound => "no such file or directory".to_string(),
        io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        io::ErrorKind::IsADirectory => "is a directory".to_string(),
        _ => err.to_string(),
    }
}

#[derive(Debug)]
pub(crate) enum ResourceError {
    Fetch(FetchError),
    Status(u16),
    Load(Box<RuleLoadError>),
    Other(String),
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceError::Fetch(err) => write!(f, "{err}"),
            ResourceError::Status(code) => {
                let reason = http::StatusCode::from_u16(*code)
                    .ok()
                    .and_then(|status| status.canonical_reason())
                    .unwrap_or("");
                write!(f, "{}", format!("{code} {reason}").trim_end())
            }
            ResourceError::Load(err) => write!(f, "{err}"),
            ResourceError::Other(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ResourceError {}

/// Why a rule provider could not be set up or loaded.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RuleLoadError {
    #[error("rule provider {provider}: {source}: {path}")]
    Path {
        provider: String,
        path: String,
        source: std::io::Error,
    },
    #[error(transparent)]
    Parse(#[from] RuleSetError),
    #[error(transparent)]
    Write(std::io::Error),
    #[error(transparent)]
    Pull(#[from] ResourceError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

impl RuleLoadError {
    pub(crate) fn path(def: &RuleProviderDef, path: &str) -> impl FnOnce(std::io::Error) -> Self {
        let (provider, path) = (def.name.clone(), path.to_string());
        move |source| RuleLoadError::Path {
            provider,
            path,
            source,
        }
    }
}

/// Why a geo file could not be fetched or refreshed. The text is what the resource event and
/// the apply failure report.
#[derive(Debug, thiserror::Error)]
pub(crate) enum GeoUpdateError {
    #[error("can't download {what}: {source}")]
    Download { what: String, source: ResourceError },
    #[error("can't download {label} database file: no data")]
    NoData { label: &'static str },
    #[error("invalid {label} database file: {message}")]
    Invalid {
        label: &'static str,
        message: String,
    },
    #[error("can't save {label} database file: {source}")]
    Save {
        label: &'static str,
        source: WriteError,
    },
    #[error(transparent)]
    Write(#[from] WriteError),
    #[error(transparent)]
    Store(#[from] GeoError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WriteError {
    #[error("not initialized")]
    NotInitialized,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
