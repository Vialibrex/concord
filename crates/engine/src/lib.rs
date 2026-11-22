//! Composition root: lifecycle, apply, and the state that outlives a config.

mod apply;
mod dns_server;
mod engine;
mod error;
mod fake_ip_store;
mod faults;
mod lan;
mod ntp;
pub mod ops;
pub mod probe;
mod probe_env;
mod proxy_tasks;
mod resources;
mod route;
mod trust;
mod tun;
mod views;

pub use concord_config::general::ControllerCors;
pub use concord_dns::{QueryView, QuestionView, RecordView};
pub use concord_group::{
    DelayRecord, GroupView, HealthSnapshot, NodeStateView, NodeView, ProxyView, ProxyViews,
    StatusRanges, UrlHealth,
};
#[cfg(feature = "mitm")]
pub use concord_mitm::{
    Action as MitmAction, AnsweredBy, App as MitmApp, Body as MitmBody, CertificateInfo,
    Exchange as MitmExchange, ExchangeList, ExchangeSummary, Facets as MitmFacets, QueryAnswer,
    RateBucket, RouteNote, ScriptOutput,
};
pub use concord_platform::{HomeDir, local_utc_offset};
#[cfg(feature = "mitm")]
pub use engine::ConnectionExchanges;
pub use engine::{
    Engine, EngineConfig, MitmService, Providers, SetupRequest, TunPatch, UpdateRequest,
};
pub use error::Failure;
pub use faults::{Service, ServiceFault};
pub use probe::{OutboundIpResult, RouteHit, ServiceItem};
pub use route::RouteCounters;
pub use tun::TunStartError;
#[cfg(unix)]
pub use tun::{InheritedTun, InheritedTunError};
pub use views::*;

pub use concord_tunnel::ExplainFlow;
