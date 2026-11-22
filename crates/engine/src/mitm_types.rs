//! What the MITM methods answer, as the engine and the crates under it write it; the API
//! converts each into its wire type.

pub use concord_config::mitm::module::{
    ArgumentDef, ArgumentKind, DomainEntry, IgnoreReason, InlineRule, ListEdit, ModuleFormat,
    ModuleMeta, ModuleOff, ModuleRule, NetworkDef, Policy, ProviderKind, ResourceDef, ResourceKind,
    RuleSetDef, RuleSetSource,
};
pub use concord_config::mitm::modules::{ModuleProblem, RefusedRule};
pub use concord_config::mitm::{DataType, IssueKind, UrlAction};
pub use concord_mitm::{
    Action, AnsweredBy, App, Body, BodyReplacementView, BodyRewriteView, CertificateInfo, Exchange,
    ExchangeList, ExchangeSummary, Facets, HeaderAction, HeaderRewriteView, HeaderView,
    HostEntryView, HostsView, IgnoredView, Issue, LineEntry, LineView, MapLocalView, ModuleView,
    Phase, QueryAnswer, RateBucket, RouteNote, RuleView, ScriptOutput, ScriptView, ScriptViewKind,
    SourceEntryView, SourcesView, UrlRewriteView, Validation,
};

pub use crate::engine::{
    ConnectionExchanges, FailureReason, FetchFailure, ModuleStatus, ResourceState, ResourceStatus,
};
