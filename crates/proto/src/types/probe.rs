use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{Json, MitmIssue, MitmLineEntry, RouteHit};

dto! {
    pub struct RouteCheckParams {
        pub routes: Vec<Vec<RouteHit>>,
    }

    /// `held[i]` says route `i` still leaves where it did; `epoch` and `version`
    /// are the stamp the answers were checked against.
    pub struct RouteCheckResult {
        pub epoch: u64,
        pub version: u64,
        pub held: Vec<bool>,
    }

    pub struct OutboundIpParams {
        pub proxy: String,
        pub urls: Vec<String>,
        /// Milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<u64>,
    }

    pub struct OutboundIp {
        pub url: String,
        pub body: String,
        pub delay: i64,
        pub chains: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
        #[serde(alias = "core-epoch")]
        pub epoch: u64,
        #[serde(alias = "route-version")]
        pub version: u64,
        pub hits: Vec<RouteHit>,
        #[serde(default, skip_serializing_if = "Vec::is_empty", alias = "node-hits")]
        pub node_hits: Vec<RouteHit>,
    }

    pub struct ServicesParams {
        pub proxy: String,
        pub names: Vec<String>,
        /// Milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timeout: Option<u64>,
    }

    pub struct ServiceItem {
        pub name: String,
        pub status: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub region: String,
        /// The address the service saw the check come from, which a node that sends
        /// the service out another way does not share with its other traffic. Only
        /// checks whose answer names it carry one.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub ip: String,
        #[serde(default, skip_serializing_if = "is_zero")]
        pub delay: i64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub chains: Vec<String>,
        #[serde(alias = "checked-at")]
        pub checked_at: i64,
        #[serde(alias = "core-epoch")]
        pub epoch: u64,
        #[serde(alias = "route-version")]
        pub version: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub hits: Vec<RouteHit>,
    }

    pub struct ServiceList {
        pub items: Vec<ServiceItem>,
    }

    pub struct MitmCertificate {
        /// Absent while no certificate authority exists.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub certificate: Option<Json>,
    }

    pub struct MitmValidateParams {
        pub config: Json,
    }

    /// Both keyed by list, as the section names it (`hostname`, `url-rewrite`, ...), in
    /// line order. A line in force has a view; one that cannot be read has an issue; a
    /// `hostname` or `client-source-address` line some of whose items apply has both.
    pub struct MitmValidateResult {
        pub issues: BTreeMap<String, Vec<MitmIssue>>,
        #[serde(default)]
        pub views: BTreeMap<String, Vec<MitmLineEntry>>,
    }

    pub struct MitmIssueParams {
        pub host: String,
    }

    pub struct MitmPem {
        pub pem: String,
    }

    pub struct MitmScriptParams {
        pub name: String,
    }

    pub struct MitmResult {
        pub result: Json,
    }

    pub struct MitmExchangesParams {
        /// A connection id from `connection.watch`, open or closed since, as long as
        /// the capture still holds its exchanges.
        pub connection: u64,
    }

    pub struct MitmExchangeParams {
        pub id: i64,
    }

    pub struct MitmBodyParams {
        pub id: i64,
        #[serde(default)]
        pub response: bool,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum MitmStatus {
    #[serde(rename = "1xx")]
    Informational,
    #[serde(rename = "2xx")]
    Success,
    #[serde(rename = "3xx")]
    Redirect,
    #[serde(rename = "4xx")]
    ClientError,
    #[serde(rename = "5xx")]
    ServerError,
    /// No response: the request failed, was aborted or its connection broke.
    #[serde(rename = "failed")]
    Failed,
    /// Still waiting for its response.
    #[serde(rename = "pending")]
    Pending,
}

/// What a response holds, read from its `Content-Type`; `other` also takes a response
/// without one and a request not answered yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MitmKind {
    Json,
    Html,
    Script,
    Css,
    Image,
    Font,
    Media,
    Text,
    Other,
}

dto! {
    /// An empty list or an absent field lets every exchange through; a list keeps the
    /// exchanges that match any of its items.
    #[derive(Default)]
    pub struct MitmFilter {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub statuses: Vec<MitmStatus>,
        /// Compared without case.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub methods: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub kinds: Vec<MitmKind>,
        /// The URL's host, without its port, compared whole and without case.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub hosts: Vec<String>,
        /// The `process` of the exchange's connection as `connection.watch` lists it,
        /// compared without case; `""` for none.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub apps: Vec<String>,
        /// Whether a rewrite, a local map or a script acted on it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rewritten: Option<bool>,
        /// Took at least this long, in milliseconds; an exchange still in progress by how
        /// long it had waited when the query ran, so a client counts its running time from
        /// `start` itself.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub slow_ms: Option<i64>,
        /// Found without case in the URL, method, content type, error or app.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub text: Option<String>,
        /// Started at or after, in Unix milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub from: Option<i64>,
        /// Started before, in Unix milliseconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub to: Option<i64>,
    }

    /// The capture across connections, newest first. Ids only grow and the oldest
    /// exchanges are dropped first, so a page taken with `before` never moves when
    /// new exchanges arrive. To page through the capture, pass each answer's `next` as
    /// `before`. To follow it, pass the `version` of the first page of a pass as `since`
    /// with no `before`; when that answer has a `next`, keep the same `since` and pass
    /// `next` as `before` until no `next` comes, then start the next pass from the first
    /// page's `version`. `matched`, `facets` and `rate` count every held match whatever
    /// `before` and `since` say. A value out of range, `from` after `to`, or a filter
    /// list or `text` over its limit is refused as invalid params.
    #[derive(Default)]
    pub struct MitmQueryParams {
        #[serde(default)]
        pub filter: MitmFilter,
        /// Only exchanges with a lower id: the `next` of the page before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub before: Option<i64>,
        /// At most this many, from 1 to 64; absent, 64.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limit: Option<u32>,
        /// Only exchanges added or changed after the `version` of an earlier answer, and
        /// every exchange still in progress, whose sizes and duration move without
        /// changing the version.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub since: Option<u64>,
        /// Also count the held exchanges by status, method, kind and app.
        #[serde(default)]
        pub facets: bool,
        /// Also count the matches by the second they started in, from this time on
        /// (Unix milliseconds).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rate_from: Option<i64>,
    }
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// One page of `mitm.query`, newest first, with what a view of the capture needs besides.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub struct MitmQueryAnswer {
    pub capturing: bool,
    /// When the oldest held exchange started, or capture was turned on (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// The `since` that asks for what is added or changed after this answer.
    pub version: u64,
    /// The lowest id held; a client keeping earlier answers drops the ids below it.
    pub oldest: i64,
    pub held: u64,
    /// How many held exchanges match the filter.
    pub matched: u64,
    pub exchanges: Vec<MitmExchangeSummary>,
    /// The `before` of the next page; absent when this page holds the last match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<i64>,
    /// Changed since `since` and no longer matching, so a client drops them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmatched: Vec<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facets: Option<MitmFacets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Vec<MitmRateBucket>>,
    /// Of the finished matches, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_duration: Option<i64>,
}

/// One exchange as `mitm.query` and `mitm.exchanges` list it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub struct MitmExchangeSummary {
    pub id: i64,
    /// RFC 3339.
    pub start: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pending: bool,
    /// Milliseconds; for one in progress, how long it had waited when listed.
    pub duration: i64,
    pub method: String,
    pub url: String,
    /// 0 until a response came.
    pub status: i32,
    pub request_size: i64,
    pub response_size: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    pub host: String,
    /// With its query.
    pub path: String,
    /// The response's, without parameters, in lower case.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    pub status_class: MitmStatus,
    pub kind: MitmKind,
    /// A rewrite, a local map or a script acted on it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rewritten: bool,
    /// The connection it went out on, as `connection.watch` numbers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<MitmApp>,
}

/// The process behind the connection an exchange went out on, kept after it closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub struct MitmApp {
    pub process: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub process_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

/// Each dimension counts the matches of every other part of the filter, so a view can
/// offer the other values of a dimension it already narrowed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MitmFacets {
    /// Keyed as `MitmStatus` names them.
    pub status: BTreeMap<String, u64>,
    /// Keyed in upper case.
    pub method: BTreeMap<String, u64>,
    /// Keyed as `MitmKind` names them.
    pub kind: BTreeMap<String, u64>,
    /// Keyed by process; `""` holds the exchanges of no known app.
    pub app: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MitmRateBucket {
    /// The second's start, in Unix milliseconds.
    pub t: i64,
    pub requests: u64,
    /// Failed, or answered 4xx or 5xx.
    pub errors: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}
