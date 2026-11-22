use serde::{Serialize, Serializer};
use time::OffsetDateTime;

use super::App;
use crate::script::HeaderList;

pub(super) fn is_false(value: &bool) -> bool {
    !*value
}

pub(super) fn is_empty(value: &str) -> bool {
    value.is_empty()
}

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeSummary {
    pub id: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub start: OffsetDateTime,
    #[serde(skip_serializing_if = "is_false")]
    pub pending: bool,
    pub duration: i64,
    pub method: String,
    pub url: String,
    pub status: i32,
    #[serde(rename = "request-size")]
    pub request_size: i64,
    #[serde(rename = "response-size")]
    pub response_size: i64,
    #[serde(skip_serializing_if = "is_empty")]
    pub error: String,
    pub host: String,
    pub path: String,
    /// The response's, without parameters, in lower case.
    #[serde(rename = "content-type", skip_serializing_if = "is_empty")]
    pub content_type: String,
    #[serde(rename = "status-class")]
    pub status_class: &'static str,
    pub kind: &'static str,
    /// A rewrite, a local map or a script acted on it.
    #[serde(skip_serializing_if = "is_false")]
    pub rewritten: bool,
    /// The kinds of its `actions`, each once, in the order they first acted.
    #[serde(rename = "action-kinds", skip_serializing_if = "Vec::is_empty")]
    pub action_kinds: Vec<&'static str>,
    /// What stood in for the server; none when the request went to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<AnsweredBy>,
    /// The connection it went out on, as `connection.watch` numbers it.
    #[serde(rename = "connection-id", skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<App>,
}

/// One request as the rules left it: the headers sent upstream and those
/// answered to the client. The sizes and the protocol are the client's.
#[derive(Clone, Debug, Serialize)]
pub struct Exchange {
    #[serde(flatten)]
    pub summary: ExchangeSummary,
    #[serde(skip_serializing_if = "is_empty")]
    pub connection: String,
    #[serde(rename = "original-url", skip_serializing_if = "is_empty")]
    pub original_url: String,
    pub proto: String,
    pub ttfb: i64,
    #[serde(rename = "request-header")]
    pub request_header: HeaderList,
    #[serde(rename = "response-header")]
    pub response_header: Option<HeaderList>,
    pub actions: Vec<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteNote>,
}

/// The rule that decided the request and the chain it left through, exit first, as a
/// connection lists them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RouteNote {
    #[serde(skip_serializing_if = "is_empty")]
    pub rule: String,
    #[serde(rename = "rule-payload", skip_serializing_if = "is_empty")]
    pub rule_payload: String,
    pub chains: Vec<String>,
}

/// What answered a request in place of its server; a request script that aborts it counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnsweredBy {
    Reject,
    Redirect,
    MapLocal,
    Script,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Action {
    pub kind: &'static str,
    #[serde(skip_serializing_if = "is_empty")]
    pub phase: String,
    #[serde(skip_serializing_if = "is_empty")]
    pub detail: String,
    /// The module whose line acted; none for the profile's own.
    #[serde(skip_serializing_if = "is_empty")]
    pub module: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeList {
    pub capturing: bool,
    #[serde(skip_serializing_if = "Option::is_none", with = "since_format")]
    pub since: Option<OffsetDateTime>,
    pub exchanges: Vec<ExchangeSummary>,
}

pub(super) mod since_format {
    use serde::Serializer;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(
        value: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(at) => time::serde::rfc3339::serialize(at, serializer),
            None => serializer.serialize_none(),
        }
    }
}

/// A body as kept, decoded unless `encoding` names a coding left on it.
#[derive(Clone, Debug, Serialize)]
pub struct Body {
    #[serde(serialize_with = "base64_bytes")]
    pub data: Vec<u8>,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    #[serde(skip_serializing_if = "is_empty")]
    pub encoding: String,
}

fn base64_bytes<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    use base64::Engine as _;
    serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(data))
}
