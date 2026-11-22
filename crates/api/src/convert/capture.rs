use std::collections::BTreeMap;

use base64::Engine as _;
use concord_common::exchange_query::{ContentKind, StatusClass};
use concord_engine::{
    AnsweredBy, CertificateInfo, ConnectionExchanges, ExchangeSummary, MitmAction, MitmApp,
    MitmBody as EngineBody, MitmExchange as EngineExchange, MitmFacets as EngineFacets,
    QueryAnswer, RateBucket, RouteNote, ScriptOutput,
};
use concord_proto::types::{
    MitmAction as WireAction, MitmAnswer, MitmApp as WireApp, MitmBody, MitmCertificateInfo,
    MitmExchange, MitmExchangeList, MitmExchangeSummary, MitmFacets, MitmKind, MitmQueryAnswer,
    MitmRateBucket, MitmRouteNote, MitmScriptOutput, MitmStatus,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The capture keeps the times it stamped itself, which always format.
fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub fn status_class(status: MitmStatus) -> StatusClass {
    match status {
        MitmStatus::Informational => StatusClass::Informational,
        MitmStatus::Success => StatusClass::Success,
        MitmStatus::Redirect => StatusClass::Redirect,
        MitmStatus::ClientError => StatusClass::ClientError,
        MitmStatus::ServerError => StatusClass::ServerError,
        MitmStatus::Failed => StatusClass::Failed,
        MitmStatus::Pending => StatusClass::Pending,
    }
}

fn mitm_status(status: StatusClass) -> MitmStatus {
    match status {
        StatusClass::Informational => MitmStatus::Informational,
        StatusClass::Success => MitmStatus::Success,
        StatusClass::Redirect => MitmStatus::Redirect,
        StatusClass::ClientError => MitmStatus::ClientError,
        StatusClass::ServerError => MitmStatus::ServerError,
        StatusClass::Failed => MitmStatus::Failed,
        StatusClass::Pending => MitmStatus::Pending,
    }
}

pub fn content_kind(kind: MitmKind) -> ContentKind {
    match kind {
        MitmKind::Json => ContentKind::Json,
        MitmKind::Html => ContentKind::Html,
        MitmKind::Script => ContentKind::Script,
        MitmKind::Css => ContentKind::Css,
        MitmKind::Image => ContentKind::Image,
        MitmKind::Font => ContentKind::Font,
        MitmKind::Media => ContentKind::Media,
        MitmKind::Text => ContentKind::Text,
        MitmKind::Other => ContentKind::Other,
    }
}

fn mitm_kind(kind: ContentKind) -> MitmKind {
    match kind {
        ContentKind::Json => MitmKind::Json,
        ContentKind::Html => MitmKind::Html,
        ContentKind::Script => MitmKind::Script,
        ContentKind::Css => MitmKind::Css,
        ContentKind::Image => MitmKind::Image,
        ContentKind::Font => MitmKind::Font,
        ContentKind::Media => MitmKind::Media,
        ContentKind::Text => MitmKind::Text,
        ContentKind::Other => MitmKind::Other,
    }
}

fn answer(by: AnsweredBy) -> MitmAnswer {
    match by {
        AnsweredBy::Reject => MitmAnswer::Reject,
        AnsweredBy::Redirect => MitmAnswer::Redirect,
        AnsweredBy::MapLocal => MitmAnswer::MapLocal,
        AnsweredBy::Script => MitmAnswer::Script,
    }
}

fn app(app: MitmApp) -> WireApp {
    let MitmApp {
        process,
        process_path,
        uid,
    } = app;
    WireApp {
        process,
        process_path,
        uid,
    }
}

fn summary(summary: ExchangeSummary) -> MitmExchangeSummary {
    let ExchangeSummary {
        id,
        start,
        pending,
        duration,
        method,
        url,
        status,
        request_size,
        response_size,
        error,
        host,
        path,
        content_type,
        status_class,
        kind,
        rewritten,
        action_kinds,
        answer: answered_by,
        connection_id,
        app: process,
    } = summary;
    MitmExchangeSummary {
        id,
        start: rfc3339(start),
        pending,
        duration,
        method,
        url,
        status,
        request_size,
        response_size,
        error,
        host,
        path,
        content_type,
        status_class: mitm_status(status_class),
        kind: mitm_kind(kind),
        rewritten,
        action_kinds: action_kinds.into_iter().map(str::to_owned).collect(),
        answer: answered_by.map(answer),
        connection_id,
        app: process.map(app),
    }
}

fn summaries(list: Vec<ExchangeSummary>) -> Vec<MitmExchangeSummary> {
    list.into_iter().map(summary).collect()
}

pub fn exchange_list(exchanges: ConnectionExchanges) -> MitmExchangeList {
    let ConnectionExchanges { list, closed } = exchanges;
    let concord_engine::ExchangeList {
        capturing,
        since,
        exchanges,
    } = list;
    MitmExchangeList {
        capturing,
        since: since.map(rfc3339),
        exchanges: summaries(exchanges),
        closed,
    }
}

fn action(action: MitmAction) -> WireAction {
    let MitmAction {
        kind,
        phase,
        detail,
        module,
    } = action;
    WireAction {
        kind: kind.to_owned(),
        phase,
        detail,
        module,
    }
}

fn route_note(note: RouteNote) -> MitmRouteNote {
    let RouteNote {
        rule,
        rule_payload,
        chains,
    } = note;
    MitmRouteNote {
        rule,
        rule_payload,
        chains,
    }
}

pub fn exchange(exchange: EngineExchange) -> MitmExchange {
    let EngineExchange {
        summary: head,
        connection,
        original_url,
        proto,
        reason,
        ttfb,
        request_header,
        response_header,
        actions,
        route,
    } = exchange;
    MitmExchange {
        summary: summary(head),
        connection,
        original_url,
        proto,
        reason: reason.to_owned(),
        ttfb,
        request_header,
        response_header,
        actions: actions.into_iter().map(action).collect(),
        route: route.map(route_note),
    }
}

pub fn body(body: EngineBody) -> MitmBody {
    let EngineBody {
        data,
        truncated,
        encoding,
    } = body;
    MitmBody {
        data: base64::engine::general_purpose::STANDARD.encode(data),
        truncated,
        encoding,
    }
}

fn counts<K: Into<String>>(counts: BTreeMap<K, usize>) -> BTreeMap<String, u64> {
    counts
        .into_iter()
        .map(|(key, value)| (key.into(), count(value)))
        .collect()
}

fn facets(facets: EngineFacets) -> MitmFacets {
    let EngineFacets {
        status,
        method,
        kind,
        app,
    } = facets;
    MitmFacets {
        status: counts(status),
        method: counts(method),
        kind: counts(kind),
        app: counts(app),
    }
}

fn rate_bucket(bucket: RateBucket) -> MitmRateBucket {
    let RateBucket {
        t,
        requests,
        errors,
    } = bucket;
    MitmRateBucket {
        t,
        requests: count(requests),
        errors: count(errors),
    }
}

pub fn query_answer(answer: QueryAnswer) -> MitmQueryAnswer {
    let QueryAnswer {
        capturing,
        since,
        version,
        oldest,
        held,
        matched,
        exchanges,
        next,
        unmatched,
        facets: by,
        rate,
        median_duration,
    } = answer;
    MitmQueryAnswer {
        capturing,
        since: since.map(rfc3339),
        version,
        oldest,
        held: count(held),
        matched: count(matched),
        exchanges: summaries(exchanges),
        next,
        unmatched,
        facets: by.map(facets),
        rate: rate.map(|buckets| buckets.into_iter().map(rate_bucket).collect()),
        median_duration,
    }
}

pub fn certificate(info: CertificateInfo) -> MitmCertificateInfo {
    let CertificateInfo {
        pem,
        fingerprint,
        subject,
        not_before,
        not_after,
    } = info;
    MitmCertificateInfo {
        pem,
        fingerprint,
        subject,
        not_before: rfc3339(not_before),
        not_after: rfc3339(not_after),
    }
}

pub fn script_output(output: ScriptOutput) -> MitmScriptOutput {
    let ScriptOutput {
        logs,
        result,
        error,
    } = output;
    MitmScriptOutput {
        logs,
        result,
        error,
    }
}

#[cfg(test)]
mod tests {
    use concord_engine::ExchangeList;
    use serde::Serialize;
    use serde_json::{Value, json};
    use time::macros::datetime;

    use super::*;

    fn wire(value: impl Serialize) -> Value {
        serde_json::to_value(value).unwrap()
    }

    fn summary_with(full: bool) -> ExchangeSummary {
        ExchangeSummary {
            id: 7,
            start: datetime!(2026-11-23 01:02:03.456 UTC),
            pending: full,
            duration: 12,
            method: "GET".into(),
            url: "https://a.test/p?q".into(),
            status: if full { 0 } else { 404 },
            request_size: 1,
            response_size: 2,
            error: if full { "reset".into() } else { String::new() },
            host: "a.test".into(),
            path: "/p?q".into(),
            content_type: if full {
                "image/png".into()
            } else {
                String::new()
            },
            status_class: if full {
                StatusClass::Pending
            } else {
                StatusClass::ClientError
            },
            kind: if full {
                ContentKind::Image
            } else {
                ContentKind::Other
            },
            rewritten: full,
            action_kinds: if full { vec!["map-local"] } else { Vec::new() },
            answer: full.then_some(AnsweredBy::MapLocal),
            connection_id: full.then_some(3),
            app: full.then(|| MitmApp {
                process: "curl".into(),
                process_path: "/usr/bin/curl".into(),
                uid: Some(10_001),
            }),
        }
    }

    #[test]
    fn exchange_lists_reach_the_wire_as_the_capture_writes_them() {
        for full in [true, false] {
            let list = ExchangeList {
                capturing: full,
                since: full.then_some(datetime!(2026-11-23 00:00 UTC)),
                exchanges: vec![summary_with(true), summary_with(false)],
            };
            let mut expected = wire(&list);
            expected["closed"] = json!(full);
            let converted = exchange_list(ConnectionExchanges { list, closed: full });
            assert_eq!(wire(converted), expected);
        }
    }

    #[test]
    fn an_exchange_reaches_the_wire_as_the_capture_writes_it() {
        for full in [true, false] {
            let exchange = EngineExchange {
                summary: summary_with(full),
                connection: if full { "c1".into() } else { String::new() },
                original_url: if full {
                    "http://a.test/".into()
                } else {
                    String::new()
                },
                proto: "HTTP/1.1".into(),
                reason: if full { "Not Found" } else { "" },
                ttfb: 4,
                request_header: [("X-A".to_string(), vec!["1".to_string()])].into(),
                response_header: full.then(|| [("X-B".to_string(), vec!["2".to_string()])].into()),
                actions: vec![
                    MitmAction {
                        kind: "header",
                        phase: "request".into(),
                        detail: "X-A".into(),
                        module: "m".into(),
                    },
                    MitmAction {
                        kind: "reject",
                        phase: String::new(),
                        detail: String::new(),
                        module: String::new(),
                    },
                ],
                route: full.then(|| RouteNote {
                    rule: "MATCH".into(),
                    rule_payload: String::new(),
                    chains: vec!["DIRECT".into()],
                }),
            };
            let expected = wire(&exchange);
            assert_eq!(wire(Some(super::exchange(exchange))), expected);
        }
    }

    #[test]
    fn a_body_reaches_the_wire_as_the_capture_writes_it() {
        for full in [true, false] {
            let kept = EngineBody {
                data: b"/page|yes".to_vec(),
                truncated: full,
                encoding: if full { "gzip".into() } else { String::new() },
            };
            let expected = wire(&kept);
            assert_eq!(wire(body(kept)), expected);
        }
    }

    #[test]
    fn a_query_answer_reaches_the_wire_as_the_capture_writes_it() {
        for full in [true, false] {
            let make = || QueryAnswer {
                capturing: true,
                since: full.then_some(datetime!(2026-11-23 00:00 UTC)),
                version: 9,
                oldest: 1,
                held: 5,
                matched: 2,
                exchanges: vec![summary_with(full)],
                next: full.then_some(6),
                unmatched: if full { vec![3] } else { Vec::new() },
                facets: full.then(|| EngineFacets {
                    status: [("2xx", 1)].into(),
                    method: [("GET".to_string(), 2)].into(),
                    kind: [("json", 1)].into(),
                    app: [(String::new(), 1)].into(),
                }),
                rate: full.then(|| {
                    vec![RateBucket {
                        t: 1_000,
                        requests: 2,
                        errors: 1,
                    }]
                }),
                median_duration: full.then_some(40),
            };
            assert_eq!(wire(query_answer(make())), wire(make()));
        }
    }

    #[test]
    fn a_certificate_and_a_script_output_reach_the_wire_as_written() {
        let info = CertificateInfo {
            pem: "PEM".into(),
            fingerprint: "ab:cd".into(),
            subject: "CN=Concord".into(),
            not_before: datetime!(2026-01-01 00:00 UTC),
            not_after: datetime!(2036-01-01 00:00 UTC),
        };
        let expected = wire(&info);
        assert_eq!(wire(certificate(info)), expected);
        for full in [true, false] {
            let output = ScriptOutput {
                logs: vec!["pong".into()],
                result: if full { "{}".into() } else { String::new() },
                error: if full { "boom".into() } else { String::new() },
            };
            let expected = wire(&output);
            assert_eq!(wire(script_output(output)), expected);
        }
    }
}
