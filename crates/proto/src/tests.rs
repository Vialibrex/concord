use std::collections::HashSet;

use serde_json::{Value, json};

use crate::types::*;
use crate::*;

#[test]
fn every_method_is_declared_once_and_the_rpc_layer_owns_only_hello() {
    let mut names = HashSet::new();
    for spec in METHODS {
        assert!(names.insert(spec.name), "{} is declared twice", spec.name);
        assert_eq!(
            spec.kind == Kind::Stream,
            spec.policy.is_some(),
            "{}: a stream has a policy and nothing else does",
            spec.name
        );
        assert_eq!(
            spec.kind == Kind::Rpc,
            spec.name == "core.hello",
            "{}",
            spec.name
        );
        if spec.kind == Kind::Stream {
            assert_eq!(
                spec.exec,
                Exec::Inline,
                "{}: opening a stream must not queue",
                spec.name
            );
        }
        assert!(
            spec.name.split('.').count() == 2,
            "{} is not namespace.method",
            spec.name
        );
        assert_eq!(
            spec.capability == Cap::Mitm,
            spec.name.starts_with("mitm."),
            "{}",
            spec.name
        );
        assert_eq!(
            spec.capability == Cap::Debug,
            spec.name.starts_with("debug."),
            "{}",
            spec.name
        );
    }
    assert_eq!(METHODS[0].name, "core.hello");
    assert_eq!(
        method("traffic.watch").unwrap().policy,
        Some(StreamPolicy::Latest)
    );
    assert!(method("nope").is_none());
}

fn refs(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if key == "$ref"
                    && let Some(target) = inner.as_str()
                {
                    found.push(target.to_string());
                }
                refs(inner, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| refs(item, found)),
        _ => {}
    }
}

#[test]
fn the_schema_describes_every_method_and_every_reference_resolves() {
    let schema = api_schema();
    let methods = schema["methods"].as_array().unwrap();
    assert_eq!(methods.len(), METHODS.len());
    let definitions = schema["$defs"].as_object().unwrap();
    let mut found = Vec::new();
    refs(&schema, &mut found);
    assert!(!found.is_empty());
    for target in found {
        let name = target.strip_prefix("#/$defs/").expect(&target);
        assert!(definitions.contains_key(name), "{target} is not defined");
    }
    let watch = methods
        .iter()
        .find(|entry| entry["name"] == "log.watch")
        .unwrap();
    assert_eq!(watch["stream"]["policy"], "drop_oldest");
    assert_eq!(watch["kind"], "stream");
    let apply = methods
        .iter()
        .find(|entry| entry["name"] == "config.apply")
        .unwrap();
    assert_eq!(apply["exec"], "serial");
    let mitm = methods
        .iter()
        .find(|entry| entry["name"] == "mitm.body")
        .unwrap();
    assert_eq!(mitm["capability"], "mitm");
    assert_eq!(schema["errors"].as_array().unwrap().len(), 10);
    assert!(schema["error"].is_object());
}

#[test]
fn every_error_kind_has_its_own_code_and_a_row_in_the_table() {
    let samples = [
        ErrorData::InvalidParams { path: None },
        ErrorData::Unsupported {
            method: None,
            capability: None,
        },
        ErrorData::NotFound {
            entity: "e".into(),
            name: "n".into(),
        },
        ErrorData::Rejected {
            issues: vec![],
            fell_back: None,
            reason: None,
        },
        ErrorData::Conflict { state: None },
        ErrorData::Cancelled,
        ErrorData::Timeout { after: None },
        ErrorData::Unavailable { target: None },
        ErrorData::PayloadTooLarge { limit: 1 },
        ErrorData::Internal,
    ];
    assert_eq!(samples.len(), ERROR_KINDS.len());
    let mut codes = HashSet::new();
    for sample in &samples {
        let row = ERROR_KINDS
            .iter()
            .find(|(kind, _, _)| *kind == sample.kind())
            .unwrap_or_else(|| panic!("{} has no row", sample.kind()));
        assert_eq!(row.1, sample.code());
        assert!(
            codes.insert(sample.code()),
            "{} shares its code",
            sample.kind()
        );
        let wire = serde_json::to_value(sample).unwrap();
        assert_eq!(wire["kind"], sample.kind());
        assert_eq!(serde_json::from_value::<ErrorData>(wire).unwrap(), *sample);
    }
    assert_eq!(ApiError::unsupported_method("x").code(), METHOD_NOT_FOUND);
    assert_eq!(ApiError::invalid_params("x").code(), INVALID_PARAMS);
    assert_eq!(ApiError::internal("x").code(), INTERNAL_ERROR);
}

#[test]
fn an_error_object_has_the_documented_shape() {
    let error = ApiError::rejected("bad rule", true);
    assert_eq!(
        serde_json::to_value(error.to_object()).unwrap(),
        json!({
            "code": -32011,
            "message": "bad rule",
            "data": {"kind": "rejected", "issues": [{"message": "bad rule"}], "fellBack": true}
        })
    );
    assert_eq!(
        serde_json::to_value(ApiError::not_found("proxy", "HK-01").to_object()).unwrap()["data"],
        json!({"kind": "not_found", "entity": "proxy", "name": "HK-01"})
    );
}

#[test]
fn payloads_follow_the_conventions() {
    let params: ConfigApplyParams = serde_json::from_value(json!({
        "profile": {"path": "p.yaml"},
        "overlay": {"mode": "global"},
        "selection": {"G": "a"},
        "options": {"testUrl": "u", "future": 1},
        "unknownField": true
    }))
    .unwrap();
    assert_eq!(params.options.test_url, "u");
    assert_eq!(params.profile.unwrap().path, "p.yaml");

    let missing = serde_json::from_value::<CoreInitParams>(json!({"sdkInt": 3}));
    assert!(missing.unwrap_err().to_string().contains("home"));

    let output: Output = serde_json::from_value(json!({"file": "a/b"})).unwrap();
    assert_eq!(output, Output::File { file: "a/b".into() });
    assert_eq!(Output::default(), Output::Inline { inline: true });

    let sparse = serde_json::to_value(GroupInfo {
        name: "G".into(),
        kind: "Selector".into(),
        now: None,
        all: None,
        test_url: String::new(),
        expected_status: None,
        fixed: None,
        hidden: false,
        icon: String::new(),
        empty_fallback: "COMPATIBLE".into(),
    })
    .unwrap();
    assert_eq!(sparse["testUrl"], "");
    assert!(
        sparse.get("now").is_none(),
        "an absent option is left out, never null"
    );

    let source: TunSource =
        serde_json::from_value(json!({"kind": "inherited", "handle": 4})).unwrap();
    assert_eq!(source, TunSource::Inherited { handle: 4 });

    let event = serde_json::to_value(CoreEvent::ResourceUpdate {
        kind: ResourceKind::ProxyProvider,
        name: "p".into(),
        phase: ResourcePhase::Updated,
        error: String::new(),
    })
    .unwrap();
    assert_eq!(
        event,
        json!({"type": "resourceUpdate", "kind": "proxyProvider", "name": "p", "phase": "updated"})
    );
    assert_eq!(
        serde_json::to_value(EngineState::Failed).unwrap(),
        json!("failed")
    );
}

#[test]
fn stream_options_ride_along_with_the_stream_parameters() {
    let params: TrafficWatchParams = serde_json::from_value(json!({
        "intervalMs": 500,
        "onlyProxy": true,
        "credit": 2,
        "maxBatchMs": 10,
        "maxBatchBytes": 1024
    }))
    .unwrap();
    assert_eq!(params.interval_ms, Some(500));
    assert_eq!(params.watch.credit, Some(2));
    assert_eq!(params.watch.max_batch_bytes, Some(1024));
}

#[test]
fn a_service_item_carries_the_address_only_when_its_check_read_one() {
    let item: ServiceItem = serde_json::from_value(json!({
        "name": "claude", "status": "available", "region": "US", "ip": "198.51.100.9",
        "checkedAt": 5, "epoch": 1, "version": 2,
    }))
    .unwrap();
    assert_eq!(item.ip, "198.51.100.9");
    assert_eq!(serde_json::to_value(&item).unwrap()["ip"], "198.51.100.9");

    let without: ServiceItem = serde_json::from_value(json!({
        "name": "google", "status": "available", "checkedAt": 5, "epoch": 1, "version": 2,
    }))
    .unwrap();
    assert_eq!(without.ip, "");
    assert!(serde_json::to_value(&without).unwrap().get("ip").is_none());
}

#[test]
fn general_state_omits_fell_back_when_false_and_round_trips_when_true() {
    let base = json!({
        "seq": 1,
        "port": 0,
        "socksPort": 0,
        "redirPort": 0,
        "tproxyPort": 0,
        "mixedPort": 7890,
        "allowLan": false,
        "bindAddress": "*",
        "lanAllowedIps": [],
        "lanDisallowedIps": [],
        "authentication": [],
        "skipAuthPrefixes": [],
        "mode": "rule",
        "logLevel": "info",
        "ipv6": false,
        "tcpConcurrent": false,
        "unifiedDelay": false,
        "findProcessMode": "strict",
        "interfaceName": "",
        "routingMark": 0,
        "sniffing": false,
        "globalUa": "",
        "keepAliveIdle": 0,
        "keepAliveInterval": 0,
        "disableKeepAlive": false,
        "geoAutoUpdate": false,
        "geoUpdateInterval": 24,
        "geoxUrl": {},
        "tun": {
            "enable": false,
            "device": "",
            "autoRoute": false,
            "autoDetectInterface": false,
            "dnsHijack": [],
            "mtu": 9000
        },
        "selections": {}
    });
    let normal: GeneralState = serde_json::from_value(base).unwrap();
    assert!(!normal.fell_back);
    assert!(
        serde_json::to_value(&normal)
            .unwrap()
            .get("fellBack")
            .is_none()
    );

    let mut fallback = normal;
    fallback.fell_back = true;
    let wire = serde_json::to_value(&fallback).unwrap();
    assert_eq!(wire["fellBack"], true);
    assert!(
        serde_json::from_value::<GeneralState>(wire)
            .unwrap()
            .fell_back
    );
}
