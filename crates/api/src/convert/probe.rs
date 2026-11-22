use concord_engine::{OutboundIpResult, ServiceItem as EngineService};
use concord_proto::types::{OutboundIp, RouteHit, ServiceItem};

pub fn route_hit(hit: concord_engine::RouteHit) -> RouteHit {
    let concord_engine::RouteHit { host, proxy, exit } = hit;
    RouteHit { host, proxy, exit }
}

fn route_hits(hits: Vec<concord_engine::RouteHit>) -> Vec<RouteHit> {
    hits.into_iter().map(route_hit).collect()
}

pub fn outbound_ip(result: OutboundIpResult) -> OutboundIp {
    let OutboundIpResult {
        url,
        body,
        delay,
        chains,
        error,
        core_epoch,
        route_version,
        hits,
        node_hits,
    } = result;
    OutboundIp {
        url,
        body,
        delay,
        chains,
        error: error.map(str::to_owned),
        epoch: core_epoch,
        version: route_version,
        hits: route_hits(hits),
        node_hits: route_hits(node_hits),
    }
}

pub fn service_item(item: EngineService) -> ServiceItem {
    let EngineService {
        name,
        status,
        region,
        ip,
        delay,
        chains,
        checked_at,
        core_epoch,
        route_version,
        hits,
    } = item;
    ServiceItem {
        name,
        status: status.to_owned(),
        region,
        ip,
        delay,
        chains,
        checked_at,
        epoch: core_epoch,
        version: route_version,
        hits: route_hits(hits),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_hit_leaves_out_an_empty_proxy() {
        let hit = |proxy: &str| concord_engine::RouteHit {
            host: "a:1".into(),
            proxy: proxy.into(),
            exit: "x".into(),
        };
        assert_eq!(
            serde_json::to_value(route_hit(hit(""))).unwrap(),
            json!({"host": "a:1", "exit": "x"})
        );
        assert_eq!(
            serde_json::to_value(route_hit(hit("n"))).unwrap(),
            json!({"host": "a:1", "proxy": "n", "exit": "x"})
        );
    }

    #[test]
    fn a_service_item_leaves_out_what_it_did_not_learn() {
        let full = EngineService {
            name: "claude".into(),
            status: "available",
            region: "JP".into(),
            ip: "198.51.100.9".into(),
            delay: 120,
            chains: vec!["node".into()],
            checked_at: 5,
            core_epoch: 1,
            route_version: 2,
            hits: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(service_item(full)).unwrap(),
            json!({
                "name": "claude", "status": "available", "region": "JP", "ip": "198.51.100.9",
                "delay": 120, "chains": ["node"], "checkedAt": 5, "epoch": 1, "version": 2,
            })
        );
        let failed = EngineService::with_status("failed");
        assert_eq!(
            serde_json::to_value(service_item(failed)).unwrap(),
            json!({"name": "", "status": "failed", "checkedAt": 0, "epoch": 0, "version": 0})
        );
    }
}
