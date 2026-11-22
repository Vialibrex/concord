use concord_engine::ops::{ProfileBase, ProfileOutbound, ProfileOutbounds as EngineOutbounds};
use concord_proto::types::{OutboundRef, ProfileInspect, ProfileOutbounds};

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub fn profile_inspect(base: ProfileBase) -> ProfileInspect {
    let ProfileBase {
        config,
        digest,
        match_rules,
        proxies,
        proxy_groups,
        rules,
    } = base;
    ProfileInspect {
        config,
        digest,
        match_rules,
        proxies: count(proxies),
        proxy_groups: count(proxy_groups),
        rules: count(rules),
    }
}

fn outbound_ref(outbound: ProfileOutbound) -> OutboundRef {
    let ProfileOutbound { name, kind } = outbound;
    OutboundRef { name, kind }
}

pub fn profile_outbounds(outbounds: EngineOutbounds) -> ProfileOutbounds {
    let EngineOutbounds {
        proxies,
        proxy_groups,
    } = outbounds;
    ProfileOutbounds {
        proxies: proxies.into_iter().map(outbound_ref).collect(),
        proxy_groups: proxy_groups.into_iter().map(outbound_ref).collect(),
    }
}
