use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ChangeOrigin, LogLevel, Network, RouteStamp, StateChangeKind, WatchOptions};

dto! {
    #[derive(Default)]
    pub struct TrafficWatchParams {
        /// Default 1000.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub interval_ms: Option<u32>,
        #[serde(default)]
        pub only_proxy: bool,
        /// Send a sample only when it differs from the last one sent, the
        /// snapshot included; sampling still runs on the interval. Default
        /// false: one sample per interval, as a running clock needs.
        #[serde(default)]
        pub changes_only: bool,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    /// Rates are bytes per second; totals count from the last `traffic.reset`.
    pub struct Traffic {
        pub up: i64,
        pub down: i64,
        pub total_up: i64,
        pub total_down: i64,
    }

    #[derive(Default)]
    pub struct ConnectionWatchParams {
        /// Send the running `counters` in the deltas. Default true; a client
        /// that shows no traffic figures turns them off and the stream carries
        /// only opens and closes, each close still with its final totals.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub counters: Option<bool>,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct ConnectionInfo {
        pub id: u64,
        pub start: i64,
        pub network: Network,
        pub source_ip: String,
        pub source_port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination_ip: Option<String>,
        pub destination_port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub host: Option<String>,
        /// The host the sniffer read from the traffic.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub sniff_host: Option<String>,
        /// The kind of inbound that accepted the connection, such as `socks5` or `tun`.
        pub inbound_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_ip: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_port: Option<u16>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub inbound_user: Option<String>,
        /// `normal`, `fake-ip`, `redir-host` or `hosts`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns_mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub process: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub process_path: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub remote_destination: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_geo_ip: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination_geo_ip: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub source_asn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub destination_asn: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rematch_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub special_rules: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub special_proxy: Option<String>,
        #[serde(default)]
        pub mitm: bool,
        #[serde(default)]
        pub mitm_refused: bool,
        /// The exit first.
        pub chains: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub provider_chains: Vec<String>,
        pub rule: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub rule_payload: String,
        /// The deciding rule's position, from 0, in the list `rule.list` gave for the config
        /// the connection was routed by. Absent when no rule decided (the final fallback, a
        /// global or direct mode, a named proxy) or when matching started in a sub-rule list.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub rule_index: Option<u32>,
        pub upload: u64,
        pub download: u64,
        /// Present only on a connection whose dial failed. It is never in `connection.list`;
        /// `connection.watch` sends it in `opened` and `closed` of the same delta, with zero
        /// traffic. A route that could not be decided is not reported.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub failure: Option<ConnectionFailure>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub timing: Option<ConnectionTiming>,
        /// The `id`s, in no set order, of the `dns.watch` entries that gave out the destination's
        /// address: every lookup the core made for it, for the rules and for a DIRECT dial (A and
        /// AAAA, cache hits included), or the client's query that a redir-host address maps back
        /// to. A fake-ip address, a `hosts` entry and a node's lookup of its own server have
        /// none, and neither has a lookup made while nobody watched DNS.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub dns_queries: Vec<u64>,
    }

    /// When each step of setting the connection up happened, in microseconds after `accepted`.
    /// A step the connection did not take is absent; all are fixed by the time it is opened.
    pub struct ConnectionTiming {
        /// Unix milliseconds when the core accepted the client's flow, which is before `start`.
        pub accepted: i64,
        /// The rules' lookup of the destination, or DIRECT's own when the rules did not need one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns_start: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns_end: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub routed: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dial_start: Option<u32>,
        /// The first hop's TCP connection is up: the destination's for DIRECT, the node's for a proxy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub connected: Option<u32>,
        /// The outbound's own TLS or QUIC handshake with its server is done.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub tls: Option<u32>,
        /// The outbound is ready to carry the connection; absent on a failed dial.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dial_end: Option<u32>,
        /// For a MITM upstream: the TLS handshake with the destination is done.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub target_tls: Option<u32>,
        /// For a MITM upstream: the client's handshake was answered and its requests are read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub decrypted: Option<u32>,
    }

    pub struct ConnectionFailure {
        pub kind: ConnectionFailureKind,
        /// The error as the core logs it.
        pub message: String,
    }

    pub struct ConnectionSnapshot {
        pub connections: Vec<ConnectionInfo>,
    }

    pub struct ConnectionCounter {
        pub id: u64,
        pub upload: u64,
        pub download: u64,
    }

    /// Why a connection ended and when.
    pub struct ConnectionEnd {
        pub id: u64,
        pub reason: ConnectionEndReason,
        /// Unix milliseconds.
        pub ended_at: i64,
        /// The error's text for `timeout`, `reset` and `error`, for display only.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub message: String,
    }

    /// An `opened` entry that a client already has is a repeat and replaces it.
    /// A connection that opened and closed between two batches is in both lists,
    /// so apply `opened` first, then `counters` and `ended`, then `closed`.
    pub struct ConnectionDelta {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub opened: Vec<ConnectionInfo>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub closed: Vec<u64>,
        /// Totals since each connection opened. Every id in `closed` has an
        /// entry here with its final totals, whether or not the subscription
        /// asked for `counters`; the others are only sent when it did, for the
        /// connections whose traffic moved.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub counters: Vec<ConnectionCounter>,
        /// Every id in `closed` has an entry here with why it ended.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub ended: Vec<ConnectionEnd>,
    }

    pub struct ConnectionCloseParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ids: Option<Vec<u64>>,
        /// Closes every connection.
        #[serde(default)]
        pub all: bool,
    }

    #[derive(Default)]
    pub struct LogWatchParams {
        /// Entries below this level are left out of this subscription.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub level: Option<LogLevel>,
        /// Deliver entries below the profile's `log-level` too, so `level` alone filters this
        /// subscription, as mihomo's `/logs` does. Default false: entries stop at the higher of
        /// `level` and `log-level`.
        #[serde(default)]
        pub ignore_log_level: bool,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct LogEntry {
        pub level: LogLevel,
        pub time: i64,
        pub text: String,
    }

    #[derive(Default)]
    pub struct DnsWatchParams {
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct DnsEntry {
        /// Counts up from 1 over the core process; a connection's `dnsQueries` names entries by it.
        #[serde(default)]
        pub id: u64,
        pub domain: String,
        #[serde(rename = "type")]
        pub query_type: String,
        /// `app` for a query a client sent the core: to its DNS `listen`, through
        /// `dns-hijack` or a `dns` outbound. `rule`, `direct` and `proxy` for the core's own
        /// lookups for a rule, a DIRECT dial and a node's server; `other` for the rest.
        pub initiator: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub upstream: String,
        #[serde(default)]
        pub cached: bool,
        pub answers: Vec<String>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub rcode: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub error: String,
        pub delay: i64,
        pub time: i64,
    }

    #[derive(Default)]
    pub struct RouteWatchParams {
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    #[derive(Default)]
    pub struct EventsWatchParams {
        /// Also report every URL test result, the automatic ones of the groups included.
        #[serde(default)]
        pub delays: bool,
        /// Also report `stateChanged`: every change of a pick or of the general
        /// settings a host keeps, from any origin, in the order it took effect.
        #[serde(default)]
        pub state: bool,
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct DnsQueryParams {
        pub name: String,
        /// A record type such as `A` or `AAAA`. Default `A`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub qtype: Option<String>,
    }

    pub struct DnsQuestion {
        pub name: String,
        pub qtype: u16,
        pub qclass: u16,
    }

    /// `data` is the record's data in presentation format.
    pub struct DnsRecord {
        pub name: String,
        pub rtype: u16,
        pub ttl: u32,
        pub data: String,
    }

    pub struct DnsQueryResult {
        pub rcode: u16,
        pub questions: Vec<DnsQuestion>,
        pub truncated: bool,
        pub recursion_desired: bool,
        pub recursion_available: bool,
        pub authentic_data: bool,
        pub checking_disabled: bool,
        pub answers: Vec<DnsRecord>,
        pub authorities: Vec<DnsRecord>,
        pub additionals: Vec<DnsRecord>,
    }

    #[derive(Default)]
    pub struct EngineStateParams {
        #[serde(flatten)]
        pub watch: WatchOptions,
    }

    pub struct EngineStatus {
        pub state: EngineState,
        /// Why the engine is `failed`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kind: Option<String>,
        /// Requested services that did not start, as of the last apply, patch, start or stop.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub faults: Vec<ServiceFault>,
    }

    pub struct ServiceFault {
        pub service: FaultService,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        pub address: String,
        pub reason: FaultReason,
        pub message: String,
    }

    pub struct TunStartParams {
        pub source: TunSource,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub mtu: Option<u32>,
        #[serde(default)]
        pub address: Vec<String>,
        #[serde(default)]
        pub dns: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub congestion_controller: Option<String>,
    }

    pub struct NetworkUpdateParams {
        /// Socket addresses of the resolvers the system now uses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub dns_servers: Option<Vec<String>>,
        /// The default network changed: connections over the old one are closed.
        #[serde(default)]
        pub interface_changed: bool,
    }
}

/// Why a dial failed. `dns`: the name had no usable address. `handshake`: the path
/// to the target opened but the exchange over it failed, as when a proxy server
/// closes, resets or breaks its protocol. `other` takes the rest, a resolver's own
/// error among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionFailureKind {
    Timeout,
    Refused,
    Unreachable,
    Dns,
    Handshake,
    Other,
}

/// Why a connection ended. `local`, `remote`: that side finished first. `finished`: both
/// did and nothing tells which first. `core`: the core closed it (`connection.close`, a
/// config change, a full UDP table, a stop). `failed`: its dial failed, as `failure` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEndReason {
    Local,
    Remote,
    Finished,
    Timeout,
    Reset,
    Core,
    Error,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FaultService {
    Mixed,
    Http,
    Socks,
    Redir,
    Tproxy,
    Tun,
    Dns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FaultReason {
    AddressInUse,
    AddressNotAvailable,
    PermissionDenied,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EngineState {
    Created,
    Initialized,
    Configured,
    Running,
    Failed,
}

/// A device the core creates itself, or a descriptor the host opened and
/// registered beforehand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TunSource {
    Device {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Inherited {
        handle: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ResourceKind {
    ProxyProvider,
    RuleProvider,
    Geo,
    /// The remote files of the MITM module of that name.
    MitmModule,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ResourcePhase {
    Updating,
    Updated,
    /// Fetched, and the same as the content in force.
    Unchanged,
    Failed,
}

/// One entry of `events.watch`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CoreEvent {
    /// One step of a fetch of a provider or a geo database, whatever started
    /// it: its first load, a retry, its interval, its file changing, or a
    /// caller. A geo database is named `MMDB`, `ASN` or `GEOSITE`, as
    /// `geo.update` names it. Every step of a provider's first load waits
    /// until the `config.apply` that made it has finished. A fetch cut short by
    /// a newer apply or by shutdown ends `failed` with the error `superseded`.
    ResourceUpdate {
        kind: ResourceKind,
        name: String,
        phase: ResourcePhase,
        /// Set when `phase` is `failed`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        error: String,
    },
    DialerLoop {
        name: String,
    },
    /// The node of that name can carry nothing until its user logs in at `url`: a tailscale
    /// node with no auth key and no saved login. Sent each time the node asks, which is on
    /// its first dial and again if the login expires.
    NodeLogin {
        name: String,
        url: String,
    },
    Delay {
        name: String,
        url: String,
        value: i32,
    },
    /// What a MITM script posted with `$notification.post`, sent as it posts.
    /// None is kept for a watch that comes later, and one a watch has no room
    /// for ends in a resync like any other event.
    ScriptNotification {
        script: String,
        title: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        subtitle: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        body: String,
        /// What opening it opens: the post's `url`, `open-url` or `openUrl`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        url: String,
        /// Unix milliseconds when the script posted it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at: Option<i64>,
        /// The `connection.watch` id of the upstream connection the request went out on, or for
        /// a request not yet sent to the server its client asked for, the one opened for it.
        /// Absent for a `rule`, `dns` or cron script, and for a request not yet sent that goes
        /// to another server or is routed on its own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection: Option<u64>,
        /// The `mitm.exchanges` id of the request, while capture is on.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exchange: Option<i64>,
    },
    /// Sent only to a watch that asked for `state`.
    StateChanged {
        seq: u64,
        origin: ChangeOrigin,
        change: StateChangeKind,
    },
}

/// One entry of `delay.run`: a result for each proxy, then `done`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum DelayRunEvent {
    Result {
        name: String,
        url: String,
        value: i32,
    },
    Done,
}

pub type RouteSnapshot = RouteStamp;
