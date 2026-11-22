use std::sync::Arc;
use std::time::Duration;

use quinn::congestion::ControllerFactory;
use quinn::{IdleTimeout, TransportConfig, VarInt};

use crate::{INITIAL_PACKET_SIZE, datagram_buffer, transport_config};

pub const MAX_IDLE: Duration = Duration::from_secs(30);
pub const STREAM_WINDOW: u64 = 15_728_640;
pub const CONN_WINDOW: u64 = 67_108_864;
pub const DEFAULT_CWND: u64 = 32;

pub fn or_default(value: impl Into<u64>, fallback: u64) -> u64 {
    match value.into() {
        0 => fallback,
        value => value,
    }
}

/// The BBR initial window in bytes for a node's `cwnd` in packets.
pub fn bbr_window(cwnd: u32) -> u64 {
    or_default(cwnd, DEFAULT_CWND) * INITIAL_PACKET_SIZE
}

pub struct Transport {
    pub stream_window: u64,
    pub conn_window: u64,
    /// Bounds unacknowledged writes by the peer's flow-control credit alone, as quic-go does,
    /// instead of quinn's own send window.
    pub peer_bounded_send: bool,
    pub keep_alive: Option<Duration>,
    /// The `max_datagram_frame_size` the connection advertises, which sizes its receive buffer.
    pub datagram_frame: u64,
    /// The concurrent bidirectional and unidirectional streams the peer may open.
    pub streams: Option<u64>,
    pub mtu_discovery: bool,
    pub congestion: Option<Arc<dyn ControllerFactory + Send + Sync>>,
}

impl Transport {
    pub fn build(self) -> Arc<TransportConfig> {
        let varint = |value: u64| VarInt::from_u64(value).unwrap_or(VarInt::MAX);
        let conn_window = varint(self.conn_window);
        let mut config = transport_config();
        config
            .max_idle_timeout(IdleTimeout::try_from(MAX_IDLE).ok())
            .keep_alive_interval(self.keep_alive)
            .stream_receive_window(varint(self.stream_window))
            .receive_window(conn_window)
            .datagram_receive_buffer_size(Some(datagram_buffer(self.datagram_frame)));
        if self.peer_bounded_send {
            config.send_window(u64::MAX);
        }
        if let Some(streams) = self.streams {
            config
                .max_concurrent_bidi_streams(varint(streams))
                .max_concurrent_uni_streams(varint(streams));
        }
        if !self.mtu_discovery {
            config.mtu_discovery_config(None);
        }
        if let Some(factory) = self.congestion {
            config.congestion_controller_factory(factory);
        }
        Arc::new(config)
    }
}
