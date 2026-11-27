//! The pushed routes: newline-separated JSON over a chunked response, or one JSON
//! text message per value over a WebSocket, as mihomo writes both.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use concord_api::{Control, ControlService, Delivery, EventStream};
use concord_common::Tasks;
use concord_proto::types::{
    ConnectionInfo, ConnectionWatchParams, Empty, LogLevel, LogWatchParams, Traffic,
    TrafficWatchParams,
};
use futures_util::stream::{self, BoxStream};
use futures_util::{SinkExt, StreamExt};
use http::header::{self, HeaderValue};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::TokioIo;
use serde::{Serialize, Serializer};
use serde_json::json;
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::{Message, Role};

use crate::http::{Body, is_websocket};
use crate::shapes;

pub type Frames = BoxStream<'static, String>;

/// mihomo's tickers for `/traffic`, `/memory` and the default `/connections` interval.
const TICK: Duration = Duration::from_secs(1);

fn encode_json(value: &impl Serialize) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Answers with `frames` as a WebSocket when the request asks for one, otherwise
/// as a chunked JSON stream.
pub fn respond(request: Request<Incoming>, frames: Frames, sessions: &Tasks) -> Response<Body> {
    if !is_websocket(request.headers()) {
        let lines = frames.map(|mut text| {
            text.push('\n');
            Ok::<_, Infallible>(Frame::data(Bytes::from(text.into_bytes())))
        });
        let mut response = Response::new(StreamBody::new(lines).boxed_unsync());
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return response;
    }
    let Some(accept) = accept_key(&request) else {
        return crate::http::error(
            StatusCode::BAD_REQUEST,
            "handshake error: bad Sec-WebSocket-Key header",
        );
    };
    sessions.spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(request).await else {
            return;
        };
        let socket =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
        pump(socket, frames).await;
    });
    let mut response = crate::http::empty(StatusCode::SWITCHING_PROTOCOLS);
    let headers = response.headers_mut();
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    if let Ok(value) = HeaderValue::from_str(&accept) {
        headers.insert(header::SEC_WEBSOCKET_ACCEPT, value);
    }
    response
}

fn accept_key(request: &Request<Incoming>) -> Option<String> {
    let headers = request.headers();
    let key = headers.get(header::SEC_WEBSOCKET_KEY)?;
    let version_ok = headers
        .get(header::SEC_WEBSOCKET_VERSION)
        .is_some_and(|version| version == "13");
    (key.len() == 24 && version_ok).then(|| derive_accept_key(key.as_bytes()))
}

/// Ends when the frames end, the client closes, or a write fails.
async fn pump<S>(socket: WebSocketStream<S>, mut frames: Frames)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut incoming) = socket.split();
    loop {
        tokio::select! {
            frame = frames.next() => {
                let Some(frame) = frame else { break };
                if sink.send(Message::Text(frame.into())).await.is_err() {
                    return;
                }
            }
            message = incoming.next() => match message {
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
    let _ = sink.close().await;
}

fn events<E: Send + 'static>(stream: EventStream<E>) -> BoxStream<'static, E> {
    stream
        .take_while(|delivery| std::future::ready(matches!(delivery, Delivery::Event { .. })))
        .filter_map(|delivery| async move {
            match delivery {
                Delivery::Event { data, .. } => Some(data),
                Delivery::Resync => None,
            }
        })
        .boxed()
}

fn traffic_frame(traffic: &Traffic) -> String {
    encode_json(&json!({
        "up": traffic.up,
        "down": traffic.down,
        "upTotal": traffic.total_up,
        "downTotal": traffic.total_down,
    }))
}

pub async fn traffic(control: &Arc<Control>) -> Frames {
    let params = TrafficWatchParams {
        interval_ms: Some(1000),
        ..Default::default()
    };
    match control.traffic_watch(params).await {
        Ok(subscription) => events(subscription.events)
            .map(|traffic| traffic_frame(&traffic))
            .boxed(),
        Err(_) => stream::empty().boxed(),
    }
}

/// The first value is zero so a chart starts there (`server.go:440-446`).
pub fn memory(control: Arc<Control>) -> Frames {
    let mut ticker = interval_at(Instant::now() + TICK, TICK);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    stream::unfold(
        (control, ticker, true),
        |(control, mut ticker, first)| async move {
            ticker.tick().await;
            let inuse = if first {
                0
            } else {
                control
                    .core_stats(Empty {})
                    .await
                    .map_or(0, |stats| stats.rss)
            };
            Some((
                encode_json(&json!({ "inuse": inuse, "oslimit": 0 })),
                (control, ticker, false),
            ))
        },
    )
    .boxed()
}

pub async fn logs(control: &Arc<Control>, level: LogLevel, structured: bool) -> Frames {
    let params = LogWatchParams {
        level: Some(level),
        ignore_log_level: true,
        ..Default::default()
    };
    match control.log_watch(params).await {
        Ok(subscription) => events(subscription.events)
            .filter(move |entry| {
                std::future::ready(level != LogLevel::Silent && entry.level >= level)
            })
            .map(move |entry| {
                encode_json(&shapes::log(
                    entry.level,
                    entry.time,
                    &entry.text,
                    structured,
                ))
            })
            .boxed(),
        Err(_) => stream::empty().boxed(),
    }
}

/// The connection table as a session sees it: a snapshot, then deltas applied
/// in order. A resync takes a fresh snapshot.
pub struct Table {
    control: Arc<Control>,
    open: BTreeMap<u64, ConnectionInfo>,
    deltas: Option<EventStream<concord_proto::types::ConnectionDelta>>,
}

impl Table {
    pub fn new(control: Arc<Control>) -> Self {
        Table {
            control,
            open: BTreeMap::new(),
            deltas: None,
        }
    }

    async fn subscribe(&mut self) {
        self.open.clear();
        self.deltas = None;
        let params = ConnectionWatchParams {
            counters: Some(true),
            ..Default::default()
        };
        if let Ok(subscription) = self.control.connection_watch(params).await {
            for info in subscription
                .snapshot
                .into_iter()
                .flat_map(|snapshot| snapshot.connections)
            {
                self.open.insert(info.id, info);
            }
            self.deltas = Some(subscription.events);
        }
    }

    /// Applies what has arrived without waiting for more.
    async fn catch_up(&mut self) {
        if self.deltas.is_none() {
            self.subscribe().await;
        }
        loop {
            let Some(deltas) = self.deltas.as_mut() else {
                return;
            };
            let Some(delivery) = futures_util::FutureExt::now_or_never(deltas.next()) else {
                return;
            };
            match delivery {
                Some(Delivery::Event { data, .. }) => {
                    for info in data.opened {
                        self.open.insert(info.id, info);
                    }
                    for counter in data.counters {
                        if let Some(info) = self.open.get_mut(&counter.id) {
                            info.upload = counter.upload;
                            info.download = counter.download;
                        }
                    }
                    for id in data.closed {
                        self.open.remove(&id);
                    }
                }
                Some(Delivery::Resync) | None => {
                    self.subscribe().await;
                    return;
                }
            }
        }
    }

    pub async fn snapshot(&mut self) -> String {
        self.catch_up().await;
        let (upload, download, memory) = snapshot_totals(&self.control).await;
        encode_json(&shapes::snapshot(
            self.open.values(),
            upload,
            download,
            memory,
        ))
    }
}

pub struct ClashSnapshot {
    connections: Vec<ConnectionInfo>,
    upload_total: i64,
    download_total: i64,
    memory: u64,
}

impl Serialize for ClashSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        shapes::snapshot(
            self.connections.iter(),
            self.upload_total,
            self.download_total,
            self.memory,
        )
        .serialize(serializer)
    }
}

pub async fn connection_snapshot(control: &Arc<Control>) -> ClashSnapshot {
    let mut connections = control.connection_snapshot().connections;
    sort_connections(&mut connections);
    let (upload_total, download_total, memory) = snapshot_totals(control).await;
    ClashSnapshot {
        connections,
        upload_total,
        download_total,
        memory,
    }
}

fn sort_connections(list: &mut [ConnectionInfo]) {
    list.sort_unstable_by_key(|info| info.id);
}

async fn snapshot_totals(control: &Arc<Control>) -> (i64, i64, u64) {
    let (upload, download) = control.traffic_totals();
    let memory = control
        .core_stats(Empty {})
        .await
        .map_or(0, |stats| stats.rss);
    (upload, download, memory)
}

/// A snapshot now, then one every `period` (`connections.go:60-70`).
pub fn connections(control: Arc<Control>, period: Duration) -> Frames {
    let mut ticker = interval_at(Instant::now(), period.max(Duration::from_millis(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    stream::unfold(
        (Table::new(control), ticker),
        |(mut table, mut ticker)| async move {
            ticker.tick().await;
            let frame = table.snapshot().await;
            Some((frame, (table, ticker)))
        },
    )
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(id: u64) -> ConnectionInfo {
        serde_json::from_value(json!({
            "id": id,
            "start": 1_700_000_000_000i64,
            "network": "tcp",
            "sourceIp": "127.0.0.1",
            "sourcePort": 1234,
            "destinationPort": 443,
            "inboundType": "socks5",
            "chains": ["DIRECT"],
            "rule": "MATCH",
            "upload": id * 10,
            "download": id * 20,
        }))
        .unwrap()
    }

    #[test]
    fn direct_snapshot_sorts_connection_ids_numerically() {
        let mut list = vec![info(10), info(2), info(100), info(1)];
        sort_connections(&mut list);
        let snap = ClashSnapshot {
            connections: list,
            upload_total: 100,
            download_total: 200,
            memory: 4096,
        };
        let direct_bytes = serde_json::to_string(&snap).unwrap();
        let map: BTreeMap<u64, ConnectionInfo> = snap
            .connections
            .iter()
            .cloned()
            .map(|item| (item.id, item))
            .collect();
        let ws_bytes = encode_json(&shapes::snapshot(map.values(), 100, 200, 4096));
        assert_eq!(direct_bytes, ws_bytes);

        let value: serde_json::Value = serde_json::from_str(&direct_bytes).unwrap();
        let ids: Vec<&str> = value["connections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["1", "2", "10", "100"]);
        assert_eq!(value["uploadTotal"], 100);
        assert_eq!(value["downloadTotal"], 200);
        assert_eq!(value["memory"], 4096);

        let empty = serde_json::to_value(shapes::snapshot(std::iter::empty(), 0, 0, 0)).unwrap();
        assert_eq!(empty["connections"], json!([]));
    }
}
