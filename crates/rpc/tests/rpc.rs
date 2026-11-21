use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use concord_api::sync::lock;
use concord_api::{ControlService, PolicyQueue, QueueStream, ServiceInfo, Subscription};
use concord_proto::ApiError;
use concord_proto::StreamPolicy;
use concord_proto::types::*;
use concord_rpc::{
    MemoryChannel, MessageChannel, MessageReader, MessageWriter, SendError, Server, ServerConfig,
};
use futures_util::stream::{Stream, StreamExt};
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc};
use tokio::time::timeout;

struct Counted<S> {
    inner: S,
    polls: Arc<AtomicUsize>,
}

impl<S: Stream + Unpin> Stream for Counted<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

struct DropCount(Arc<AtomicUsize>);

impl Drop for DropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct Mock {
    mitm: bool,
    debug: bool,
    order: Mutex<Vec<String>>,
    release: Notify,
    running: AtomicUsize,
    peak: AtomicUsize,
    hung_dropped: Arc<AtomicBool>,
    streams_dropped: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
    traffic: Mutex<Option<Arc<PolicyQueue<Traffic>>>>,
    logs: Mutex<Option<Arc<PolicyQueue<LogEntry>>>>,
    deltas: Mutex<Option<Arc<PolicyQueue<ConnectionDelta>>>>,
}

impl Mock {
    fn note(&self, line: impl Into<String>) {
        lock(&self.order).push(line.into());
    }

    fn seen(&self) -> Vec<String> {
        lock(&self.order).clone()
    }

    fn queue<T>(slot: &Mutex<Option<Arc<PolicyQueue<T>>>>) -> Arc<PolicyQueue<T>> {
        lock(slot).clone().expect("the test made the queue")
    }

    fn subscription<T: Send + Unpin + 'static>(
        &self,
        slot: &Mutex<Option<Arc<PolicyQueue<T>>>>,
    ) -> concord_api::EventStream<T> {
        let queue = Self::queue(slot);
        let counted = Counted {
            inner: QueueStream::new(queue, DropCount(self.streams_dropped.clone())),
            polls: self.polls.clone(),
        };
        counted.boxed()
    }
}

struct Hung(Arc<AtomicBool>);

impl Drop for Hung {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl ControlService for Mock {
    fn info(&self) -> ServiceInfo {
        ServiceInfo {
            server: ServerInfo {
                implementation: "mock".into(),
                version: "0".into(),
                build: "test".into(),
            },
            platform: PlatformInfo {
                os: "test".into(),
                privileged: false,
                capabilities: vec!["tun.inherited".into()],
            },
            features: Features {
                mitm: self.mitm,
                ech: false,
                system_stack: false,
            },
            engine: EngineStatus {
                state: EngineState::Created,
                kind: None,
                faults: Vec::new(),
            },
            debug: self.debug,
        }
    }

    async fn core_stats(&self, _params: Empty) -> Result<CoreStats, ApiError> {
        Ok(CoreStats { rss: 42 })
    }

    async fn core_init(&self, params: CoreInitParams) -> Result<Empty, ApiError> {
        self.note(format!("init {}", params.home));
        Ok(Empty {})
    }

    async fn core_release_memory(&self, _params: Empty) -> Result<Empty, ApiError> {
        panic!("boom")
    }

    async fn proxy_select(&self, params: ProxySelectParams) -> Result<ProxySelectResult, ApiError> {
        Err(ApiError::not_found("proxy", params.proxy))
    }

    async fn config_apply(&self, params: ConfigApplyParams) -> Result<ConfigApplyResult, ApiError> {
        let name = format!("apply {}", params.options.test_url);
        self.note(format!("start {name}"));
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        self.release.notified().await;
        self.running.fetch_sub(1, Ordering::SeqCst);
        self.note(format!("end {name}"));
        Ok(ConfigApplyResult { warnings: vec![] })
    }

    async fn delay_test(&self, params: DelayTestParams) -> Result<DelayResult, ApiError> {
        let hung = Hung(self.hung_dropped.clone());
        self.note(format!("delay {}", params.proxy));
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        if params.proxy == "hang" {
            std::future::pending::<()>().await;
        }
        self.release.notified().await;
        self.running.fetch_sub(1, Ordering::SeqCst);
        drop(hung);
        self.hung_dropped.store(false, Ordering::SeqCst);
        Ok(DelayResult {
            name: params.proxy,
            url: String::new(),
            value: 1,
        })
    }

    async fn core_last_warnings(&self, _params: Empty) -> Result<WarningList, ApiError> {
        Ok(WarningList {
            warnings: vec![
                Warning {
                    level: "warning".into(),
                    code: None,
                    path: "x".into(),
                    message: "y".repeat(10_000),
                };
                2
            ],
        })
    }

    async fn traffic_watch(
        &self,
        _params: TrafficWatchParams,
    ) -> Result<Subscription<Traffic, Traffic>, ApiError> {
        Ok(Subscription::new(
            Some(Traffic {
                up: 0,
                down: 0,
                total_up: 0,
                total_down: 0,
            }),
            self.subscription(&self.traffic),
        ))
    }

    async fn log_watch(
        &self,
        _params: LogWatchParams,
    ) -> Result<Subscription<Empty, LogEntry>, ApiError> {
        Ok(Subscription::new(None, self.subscription(&self.logs)))
    }

    async fn connection_watch(
        &self,
        _params: ConnectionWatchParams,
    ) -> Result<Subscription<ConnectionSnapshot, ConnectionDelta>, ApiError> {
        Ok(Subscription::new(
            Some(ConnectionSnapshot {
                connections: vec![],
            }),
            self.subscription(&self.deltas),
        ))
    }
}

struct Client {
    channel: MemoryChannel,
    next: u64,
    events: VecDeque<Value>,
}

impl Client {
    async fn send(&self, value: Value) {
        assert!(self.channel.send(serde_json::to_vec(&value).unwrap()).await);
    }

    async fn request(&mut self, method: &str, params: Value) -> u64 {
        self.next += 1;
        let id = self.next;
        let mut message = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if !params.is_null() {
            message["params"] = params;
        }
        self.send(message).await;
        id
    }

    async fn next_message(&mut self) -> Option<Value> {
        let bytes = timeout(Duration::from_secs(5), self.channel.recv())
            .await
            .expect("no message arrived")?;
        Some(serde_json::from_slice(&bytes).unwrap())
    }

    async fn response(&mut self, id: u64) -> Value {
        loop {
            let message = self.next_message().await.expect("the connection closed");
            if message.get("id") == Some(&json!(id)) {
                return message;
            }
            if message.get("method") == Some(&json!("$/event")) {
                self.events.push_back(message);
            }
        }
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.request(method, params).await;
        self.response(id).await
    }

    async fn event(&mut self) -> Value {
        if let Some(event) = self.events.pop_front() {
            return event;
        }
        loop {
            let message = self.next_message().await.expect("the connection closed");
            if message.get("method") == Some(&json!("$/event")) {
                return message;
            }
        }
    }

    async fn hello(&mut self) -> Value {
        self.call(
            "core.hello",
            json!({"protocol": {"min": 1, "max": 1}, "client": {"name": "t", "version": "0"}, "capabilities": ["debug"]}),
        )
        .await
    }

    async fn quiet(&mut self) {
        let waited = timeout(Duration::from_millis(150), self.channel.recv()).await;
        assert!(waited.is_err(), "unexpected message: {waited:?}");
    }
}

fn start(mock: Mock) -> (Client, Arc<Mock>, tokio::task::JoinHandle<()>) {
    start_with(mock, ServerConfig::default())
}

fn start_with(
    mock: Mock,
    config: ServerConfig,
) -> (Client, Arc<Mock>, tokio::task::JoinHandle<()>) {
    let mock = Arc::new(mock);
    let (ours, theirs) = MemoryChannel::pair(64);
    let server = Server::with_config(mock.clone(), config);
    let serving = tokio::spawn(async move { server.serve(theirs).await });
    (
        Client {
            channel: ours,
            next: 0,
            events: VecDeque::new(),
        },
        mock,
        serving,
    )
}

async fn ready(mock: Mock) -> (Client, Arc<Mock>, tokio::task::JoinHandle<()>) {
    let (mut client, mock, serving) = start(mock);
    client.hello().await;
    (client, mock, serving)
}

fn queue<T>(
    slot: &Mutex<Option<Arc<PolicyQueue<T>>>>,
    policy: StreamPolicy,
    depth: usize,
) -> Arc<PolicyQueue<T>> {
    let queue = PolicyQueue::new(policy, depth);
    *lock(slot) = Some(queue.clone());
    queue
}

fn named(name: &str) -> Value {
    json!({"options": {"testUrl": name}})
}

fn traffic(up: i64) -> Traffic {
    Traffic {
        up,
        down: 0,
        total_up: 0,
        total_down: 0,
    }
}

fn entry(text: &str) -> LogEntry {
    LogEntry {
        level: LogLevel::Info,
        time: 1,
        text: text.to_string(),
    }
}

async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn nothing_but_hello_is_answered_before_hello() {
    let (mut client, _, _) = start(Mock::default());

    let early = client.call("core.stats", Value::Null).await;
    assert_eq!(early["error"]["data"]["kind"], "conflict", "{early}");
    assert_eq!(early["error"]["data"]["state"], "hello_required");
    assert_eq!(early["error"]["code"], -32012);

    let hello = client.hello().await;
    assert_eq!(hello["result"]["protocol"], 1, "{hello}");
    assert_eq!(hello["result"]["server"]["implementation"], "mock");
    assert_eq!(
        hello["result"]["platform"]["capabilities"][0],
        "tun.inherited"
    );
    assert_eq!(hello["result"]["limits"]["maxMessage"], 64 * 1024 * 1024);
    assert_eq!(hello["result"]["engine"]["state"], "created");
    let methods = hello["result"]["methods"].as_array().unwrap();
    assert!(methods.contains(&json!("core.hello")));
    assert!(methods.contains(&json!("traffic.watch")));
    assert!(!methods.contains(&json!("mitm.certificate")));
    assert!(!methods.contains(&json!("debug.crash")));

    let late = client.call("core.stats", Value::Null).await;
    assert_eq!(late["result"], json!({"rss": 42}));
}

#[tokio::test]
async fn a_hello_for_a_protocol_the_core_does_not_speak_is_refused() {
    let (mut client, _, _) = start(Mock::default());
    let refused = client
        .call(
            "core.hello",
            json!({"protocol": {"min": 2, "max": 3}, "client": {"name": "t", "version": "0"}}),
        )
        .await;
    assert_eq!(refused["error"]["data"]["kind"], "unsupported", "{refused}");
    assert_eq!(refused["error"]["data"]["capability"], "protocol");
    let still_closed = client.call("core.stats", Value::Null).await;
    assert_eq!(still_closed["error"]["data"]["state"], "hello_required");
}

#[tokio::test]
async fn capabilities_gate_the_methods_they_name() {
    let (mut client, _, _) = start(Mock {
        mitm: true,
        debug: true,
        ..Mock::default()
    });
    let hello = client.hello().await;
    let methods = hello["result"]["methods"].as_array().unwrap();
    assert!(methods.contains(&json!("mitm.certificate")));
    assert!(methods.contains(&json!("debug.crash")));

    let (mut client, _, _) = start(Mock::default());
    client.hello().await;
    let refused = client.call("mitm.certificate", Value::Null).await;
    assert_eq!(refused["error"]["data"]["kind"], "unsupported", "{refused}");
    assert_eq!(refused["error"]["data"]["capability"], "mitm");
    let hidden = client.call("debug.crash", Value::Null).await;
    assert_eq!(hidden["error"]["data"]["method"], "debug.crash");
}

#[tokio::test]
async fn malformed_messages_and_params_get_typed_errors() {
    let (mut client, _, _) = ready(Mock::default()).await;

    assert!(client.channel.send(b"{not json".to_vec()).await);
    let parse = client.next_message().await.unwrap();
    assert_eq!(parse["error"]["code"], -32700, "{parse}");
    assert_eq!(parse["id"], Value::Null);

    client.send(json!({"jsonrpc": "2.0", "id": 90})).await;
    let invalid = client.response(90).await;
    assert_eq!(invalid["error"]["code"], -32600, "{invalid}");

    let unknown = client.call("no.such", Value::Null).await;
    assert_eq!(unknown["error"]["code"], -32601, "{unknown}");
    assert_eq!(unknown["error"]["data"]["kind"], "unsupported");

    let bare = client.call("core.init", json!([1])).await;
    assert_eq!(bare["error"]["code"], -32602, "{bare}");
    assert_eq!(bare["error"]["data"]["kind"], "invalid_params");

    let missing = client.call("core.init", json!({})).await;
    assert_eq!(
        missing["error"]["data"]["kind"], "invalid_params",
        "{missing}"
    );
    assert_eq!(missing["error"]["data"]["path"], "home");

    let wrong = client.call("core.init", json!({"home": 4})).await;
    assert_eq!(wrong["error"]["data"]["kind"], "invalid_params", "{wrong}");

    let extra = client
        .call("core.init", json!({"home": "h", "future": true}))
        .await;
    assert_eq!(
        extra["result"],
        json!({}),
        "unknown fields are ignored: {extra}"
    );

    let typed = client
        .call("proxy.select", json!({"group": "g", "proxy": "p"}))
        .await;
    assert_eq!(typed["error"]["code"], -32010, "{typed}");
    assert_eq!(
        typed["error"]["data"],
        json!({"kind": "not_found", "entity": "proxy", "name": "p"})
    );
    assert!(typed["error"]["message"].is_string());
}

#[tokio::test]
async fn a_notification_for_an_ordinary_method_is_ignored() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    client
        .send(json!({"jsonrpc": "2.0", "method": "core.init", "params": {"home": "x"}}))
        .await;
    client
        .send(json!({"jsonrpc": "2.0", "method": "$/credit", "params": {"sub": 99, "n": 1}}))
        .await;
    client.quiet().await;
    assert!(mock.seen().is_empty());
}

#[tokio::test]
async fn a_panic_in_a_method_is_an_internal_error_and_the_connection_lives() {
    let (mut client, _, _) = ready(Mock::default()).await;
    let crashed = client.call("core.releaseMemory", Value::Null).await;
    assert_eq!(crashed["error"]["data"]["kind"], "internal", "{crashed}");
    assert!(
        crashed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("boom")
    );
    let alive = client.call("core.stats", Value::Null).await;
    assert_eq!(alive["result"]["rss"], 42);
}

#[tokio::test]
async fn serial_methods_run_one_at_a_time_in_arrival_order() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let first = client.request("config.apply", named("1")).await;
    let second = client.request("config.apply", named("2")).await;
    let third = client.request("config.apply", named("3")).await;
    settle().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mock.seen(), ["start apply 1"], "only the first may run");

    for _ in 0..3 {
        mock.release.notify_one();
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    client.response(first).await;
    let second = client.response(second).await;
    let third = client.response(third).await;
    assert_eq!(mock.peak.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.seen(),
        [
            "start apply 1",
            "end apply 1",
            "start apply 2",
            "end apply 2",
            "start apply 3",
            "end apply 3"
        ]
    );
    assert!(second.get("result").is_some(), "{second}");
    assert!(third.get("result").is_some(), "{third}");
}

#[tokio::test]
async fn concurrent_methods_overlap_and_inline_ones_do_not_queue_behind_a_serial_one() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let a = client.request("delay.test", json!({"proxy": "a"})).await;
    let b = client.request("delay.test", json!({"proxy": "b"})).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mock.peak.load(Ordering::SeqCst), 2);
    mock.release.notify_waiters();
    client.response(a).await;
    client.response(b).await;

    let apply = client.request("config.apply", named("1")).await;
    tokio::time::sleep(Duration::from_millis(30)).await;
    queue(&mock.traffic, StreamPolicy::Latest, 1);
    let watching = client.call("traffic.watch", json!({})).await;
    assert!(watching["result"]["sub"].is_u64(), "{watching}");
    mock.release.notify_one();
    client.response(apply).await;
}

#[tokio::test]
async fn cancelling_a_running_call_drops_its_work_and_answers_cancelled() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let id = client.request("delay.test", json!({"proxy": "hang"})).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!mock.hung_dropped.load(Ordering::SeqCst));

    client
        .send(json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": id}}))
        .await;
    let answer = client.response(id).await;

    assert_eq!(answer["error"]["data"]["kind"], "cancelled", "{answer}");
    assert_eq!(answer["error"]["code"], -32014);
    assert!(
        mock.hung_dropped.load(Ordering::SeqCst),
        "the work was still alive after the cancel"
    );
}

#[tokio::test]
async fn cancelling_a_queued_call_means_it_never_runs() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let first = client.request("config.apply", named("1")).await;
    let queued = client.request("config.apply", named("2")).await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    client
        .send(json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": queued}}))
        .await;
    mock.release.notify_one();
    client.response(first).await;
    let answer = client.response(queued).await;

    assert_eq!(answer["error"]["data"]["kind"], "cancelled", "{answer}");
    assert_eq!(mock.seen(), ["start apply 1", "end apply 1"]);
}

#[tokio::test]
async fn cancelling_a_finished_call_is_ignored() {
    let (mut client, _, _) = ready(Mock::default()).await;
    let id = client.request("core.stats", Value::Null).await;
    let done = client.response(id).await;
    assert!(done.get("result").is_some());
    client
        .send(json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": id}}))
        .await;
    client.quiet().await;
    assert!(
        client
            .call("core.stats", Value::Null)
            .await
            .get("result")
            .is_some()
    );
}

#[tokio::test]
async fn a_subscription_answers_with_sub_and_snapshot_then_numbered_batches() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let source = queue(&mock.traffic, StreamPolicy::Latest, 1);

    let opened = client.call("traffic.watch", json!({"maxBatchMs": 0})).await;
    assert_eq!(opened["result"]["snapshot"]["totalUp"], 0, "{opened}");
    let sub = opened["result"]["sub"].as_u64().unwrap();

    source.push(traffic(5));
    let first = client.event().await;
    assert_eq!(first["params"]["sub"], sub);
    assert_eq!(first["params"]["seq"], 1);
    assert_eq!(
        first["params"]["data"][0]["up"], 5,
        "data is always an array: {first}"
    );
    assert!(first["params"].get("dropped").is_none());

    source.push(traffic(6));
    let second = client.event().await;
    assert_eq!(second["params"]["seq"], 2);
    assert_eq!(second["params"]["data"][0]["up"], 6);
}

#[tokio::test]
async fn without_credit_the_stream_is_not_polled_at_all() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let source = queue(&mock.logs, StreamPolicy::DropOldest, 256);
    let opened = client
        .call("log.watch", json!({"credit": 1, "maxBatchMs": 0}))
        .await;
    let sub = opened["result"]["sub"].as_u64().unwrap();

    source.push(entry("one"));
    assert_eq!(client.event().await["params"]["data"][0]["text"], "one");
    settle().await;
    let polls = mock.polls.load(Ordering::SeqCst);
    for index in 0..50 {
        source.push(entry(&format!("later {index}")));
    }
    client.quiet().await;
    assert_eq!(
        mock.polls.load(Ordering::SeqCst),
        polls,
        "the consumer has no credit, so nothing may be pulled or encoded"
    );

    client
        .send(json!({"jsonrpc": "2.0", "method": "$/credit", "params": {"sub": sub, "n": 1}}))
        .await;
    let batch = client.event().await;
    assert_eq!(batch["params"]["seq"], 2);
    assert_eq!(batch["params"]["data"].as_array().unwrap().len(), 50);
}

#[tokio::test(start_paused = true)]
async fn a_batch_collects_events_for_its_window_and_stops_at_its_size() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let source = queue(&mock.logs, StreamPolicy::DropOldest, 256);
    client
        .call("log.watch", json!({"credit": 8, "maxBatchMs": 50}))
        .await;

    source.push(entry("a"));
    tokio::task::yield_now().await;
    source.push(entry("b"));
    source.push(entry("c"));
    let batch = client.event().await;
    assert_eq!(
        batch["params"]["data"].as_array().unwrap().len(),
        3,
        "{batch}"
    );

    let (mut client, mock, _) = ready(Mock::default()).await;
    let source = queue(&mock.logs, StreamPolicy::DropOldest, 256);
    client
        .call(
            "log.watch",
            json!({"credit": 8, "maxBatchMs": 0, "maxBatchBytes": 1}),
        )
        .await;
    for text in ["a", "b", "c"] {
        source.push(entry(text));
    }
    for expected in ["a", "b", "c"] {
        let batch = client.event().await;
        assert_eq!(
            batch["params"]["data"].as_array().unwrap().len(),
            1,
            "{batch}"
        );
        assert_eq!(batch["params"]["data"][0]["text"], expected);
    }
}

#[tokio::test]
async fn an_event_batch_fits_one_message_and_counts_an_event_that_cannot() {
    let (mut client, mock, _) = start_with(Mock::default(), ServerConfig { max_message: 4096 });
    client.hello().await;
    let source = queue(&mock.logs, StreamPolicy::DropOldest, 256);
    client
        .call("log.watch", json!({"credit": 16, "maxBatchMs": 0}))
        .await;
    let medium = "m".repeat(1500);
    for text in [medium.as_str(), &medium, &medium, &"h".repeat(5000), "tail"] {
        source.push(entry(text));
    }

    let (mut seqs, mut texts, mut dropped) = (Vec::new(), Vec::new(), 0);
    while texts.len() < 4 {
        let batch = client.event().await;
        assert!(
            batch.to_string().len() <= 4096,
            "{} bytes",
            batch.to_string().len()
        );
        seqs.push(batch["params"]["seq"].as_u64().unwrap());
        dropped += batch["params"]["dropped"].as_u64().unwrap_or(0);
        for event in batch["params"]["data"].as_array().unwrap() {
            texts.push(event["text"].as_str().unwrap().len());
        }
    }

    assert_eq!(texts, [1500, 1500, 1500, 4]);
    assert_eq!(dropped, 1);
    assert!(
        seqs.windows(2).all(|pair| pair[1] == pair[0] + 1),
        "{seqs:?}"
    );
}

#[tokio::test]
async fn latest_keeps_only_the_newest_value_for_a_slow_consumer() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let source = queue(&mock.traffic, StreamPolicy::Latest, 1);
    let opened = client
        .call("traffic.watch", json!({"credit": 0, "maxBatchMs": 0}))
        .await;
    let sub = opened["result"]["sub"].as_u64().unwrap();
    for up in 1..=100 {
        source.push(traffic(up));
    }
    client
        .send(json!({"jsonrpc": "2.0", "method": "$/credit", "params": {"sub": sub, "n": 5}}))
        .await;

    let only = client.event().await;

    assert_eq!(only["params"]["data"], json!([traffic_json(100)]));
    client.quiet().await;
}

fn traffic_json(up: i64) -> Value {
    json!({"up": up, "down": 0, "totalUp": 0, "totalDown": 0})
}

#[tokio::test]
async fn drop_oldest_reports_how_many_events_a_slow_consumer_lost() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let source = queue(&mock.logs, StreamPolicy::DropOldest, 8);
    let opened = client
        .call("log.watch", json!({"credit": 0, "maxBatchMs": 0}))
        .await;
    let sub = opened["result"]["sub"].as_u64().unwrap();
    for index in 0..20 {
        source.push(entry(&index.to_string()));
    }
    client
        .send(json!({"jsonrpc": "2.0", "method": "$/credit", "params": {"sub": sub, "n": 1}}))
        .await;

    let batch = client.event().await;

    let texts: Vec<&str> = batch["params"]["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["text"].as_str().unwrap())
        .collect();
    assert_eq!(texts, ["12", "13", "14", "15", "16", "17", "18", "19"]);
    assert_eq!(batch["params"]["dropped"], 12, "{batch}");
}

#[tokio::test]
async fn resync_overflow_stops_the_stream_with_a_resync_and_never_drops_silently() {
    let (mut client, mock, serving) = ready(Mock::default()).await;
    let source = queue(&mock.deltas, StreamPolicy::Resync, 4);
    let opened = client
        .call("connection.watch", json!({"credit": 0, "maxBatchMs": 0}))
        .await;
    let sub = opened["result"]["sub"].as_u64().unwrap();
    for id in 0..10 {
        source.push(ConnectionDelta {
            opened: vec![],
            closed: vec![id],
            counters: vec![],
            ended: vec![],
        });
    }
    client
        .send(json!({"jsonrpc": "2.0", "method": "$/credit", "params": {"sub": sub, "n": 4}}))
        .await;

    let resync = client.event().await;

    assert_eq!(resync["params"]["resync"], true, "{resync}");
    assert!(resync["params"].get("data").is_none());
    client.quiet().await;
    source.push(ConnectionDelta {
        opened: vec![],
        closed: vec![99],
        counters: vec![],
        ended: vec![],
    });
    client.quiet().await;
    assert_eq!(
        mock.streams_dropped.load(Ordering::SeqCst),
        1,
        "the stream ended"
    );

    let again = queue(&mock.deltas, StreamPolicy::Resync, 4);
    let fresh = client
        .call("connection.watch", json!({"maxBatchMs": 0}))
        .await;
    assert!(fresh["result"]["snapshot"].is_object(), "{fresh}");
    again.push(ConnectionDelta {
        opened: vec![],
        closed: vec![1],
        counters: vec![],
        ended: vec![],
    });
    assert_eq!(client.event().await["params"]["data"][0]["closed"][0], 1);
    drop(client);
    let _ = timeout(Duration::from_secs(5), serving).await;
}

#[tokio::test]
async fn cancelling_a_subscription_ends_it_and_drops_its_stream() {
    let (mut client, mock, _) = ready(Mock::default()).await;
    let source = queue(&mock.logs, StreamPolicy::DropOldest, 8);
    let id = client.request("log.watch", json!({"maxBatchMs": 0})).await;
    let opened = client.response(id).await;
    assert!(opened["result"]["sub"].is_u64());
    source.push(entry("seen"));
    client.event().await;

    client
        .send(json!({"jsonrpc": "2.0", "method": "$/cancel", "params": {"id": id}}))
        .await;
    settle().await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(mock.streams_dropped.load(Ordering::SeqCst), 1);
    source.push(entry("unseen"));
    client.quiet().await;
}

#[tokio::test]
async fn a_disconnect_stops_every_request_and_subscription_of_the_connection() {
    let (mut client, mock, serving) = ready(Mock::default()).await;
    queue(&mock.traffic, StreamPolicy::Latest, 1);
    queue(&mock.logs, StreamPolicy::DropOldest, 8);
    client.call("traffic.watch", json!({})).await;
    client.call("log.watch", json!({})).await;
    client.request("delay.test", json!({"proxy": "hang"})).await;
    client.request("config.apply", named("1")).await;
    client.request("config.apply", named("2")).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mock.streams_dropped.load(Ordering::SeqCst), 0);

    drop(client);
    timeout(Duration::from_secs(5), serving)
        .await
        .expect("serve outlived the connection")
        .unwrap();

    assert_eq!(mock.streams_dropped.load(Ordering::SeqCst), 2);
    assert!(mock.hung_dropped.load(Ordering::SeqCst));
    assert_eq!(
        mock.seen()
            .iter()
            .filter(|line| line.starts_with("start apply"))
            .count(),
        1
    );
}

#[tokio::test]
async fn a_result_above_the_message_limit_is_a_typed_error_not_a_dropped_message() {
    let (mut client, _, _) = start_with(Mock::default(), ServerConfig { max_message: 4096 });
    client.hello().await;

    let answer = client.call("core.lastWarnings", Value::Null).await;

    assert_eq!(
        answer["error"]["data"]["kind"], "payload_too_large",
        "{answer}"
    );
    assert_eq!(answer["error"]["data"]["limit"], 4096);
    assert_eq!(answer["error"]["code"], -32017);
    assert!(
        client
            .call("core.stats", Value::Null)
            .await
            .get("result")
            .is_some()
    );
}

#[tokio::test]
async fn an_oversized_incoming_message_is_answered_and_the_connection_goes_on() {
    let (mut client, _, _) = ready(Mock::default()).await;
    assert!(client.channel.send_oversized(70_000_000).await);

    let answer = client.next_message().await.unwrap();

    assert_eq!(answer["id"], Value::Null);
    assert_eq!(
        answer["error"]["data"]["kind"], "payload_too_large",
        "{answer}"
    );
    assert!(
        client
            .call("core.stats", Value::Null)
            .await
            .get("result")
            .is_some()
    );
}

struct Scripted {
    incoming: mpsc::Receiver<Vec<u8>>,
    sent: Arc<AtomicUsize>,
    fail_after: usize,
}

struct ScriptedReader(mpsc::Receiver<Vec<u8>>);
struct ScriptedWriter {
    sent: Arc<AtomicUsize>,
    fail_after: usize,
}

impl MessageReader for ScriptedReader {
    async fn recv(&mut self) -> std::io::Result<Option<concord_rpc::Incoming>> {
        Ok(self.0.recv().await.map(concord_rpc::Incoming::Message))
    }
}

impl MessageWriter for ScriptedWriter {
    async fn send(&mut self, _message: Vec<u8>) -> Result<(), SendError> {
        if self.sent.fetch_add(1, Ordering::SeqCst) >= self.fail_after {
            return Err(SendError::Broken(std::io::ErrorKind::BrokenPipe.into()));
        }
        Ok(())
    }
}

impl MessageChannel for Scripted {
    type Reader = ScriptedReader;
    type Writer = ScriptedWriter;

    fn split(self) -> (ScriptedReader, ScriptedWriter) {
        (
            ScriptedReader(self.incoming),
            ScriptedWriter {
                sent: self.sent,
                fail_after: self.fail_after,
            },
        )
    }
}

struct CountEvents(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CountEvents {
    fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn a_broken_write_ends_the_connection_and_is_not_reported_through_the_log_system() {
    use tracing_subscriber::layer::SubscriberExt;
    let events = Arc::new(AtomicUsize::new(0));
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(CountEvents(events.clone())),
    );
    let (feed, incoming) = mpsc::channel(8);
    let channel = Scripted {
        incoming,
        sent: Arc::new(AtomicUsize::new(0)),
        fail_after: 0,
    };
    let server = Server::new(Arc::new(Mock::default()));
    feed.send(
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "core.hello", "params": {"protocol": {"min": 1, "max": 1}, "client": {"name": "t", "version": "0"}}}))
            .unwrap(),
    )
    .await
    .unwrap();

    timeout(Duration::from_secs(5), server.serve(channel))
        .await
        .expect("a broken write must end the connection");

    assert_eq!(events.load(Ordering::SeqCst), 0);
}
