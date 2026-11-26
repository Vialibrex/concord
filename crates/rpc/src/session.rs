use std::collections::HashMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_api::ControlService;
use concord_common::sync::lock;
use concord_proto::types::{HelloParams, HelloResult, Limits};
use concord_proto::{
    ApiError, Cap, DEFAULT_BATCH_MS, DEFAULT_CREDIT, Kind, MAX_BATCH_BYTES, METHODS,
    PROTOCOL_VERSION,
};
use futures_util::FutureExt;
use serde_json::Value;
use serde_json::value::RawValue;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::dispatch::{Call, Reply, StreamReply, decode, invoke};
use crate::envelope::{Envelope, error_response, id_key, response};
use crate::pump::Pump;

type SerialJob = Pin<Box<dyn Future<Output = ()> + Send>>;

pub struct Request {
    pub id: String,
    pub token: CancellationToken,
}

#[derive(Clone, Copy)]
struct Hello {
    debug: bool,
}

pub struct Session<S: ControlService> {
    service: Arc<S>,
    max_message: u64,
    outbox: mpsc::Sender<Vec<u8>>,
    inflight: Mutex<HashMap<String, CancellationToken>>,
    subs: Mutex<HashMap<u64, Arc<Semaphore>>>,
    next_sub: AtomicU64,
    hello: Mutex<Option<Hello>>,
    serial: mpsc::UnboundedSender<SerialJob>,
    pub root: CancellationToken,
    closing: AtomicBool,
}

fn panic_error(panic: Box<dyn std::any::Any + Send>) -> ApiError {
    let reason = panic
        .downcast_ref::<&str>()
        .map(|text| (*text).to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown".to_string());
    ApiError::internal(format!("internal panic: {reason}"))
}

impl<S: ControlService> Session<S> {
    pub fn new(
        service: Arc<S>,
        max_message: u64,
        outbox: mpsc::Sender<Vec<u8>>,
        serial: mpsc::UnboundedSender<SerialJob>,
    ) -> Arc<Self> {
        Arc::new(Session {
            service,
            max_message,
            outbox,
            inflight: Mutex::new(HashMap::new()),
            subs: Mutex::new(HashMap::new()),
            next_sub: AtomicU64::new(0),
            hello: Mutex::new(None),
            serial,
            root: CancellationToken::new(),
            closing: AtomicBool::new(false),
        })
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.root.cancel();
    }

    async fn send(&self, message: Vec<u8>) {
        let message = if message.len() as u64 > self.max_message {
            error_response(None, &ApiError::payload_too_large(self.max_message))
        } else {
            message
        };
        let _ = self.outbox.send(message).await;
    }

    pub async fn reject_oversized(&self, len: u64) {
        let error = ApiError::payload_too_large(self.max_message);
        let mut error = error;
        error.message = format!(
            "a message of {len} bytes is larger than {}",
            self.max_message
        );
        self.send(error_response(None, &error)).await;
    }

    pub async fn reject_unparsable(&self, reason: &str) {
        let error = ApiError::new(
            concord_proto::ErrorData::InvalidParams { path: None },
            format!("parse error: {reason}"),
        );
        self.send(raw_error(concord_proto::PARSE_ERROR, None, &error))
            .await;
    }

    fn hello_state(&self) -> Option<Hello> {
        *lock(&self.hello)
    }

    /// Reads one message. A request is run, queued or started according to its
    /// `Exec`; the notifications `$/cancel` and `$/credit` act at once.
    pub fn handle(
        self: &Arc<Self>,
        bytes: &[u8],
        tasks: &mut tokio::task::JoinSet<()>,
    ) -> Result<(), String> {
        while tasks.try_join_next().is_some() {}
        let envelope: Envelope = match serde_json::from_slice(bytes) {
            Ok(envelope) => envelope,
            Err(err) => return Err(err.to_string()),
        };
        let Some(name) = envelope.method.as_deref() else {
            let session = self.clone();
            let id = envelope.id.as_deref().map(id_key);
            tasks.spawn(async move {
                let error = ApiError::new(
                    concord_proto::ErrorData::InvalidParams { path: None },
                    "a request needs a method",
                );
                session
                    .send(raw_error(
                        concord_proto::INVALID_REQUEST,
                        id.as_deref(),
                        &error,
                    ))
                    .await;
            });
            return Ok(());
        };
        match name {
            "$/cancel" => {
                self.cancel(envelope.params.as_deref());
                return Ok(());
            }
            "$/credit" => {
                self.credit(envelope.params.as_deref());
                return Ok(());
            }
            _ => {}
        }
        let Some(id) = envelope.id.as_deref().map(id_key) else {
            tracing::debug!("ignored the notification {name}");
            return Ok(());
        };
        let session = self.clone();
        let gate = self.admit(name);
        let spec = METHODS.iter().find(|spec| spec.name == name);
        let (spec, spec_error) = match (spec, gate) {
            (Some(spec), Ok(())) => (Some(spec), None),
            (_, Err(error)) => (None, Some(error)),
            (None, Ok(())) => (None, Some(ApiError::unsupported_method(name))),
        };
        let Some(spec) = spec else {
            let error = spec_error.unwrap_or_else(|| ApiError::unsupported_method(name));
            tasks.spawn(async move {
                session.send(error_response(Some(&id), &error)).await;
            });
            return Ok(());
        };

        let token = self.root.child_token();
        {
            let mut inflight = lock(&self.inflight);
            inflight.insert(id.clone(), token.clone());
        }
        let request = Request { id, token };

        if spec.kind == Kind::Rpc {
            let outcome = self.hello(envelope.params.as_deref());
            tasks.spawn(async move { session.settle(request, outcome).await });
            return Ok(());
        }
        let Some(call) = invoke(self.service.clone(), name, envelope.params) else {
            let error = ApiError::unsupported_method(name);
            tasks.spawn(async move { session.settle(request, Err(error)).await });
            return Ok(());
        };
        match spec.exec {
            concord_proto::Exec::Inline => {
                let mut call = call;
                match (&mut call).now_or_never() {
                    Some(outcome) => {
                        tasks.spawn(async move { session.settle(request, outcome).await });
                    }
                    None => {
                        tasks.spawn(async move {
                            let outcome = session.execute(&request, call).await;
                            session.settle(request, outcome).await;
                        });
                    }
                }
            }
            concord_proto::Exec::Serial => {
                let job: SerialJob = Box::pin(async move {
                    let outcome = session.execute(&request, call).await;
                    session.settle(request, outcome).await;
                });
                let _ = self.serial.send(job);
            }
            concord_proto::Exec::Concurrent => {
                tasks.spawn(async move {
                    let outcome = session.execute(&request, call).await;
                    session.settle(request, outcome).await;
                });
            }
        }
        Ok(())
    }

    fn admit(&self, name: &str) -> Result<(), ApiError> {
        let hello = self.hello_state();
        if name == "core.hello" {
            return Ok(());
        }
        let Some(hello) = hello else {
            return Err(ApiError::conflict(
                "hello_required",
                "core.hello must be the first call on a connection",
            ));
        };
        let Some(spec) = METHODS.iter().find(|spec| spec.name == name) else {
            return Ok(());
        };
        match spec.capability {
            Cap::None => Ok(()),
            Cap::Mitm if self.service.info().features.mitm => Ok(()),
            Cap::Mitm => Err(ApiError::unsupported_capability(
                "mitm",
                "this core has no MITM",
            )),
            Cap::Debug if hello.debug && self.service.info().debug => Ok(()),
            Cap::Debug => Err(ApiError::unsupported_method(name)),
        }
    }

    fn hello(&self, raw: Option<&RawValue>) -> Result<Reply, ApiError> {
        let params: HelloParams = decode(raw)?;
        if params.protocol.min > PROTOCOL_VERSION || params.protocol.max < PROTOCOL_VERSION {
            return Err(ApiError::unsupported_capability(
                "protocol",
                format!(
                    "this core speaks protocol {PROTOCOL_VERSION}, the client {}..{}",
                    params.protocol.min, params.protocol.max
                ),
            ));
        }
        let info = self.service.info();
        let debug = params.capabilities.iter().any(|name| name == "debug") && info.debug;
        {
            let mut hello = lock(&self.hello);
            *hello = Some(Hello { debug });
        }
        let methods = METHODS
            .iter()
            .filter(|spec| match spec.capability {
                Cap::None => true,
                Cap::Mitm => info.features.mitm,
                Cap::Debug => debug,
            })
            .map(|spec| spec.name.to_string())
            .collect();
        let result = HelloResult {
            protocol: PROTOCOL_VERSION,
            server: info.server,
            platform: info.platform,
            limits: Limits {
                max_message: self.max_message,
                max_batch_bytes: MAX_BATCH_BYTES,
            },
            methods,
            features: info.features,
            engine: info.engine,
        };
        let body = serde_json::to_vec(&result)
            .map_err(|err| ApiError::internal(format!("encode result: {err}")))?;
        Ok(Reply::Unary(body))
    }

    fn cancel(&self, raw: Option<&RawValue>) {
        let id = raw
            .and_then(|raw| serde_json::from_str::<Value>(raw.get()).ok())
            .and_then(|params| params.get("id").map(Value::to_string));
        if let Some(id) = id
            && let Some(token) = lock(&self.inflight).get(&id)
        {
            token.cancel();
        }
    }

    fn credit(&self, raw: Option<&RawValue>) {
        let params = raw.and_then(|raw| serde_json::from_str::<Value>(raw.get()).ok());
        let field = |key: &str| params.as_ref()?.get(key)?.as_u64();
        let (Some(sub), Some(count)) = (field("sub"), field("n")) else {
            return;
        };
        let subs = lock(&self.subs);
        if let Some(credit) = subs.get(&sub) {
            let room = Semaphore::MAX_PERMITS.saturating_sub(credit.available_permits());
            credit.add_permits(
                usize::try_from(count)
                    .unwrap_or(Semaphore::MAX_PERMITS)
                    .min(room),
            );
        }
    }

    /// Runs the call unless it was cancelled while queued.
    async fn execute(&self, request: &Request, call: Call) -> Result<Reply, ApiError> {
        if request.token.is_cancelled() {
            return Err(ApiError::cancelled());
        }
        tokio::select! {
            biased;
            () = request.token.cancelled() => Err(ApiError::cancelled()),
            outcome = AssertUnwindSafe(call).catch_unwind() => {
                outcome.unwrap_or_else(|panic| Err(panic_error(panic)))
            }
        }
    }

    fn forget(&self, id: &str) {
        {
            let mut inflight = lock(&self.inflight);
            inflight.remove(id);
        }
    }

    pub async fn settle(self: Arc<Self>, request: Request, outcome: Result<Reply, ApiError>) {
        match outcome {
            Err(error) => {
                self.forget(&request.id);
                self.send(error_response(Some(&request.id), &error)).await;
            }
            Ok(Reply::Unary(body)) => {
                self.forget(&request.id);
                if body.len() as u64 > self.max_message {
                    let error = ApiError::payload_too_large(self.max_message);
                    self.send(error_response(Some(&request.id), &error)).await;
                } else {
                    self.send(response(&request.id, &body)).await;
                }
            }
            Ok(Reply::Stream(reply)) => self.stream(request, reply).await,
        }
    }

    async fn stream(self: Arc<Self>, request: Request, reply: StreamReply) {
        let StreamReply {
            options,
            snapshot,
            events,
        } = reply;
        let sub = self.next_sub.fetch_add(1, Ordering::SeqCst) + 1;
        let credit = Arc::new(Semaphore::new(
            usize::try_from(options.credit.unwrap_or(DEFAULT_CREDIT))
                .unwrap_or(Semaphore::MAX_PERMITS)
                .min(Semaphore::MAX_PERMITS),
        ));
        {
            let mut subs = lock(&self.subs);
            subs.insert(sub, credit.clone());
        }
        let mut body = format!("{{\"sub\":{sub}").into_bytes();
        if let Some(snapshot) = snapshot {
            body.extend_from_slice(b",\"snapshot\":");
            body.extend_from_slice(&snapshot);
        }
        body.push(b'}');
        if body.len() as u64 > self.max_message {
            self.finish_stream(&request.id, sub);
            let error = ApiError::payload_too_large(self.max_message);
            self.send(error_response(Some(&request.id), &error)).await;
            return;
        }
        self.send(response(&request.id, &body)).await;
        let pump = Pump {
            sub,
            events,
            credit,
            batch_window: Duration::from_millis(u64::from(
                options.max_batch_ms.unwrap_or(DEFAULT_BATCH_MS),
            )),
            batch_bytes: options
                .max_batch_bytes
                .map_or(MAX_BATCH_BYTES, |bytes| bytes.clamp(1, MAX_BATCH_BYTES))
                as usize,
            max_message: usize::try_from(self.max_message).unwrap_or(usize::MAX),
            token: request.token.clone(),
            outbox: self.outbox.clone(),
        };
        pump.run().await;
        self.finish_stream(&request.id, sub);
    }

    fn finish_stream(&self, id: &str, sub: u64) {
        self.forget(id);
        {
            let mut subs = lock(&self.subs);
            subs.remove(&sub);
        }
    }
}

fn raw_error(code: i32, id: Option<&str>, error: &ApiError) -> Vec<u8> {
    let mut object = error.to_object();
    object.code = code;
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(br#"{"jsonrpc":"2.0","id":"#);
    out.extend_from_slice(id.unwrap_or("null").as_bytes());
    out.extend_from_slice(br#","error":"#);
    out.extend_from_slice(&serde_json::to_vec(&object).unwrap_or_default());
    out.push(b'}');
    out
}

#[cfg(test)]
mod tests {
    use concord_api::ServiceInfo;
    use concord_proto::types::{EngineState, EngineStatus, Features, PlatformInfo, ServerInfo};
    use tokio::task::JoinSet;

    use super::*;

    struct Bare;

    impl ControlService for Bare {
        fn info(&self) -> ServiceInfo {
            ServiceInfo {
                server: ServerInfo {
                    implementation: "bare".into(),
                    version: "0".into(),
                    build: "test".into(),
                },
                platform: PlatformInfo {
                    os: "test".into(),
                    privileged: false,
                    capabilities: vec![],
                },
                features: Features {
                    mitm: false,
                    ech: false,
                    system_stack: false,
                },
                engine: EngineStatus {
                    state: EngineState::Created,
                    kind: None,
                    faults: Vec::new(),
                },
                debug: false,
            }
        }
    }

    #[tokio::test]
    async fn finished_request_tasks_are_reaped_while_the_connection_lives() {
        let (outbox, mut sink) = mpsc::channel(8);
        let (serial, _jobs) = mpsc::unbounded_channel();
        let session = Session::new(Arc::new(Bare), 1 << 20, outbox, serial);
        let mut tasks = JoinSet::new();
        for id in 0..200 {
            let message = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"core.stats"}}"#);
            session.handle(message.as_bytes(), &mut tasks).unwrap();
            sink.recv().await.expect("the refusal is sent");
            tokio::task::yield_now().await;
        }
        assert!(tasks.len() <= 2, "{} tasks kept", tasks.len());
    }
}
