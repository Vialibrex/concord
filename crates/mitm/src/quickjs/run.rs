use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Read;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use concord_common::ScriptNotification;
use concord_config::mitm::text::canonical_header;
use concord_tls::TrustStore;
use rand::Rng;

use super::bytecode::Thrown;
use rquickjs::{
    CatchResultExt, CaughtError, Context, Ctx, Exception, Function, Object, Runtime, Value,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use url::Url;

use super::fetch::{Client, Fetch, Fetched};
use super::store::Store;
use crate::script::{
    ConsoleSink, HeaderList, NotifySink, ScriptError, ScriptInvocation, ScriptResponse,
    ScriptResult,
};

pub(super) const POLYFILL: &str = include_str!("polyfill.js");
pub(super) const PRELUDE: &str = include_str!("prelude.js");
pub(super) const QUANTUMULT: &str = include_str!("quantumult.js");
const DEFAULT_REQUEST_TIMEOUT_MS: f64 = 5000.0;
const NO_DONE: &str = "the script ended without calling $done";
const CANCELLED: &str = "the script was cancelled";

enum Msg {
    Http { id: u32, json: String },
    Stop,
}

struct HttpJob {
    id: u32,
    json: String,
}

struct Cancel {
    flag: Arc<AtomicBool>,
    wake: mpsc::Sender<Msg>,
}

impl Drop for Cancel {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::Relaxed);
        let _ = self.wake.send(Msg::Stop);
    }
}

struct Setup {
    program: Arc<Compiled>,
    input: String,
    store: Arc<Store>,
    name: String,
    console: Option<ConsoleSink>,
    notify: Option<NotifySink>,
    memory_limit: u64,
    max_body: i64,
    jobs: UnboundedSender<HttpJob>,
    inbox: mpsc::Receiver<Msg>,
    cancel: Arc<AtomicBool>,
}

pub(super) fn describe_exception(exception: &Exception<'_>) -> String {
    let message = exception.message().unwrap_or_default();
    let name = exception
        .as_object()
        .get::<_, Option<String>>("name")
        .ok()
        .flatten();
    let text = match name {
        Some(name) if !name.is_empty() => format!("{name}: {message}"),
        _ => message,
    };
    text.lines().next().unwrap_or_default().to_string()
}

pub(super) fn describe(err: &CaughtError<'_>) -> String {
    match err {
        CaughtError::Exception(exception) => describe_exception(exception),
        CaughtError::Value(value) => format!("{value:?}"),
        CaughtError::Error(err) => err.to_string(),
    }
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        "android" => "Android",
        "ios" => "iOS",
        _ => "",
    }
}

#[derive(Serialize)]
enum BodyPayload<'a> {
    #[serde(rename = "b")]
    Binary(String),
    #[serde(rename = "s")]
    Text(Cow<'a, str>),
}

impl<'a> BodyPayload<'a> {
    fn of(data: &'a [u8], binary: bool) -> Self {
        if binary {
            BodyPayload::Binary(STANDARD.encode(data))
        } else {
            BodyPayload::Text(String::from_utf8_lossy(data))
        }
    }
}

#[derive(Serialize)]
struct RequestPayload<'a> {
    id: &'a str,
    url: &'a str,
    method: &'a str,
    headers: &'a HeaderList,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<BodyPayload<'a>>,
}

#[derive(Serialize)]
struct ResponsePayload<'a> {
    status: u16,
    headers: &'a HeaderList,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<BodyPayload<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trailers: Option<&'a HeaderList>,
}

#[derive(Serialize)]
struct InputPayload<'a> {
    name: &'a str,
    kind: &'a str,
    binary: bool,
    full: bool,
    system: &'static str,
    started: f64,
    session: String,
    cronexp: &'a str,
    trigger: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argument: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<RequestPayload<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response: Option<ResponsePayload<'a>>,
}

pub(super) fn build_input(invocation: &ScriptInvocation) -> String {
    let mut session = [0u8; 4];
    rand::rng().fill_bytes(&mut session);
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64());
    let request = invocation.request.as_ref().map(|request| {
        let (scheme, path) = match Url::parse(&request.url) {
            Ok(target) => {
                let mut path = target.path().to_string();
                if let Some(query) = target.query() {
                    path.push('?');
                    path.push_str(query);
                }
                (Some(target.scheme().to_string()), Some(path))
            }
            Err(_) => (None, None),
        };
        RequestPayload {
            id: &request.id,
            url: &request.url,
            method: &request.method,
            headers: &request.header,
            scheme,
            path,
            body: request
                .body
                .as_deref()
                .map(|data| BodyPayload::of(data, invocation.binary_body)),
        }
    });
    let response = invocation
        .response
        .as_ref()
        .map(|response| ResponsePayload {
            status: response.status,
            headers: &response.header,
            body: response
                .body
                .as_deref()
                .map(|data| BodyPayload::of(data, invocation.binary_body)),
            trailers: response.trailers.as_ref(),
        });
    let payload = InputPayload {
        name: &invocation.name,
        kind: &invocation.kind,
        binary: invocation.binary_body,
        full: invocation.full_header,
        system: os_name(),
        started,
        session: hex::encode(session),
        cronexp: &invocation.cronexp,
        trigger: &invocation.trigger,
        event: invocation.event.as_ref().map(|e| e.name.as_str()),
        argument: invocation.argument.as_ref(),
        rule: invocation.rule.as_ref(),
        domain: invocation.domain.as_deref(),
        request,
        response,
    };
    serde_json::to_string(&payload).unwrap_or_default()
}

/// A script's source and, once a run has compiled it, its bytecode.
pub(super) struct Compiled {
    source: String,
    pub(super) quantumult: bool,
    bytecode: OnceLock<Result<Vec<u8>, Thrown>>,
}

impl Compiled {
    pub(super) fn new(quantumult: bool, source: String) -> Compiled {
        Compiled {
            source,
            quantumult,
            bytecode: OnceLock::new(),
        }
    }

    fn bytecode(&self) -> &Result<Vec<u8>, Thrown> {
        self.bytecode
            .get_or_init(|| super::bytecode::compile(&self.source))
    }
}

pub(super) async fn execute(
    program: Arc<Compiled>,
    store: Arc<Store>,
    trust: Arc<TrustStore>,
    invocation: ScriptInvocation,
) -> Result<ScriptResult, ScriptError> {
    let (jobs, mut requests): (UnboundedSender<HttpJob>, UnboundedReceiver<HttpJob>) =
        unbounded_channel();
    let (wake, inbox) = mpsc::channel();
    let (finished, mut outcome) = tokio::sync::oneshot::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = Cancel {
        flag: cancel.clone(),
        wake: wake.clone(),
    };
    let setup = Setup {
        program,
        input: build_input(&invocation),
        store,
        name: invocation.name.clone(),
        console: invocation.console.clone(),
        notify: invocation.notify.clone(),
        memory_limit: invocation.memory_limit,
        max_body: invocation.max_body_size,
        jobs,
        inbox,
        cancel,
    };
    std::thread::Builder::new()
        .name("mitm-script".to_string())
        .spawn(move || {
            let _ = finished.send(run_thread(setup));
        })
        .map_err(|err| ScriptError(err.to_string()))?;
    let run = invocation.dial.tasks();
    let ended = run.child_token();
    let fetches = run.with_stop(ended.clone());
    let _ended = ended.drop_guard();
    let client = Arc::new(Client {
        dial: invocation.dial.clone(),
        trust,
        max_body: invocation.max_body_size,
        tasks: fetches.clone(),
    });
    loop {
        tokio::select! {
            result = &mut outcome => {
                return result.unwrap_or_else(|_| Err(ScriptError(CANCELLED.to_string())));
            }
            Some(job) = requests.recv() => {
                let (client, wake) = (client.clone(), wake.clone());
                fetches.spawn(async move {
                    let json = answer(&client, &job.json).await;
                    let _ = wake.send(Msg::Http { id: job.id, json });
                });
            }
        }
    }
}

#[derive(Deserialize)]
struct RequestJson {
    method: String,
    url: String,
    headers: Vec<(String, Vec<String>)>,
    body: Option<BodyJson>,
    timeout: f64,
    redirect: bool,
    insecure: bool,
}

#[derive(Deserialize, Default)]
struct BodyJson {
    s: Option<String>,
    b: Option<String>,
}

impl BodyJson {
    fn bytes(&self) -> Option<Vec<u8>> {
        match (&self.b, &self.s) {
            (Some(encoded), _) => STANDARD.decode(encoded).ok(),
            (None, Some(text)) => Some(text.clone().into_bytes()),
            (None, None) => None,
        }
    }
}

async fn answer(client: &Client, json: &str) -> String {
    let failed = |message: String| json!({ "error": message }).to_string();
    let request: RequestJson = match serde_json::from_str(json) {
        Ok(request) => request,
        Err(err) => return failed(err.to_string()),
    };
    let timeout = if request.timeout.is_finite() && request.timeout > 0.0 {
        request.timeout
    } else {
        DEFAULT_REQUEST_TIMEOUT_MS
    };
    let fetch = Fetch {
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: request.body.as_ref().and_then(BodyJson::bytes),
        timeout: Duration::try_from_secs_f64(timeout / 1000.0)
            .unwrap_or_else(|_| Duration::from_secs_f64(DEFAULT_REQUEST_TIMEOUT_MS / 1000.0)),
        redirect: request.redirect,
        insecure: request.insecure,
    };
    match client.fetch(fetch).await {
        Ok(Fetched {
            status,
            headers,
            body,
        }) => json!({
            "status": status,
            "headers": headers,
            "body": { "b": STANDARD.encode(&body), "s": String::from_utf8_lossy(&body) },
        })
        .to_string(),
        Err(message) => failed(message),
    }
}

struct State {
    timers: RefCell<HashMap<u32, Instant>>,
    http: Cell<usize>,
    done: RefCell<Option<String>>,
}

fn install(
    ctx: &Ctx<'_>,
    state: &Rc<State>,
    setup: &Rc<Setup>,
    input: String,
) -> rquickjs::Result<()> {
    let native = Object::new(ctx.clone())?;
    let input = RefCell::new(Some(input));
    native.set(
        "input",
        Function::new(ctx.clone(), move || {
            input.borrow_mut().take().unwrap_or_default()
        })?,
    )?;
    let done = state.clone();
    native.set(
        "done",
        Function::new(ctx.clone(), move |json: String| {
            done.done.borrow_mut().get_or_insert(json);
        })?,
    )?;
    let timers = state.clone();
    native.set(
        "timer",
        Function::new(ctx.clone(), move |id: u32, ms: f64| {
            let delay = if ms.is_finite() && ms > 0.0 {
                Duration::try_from_secs_f64(ms / 1000.0).unwrap_or(Duration::MAX)
            } else {
                Duration::ZERO
            };
            if let Some(due) = Instant::now().checked_add(delay) {
                timers.timers.borrow_mut().insert(id, due);
            }
        })?,
    )?;
    let timers = state.clone();
    native.set(
        "cancel",
        Function::new(ctx.clone(), move |id: u32| {
            timers.timers.borrow_mut().remove(&id);
        })?,
    )?;
    let log = setup.clone();
    native.set(
        "log",
        Function::new(ctx.clone(), move |level: String, line: String| {
            match level.as_str() {
                "debug" => tracing::debug!("[MITM] {}: {line}", log.name),
                "warn" => tracing::warn!("[MITM] {}: {line}", log.name),
                "error" => tracing::error!("[MITM] {}: {line}", log.name),
                _ => tracing::info!("[MITM] {}: {line}", log.name),
            }
            if let Some(console) = &log.console {
                console(&line);
            }
        })?,
    )?;
    let notify = setup.clone();
    native.set(
        "notify",
        Function::new(
            ctx.clone(),
            move |title: String, subtitle: String, body: String, url: String| {
                emit_notification(&notify, title, subtitle, body, url);
            },
        )?,
    )?;
    let store = setup.store.clone();
    native.set(
        "read",
        Function::new(ctx.clone(), move |key: String| store.read(&key))?,
    )?;
    let store = setup.store.clone();
    native.set(
        "write",
        Function::new(ctx.clone(), move |key: String, value: String| {
            store.write(&key, &value)
        })?,
    )?;
    let store = setup.store.clone();
    native.set(
        "remove",
        Function::new(ctx.clone(), move |key: String| store.remove(&key))?,
    )?;
    let limit = setup.max_body;
    native.set(
        "ungzip",
        Function::new(ctx.clone(), move |encoded: String| ungzip(&encoded, limit))?,
    )?;
    let http = state.clone();
    let jobs = setup.jobs.clone();
    native.set(
        "http",
        Function::new(ctx.clone(), move |id: u32, json: String| {
            http.http.set(http.http.get() + 1);
            let _ = jobs.send(HttpJob { id, json });
        })?,
    )?;
    ctx.globals().set("__native", native)
}

fn emit_notification(setup: &Setup, title: String, subtitle: String, body: String, url: String) {
    tracing::info!(
        "[MITM] {} notifies {title:?} {subtitle:?} {body:?}",
        setup.name
    );
    if let Some(console) = &setup.console {
        let parts: Vec<&str> = [title.as_str(), subtitle.as_str(), body.as_str()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect();
        console(&parts.join("\n"));
    }
    if let Some(sink) = &setup.notify {
        sink(ScriptNotification {
            script: setup.name.clone(),
            title,
            subtitle,
            body,
            url,
            at: std::time::SystemTime::now(),
            connection: None,
            exchange: None,
        });
    }
}

fn ungzip(encoded: &str, limit: i64) -> Option<String> {
    let data = STANDARD.decode(encoded).ok()?;
    let cap = u64::try_from(limit).ok()?;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(data.as_slice())
        .take(cap + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() as u64 <= cap).then(|| STANDARD.encode(out))
}

fn call(ctx: &Ctx<'_>, name: &str, id: u32, json: Option<&str>) -> Result<(), String> {
    let function: Function<'_> = ctx.globals().get(name).map_err(|err| err.to_string())?;
    let result = match json {
        Some(json) => function.call::<_, Value<'_>>((id, json)),
        None => function.call::<_, Value<'_>>((id,)),
    };
    result.catch(ctx).map(|_| ()).map_err(|err| describe(&err))
}

fn run_thread(mut setup: Setup) -> Result<ScriptResult, ScriptError> {
    let fail = |message: String| ScriptError(message);
    let runtime = Runtime::new().map_err(|err| fail(err.to_string()))?;
    if let Ok(limit) = usize::try_from(setup.memory_limit)
        && limit > 0
    {
        runtime.set_memory_limit(limit);
    }
    let flag = setup.cancel.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || flag.load(Ordering::Relaxed))));
    let context = Context::full(&runtime).map_err(|err| fail(err.to_string()))?;
    let state = Rc::new(State {
        timers: RefCell::default(),
        http: Cell::new(0),
        done: RefCell::new(None),
    });
    let input = std::mem::take(&mut setup.input);
    let setup = Rc::new(setup);

    let started = context.with(|ctx| -> Result<(), String> {
        install(&ctx, &state, &setup, input).map_err(|err| err.to_string())?;
        super::bytecode::run(&ctx, super::bytecode::prelude(setup.program.quantumult))?;
        let program = setup.program.bytecode().as_ref().map_err(Clone::clone)?;
        match super::bytecode::run(&ctx, program) {
            Err(thrown) if state.done.borrow().is_none() => Err(thrown.into()),
            _ => Ok(()),
        }
    });
    started.map_err(fail)?;

    loop {
        loop {
            match runtime.execute_pending_job() {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) if state.done.borrow().is_some() => break,
                Err(job) => {
                    let message = job.0.with(|ctx| {
                        let value = ctx.catch();
                        value
                            .as_exception()
                            .map_or_else(|| "a job failed".to_string(), describe_exception)
                    });
                    return Err(fail(message));
                }
            }
        }
        if setup.cancel.load(Ordering::Relaxed) {
            return Err(fail(CANCELLED.to_string()));
        }
        if let Some(json) = state.done.borrow_mut().take() {
            return parse_result(&json).map_err(fail);
        }
        let next = state.timers.borrow().values().min().copied();
        if next.is_none() && state.http.get() == 0 {
            return Err(fail(NO_DONE.to_string()));
        }
        let message = match next {
            Some(at) => setup
                .inbox
                .recv_timeout(at.saturating_duration_since(Instant::now())),
            None => setup
                .inbox
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected),
        };
        let step = match message {
            Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => {
                return Err(fail(CANCELLED.to_string()));
            }
            Ok(Msg::Http { id, json }) => {
                state.http.set(state.http.get().saturating_sub(1));
                context.with(|ctx| call(&ctx, "__httpDone", id, Some(&json)))
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                let due = state
                    .timers
                    .borrow()
                    .iter()
                    .filter(|(_, at)| **at <= now)
                    .min_by_key(|(id, at)| (**at, **id))
                    .map(|(id, _)| *id);
                match due {
                    Some(id) => {
                        state.timers.borrow_mut().remove(&id);
                        context.with(|ctx| call(&ctx, "__fire", id, None))
                    }
                    None => Ok(()),
                }
            }
        };
        if let Err(message) = step
            && state.done.borrow().is_none()
        {
            return Err(fail(message));
        }
    }
}

#[derive(Deserialize, Default)]
struct DoneJson {
    url: Option<String>,
    status: Option<i64>,
    header: Option<Vec<(String, Vec<String>)>>,
    body: Option<BodyJson>,
    trailers: Option<Vec<(String, Vec<String>)>>,
    response: Option<ResponseJson>,
    abort: Option<bool>,
    value: Option<String>,
}

#[derive(Deserialize)]
struct ResponseJson {
    status: Option<i64>,
    header: Option<Vec<(String, Vec<String>)>>,
    body: Option<BodyJson>,
}

fn to_list(header: Vec<(String, Vec<String>)>) -> HeaderList {
    let mut list = HeaderList::new();
    for (name, values) in header {
        list.entry(canonical_header(&name))
            .or_default()
            .extend(values);
    }
    list
}

fn parse_result(json: &str) -> Result<ScriptResult, String> {
    let done: DoneJson = serde_json::from_str(json)
        .map_err(|err| format!("the script's result is unreadable: {err}"))?;
    let status = |value: Option<i64>| value.and_then(|n| u16::try_from(n).ok()).unwrap_or(0);
    Ok(ScriptResult {
        url: done.url.unwrap_or_default(),
        status: status(done.status),
        header: done.header.map(to_list),
        body: done.body.as_ref().and_then(BodyJson::bytes),
        trailers: done.trailers.map(to_list),
        response: done.response.map(|answer| ScriptResponse {
            status: status(answer.status),
            header: answer.header.map(to_list).unwrap_or_default(),
            body: answer
                .body
                .as_ref()
                .and_then(BodyJson::bytes)
                .map(Bytes::from),
            trailers: None,
        }),
        abort: done.abort.unwrap_or(false),
        value: done.value.unwrap_or_default().into_bytes(),
    })
}
