mod bytecode;
mod fetch;
mod run;
mod store;

use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use rquickjs::{CatchResultExt, Context, Runtime};

use crate::script::{
    CompileError, ScriptBatch, ScriptError, ScriptInvocation, ScriptProgram, ScriptResult,
    ScriptRuntime,
};
use store::Store;

const QUANTUMULT_APIS: [&str; 3] = ["$task.fetch", "$prefs.", "$notify("];
const SURGE_APIS: [&str; 3] = ["$httpClient", "$persistentStore", "$notification"];

/// Scripts written for both clients tell them apart by whether `$task` exists, and the Surge side is the one that works here.
fn quantumult_only(source: &str) -> bool {
    let uses = |names: &[&str]| names.iter().any(|name| source.contains(name));
    uses(&QUANTUMULT_APIS) && !uses(&SURGE_APIS)
}

pub struct QuickJs {
    store: Arc<Store>,
    trust: Arc<ArcSwap<TrustStore>>,
}

impl QuickJs {
    pub fn new(home: Arc<HomeDir>, trust: Arc<ArcSwap<TrustStore>>) -> Arc<QuickJs> {
        Arc::new(QuickJs {
            store: Store::new(home),
            trust,
        })
    }

    pub fn flush(&self) {
        self.store.flush();
    }

    fn new_batch(&self) -> QuickJsBatch {
        QuickJsBatch {
            store: self.store.clone(),
            trust: self.trust.clone(),
            checker: None,
        }
    }
}

impl ScriptRuntime for QuickJs {
    fn compile(&self, name: &str, source: &[u8]) -> Result<Arc<dyn ScriptProgram>, CompileError> {
        self.new_batch().compile(name, source)
    }

    fn batch(&self) -> Option<Box<dyn ScriptBatch>> {
        Some(Box::new(self.new_batch()))
    }
}

struct QuickJsBatch {
    store: Arc<Store>,
    trust: Arc<ArcSwap<TrustStore>>,
    checker: Option<(Runtime, Context)>,
}

impl ScriptBatch for QuickJsBatch {
    fn compile(
        &mut self,
        _name: &str,
        source: &[u8],
    ) -> Result<Arc<dyn ScriptProgram>, CompileError> {
        let text = std::str::from_utf8(source)
            .map_err(|err| CompileError(err.to_string()))?
            .to_string();
        let (_, context) = match &self.checker {
            Some(pair) => pair,
            None => {
                let fail = |err: &dyn std::fmt::Display| CompileError(err.to_string());
                let runtime = Runtime::new().map_err(|err| fail(&err))?;
                let context = Context::full(&runtime).map_err(|err| fail(&err))?;
                self.checker.insert((runtime, context))
            }
        };
        check_syntax_in(context, &text)?;
        Ok(Arc::new(Program {
            compiled: Arc::new(run::Compiled::new(quantumult_only(&text), text)),
            store: self.store.clone(),
            trust: self.trust.clone(),
        }))
    }
}

fn check_syntax_in(context: &Context, source: &str) -> Result<(), CompileError> {
    let literal = serde_json::to_string(source).map_err(|err| CompileError(err.to_string()))?;
    context.with(|ctx| {
        ctx.eval::<rquickjs::Value<'_>, _>(format!("new Function({literal})"))
            .catch(&ctx)
            .map(|_| ())
            .map_err(|err| CompileError(run::describe(&err)))
    })
}

struct Program {
    compiled: Arc<run::Compiled>,
    store: Arc<Store>,
    trust: Arc<ArcSwap<TrustStore>>,
}

#[async_trait]
impl ScriptProgram for Program {
    async fn run(&self, invocation: ScriptInvocation) -> Result<ScriptResult, ScriptError> {
        run::execute(
            self.compiled.clone(),
            self.store.clone(),
            self.trust.load_full(),
            invocation,
        )
        .await
    }
}

#[cfg(test)]
mod tests;
