//! What a run writes: one JSON line per event, in the order they happened.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};

pub const PHASES: [&str; 3] = ["warmup", "observe", "idle"];

pub fn phase_name(index: u8) -> &'static str {
    PHASES.get(usize::from(index)).copied().unwrap_or("observe")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// `t` is when the request was issued, in seconds since the run began; `node` is read from the body.
    Request {
        t: f64,
        site: usize,
        ok: bool,
        class: Option<String>,
        total_ms: f64,
        ttfb_ms: Option<f64>,
        node: Option<usize>,
        phase: String,
    },
    /// A health check that reached the origin, and the address it came from.
    Probe {
        t: f64,
        src: String,
        phase: String,
    },
    /// The node the group reported as selected, written when it changes.
    Group {
        t: f64,
        now: String,
    },
    Mark {
        t: f64,
        what: String,
    },
}

pub struct Clock {
    pub start: Instant,
    pub phase: Arc<AtomicU8>,
}

impl Clock {
    pub fn seconds(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    pub fn phase_name(&self) -> &'static str {
        phase_name(self.phase.load(Ordering::Relaxed))
    }
}

struct Inner {
    out: std::io::BufWriter<std::fs::File>,
    all: Vec<Event>,
}

/// Appends events to the run's file as they happen and keeps them for the summary.
#[derive(Clone)]
pub struct Recorder(Arc<Mutex<Inner>>);

impl Recorder {
    pub fn create(path: &Path) -> Result<Recorder, String> {
        let file = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Recorder(Arc::new(Mutex::new(Inner {
            out: std::io::BufWriter::new(file),
            all: Vec::new(),
        }))))
    }

    pub fn record(&self, event: Event) {
        let Ok(mut inner) = self.0.lock() else {
            return;
        };
        if let Ok(line) = serde_json::to_string(&event) {
            let _ = writeln!(inner.out, "{line}");
        }
        inner.all.push(event);
    }

    pub fn finish(&self) -> Vec<Event> {
        let Ok(mut inner) = self.0.lock() else {
            return Vec::new();
        };
        let _ = inner.out.flush();
        inner.all.clone()
    }
}
