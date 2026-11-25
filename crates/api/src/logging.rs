use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use concord_common::sync::lock;
use concord_common::{CoreEvent, EventSink, LogLevel, LogRecord};
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

/// Whether log entries are wanted and from what level. Entries are produced only
/// while a `log.watch` subscription exists, from the profile's `log-level`, or
/// from a lower level a subscription that ignores it asked for.
pub struct LogGate {
    streaming: AtomicBool,
    level: AtomicU8,
    floor: AtomicU8,
    ignoring: Mutex<[usize; LogLevel::ALL.len()]>,
}

impl LogGate {
    pub fn new() -> Arc<Self> {
        Arc::new(LogGate {
            streaming: AtomicBool::new(false),
            level: AtomicU8::new(LogLevel::Info as u8),
            floor: AtomicU8::new(LogLevel::Silent as u8),
            ignoring: Mutex::new([0; LogLevel::ALL.len()]),
        })
    }

    pub fn set_streaming(&self, on: bool) {
        self.streaming.store(on, Ordering::SeqCst);
    }

    pub fn set_level(&self, level: LogLevel) {
        self.level.store(level as u8, Ordering::SeqCst);
    }

    pub(crate) fn level(&self) -> LogLevel {
        let level = self.level.load(Ordering::Relaxed);
        LogLevel::ALL
            .into_iter()
            .find(|known| *known as u8 == level)
            .unwrap_or_default()
    }

    pub(crate) fn wants(&self, level: LogLevel) -> bool {
        self.streaming.load(Ordering::Relaxed)
            && (level as u8 >= self.level.load(Ordering::Relaxed)
                || level as u8 >= self.floor.load(Ordering::Relaxed))
    }

    /// Opens the gate from `level` whatever the profile's level, until the hold is dropped.
    pub(crate) fn ignore_level_from(self: &Arc<Self>, level: LogLevel) -> IgnoreLevel {
        self.count_ignoring(level, |count| *count += 1);
        IgnoreLevel {
            gate: self.clone(),
            level,
        }
    }

    fn count_ignoring(&self, level: LogLevel, change: impl FnOnce(&mut usize)) {
        let mut ignoring = lock(&self.ignoring);
        if let Some(count) = ignoring.get_mut(level as usize) {
            change(count);
        }
        let floor = LogLevel::ALL
            .into_iter()
            .zip(ignoring.iter())
            .find_map(|(level, count)| (*count > 0).then_some(level))
            .unwrap_or(LogLevel::Silent);
        self.floor.store(floor as u8, Ordering::SeqCst);
    }
}

pub struct IgnoreLevel {
    gate: Arc<LogGate>,
    level: LogLevel,
}

impl Drop for IgnoreLevel {
    fn drop(&mut self) {
        self.gate
            .count_ignoring(self.level, |count| *count = count.saturating_sub(1));
    }
}

fn level_of(level: Level) -> LogLevel {
    match level {
        Level::ERROR => LogLevel::Error,
        Level::WARN => LogLevel::Warning,
        Level::INFO => LogLevel::Info,
        Level::DEBUG | Level::TRACE => LogLevel::Debug,
    }
}

/// Bridges `tracing` to the event bus. A failure to deliver an entry is reported
/// on stderr by the transport and never comes back through here, otherwise a send
/// failure would feed itself.
pub struct LogBridge {
    gate: Arc<LogGate>,
    sink: Arc<dyn EventSink>,
    stderr: bool,
}

impl LogBridge {
    pub fn new(gate: Arc<LogGate>, sink: Arc<dyn EventSink>, stderr: bool) -> Self {
        LogBridge { gate, sink, stderr }
    }
}

impl<S: Subscriber> Layer<S> for LogBridge {
    // The default turns `enabled` at a callsite's first hit into a permanent answer, which would
    // silence every line first reached before a `log.watch` opened.
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        self.stderr && *metadata.level() <= Level::ERROR
            || self.gate.wants(level_of(*metadata.level()))
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = level_of(*event.metadata().level());
        let wanted = self.gate.wants(level);
        let to_stderr = self.stderr && level == LogLevel::Error;
        if !wanted && !to_stderr {
            return;
        }
        let mut message = MessageVisitor::default();
        event.record(&mut message);
        if to_stderr {
            eprintln!("[ERROR] {}", message.text);
        }
        if wanted && self.sink.enabled() {
            self.sink.publish(CoreEvent::Log(LogRecord {
                level,
                payload: message.text,
            }));
        }
    }
}

#[derive(Default)]
struct MessageVisitor {
    text: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.text, "{value:?}");
        } else {
            let _ = write!(self.text, " {}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.text.push_str(value);
        } else {
            let _ = write!(self.text, " {}={value}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    use concord_common::sync::lock;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl EventSink for Recorder {
        fn enabled(&self) -> bool {
            true
        }

        fn publish(&self, event: CoreEvent) {
            if let CoreEvent::Log(record) = event {
                lock(&self.0).push(record.payload);
            }
        }
    }

    fn the_same_callsite() {
        tracing::info!("reached");
    }

    #[test]
    fn a_line_first_reached_with_the_gate_closed_is_delivered_once_it_opens() {
        let gate = LogGate::new();
        let sink = Arc::new(Recorder::default());
        let bridge = LogBridge::new(gate.clone(), sink.clone(), false);
        let subscriber = tracing_subscriber::registry().with(bridge);

        tracing::subscriber::with_default(subscriber, || {
            the_same_callsite();
            assert!(lock(&sink.0).is_empty());

            gate.set_streaming(true);
            the_same_callsite();
        });

        assert_eq!(*lock(&sink.0), ["reached"]);
    }
}
