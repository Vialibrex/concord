use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use concord_common::{CoreEvent, DnsRecord, EventSink, Initiator};
use hickory_proto::op::{Message, Query};

use crate::msg;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct Trace {
    pub query: Query,
    pub initiator: Initiator,
    pub start: Instant,
    pub started_at: SystemTime,
}

impl Trace {
    pub(crate) fn new(query: &Query, initiator: Initiator) -> Self {
        Trace {
            query: query.clone(),
            initiator,
            start: Instant::now(),
            started_at: SystemTime::now(),
        }
    }

    pub(crate) fn emit(
        &self,
        events: &dyn EventSink,
        outcome: Result<&Message, &std::io::Error>,
        upstream: &str,
        cached: bool,
    ) -> Option<u64> {
        if !events.enabled() {
            return None;
        }
        let mut domain = self.query.name.to_ascii();
        if domain.ends_with('.') {
            domain.pop();
        }
        let (answers, rcode, error) = match outcome {
            Ok(message) => (
                message.answers.iter().map(msg::answer_text).collect(),
                msg::rcode_name(message.metadata.response_code),
                String::new(),
            ),
            Err(err) => (Vec::new(), String::new(), err.to_string()),
        };
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        events.publish(CoreEvent::Dns(DnsRecord {
            id,
            domain,
            qtype: msg::qtype_name(self.query.query_type),
            initiator: self.initiator,
            upstream: upstream.to_string(),
            cached,
            answers,
            rcode,
            error,
            delay_ms: i64::try_from(self.start.elapsed().as_millis()).unwrap_or(i64::MAX),
            time: self.started_at,
        }));
        Some(id)
    }
}
