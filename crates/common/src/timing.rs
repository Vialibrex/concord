use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime};

/// A step of setting a connection up, in the order a connection usually takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnStep {
    DnsStart,
    DnsEnd,
    Routed,
    DialStart,
    /// The first hop's TCP connection is up.
    Connected,
    /// The outbound's own TLS handshake is done.
    Tls,
    DialEnd,
    /// MITM's TLS handshake with the destination is done.
    TargetTls,
    /// MITM answered the client's handshake and reads its requests.
    Decrypted,
}

impl ConnStep {
    pub const ALL: [ConnStep; 9] = [
        ConnStep::DnsStart,
        ConnStep::DnsEnd,
        ConnStep::Routed,
        ConnStep::DialStart,
        ConnStep::Connected,
        ConnStep::Tls,
        ConnStep::DialEnd,
        ConnStep::TargetTls,
        ConnStep::Decrypted,
    ];
}

/// When each step happened, in microseconds after the flow was accepted. The first mark of
/// a step is kept, so the first hop of a chain and the first attempt of a redial win.
#[derive(Debug, Default)]
pub struct ConnTiming {
    accepted: Option<(SystemTime, Instant)>,
    steps: [AtomicU32; ConnStep::ALL.len()],
}

impl ConnTiming {
    pub fn start() -> Self {
        ConnTiming {
            accepted: Some((SystemTime::now(), Instant::now())),
            steps: std::array::from_fn(|_| AtomicU32::new(u32::MAX)),
        }
    }

    pub fn mark(&self, step: ConnStep) {
        let Some((_, base)) = self.accepted else {
            return;
        };
        let micros = u32::try_from(base.elapsed().as_micros()).unwrap_or(u32::MAX - 1);
        let _ = self.steps[step as usize].compare_exchange(
            u32::MAX,
            micros,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// When the flow was accepted; `None` for a record that was never timed.
    pub fn accepted(&self) -> Option<SystemTime> {
        self.accepted.map(|(at, _)| at)
    }

    pub fn get(&self, step: ConnStep) -> Option<u32> {
        let micros = self.steps[step as usize].load(Ordering::Relaxed);
        (self.accepted.is_some() && micros != u32::MAX).then_some(micros)
    }
}

impl Clone for ConnTiming {
    fn clone(&self) -> Self {
        ConnTiming {
            accepted: self.accepted,
            steps: std::array::from_fn(|index| {
                AtomicU32::new(self.steps[index].load(Ordering::Relaxed))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_mark_of_a_step_stays_and_an_unmarked_step_is_absent() {
        let timing = ConnTiming::start();
        timing.mark(ConnStep::Routed);
        let routed = timing.get(ConnStep::Routed).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        timing.mark(ConnStep::Routed);
        timing.mark(ConnStep::DialEnd);
        assert_eq!(timing.get(ConnStep::Routed), Some(routed));
        assert!(timing.get(ConnStep::DialEnd).unwrap() >= routed + 2000);
        assert_eq!(timing.get(ConnStep::Tls), None);
        assert_eq!(timing.clone().get(ConnStep::Routed), Some(routed));
    }

    #[test]
    fn an_untimed_record_marks_nothing() {
        let timing = ConnTiming::default();
        timing.mark(ConnStep::Routed);
        assert_eq!(timing.accepted(), None);
        assert_eq!(timing.get(ConnStep::Routed), None);
    }
}
