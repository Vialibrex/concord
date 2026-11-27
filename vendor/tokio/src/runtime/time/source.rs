use super::MAX_SAFE_MILLIS_DURATION;
use crate::time::{Clock, Duration, Instant};

/// A structure which handles conversion from Instants to `u64` timestamps.
#[derive(Debug)]
pub(crate) struct TimeSource {
    start_time: Instant,
}

impl TimeSource {
    pub(crate) fn new(clock: &Clock) -> Self {
        Self {
            start_time: clock.now(),
        }
    }

    #[cfg_attr(
        not(all(tokio_unstable, feature = "rt-multi-thread")),
        allow(dead_code, reason = "used by the tokio_unstable alternative time driver")
    )]
    pub(crate) fn deadline_to_tick(&self, t: Instant) -> u64 {
        // Round up to the end of a ms
        self.instant_to_tick(t + Duration::from_nanos(999_999))
    }

    // Concord: the traditional driver keeps each deadline in nanoseconds and fires it once the clock has
    // reached it, so a 30 ms sleep ends at 30 ms instead of at the millisecond tick after it.
    pub(crate) fn deadline_to_nanos(&self, t: Instant) -> u64 {
        let dur: Duration = t.saturating_duration_since(self.start_time);
        let nanos = dur
            .as_nanos()
            .try_into()
            .unwrap_or(MAX_SAFE_MILLIS_DURATION);
        nanos.min(MAX_SAFE_MILLIS_DURATION)
    }

    pub(crate) fn now_nanos(&self, clock: &Clock) -> u64 {
        self.deadline_to_nanos(clock.now())
    }

    #[cfg_attr(
        not(all(tokio_unstable, feature = "rt-multi-thread")),
        allow(dead_code, reason = "used by the tokio_unstable alternative time driver")
    )]
    pub(crate) fn instant_to_tick(&self, t: Instant) -> u64 {
        // round up
        let dur: Duration = t.saturating_duration_since(self.start_time);
        let ms = dur
            .as_millis()
            .try_into()
            .unwrap_or(MAX_SAFE_MILLIS_DURATION);
        ms.min(MAX_SAFE_MILLIS_DURATION)
    }

    #[cfg_attr(
        not(all(tokio_unstable, feature = "rt-multi-thread")),
        allow(dead_code, reason = "used by the tokio_unstable alternative time driver")
    )]
    pub(crate) fn tick_to_duration(&self, t: u64) -> Duration {
        Duration::from_millis(t)
    }

    #[cfg_attr(
        not(all(tokio_unstable, feature = "rt-multi-thread")),
        allow(dead_code, reason = "used by the tokio_unstable alternative time driver")
    )]
    pub(crate) fn now(&self, clock: &Clock) -> u64 {
        self.instant_to_tick(clock.now())
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn start_time(&self) -> Instant {
        self.start_time
    }
}
