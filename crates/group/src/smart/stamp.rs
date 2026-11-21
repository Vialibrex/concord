use std::time::{Duration, SystemTime};

use tokio::time::Instant;

#[derive(Clone, Copy, Debug)]
pub struct Stamp {
    pub mono: Instant,
    pub wall: SystemTime,
}

impl Stamp {
    pub fn now() -> Stamp {
        Stamp {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }

    /// `max(monotonic elapsed, wall elapsed clamped at zero)`: `Instant` stops while the device sleeps
    /// (`CLOCK_UPTIME_RAW` on Apple, `CLOCK_MONOTONIC` elsewhere) and `SystemTime` does not; a wall clock stepped
    /// back reads as zero.
    pub fn since(&self, earlier: &Stamp) -> Duration {
        let mono = self.mono.saturating_duration_since(earlier.mono);
        let wall = self.wall.duration_since(earlier.wall).unwrap_or_default();
        mono.max(wall)
    }

    pub(super) fn after(&self, by: Duration) -> Stamp {
        Stamp {
            mono: self.mono + by,
            wall: self.wall + by,
        }
    }
}
