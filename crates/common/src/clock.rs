use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

/// How far the NTP service found the device clock from real time; timestamps on the wire
/// and certificate checks read it instead of the system clock.
#[derive(Debug, Default)]
pub struct ClockOffset {
    nanos: AtomicI64,
}

impl ClockOffset {
    pub fn set(&self, nanos: i64) {
        self.nanos.store(nanos, Ordering::Relaxed);
    }

    pub fn nanos(&self) -> i64 {
        self.nanos.load(Ordering::Relaxed)
    }

    pub fn now(&self) -> SystemTime {
        let nanos = self.nanos();
        let now = SystemTime::now();
        let shift = Duration::from_nanos(nanos.unsigned_abs());
        let shifted = if nanos >= 0 {
            now.checked_add(shift).unwrap_or(now)
        } else {
            now.checked_sub(shift).unwrap_or(SystemTime::UNIX_EPOCH)
        };
        shifted.max(SystemTime::UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gap(clock: &ClockOffset) -> i128 {
        let now = SystemTime::now();
        match clock.now().duration_since(now) {
            Ok(ahead) => i128::try_from(ahead.as_nanos()).unwrap_or(i128::MAX),
            Err(behind) => -i128::try_from(behind.duration().as_nanos()).unwrap_or(i128::MAX),
        }
    }

    #[test]
    fn the_offset_moves_time_both_ways() {
        let clock = ClockOffset::default();
        assert!(gap(&clock).abs() < 1_000_000_000);
        clock.set(3_600_000_000_000);
        assert!((gap(&clock) - 3_600_000_000_000).abs() < 1_000_000_000);
        clock.set(-90_000_000_000);
        assert!((gap(&clock) + 90_000_000_000).abs() < 1_000_000_000);
        clock.set(0);
        assert!(gap(&clock).abs() < 1_000_000_000);
    }
}
