use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use super::{
    EJECT_BASE, EJECT_DECAY, EJECT_MAX, ESCALATION_SITES, RTT_ALPHA, RTT_BETA, SITE_LIMIT,
    Settings, Stamp, T_FAIL_GAIN,
};

/// RFC 6298 smoothed round-trip time and variation, in milliseconds.
#[derive(Clone, Copy, Debug)]
pub(super) struct Rtt {
    pub srtt: f64,
    rttvar: f64,
}

impl Rtt {
    pub fn first(sample: Duration) -> Rtt {
        let sample = sample.as_secs_f64() * 1000.0;
        Rtt {
            srtt: sample,
            rttvar: sample / 2.0,
        }
    }

    pub fn update(&mut self, sample: Duration) {
        let sample = sample.as_secs_f64() * 1000.0;
        self.rttvar = (1.0 - RTT_BETA) * self.rttvar + RTT_BETA * (self.srtt - sample).abs();
        self.srtt = (1.0 - RTT_ALPHA) * self.srtt + RTT_ALPHA * sample;
    }

    /// The retransmission timeout of RFC 6298 §2: `srtt + 4 * rttvar`.
    pub fn rto_ms(&self) -> f64 {
        self.srtt + 4.0 * self.rttvar
    }

    pub fn observe(slot: &mut Option<Rtt>, sample: Duration) {
        match slot {
            Some(rtt) => rtt.update(sample),
            None => *slot = Some(Rtt::first(sample)),
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static EXP2_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn take_exp2_calls() -> usize {
    EXP2_CALLS.with(|calls| calls.replace(0))
}

fn decay_factor(dt: Duration, half_life: Duration) -> f64 {
    if half_life.is_zero() || dt.is_zero() {
        return 1.0;
    }
    #[cfg(test)]
    EXP2_CALLS.with(|calls| calls.set(calls.get() + 1));
    (-dt.as_secs_f64() / half_life.as_secs_f64()).exp2()
}

pub(super) struct NodeState {
    successes: f64,
    failures: f64,
    counted_at: Stamp,
    consecutive: u32,
    t_fail_ms: Option<f64>,
    eject: Option<(Stamp, Duration)>,
    multiplier: u32,
    idle_since: Option<Stamp>,
    recovering: bool,
    site_fails: HashSet<Arc<str>>,
    pub connect: Option<Rtt>,
}

impl NodeState {
    pub fn new(now: Stamp) -> NodeState {
        NodeState {
            successes: 0.0,
            failures: 0.0,
            counted_at: now,
            consecutive: 0,
            t_fail_ms: None,
            eject: None,
            multiplier: 0,
            idle_since: None,
            recovering: false,
            site_fails: HashSet::new(),
            connect: None,
        }
    }

    fn decay(&mut self, now: Stamp, half_life: Duration) {
        let dt = now.since(&self.counted_at);
        if dt.is_zero() {
            return;
        }
        let k = decay_factor(dt, half_life);
        self.successes *= k;
        self.failures *= k;
        self.counted_at = now;
    }

    /// `p / (1 - p) * T_fail` with `p = F / (S + F + 1)`, which is `F / (S + 1) * T_fail`.
    pub fn penalty_ms(&self, now: Stamp, half_life: Duration) -> f64 {
        if self.failures == 0.0 {
            return 0.0;
        }
        let Some(t_fail_ms) = self.t_fail_ms.filter(|&t| t != 0.0) else {
            return 0.0;
        };
        let k = decay_factor(now.since(&self.counted_at), half_life);
        let (s, f) = (self.successes * k, self.failures * k);
        f / (s + 1.0) * t_fail_ms
    }

    pub fn ejection(&self, now: Stamp) -> (bool, Duration) {
        let Some((at, span)) = self.eject else {
            return (false, Duration::ZERO);
        };
        let elapsed = now.since(&at);
        if elapsed < span {
            (true, span.saturating_sub(elapsed))
        } else {
            (false, Duration::ZERO)
        }
    }

    pub fn ejected(&self, now: Stamp) -> bool {
        self.eject.is_some_and(|(at, span)| now.since(&at) < span)
    }

    #[cfg(test)]
    pub fn raw_penalty_parts(&self) -> (f64, f64, Stamp, Option<f64>) {
        (
            self.successes,
            self.failures,
            self.counted_at,
            self.t_fail_ms,
        )
    }

    /// Ends an expired ejection and lets the multiplier fall by one per `EJECT_DECAY` since it ended.
    pub fn settle(&mut self, now: Stamp) {
        if let Some((at, span)) = self.eject
            && now.since(&at) >= span
        {
            self.idle_since = Some(at.after(span));
            self.eject = None;
        }
        if self.eject.is_some() {
            return;
        }
        let Some(since) = self.idle_since else {
            return;
        };
        let steps = now.since(&since).as_nanos() / EJECT_DECAY.as_nanos();
        let steps = u32::try_from(steps).unwrap_or(u32::MAX);
        if steps >= self.multiplier {
            self.multiplier = 0;
            self.idle_since = None;
        } else if steps > 0 {
            self.multiplier -= steps;
            self.idle_since = Some(since.after(EJECT_DECAY * steps));
        }
    }

    /// A flow's first download byte (`flow`) or a successful probe.
    pub fn success(&mut self, now: Stamp, half_life: Duration, flow: bool) {
        self.settle(now);
        self.decay(now, half_life);
        self.successes += 1.0;
        self.consecutive = 0;
        if flow {
            self.site_fails.clear();
        }
    }

    /// An expired ejection ends with the node's next successful probe, which clears its counts.
    pub fn probe_success(&mut self, now: Stamp, half_life: Duration) {
        self.settle(now);
        if self.recovering && !self.ejected(now) {
            self.successes = 0.0;
            self.failures = 0.0;
            self.consecutive = 0;
            self.counted_at = now;
            self.recovering = false;
        }
        self.success(now, half_life, false);
    }

    /// Returns true when this failure ejects the node.
    pub fn failure(&mut self, now: Stamp, elapsed: Duration, settings: &Settings) -> bool {
        self.settle(now);
        if self.ejected(now) {
            return false;
        }
        self.decay(now, settings.half_life);
        self.failures += 1.0;
        self.consecutive = self.consecutive.saturating_add(1);
        let ms = elapsed.as_secs_f64() * 1000.0;
        self.t_fail_ms = Some(match self.t_fail_ms {
            Some(t) => t + T_FAIL_GAIN * (ms - t),
            None => ms,
        });
        if self.consecutive < settings.max_failed.max(1) {
            return false;
        }
        self.multiplier = self.multiplier.saturating_add(1);
        let span = EJECT_BASE.saturating_mul(self.multiplier).min(EJECT_MAX);
        self.eject = Some((now, span));
        self.idle_since = None;
        self.recovering = true;
        self.consecutive = 0;
        self.site_fails.clear();
        true
    }

    /// Records a site-level failure; true when it counts as one more node-level failure.
    pub fn site_failure(&mut self, site: &Arc<str>) -> bool {
        let new = self.site_fails.len() < SITE_LIMIT && self.site_fails.insert(site.clone());
        new && self.site_fails.len() >= ESCALATION_SITES
    }

    #[cfg(test)]
    pub fn connect_srtt(&self) -> Option<f64> {
        self.connect.map(|rtt| rtt.srtt)
    }
}
