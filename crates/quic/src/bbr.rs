#![allow(
    clippy::indexing_slicing,
    reason = "fixed-size sample and gain tables indexed by values kept in range"
)]

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use quinn_proto::congestion::ControllerMetrics;
use rand::Rng;

const PACING_GAIN: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const STARTUP_GROWTH_TARGET: f32 = 1.25;
const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
const PROBE_RTT_TIME: Duration = Duration::from_millis(200);

/// The knobs mihomo's `bbr-profile` turns, with the values it gives each name.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Profile {
    high_gain: f32,
    high_cwnd_gain: f32,
    probe_cwnd_gain: f32,
    startup_rounds: u64,
    drain_to_target: bool,
}

const CONSERVATIVE: Profile = Profile {
    high_gain: 2.25,
    high_cwnd_gain: 1.75,
    probe_cwnd_gain: 1.75,
    startup_rounds: 2,
    drain_to_target: true,
};

const AGGRESSIVE: Profile = Profile {
    high_gain: 3.0,
    high_cwnd_gain: 2.25,
    probe_cwnd_gain: 2.5,
    startup_rounds: 4,
    drain_to_target: false,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbrProfile {
    Standard,
    Conservative,
    Aggressive,
}

impl BbrProfile {
    /// Any name mihomo does not know is `standard`.
    pub fn parse(name: &str) -> Self {
        match name {
            "conservative" => BbrProfile::Conservative,
            "aggressive" => BbrProfile::Aggressive,
            _ => BbrProfile::Standard,
        }
    }
}

/// The controller for a profile. `standard` is the stock controller; the other
/// two keep quinn's loss handling and take only the gains, startup length and
/// drain rule of the profile: overshoot detection and overestimate avoidance
/// are not modelled.
pub fn factory(
    profile: BbrProfile,
    initial_window: u64,
) -> Arc<dyn ControllerFactory + Send + Sync> {
    let chosen = match profile {
        BbrProfile::Conservative => CONSERVATIVE,
        BbrProfile::Aggressive => AGGRESSIVE,
        BbrProfile::Standard => {
            let mut config = BbrConfig::default();
            config.initial_window(initial_window);
            return Arc::new(config);
        }
    };
    Arc::new(Profiled {
        profile: chosen,
        initial_window,
    })
}

struct Profiled {
    profile: Profile,
    initial_window: u64,
}

impl ControllerFactory for Profiled {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr::new(self.profile, self.initial_window, current_mtu))
    }
}

#[derive(Clone, Copy, Default)]
struct Sample {
    time: u64,
    value: u64,
}

#[derive(Clone, Copy)]
struct MaxFilter {
    window: u64,
    samples: [Sample; 3],
}

impl Default for MaxFilter {
    fn default() -> Self {
        MaxFilter {
            window: 10,
            samples: [Sample::default(); 3],
        }
    }
}

impl MaxFilter {
    fn get(&self) -> u64 {
        self.samples[0].value
    }

    fn reset(&mut self) {
        self.samples = [Sample::default(); 3];
    }

    fn update(&mut self, round: u64, value: u64) {
        let sample = Sample { time: round, value };
        if self.samples[0].value == 0
            || value >= self.samples[0].value
            || sample.time - self.samples[2].time > self.window
        {
            self.samples = [sample; 3];
            return;
        }
        if value >= self.samples[1].value {
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if value >= self.samples[2].value {
            self.samples[2] = sample;
        }
        let dt = sample.time - self.samples[0].time;
        if dt > self.window {
            self.samples[0] = self.samples[1];
            self.samples[1] = self.samples[2];
            self.samples[2] = sample;
            if sample.time - self.samples[0].time > self.window {
                self.samples[0] = self.samples[1];
                self.samples[1] = self.samples[2];
                self.samples[2] = sample;
            }
        } else if self.samples[1].time == self.samples[0].time && dt > self.window / 4 {
            self.samples[2] = sample;
            self.samples[1] = sample;
        } else if self.samples[2].time == self.samples[1].time && dt > self.window / 2 {
            self.samples[2] = sample;
        }
    }
}

fn rate(bytes: u64, delta: Duration) -> Option<u64> {
    let nanos = u64::try_from(delta.as_nanos()).ok().filter(|n| *n > 0)?;
    Some(bytes.saturating_mul(1_000_000_000) / nanos)
}

#[derive(Clone, Default)]
struct Bandwidth {
    total_acked: u64,
    prev_total_acked: u64,
    acked_time: Option<Instant>,
    prev_acked_time: Option<Instant>,
    total_sent: u64,
    prev_total_sent: u64,
    sent_time: Option<Instant>,
    prev_sent_time: Option<Instant>,
    filter: MaxFilter,
    acked_at_last_window: u64,
}

impl Bandwidth {
    fn on_sent(&mut self, now: Instant, bytes: u64) {
        self.prev_total_sent = self.total_sent;
        self.total_sent += bytes;
        self.prev_sent_time = self.sent_time;
        self.sent_time = Some(now);
    }

    fn on_ack(&mut self, now: Instant, bytes: u64, round: u64, app_limited: bool) {
        self.prev_total_acked = self.total_acked;
        self.total_acked += bytes;
        self.prev_acked_time = self.acked_time;
        self.acked_time = Some(now);
        let Some(prev_sent) = self.prev_sent_time else {
            return;
        };
        let send_rate = match self.sent_time {
            Some(sent) if sent > prev_sent => {
                rate(self.total_sent - self.prev_total_sent, sent - prev_sent).unwrap_or(0)
            }
            _ => u64::MAX,
        };
        let ack_rate = self
            .prev_acked_time
            .and_then(|prev| rate(self.total_acked - self.prev_total_acked, now - prev))
            .unwrap_or(0);
        let bandwidth = send_rate.min(ack_rate);
        if !app_limited && self.filter.get() < bandwidth {
            self.filter.update(round, bandwidth);
        }
    }

    fn acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    fn end_acks(&mut self) {
        self.acked_at_last_window = self.total_acked;
    }

    fn estimate(&self) -> u64 {
        self.filter.get()
    }
}

#[derive(Clone, Copy, Default)]
struct Aggregation {
    max_height: MaxFilter,
    epoch_start: Option<Instant>,
    epoch_bytes: u64,
}

impl Aggregation {
    fn update(&mut self, acked: u64, now: Instant, round: u64, bandwidth: u64) -> u64 {
        let elapsed = now.saturating_duration_since(self.epoch_start.unwrap_or(now));
        let expected =
            bandwidth.saturating_mul(u64::try_from(elapsed.as_micros()).unwrap_or(0)) / 1_000_000;
        if self.epoch_bytes <= expected {
            self.epoch_bytes = acked;
            self.epoch_start = Some(now);
            return 0;
        }
        self.epoch_bytes += acked;
        let extra = self.epoch_bytes - expected;
        self.max_height.update(round, extra);
        extra
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Recovery {
    None,
    Conservation,
    Growth,
}

impl Recovery {
    fn active(self) -> bool {
        self != Recovery::None
    }
}

#[derive(Clone)]
struct Bbr {
    profile: Profile,
    initial_window: u64,
    mtu: u64,
    bandwidth: Bandwidth,
    acked_bytes: u64,
    mode: Mode,
    lost_bytes: u64,
    recovery: Recovery,
    recovery_window: u64,
    full_bandwidth: bool,
    pacing_gain: f32,
    drain_gain: f32,
    cwnd_gain: f32,
    last_cycle_start: Option<Instant>,
    cycle_offset: usize,
    init_cwnd: u64,
    min_cwnd: u64,
    prev_in_flight: u64,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_started: Option<Instant>,
    min_rtt: Duration,
    pacing_rate: u64,
    max_acked_packet: u64,
    max_sent_packet: u64,
    end_recovery_at: u64,
    cwnd: u64,
    round_end_packet: u64,
    round_count: u64,
    bw_at_last_round: u64,
    rounds_without_gain: u64,
    aggregation: Aggregation,
}

impl Bbr {
    fn new(profile: Profile, initial_window: u64, mtu: u16) -> Self {
        let mtu = u64::from(mtu);
        Bbr {
            profile,
            initial_window,
            mtu,
            bandwidth: Bandwidth::default(),
            acked_bytes: 0,
            mode: Mode::Startup,
            lost_bytes: 0,
            recovery: Recovery::None,
            recovery_window: 0,
            full_bandwidth: false,
            pacing_gain: profile.high_gain,
            drain_gain: 1.0 / profile.high_gain,
            cwnd_gain: profile.high_cwnd_gain,
            last_cycle_start: None,
            cycle_offset: 0,
            init_cwnd: initial_window,
            min_cwnd: 4 * mtu,
            prev_in_flight: 0,
            exit_probe_rtt_at: None,
            probe_rtt_started: None,
            min_rtt: Duration::ZERO,
            pacing_rate: 0,
            max_acked_packet: 0,
            max_sent_packet: 0,
            end_recovery_at: 0,
            cwnd: initial_window,
            round_end_packet: 0,
            round_count: 0,
            bw_at_last_round: 0,
            rounds_without_gain: 0,
            aggregation: Aggregation::default(),
        }
    }

    fn enter_startup(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.profile.high_gain;
        self.cwnd_gain = self.profile.high_cwnd_gain;
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = self.profile.probe_cwnd_gain;
        self.last_cycle_start = Some(now);
        let mut index = rand::rng().random_range(0..PACING_GAIN.len() - 1);
        if index >= 1 {
            index += 1;
        }
        self.cycle_offset = index;
        self.pacing_gain = PACING_GAIN[index];
    }

    fn update_recovery(&mut self, round_start: bool) {
        let losses = self.lost_bytes != 0;
        if losses {
            self.end_recovery_at = self.max_sent_packet;
        }
        match self.recovery {
            Recovery::None if losses => {
                self.recovery = Recovery::Conservation;
                self.recovery_window = 0;
                self.round_end_packet = self.max_sent_packet;
            }
            Recovery::Growth | Recovery::Conservation => {
                if self.recovery == Recovery::Conservation && round_start {
                    self.recovery = Recovery::Growth;
                }
                if !losses && self.max_acked_packet > self.end_recovery_at {
                    self.recovery = Recovery::None;
                }
            }
            Recovery::None => {}
        }
    }

    fn update_gain_cycle(&mut self, now: Instant, in_flight: u64) {
        let mut advance = self
            .last_cycle_start
            .is_some_and(|start| now.duration_since(start) > self.min_rtt);
        if self.pacing_gain > 1.0
            && self.lost_bytes == 0
            && self.prev_in_flight < self.target_cwnd(self.pacing_gain)
        {
            advance = false;
        }
        if self.pacing_gain < 1.0 && in_flight <= self.target_cwnd(1.0) {
            advance = true;
        }
        if advance {
            self.cycle_offset = (self.cycle_offset + 1) % PACING_GAIN.len();
            self.last_cycle_start = Some(now);
            if self.profile.drain_to_target
                && self.pacing_gain < 1.0
                && (PACING_GAIN[self.cycle_offset] - 1.0).abs() < f32::EPSILON
                && in_flight > self.target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain = PACING_GAIN[self.cycle_offset];
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: u64) {
        if self.mode == Mode::Startup && self.full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.profile.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && in_flight <= self.target_cwnd(1.0) {
            self.enter_probe_bw(now);
        }
    }

    fn min_rtt_expired(&self, now: Instant, app_limited: bool) -> bool {
        !app_limited
            && self
                .probe_rtt_started
                .is_none_or(|last| now.saturating_duration_since(last) > MIN_RTT_EXPIRY)
    }

    fn maybe_probe_rtt(&mut self, now: Instant, round_start: bool, in_flight: u64, limited: bool) {
        if self.min_rtt_expired(now, limited) && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            self.exit_probe_rtt_at = None;
            self.probe_rtt_started = Some(now);
        }
        if self.mode != Mode::ProbeRtt {
            return;
        }
        match self.exit_probe_rtt_at {
            None => {
                if in_flight < self.probe_rtt_cwnd() + self.mtu {
                    self.exit_probe_rtt_at = Some(now + PROBE_RTT_TIME);
                }
            }
            Some(exit) if round_start && now >= exit => {
                if self.full_bandwidth {
                    self.enter_probe_bw(now);
                } else {
                    self.enter_startup();
                }
            }
            Some(_) => {}
        }
    }

    fn target_cwnd(&self, gain: f32) -> u64 {
        let micros = u64::try_from(self.min_rtt.as_micros()).unwrap_or(u64::MAX);
        let bdp = micros.saturating_mul(self.bandwidth.estimate()) as f64;
        let cwnd = (f64::from(gain) * bdp / 1_000_000.0) as u64;
        if cwnd == 0 {
            return ((f64::from(gain) * self.init_cwnd as f64) as u64).max(self.min_cwnd);
        }
        cwnd.max(self.min_cwnd)
    }

    fn probe_rtt_cwnd(&self) -> u64 {
        self.target_cwnd(0.75)
    }

    fn update_pacing_rate(&mut self) {
        let bandwidth = self.bandwidth.estimate();
        if bandwidth == 0 {
            return;
        }
        let target = (bandwidth as f64 * f64::from(self.pacing_gain)) as u64;
        if self.full_bandwidth {
            self.pacing_rate = target;
            return;
        }
        if self.pacing_rate == 0 && !self.min_rtt.is_zero() {
            self.pacing_rate = rate(self.init_cwnd, self.min_rtt).unwrap_or(0);
            return;
        }
        self.pacing_rate = self.pacing_rate.max(target);
    }

    fn update_cwnd(&mut self, acked: u64, excess: u64) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target = self.target_cwnd(self.cwnd_gain);
        if self.full_bandwidth {
            target += self.aggregation.max_height.get();
        } else {
            target += excess;
        }
        if self.full_bandwidth {
            self.cwnd = target.min(self.cwnd + acked);
        } else if self.cwnd < target || self.acked_bytes < self.init_cwnd {
            self.cwnd += acked;
        }
        self.cwnd = self.cwnd.max(self.min_cwnd).min(20_000 * self.mtu);
    }

    fn update_recovery_window(&mut self, acked: u64, lost: u64, in_flight: u64) {
        if !self.recovery.active() {
            return;
        }
        if self.recovery_window == 0 {
            self.recovery_window = self.min_cwnd.max(in_flight + acked);
            return;
        }
        self.recovery_window = if self.recovery_window >= lost {
            self.recovery_window - lost
        } else {
            self.mtu
        };
        if self.recovery == Recovery::Growth {
            self.recovery_window += acked;
        }
        self.recovery_window = self
            .recovery_window
            .max(in_flight + acked)
            .max(self.min_cwnd);
    }

    fn check_full_bandwidth(&mut self, app_limited: bool) {
        if app_limited {
            return;
        }
        let target = (self.bw_at_last_round as f64 * f64::from(STARTUP_GROWTH_TARGET)) as u64;
        let bandwidth = self.bandwidth.estimate();
        if bandwidth >= target {
            self.bw_at_last_round = bandwidth;
            self.rounds_without_gain = 0;
            self.aggregation.max_height.reset();
            return;
        }
        self.rounds_without_gain += 1;
        if self.rounds_without_gain >= self.profile.startup_rounds || self.recovery.active() {
            self.full_bandwidth = true;
        }
    }
}

impl Controller for Bbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.max_sent_packet = last_packet_number;
        self.bandwidth.on_sent(now, bytes);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.bandwidth
            .on_ack(now, bytes, self.round_count, app_limited);
        self.acked_bytes += bytes;
        if self.min_rtt_expired(now, app_limited) || self.min_rtt > rtt.min() {
            self.min_rtt = rtt.min();
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_acked: Option<u64>,
    ) {
        let acked = self.bandwidth.acked_this_window();
        let excess =
            self.aggregation
                .update(acked, now, self.round_count, self.bandwidth.estimate());
        self.bandwidth.end_acks();
        if let Some(largest) = largest_acked {
            self.max_acked_packet = largest;
        }
        let mut round_start = false;
        if acked > 0 {
            round_start = self.max_acked_packet > self.round_end_packet;
            if round_start {
                self.round_end_packet = self.max_sent_packet;
                self.round_count += 1;
            }
        }
        self.update_recovery(round_start);
        if self.mode == Mode::ProbeBw {
            self.update_gain_cycle(now, in_flight);
        }
        if round_start && !self.full_bandwidth {
            self.check_full_bandwidth(app_limited);
        }
        self.maybe_exit_startup_or_drain(now, in_flight);
        self.maybe_probe_rtt(now, round_start, in_flight, app_limited);
        self.update_pacing_rate();
        self.update_cwnd(acked, excess);
        self.update_recovery_window(acked, self.lost_bytes, in_flight);
        self.prev_in_flight = in_flight;
        self.lost_bytes = 0;
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _persistent: bool,
        lost_bytes: u64,
    ) {
        self.lost_bytes += lost_bytes;
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
        self.min_cwnd = 4 * self.mtu;
        self.init_cwnd = self.initial_window.max(self.min_cwnd);
        self.cwnd = self.cwnd.max(self.min_cwnd);
    }

    fn window(&self) -> u64 {
        if self.mode == Mode::ProbeRtt {
            self.probe_rtt_cwnd()
        } else if self.recovery.active() && self.mode != Mode::Startup {
            self.cwnd.min(self.recovery_window)
        } else {
            self.cwnd
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some(self.pacing_rate * 8);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKET: u64 = 1200;

    fn bbr(profile: Profile) -> Bbr {
        Bbr::new(profile, 32 * PACKET, 1252)
    }

    #[test]
    fn profiles_start_with_their_own_gains() {
        let conservative = bbr(CONSERVATIVE);
        assert!((conservative.pacing_gain - 2.25).abs() < f32::EPSILON);
        assert!((conservative.cwnd_gain - 1.75).abs() < f32::EPSILON);
        let aggressive = bbr(AGGRESSIVE);
        assert!((aggressive.pacing_gain - 3.0).abs() < f32::EPSILON);
        assert!((aggressive.drain_gain - 1.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn startup_ends_after_the_profile_number_of_flat_rounds() {
        for (profile, rounds) in [(CONSERVATIVE, 2), (AGGRESSIVE, 4)] {
            let mut bbr = bbr(profile);
            bbr.bandwidth.filter.update(1, 1_000_000);
            bbr.check_full_bandwidth(false);
            assert!(!bbr.full_bandwidth);
            for round in 1..=rounds {
                assert!(!bbr.full_bandwidth, "round {round} of {rounds}");
                bbr.check_full_bandwidth(false);
            }
            assert!(bbr.full_bandwidth);
        }
    }

    #[test]
    fn probe_bw_uses_the_profile_window_gain() {
        let mut bbr = bbr(AGGRESSIVE);
        bbr.enter_probe_bw(Instant::now());
        assert!((bbr.cwnd_gain - 2.5).abs() < f32::EPSILON);
    }

    #[test]
    fn the_window_never_drops_below_four_packets() {
        let mut bbr = bbr(CONSERVATIVE);
        bbr.cwnd = 1;
        bbr.update_cwnd(0, 0);
        assert_eq!(bbr.window(), 4 * 1252);
    }

    #[test]
    fn without_a_bandwidth_sample_startup_stops_at_the_gain_times_the_initial_window() {
        let mut bbr = bbr(CONSERVATIVE);
        bbr.acked_bytes = bbr.init_cwnd;
        let target = (1.75 * bbr.init_cwnd as f64) as u64;
        for _ in 0..100_000 {
            bbr.update_cwnd(1252, 0);
        }
        assert!(
            bbr.cwnd >= target && bbr.cwnd < target + 1252,
            "cwnd {} target {target}",
            bbr.cwnd
        );
    }

    #[test]
    fn the_window_never_exceeds_twenty_thousand_packets() {
        for full_bandwidth in [false, true] {
            let mut bbr = bbr(CONSERVATIVE);
            bbr.full_bandwidth = full_bandwidth;
            bbr.cwnd = 30_000 * 1252;
            bbr.update_cwnd(1252, 0);
            assert!(
                bbr.cwnd <= 20_000 * 1252,
                "full_bandwidth {full_bandwidth}: cwnd {}",
                bbr.cwnd
            );
        }
    }

    #[test]
    fn unknown_names_and_standard_build_the_stock_controller() {
        let now = Instant::now();
        for name in ["", "standard", "turbo"] {
            let profile = BbrProfile::parse(name);
            assert_eq!(profile, BbrProfile::Standard);
            let controller = factory(profile, 10 * PACKET).build(now, 1252);
            assert_eq!(controller.initial_window(), 10 * PACKET);
        }
        assert_eq!(BbrProfile::parse("aggressive"), BbrProfile::Aggressive);
        let profiled = factory(BbrProfile::Aggressive, 10 * PACKET).build(now, 1252);
        assert_eq!(profiled.initial_window(), 10 * PACKET);
    }
}
