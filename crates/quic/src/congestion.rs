use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use concord_common::sync::lock;
use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use quinn_proto::congestion::ControllerMetrics;

const SLOT_COUNT: u64 = 5;
const MIN_SAMPLES: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const UNKNOWN_RTT_WINDOW: u64 = 10_240;
const MIN_PACING_DELAY: Duration = Duration::from_millis(1);

#[derive(Clone, Copy)]
enum BrutalProfile {
    Legacy,
    Hysteria2,
}

#[derive(Clone, Copy)]
struct Slot {
    second: u64,
    acks: u64,
    losses: u64,
}

/// Hysteria's fixed-rate sender: the rate is the one the server granted, scaled
/// up by the recent loss so that the goodput stays at it.
#[derive(Clone)]
pub struct Brutal {
    bytes_per_sec: u64,
    profile: BrutalProfile,
    mtu: u64,
    epoch: Instant,
    slots: [Slot; SLOT_COUNT as usize],
    ack_rate: f64,
    rtt: Duration,
}

impl Brutal {
    pub fn new(bytes_per_sec: u64, mtu: u16, now: Instant) -> Self {
        Self::with_profile(
            bytes_per_sec,
            BrutalProfile::Legacy,
            u64::from(mtu),
            Duration::ZERO,
            now,
        )
    }

    pub fn hysteria2(bytes_per_sec: u64, rtt: Duration, now: Instant) -> Self {
        Self::with_profile(bytes_per_sec, BrutalProfile::Hysteria2, 1252, rtt, now)
    }

    fn with_profile(
        bytes_per_sec: u64,
        profile: BrutalProfile,
        mtu: u64,
        rtt: Duration,
        now: Instant,
    ) -> Self {
        Brutal {
            bytes_per_sec,
            profile,
            mtu,
            epoch: now,
            slots: [Slot {
                second: u64::MAX,
                acks: 0,
                losses: 0,
            }; SLOT_COUNT as usize],
            ack_rate: 1.0,
            rtt,
        }
    }

    fn pacing_rate(&self) -> u64 {
        (self.bytes_per_sec as f64 / self.ack_rate) as u64
    }

    fn burst(&self) -> u64 {
        (self.pacing_rate().saturating_mul(4) / 1000).max(10 * self.mtu)
    }

    fn reference_window(&self) -> u64 {
        if self.rtt.is_zero() {
            return UNKNOWN_RTT_WINDOW;
        }
        let factor = match self.profile {
            BrutalProfile::Legacy => 1.25,
            BrutalProfile::Hysteria2 => 2.0,
        };
        let window =
            (self.bytes_per_sec as f64 * self.rtt.as_secs_f64() * factor / self.ack_rate) as u64;
        match self.profile {
            BrutalProfile::Legacy => window.max(10 * self.mtu),
            BrutalProfile::Hysteria2 => window.max(self.mtu),
        }
    }

    fn admission_window(&self, reference_window: u64) -> u64 {
        if matches!(self.profile, BrutalProfile::Legacy) {
            return reference_window;
        }
        // Quinn reserves the next packet before admission; the references compare bytes already in flight.
        reference_window.saturating_add(self.mtu).saturating_add(1)
    }

    fn second(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs()
    }

    fn slot_mut(&mut self, second: u64) -> Option<&mut Slot> {
        let slot = self.slots.get_mut((second % SLOT_COUNT) as usize)?;
        if slot.second != second {
            *slot = Slot {
                second,
                acks: 0,
                losses: 0,
            };
        }
        Some(slot)
    }

    fn refresh_ack_rate(&mut self, second: u64) {
        let oldest = second.saturating_sub(SLOT_COUNT);
        let (mut acks, mut losses) = (0u64, 0u64);
        for slot in &self.slots {
            if slot.second != u64::MAX && slot.second >= oldest {
                acks += slot.acks;
                losses += slot.losses;
            }
        }
        self.ack_rate = if acks + losses < MIN_SAMPLES {
            1.0
        } else {
            (acks as f64 / (acks + losses) as f64).max(MIN_ACK_RATE)
        };
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = rtt.get();
        let second = self.second(now);
        if let Some(slot) = self.slot_mut(second) {
            slot.acks += 1;
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_acked: Option<u64>,
    ) {
        let second = self.second(now);
        self.refresh_ack_rate(second);
    }

    fn on_packet_lost(&mut self, _bytes: u16, _pn: u64, now: Instant) {
        if matches!(self.profile, BrutalProfile::Legacy) {
            return;
        }
        let second = self.second(now);
        if let Some(slot) = self.slot_mut(second) {
            slot.losses += 1;
        }
        self.refresh_ack_rate(second);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _persistent: bool,
        lost_bytes: u64,
    ) {
        if matches!(self.profile, BrutalProfile::Legacy) {
            let packets = lost_bytes.div_ceil(self.mtu.max(1)).max(1);
            let second = self.second(now);
            if let Some(slot) = self.slot_mut(second) {
                slot.losses += packets;
            }
            self.refresh_ack_rate(second);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        self.admission_window(self.reference_window())
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        if matches!(self.profile, BrutalProfile::Legacy) {
            return metrics;
        }
        metrics.pacing_rate = Some(self.pacing_rate().saturating_mul(8));
        metrics.send_quantum = Some(self.burst());
        metrics.min_pacing_delay = Some(MIN_PACING_DELAY);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        match self.profile {
            BrutalProfile::Legacy => UNKNOWN_RTT_WINDOW.max(1252),
            BrutalProfile::Hysteria2 => self.admission_window(UNKNOWN_RTT_WINDOW),
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// A controller that can be replaced while the connection runs: Hysteria2
/// learns which one to use only from the server's reply to the auth request.
#[derive(Clone)]
pub struct Switch(Arc<Mutex<SwitchState>>);

struct SwitchState {
    controller: Box<dyn Controller>,
    mtu: u16,
}

impl Switch {
    pub fn replace(&self, controller: Box<dyn Controller>) {
        lock(&self.0).controller = controller;
    }

    pub fn replace_brutal(&self, mut controller: Brutal) {
        let mut state = lock(&self.0);
        controller.on_mtu_update(state.mtu);
        state.controller = Box::new(controller);
    }
}

impl Controller for Switch {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        lock(&self.0)
            .controller
            .on_sent(now, bytes, last_packet_number);
    }

    fn on_packet_lost(&mut self, bytes: u16, pn: u64, now: Instant) {
        lock(&self.0).controller.on_packet_lost(bytes, pn, now);
    }

    fn metrics(&self) -> ControllerMetrics {
        lock(&self.0).controller.metrics()
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        lock(&self.0)
            .controller
            .on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_acked: Option<u64>,
    ) {
        lock(&self.0)
            .controller
            .on_end_acks(now, in_flight, app_limited, largest_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        persistent: bool,
        lost_bytes: u64,
    ) {
        lock(&self.0)
            .controller
            .on_congestion_event(now, sent, persistent, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let mut state = lock(&self.0);
        state.mtu = new_mtu;
        state.controller.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        lock(&self.0).controller.window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        lock(&self.0).controller.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Builds the starting controller and keeps the handle that replaces it.
pub struct SwitchFactory {
    initial: Arc<dyn ControllerFactory + Send + Sync>,
    handle: Mutex<Option<Switch>>,
}

impl SwitchFactory {
    pub fn new(initial: Arc<dyn ControllerFactory + Send + Sync>) -> Arc<Self> {
        Arc::new(SwitchFactory {
            initial,
            handle: Mutex::new(None),
        })
    }

    pub fn handle(&self) -> Option<Switch> {
        lock(&self.handle).clone()
    }
}

impl ControllerFactory for SwitchFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let inner = self.initial.clone().build(now, current_mtu);
        let switch = Switch(Arc::new(Mutex::new(SwitchState {
            controller: inner,
            mtu: current_mtu,
        })));
        *lock(&self.handle) = Some(switch.clone());
        Box::new(switch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_window_and_pacing_are_independent() {
        let start = Instant::now();
        let mut h2 = Brutal::hysteria2(1_000_000, Duration::ZERO, start);
        assert_eq!(h2.reference_window(), UNKNOWN_RTT_WINDOW);
        h2.rtt = Duration::from_millis(100);
        assert_eq!(h2.reference_window(), 200_000);
        assert_eq!(h2.metrics().pacing_rate, Some(8_000_000));
        assert_eq!(h2.metrics().send_quantum, Some(12_520));
    }

    #[test]
    fn negotiated_controller_uses_the_established_rtt_immediately() {
        let now = Instant::now();
        let h2 = Brutal::hysteria2(12_500_000, Duration::from_millis(40), now);
        assert_eq!(h2.reference_window(), 1_000_000);
    }

    #[test]
    fn actual_packet_losses_ignore_size_and_ecn() {
        let start = Instant::now();
        let mut brutal = Brutal::hysteria2(1_000_000, Duration::ZERO, start);
        brutal.slot_mut(0).unwrap().acks = 90;
        for pn in 0..10 {
            brutal.on_packet_lost(100, pn, start);
        }
        assert!((brutal.ack_rate - 0.9).abs() < f64::EPSILON);
        brutal.on_congestion_event(start, start, false, 0);
        assert!((brutal.ack_rate - 0.9).abs() < f64::EPSILON);
        assert_eq!(brutal.slot_mut(0).unwrap().losses, 10);
        assert_eq!(brutal.pacing_rate(), 1_111_111);
    }

    #[test]
    fn sample_threshold_floor_and_expiry_follow_reference() {
        let start = Instant::now();
        let mut brutal = Brutal::hysteria2(1_000_000, Duration::ZERO, start);
        for pn in 0..49 {
            brutal.on_packet_lost(100, pn, start);
        }
        assert_eq!(brutal.ack_rate, 1.0);
        brutal.on_packet_lost(100, 49, start);
        assert_eq!(brutal.ack_rate, MIN_ACK_RATE);
        brutal.refresh_ack_rate(10);
        assert_eq!(brutal.ack_rate, 1.0);
    }

    #[test]
    fn burst_uses_reference_interval_and_current_mtu() {
        let start = Instant::now();
        let mut h2 = Brutal::hysteria2(12_500_000, Duration::ZERO, start);
        assert_eq!(h2.burst(), 50_000);
        h2.on_mtu_update(9000);
        assert_eq!(h2.burst(), 90_000);
    }

    #[test]
    fn small_windows_allow_a_whole_packet() {
        let start = Instant::now();
        let brutal = Brutal::hysteria2(1_000, Duration::from_millis(1), start);
        assert!(brutal.window() > brutal.mtu);
    }

    #[test]
    fn unknown_rtt_admission_matches_reference_with_buffered_packets() {
        let now = Instant::now();
        let mut brutal = Brutal::hysteria2(1_000, Duration::ZERO, now);
        brutal.on_mtu_update(9000);
        assert_eq!(brutal.reference_window(), UNKNOWN_RTT_WINDOW);
        assert_eq!(brutal.initial_window(), brutal.window());
        for pending in [0, 9000] {
            for total_in_flight in [9000, 10_239, 10_240, 10_241] {
                let tracked = total_in_flight - pending;
                let quinn_admits = tracked + pending + brutal.mtu < brutal.window();
                assert_eq!(quinn_admits, total_in_flight <= UNKNOWN_RTT_WINDOW);
            }
        }
    }

    #[test]
    fn switching_forwards_pacing_and_loss_notifications() {
        let start = Instant::now();
        let cubic = || Arc::new(quinn::congestion::CubicConfig::default()).build(start, 1200);
        let mut switch = Switch(Arc::new(Mutex::new(SwitchState {
            controller: cubic(),
            mtu: 1200,
        })));
        assert!(switch.metrics().send_quantum.is_none());
        switch.replace_brutal(Brutal::hysteria2(1_000_000, Duration::ZERO, start));
        for pn in 0..50 {
            switch.on_packet_lost(100, pn, start);
        }
        assert_eq!(switch.metrics().pacing_rate, Some(10_000_000));
        assert_eq!(switch.metrics().send_quantum, Some(12_000));
        switch.replace(cubic());
        assert!(switch.metrics().send_quantum.is_none());
    }

    #[test]
    fn brutal_replacement_keeps_the_detected_path_mtu() {
        let now = Instant::now();
        let factory = SwitchFactory::new(Arc::new(quinn::congestion::CubicConfig::default()));
        let mut controller = factory.clone().build(now, 1200);
        controller.on_mtu_update(9000);
        let switch = factory.handle().unwrap();
        switch.replace_brutal(Brutal::hysteria2(1_000, Duration::from_millis(1), now));
        assert!(controller.window() > 9000);
        assert_eq!(controller.metrics().send_quantum, Some(90_000));
        controller.on_mtu_update(1400);
        assert!(controller.window() > 1400);
        assert_eq!(controller.metrics().send_quantum, Some(14_000));
    }

    #[test]
    fn unselected_protocols_keep_their_original_controller_contract() {
        let start = Instant::now();
        let mut brutal = Brutal::new(1_000_000, 1200, start);
        assert_eq!(brutal.window(), UNKNOWN_RTT_WINDOW);
        assert_eq!(brutal.initial_window(), UNKNOWN_RTT_WINDOW);
        assert!(brutal.metrics().send_quantum.is_none());
        assert!(brutal.metrics().pacing_rate.is_none());
        brutal.rtt = Duration::from_millis(100);
        assert_eq!(brutal.window(), 125_000);
        brutal.rtt = Duration::from_micros(1);
        assert_eq!(brutal.window(), 12_000);
        for _ in 0..100 {
            brutal.slot_mut(0).unwrap().acks += 1;
        }
        brutal.on_packet_lost(100, 0, start);
        assert_eq!(brutal.slot_mut(0).unwrap().losses, 0);
        brutal.on_congestion_event(start, start, false, 1200 * 100);
        assert!((brutal.ack_rate - 0.8).abs() < f64::EPSILON);
        brutal.on_congestion_event(start, start, false, 0);
        assert_eq!(brutal.slot_mut(0).unwrap().losses, 101);
    }
}
