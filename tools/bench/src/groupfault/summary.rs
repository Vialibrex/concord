//! What one run showed, computed from its event list alone.

use std::collections::BTreeMap;

use serde::Serialize;

use super::record::Event;

pub struct Meta {
    pub scenario: String,
    pub group_type: String,
    pub fault: String,
    /// The node the fault hit, counted from 1.
    pub node: usize,
    /// When the fault began, in seconds since the run began.
    pub t0: f64,
    /// How long the observed phase lasted, in seconds.
    pub observe_s: f64,
    /// The source address the origin sees for each node, in node order.
    pub egress: Vec<String>,
}

#[derive(Debug, Default, Serialize, PartialEq)]
pub struct PhaseStats {
    pub requests: u64,
    pub failures: u64,
    pub failure_rate: f64,
    pub errors: BTreeMap<String, u64>,
    pub total_ms_p50: Option<f64>,
    pub total_ms_p95: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub scenario: String,
    pub group_type: String,
    pub fault: String,
    pub fault_node: usize,
    pub t0_s: f64,
    pub phases: BTreeMap<String, PhaseStats>,
    /// Failures over failures plus successes through the faulted node, in the observed phase: the failure
    /// rate of requests that took that node, when it is the only faulty one.
    pub faulted_node_failure_share: Option<f64>,
    pub first_failure_after_t0_s: Option<f64>,
    /// Seconds from the fault's start to the last failed request, issued in the observed phase.
    pub recovery_s: Option<f64>,
    pub switches_total: u64,
    pub switches_per_site_per_hour: BTreeMap<String, f64>,
    pub requests_per_node: BTreeMap<String, BTreeMap<String, u64>>,
    pub probes_per_node: BTreeMap<String, BTreeMap<String, u64>>,
    pub group_selected: Vec<(f64, String)>,
}

fn percentile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((sorted.len() - 1) as f64 * q).round() as usize;
    Some(sorted[rank])
}

pub fn summarize(events: &[Event], meta: &Meta) -> Summary {
    let mut phases: BTreeMap<String, (PhaseStats, Vec<f64>)> = BTreeMap::new();
    let mut per_node: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut probes: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    let mut by_site: BTreeMap<usize, Vec<(f64, usize)>> = BTreeMap::new();
    let mut failure_times = Vec::new();
    let mut observed_ok_on_fault_node = 0u64;
    let mut observed_failures = 0u64;
    let mut group_selected = Vec::new();
    for event in events {
        match event {
            Event::Request {
                t,
                site,
                ok,
                class,
                total_ms,
                node,
                phase,
                ..
            } => {
                let (stats, times) = phases.entry(phase.clone()).or_default();
                stats.requests += 1;
                if *ok {
                    times.push(*total_ms);
                } else {
                    stats.failures += 1;
                    *stats
                        .errors
                        .entry(class.clone().unwrap_or_default())
                        .or_default() += 1;
                }
                if *ok && let Some(node) = node {
                    *per_node
                        .entry(phase.clone())
                        .or_default()
                        .entry(format!("node{node}"))
                        .or_default() += 1;
                    if phase == "observe" {
                        by_site.entry(*site).or_default().push((*t, *node));
                        observed_ok_on_fault_node += u64::from(*node == meta.node);
                    }
                }
                if !*ok && phase == "observe" {
                    failure_times.push(*t);
                    observed_failures += 1;
                }
            }
            Event::Probe { src, phase, .. } => {
                let node = meta
                    .egress
                    .iter()
                    .position(|e| e == src)
                    .map_or_else(|| src.clone(), |i| format!("node{}", i + 1));
                *probes
                    .entry(phase.clone())
                    .or_default()
                    .entry(node)
                    .or_default() += 1;
            }
            Event::Group { t, now } => group_selected.push((*t, now.clone())),
            Event::Mark { .. } => {}
        }
    }
    let phases = phases
        .into_iter()
        .map(|(name, (mut stats, mut times))| {
            stats.failure_rate = stats.failures as f64 / stats.requests.max(1) as f64;
            times.sort_by(f64::total_cmp);
            stats.total_ms_p50 = percentile(&times, 0.5);
            stats.total_ms_p95 = percentile(&times, 0.95);
            (name, stats)
        })
        .collect();
    let mut switches_total = 0u64;
    let hours = meta.observe_s / 3600.0;
    let per_hour = |count: u64| {
        if hours > 0.0 {
            count as f64 / hours
        } else {
            0.0
        }
    };
    let switches_per_site_per_hour = by_site
        .into_iter()
        .map(|(site, mut seen)| {
            seen.sort_by(|a, b| a.0.total_cmp(&b.0));
            let switches = seen.windows(2).filter(|w| w[0].1 != w[1].1).count() as u64;
            switches_total += switches;
            (format!("site{site}"), per_hour(switches))
        })
        .collect();
    let denominator = observed_failures + observed_ok_on_fault_node;
    Summary {
        scenario: meta.scenario.clone(),
        group_type: meta.group_type.clone(),
        fault: meta.fault.clone(),
        fault_node: meta.node,
        t0_s: meta.t0,
        phases,
        faulted_node_failure_share: (denominator > 0)
            .then(|| observed_failures as f64 / denominator as f64),
        first_failure_after_t0_s: failure_times
            .iter()
            .copied()
            .min_by(f64::total_cmp)
            .map(|t| t - meta.t0),
        recovery_s: failure_times
            .iter()
            .copied()
            .max_by(f64::total_cmp)
            .map(|t| t - meta.t0),
        switches_total,
        switches_per_site_per_hour,
        requests_per_node: per_node,
        probes_per_node: probes,
        group_selected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(t: f64, site: usize, node: Option<usize>, phase: &str) -> Event {
        Event::Request {
            t,
            site,
            ok: node.is_some(),
            class: node.is_none().then(|| "timeout_http".to_string()),
            total_ms: 10.0,
            ttfb_ms: node.map(|_| 5.0),
            node,
            phase: phase.into(),
        }
    }

    fn meta() -> Meta {
        Meta {
            scenario: "S1".into(),
            group_type: "url-test".into(),
            fault: "blackhole".into(),
            node: 2,
            t0: 60.0,
            observe_s: 360.0,
            egress: vec!["10.61.1.1".into(), "10.61.2.1".into()],
        }
    }

    #[test]
    fn a_failure_window_and_a_move_off_the_faulted_node_are_counted() {
        let events = vec![
            request(10.0, 1, Some(2), "warmup"),
            request(61.0, 1, None, "observe"),
            request(75.0, 1, None, "observe"),
            request(90.0, 1, Some(1), "observe"),
            request(100.0, 2, Some(1), "observe"),
            Event::Probe {
                t: 80.0,
                src: "10.61.1.1".into(),
                phase: "observe".into(),
            },
        ];
        let summary = summarize(&events, &meta());
        assert_eq!(summary.phases["observe"].failures, 2);
        assert_eq!(summary.recovery_s, Some(15.0));
        assert_eq!(summary.first_failure_after_t0_s, Some(1.0));
        assert_eq!(summary.switches_total, 0);
        assert_eq!(summary.faulted_node_failure_share, Some(1.0));
        assert_eq!(summary.probes_per_node["observe"]["node1"], 1);
        assert_eq!(summary.requests_per_node["warmup"]["node2"], 1);
    }

    #[test]
    fn a_site_that_changes_node_counts_a_switch_per_hour_of_the_observed_phase() {
        let events = vec![
            request(70.0, 3, Some(1), "observe"),
            request(80.0, 3, Some(2), "observe"),
            request(90.0, 3, Some(1), "observe"),
        ];
        let summary = summarize(&events, &meta());
        assert_eq!(summary.switches_total, 2);
        assert_eq!(summary.switches_per_site_per_hour["site3"], 20.0);
    }
}
