//! The tunnel's side of smart groups: dial reports, the flow tap and the redial.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use concord_common::{Address, BoxStream, Network, OutboundKind};
use concord_group::{FlowEnd, Outbounds, Resolved, SmartFlow};
use concord_net::{Direction, Meter, RelayEnd, RelayOutcome};
use tokio::time::Instant;

use crate::flow::FlowState;
use crate::route::Decision;
use crate::runtime::{Inner, Runtime};
use crate::table::Tracked;
use crate::tcp::{DIAL_TIMEOUT, FailedDial, dial_once};

/// The first attempt plus at most two more.
const MAX_ATTEMPTS: usize = 3;
const TLS_RECORD: u8 = 0x16;

pub(crate) struct SmartMeter<'a> {
    pub tracked: &'a Arc<Tracked>,
    pub flow: &'a SmartFlow,
}

impl Meter for SmartMeter<'_> {
    fn on_upload(&self, bytes: u64) {
        self.tracked.uploaded(bytes);
        self.flow.on_upload();
    }

    fn on_download(&self, bytes: u64) {
        self.tracked.downloaded(bytes);
        self.flow.on_download();
    }
}

pub(crate) fn flow_end(outcome: &RelayOutcome) -> FlowEnd {
    FlowEnd {
        download: outcome.download,
        remote_first: outcome
            .first_finished
            .map(|direction| direction == Direction::Download),
        cancelled: matches!(outcome.end, RelayEnd::Cancelled),
    }
}

pub(crate) fn tap(
    runtime: &Runtime,
    flow: &FlowState,
    decision: &Decision,
    head: &[u8],
) -> Option<SmartFlow> {
    if !decision.smart {
        return None;
    }
    let site = Outbounds::smart_site(&flow.meta, flow.host.as_deref())?;
    runtime
        .outbounds
        .smart_flow(&decision.chain, &site, head.first() == Some(&TLS_RECORD))
}

fn attempt_deadline(started: Instant, overall: Instant, budget: Option<Duration>) -> Instant {
    match budget {
        Some(budget) => overall.min(started + budget),
        None => overall,
    }
}

/// An attempt that only ran out of its own shortened budget says "slower than usual", not "broken".
fn budget_ran_out(err: &io::Error, deadline: Instant, overall: Instant, now: Instant) -> bool {
    err.kind() == io::ErrorKind::TimedOut && deadline < overall && now >= deadline
}

struct Attempt<'a> {
    inner: &'a Inner,
    runtime: &'a Runtime,
    site: Option<&'a str>,
}

/// An attempt cut short by its own budget, held until the flow's later attempts say what it meant.
struct Slow {
    chain: Box<[Arc<str>]>,
    kind: OutboundKind,
    elapsed: Duration,
    proxied_before: u64,
}

impl Attempt<'_> {
    fn report_failure(
        &self,
        decision: &Decision,
        err: &io::Error,
        elapsed: Duration,
        proxied_before: u64,
    ) {
        let corroborated = self.inner.table.total(true).1 > proxied_before;
        self.report(
            &decision.chain,
            decision.leaf.info().kind,
            err,
            elapsed,
            corroborated,
        );
    }

    fn report(
        &self,
        chain: &[Arc<str>],
        kind: OutboundKind,
        err: &io::Error,
        elapsed: Duration,
        corroborated: bool,
    ) {
        let outbounds = &self.runtime.outbounds;
        outbounds.smart_dial_failed(chain, self.site, err, elapsed, corroborated);
        outbounds.note_dial_failed(chain, kind, Network::Tcp, err);
    }

    /// A node that let its budget run out while another member then connected did not answer a network
    /// that works: a corroborated failure. When nothing connected, each stands on its own evidence.
    fn settle(&self, slow: Vec<Slow>, connected: bool) {
        let err = io::Error::from(io::ErrorKind::TimedOut);
        for held in slow {
            let corroborated = connected || self.inner.table.total(true).1 > held.proxied_before;
            self.report(&held.chain, held.kind, &err, held.elapsed, corroborated);
        }
    }
}

/// Dials a flow whose chain has a smart group, redialling the group's next member after a
/// node-level failure within the same overall time.
pub(crate) async fn dial(
    inner: &Inner,
    runtime: &Runtime,
    flow: &FlowState,
    mut decision: Decision,
    dst: &Address,
) -> Result<(BoxStream, Decision), FailedDial> {
    let outbounds = &runtime.outbounds;
    let site = Outbounds::smart_site(&flow.meta, flow.host.as_deref());
    let attempt = Attempt {
        inner,
        runtime,
        site: site.as_deref(),
    };
    let overall = Instant::now() + DIAL_TIMEOUT;
    let mut tried: Vec<Arc<str>> = outbounds
        .smart_member(&decision.chain)
        .into_iter()
        .collect();
    let mut attempts = 1;
    let mut slow = Vec::new();
    loop {
        let started = Instant::now();
        let budget = if attempts < MAX_ATTEMPTS {
            outbounds.smart_attempt_budget(
                &decision.chain,
                &flow.meta,
                flow.host.as_deref(),
                &tried,
            )
        } else {
            None
        };
        let deadline = attempt_deadline(started, overall, budget);
        let proxied_before = inner.table.total(true).1;
        let outcome = dial_once(inner, runtime, flow, &decision, dst, deadline).await;
        let elapsed = started.elapsed();
        let err = match outcome {
            Ok(remote) => {
                attempt.settle(slow, true);
                outbounds.smart_dial_succeeded(&decision.chain, elapsed);
                let kind = decision.leaf.info().kind;
                let remote = outbounds.watch_first_write(&decision.chain, kind, remote);
                return Ok((remote, decision));
            }
            Err(err) => err,
        };

        let now = Instant::now();
        let can_retry =
            attempts < MAX_ATTEMPTS && now < overall && Outbounds::smart_retryable(&err);
        let quiet = can_retry && budget_ran_out(&err, deadline, overall, now);
        if !quiet {
            attempt.report_failure(&decision, &err, elapsed, proxied_before);
        }
        let next = if can_retry {
            match outbounds.smart_retry(&decision.chain, &flow.meta, flow.host.as_deref(), &tried) {
                Some((
                    Resolved::Route {
                        leaf,
                        chain,
                        provider_chain,
                        exit_group,
                        ..
                    },
                    member,
                )) => Some((leaf, chain, provider_chain, exit_group, member)),
                _ => None,
            }
        } else {
            None
        };
        let Some((leaf, chain, provider_chain, exit_group, member)) = next else {
            attempt.settle(slow, false);
            if quiet {
                attempt.report_failure(&decision, &err, elapsed, proxied_before);
            }
            return Err(FailedDial::logged(flow, decision, err));
        };
        tracing::debug!(
            "[{}] dial {} --> {} error: {err}, retry through {member} (attempt {})",
            flow.network_name(),
            decision.chain_text(),
            flow.remote_text(),
            attempts + 1
        );
        if quiet {
            slow.push(Slow {
                chain: decision.chain.clone(),
                kind: decision.leaf.info().kind,
                elapsed,
                proxied_before,
            });
        }
        decision.leaf = leaf;
        decision.chain = chain;
        decision.provider_chain = provider_chain;
        decision.exit_group = exit_group;
        tried.push(member);
        attempts += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(end: RelayEnd, first_finished: Option<Direction>) -> RelayOutcome {
        RelayOutcome {
            upload: 10,
            download: 20,
            end,
            first_finished,
        }
    }

    #[test]
    fn remote_finishing_first_is_reported() {
        let end = flow_end(&outcome(RelayEnd::Eof, Some(Direction::Download)));
        assert_eq!(end.download, 20);
        assert_eq!(end.remote_first, Some(true));
        assert!(!end.cancelled);
    }

    #[test]
    fn local_finishing_first_is_reported() {
        let end = flow_end(&outcome(RelayEnd::Eof, Some(Direction::Upload)));
        assert_eq!(end.remote_first, Some(false));
    }

    #[test]
    fn a_cancelled_relay_has_no_direction() {
        let end = flow_end(&outcome(RelayEnd::Cancelled, None));
        assert_eq!(end.remote_first, None);
        assert!(end.cancelled);
    }

    #[test]
    fn an_attached_relay_reports_no_direction() {
        let end = flow_end(&outcome(RelayEnd::Error(io::Error::other("reset")), None));
        assert_eq!(end.remote_first, None);
        assert!(!end.cancelled);
    }

    #[test]
    fn the_attempt_deadline_is_the_shorter_of_budget_and_overall() {
        let started = Instant::now();
        let overall = started + Duration::from_secs(5);
        assert_eq!(
            attempt_deadline(started, overall, Some(Duration::from_secs(2))),
            started + Duration::from_secs(2)
        );
        assert_eq!(
            attempt_deadline(started, overall, Some(Duration::from_secs(9))),
            overall
        );
        assert_eq!(attempt_deadline(started, overall, None), overall);
    }

    #[test]
    fn only_a_timeout_at_a_shortened_deadline_is_slow_not_broken() {
        let now = Instant::now();
        let overall = now + Duration::from_secs(5);
        let timed_out = io::Error::from(io::ErrorKind::TimedOut);
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        let early = now + Duration::from_secs(1);
        let later = early + Duration::from_millis(1);
        assert!(budget_ran_out(&timed_out, early, overall, later));
        assert!(!budget_ran_out(&timed_out, overall, overall, overall));
        assert!(!budget_ran_out(&timed_out, early, overall, now));
        assert!(!budget_ran_out(&refused, early, overall, later));
    }
}
