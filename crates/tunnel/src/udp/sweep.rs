use super::*;

const TICK: Duration = Duration::from_secs(1);

pub(super) fn start_scanner(inner: &Arc<Inner>) {
    if inner.nat.scanning.swap(true, Ordering::AcqRel) {
        return;
    }
    inner.tasks.spawn_to_end(scan(inner.clone()));
}

/// Coarse on purpose: nothing per packet beyond storing a counter, and no task at
/// all while there is no UDP traffic.
pub(super) async fn scan(inner: Arc<Inner>) {
    let nat = &inner.nat;
    let mut tick = tokio::time::interval(TICK);
    loop {
        tick.tick().await;
        let now = nat.clock.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let limit = u32::try_from(inner.live().udp_timeout.as_secs()).unwrap_or(u32::MAX);
        let idle = |since: u32| now.wrapping_sub(since) >= limit;

        nat.flows.retain(|id, flow| {
            let keep = !idle(flow.last_active.load(Ordering::Relaxed));
            if !keep {
                flow.detach(id);
            }
            keep
        });
        nat.forget_departed();
        for slot in nat.slots.iter() {
            if let Some(session) = slot.value().get()
                && idle(session.last_active.load(Ordering::Relaxed))
            {
                session.end(ConnEnd::new(EndReason::Timeout));
                session.close();
            }
        }

        if nat.flows.is_empty() && nat.slots.is_empty() {
            nat.scanning.store(false, Ordering::Release);
            if nat.flows.is_empty() || nat.scanning.swap(true, Ordering::AcqRel) {
                return;
            }
        }
    }
}
