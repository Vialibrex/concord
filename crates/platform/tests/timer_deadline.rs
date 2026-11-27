//! The vendored tokio fires a timer once the clock reaches its deadline, and on Linux the vendored mio waits for
//! less than a millisecond, so a wait ends just after its deadline instead of on the millisecond after it.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::time::{Duration, Instant};

const WAITS: usize = 400;
/// Half the millisecond a driver that rounds deadlines up adds to every wait: such a driver cannot pass.
const BOUND: Duration = Duration::from_micros(500);

fn waits() -> impl Iterator<Item = Duration> {
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    std::iter::repeat_with(move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        Duration::from_nanos(100_000 + seed % 2_900_000)
    })
    .take(WAITS)
}

fn median(mut overshoot: Vec<Duration>) -> Duration {
    overshoot.sort();
    overshoot[overshoot.len() / 2]
}

#[test]
fn a_tokio_sleep_ends_after_its_deadline_and_close_to_it() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let overshoot = runtime.block_on(async {
        let mut overshoot = Vec::with_capacity(WAITS);
        for wait in waits() {
            let start = Instant::now();
            tokio::time::sleep(wait).await;
            let took = start.elapsed();
            assert!(took >= wait, "a {wait:?} sleep ended after {took:?}");
            overshoot.push(took - wait);
        }
        overshoot
    });
    let median = median(overshoot);
    assert!(
        median < BOUND,
        "sleeps overshot their deadline by {median:?} at the median"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_timed_poll_waits_for_less_than_a_rounded_up_millisecond() {
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(16);
    let mut overshoot = Vec::with_capacity(WAITS);
    for wait in waits() {
        let start = Instant::now();
        poll.poll(&mut events, Some(wait)).unwrap();
        let took = start.elapsed();
        assert!(events.is_empty());
        assert!(took >= wait, "a {wait:?} poll returned after {took:?}");
        overshoot.push(took - wait);
    }
    let median = median(overshoot);
    assert!(
        median < BOUND,
        "polls overshot their timeout by {median:?} at the median"
    );
}
