#![cfg(all(not(target_os = "wasi"), not(target_os = "emscripten")))]

use std::task::Context;

#[cfg(not(loom))]
use futures::task::noop_waker_ref;

use crate::loom::sync::atomic::{AtomicBool, Ordering};
use crate::loom::sync::Arc;
use crate::loom::thread;

use super::entry::NANOS_PER_TICK;
use super::TimerEntry;

// Concord: entry deadlines are nanoseconds.
fn ms(n: u64) -> u64 {
    n * NANOS_PER_TICK
}

fn block_on<T>(f: impl std::future::Future<Output = T>) -> T {
    #[cfg(loom)]
    return loom::future::block_on(f);

    #[cfg(not(loom))]
    {
        let rt = crate::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(f)
    }
}

fn model(f: impl Fn() + Send + Sync + 'static) {
    #[cfg(loom)]
    loom::model(f);

    #[cfg(not(loom))]
    f();
}

fn rt(start_paused: bool) -> crate::runtime::Runtime {
    crate::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(start_paused)
        .build()
        .unwrap()
}

#[test]
fn single_timer() {
    model(|| {
        let rt = rt(false);
        let handle = rt.handle();

        let inner = handle.inner.clone();
        let jh = thread::spawn(move || {
            let entry = TimerEntry::new(inner.clone());
            pin!(entry);
            entry.as_mut().init(inner.driver().now() + ms(1000));

            block_on(std::future::poll_fn(|cx| entry.as_mut().poll_elapsed(cx))).unwrap();
        });

        thread::yield_now();

        let time = handle.inner.driver().time();
        let clock = handle.inner.driver().clock();

        // advance 2s
        time.process_at_time(time.time_source().now_nanos(clock) + 2_000_000_000);

        jh.join().unwrap();
    })
}

#[test]
fn drop_timer() {
    model(|| {
        let rt = rt(false);
        let handle = rt.handle();

        let inner = handle.inner.clone();
        let jh = thread::spawn(move || {
            let entry = TimerEntry::new(inner.clone());
            pin!(entry);
            entry.as_mut().init(inner.driver().now() + ms(1000));

            let _ = entry
                .as_mut()
                .poll_elapsed(&mut Context::from_waker(futures::task::noop_waker_ref()));
            let _ = entry
                .as_mut()
                .poll_elapsed(&mut Context::from_waker(futures::task::noop_waker_ref()));
        });

        thread::yield_now();

        let time = handle.inner.driver().time();
        let clock = handle.inner.driver().clock();

        // advance 2s in the future.
        time.process_at_time(time.time_source().now_nanos(clock) + 2_000_000_000);

        jh.join().unwrap();
    })
}

#[test]
fn change_waker() {
    model(|| {
        let rt = rt(false);
        let handle = rt.handle();

        let inner = handle.inner.clone();
        let jh = thread::spawn(move || {
            let entry = TimerEntry::new(inner.clone());
            pin!(entry);
            entry.as_mut().init(inner.driver().now() + ms(1000));

            let _ = entry
                .as_mut()
                .poll_elapsed(&mut Context::from_waker(futures::task::noop_waker_ref()));

            block_on(std::future::poll_fn(|cx| entry.as_mut().poll_elapsed(cx))).unwrap();
        });

        thread::yield_now();

        let time = handle.inner.driver().time();
        let clock = handle.inner.driver().clock();

        // advance 2s
        time.process_at_time(time.time_source().now_nanos(clock) + 2_000_000_000);

        jh.join().unwrap();
    })
}

#[test]
fn reset_future() {
    model(|| {
        let finished_early = Arc::new(AtomicBool::new(false));

        let rt = rt(false);
        let handle = rt.handle();

        let inner = handle.clone().inner;
        let finished_early_ = finished_early.clone();
        let start = handle.inner.driver().now();

        let jh = thread::spawn(move || {
            let entry = TimerEntry::new(inner.clone());
            pin!(entry);
            entry.as_mut().init(start + ms(1000));

            let _ = entry
                .as_mut()
                .poll_elapsed(&mut Context::from_waker(futures::task::noop_waker_ref()));

            entry.as_mut().reset(start + ms(2000));

            // shouldn't complete before 2s
            block_on(std::future::poll_fn(|cx| entry.as_mut().poll_elapsed(cx))).unwrap();

            finished_early_.store(true, Ordering::Relaxed);
        });

        thread::yield_now();

        let handle = handle.inner.driver().time();

        handle.process_at_time(start + ms(1500));

        assert!(!finished_early.load(Ordering::Relaxed));

        handle.process_at_time(start + ms(2500));

        jh.join().unwrap();

        assert!(finished_early.load(Ordering::Relaxed));
    })
}

#[test]
fn interval_poll_tick_races_with_fire() {
    model(|| {
        let rt = rt(false);
        let handle = rt.handle().clone();

        let jh = thread::spawn(move || {
            let _guard = handle.enter();
            let mut interval = crate::time::interval_at(
                crate::time::Instant::now() + crate::time::Duration::from_secs(1),
                crate::time::Duration::from_secs(1),
            );
            let mut cx = Context::from_waker(futures::task::noop_waker_ref());
            let _ = interval.poll_tick(&mut cx);
            let _ = interval.poll_tick(&mut cx);
        });

        let time = rt.handle().inner.driver().time();
        let clock = rt.handle().inner.driver().clock();
        time.process_at_time(time.time_source().now_nanos(clock) + 2_000_000_000);

        jh.join().unwrap();
    })
}

#[cfg(not(loom))]
fn normal_or_miri<T>(normal: T, miri: T) -> T {
    if cfg!(miri) {
        miri
    } else {
        normal
    }
}

#[test]
#[cfg(not(loom))]
fn poll_process_levels() {
    let rt = rt(true);
    let handle = rt.handle();

    let mut entries = vec![];

    for i in 0..normal_or_miri(1024, 64) {
        let mut entry = Box::pin(TimerEntry::new(handle.inner.clone()));
        entry.as_mut().init(handle.inner.driver().now() + ms(i));

        let _ = entry
            .as_mut()
            .poll_elapsed(&mut Context::from_waker(noop_waker_ref()));

        entries.push(entry);
    }

    for t in 1..normal_or_miri(1024, 64) {
        handle.inner.driver().time().process_at_time(ms(t));

        for (deadline, future) in entries.iter_mut().enumerate() {
            let mut context = Context::from_waker(noop_waker_ref());
            if deadline as u64 <= t {
                assert!(future.as_mut().poll_elapsed(&mut context).is_ready());
            } else {
                assert!(future.as_mut().poll_elapsed(&mut context).is_pending());
            }
        }
    }
}

#[test]
#[cfg(not(loom))]
fn poll_process_levels_targeted() {
    let mut context = Context::from_waker(noop_waker_ref());

    let rt = rt(true);
    let handle = rt.handle();

    let e1 = TimerEntry::new(handle.inner.clone());
    pin!(e1);
    e1.as_mut().init(handle.inner.driver().now() + ms(193));

    let handle = handle.inner.driver().time();

    handle.process_at_time(ms(62));
    assert!(e1.as_mut().poll_elapsed(&mut context).is_pending());
    handle.process_at_time(ms(192));
    handle.process_at_time(ms(192));
}

#[test]
#[cfg(not(loom))]
fn instant_to_tick_max() {
    use crate::runtime::time::entry::MAX_SAFE_MILLIS_DURATION;

    let rt = rt(true);
    let handle = rt.handle().inner.driver().time();

    let start_time = handle.time_source.start_time();
    let long_future = start_time + std::time::Duration::from_millis(MAX_SAFE_MILLIS_DURATION + 1);

    assert!(handle.time_source.instant_to_tick(long_future) <= MAX_SAFE_MILLIS_DURATION);
}

// Concord: a timer fires once the clock reaches its nanosecond deadline, never earlier, and an entry waiting out
// the rest of its millisecond on the held list can be cancelled, reset and shut down like any other.
#[cfg(not(loom))]
mod concord_tests {
    use super::*;
    use crate::time::{Duration, Instant};
    use std::pin::Pin;

    fn is_ready(entry: Pin<&mut TimerEntry>) -> bool {
        entry
            .poll_elapsed(&mut Context::from_waker(noop_waker_ref()))
            .is_ready()
    }

    fn next_wake(handle: &crate::runtime::Handle) -> Option<u64> {
        handle.inner.driver().time().inner.lock().wheel.next_wake_nanos()
    }

    #[test]
    fn a_deadline_inside_a_millisecond_fires_at_its_nanosecond() {
        let rt = rt(true);
        let handle = rt.handle();
        let start = handle.inner.driver().now();
        let deadline = start + ms(10) + 400_000;
        let entry = TimerEntry::new(handle.inner.clone());
        pin!(entry);
        entry.as_mut().init(deadline);
        assert_eq!(next_wake(handle), Some(deadline));

        let time = handle.inner.driver().time();
        time.process_at_time(start + ms(10));
        assert!(!is_ready(entry.as_mut()));
        assert_eq!(next_wake(handle), Some(deadline));
        time.process_at_time(deadline - 1);
        assert!(!is_ready(entry.as_mut()));
        time.process_at_time(deadline);
        assert!(is_ready(entry.as_mut()));
        assert_eq!(next_wake(handle), None);
    }

    #[test]
    fn the_next_wake_is_the_earliest_deadline_in_the_slot() {
        let rt = rt(true);
        let handle = rt.handle();
        let start = handle.inner.driver().now();
        let late = TimerEntry::new(handle.inner.clone());
        let early = TimerEntry::new(handle.inner.clone());
        pin!(late);
        pin!(early);
        late.as_mut().init(start + ms(5) + 900_000);
        early.as_mut().init(start + ms(5) + 100_000);
        assert_eq!(next_wake(handle), Some(start + ms(5) + 100_000));

        let time = handle.inner.driver().time();
        time.process_at_time(start + ms(5) + 100_000);
        assert!(is_ready(early.as_mut()));
        assert!(!is_ready(late.as_mut()));
        assert_eq!(next_wake(handle), Some(start + ms(5) + 900_000));
    }

    #[test]
    fn a_held_entry_can_be_cancelled() {
        let rt = rt(true);
        let handle = rt.handle();
        let start = handle.inner.driver().now();
        let time = handle.inner.driver().time();
        {
            let entry = TimerEntry::new(handle.inner.clone());
            pin!(entry);
            entry.as_mut().init(start + ms(3) + 500_000);
            time.process_at_time(start + ms(3));
            assert!(!is_ready(entry.as_mut()));
        }
        assert_eq!(next_wake(handle), None);
        time.process_at_time(start + ms(4));
    }

    #[test]
    fn a_held_entry_reset_earlier_fires_at_the_new_deadline() {
        let rt = rt(true);
        let handle = rt.handle();
        let start = handle.inner.driver().now();
        let time = handle.inner.driver().time();
        let entry = TimerEntry::new(handle.inner.clone());
        pin!(entry);
        entry.as_mut().init(start + ms(7) + 800_000);
        time.process_at_time(start + ms(7) + 100_000);
        entry.as_mut().reset(start + ms(7) + 200_000);
        assert_eq!(next_wake(handle), Some(start + ms(7) + 200_000));
        time.process_at_time(start + ms(7) + 199_999);
        assert!(!is_ready(entry.as_mut()));
        time.process_at_time(start + ms(7) + 200_000);
        assert!(is_ready(entry.as_mut()));
    }

    #[test]
    fn a_held_entry_extended_past_its_millisecond_returns_to_the_wheel() {
        let rt = rt(true);
        let handle = rt.handle();
        let start = handle.inner.driver().now();
        let time = handle.inner.driver().time();
        let entry = TimerEntry::new(handle.inner.clone());
        pin!(entry);
        entry.as_mut().init(start + ms(9) + 500_000);
        time.process_at_time(start + ms(9));
        entry.as_mut().reset(start + ms(12) + 300_000);
        time.process_at_time(start + ms(9) + 600_000);
        assert!(!is_ready(entry.as_mut()));
        time.process_at_time(start + ms(12));
        assert!(!is_ready(entry.as_mut()));
        assert_eq!(next_wake(handle), Some(start + ms(12) + 300_000));
        time.process_at_time(start + ms(12) + 300_000);
        assert!(is_ready(entry.as_mut()));
    }

    #[test]
    fn a_registration_inside_the_processed_millisecond_waits_for_its_deadline() {
        let rt = rt(true);
        let handle = rt.handle();
        let start = handle.inner.driver().now();
        let time = handle.inner.driver().time();
        time.process_at_time(start + ms(2) + 100_000);
        let entry = TimerEntry::new(handle.inner.clone());
        pin!(entry);
        entry.as_mut().init(start + ms(2) + 700_000);
        assert!(!is_ready(entry.as_mut()));
        assert_eq!(next_wake(handle), Some(start + ms(2) + 700_000));
        time.process_at_time(start + ms(2) + 700_000);
        assert!(is_ready(entry.as_mut()));

        let past = TimerEntry::new(handle.inner.clone());
        pin!(past);
        past.as_mut().init(start + ms(2) + 50_000);
        assert!(is_ready(past.as_mut()));
    }

    #[test]
    fn shutdown_fires_held_entries() {
        let rt = rt(true);
        let handle = rt.handle();
        let start = handle.inner.driver().now();
        let time = handle.inner.driver().time();
        let entry = TimerEntry::new(handle.inner.clone());
        pin!(entry);
        entry.as_mut().init(start + ms(4) + 300_000);
        time.process_at_time(start + ms(4));
        time.process_at_time(u64::MAX);
        assert!(is_ready(entry.as_mut()));
    }

    #[test]
    fn a_paused_sleep_ends_exactly_at_a_sub_millisecond_deadline() {
        let rt = rt(true);
        rt.block_on(async {
            let mut seed = 0x2545_f491_4f6c_dd1d_u64;
            for _ in 0..200 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let wait = Duration::from_nanos(50_000 + seed % 3_000_000);
                let start = Instant::now();
                crate::time::sleep(wait).await;
                assert_eq!(start.elapsed(), wait);
            }
        });
    }

    #[test]
    fn concurrent_paused_sleeps_each_end_at_their_own_deadline() {
        let rt = rt(true);
        rt.block_on(async {
            let start = Instant::now();
            let waits = [1_200_000, 1_700_000, 1_000_001, 63_999_999, 64_000_001, 200_000_123];
            let ends = futures::future::join_all(waits.map(|nanos| async move {
                crate::time::sleep(Duration::from_nanos(nanos)).await;
                Instant::now() - start
            }))
            .await;
            for (nanos, end) in waits.into_iter().zip(ends) {
                assert_eq!(end, Duration::from_nanos(nanos));
            }
        });
    }
}
