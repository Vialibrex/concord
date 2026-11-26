//! Regression tests for the vendored tokio multi-thread scheduler fixes.

use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::runtime::Builder;

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "loopback UDP sockets in scheduler regression test"
)]
fn driver_batch_wake_does_not_self_notify_extra_park() {
    let rt = Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();

    let (sock1, sock2, addr1, addr2) = rt.block_on(async {
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a1 = s1.local_addr().unwrap();
        let a2 = s2.local_addr().unwrap();
        (s1, s2, a1, a2)
    });
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();
    let (gate_tx, gate_rx) =
        tokio::sync::mpsc::unbounded_channel::<(mpsc::Sender<()>, mpsc::Receiver<()>)>();

    const ROUNDS: u64 = 20;
    let h1 = rt.spawn(async move {
        let mut buf = [0u8; 8];
        for _ in 0..ROUNDS {
            sock1.recv(&mut buf).await.unwrap();
            tx1.send(()).unwrap();
        }
    });
    let h2 = rt.spawn(async move {
        let mut buf = [0u8; 8];
        for _ in 0..ROUNDS {
            sock2.recv(&mut buf).await.unwrap();
            tx2.send(()).unwrap();
        }
    });
    let h_gate = rt.spawn(async move {
        let mut gate_rx = gate_rx;
        while let Some((ready_tx, go_rx)) = gate_rx.recv().await {
            ready_tx.send(()).unwrap();
            go_rx.recv().unwrap();
        }
    });

    let metrics = rt.metrics();
    for _ in 0..200 {
        if metrics.worker_park_unpark_count(0) % 2 == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let parks_before = metrics.worker_park_count(0);
    for _ in 0..ROUNDS {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel();
        gate_tx.send((ready_tx, go_rx)).unwrap();
        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        sender.send_to(b"1", addr1).unwrap();
        sender.send_to(b"2", addr2).unwrap();
        go_tx.send(()).unwrap();

        rx1.recv_timeout(Duration::from_secs(2)).unwrap();
        rx2.recv_timeout(Duration::from_secs(2)).unwrap();

        for _ in 0..200 {
            if metrics.worker_park_unpark_count(0) % 2 == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    let parks_delta = metrics.worker_park_count(0) - parks_before;

    drop(gate_tx);
    rt.block_on(async {
        h1.await.unwrap();
        h2.await.unwrap();
        h_gate.await.unwrap();
    });

    // Without the fix, each driver batch wake self-notifies and leaves the worker's
    // parker `NOTIFIED`, adding 1-2 spurious parks per round (~60-80 parks over 20 rounds
    // vs ~40 parks with the fix).
    assert!(
        parks_delta <= ROUNDS * 2 + 6,
        "driver batch wake caused extra noop parks: parks_delta={parks_delta} over {ROUNDS} rounds"
    );
}

#[test]
fn single_remote_task_wakes_only_one_worker() {
    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let metrics = rt.metrics();
    for _ in 0..200 {
        if metrics.worker_park_unpark_count(0) >= 1 && metrics.worker_park_unpark_count(1) >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(metrics.worker_park_unpark_count(0) % 2, 1);
    assert_eq!(metrics.worker_park_unpark_count(1) % 2, 1);

    const ROUNDS: u64 = 20;
    let parks_before = metrics.worker_park_count(0) + metrics.worker_park_count(1);

    for _ in 0..ROUNDS {
        let (tx, rx) = mpsc::channel();
        rt.spawn(async move {
            tx.send(()).unwrap();
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();

        for _ in 0..200 {
            if metrics.worker_park_unpark_count(0) % 2 == 1
                && metrics.worker_park_unpark_count(1) % 2 == 1
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    let parks_delta = (metrics.worker_park_count(0) + metrics.worker_park_count(1)) - parks_before;
    assert!(
        parks_delta <= ROUNDS + 2,
        "single remote task spuriously woke second worker: parks_delta={parks_delta} over {ROUNDS} rounds"
    );
}

#[test]
fn two_remote_tasks_rendezvous_across_workers() {
    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let metrics = rt.metrics();

    for _ in 0..8 {
        for _ in 0..200 {
            if metrics.worker_park_unpark_count(0) % 2 == 1
                && metrics.worker_park_unpark_count(1) % 2 == 1
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        let pair = Arc::new((Mutex::new(0usize), Condvar::new()));
        let p1 = pair.clone();
        let p2 = pair.clone();
        let (tx, rx) = mpsc::channel();
        let tx2 = tx.clone();

        let rendezvous = |pair: Arc<(Mutex<usize>, Condvar)>| -> bool {
            let (lock, cvar) = &*pair;
            let mut count = concord_common::sync::lock(lock);
            *count += 1;
            if *count == 2 {
                cvar.notify_all();
                true
            } else {
                let (guard, _) = cvar
                    .wait_timeout_while(count, Duration::from_secs(2), |c| *c < 2)
                    .unwrap();
                *guard == 2
            }
        };

        rt.spawn(async move {
            tx.send(rendezvous(p1)).unwrap();
        });
        rt.spawn(async move {
            tx2.send(rendezvous(p2)).unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "first task timed out waiting for second worker"
        );
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "second task timed out waiting for first worker"
        );
    }
}

#[test]
fn single_self_notified_task_does_not_wake_parked_worker() {
    use std::future::poll_fn;
    use std::task::Poll;

    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let metrics = rt.metrics();
    for _ in 0..200 {
        if metrics.worker_park_unpark_count(0) % 2 == 1
            && metrics.worker_park_unpark_count(1) % 2 == 1
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(metrics.worker_park_unpark_count(0) % 2, 1);
    assert_eq!(metrics.worker_park_unpark_count(1) % 2, 1);

    const YIELDS: usize = 20;
    let parks_before = metrics.worker_park_count(0) + metrics.worker_park_count(1);
    let (done_tx, done_rx) = mpsc::channel();

    rt.spawn(async move {
        let mut left = YIELDS;
        poll_fn(|cx| {
            // Pause briefly per poll so a spuriously woken peer has time to
            // wake from the OS driver, scan empty queues, and re-park before
            // the next self-notified yield.
            std::thread::sleep(Duration::from_millis(2));
            if left == 0 {
                Poll::Ready(())
            } else {
                left -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        done_tx.send(()).unwrap();
    });

    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    for _ in 0..200 {
        if metrics.worker_park_unpark_count(0) % 2 == 1
            && metrics.worker_park_unpark_count(1) % 2 == 1
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    let parks_delta = (metrics.worker_park_count(0) + metrics.worker_park_count(1)) - parks_before;
    // Only the worker running the single task should unpark and re-park; waking the
    // parked peer on every `PollFuture::Notified` yield produces >= YIELDS parks.
    assert!(
        parks_delta <= 4,
        "single self-notified task spuriously woke parked worker: parks_delta={parks_delta} over {YIELDS} yields"
    );
}

#[test]
fn self_notified_task_with_peer_in_lifo_slot_wakes_parked_worker() {
    use std::future::poll_fn;
    use std::task::Poll;

    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let metrics = rt.metrics();

    for _ in 0..8 {
        for _ in 0..200 {
            if metrics.worker_park_unpark_count(0) % 2 == 1
                && metrics.worker_park_unpark_count(1) % 2 == 1
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        let pair = Arc::new((Mutex::new(0usize), Condvar::new()));
        let p1 = pair.clone();
        let p2 = pair.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let done_tx2 = done_tx.clone();

        let rendezvous = |pair: Arc<(Mutex<usize>, Condvar)>| -> bool {
            let (lock, cvar) = &*pair;
            let mut count = concord_common::sync::lock(lock);
            *count += 1;
            if *count == 2 {
                cvar.notify_all();
                true
            } else {
                let (guard, _) = cvar
                    .wait_timeout_while(count, Duration::from_secs(2), |c| *c < 2)
                    .unwrap();
                *guard == 2
            }
        };

        let (wake_tx, wake_rx) = tokio::sync::oneshot::channel::<()>();
        let h_peer = rt.spawn(async move {
            wake_rx.await.unwrap();
            done_tx2.send(rendezvous(p2)).unwrap();
        });

        for _ in 0..200 {
            if metrics.worker_park_unpark_count(0) % 2 == 1
                && metrics.worker_park_unpark_count(1) % 2 == 1
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }

        let h_yielder = rt.spawn(async move {
            let mut wake_tx = Some(wake_tx);
            poll_fn(|cx| {
                if let Some(tx) = wake_tx.take() {
                    // Waking the peer places it in `lifo_slot` without notifying; self-notifying
                    // then enters `schedule_local(is_yield = true)` with 2 runnable tasks and
                    // must wake the second worker so both tasks can rendezvous concurrently.
                    let _ = tx.send(());
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            done_tx.send(rendezvous(p1)).unwrap();
        });

        assert!(
            done_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "first task timed out waiting for peer worker after two-task yield"
        );
        assert!(
            done_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            "second task timed out waiting for peer worker after two-task yield"
        );
        rt.block_on(async {
            h_peer.await.unwrap();
            h_yielder.await.unwrap();
        });
    }
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "loopback UDP sockets in scheduler regression test"
)]
fn parked_driver_worker_handles_io_promptly_while_peer_self_yields() {
    use std::future::poll_fn;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Instant;

    let rt = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let (sock, addr) = rt.block_on(async {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = s.local_addr().unwrap();
        (s, a)
    });
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

    const ROUNDS: usize = 20;
    let (io_tx, io_rx) = mpsc::channel();
    let h_io = rt.spawn(async move {
        let mut buf = [0u8; 16];
        for _ in 0..ROUNDS {
            let n = sock.recv(&mut buf).await.unwrap();
            io_tx.send(n).unwrap();
        }
    });

    let metrics = rt.metrics();
    for _ in 0..200 {
        if metrics.worker_park_unpark_count(0) % 2 == 1
            && metrics.worker_park_unpark_count(1) % 2 == 1
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let stop = Arc::new(AtomicBool::new(false));
    let yields = Arc::new(AtomicUsize::new(0));
    let stop_c = stop.clone();
    let yields_c = yields.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let h_yield = rt.spawn(async move {
        let _ = started_tx.send(());
        poll_fn(|cx| {
            if stop_c.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                yields_c.fetch_add(1, Ordering::Relaxed);
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let mut max_latency = Duration::ZERO;
    for i in 0..ROUNDS {
        let start = Instant::now();
        sender.send_to(b"ping", addr).unwrap();
        let n = io_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| panic!("UDP I/O timed out on round {i} while peer self-yielded"));
        assert_eq!(n, 4);
        max_latency = max_latency.max(start.elapsed());
        std::thread::sleep(Duration::from_millis(1));
    }

    stop.store(true, Ordering::Release);
    rt.block_on(async {
        h_yield.await.unwrap();
        h_io.await.unwrap();
    });

    assert!(
        yields.load(Ordering::Relaxed) > 0,
        "self-yielding task did not run"
    );
    assert!(
        max_latency < Duration::from_millis(200),
        "I/O readiness delayed while peer self-yielded: max_latency={max_latency:?}"
    );
}
