use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use concord_common::sync::lock;
use concord_proto::StreamPolicy;
use futures_util::stream::{BoxStream, Stream};

/// One step of a subscription as the RPC layer consumes it.
#[derive(Clone, Debug, PartialEq)]
pub enum Delivery<E> {
    /// `dropped` counts the events a `drop_oldest` queue evicted since the last one.
    Event { data: E, dropped: u64 },
    /// The queue overflowed. This is the last delivery: the client subscribes
    /// again to get a fresh snapshot.
    Resync,
}

pub type EventStream<E> = BoxStream<'static, Delivery<E>>;

/// What a stream method returns. The snapshot is read after the stream is
/// registered, so no event falls between the two.
pub struct Subscription<S, E> {
    pub snapshot: Option<S>,
    pub events: EventStream<E>,
}

impl<S, E> Subscription<S, E> {
    pub fn new(snapshot: Option<S>, events: EventStream<E>) -> Self {
        Subscription { snapshot, events }
    }
}

/// The policy the registry declares for a stream method, so the queue behind it
/// cannot disagree with the schema.
pub(crate) fn policy_of(method: &str) -> StreamPolicy {
    concord_proto::method(method)
        .and_then(|spec| spec.policy)
        .unwrap_or_else(|| panic!("{method} is not a stream method of the registry"))
}

struct Inner<T> {
    items: VecDeque<T>,
    dropped: u64,
    overflowed: bool,
    resync_sent: bool,
    closed: bool,
    waker: Option<Waker>,
}

/// A bounded buffer between a producer that cannot wait and a consumer that
/// is polled only when it has credit.
pub struct PolicyQueue<T> {
    policy: StreamPolicy,
    capacity: usize,
    inner: Mutex<Inner<T>>,
}

impl<T> PolicyQueue<T> {
    pub fn new(policy: StreamPolicy, capacity: usize) -> Arc<Self> {
        Arc::new(PolicyQueue {
            policy,
            capacity: capacity.max(1),
            inner: Mutex::new(Inner {
                items: VecDeque::new(),
                dropped: 0,
                overflowed: false,
                resync_sent: false,
                closed: false,
                waker: None,
            }),
        })
    }

    pub fn push(&self, item: T) {
        let waker = {
            let mut inner = lock(&self.inner);
            if inner.closed {
                return;
            }
            match self.policy {
                StreamPolicy::Latest => {
                    inner.items.clear();
                    inner.items.push_back(item);
                }
                StreamPolicy::DropOldest => {
                    if inner.items.len() >= self.capacity {
                        inner.items.pop_front();
                        inner.dropped += 1;
                    }
                    inner.items.push_back(item);
                }
                StreamPolicy::Resync => {
                    if inner.overflowed {
                        return;
                    }
                    if inner.items.len() >= self.capacity {
                        inner.overflowed = true;
                        inner.items.clear();
                    } else {
                        inner.items.push_back(item);
                    }
                }
            }
            inner.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub fn close(&self) {
        let waker = {
            let mut inner = lock(&self.inner);
            inner.closed = true;
            inner.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn poll_next(&self, cx: &mut Context<'_>) -> Poll<Option<Delivery<T>>> {
        let mut inner = lock(&self.inner);
        if inner.overflowed {
            if inner.resync_sent {
                return Poll::Ready(None);
            }
            inner.resync_sent = true;
            return Poll::Ready(Some(Delivery::Resync));
        }
        if let Some(data) = inner.items.pop_front() {
            let dropped = std::mem::take(&mut inner.dropped);
            return Poll::Ready(Some(Delivery::Event { data, dropped }));
        }
        if inner.closed {
            return Poll::Ready(None);
        }
        inner.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// The consuming end. Dropping it runs `release`, which is how a subscription
/// leaves its topic.
pub struct QueueStream<T, G> {
    queue: Arc<PolicyQueue<T>>,
    _guard: G,
}

impl<T, G> QueueStream<T, G> {
    pub fn new(queue: Arc<PolicyQueue<T>>, guard: G) -> Self {
        QueueStream {
            queue,
            _guard: guard,
        }
    }

    pub fn holding<H>(self, extra: H) -> QueueStream<T, (G, H)> {
        QueueStream {
            queue: self.queue,
            _guard: (self._guard, extra),
        }
    }
}

impl<T, G: Unpin> Stream for QueueStream<T, G> {
    type Item = Delivery<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.queue.poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;

    fn drain<T: Unpin + Send + 'static, G: Unpin + Send + 'static>(
        stream: &mut QueueStream<T, G>,
    ) -> Vec<Delivery<T>> {
        let mut out = Vec::new();
        while let Some(Some(item)) = stream.next().now_or_never() {
            out.push(item);
        }
        out
    }

    use futures_util::FutureExt;

    #[test]
    fn every_queue_policy_name_is_a_stream_method() {
        for method in [
            "log.watch",
            "dns.watch",
            "route.watch",
            "events.watch",
            "delay.run",
        ] {
            policy_of(method);
        }
    }

    #[test]
    fn latest_keeps_only_the_newest() {
        let queue = PolicyQueue::new(StreamPolicy::Latest, 8);
        let mut stream = QueueStream::new(queue.clone(), ());
        for value in 0..5 {
            queue.push(value);
        }
        assert_eq!(
            drain(&mut stream),
            [Delivery::Event {
                data: 4,
                dropped: 0
            }]
        );
    }

    #[test]
    fn drop_oldest_evicts_and_reports_how_many() {
        let queue = PolicyQueue::new(StreamPolicy::DropOldest, 3);
        let mut stream = QueueStream::new(queue.clone(), ());
        for value in 0..7 {
            queue.push(value);
        }
        assert_eq!(
            drain(&mut stream),
            [
                Delivery::Event {
                    data: 4,
                    dropped: 4
                },
                Delivery::Event {
                    data: 5,
                    dropped: 0
                },
                Delivery::Event {
                    data: 6,
                    dropped: 0
                },
            ]
        );
    }

    #[test]
    fn resync_never_drops_silently() {
        let queue = PolicyQueue::new(StreamPolicy::Resync, 3);
        let mut stream = QueueStream::new(queue.clone(), ());
        for value in 0..5 {
            queue.push(value);
        }
        assert_eq!(drain(&mut stream), [Delivery::Resync]);
        queue.push(9);
        assert!(drain(&mut stream).is_empty());
    }

    #[test]
    fn a_full_resync_queue_below_capacity_delivers_in_order() {
        let queue = PolicyQueue::new(StreamPolicy::Resync, 3);
        let mut stream = QueueStream::new(queue.clone(), ());
        for value in 0..3 {
            queue.push(value);
        }
        let data: Vec<i32> = drain(&mut stream)
            .into_iter()
            .map(|item| match item {
                Delivery::Event { data, .. } => data,
                Delivery::Resync => -1,
            })
            .collect();
        assert_eq!(data, [0, 1, 2]);
    }
}
