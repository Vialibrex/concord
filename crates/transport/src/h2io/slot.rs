use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use concord_common::Tasks;

use super::{
    Activity, DEFAULT_MAX_SEND_STREAMS, INITIAL_MAX_SEND_STREAMS, h2_io_error, handshake_split,
    spawn_connection,
};

pub(crate) struct StreamGuard(Arc<AtomicUsize>, usize);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Ordering::Relaxed);
    }
}

pub(crate) fn reserve_stream(counter: &Arc<AtomicUsize>) -> StreamGuard {
    reserve_streams(counter, 1)
}

pub(crate) fn reserve_streams(counter: &Arc<AtomicUsize>, count: usize) -> StreamGuard {
    counter.fetch_add(count, Ordering::Relaxed);
    StreamGuard(counter.clone(), count)
}

pub(crate) fn sender_max_streams(sender: &h2::client::SendRequest<Bytes>) -> Option<usize> {
    let limit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sender.current_max_send_streams()
    }))
    .ok()?;
    Some(if limit == usize::MAX {
        DEFAULT_MAX_SEND_STREAMS
    } else {
        limit
    })
}

fn clone_sender(sender: &h2::client::SendRequest<Bytes>) -> Option<h2::client::SendRequest<Bytes>> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sender.clone())).ok()
}

/// Wraps an `h2` `SendRequest` so querying, cloning, or dropping a connection whose
/// internal stream lock was poisoned never panics the pool or its caller.
pub(crate) struct SafeSender(Option<h2::client::SendRequest<Bytes>>);

impl SafeSender {
    pub(crate) fn new(sender: h2::client::SendRequest<Bytes>) -> Self {
        SafeSender(Some(sender))
    }

    pub(crate) fn max_streams(&self) -> Option<usize> {
        self.0.as_ref().and_then(sender_max_streams)
    }

    pub(crate) fn clone_sender(&self) -> Option<h2::client::SendRequest<Bytes>> {
        self.0.as_ref().and_then(clone_sender)
    }
}

impl Drop for SafeSender {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(sender)));
        }
    }
}

pub(super) struct Live {
    sender: SafeSender,
    activity: Arc<Activity>,
}

impl Live {
    pub(super) fn new(sender: h2::client::SendRequest<Bytes>, activity: Arc<Activity>) -> Self {
        Live {
            sender: SafeSender::new(sender),
            activity,
        }
    }

    fn is_dead(&self) -> bool {
        self.activity.ended() || self.sender.max_streams().is_none()
    }
}

/// Shared single-connection HTTP/2 client slot that deduplicates dials, tracks open
/// streams, and exposes the peer's advertised concurrent-stream limit without locking
/// across `.await`.
pub(crate) struct ClientSlot {
    dial_lock: tokio::sync::Mutex<()>,
    pub(super) live: Mutex<Option<Live>>,
    streams: Arc<AtomicUsize>,
}

impl ClientSlot {
    pub(crate) fn new() -> Self {
        ClientSlot {
            dial_lock: tokio::sync::Mutex::new(()),
            live: Mutex::new(None),
            streams: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn streams(&self) -> usize {
        self.streams.load(Ordering::Relaxed)
    }

    pub(crate) fn reserve(&self) -> StreamGuard {
        self.reserve_streams(1)
    }

    pub(crate) fn reserve_streams(&self, count: usize) -> StreamGuard {
        reserve_streams(&self.streams, count)
    }

    pub(crate) fn is_dead(&self) -> bool {
        concord_common::sync::lock(&self.live)
            .as_ref()
            .is_some_and(Live::is_dead)
    }

    pub(crate) fn peer_max_streams(&self) -> usize {
        concord_common::sync::lock(&self.live)
            .as_ref()
            .and_then(|live| {
                (!live.activity.ended())
                    .then(|| live.sender.max_streams())
                    .flatten()
            })
            .unwrap_or(INITIAL_MAX_SEND_STREAMS)
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.has_capacity_for(1)
    }

    pub(crate) fn has_capacity_for(&self, need: usize) -> bool {
        !self.is_dead() && self.streams().saturating_add(need) <= self.peer_max_streams()
    }

    pub(crate) fn close(&self) {
        concord_common::sync::lock(&self.live).take();
    }

    pub(super) fn current(&self) -> Option<(h2::client::SendRequest<Bytes>, Arc<Activity>)> {
        let mut slot = concord_common::sync::lock(&self.live);
        let live = slot.as_ref()?;
        if live.activity.ended() {
            *slot = None;
            return None;
        }
        let Some(sender) = live.sender.clone_sender() else {
            *slot = None;
            return None;
        };
        Some((sender, live.activity.clone()))
    }

    async fn connect(
        &self,
        dial: &crate::DialFn,
        builder: &h2::client::Builder,
        tasks: &Tasks,
        ping_interval: Option<Duration>,
    ) -> io::Result<(h2::client::SendRequest<Bytes>, Arc<Activity>)> {
        let _guard = self.dial_lock.lock().await;
        if let Some(pair) = self.current() {
            return Ok(pair);
        }
        let io = dial().await?;
        let (sender, conn) = handshake_split(builder, io).await?;
        let activity = Activity::new();
        activity.touch();
        spawn_connection(tasks, conn, ping_interval, activity.clone());
        let pair = (sender.clone(), activity.clone());
        *concord_common::sync::lock(&self.live) = Some(Live::new(sender, activity));
        Ok(pair)
    }

    pub(crate) async fn ready_sender(
        &self,
        dial: &crate::DialFn,
        builder: &h2::client::Builder,
        tasks: &Tasks,
        ping_interval: Option<Duration>,
    ) -> io::Result<(h2::client::SendRequest<Bytes>, Arc<Activity>)> {
        for attempt in 0..2 {
            let (current, activity) = match self.current() {
                Some(pair) => pair,
                None => self.connect(dial, builder, tasks, ping_interval).await?,
            };
            match current.ready().await {
                Ok(ready) => return Ok((ready, activity)),
                Err(err) if attempt == 1 => return Err(h2_io_error(err)),
                Err(_) => {
                    let _guard = self.dial_lock.lock().await;
                    let mut slot = concord_common::sync::lock(&self.live);
                    if slot
                        .as_ref()
                        .is_some_and(|live| Arc::ptr_eq(&live.activity, &activity))
                    {
                        *slot = None;
                    }
                }
            }
        }
        Err(io::ErrorKind::NotConnected.into())
    }
}
