// Concord: shared outbound FramedWrite state for opt-in split-I/O client connections.
// Mirrors Go metacubex/http ClientConn.wmu: callers write one DATA frame at a time
// directly to the outbound AsyncWrite under a short mutex, never holding the mutex
// across Poll::Pending. Half-written frames keep ownership until flushed (or are
// handed off to Connection as Abandoned on drop), preserving HTTP/2 frame integrity
// and HPACK encoding order.

use crate::codec::FrameSink;
use crate::proto::streams::{Prioritized, StoreKey};

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::{Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteOwner {
    Connection,
    Stream(StoreKey),
    Reserved(StoreKey),
    Abandoned,
}

pub(crate) struct DirectWriter<B> {
    state: Mutex<DirectWriterState<B>>,
}

pub(crate) struct DirectWriterState<B> {
    pub(crate) sink: Box<dyn FrameSink<Prioritized<B>>>,
    pub(crate) owner: Option<WriteOwner>,
    /// True when the in-flight frame in `sink` is a direct-written DATA frame
    /// (so reclaiming it must drop `take_last_data_frame()` rather than calling
    /// `Prioritize::reclaim_written_frame`).
    pub(crate) is_direct_data_frame: bool,
    /// True once the outbound transport has encountered a fatal write error or closed;
    /// streams then fail instead of taking the writer.
    pub(crate) broken: bool,
    pub(crate) conn_waiting: bool,
    pub(crate) conn_waker: Option<Waker>,
    pub(crate) waiters: VecDeque<(StoreKey, Waker)>,
}

impl<B> fmt::Debug for DirectWriter<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectWriter").finish_non_exhaustive()
    }
}

impl<B> DirectWriter<B> {
    pub(crate) fn new(sink: Box<dyn FrameSink<Prioritized<B>>>) -> Self {
        DirectWriter {
            state: Mutex::new(DirectWriterState {
                sink,
                owner: None,
                is_direct_data_frame: false,
                broken: false,
                conn_waiting: false,
                conn_waker: None,
                waiters: VecDeque::new(),
            }),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, DirectWriterState<B>> {
        self.state.lock().unwrap()
    }

    pub(crate) fn lock_unless_poisoned(&self) -> Option<MutexGuard<'_, DirectWriterState<B>>> {
        self.state.lock().ok()
    }

    /// Wake everyone when the connection is dropped or hits a fatal write error.
    pub(crate) fn wake_all_on_close(&self) {
        let waiters = match self.state.lock() {
            Ok(mut state) => state.fail_and_take_waiters(),
            Err(_) => return,
        };
        for waker in waiters {
            waker.wake();
        }
    }
}

impl<B> DirectWriterState<B> {
    /// Returns true if `key` may take ownership of an idle writer right now.
    pub(crate) fn can_stream_acquire(&self, key: StoreKey) -> bool {
        !self.conn_waiting
            && match self.owner {
                None => true,
                Some(WriteOwner::Reserved(k)) => k == key,
                Some(WriteOwner::Stream(_))
                | Some(WriteOwner::Connection)
                | Some(WriteOwner::Abandoned) => false,
            }
    }

    pub(crate) fn enqueue_waiter(&mut self, key: StoreKey, waker: &Waker) {
        for (existing, slot) in &mut self.waiters {
            if *existing == key {
                slot.clone_from(waker);
                return;
            }
        }
        self.waiters.push_back((key, waker.clone()));
    }

    /// Release ownership once `sink.is_write_empty()` is true, prioritizing Connection
    /// control frames and otherwise passing FIFO reservation to the next waiting stream.
    pub(crate) fn release_locked(&mut self) -> Option<Waker> {
        debug_assert!(self.broken || self.sink.is_write_empty());
        self.is_direct_data_frame = false;
        if self.conn_waiting {
            self.owner = None;
            return self.conn_waker.take();
        }
        if let Some((next_key, waker)) = self.waiters.pop_front() {
            self.owner = Some(WriteOwner::Reserved(next_key));
            return Some(waker);
        }
        self.owner = None;
        None
    }

    /// Releases the writer to the next owner and wakes it, after unlocking.
    pub(crate) fn release(mut state: MutexGuard<'_, Self>) {
        let wake = state.release_locked();
        drop(state);
        if let Some(w) = wake {
            w.wake();
        }
    }

    /// Marks the writer broken and wakes the connection and every waiting stream, after unlocking.
    pub(crate) fn fail(mut state: MutexGuard<'_, Self>) {
        let waiters = state.fail_and_take_waiters();
        drop(state);
        for w in waiters {
            w.wake();
        }
    }

    /// After the in-flight frame is flushed: drops a direct DATA frame, or hands a frame the
    /// connection path buffered back to `reclaim` (`Prioritize::reclaim_written_frame`).
    pub(crate) fn reclaim_flushed(
        &mut self,
        reclaim: impl FnOnce(&mut dyn FrameSink<Prioritized<B>>),
    ) {
        if self.is_direct_data_frame {
            let _ = self.sink.take_last_data_frame();
        } else {
            reclaim(&mut *self.sink);
        }
        self.is_direct_data_frame = false;
    }

    /// Takes the writer for the connection unless a stream owns it, in which case the
    /// connection is woken when that stream releases it. Ready(true) means a frame a
    /// dropped stream or the connection started is still in the sink.
    pub(crate) fn take_for_connection(&mut self, cx: &Context) -> Poll<bool> {
        let started = match self.owner {
            Some(WriteOwner::Stream(_)) => {
                self.conn_waiting = true;
                self.conn_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            Some(WriteOwner::Abandoned) | Some(WriteOwner::Connection) => true,
            None | Some(WriteOwner::Reserved(_)) => false,
        };
        self.owner = Some(WriteOwner::Connection);
        self.conn_waiting = false;
        Poll::Ready(started)
    }

    /// `take_for_connection`, then finishes and reclaims a frame left in the sink. On an
    /// error the caller still holds the writer and fails it.
    pub(crate) fn poll_acquire_for_connection(
        &mut self,
        cx: &mut Context,
        reclaim: impl FnOnce(&mut dyn FrameSink<Prioritized<B>>),
    ) -> Poll<io::Result<()>> {
        if !ready!(self.take_for_connection(cx)) {
            self.is_direct_data_frame = false;
            return Poll::Ready(Ok(()));
        }
        ready!(self.sink.flush(cx))?;
        self.reclaim_flushed(reclaim);
        Poll::Ready(Ok(()))
    }

    /// Release after fatal I/O error or connection close and return all wakers to notify.
    pub(crate) fn fail_and_take_waiters(&mut self) -> Vec<Waker> {
        self.owner = None;
        self.is_direct_data_frame = false;
        self.broken = true;
        self.conn_waiting = false;
        let mut out = Vec::with_capacity(self.waiters.len() + 1);
        if let Some(w) = self.conn_waker.take() {
            out.push(w);
        }
        while let Some((_, w)) = self.waiters.pop_front() {
            out.push(w);
        }
        out
    }

    /// Handle dropping a `SendStream` that may own or be queued on this writer.
    /// Returns `(waker_to_wake, need_wake_connection_task)`.
    pub(crate) fn on_stream_drop(&mut self, key: StoreKey) -> (Option<Waker>, bool) {
        self.waiters.retain(|(k, _)| *k != key);
        match self.owner {
            Some(WriteOwner::Stream(k)) if k == key => {
                self.owner = Some(WriteOwner::Abandoned);
                (self.conn_waker.take(), true)
            }
            Some(WriteOwner::Reserved(k)) if k == key => (self.release_locked(), false),
            _ => (None, false),
        }
    }
}
