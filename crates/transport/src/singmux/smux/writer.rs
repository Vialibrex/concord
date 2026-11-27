use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker, ready};

use concord_common::BoxWrite;
use concord_common::sync::lock;
use tokio::io::AsyncWrite;

use super::VERSION;

pub(super) fn put_frame(out: &mut Vec<u8>, cmd: u8, sid: u32, payload: &[u8]) {
    let len = u16::try_from(payload.len())
        .unwrap_or(u16::MAX)
        .to_le_bytes();
    let [s0, s1, s2, s3] = sid.to_le_bytes();
    out.extend_from_slice(&[VERSION, cmd, len[0], len[1], s0, s1, s2, s3]);
    out.extend_from_slice(payload);
}

/// The session's write half. A stream writes its frame itself, in its own task, as
/// metacubex/smux's writeFrameInternal hands its frame to the connection writer
/// (session.go:671-695), and streams waiting for their turn queue in arrival order.
/// Waiting is the only time a write is pending, so a cancelled write has handed over
/// nothing. A taken frame belongs to the session: the next writer finishes it before its
/// own, and if no one comes the session's driver does, so no write leaves half a frame on
/// the wire or holds up the streams behind it. A writer waiting for its turn drives the
/// frame ahead of it itself; one that stops polling while it waits keeps its place, and
/// the rest of that frame, until it polls again or is dropped.
pub(super) struct FrameWriter(Mutex<WriterState>);

struct WriterState {
    io: Option<BoxWrite>,
    frame: Vec<u8>,
    off: usize,
    unflushed: bool,
    waiting: VecDeque<(u64, Waker)>,
    next_ticket: u64,
    driver: Option<Waker>,
}

pub(super) struct Turn {
    writer: Arc<FrameWriter>,
    ticket: Option<u64>,
}

impl Turn {
    pub(super) fn new(writer: Arc<FrameWriter>) -> Self {
        Turn {
            writer,
            ticket: None,
        }
    }

    pub(super) fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        make: impl FnOnce(&mut Vec<u8>),
    ) -> Poll<io::Result<()>> {
        let writer = self.writer.clone();
        writer.poll_send(cx, &mut self.ticket, make)
    }

    pub(super) fn leave(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.writer.leave(ticket);
        }
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        self.leave();
    }
}

struct WakeAll(Vec<Waker>);

impl Wake for WakeAll {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        for waker in &self.0 {
            waker.wake_by_ref();
        }
    }
}

impl WriterState {
    fn broken() -> io::Error {
        io::ErrorKind::BrokenPipe.into()
    }

    fn busy(&self) -> bool {
        self.off < self.frame.len()
    }

    /// The connection wakes only its last poller, who may be a writer dropped since; the
    /// head of the queue is woken with it, so a frame left half written still finishes.
    fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.busy() {
            return Poll::Ready(Ok(()));
        }
        let head = self
            .waiting
            .front()
            .map(|(_, waker)| waker)
            .filter(|w| !w.will_wake(cx.waker()))
            .cloned();
        let Some(head) = head else {
            return self.write_rest(cx);
        };
        let both = Waker::from(Arc::new(WakeAll(vec![cx.waker().clone(), head])));
        self.write_rest(&mut Context::from_waker(&both))
    }

    fn write_rest(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(io) = self.io.as_mut() else {
            return Poll::Ready(Err(Self::broken()));
        };
        while let Some(rest) = self.frame.get(self.off..).filter(|rest| !rest.is_empty()) {
            match ready!(Pin::new(&mut *io).poll_write(cx, rest)) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(n) => self.off += n,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }
        self.unflushed = true;
        Poll::Ready(Ok(()))
    }

    fn write_taken(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.write_rest(cx) {
            Poll::Ready(Ok(())) if self.waiting.is_empty() => self.poll_flush(cx),
            other => other,
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_progress(cx))?;
        let Some(io) = self.io.as_mut() else {
            return Poll::Ready(Err(Self::broken()));
        };
        ready!(Pin::new(io).poll_flush(cx))?;
        self.unflushed = false;
        Poll::Ready(Ok(()))
    }

    fn head(&self) -> Option<u64> {
        self.waiting.front().map(|(ticket, _)| *ticket)
    }

    fn wait(&mut self, cx: &mut Context<'_>, ticket: &mut Option<u64>) {
        let queued = ticket.and_then(|ticket| self.waiting.iter_mut().find(|(t, _)| *t == ticket));
        match queued {
            Some((_, waker)) => waker.clone_from(cx.waker()),
            None => {
                let next = self.next_ticket;
                self.next_ticket += 1;
                *ticket = Some(next);
                self.waiting.push_back((next, cx.waker().clone()));
            }
        }
    }

    fn fail(&mut self) -> Vec<Waker> {
        self.io = None;
        self.frame.clear();
        self.off = 0;
        self.waiting
            .drain(..)
            .map(|(_, waker)| waker)
            .chain(self.driver.take())
            .collect()
    }
}

impl FrameWriter {
    pub(super) fn new(io: BoxWrite) -> Arc<Self> {
        Arc::new(FrameWriter(Mutex::new(WriterState {
            io: Some(io),
            frame: Vec::new(),
            off: 0,
            unflushed: false,
            waiting: VecDeque::new(),
            next_ticket: 0,
            driver: None,
        })))
    }

    /// Waits for `ticket`'s turn behind the frame in progress and the writers that came
    /// first, then takes the frame `make` builds and writes what the connection accepts
    /// now; the last writer in line also flushes. Waiting holds no lock, and only the
    /// connection itself not taking bytes stops every stream, as it stops smux's sendLoop.
    pub(super) fn poll_send(
        &self,
        cx: &mut Context<'_>,
        ticket: &mut Option<u64>,
        make: impl FnOnce(&mut Vec<u8>),
    ) -> Poll<io::Result<()>> {
        let mut wake = Vec::new();
        let result = {
            let mut state = lock(&self.0);
            Self::poll_send_locked(&mut state, cx, ticket, make, &mut wake)
        };
        for waker in wake {
            waker.wake();
        }
        result
    }

    fn poll_send_locked(
        state: &mut WriterState,
        cx: &mut Context<'_>,
        ticket: &mut Option<u64>,
        make: impl FnOnce(&mut Vec<u8>),
        wake: &mut Vec<Waker>,
    ) -> Poll<io::Result<()>> {
        match state.poll_progress(cx) {
            Poll::Pending => {
                state.wait(cx, ticket);
                return Poll::Pending;
            }
            Poll::Ready(Err(err)) => {
                *ticket = None;
                wake.extend(state.fail());
                return Poll::Ready(Err(err));
            }
            Poll::Ready(Ok(())) => {}
        }
        let head = state.head();
        if head.is_some() && head != *ticket {
            state.wait(cx, ticket);
            wake.extend(state.waiting.front().map(|(_, waker)| waker.clone()));
            return Poll::Pending;
        }
        if head.is_some() {
            state.waiting.pop_front();
        }
        *ticket = None;
        state.frame.clear();
        make(&mut state.frame);
        state.off = 0;
        // The writer returns once its frame is taken, so the connection wakes the driver,
        // not the writer; a writer that comes back first registers itself instead.
        let written = match state.driver.clone() {
            Some(driver) => state.write_taken(&mut Context::from_waker(&driver)),
            None => state.write_taken(cx),
        };
        if let Poll::Ready(Err(err)) = written {
            wake.extend(state.fail());
            return Poll::Ready(Err(err));
        }
        wake.extend(state.waiting.front().map(|(_, waker)| waker.clone()));
        Poll::Ready(Ok(()))
    }

    pub(super) fn leave(&self, ticket: u64) {
        let waker = {
            let mut state = lock(&self.0);
            let was_head = state.head() == Some(ticket);
            state.waiting.retain(|(t, _)| *t != ticket);
            match state.waiting.front() {
                Some((_, head)) if was_head => Some(head.clone()),
                None if state.busy() || state.unflushed => state.driver.clone(),
                _ => None,
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The session's driver: finishes a frame its writer left half written and flushes
    /// what the last writer could not, and otherwise sleeps.
    pub(super) fn poll_drive(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = lock(&self.0);
        if state.io.is_none() {
            return Poll::Ready(());
        }
        match state.driver.as_mut() {
            Some(driver) => driver.clone_from(cx.waker()),
            None => state.driver = Some(cx.waker().clone()),
        }
        let done = if state.unflushed && state.waiting.is_empty() {
            state.poll_flush(cx)
        } else {
            state.poll_progress(cx)
        };
        let wake = match done {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => state.fail(),
            Poll::Ready(Ok(())) => state
                .waiting
                .front()
                .map(|(_, waker)| waker.clone())
                .into_iter()
                .collect(),
        };
        drop(state);
        for waker in wake {
            waker.wake();
        }
        Poll::Pending
    }

    pub(super) fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        lock(&self.0).poll_flush(cx)
    }

    pub(super) fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = lock(&self.0);
        ready!(state.poll_flush(cx))?;
        match state.io.as_mut() {
            Some(io) => Pin::new(io).poll_shutdown(cx),
            None => Poll::Ready(Err(WriterState::broken())),
        }
    }

    pub(super) fn close(&self) {
        let wakers = lock(&self.0).fail();
        for waker in wakers {
            waker.wake();
        }
    }
}
