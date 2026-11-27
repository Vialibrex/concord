use concord_common::sync::lock;
use concord_common::{Replies, ReplyOut, ReplySource};

use super::*;

pub(super) type Answered = Option<(Address, u32, Option<Arc<Flow>>)>;

thread_local! {
    static RECEIVED: RefCell<RecvBatch> = RefCell::default();
}

pub(super) async fn receive_loop(inner: Arc<Inner>, session: Arc<Session>) {
    let tracked = session.registration.tracked().clone();
    let cancel = tracked.record.cancel.clone();
    let mut answered: Answered = None;
    if session.inner.recv_batches() {
        receive_batches(&inner, &session, &tracked, &cancel, &mut answered).await;
    } else {
        loop {
            let (packet, from) = tokio::select! {
                () = cancel.cancelled() => break,
                received = recv_packet(&*session.inner) => match received {
                    Ok(received) => received,
                    Err(err) => {
                        session.end(ConnEnd::of_error(&err));
                        break;
                    }
                },
            };
            let from = arrived(
                &inner,
                &session,
                &tracked,
                &mut answered,
                packet.len(),
                &from,
            );
            if !write_back(&session, &cancel, &packet, &from).await {
                if !cancel.is_cancelled() {
                    session.end(ConnEnd::new(EndReason::Local));
                }
                break;
            }
        }
    }
    session.close();
    end_session(&inner, &session);
}

/// The batch belongs to the worker thread and cannot be held across an await, so each poll
/// writes back what one receive took while the reply accepts it, and copies out whatever
/// follows a reply that is not ready.
pub(super) async fn receive_batches(
    inner: &Inner,
    session: &Session,
    tracked: &Arc<Tracked>,
    cancel: &CancellationToken,
    answered: &mut Answered,
) {
    loop {
        let took = tokio::select! {
            () = cancel.cancelled() => return,
            took = poll_fn(|cx| take_batch(cx, inner, session, tracked, answered)) => took,
        };
        let Some(backlog) = took else {
            return;
        };
        for (packet, from) in backlog {
            if !write_back(session, cancel, &packet, &from).await {
                if !cancel.is_cancelled() {
                    session.end(ConnEnd::new(EndReason::Local));
                }
                return;
            }
        }
    }
}

/// `None` when the session can no longer receive or its client is gone.
pub(super) fn take_batch(
    cx: &mut Context<'_>,
    inner: &Inner,
    session: &Session,
    tracked: &Arc<Tracked>,
    answered: &mut Answered,
) -> Poll<Option<Vec<(PacketBuf, Address)>>> {
    RECEIVED.with_borrow_mut(|batch| {
        match session.inner.poll_recv_batch(cx, batch) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => {
                session.end(ConnEnd::of_error(&err));
                return Poll::Ready(None);
            }
            Poll::Ready(Ok(())) => {}
        }
        let reply = session.reply.load_full();
        let mut backlog = Vec::new();
        for (payload, from) in batch.iter() {
            let from = arrived(
                inner,
                session,
                tracked,
                answered,
                payload.len(),
                &Address::from(from),
            );
            if backlog.is_empty() {
                match reply.poll_write_back(cx, payload, &from) {
                    Poll::Ready(result) => {
                        if !delivered(result) {
                            session.end(ConnEnd::new(EndReason::Local));
                            return Poll::Ready(None);
                        }
                        continue;
                    }
                    Poll::Pending => {}
                }
            }
            let mut packet = PacketBuf::take();
            packet.extend_from_slice(payload);
            backlog.push((packet, from));
        }
        Poll::Ready(Some(backlog))
    })
}

/// Records a datagram from `from` and returns the address to answer the client from.
pub(super) fn arrived(
    inner: &Inner,
    session: &Session,
    tracked: &Arc<Tracked>,
    answered: &mut Answered,
    len: usize,
    from: &Address,
) -> Address {
    let now = inner.nat.now();
    session.last_active.store(now, Ordering::Relaxed);
    tracked.downloaded(len as u64);
    answer_from(inner, session, answered, now, from)
}

/// The address to answer the client from, keeping the flow it answers alive.
fn answer_from(
    inner: &Inner,
    session: &Session,
    answered: &mut Answered,
    now: u32,
    from: &Address,
) -> Address {
    let from = session.restored(from);
    let stale = answered
        .as_ref()
        .is_none_or(|(known, since, _)| *known != from || now != *since);
    if stale {
        let flow = answered_flow(&inner.nat, session, &from);
        *answered = Some((from.clone(), now, flow));
    }
    if let Some((_, _, Some(flow))) = answered {
        flow.last_active.store(now, Ordering::Relaxed);
    }
    from
}

/// False when the client is gone or the session was cancelled.
pub(super) async fn write_back(
    session: &Session,
    cancel: &CancellationToken,
    packet: &PacketBuf,
    from: &Address,
) -> bool {
    let reply = session.reply.load_full();
    let written = poll_fn(|cx| reply.poll_write_back(cx, packet.as_slice(), from));
    tokio::select! {
        () = cancel.cancelled() => false,
        result = written => delivered(result),
    }
}

/// False when a failed write means the client is gone.
pub(super) fn delivered(result: io::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(err) => {
            tracing::debug!("[UDP] reply to the client failed: {err}");
            !is_gone(&err)
        }
    }
}

/// The flow a reply from `from` is delivered for. A flow to a name is keyed by the
/// name, so a session with one flow stands in for it.
pub(super) fn answered_flow(nat: &UdpNat, session: &Session, from: &Address) -> Option<Arc<Flow>> {
    let id = FlowId {
        src: session.key.src,
        conn: session.key.conn,
        dst: from.clone(),
    };
    if let Some(flow) = nat.flows.get(&id) {
        return Some(flow.clone());
    }
    let flows = lock(&session.flows);
    let mut only = flows.iter();
    match (only.next(), only.next()) {
        (Some(id), None) => nat.flows.get(id).map(|flow| flow.clone()),
        _ => None,
    }
}

/// Hands the session's receiving to its reply writer when the session receives in batches and
/// the writer takes it; false leaves it to [`receive_loop`].
pub(super) fn adopt(inner: &Arc<Inner>, session: &Arc<Session>, reply: &Arc<dyn UdpReply>) -> bool {
    if !session.inner.recv_batches() {
        return false;
    }
    let source = Arc::new(Adopted {
        inner: inner.clone(),
        session: session.clone(),
        tracked: session.registration.tracked().clone(),
        answered: Mutex::new(None),
        armed: AtomicBool::new(true),
    });
    if reply.adopt(source.clone()).is_err() {
        source.armed.store(false, Ordering::Release);
        return false;
    }
    inner
        .tasks
        .spawn_to_end(end_adopted(inner.clone(), session.clone()));
    true
}

/// An adopted session has no receive task to notice that it was closed, so this waits for that
/// and ends it, waking the writer to drop its source.
async fn end_adopted(inner: Arc<Inner>, session: Arc<Session>) {
    let cancel = session.registration.tracked().record.cancel.clone();
    cancel.cancelled().await;
    end_session(&inner, &session);
    session.wake_replies();
}

/// A session whose reply writer receives its datagrams.
pub(super) struct Adopted {
    inner: Arc<Inner>,
    session: Arc<Session>,
    tracked: Arc<Tracked>,
    answered: Mutex<Answered>,
    /// Cleared when the writer refused it, so dropping it then leaves the session open.
    armed: AtomicBool,
}

impl ReplySource for Adopted {
    fn poll_replies(&self, cx: &mut Context<'_>, out: &mut dyn ReplyOut) -> Poll<Replies> {
        let session = &self.session;
        {
            let mut waker = lock(&session.replies);
            if !waker
                .as_ref()
                .is_some_and(|known| known.will_wake(cx.waker()))
            {
                *waker = Some(cx.waker().clone());
            }
        }
        if session.ended.load(Ordering::Acquire) || self.tracked.record.cancel.is_cancelled() {
            return Poll::Ready(Replies::Ended);
        }
        RECEIVED.with_borrow_mut(|batch| {
            let mut received = false;
            // To the first empty read: only that read leaves the waker with the socket, and a
            // writer told to poll again would come back through the scheduler to make it.
            loop {
                let room = out.room();
                if room == 0 {
                    return Poll::Ready(Replies::Received);
                }
                batch.limit(room);
                match session.inner.poll_recv_batch(cx, batch) {
                    Poll::Pending if received => return Poll::Ready(Replies::Drained),
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        session.close();
                        return Poll::Ready(Replies::Ended);
                    }
                    Poll::Ready(Ok(())) => {}
                }
                let now = self.inner.nat.now();
                let mut bytes = 0;
                let mut answered = lock(&self.answered);
                for (payload, from) in batch.iter() {
                    bytes += payload.len() as u64;
                    let from = answer_from(
                        &self.inner,
                        session,
                        &mut answered,
                        now,
                        &Address::from(from),
                    );
                    if let Err(err) = out.put(payload, &from)
                        && !delivered(Err(err))
                    {
                        session.close();
                        return Poll::Ready(Replies::Ended);
                    }
                }
                drop(answered);
                session.last_active.store(now, Ordering::Relaxed);
                self.tracked.downloaded(bytes);
                received = true;
            }
        })
    }

    fn watch(&self, watcher: &dyn concord_common::SocketWatcher) {
        self.session.inner.watch(watcher);
    }
}

impl Drop for Adopted {
    fn drop(&mut self) {
        if self.armed.load(Ordering::Acquire) {
            self.session.close();
        }
    }
}
