use super::*;

/// One session's datagrams in one driver round. sing-tun's upload array holds 32 for a whole
/// engine (`goPacketBatchSize`); this cap is per session and per round, and a round reads at
/// most 64 packets, so it does not bind first (`.agents/reference-choices.md`).
pub(super) const BATCH_DATAGRAMS: usize = 64;

/// One receive round's datagrams for sessions that send in batches, and the round's last flow.
/// The datagrams are copied in from the reader's buffer, so a round holds only their bytes.
/// It is per thread, so a round lives inside one synchronous call: see [`BatchRound`].
#[derive(Default)]
pub(super) struct Batch {
    open: bool,
    pub(super) bytes: Vec<u8>,
    pub(super) staged: Vec<Staged>,
    pub(super) sessions: Vec<Held>,
    /// A session's index in `sessions`, keyed by its address.
    held_at: HashMap<usize, usize, BuildHasherDefault<AddressHasher>>,
    flow: Option<(FlowId, Arc<Flow>)>,
    /// Counts the round flows forgotten, so one taken out for a datagram does not go back
    /// stale.
    forgotten: u32,
}

pub(super) struct Held {
    session: Arc<Session>,
    count: usize,
    first: usize,
    last: usize,
}

pub(super) struct Staged {
    start: usize,
    end: usize,
    dst: SocketAddr,
    /// The session's next datagram in `staged`.
    next: Option<usize>,
}

/// Hashes a session's address. Its low bits are alignment zeros, which a multiply keeps, so
/// `finish` brings the product's high bits down to where the table picks a bucket.
#[derive(Default)]
pub(super) struct AddressHasher(u64);

impl Hasher for AddressHasher {
    fn finish(&self) -> u64 {
        self.0.rotate_left(32)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.write_u64(u64::from(byte));
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }
}

fn address(session: &Arc<Session>) -> usize {
    Arc::as_ptr(session) as usize
}

thread_local! {
    pub(super) static BATCH: RefCell<Batch> = RefCell::default();
}

/// One receive round on this thread: datagrams for sessions that send in batches wait until it
/// drops, and the round remembers its last flow. It is neither `Send` nor `Sync`, so it ends
/// on the thread that began it and cannot be held across an await in a spawned task.
pub(crate) struct BatchRound<'a> {
    inner: &'a Arc<Inner>,
    _thread: PhantomData<*const ()>,
}

impl<'a> BatchRound<'a> {
    pub(crate) fn begin(inner: &'a Arc<Inner>) -> Self {
        let _ = BATCH.try_with(|batch| {
            let mut batch = batch.borrow_mut();
            debug_assert!(!batch.open, "a UDP batch began inside another");
            debug_assert!(
                batch.bytes.is_empty() && batch.staged.is_empty() && batch.sessions.is_empty(),
                "a UDP batch began with datagrams held"
            );
            batch.open = true;
        });
        BatchRound {
            inner,
            _thread: PhantomData,
        }
    }
}

impl Drop for BatchRound<'_> {
    fn drop(&mut self) {
        let flow = BATCH.try_with(|batch| {
            let mut batch = batch.borrow_mut();
            batch.open = false;
            batch.flow.take()
        });
        drop(flow);
        flush_batch(self.inner);
    }
}

/// The round's last flow if it is the one from `src` to `dst`, taken out while a datagram is
/// delivered to it, and the lease that puts a flow back.
pub(super) fn take_round_flow(
    src: SocketAddr,
    conn: u64,
    dst: &Address,
) -> (Option<(FlowId, Arc<Flow>)>, RoundLease) {
    BATCH
        .try_with(|batch| {
            let mut batch = batch.borrow_mut();
            let flow = batch.flow.take_if(|(id, _)| {
                id.src == nat_src(src, conn) && id.conn == conn && id.dst == *dst
            });
            let forgotten = batch.forgotten;
            (flow, RoundLease { forgotten })
        })
        .unwrap_or((None, RoundLease { forgotten: 0 }))
}

/// One datagram's hold on the round's flow, from [`take_round_flow`].
#[must_use]
pub(super) struct RoundLease {
    forgotten: u32,
}

impl RoundLease {
    /// Remembers `flow` for the rest of the round unless a flow was forgotten since the lease
    /// was taken.
    pub(super) fn keep(self, id: FlowId, flow: Arc<Flow>) {
        let replaced = BATCH.try_with(|batch| {
            let mut batch = batch.borrow_mut();
            if batch.open && batch.forgotten == self.forgotten {
                batch.flow.replace((id, flow))
            } else {
                None
            }
        });
        drop(replaced);
    }
}

/// For a flow that leaves the table during a round, which a later datagram must not reach
/// through the round. Only this thread's removals take effect at once; another thread's (the
/// idle sweep, a failed establish, a receive loop that ends) reach the round's flow at the next
/// round, as sing-tun's `packetFlows` is cleared only at each park (`stack_go_engine.go:362`).
pub(super) fn forget_round_flow() {
    let forgotten = BATCH.try_with(|batch| {
        let mut batch = batch.borrow_mut();
        batch.forgotten = batch.forgotten.wrapping_add(1);
        batch.flow.take()
    });
    drop(forgotten);
}

pub(super) fn batch_target(session: &Session, target: &Address) -> Option<SocketAddr> {
    match target {
        Address::Socket(dst) if session.inner.batches() => Some(*dst),
        _ => None,
    }
}

/// True when the datagram now waits for the end of the round.
pub(super) fn stage(
    inner: &Arc<Inner>,
    session: &Arc<Session>,
    payload: &[u8],
    dst: SocketAddr,
) -> bool {
    loop {
        let staged = BATCH.try_with(|batch| {
            let mut batch = batch.borrow_mut();
            let batch = &mut *batch;
            if !batch.open {
                return Some(false);
            }
            let held_at = batch.held_at.get(&address(session)).copied();
            let count = held_at
                .and_then(|index| batch.sessions.get(index))
                .map_or(0, |held| held.count);
            if count >= BATCH_DATAGRAMS {
                return None;
            }
            let index = batch.staged.len();
            let start = batch.bytes.len();
            batch.bytes.extend_from_slice(payload);
            batch.staged.push(Staged {
                start,
                end: batch.bytes.len(),
                dst,
                next: None,
            });
            match held_at.and_then(|at| batch.sessions.get_mut(at)) {
                Some(held) => {
                    if let Some(last) = batch.staged.get_mut(held.last) {
                        last.next = Some(index);
                    }
                    held.last = index;
                    held.count += 1;
                }
                None => {
                    batch.held_at.insert(address(session), batch.sessions.len());
                    batch.sessions.push(Held {
                        session: session.clone(),
                        count: 1,
                        first: index,
                        last: index,
                    });
                }
            }
            Some(true)
        });
        match staged {
            Ok(Some(staged)) => return staged,
            Ok(None) => flush_batch(inner),
            Err(_) => return false,
        }
    }
}

pub(super) fn is_staged(session: &Arc<Session>) -> bool {
    BATCH
        .try_with(|batch| batch.borrow().held_at.contains_key(&address(session)))
        .unwrap_or(false)
}

/// The batch is taken out while it is sent, so a session that calls back into the tunnel
/// finds an empty one rather than a borrowed one.
pub(super) fn flush_batch(inner: &Arc<Inner>) {
    let Ok((bytes, staged, sessions)) = BATCH.try_with(|batch| {
        let mut batch = batch.borrow_mut();
        batch.held_at.clear();
        (
            std::mem::take(&mut batch.bytes),
            std::mem::take(&mut batch.staged),
            std::mem::take(&mut batch.sessions),
        )
    }) else {
        return;
    };
    if !sessions.is_empty() {
        send_held(inner, &bytes, &staged, &sessions);
    }
    let _ = BATCH.try_with(|batch| {
        let mut batch = batch.borrow_mut();
        // A session that staged into the open round while these were sent keeps its datagrams;
        // the emptied buffers only replace an empty batch.
        if !batch.staged.is_empty() {
            return;
        }
        let (mut bytes, mut staged, mut sessions) = (bytes, staged, sessions);
        bytes.clear();
        staged.clear();
        sessions.clear();
        batch.bytes = bytes;
        batch.staged = staged;
        batch.sessions = sessions;
    });
}

fn send_held(inner: &Arc<Inner>, bytes: &[u8], staged: &[Staged], sessions: &[Held]) {
    let unsent = Datagram {
        payload: &[],
        dst: SocketAddr::from(([0, 0, 0, 0], 0)),
    };
    let mut datagrams = [unsent; BATCH_DATAGRAMS];
    for held in sessions {
        let mut count = 0;
        let mut next = Some(held.first);
        while let Some(index) = next
            && let Some(one) = staged.get(index)
            && let Some(slot) = datagrams.get_mut(count)
        {
            let payload = bytes.get(one.start..one.end);
            debug_assert!(
                payload.is_some(),
                "a staged datagram outside the round's bytes"
            );
            *slot = Datagram {
                payload: payload.unwrap_or_default(),
                dst: one.dst,
            };
            count += 1;
            next = one.next;
        }
        send_batch(
            inner,
            &held.session,
            datagrams.get(..count).unwrap_or_default(),
        );
    }
}

pub(super) fn send_batch(inner: &Arc<Inner>, session: &Arc<Session>, mut rest: &[Datagram<'_>]) {
    while !rest.is_empty() {
        if !idle(session) {
            break;
        }
        match poll_inline(|cx| session.inner.poll_send_batch(cx, rest)) {
            Poll::Ready(Ok(sent)) if sent > 0 => {
                let (done, left) = rest.split_at(sent.min(rest.len()));
                let bytes = done.iter().map(|datagram| datagram.payload.len() as u64);
                session.registration.tracked().uploaded(bytes.sum());
                rest = left;
            }
            Poll::Ready(Ok(_)) | Poll::Pending => break,
            Poll::Ready(Err(err)) => {
                if let Some(datagram) = rest.first()
                    && send_failed(inner, session, datagram.dst, &err)
                {
                    return;
                }
                rest = rest.get(1..).unwrap_or_default();
            }
        }
    }
    enqueue(
        inner,
        session,
        rest.iter().map(|datagram| {
            (
                Queued::Bytes(datagram.payload.into()),
                Address::Socket(datagram.dst),
            )
        }),
    );
}
