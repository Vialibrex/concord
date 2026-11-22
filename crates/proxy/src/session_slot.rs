use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use crate::util::lock;

/// Counts the resets of a node's shared connections, so that a dial can tell whether one ran
/// while it was under way: what it made then went out on the network the reset left.
#[derive(Default)]
pub(crate) struct Resets(u64);

/// The resets a dial started after.
#[derive(Clone, Copy)]
pub(crate) struct Ticket(u64);

impl Resets {
    pub(crate) fn ticket(&self) -> Ticket {
        Ticket(self.0)
    }

    pub(crate) fn bump(&mut self) {
        self.0 = self.0.wrapping_add(1);
    }

    pub(crate) fn none_since(&self, ticket: Ticket) -> bool {
        self.0 == ticket.0
    }
}

/// What a dial that a reset overtook fails with, as sing-quic fails the callers waiting on a
/// handshake its reset discards.
pub(crate) fn overtaken() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the network changed while connecting",
    )
}

/// A shared dial's failure as each waiting caller gets it, with the error it carries whole, so
/// that one saying the process ran out of descriptors still says so.
#[derive(Debug)]
struct SharedFailure(Arc<io::Error>);

impl std::fmt::Display for SharedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SharedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

type Outcome<T> = Option<Result<Arc<T>, Arc<io::Error>>>;

fn dropped() -> io::Error {
    io::Error::other("the shared dial was dropped")
}

/// A dial `offer_detached` started, for the task that runs it to `settle`.
pub(crate) struct Dial<T> {
    ticket: Ticket,
    done: watch::Sender<Outcome<T>>,
    mine: watch::Receiver<Outcome<T>>,
}

/// A node's one shared connection.
pub(crate) struct SessionSlot<T> {
    held: Mutex<Held<T>>,
}

struct Held<T> {
    resets: Resets,
    conn: Option<Arc<T>>,
    detached: Option<watch::Receiver<Outcome<T>>>,
}

impl<T> Default for SessionSlot<T> {
    fn default() -> Self {
        SessionSlot {
            held: Mutex::new(Held {
                resets: Resets::default(),
                conn: None,
                detached: None,
            }),
        }
    }
}

impl<T> SessionSlot<T> {
    /// The held connection if `usable` says it still is, and the ticket a dial for a new one
    /// starts with.
    pub(crate) fn get(&self, usable: impl Fn(&T) -> bool) -> (Option<Arc<T>>, Ticket) {
        let held = lock(&self.held);
        let conn = held.conn.as_ref().filter(|conn| usable(conn)).cloned();
        (conn, held.resets.ticket())
    }

    /// Holds `conn` unless a reset ran since `ticket`. On false the caller tears `conn` down.
    pub(crate) fn keep(&self, ticket: Ticket, conn: &Arc<T>) -> bool {
        let mut held = lock(&self.held);
        if !held.resets.none_since(ticket) {
            return false;
        }
        held.conn = Some(conn.clone());
        true
    }

    /// `offer`'s last step, for a dial that runs outside it, such as a handshake its callers
    /// share from a task of its own.
    pub(crate) fn adopt(
        &self,
        ticket: Ticket,
        conn: Arc<T>,
        discard: impl FnOnce(Arc<T>),
    ) -> io::Result<Arc<T>> {
        if !self.keep(ticket, &conn) {
            discard(conn);
            return Err(overtaken());
        }
        Ok(conn)
    }

    /// The held connection if `usable` says it still is, or the one `establish` makes. `dialing`
    /// lets one dial run at a time, so the callers that wait for it take what it made.
    pub(crate) async fn offer<F>(
        &self,
        dialing: &tokio::sync::Mutex<()>,
        usable: impl Fn(&T) -> bool,
        establish: impl FnOnce() -> F,
        discard: impl FnOnce(Arc<T>),
    ) -> io::Result<Arc<T>>
    where
        F: Future<Output = io::Result<Arc<T>>>,
    {
        if let (Some(conn), _) = self.get(&usable) {
            return Ok(conn);
        }
        let _turn = dialing.lock().await;
        let (held, ticket) = self.get(&usable);
        if let Some(conn) = held {
            return Ok(conn);
        }
        self.adopt(ticket, establish().await?, discard)
    }

    /// Like `offer`, but `start` spawns the dial with the [`Dial`] it then settles, so a caller that
    /// stops waiting after `wait` leaves it running for the next, as sing-quic's offer does. A reset
    /// detaches it: later callers start their own and the waiting ones get its failure.
    pub(crate) async fn offer_detached(
        &self,
        usable: impl Fn(&T) -> bool,
        wait: Option<Duration>,
        start: impl FnOnce(Dial<T>),
    ) -> io::Result<Arc<T>> {
        let (mut outcome, dial) = {
            let mut held = lock(&self.held);
            if let Some(conn) = held.conn.as_ref().filter(|conn| usable(conn)) {
                return Ok(conn.clone());
            }
            match &held.detached {
                Some(running) => (running.clone(), None),
                None => {
                    let (done, mine) = watch::channel(None);
                    held.detached = Some(mine.clone());
                    let ticket = held.resets.ticket();
                    let dial = Dial {
                        ticket,
                        done,
                        mine: mine.clone(),
                    };
                    (mine, Some(dial))
                }
            }
        };
        if let Some(dial) = dial {
            start(dial);
        }
        let settled = outcome.wait_for(Option::is_some);
        let settled = match wait {
            Some(left) => tokio::time::timeout(left, settled)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?,
            None => settled.await,
        };
        match settled.map_err(|_| dropped())?.clone() {
            Some(Ok(conn)) => Ok(conn),
            Some(Err(err)) => Err(io::Error::new(err.kind(), SharedFailure(err))),
            None => Err(dropped()),
        }
    }

    /// Keeps what `dial` made as `offer` would and hands the outcome to its callers.
    pub(crate) fn settle(
        &self,
        dial: Dial<T>,
        made: io::Result<Arc<T>>,
        discard: impl FnOnce(Arc<T>),
    ) {
        let outcome = made
            .and_then(|conn| self.adopt(dial.ticket, conn, discard))
            .map_err(Arc::new);
        {
            let mut held = lock(&self.held);
            if held
                .detached
                .as_ref()
                .is_some_and(|running| running.same_channel(&dial.mine))
            {
                held.detached = None;
            }
        }
        let _ = dial.done.send(Some(outcome));
    }

    #[cfg(test)]
    pub(crate) fn dialing_detached(&self) -> bool {
        lock(&self.held).detached.is_some()
    }

    pub(crate) fn reset(&self) -> Option<Arc<T>> {
        let mut held = lock(&self.held);
        held.resets.bump();
        held.detached = None;
        held.conn.take()
    }

    pub(crate) fn forget(&self, conn: &Arc<T>) {
        let mut held = lock(&self.held);
        if held
            .conn
            .as_ref()
            .is_some_and(|kept| Arc::ptr_eq(kept, conn))
        {
            held.conn = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_dialled_before_a_reset_is_not_kept() {
        let slot = SessionSlot::default();
        let (_, before) = slot.get(|_: &u8| true);
        assert!(slot.reset().is_none());
        assert!(!slot.keep(before, &Arc::new(1)));
        assert!(slot.get(|_| true).0.is_none());
        let (_, after) = slot.get(|_| true);
        assert!(slot.keep(after, &Arc::new(2)));
        assert_eq!(slot.get(|_| true).0.as_deref(), Some(&2));
        assert!(slot.get(|value| *value != 2).0.is_none());
    }

    #[test]
    fn forgetting_takes_out_only_the_connection_named() {
        let slot = SessionSlot::default();
        let (first, second) = (Arc::new(1u8), Arc::new(1u8));
        assert!(slot.keep(slot.get(|_| true).1, &first));
        slot.forget(&second);
        assert!(slot.get(|_| true).0.is_some());
        slot.forget(&first);
        assert!(slot.get(|_| true).0.is_none());
    }

    #[tokio::test]
    async fn callers_that_wait_take_what_the_one_dial_made() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (slot, dialing) = (SessionSlot::default(), tokio::sync::Mutex::new(()));
        let dials = AtomicUsize::new(0);
        let dial = || async {
            dials.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            Ok(Arc::new(7u8))
        };
        let (first, second) = tokio::join!(
            slot.offer(&dialing, |_| true, dial, |_| {}),
            slot.offer(&dialing, |_| true, dial, |_| {}),
        );
        assert!(Arc::ptr_eq(&first.unwrap(), &second.unwrap()));
        assert_eq!(dials.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_dial_a_reset_overtook_is_discarded() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let (slot, dialing) = (SessionSlot::default(), tokio::sync::Mutex::new(()));
        let discarded = AtomicBool::new(false);
        let dial = || async {
            slot.reset();
            Ok(Arc::new(1u8))
        };
        let discard = |_| discarded.store(true, Ordering::SeqCst);
        let err = slot
            .offer(&dialing, |_| true, dial, discard)
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(discarded.load(Ordering::SeqCst));
        assert!(slot.get(|_| true).0.is_none());
    }

    #[tokio::test]
    async fn a_detached_dial_outlives_the_caller_that_gave_up_and_serves_the_next() {
        let slot = Arc::new(SessionSlot::default());
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let runner = slot.clone();
        let start = move |dial: Dial<u8>| {
            tokio::spawn(async move {
                let _ = released.await;
                runner.settle(dial, Ok(Arc::new(3)), |_| {});
            });
        };
        let gave_up = slot
            .offer_detached(|_| true, Some(std::time::Duration::from_millis(10)), start)
            .await;
        assert_eq!(
            gave_up.err().map(|err| err.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert!(slot.dialing_detached());
        let waiting = slot.offer_detached(|_| true, None, |_| panic!("a second dial started"));
        let _ = release.send(());
        assert_eq!(*waiting.await.unwrap(), 3);
        assert!(!slot.dialing_detached());
        assert_eq!(slot.get(|_| true).0.as_deref(), Some(&3));
    }

    #[tokio::test]
    async fn a_reset_detaches_a_running_dial_and_fails_its_callers() {
        let slot = Arc::new(SessionSlot::default());
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let runner = slot.clone();
        let start = move |dial: Dial<u8>| {
            tokio::spawn(async move {
                let _ = released.await;
                runner.settle(dial, Ok(Arc::new(4)), |_| {});
            });
        };
        let waiting = tokio::spawn({
            let slot = slot.clone();
            async move { slot.offer_detached(|_| true, None, start).await }
        });
        while !slot.dialing_detached() {
            tokio::task::yield_now().await;
        }
        slot.reset();
        assert!(!slot.dialing_detached());
        let _ = release.send(());
        let err = waiting.await.unwrap().err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(slot.get(|_| true).0.is_none());
    }
}
