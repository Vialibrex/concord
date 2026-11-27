use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Context;

use futures_util::task::AtomicWaker;

/// Set by the writer of a stream that cannot half-close when its shutdown ends the whole stream,
/// for the reader, which may sit in the other half of a split, to end at once.
#[derive(Default)]
pub(crate) struct Ended {
    ended: AtomicBool,
    reader: AtomicWaker,
}

impl Ended {
    pub(crate) fn end(&self) {
        self.ended.store(true, Ordering::Release);
        self.reader.wake();
    }

    /// Registers the reader before it looks, so an `end` that races the read still wakes it.
    pub(crate) fn poll_ended(&self, cx: &Context<'_>) -> bool {
        self.reader.register(cx.waker());
        self.ended.load(Ordering::Acquire)
    }
}
