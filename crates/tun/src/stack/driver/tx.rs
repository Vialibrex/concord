use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use concord_netstack::Egress;
use concord_netstack::wire::L4Checksum;

use super::{Driver, MAX_FRAME};
use crate::device::{Device, MAX_BATCH};
use crate::stack::pool::{Slot, TxPool};

/// Builds the stack's packets in place in the device's transmit pool, or hands a payload
/// straight to the device while nothing waits ahead of it.
pub(super) struct PoolEgress<'a, D> {
    pool: &'a TxPool,
    dev: &'a D,
    direct: bool,
}

impl<'a, D: Device> PoolEgress<'a, D> {
    pub(super) fn new(pool: &'a TxPool, dev: &'a D, inflight: &VecDeque<Slot>) -> Self {
        let direct = inflight.is_empty() && !pool.has_filled();
        PoolEgress { pool, dev, direct }
    }
}

impl<D: Device> Egress for PoolEgress<'_, D> {
    fn checksum(&self) -> L4Checksum {
        self.pool.checksum
    }

    fn segment_limit(&self) -> usize {
        self.pool.segment_limit.load(Ordering::Relaxed)
    }

    fn send(&mut self, build: &mut dyn FnMut(&mut [u8]) -> Option<usize>) -> bool {
        self.send_segmented(0, build)
    }

    fn send_segmented(
        &mut self,
        segment: u16,
        build: &mut dyn FnMut(&mut [u8]) -> Option<usize>,
    ) -> bool {
        let Some(mut slot) = self.pool.take_free() else {
            return false;
        };
        if segment > 0 {
            slot.grow(MAX_FRAME);
        }
        match build(&mut slot.buf) {
            Some(len) => {
                slot.len = len;
                slot.segment = segment;
                self.pool.push_filled(slot);
                self.direct = false;
            }
            None => self.pool.release(slot),
        }
        true
    }

    fn send_in_place(&mut self, segment: u16, head: &[u8], payload: &[IoSlice<'_>]) -> bool {
        if !self.direct {
            return false;
        }
        let mut parts = [IoSlice::new(&[]); 1 + concord_netstack::PAYLOAD_SLICES];
        let Some((first, rest)) = parts.split_first_mut() else {
            return false;
        };
        let Some(tail) = rest.get_mut(..payload.len()) else {
            return false;
        };
        *first = IoSlice::new(head);
        tail.copy_from_slice(payload);
        let count = payload.len() + 1;
        self.direct = self
            .dev
            .try_send_parts(parts.get(..count).unwrap_or_default(), segment)
            .is_ok();
        self.direct
    }
}

impl<D: Device> Driver<D> {
    pub(super) fn flush(&mut self, cx: &mut Context<'_>) -> bool {
        let batch = self.dev.send_batch().clamp(1, MAX_BATCH);
        let mut released = false;
        loop {
            while self.inflight.len() < batch
                && let Some(slot) = self.pool.pop_filled()
            {
                self.inflight.push_back(slot);
            }
            if self.inflight.is_empty() {
                return released;
            }
            if let Some(front) = self.inflight.front()
                && front.segment > 0
            {
                let Poll::Ready(result) =
                    self.dev
                        .poll_send_segmented(cx, front.packet(), front.segment)
                else {
                    return released;
                };
                if let Err(err) = result {
                    self.stats.tx_errors.fetch_add(1, Ordering::Relaxed);
                    if err.kind() == io::ErrorKind::InvalidInput {
                        tracing::warn!("tun refused a segmented frame, sending segments: {err}");
                        self.pool.segment_limit.store(0, Ordering::Relaxed);
                    }
                }
                if let Some(slot) = self.inflight.pop_front() {
                    self.pool.release(slot);
                }
                released = true;
                continue;
            }
            let plain = self
                .inflight
                .iter()
                .take_while(|slot| slot.segment == 0)
                .count();
            let mut packets: [&[u8]; MAX_BATCH] = [&[]; MAX_BATCH];
            for (packet, slot) in packets.iter_mut().zip(&self.inflight) {
                *packet = slot.packet();
            }
            let mut failed = 0;
            let ready = packets.get(..plain).unwrap_or_default();
            let Poll::Ready(sent) = self.dev.poll_send_batch(cx, ready, &mut failed) else {
                return released;
            };
            if sent == 0 {
                return released;
            }
            self.stats
                .tx_errors
                .fetch_add(failed as u64, Ordering::Relaxed);
            for slot in self.inflight.drain(..sent.min(self.inflight.len())) {
                self.pool.release(slot);
            }
            released = true;
        }
    }
}
