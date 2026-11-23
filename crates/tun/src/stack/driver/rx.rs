use std::io;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use concord_netstack::Gather;
use concord_netstack::wire::DropReason;
use concord_platform::SparseBuf;

use super::{Driver, ROUND_READ_BYTES, RX_BATCH};
use crate::device::{Device, MAX_BATCH};

#[derive(Default)]
struct ReadRound {
    packets: usize,
    bytes: usize,
}

impl ReadRound {
    fn has_room(&self) -> bool {
        self.packets < RX_BATCH && self.bytes < ROUND_READ_BYTES
    }
}

impl<D: Device> Driver<D> {
    pub(super) fn retire_rx(&mut self) {
        let epoch = self.tcp.receive_epoch();
        if epoch != self.rx_receive_epoch {
            self.rx_receive_epoch = epoch;
            if self.rx_extended {
                // Every gather has been flushed; closed receive owners no longer need this
                // working set. Keep single-frame traffic from rebuilding it on each close.
                self.rx_buf = SparseBuf::zeroed(self.rx_stride * RX_BATCH);
                self.rx_extended = false;
            }
        }
    }

    pub(super) fn drain_rx(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        let mut buf = std::mem::take(&mut self.rx_buf);
        let mut round = ReadRound::default();
        let mut outcome = Ok(());
        loop {
            let mut gather = Gather::default();
            let again = self.read_into(cx, &mut buf, &mut round, &mut outcome, &mut gather);
            self.tcp.flush(&mut gather);
            if !again {
                break;
            }
        }
        self.rx_buf = buf;
        outcome.map(|()| round.packets > 0)
    }

    /// Reads packets into `buf`, each right after the last; true when `gather` holds none of
    /// them and the batch goes on, so the next read can start over at the front.
    fn read_into<'a>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &'a mut [u8],
        round: &mut ReadRound,
        outcome: &mut io::Result<()>,
        gather: &mut Gather<'a>,
    ) -> bool {
        let device_batch = D::BATCH.clamp(1, MAX_BATCH);
        let stride = self.rx_stride;
        let offset = self.dev.rx_offset();
        let lens = [0usize; MAX_BATCH];
        let capacity = buf.len();
        let mut free: &'a mut [u8] = buf;
        while round.has_room() {
            let want = self
                .rx_batch
                .min(RX_BATCH - round.packets)
                .min(free.len() / stride);
            if want == 0 {
                return false;
            }
            let mut lens = lens;
            let wanted = lens.get_mut(..want).unwrap_or_default();
            let received = match self.dev.poll_recv_batch(cx, free, stride, wanted) {
                Poll::Pending => return false,
                Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::Interrupted => continue,
                Poll::Ready(Err(err)) => {
                    tracing::error!("tun device read failed, the stack stops: {err}");
                    *outcome = Err(err);
                    return false;
                }
                Poll::Ready(Ok(received)) => received.min(want),
            };
            if device_batch > 1 {
                if received == want {
                    self.rx_batch = (want * 2).min(device_batch);
                } else if received * 2 < want {
                    self.rx_batch = (want / 2).max(1);
                }
            }
            round.packets += received.max(1);
            round.bytes += lens.iter().take(received).sum::<usize>();
            self.stats
                .rx_packets
                .fetch_add(received as u64, Ordering::Relaxed);
            let used = match received.checked_sub(1) {
                Some(last) => last * stride + offset + lens.get(last).copied().unwrap_or(0),
                None => 0,
            };
            let rest = std::mem::take(&mut free);
            let (filled, rest) = rest.split_at_mut(used.min(rest.len()));
            free = rest;
            self.rx_extended |= capacity - free.len() > stride;
            let filled: &'a [u8] = filled;
            for (index, len) in lens.iter().take(received).enumerate() {
                let start = index * stride + offset;
                match filled
                    .get(start..start + len)
                    .filter(|packet| !packet.is_empty())
                {
                    Some(packet) => self.handle_packet(packet, gather),
                    None => self.stats.count_drop(DropReason::Malformed),
                }
            }
            if gather.is_empty() && round.has_room() {
                return true;
            }
        }
        false
    }
}
