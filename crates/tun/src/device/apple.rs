use super::*;

impl Device for TunDevice {
    fn poll_recv(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, buf)
    }

    fn poll_send(&self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        self.inner.poll_send(cx, packet)
    }

    const BATCH: usize = concord_platform::UTUN_BATCH;

    fn poll_recv_batch(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        stride: usize,
        lens: &mut [usize],
    ) -> Poll<io::Result<usize>> {
        use std::io::IoSliceMut;
        use std::os::fd::AsRawFd;

        let mut slots: [IoSliceMut<'_>; MAX_BATCH] =
            std::array::from_fn(|_| IoSliceMut::new(&mut []));
        let mut count = 0;
        for (slot, chunk) in slots
            .iter_mut()
            .zip(buf.chunks_exact_mut(stride))
            .take(lens.len())
        {
            *slot = IoSliceMut::new(chunk);
            count += 1;
        }
        let batch = slots.get_mut(..count).unwrap_or_default();
        let budget = std::task::ready!(tokio::task::coop::poll_proceed(cx));
        match concord_platform::utun_recv_batch(self.inner.as_raw_fd(), batch, lens) {
            Ok(0) => {}
            Ok(received) => {
                budget.made_progress();
                return Poll::Ready(Ok(received));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Poll::Ready(Err(err)),
        }
        recv_one(self, cx, buf, stride, lens)
    }

    fn poll_send_batch(
        &self,
        cx: &mut Context<'_>,
        packets: &[&[u8]],
        failed: &mut usize,
    ) -> Poll<usize> {
        use std::os::fd::AsRawFd;

        let small = packets
            .iter()
            .take_while(|packet| packet.len() <= concord_platform::UTUN_BATCH_FRAME)
            .count();
        if let Some(run) = packets.get(..small).filter(|run| run.len() > 1) {
            match concord_platform::utun_send_batch(self.inner.as_raw_fd(), run) {
                Ok(0) => {}
                Ok(sent) => return Poll::Ready(sent),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    *failed += run.len();
                    return Poll::Ready(run.len());
                }
            }
        }
        send_one(self, cx, packets, failed)
    }
}
