use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use concord_common::Network;
use concord_netstack::wire::{
    DropReason, IpView, L4Checksum, L4Kind, Parsed, UdpView, build_echo_reply, parse_packet,
    parse_udp, parse_udp_unverified,
};
use concord_netstack::{Admit, Gather, TcpInput};

use super::{Driver, PoolEgress, QueueRole};
use crate::device::Device;
use crate::dns;
use crate::stack::pool::TxPool;
use crate::stack::stats::StackStats;
use crate::stack::{DnsConfig, Verdict, flow_key};

const TAG_FLOW: u32 = 0;
const TAG_DNS: u32 = 1;

enum Route {
    Local,
    Reserved,
    Forwarded,
}

impl QueueRole {
    /// Hands a segment to its owner, or records a new local reservation for admission.
    fn route_unbound(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        syn: bool,
        packet: &[u8],
        stats: &StackStats,
    ) -> Route {
        let QueueRole::Multi { index, queues } = self else {
            return Route::Local;
        };
        let owner = if syn {
            queues.claim((local, remote), *index)
        } else {
            queues.owner(&(local, remote)).unwrap_or(*index)
        };
        if owner == *index {
            return if syn { Route::Reserved } else { Route::Local };
        }
        if !queues.forward(owner, packet) {
            stats.rx_handoff.fetch_add(1, Ordering::Relaxed);
        }
        Route::Forwarded
    }
}

fn echo_reply(pool: &TxPool, stats: &StackStats, view: &IpView<'_>) {
    let Some(mut slot) = pool.take_free() else {
        return;
    };
    match build_echo_reply(&mut slot.buf, view) {
        Some(len) => {
            slot.len = len;
            pool.push_filled(slot);
            stats.icmp_echo.fetch_add(1, Ordering::Relaxed);
        }
        None => pool.release(slot),
    }
}

impl<D: Device> Driver<D> {
    pub(super) fn handle_packet<'a>(&mut self, packet: &'a [u8], gather: &mut Gather<'a>) {
        match parse_packet(packet) {
            Ok(Parsed::Packet(view)) => self.dispatch(&view, gather),
            Ok(Parsed::Fragment(frag)) => {
                self.tcp.flush(gather);
                let mut whole = std::mem::take(&mut self.reassembled);
                if self.fragments.push(&frag, self.tcp.now(), &mut whole) {
                    match parse_packet(&whole) {
                        Ok(Parsed::Packet(view)) => {
                            let mut own = Gather::default();
                            self.dispatch(&view, &mut own);
                            self.tcp.flush(&mut own);
                        }
                        Ok(Parsed::Fragment(_)) => self.stats.count_drop(DropReason::Fragment),
                        Err(reason) => self.stats.count_drop(reason),
                    }
                }
                self.reassembled = whole;
            }
            Err(reason) => self.stats.count_drop(reason),
        }
    }

    fn parse_udp<'a>(&self, view: &IpView<'a>) -> Result<UdpView<'a>, DropReason> {
        match self.pool.checksum {
            L4Checksum::Full => parse_udp(view),
            L4Checksum::Pseudo => parse_udp_unverified(view),
        }
    }

    fn dispatch<'a>(&mut self, view: &IpView<'a>, gather: &mut Gather<'a>) {
        if self.options.broadcast == Some(view.dst) {
            return self.stats.count_drop(DropReason::Martian);
        }
        match view.kind {
            L4Kind::Icmp => self.on_icmp(view),
            L4Kind::Udp => match self.parse_udp(view) {
                Ok(udp) => self.on_udp(view, udp.src_port, udp.dst_port, udp.payload),
                Err(reason) => self.stats.count_drop(reason),
            },
            L4Kind::Tcp => self.on_tcp(view, gather),
        }
    }

    fn on_icmp(&mut self, view: &IpView<'_>) {
        if !self.options.disable_icmp_forwarding {
            let request = view.packet.to_vec();
            let pool = Arc::clone(&self.pool);
            let stats = Arc::clone(&self.stats);
            let answer = Box::new(move || {
                if let Ok(Parsed::Packet(view)) = parse_packet(&request) {
                    echo_reply(&pool, &stats, &view);
                }
            });
            if self.sink.icmp(view.dst, view.l4, answer) {
                return;
            }
        }
        echo_reply(&self.pool, &self.stats, view);
    }

    fn hijacks(dns: Option<&DnsConfig>, dst: SocketAddr) -> bool {
        dns.is_some_and(|dns| dns.matcher.matches(dst))
    }

    fn on_udp(&mut self, view: &IpView<'_>, src_port: u16, dst_port: u16, payload: &[u8]) {
        let src = SocketAddr::new(view.src, src_port);
        let dst = SocketAddr::new(view.dst, dst_port);
        self.stats.udp_packets.fetch_add(1, Ordering::Relaxed);
        let reply = self.udp.reply_for(src);
        if Self::hijacks(self.dns.as_deref(), dst) {
            self.stats.dns_hijacked.fetch_add(1, Ordering::Relaxed);
            if let (Some(dns), Ok(permit)) = (
                self.dns.as_ref(),
                Arc::clone(&self.dns_slots).try_acquire_owned(),
            ) {
                let handler = Arc::clone(&dns.handler);
                let query = payload.to_vec();
                let reply = reply.into_owned();
                self.handlers.spawn(async move {
                    let _permit = permit;
                    dns::answer_udp(handler, reply, dst, query).await;
                });
            }
            return;
        }
        self.sink
            .udp(flow_key(Network::Udp, src, dst), payload, &reply);
    }

    pub(super) fn drain_handoffs(&mut self) -> bool {
        let QueueRole::Multi { index, queues } = &self.queue else {
            return false;
        };
        let packets = queues.take(*index);
        let any = !packets.is_empty();
        for packet in packets {
            let mut own = Gather::default();
            self.handle_packet(&packet, &mut own);
            self.tcp.flush(&mut own);
        }
        any
    }

    fn on_tcp<'a>(&mut self, view: &IpView<'a>, gather: &mut Gather<'a>) {
        let arrival = match self.tcp.arrival(view.src, view.dst, view.l4) {
            Ok(arrival) => arrival,
            Err(reason) => return self.stats.count_drop(reason),
        };
        let reserved = if let Some((local, remote, syn)) = arrival.unbound() {
            match self
                .queue
                .route_unbound(local, remote, syn, view.packet, &self.stats)
            {
                Route::Forwarded => return,
                Route::Reserved => Some((local, remote)),
                Route::Local => None,
            }
        } else {
            None
        };
        let dns = self.dns.as_deref();
        let sink = &self.sink;
        let packet = view.packet;
        let result = arrival.deliver(
            &mut PoolEgress::new(&self.pool, &self.dev, &self.inflight),
            |remote, local| {
                if Self::hijacks(dns, local) {
                    return Admit::Accept(TAG_DNS);
                }
                match sink.judge(&flow_key(Network::Tcp, remote, local), packet) {
                    Verdict::Accept => Admit::Accept(TAG_FLOW),
                    Verdict::Reject => Admit::Reject,
                    Verdict::Drop => Admit::Drop,
                }
            },
            gather,
        );
        if let Some(key) = reserved
            && let QueueRole::Multi { index, queues } = &self.queue
            && !self.tcp.owns(key.0, key.1)
        {
            queues.release_unopened(&key, *index);
        }
        match result {
            TcpInput::Refused => {
                self.stats.tcp_refused.fetch_add(1, Ordering::Relaxed);
            }
            TcpInput::Dropped(reason) => self.stats.count_drop(reason),
            TcpInput::Handled | TcpInput::Opened | TcpInput::Reset => {}
        }
    }

    pub(super) fn announce(&mut self) {
        while let Some(accepted) = self.tcp.take_accepted() {
            self.stats.tcp_accepted.fetch_add(1, Ordering::Relaxed);
            if accepted.tag == TAG_DNS {
                self.stats.dns_hijacked.fetch_add(1, Ordering::Relaxed);
                if let Some(dns) = &self.dns {
                    self.handlers
                        .spawn(dns::serve_tcp(accepted.stream, Arc::clone(&dns.handler)));
                }
                continue;
            }
            self.sink.tcp(
                flow_key(Network::Tcp, accepted.remote, accepted.local),
                Box::new(accepted.stream),
            );
        }
    }
}
