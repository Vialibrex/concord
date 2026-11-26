use std::collections::BTreeMap;

use super::wire::{ACK, ACK_CAPACITY, ControlPacket, SessionId};

const MESSAGE_ACKS: usize = 4;
const RECEIVE_CAPACITY: u32 = 12;

/// One key epoch's reliable layer, as mihomo's `ControlChannel` keeps it: numbered messages
/// that stay queued until acknowledged, ACKs that ride on later packets, and in-order
/// delivery of what arrives.
pub(super) struct Reliable {
    pub(super) key_id: u8,
    pub(super) local: SessionId,
    pub(super) remote: Option<SessionId>,
    full_acks: bool,
    next_send: u32,
    unacked: BTreeMap<u32, ControlPacket>,
    acks: Vec<u32>,
    recent: Vec<u32>,
    next_recv: u32,
    early: BTreeMap<u32, ControlPacket>,
}

impl Reliable {
    pub(super) fn new(local: SessionId, wrapped: bool) -> Reliable {
        Reliable {
            key_id: 0,
            local,
            remote: None,
            full_acks: wrapped,
            next_send: 0,
            unacked: BTreeMap::new(),
            acks: Vec::new(),
            recent: Vec::new(),
            next_recv: 0,
            early: BTreeMap::new(),
        }
    }

    pub(super) fn begin_epoch(&mut self, key_id: u8) {
        self.key_id = key_id;
        self.next_send = 0;
        self.unacked.clear();
        self.acks.clear();
        self.recent.clear();
        self.next_recv = 0;
        self.early.clear();
    }

    fn packet(&self, op: u8, acks: Vec<u32>) -> ControlPacket {
        ControlPacket {
            op,
            key_id: self.key_id,
            session: self.local,
            acks,
            ack_session: self.remote.unwrap_or_default(),
            ..ControlPacket::default()
        }
    }

    /// mihomo's `takeAcksLocked`, after OpenVPN's copy_acks_to_mru and reliable_ack_write:
    /// up to `max` pending ACKs move to the front of the recent list, and the packet repeats
    /// the newest entries of that list.
    fn take_acks(&mut self, max: usize) -> Vec<u32> {
        let taken = self.acks.len().min(max);
        for &id in self.acks.iter().take(taken).rev() {
            if let Some(at) = self.recent.iter().position(|seen| *seen == id) {
                self.recent.remove(at);
            }
            self.recent.insert(0, id);
        }
        self.recent.truncate(ACK_CAPACITY);
        self.acks.drain(..taken);
        self.recent.iter().take(max).copied().collect()
    }

    /// Queues a numbered message and returns the packet that first carries it.
    pub(super) fn message(&mut self, op: u8, payload: Vec<u8>) -> ControlPacket {
        let acks = self.take_acks(MESSAGE_ACKS);
        let mut packet = self.packet(op, acks);
        packet.message_id = self.next_send;
        packet.payload = payload;
        self.next_send = self.next_send.wrapping_add(1);
        self.unacked.insert(packet.message_id, packet.clone());
        packet
    }

    /// A dedicated ACK packet for what is still unacknowledged, if anything is.
    pub(super) fn ack_packet(&mut self) -> Option<ControlPacket> {
        if self.acks.is_empty() {
            return None;
        }
        let max = if self.full_acks {
            ACK_CAPACITY
        } else {
            MESSAGE_ACKS
        };
        let acks = self.take_acks(max);
        Some(self.packet(ACK, acks))
    }

    /// Every message still unacknowledged, each carrying the same fresh ACK set.
    pub(super) fn retransmit(&mut self) -> Vec<ControlPacket> {
        if self.unacked.is_empty() {
            return Vec::new();
        }
        let acks = self.take_acks(MESSAGE_ACKS);
        let remote = self.remote.unwrap_or_default();
        self.unacked
            .values()
            .map(|packet| ControlPacket {
                acks: acks.clone(),
                ack_session: remote,
                ..packet.clone()
            })
            .collect()
    }

    pub(super) fn unacked(&self) -> usize {
        self.unacked.len()
    }

    fn queue_ack(&mut self, id: u32) {
        if !self.acks.contains(&id) {
            self.acks.push(id);
        }
    }

    /// Marks message `id` delivered without receiving it here, for the peer's soft reset that
    /// opened this epoch.
    pub(super) fn delivered(&mut self, id: u32) {
        self.next_recv = id.wrapping_add(1);
        self.early.remove(&id);
        self.queue_ack(id);
    }

    /// Takes in a packet of this epoch and returns the messages now deliverable in order.
    /// A message is acknowledged only when it fits the receive window, so one that does not
    /// stays with the sender for a later retransmission.
    pub(super) fn receive(&mut self, packet: ControlPacket) -> Vec<ControlPacket> {
        for id in &packet.acks {
            self.unacked.remove(id);
        }
        if !packet.carries_message() {
            return Vec::new();
        }
        let id = packet.message_id;
        let ahead = id.wrapping_sub(self.next_recv);
        if ahead >= 1 << 31 {
            self.queue_ack(id);
            return Vec::new();
        }
        if ahead == 0 {
            self.queue_ack(id);
            self.next_recv = id.wrapping_add(1);
            let mut out = vec![packet];
            while let Some(next) = self.early.remove(&self.next_recv) {
                self.next_recv = self.next_recv.wrapping_add(1);
                out.push(next);
            }
            return out;
        }
        if self.early.contains_key(&id) {
            self.queue_ack(id);
        } else if ahead < RECEIVE_CAPACITY && (self.early.len() as u32) < RECEIVE_CAPACITY {
            self.early.insert(id, packet);
            self.queue_ack(id);
        }
        Vec::new()
    }
}
