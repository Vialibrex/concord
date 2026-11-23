use std::cmp::Reverse;
use std::collections::hash_map::RandomState;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::hash::BuildHasher;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Waker;
use std::time::Duration;

use tokio::time::Instant;

use crate::attach::{Attachment, Gather};
use crate::buffer::ChunkPool;
use crate::cc::Congestion;
use crate::readiness::SocketOwner;
use crate::seq::Seq;
use crate::stream::{ConnId, NetStream, Notifier, Shared};
use crate::tcp::{Egress, Event, Output, Tcb, TcpConfig, Wakes};
use crate::wire::{
    DropReason, FLAG_ACK, FLAG_RST, TcpHeader, TcpOptions, TcpSegment, emit_tcp, parse_tcp,
};

/// What the host decides for a new connection's SYN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Accept, remembering `tag` for when the handshake completes.
    Accept(u32),
    Reject,
    Drop,
}

/// A host registration kept until a connection leaves the TCP stack.
/// Called once when admitting a connection, outside its data I/O path.
pub trait FlowOwner: Send + Sync {
    /// `None` refuses admission when another stack owns the address pair.
    fn acquire(&self, local: SocketAddr, remote: SocketAddr) -> Option<Box<dyn Send + Sync>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpInput {
    Handled,
    /// A new connection was admitted and its SYN-ACK queued.
    Opened,
    /// Connection limits or another stack's ownership refused a SYN.
    Refused,
    /// A reset was sent: a rejected SYN or a segment for no connection.
    Reset,
    Dropped(DropReason),
}

/// A connection whose handshake completed, ready for the application.
pub struct Accepted {
    /// The address the peer connected to.
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub tag: u32,
    pub stream: NetStream,
}

#[derive(Clone, Copy, Debug)]
pub struct StackConfig {
    pub tcp: TcpConfig,
    pub max_connections: usize,
    pub max_half_open: usize,
}

impl Default for StackConfig {
    fn default() -> Self {
        StackConfig {
            tcp: TcpConfig::default(),
            max_connections: 32_768,
            max_half_open: 1024,
        }
    }
}

struct Conn {
    tcb: Tcb,
    shared: Arc<Shared>,
    tag: u32,
    passive: bool,
    half_open: bool,
    receiving: bool,
    touched: bool,
    sched_at: Option<u64>,
    socket: Option<Box<Attachment>>,
    _owner: Option<Box<dyn Send + Sync>>,
}

impl Conn {
    /// Closed but still owing an attached socket bytes, or not yet holding one it was given.
    fn draining(&self) -> bool {
        let state = self.shared.lock();
        state.error.is_none()
            && (state.attach.is_some() || self.socket.is_some() && !state.recv.is_empty())
    }
}

#[derive(Default)]
struct Slot {
    generation: u32,
    conn: Option<Box<Conn>>,
}

/// A TCP endpoint for every connection seen on one IP device. It is driven by its host:
/// segments go in through `input`, and `poll` sends what is due and says when to come back.
pub struct TcpStack {
    config: StackConfig,
    socket_owner: Option<Arc<dyn SocketOwner>>,
    start: Instant,
    slots: Vec<Slot>,
    free: Vec<u32>,
    by_addr: HashMap<(SocketAddr, SocketAddr), u32>,
    notifier: Arc<Notifier>,
    pool: Arc<ChunkPool>,
    timers: BinaryHeap<Reverse<(u64, u32, u32)>>,
    touched: Vec<ConnId>,
    blocked: Vec<ConnId>,
    dirty: Vec<ConnId>,
    accepted: VecDeque<Accepted>,
    wakes: Wakes,
    secret: RandomState,
    live: usize,
    half_open: usize,
    receiving: usize,
    receive_epoch: u64,
    flow_owner: Option<Arc<dyn FlowOwner>>,
}

impl TcpStack {
    pub fn new(config: StackConfig) -> Self {
        TcpStack {
            config,
            socket_owner: None,
            start: Instant::now(),
            slots: Vec::new(),
            free: Vec::new(),
            by_addr: HashMap::new(),
            notifier: Arc::default(),
            pool: Arc::default(),
            timers: BinaryHeap::new(),
            touched: Vec::new(),
            blocked: Vec::new(),
            dirty: Vec::new(),
            accepted: VecDeque::new(),
            wakes: Wakes::default(),
            secret: RandomState::new(),
            live: 0,
            half_open: 0,
            receiving: 0,
            receive_epoch: 0,
            flow_owner: None,
        }
    }

    /// Sets the host registration used for future connections.
    pub fn set_flow_owner(&mut self, owner: Arc<dyn FlowOwner>) {
        self.flow_owner = Some(owner);
    }

    pub fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_micros()).unwrap_or(u64::MAX)
    }

    pub fn with_socket_owner(mut self, owner: Option<Arc<dyn SocketOwner>>) -> Self {
        self.socket_owner = owner;
        self
    }

    pub fn instant_at(&self, at: u64) -> Instant {
        self.start + Duration::from_micros(at)
    }

    /// The waker to wake when an application reads, writes or closes.
    pub fn register_waker(&self, waker: &Waker) {
        self.notifier.register(waker);
    }

    pub fn len(&self) -> usize {
        self.live
    }

    /// Changes when the last connection stops receiving payload, before TIME_WAIT expires.
    pub fn receive_epoch(&self) -> u64 {
        self.receive_epoch
    }

    pub fn owns(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        self.by_addr.contains_key(&(local, remote))
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub fn take_accepted(&mut self) -> Option<Accepted> {
        self.accepted.pop_front()
    }

    fn iss(&self, local: SocketAddr, remote: SocketAddr, now: u64) -> Seq {
        let hash = self.secret.hash_one((local, remote));
        Seq((hash as u32).wrapping_add((now / 4) as u32))
    }

    fn insert(&mut self, tcb: Tcb, tag: u32, passive: bool) -> Option<(ConnId, Arc<Shared>)> {
        // Acquire before publishing any local connection state. A just-removed TIME_WAIT
        // connection may have released its address to another queue in the meantime.
        let owner = match &self.flow_owner {
            Some(owner) => Some(owner.acquire(tcb.local, tcb.remote)?),
            None => None,
        };
        let index = self.free.pop().unwrap_or_else(|| {
            self.slots.push(Slot::default());
            (self.slots.len() - 1) as u32
        });
        let generation = self
            .slots
            .get(index as usize)
            .map_or(0, |slot| slot.generation);
        let id = ConnId { index, generation };
        let shared = Arc::new(Shared::new(
            id,
            Arc::clone(&self.notifier),
            Arc::clone(&self.pool),
            0,
        ));
        self.by_addr.insert((tcb.local, tcb.remote), index);
        let half_open = tcb.is_half_open();
        if half_open {
            self.half_open += 1;
        }
        self.live += 1;
        self.receiving += 1;
        if let Some(slot) = self.slots.get_mut(index as usize) {
            slot.conn = Some(Box::new(Conn {
                tcb,
                shared: Arc::clone(&shared),
                tag,
                passive,
                half_open,
                receiving: true,
                touched: false,
                sched_at: None,
                socket: None,
                _owner: owner,
            }));
        }
        self.touch(id);
        Some((id, shared))
    }

    fn take(&mut self, id: ConnId) -> Option<Box<Conn>> {
        let slot = self.slots.get_mut(id.index as usize)?;
        if slot.generation != id.generation {
            return None;
        }
        slot.conn.take()
    }

    fn put_back(&mut self, id: ConnId, conn: Box<Conn>) {
        if let Some(slot) = self.slots.get_mut(id.index as usize) {
            slot.conn = Some(conn);
        }
    }

    fn stop_receiving(&mut self, receiving: &mut bool) {
        if std::mem::take(receiving) {
            self.receiving -= 1;
            if self.receiving == 0 {
                self.receive_epoch = self.receive_epoch.wrapping_add(1);
            }
        }
    }

    fn remove(&mut self, id: ConnId, mut conn: Box<Conn>) {
        self.stop_receiving(&mut conn.receiving);
        if self.by_addr.get(&(conn.tcb.local, conn.tcb.remote)) == Some(&id.index) {
            self.by_addr.remove(&(conn.tcb.local, conn.tcb.remote));
        }
        if conn.half_open {
            self.half_open -= 1;
        }
        self.live -= 1;
        {
            let mut state = conn.shared.lock();
            let result = state.error.map_or(Ok(()), Err);
            let unclaimed = state.attach.take();
            if let Some(socket) = conn.socket.as_deref() {
                socket.close(&mut state, result);
            } else if let Some(socket) = unclaimed.as_deref() {
                socket.close(&mut state, result);
            }
            state.passthrough = None;
            state.write_closed = true;
            if !state.recv_eof && state.error.is_none() {
                state.recv_eof = true;
            }
            self.wakes.add(state.wake_reader());
            self.wakes.add(state.wake_writer());
        }
        if let Some(slot) = self.slots.get_mut(id.index as usize) {
            slot.generation = slot.generation.wrapping_add(1);
            slot.conn = None;
        }
        self.free.push(id.index);
    }

    fn touch(&mut self, id: ConnId) {
        if let Some(conn) = self
            .slots
            .get_mut(id.index as usize)
            .filter(|slot| slot.generation == id.generation)
            .and_then(|slot| slot.conn.as_mut())
            && !conn.touched
        {
            conn.touched = true;
            self.touched.push(id);
        }
    }

    fn id_of(&self, index: u32) -> ConnId {
        ConnId {
            index,
            generation: self.slots.get(index as usize).map_or(0, |s| s.generation),
        }
    }

    /// Handles one TCP segment from the device. `admit` is asked about a SYN that starts a
    /// new connection.
    pub fn input(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        l4: &[u8],
        egress: &mut dyn Egress,
        admit: impl FnOnce(SocketAddr, SocketAddr) -> Admit,
    ) -> TcpInput {
        let mut gather = Gather::default();
        let result = self.input_gathered(src, dst, l4, egress, admit, &mut gather);
        self.flush(&mut gather);
        result
    }

    /// Like `input`, leaving payload for an attached socket in `gather`, borrowed from `l4`,
    /// until `flush`; the host keeps its segments until then and flushes before its next
    /// `poll`.
    pub fn input_gathered<'a>(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        l4: &'a [u8],
        egress: &mut dyn Egress,
        admit: impl FnOnce(SocketAddr, SocketAddr) -> Admit,
        gather: &mut Gather<'a>,
    ) -> TcpInput {
        let seg = match parse_tcp(l4) {
            Ok(seg) => seg,
            Err(reason) => return TcpInput::Dropped(reason),
        };
        let remote = SocketAddr::new(src, seg.src_port);
        let local = SocketAddr::new(dst, seg.dst_port);
        let now = self.now();
        if let Some(&index) = self.by_addr.get(&(local, remote)) {
            let id = self.id_of(index);
            let Some(mut conn) = self.take(id) else {
                return TcpInput::Handled;
            };
            if !gather.owned_by(&conn.shared) {
                self.flush(gather);
                gather.bind(&conn.shared);
            }
            if !(seg.is_syn() && conn.tcb.accepts_new_syn(&seg)) {
                self.segment(&mut conn, &seg, now, gather);
                self.settle(id, conn, egress);
                return TcpInput::Handled;
            }
            self.flush(gather);
            self.remove(id, conn);
        }
        if seg.has(FLAG_RST) {
            return TcpInput::Handled;
        }
        if !seg.is_syn() {
            send_reset(egress, local, remote, &seg);
            return TcpInput::Reset;
        }
        if self.live >= self.config.max_connections || self.half_open >= self.config.max_half_open {
            return TcpInput::Refused;
        }
        match admit(remote, local) {
            Admit::Accept(tag) => {
                let iss = self.iss(local, remote, now);
                let tcb = Tcb::passive(local, remote, &seg, self.config.tcp, iss, now);
                if self.insert(tcb, tag, true).is_some() {
                    TcpInput::Opened
                } else {
                    TcpInput::Refused
                }
            }
            Admit::Reject => {
                send_reset(egress, local, remote, &seg);
                TcpInput::Reset
            }
            Admit::Drop => TcpInput::Handled,
        }
    }

    fn segment<'a>(
        &mut self,
        conn: &mut Conn,
        seg: &TcpSegment<'a>,
        now: u64,
        gather: &mut Gather<'a>,
    ) {
        let event = {
            let mut state = conn.shared.lock();
            let event = conn
                .tcb
                .input(seg, now, &mut state, &self.pool, &mut self.wakes, gather);
            if state.recv_eof || state.error.is_some() || conn.tcb.is_closed() {
                self.stop_receiving(&mut conn.receiving);
                gather.write(&mut state, &self.pool);
            }
            event
        };
        self.on_event(conn, event);
    }

    fn on_event(&mut self, conn: &mut Conn, event: Event) {
        if event.established {
            if conn.half_open {
                conn.half_open = false;
                self.half_open -= 1;
            }
            if conn.passive {
                self.accepted.push_back(Accepted {
                    local: conn.tcb.local,
                    remote: conn.tcb.remote,
                    tag: conn.tag,
                    stream: NetStream::new(
                        Arc::clone(&conn.shared),
                        conn.tcb.local,
                        conn.tcb.remote,
                    ),
                });
            }
        }
    }

    fn settle(&mut self, id: ConnId, mut conn: Box<Conn>, egress: &mut dyn Egress) {
        if let Some(socket) = conn.socket.as_mut() {
            let finished = {
                let mut state = conn.shared.lock();
                socket.pump(&mut conn.tcb, &mut state, &self.pool, &mut self.wakes)
            };
            if finished {
                conn.socket = None;
            }
        }
        if let Some((local, remote, seq, ack)) = conn.tcb.take_reset() {
            send_rst_raw(egress, local, remote, seq, Some(ack));
        }
        if conn.tcb.is_closed() && !conn.draining() {
            self.remove(id, conn);
            return;
        }
        if !conn.touched {
            conn.touched = true;
            self.touched.push(id);
        }
        self.put_back(id, conn);
    }

    /// Opens a connection from `local` to `remote`; the stream is usable at once and its
    /// writes go out after the handshake.
    pub fn connect(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        congestion: Congestion,
    ) -> io::Result<NetStream> {
        if self.by_addr.contains_key(&(local, remote)) {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }
        if self.live >= self.config.max_connections {
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        let now = self.now();
        let iss = self.iss(local, remote, now);
        let config = TcpConfig {
            congestion,
            ..self.config.tcp
        };
        let tcb = Tcb::active(local, remote, config, iss, now);
        let (_, shared) = self
            .insert(tcb, 0, false)
            .ok_or_else(|| io::Error::from(io::ErrorKind::AddrInUse))?;
        Ok(NetStream::new(shared, local, remote))
    }

    pub fn is_bound(&self, local: SocketAddr, remote: SocketAddr) -> bool {
        self.by_addr.contains_key(&(local, remote))
    }

    /// Runs application notifications and due timers and sends what is pending. Returns
    /// when to call again at the latest, in the stack's clock.
    pub fn poll(&mut self, egress: &mut dyn Egress) -> Option<u64> {
        let now = self.now();
        self.run_dirty(now, egress);
        self.run_timers(now, egress);
        self.run_output(now, egress);
        self.wakes.wake();
        self.timers.peek().map(|Reverse((at, _, _))| *at)
    }

    fn run_dirty(&mut self, now: u64, egress: &mut dyn Egress) {
        let mut dirty = std::mem::take(&mut self.dirty);
        self.notifier.take(&mut dirty);
        for id in dirty.drain(..) {
            let Some(mut conn) = self.take(id) else {
                continue;
            };
            conn.shared.clear_queued();
            {
                let mut state = conn.shared.lock();
                if let Some(socket) = state.attach.take() {
                    match socket.activate(self.socket_owner.as_deref()) {
                        Ok(socket) => {
                            state.passthrough = Some(socket.socket());
                            conn.socket = Some(Box::new(socket));
                        }
                        Err(error) => {
                            conn.tcb.abort(&mut state, &mut self.wakes, error.kind());
                        }
                    }
                }
                if conn
                    .socket
                    .as_ref()
                    .is_some_and(|socket| socket.cancelled())
                {
                    let kind = io::ErrorKind::ConnectionAborted;
                    conn.tcb.abort(&mut state, &mut self.wakes, kind);
                    state.passthrough = None;
                    if let Some(socket) = conn.socket.take() {
                        socket.finish(Err(kind));
                    }
                }
                let aborted = conn.tcb.on_app_dropped(now, &mut state, &mut self.wakes);
                if !aborted && conn.tcb.window_update_due(&state) {
                    conn.tcb.request_ack();
                }
            }
            self.settle(id, conn, egress);
        }
        self.dirty = dirty;
    }

    fn run_timers(&mut self, now: u64, egress: &mut dyn Egress) {
        while let Some(Reverse((at, index, generation))) = self.timers.peek().copied() {
            if at > now {
                break;
            }
            self.timers.pop();
            let id = ConnId { index, generation };
            let Some(mut conn) = self.take(id) else {
                continue;
            };
            if conn.sched_at != Some(at) {
                self.put_back(id, conn);
                continue;
            }
            conn.sched_at = None;
            if conn.tcb.next_deadline().is_some_and(|due| due <= now) {
                let event = {
                    let mut state = conn.shared.lock();
                    conn.tcb.on_timer(now, &mut state, egress, &mut self.wakes)
                };
                self.on_event(&mut conn, event);
            }
            self.settle(id, conn, egress);
        }
    }

    fn run_output(&mut self, now: u64, egress: &mut dyn Egress) {
        // Connections waiting for room send first, in the order they began to wait, and the one
        // that used the room up goes behind them. Served after those that became ready since, a
        // waiting connection would send nothing for as long as a busy one keeps taking the room.
        // One that found no room at all keeps its place.
        let mut order = std::mem::take(&mut self.touched);
        let waiting = self.blocked.len();
        order.splice(0..0, self.blocked.drain(..));
        let mut out_of_room = false;
        let mut spent = None;
        for (position, id) in order.drain(..).enumerate() {
            let Some(mut conn) = self.take(id) else {
                continue;
            };
            if position >= waiting && !conn.touched {
                self.put_back(id, conn);
                continue;
            }
            conn.touched = false;
            if out_of_room {
                self.blocked.push(id);
            } else {
                let sent = {
                    let mut state = conn.shared.lock();
                    let sent = conn.tcb.output(now, &mut state, egress);
                    if state.send_room() > 0 {
                        self.wakes.add(state.wake_writer());
                        if conn.socket.as_ref().is_some_and(|socket| socket.limited()) {
                            conn.shared.notify();
                        }
                    }
                    sent
                };
                match sent {
                    Output::Done => {}
                    Output::Blocked => {
                        out_of_room = true;
                        self.blocked.push(id);
                    }
                    Output::Spent => {
                        out_of_room = true;
                        spent = Some(id);
                    }
                }
            }
            if let Some((local, remote, seq, ack)) = conn.tcb.take_reset() {
                send_rst_raw(egress, local, remote, seq, Some(ack));
            }
            if conn.tcb.is_closed() && !conn.draining() {
                self.remove(id, conn);
                continue;
            }
            if let Some(due) = conn.tcb.next_deadline()
                && conn.sched_at.is_none_or(|at| due < at)
            {
                conn.sched_at = Some(due);
                self.timers.push(Reverse((due, id.index, id.generation)));
            }
            self.put_back(id, conn);
        }
        self.blocked.extend(spent);
        self.touched = order;
    }

    /// Writes what `gather` holds to its connection's socket.
    pub fn flush(&mut self, gather: &mut Gather<'_>) {
        let Some(owner) = gather.take_owner() else {
            return;
        };
        if gather.is_empty() {
            return;
        }
        let queued = gather.write(&mut owner.lock(), &self.pool);
        if queued {
            owner.notify();
        }
    }

    pub fn has_blocked(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// Closes every connection; their streams fail with `ConnectionReset`.
    pub fn shutdown(&mut self) {
        for slot in &mut self.slots {
            if let Some(conn) = slot.conn.take() {
                let mut state = conn.shared.lock();
                let unclaimed = state.attach.take();
                if let Some(socket) = conn.socket.as_deref() {
                    socket.close(&mut state, Err(io::ErrorKind::ConnectionReset));
                } else if let Some(socket) = unclaimed.as_deref() {
                    socket.close(&mut state, Err(io::ErrorKind::ConnectionReset));
                }
                state.passthrough = None;
                for waker in state.fail(io::ErrorKind::ConnectionReset) {
                    self.wakes.add(waker);
                }
            }
        }
        self.by_addr.clear();
        self.timers.clear();
        self.touched.clear();
        self.blocked.clear();
        self.accepted.clear();
        self.live = 0;
        self.half_open = 0;
        if self.receiving != 0 {
            self.receiving = 0;
            self.receive_epoch = self.receive_epoch.wrapping_add(1);
        }
        self.wakes.wake();
        self.pool.trim();
    }
}

fn send_reset(
    egress: &mut dyn Egress,
    local: SocketAddr,
    remote: SocketAddr,
    seg: &TcpSegment<'_>,
) {
    if seg.has(FLAG_ACK) {
        send_rst_raw(egress, local, remote, Seq(seg.ack), None);
    } else {
        let ack = Seq(seg.seq) + seg.seq_len();
        send_rst_raw(egress, local, remote, Seq(0), Some(ack));
    }
}

fn send_rst_raw(
    egress: &mut dyn Egress,
    local: SocketAddr,
    remote: SocketAddr,
    seq: Seq,
    ack: Option<Seq>,
) {
    let header = TcpHeader {
        src: local,
        dst: remote,
        seq: seq.0,
        ack: ack.map_or(0, |a| a.0),
        flags: FLAG_RST | if ack.is_some() { FLAG_ACK } else { 0 },
        window: 0,
    };
    let checksum = egress.checksum();
    egress.send(&mut |buf| {
        emit_tcp(buf, &header, &TcpOptions::default(), 0, checksum, |_| {
            Some(())
        })
    });
}
