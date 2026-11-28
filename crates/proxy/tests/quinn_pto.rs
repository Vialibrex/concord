//! Recovery and ACK bundling contracts over two real QUIC state machines with a virtual link.
use std::collections::{BTreeMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use concord_test_support::localhost_tls;
use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, EcnCodepoint, Endpoint, Event,
    ReadError, ServerConfig, StreamEvent, StreamId, TransportConfig,
};

type Packet = (Option<EcnCodepoint>, Bytes);
/// Quinn skips a random packet number now and then (optimistic-ACK defense), and a receiver that sees the gap
/// acknowledges at once. These seeds keep the server's skips out of the exchanges the datagram contracts count; a
/// skip there fails them on every run, not now and then.
const CLIENT_SEED: [u8; 32] = [1; 32];
const SERVER_SEED: [u8; 32] = [2; 32];
struct Side {
    endpoint: Endpoint,
    conn: Option<Connection>,
    handle: Option<ConnectionHandle>,
    addr: SocketAddr,
    inbound: VecDeque<(Instant, Packet)>,
}
impl Side {
    fn conn(&mut self) -> &mut Connection {
        self.conn.as_mut().unwrap()
    }
    fn ingest(&mut self, now: Instant, remote: SocketAddr) {
        let mut response = Vec::new();
        while self.inbound.front().is_some_and(|(t, _)| *t <= now) {
            let (received, (ecn, bytes)) = self.inbound.pop_front().unwrap();
            match self.endpoint.handle(
                received,
                remote,
                None,
                ecn,
                BytesMut::from(bytes.as_ref()),
                &mut response,
            ) {
                Some(DatagramEvent::NewConnection(incoming)) => {
                    let (handle, conn) = self
                        .endpoint
                        .accept(incoming, now, &mut response, None)
                        .unwrap();
                    assert!(self.conn.replace(conn).is_none());
                    self.handle = Some(handle);
                }
                Some(DatagramEvent::ConnectionEvent(_, event)) => self.conn().handle_event(event),
                Some(DatagramEvent::Response(_)) => panic!("unexpected stateless response"),
                None => {}
            }
        }
    }
    fn emit(&mut self, now: Instant) -> Vec<Packet> {
        let Some(conn) = &mut self.conn else {
            return Vec::new();
        };
        if conn.poll_timeout().is_some_and(|t| t <= now) {
            conn.handle_timeout(now);
        }
        while let Some(event) = conn.poll_endpoint_events() {
            if let Some(event) = self.endpoint.handle_event(self.handle.unwrap(), event) {
                conn.handle_event(event);
            }
        }
        let mut out = Vec::new();
        let mut buf = Vec::new();
        for _ in 0..100 {
            let Some(tx) = conn.poll_transmit(now, 1, &mut buf) else {
                return out;
            };
            assert!(tx.segment_size.is_none_or(|n| n == tx.size));
            out.push((tx.ecn, Bytes::copy_from_slice(&buf[..tx.size])));
            buf.clear();
        }
        panic!("unbounded transmit without a new event");
    }
    fn next(&mut self) -> Option<Instant> {
        self.inbound
            .front()
            .map(|x| x.0)
            .into_iter()
            .chain(self.conn.as_mut().and_then(|c| c.poll_timeout()))
            .min()
    }
}
struct Pair {
    client: Side,
    server: Side,
    now: Instant,
    latency: Duration,
}
impl Pair {
    fn new(window: Option<u32>) -> Self {
        let (mut server_tls, mut client_tls) = localhost_tls(rustls::DEFAULT_VERSIONS);
        server_tls.alpn_protocols = vec![b"pto-contract".to_vec()];
        client_tls.alpn_protocols = vec![b"pto-contract".to_vec()];
        let mut server =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));
        let mut client =
            ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
        let mut transport = TransportConfig::default();
        transport
            .max_idle_timeout(None)
            .mtu_discovery_config(None)
            .initial_rtt(Duration::from_millis(100));
        if let Some(n) = window {
            transport
                .stream_receive_window(n.into())
                .receive_window(n.into())
                .send_window(n.into());
        }
        let transport = Arc::new(transport);
        server.transport_config(transport.clone());
        client.transport_config(transport);
        let now = Instant::now();
        let addr = |p| SocketAddr::from((Ipv4Addr::LOCALHOST, p));
        let mut c = Side {
            endpoint: Endpoint::new(Default::default(), None, true, Some(CLIENT_SEED)),
            conn: None,
            handle: None,
            addr: addr(4433),
            inbound: VecDeque::new(),
        };
        let server = Side {
            endpoint: Endpoint::new(
                Default::default(),
                Some(Arc::new(server)),
                true,
                Some(SERVER_SEED),
            ),
            conn: None,
            handle: None,
            addr: addr(4434),
            inbound: VecDeque::new(),
        };
        let (h, conn) = c
            .endpoint
            .connect(now, client, server.addr, "localhost")
            .unwrap();
        c.handle = Some(h);
        c.conn = Some(conn);
        let mut pair = Self {
            client: c,
            server,
            now,
            latency: Duration::from_millis(40),
        };
        pair.drive();
        assert!(!pair.client.conn().is_handshaking());
        assert!(!pair.server.conn().is_handshaking());
        while pair.client.conn().poll().is_some() {}
        while pair.server.conn().poll().is_some() {}
        pair
    }
    fn deliver_client(&mut self, packets: Vec<Packet>) {
        for p in packets {
            self.server.inbound.push_back((self.now + self.latency, p));
        }
        self.now += self.latency;
        self.server.ingest(self.now, self.client.addr);
    }
    fn deliver_server(&mut self, packets: Vec<Packet>) {
        for p in packets {
            self.client.inbound.push_back((self.now + self.latency, p));
        }
        self.now += self.latency;
        self.client.ingest(self.now, self.server.addr);
    }
    fn drive(&mut self) {
        for _ in 0..1000 {
            self.client.ingest(self.now, self.server.addr);
            self.server.ingest(self.now, self.client.addr);
            for p in self.client.emit(self.now) {
                self.server.inbound.push_back((self.now + self.latency, p));
            }
            for p in self.server.emit(self.now) {
                self.client.inbound.push_back((self.now + self.latency, p));
            }
            let next = self
                .client
                .next()
                .into_iter()
                .chain(self.server.next())
                .min();
            match next {
                Some(t) => {
                    assert!(t >= self.now);
                    self.now = t;
                }
                None => return,
            }
        }
        panic!("virtual link did not settle");
    }
    fn send(&mut self, bytes: &[u8], fin: bool) -> (StreamId, Vec<Packet>) {
        let id = self.client.conn().streams().open(Dir::Uni).unwrap();
        assert_eq!(
            self.client.conn().send_stream(id).write(bytes).unwrap(),
            bytes.len()
        );
        if fin {
            self.client.conn().send_stream(id).finish().unwrap();
        }
        let packets = self.client.emit(self.now);
        assert!(!packets.is_empty());
        (id, packets)
    }
    fn probe(&mut self) -> Vec<Packet> {
        self.now = self.client.conn().poll_timeout().unwrap();
        let before = self.client.conn().stats();
        let packets = self.client.emit(self.now);
        assert!(!packets.is_empty());
        assert_eq!(
            self.client.conn().stats().path.lost_packets,
            before.path.lost_packets,
            "PTO must not declare congestion loss"
        );
        packets
    }
    fn read(&mut self, id: StreamId) -> (Vec<(u64, Bytes)>, bool) {
        let _ = self.server.conn().streams().accept(Dir::Uni);
        let mut recv = self.server.conn().recv_stream(id);
        let Ok(mut chunks) = recv.read(false) else {
            return (Vec::new(), false);
        };
        let mut data = Vec::new();
        let mut eof = false;
        loop {
            match chunks.next(usize::MAX) {
                Ok(Some(chunk)) => data.push((chunk.offset, chunk.bytes)),
                Ok(None) => {
                    eof = true;
                    break;
                }
                Err(ReadError::Blocked) => break,
                Err(e) => panic!("read error: {e:?}"),
            }
        }
        let _ = chunks.finalize();
        (data, eof)
    }
    fn server_ack(&mut self) -> Vec<Packet> {
        let mut out = self.server.emit(self.now);
        if out.is_empty() {
            self.now = self.server.conn().poll_timeout().unwrap();
            out = self.server.emit(self.now);
        }
        assert!(!out.is_empty());
        out
    }
}
fn bytes(chunks: Vec<(u64, Bytes)>) -> Vec<u8> {
    let mut out = BTreeMap::new();
    for (off, data) in chunks {
        for (i, v) in data.iter().enumerate() {
            assert!(
                out.insert(off + i as u64, *v).is_none(),
                "duplicate byte delivery"
            );
        }
    }
    out.into_values().collect()
}

#[test]
fn pto_probe_retransmits_before_new_ack() {
    let mut p = Pair::new(None);
    let (id, _lost) = p.send(b"first flight", false);
    let probes = p.probe();
    p.deliver_client(probes);
    let data = bytes(p.read(id).0);
    eprintln!(
        "PTO_COUNT delivered_before_probe_ack={} bytes={}",
        !data.is_empty(),
        data.len()
    );
    assert_eq!(
        data, b"first flight",
        "lost STREAM must recover in the probe before any new ACK"
    );
}
#[test]
fn repeated_pto_keeps_original_stream_metadata() {
    let mut p = Pair::new(None);
    let (id, original) = p.send(b"retry", true);
    let _lost_probe = p.probe();
    let probe = p.probe();
    p.deliver_client(probe);
    let (data, eof) = p.read(id);
    assert_eq!(bytes(data), b"retry");
    assert!(eof);
    let ack = p.server_ack();
    p.deliver_server(ack);
    p.deliver_client(original);
    assert!(p.read(id).0.is_empty());
    p.drive();
    assert_eq!(p.client.conn().streams().send_streams(), 0);
}
#[test]
fn original_and_probe_acks_each_free_fin_once() {
    for probe_first in [false, true] {
        let mut p = Pair::new(None);
        let (id, original) = p.send(b"finish", true);
        p.deliver_client(original);
        assert_eq!(bytes(p.read(id).0), b"finish");
        let original_ack = p.server_ack();
        let probes = p.probe();
        if !probe_first {
            p.deliver_server(original_ack.clone());
        }
        p.deliver_client(probes);
        assert!(p.read(id).0.is_empty());
        let probe_ack = p.server_ack();
        p.deliver_server(probe_ack);
        if probe_first {
            p.deliver_server(original_ack);
        }
        p.drive();
        assert_eq!(p.client.conn().streams().send_streams(), 0);
        let finished = std::iter::from_fn(|| p.client.conn().poll())
            .filter(|e| matches!(e,Event::Stream(StreamEvent::Finished{id:got})if *got==id))
            .count();
        assert_eq!(finished, 1);
    }
}
#[test]
fn probe_ack_then_original_loss_does_not_requeue_freed_bytes() {
    let mut p = Pair::new(Some(8));
    let (id, _lost) = p.send(b"12345678", false);
    let probes = p.probe();
    p.deliver_client(probes);
    assert_eq!(bytes(p.read(id).0), b"12345678");
    let ack = p.server_ack();
    p.deliver_server(ack);
    p.drive();
    assert_eq!(
        p.client.conn().send_stream(id).write(b"abcdefgh").unwrap(),
        8
    );
    p.drive();
    assert_eq!(bytes(p.read(id).0), b"abcdefgh");
}
#[test]
fn retransmission_uses_existing_flow_control_credit() {
    let mut p = Pair::new(Some(8));
    let (id, _lost) = p.send(b"12345678", false);
    assert!(p.client.conn().send_stream(id).write(b"x").is_err());
    let probes = p.probe();
    p.deliver_client(probes);
    assert_eq!(bytes(p.read(id).0), b"12345678");
}
#[test]
fn new_stream_data_precedes_probe_retransmission() {
    let mut p = Pair::new(None);
    let (id, _lost) = p.send(b"old", false);
    assert_eq!(p.client.conn().send_stream(id).write(b"new").unwrap(), 3);
    let mut probes = p.probe();
    let first = probes.remove(0);
    p.deliver_client(vec![first]);
    let got = p.read(id).0;
    assert_eq!(got.first().map(|x| x.0), Some(3));
    assert_eq!(bytes(got), b"new");
    p.deliver_client(probes);
    assert_eq!(bytes(p.read(id).0), b"old");
    p.drive();
}
#[test]
fn reset_stream_is_not_resurrected_by_probe() {
    let mut p = Pair::new(None);
    let (id, _lost) = p.send(b"reset", false);
    let before = p.client.conn().stats().frame_tx.stream;
    p.client.conn().send_stream(id).reset(7u32.into()).unwrap();
    let _lost_reset = p.client.emit(p.now);
    let probes = p.probe();
    p.deliver_client(probes);
    assert_eq!(p.server.conn().streams().accept(Dir::Uni), Some(id));
    {
        let mut recv = p.server.conn().recv_stream(id);
        let mut chunks = recv.read(false).unwrap();
        assert!(
            matches!(chunks.next(usize::MAX), Err(ReadError::Reset(code)) if code == 7u32.into())
        );
        let _ = chunks.finalize();
    }
    p.drive();
    assert_eq!(p.client.conn().streams().send_streams(), 0);
    assert_eq!(p.client.conn().stats().frame_tx.stream, before);
}

#[test]
fn closed_stream_probe_copies_cannot_resurrect_fin() {
    let mut p = Pair::new(None);
    let (id, original) = p.send(b"closed", true);
    p.deliver_client(original);
    let (data, eof) = p.read(id);
    assert_eq!(bytes(data), b"closed");
    assert!(eof);
    let original_ack = p.server_ack();
    let unacknowledged_copies = p.probe();
    p.deliver_server(original_ack);
    assert_eq!(p.client.conn().streams().send_streams(), 0);
    let before = p.client.conn().stats().frame_tx.stream;
    let closed_probe = p.probe();
    assert_eq!(p.client.conn().stats().frame_tx.stream, before);
    p.deliver_client(closed_probe);
    p.deliver_client(unacknowledged_copies);
    assert!(p.read(id).0.is_empty());
    p.drive();
    let finished = std::iter::from_fn(|| p.client.conn().poll())
        .filter(|e| matches!(e,Event::Stream(StreamEvent::Finished{id:got})if *got==id))
        .count();
    assert_eq!(finished, 1);
}
#[test]
fn control_only_probe_does_not_add_stream_frames() {
    let mut p = Pair::new(None);
    let before = p.client.conn().stats().frame_tx.stream;
    p.client.conn().ping();
    let _lost = p.client.emit(p.now);
    let probes = p.probe();
    p.deliver_client(probes);
    p.drive();
    assert_eq!(p.client.conn().stats().frame_tx.stream, before);
}

#[test]
fn late_original_ack_cancels_the_unsent_part_of_a_probe() {
    let mut p = Pair::new(None);
    let data = vec![0x42; 2000];
    let (id, original) = p.send(&data, false);
    p.deliver_client(original);
    assert_eq!(bytes(p.read(id).0), data);
    let original_ack = p.server_ack();
    // Leave part of the oldest STREAM range queued after this probe's DATAGRAM.
    p.client
        .conn()
        .datagrams()
        .send(Bytes::from(vec![0x73; 1000]), false)
        .unwrap();
    p.now = p.client.conn().poll_timeout().unwrap();
    let now = p.now;
    p.client.conn().handle_timeout(now);
    let mut buf = Vec::new();
    let tx = p.client.conn().poll_transmit(now, 1, &mut buf).unwrap();
    let first_probe = (tx.ecn, Bytes::copy_from_slice(&buf[..tx.size]));
    assert_eq!(p.client.conn().stats().frame_tx.datagram, 1);
    let stream_frames = p.client.conn().stats().frame_tx.stream;
    p.deliver_server(original_ack);
    let rest = p.client.emit(p.now);
    assert_eq!(p.client.conn().stats().frame_tx.stream, stream_frames);
    p.deliver_client(vec![first_probe]);
    p.deliver_client(rest);
    assert!(p.read(id).0.is_empty());
    p.drive();
    assert_eq!(p.client.conn().send_stream(id).write(b"next").unwrap(), 4);
    p.drive();
    assert_eq!(bytes(p.read(id).0), b"next");
}

fn acks_sent(side: &mut Side) -> u64 {
    side.conn().stats().frame_tx.acks
}

/// A link short enough that no ACK delay ends during an exchange.
fn datagram_pair() -> Pair {
    let mut p = Pair::new(None);
    p.latency = Duration::from_micros(100);
    p
}

/// The server sends a datagram, which the client takes before the server's next one; returns the ACK frames in the
/// packet that `reply` makes the client send.
fn request(p: &mut Pair, reply: impl FnOnce(&mut Pair) -> Vec<Packet>) -> u64 {
    p.server
        .conn()
        .datagrams()
        .send(Bytes::from_static(b"request"), false)
        .unwrap();
    let packets = p.server.emit(p.now);
    p.deliver_server(packets);
    assert!(p.client.conn().datagrams().recv().is_some());
    let before = acks_sent(&mut p.client);
    let packets = reply(p);
    assert_eq!(packets.len(), 1);
    let acks = acks_sent(&mut p.client) - before;
    p.deliver_client(packets);
    acks
}

fn datagram_reply(p: &mut Pair) -> Vec<Packet> {
    p.client
        .conn()
        .datagrams()
        .send(Bytes::from_static(b"response"), false)
        .unwrap();
    p.client.emit(p.now)
}

#[test]
fn datagram_replies_acknowledge_every_second_datagram() {
    let mut p = datagram_pair();
    assert_eq!(
        request(&mut p, datagram_reply),
        0,
        "an ACK rode on the first reply"
    );
    assert_eq!(
        request(&mut p, datagram_reply),
        1,
        "no ACK on the reply to the second datagram"
    );
    assert_eq!(
        request(&mut p, datagram_reply),
        0,
        "an ACK rode on the third reply"
    );
}

#[test]
fn a_lone_datagram_is_acknowledged_when_the_ack_delay_ends() {
    let mut p = datagram_pair();
    assert_eq!(request(&mut p, datagram_reply), 0);
    p.now = p.client.conn().poll_timeout().unwrap();
    let before = p.client.conn().stats().frame_tx;
    assert_eq!(p.client.emit(p.now).len(), 1);
    let after = p.client.conn().stats().frame_tx;
    assert_eq!(after.acks - before.acks, 1);
    assert_eq!(after.datagram, before.datagram);
}

#[test]
fn a_stream_reply_carries_the_ack() {
    let mut p = datagram_pair();
    let acks = request(&mut p, |p| p.send(b"response", false).1);
    assert_eq!(acks, 1);
}

fn acked(p: &mut Pair, id: StreamId) -> usize {
    std::iter::from_fn(|| p.client.conn().poll())
        .filter(|e| matches!(e, Event::Stream(StreamEvent::Acked { id: got }) if *got == id))
        .count()
}

#[test]
fn a_waited_stream_is_acknowledged_only_once_its_bytes_are() {
    let mut p = Pair::new(None);
    let (id, packets) = p.send(b"last writes", false);
    assert!(!p.client.conn().send_stream(id).wait_acked());
    p.deliver_client(packets);
    assert_eq!(bytes(p.read(id).0), b"last writes");
    assert_eq!(acked(&mut p, id), 0);
    assert!(!p.client.conn().send_stream(id).wait_acked());
    let ack = p.server_ack();
    p.deliver_server(ack);
    assert_eq!(acked(&mut p, id), 1);
    assert!(p.client.conn().send_stream(id).wait_acked());
}

#[test]
fn a_waited_stream_whose_packet_is_lost_is_acknowledged_after_the_retransmission() {
    let mut p = Pair::new(None);
    let (id, _lost) = p.send(b"lost once", false);
    assert!(!p.client.conn().send_stream(id).wait_acked());
    let probes = p.probe();
    assert_eq!(acked(&mut p, id), 0);
    p.deliver_client(probes);
    assert_eq!(bytes(p.read(id).0), b"lost once");
    let ack = p.server_ack();
    p.deliver_server(ack);
    assert_eq!(acked(&mut p, id), 1);
}

#[test]
fn a_stream_nobody_waits_on_raises_no_acked_event() {
    let mut p = Pair::new(None);
    let (id, packets) = p.send(b"unwatched", false);
    p.deliver_client(packets);
    assert_eq!(bytes(p.read(id).0), b"unwatched");
    let ack = p.server_ack();
    p.deliver_server(ack);
    p.drive();
    assert_eq!(acked(&mut p, id), 0);
}

#[test]
fn a_reset_stream_leaves_nothing_to_wait_for() {
    let mut p = Pair::new(None);
    let (id, _lost) = p.send(b"abandoned", false);
    p.client.conn().send_stream(id).reset(7u32.into()).unwrap();
    assert!(p.client.conn().send_stream(id).wait_acked());
    p.drive();
    assert_eq!(acked(&mut p, id), 0);
}
