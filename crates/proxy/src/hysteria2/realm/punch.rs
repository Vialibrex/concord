use std::collections::{BTreeMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand::RngExt;
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::time::{Instant, MissedTickBehavior, interval, timeout_at};

const TIMEOUT: Duration = Duration::from_secs(10);
const INTERVAL: Duration = Duration::from_millis(100);
const SALT: usize = 8;
const MAGIC: [u8; 8] = *b"HYRLMv1\0";
const NONCE: usize = 16;
const BODY: usize = MAGIC.len() + 1 + NONCE;
const MAX_PADDING: usize = 1024;
const SYMMETRIC_GAP: u16 = 4;
const SYMMETRIC_EXTRA: u32 = 4;
const SYMMETRIC_PER_HOST: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Hello = 1,
    Ack = 2,
}

/// What both ends of a punch attempt share: the nonce names the attempt and
/// the key hides the packets from anyone who has not seen the control exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Metadata {
    pub(super) nonce: [u8; NONCE],
    pub(super) key: [u8; 32],
}

impl Metadata {
    pub(super) fn random() -> Self {
        let mut rng = rand::rng();
        Metadata {
            nonce: rng.random(),
            key: rng.random(),
        }
    }
}

fn xor(metadata: &Metadata, salt: &[u8], body: &mut [u8]) {
    let mut hasher = Sha256::new();
    hasher.update(metadata.key);
    hasher.update(salt);
    let stream = hasher.finalize();
    for (byte, mask) in body.iter_mut().zip(stream.iter().cycle()) {
        *byte ^= mask;
    }
}

pub(super) fn encode(kind: Kind, metadata: &Metadata) -> Vec<u8> {
    let mut rng = rand::rng();
    let padding = rng.random_range(0..=MAX_PADDING);
    let mut packet = vec![0u8; SALT + BODY + padding];
    rng.fill(packet.as_mut_slice());
    let (salt, body) = packet.split_at_mut(SALT);
    if let Some((magic, rest)) = body.split_first_chunk_mut::<{ MAGIC.len() }>() {
        *magic = MAGIC;
        if let Some((tag, rest)) = rest.split_first_mut() {
            *tag = kind as u8;
            if let Some(nonce) = rest.get_mut(..NONCE) {
                nonce.copy_from_slice(&metadata.nonce);
            }
        }
    }
    xor(metadata, salt, body);
    packet
}

pub(super) fn decode(data: &[u8], metadata: &Metadata) -> Option<Kind> {
    if !(SALT + BODY..=SALT + BODY + MAX_PADDING).contains(&data.len()) {
        return None;
    }
    let (salt, body) = data.split_at(SALT);
    let mut body = body.to_vec();
    xor(metadata, salt, &mut body);
    let (magic, rest) = body.split_first_chunk::<{ MAGIC.len() }>()?;
    if *magic != MAGIC {
        return None;
    }
    let (tag, rest) = rest.split_first()?;
    if rest.get(..NONCE)? != metadata.nonce {
        return None;
    }
    match tag {
        1 => Some(Kind::Hello),
        2 => Some(Kind::Ack),
        _ => None,
    }
}

/// The addresses to punch toward: the peer's own, plus a few ports around
/// them when its NAT hands out consecutive ports per destination.
pub(super) fn candidates(peers: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for peer in peers {
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        if peer.port() != 0 && seen.insert(peer) {
            out.push(peer);
        }
    }
    let mut ports: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    for peer in &out {
        if peer.is_ipv4() {
            ports.entry(peer.ip()).or_default().push(peer.port());
        }
    }
    for (ip, mut ports) in ports {
        ports.sort_unstable();
        ports.dedup();
        if ports.len() < 2 || ports.windows(2).any(|pair| gap(pair) > SYMMETRIC_GAP) {
            continue;
        }
        let (Some(first), Some(last)) = (ports.first(), ports.last()) else {
            continue;
        };
        let end = (u32::from(*last) + SYMMETRIC_EXTRA).min(65535);
        let mut added = 0;
        for port in u32::from(*first)..=end {
            let Ok(port) = u16::try_from(port) else {
                break;
            };
            let address = SocketAddr::new(ip, port);
            if !seen.insert(address) {
                continue;
            }
            out.push(address);
            added += 1;
            if added >= SYMMETRIC_PER_HOST {
                break;
            }
        }
    }
    out
}

fn gap(pair: &[u16]) -> u16 {
    match pair {
        [low, high] => high.saturating_sub(*low),
        _ => 0,
    }
}

pub(super) async fn send(socket: &UdpSocket, to: SocketAddr, kind: Kind, metadata: &Metadata) {
    let _ = socket.send_to(&encode(kind, metadata), to).await;
}

async fn send_all(socket: &UdpSocket, to: &[SocketAddr], metadata: &Metadata) {
    for address in to {
        send(socket, *address, Kind::Hello, metadata).await;
    }
}

/// Sends hellos to every candidate every 100 ms and returns who answered
/// first. A hello from the peer is acknowledged on the way out, so the peer
/// sees its own punch succeed even if ours arrived first.
pub(super) async fn punch(
    socket: &UdpSocket,
    peers: &[SocketAddr],
    metadata: &Metadata,
) -> io::Result<(SocketAddr, Kind)> {
    let targets = candidates(peers);
    if targets.is_empty() {
        return Err(io::Error::other("no compatible peer addresses"));
    }
    let deadline = Instant::now() + TIMEOUT;
    let mut tick = interval(INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut buf = [0u8; SALT + BODY + MAX_PADDING + 1];
    loop {
        tokio::select! {
            _ = tick.tick() => send_all(socket, &targets, metadata).await,
            received = timeout_at(deadline, socket.recv_from(&mut buf)) => {
                let (read, from) = match received {
                    Ok(received) => received.map_err(|err| io::Error::new(err.kind(), format!("punch read: {err}")))?,
                    Err(_) => return Err(io::Error::new(io::ErrorKind::TimedOut, "punch timeout")),
                };
                let from = SocketAddr::new(from.ip().to_canonical(), from.port());
                let Some(kind) = buf.get(..read).and_then(|data| decode(data, metadata)) else {
                    continue;
                };
                if kind == Kind::Hello {
                    send(socket, from, Kind::Ack, metadata).await;
                }
                return Ok((from, kind));
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "the tests talk to loopback sockets directly"
)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn packets_round_trip_and_hide_their_magic() {
        let metadata = Metadata::random();
        for kind in [Kind::Hello, Kind::Ack] {
            for _ in 0..50 {
                let packet = encode(kind, &metadata);
                assert!((SALT + BODY..=SALT + BODY + MAX_PADDING).contains(&packet.len()));
                assert_eq!(decode(&packet, &metadata), Some(kind));
                assert!(
                    !packet
                        .windows(MAGIC.len())
                        .any(|window| window == &MAGIC[..])
                );
            }
        }
    }

    #[test]
    fn another_attempt_cannot_read_the_packet() {
        let (ours, theirs) = (Metadata::random(), Metadata::random());
        let packet = encode(Kind::Hello, &ours);
        assert_eq!(decode(&packet, &theirs), None);
        let other_nonce = Metadata {
            nonce: theirs.nonce,
            key: ours.key,
        };
        assert_eq!(decode(&packet, &other_nonce), None);
        assert_eq!(decode(&packet[..SALT + BODY - 1], &ours), None);
        assert_eq!(
            decode(&vec![0u8; SALT + BODY + MAX_PADDING + 1], &ours),
            None
        );
    }

    #[test]
    fn a_known_packet_decodes() {
        let metadata = Metadata {
            nonce: [7; 16],
            key: [9; 32],
        };
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut body = Vec::new();
        body.extend_from_slice(b"HYRLMv1\0");
        body.push(2);
        body.extend_from_slice(&metadata.nonce);
        xor(&metadata, &salt, &mut body);
        let mut packet = salt.to_vec();
        packet.extend(body);
        assert_eq!(decode(&packet, &metadata), Some(Kind::Ack));
    }

    #[test]
    fn candidates_drop_invalid_and_repeated_addresses() {
        let out = candidates(&[
            addr("203.0.113.1:5000"),
            addr("203.0.113.1:5000"),
            addr("203.0.113.1:0"),
            addr("[::ffff:203.0.113.2]:6000"),
            addr("[2001:db8::1]:7000"),
        ]);
        assert_eq!(
            out,
            [
                addr("203.0.113.1:5000"),
                addr("203.0.113.2:6000"),
                addr("[2001:db8::1]:7000"),
            ]
        );
    }

    #[test]
    fn a_predictable_nat_adds_nearby_ports() {
        let out = candidates(&[addr("203.0.113.1:5000"), addr("203.0.113.1:5002")]);
        let ports: Vec<u16> = out.iter().map(SocketAddr::port).collect();
        assert_eq!(ports, [5000, 5002, 5001, 5003, 5004, 5005, 5006]);
    }

    #[test]
    fn distant_ports_and_v6_are_left_alone() {
        assert_eq!(
            candidates(&[addr("203.0.113.1:5000"), addr("203.0.113.1:5100")]).len(),
            2
        );
        assert_eq!(
            candidates(&[addr("[2001:db8::1]:5000"), addr("[2001:db8::1]:5001")]).len(),
            2
        );
    }

    #[test]
    fn the_expansion_is_capped_per_host() {
        let peers: Vec<SocketAddr> = (0..20u16)
            .map(|i| addr(&format!("203.0.113.1:{}", 5000 + i * 4)))
            .collect();
        let out = candidates(&peers);
        assert_eq!(out.len(), 20 + SYMMETRIC_PER_HOST);
    }

    #[tokio::test]
    async fn two_sockets_punching_each_other_meet() {
        let (a, b) = (
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        );
        let (addr_a, addr_b) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        let metadata = Metadata::random();
        let (to_b, to_a) = ([addr_b], [addr_a]);
        let (left, right) = tokio::join!(punch(&a, &to_b, &metadata), punch(&b, &to_a, &metadata));
        assert_eq!(left.unwrap().0, addr_b);
        assert_eq!(right.unwrap().0, addr_a);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_times_out_after_ten_seconds() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let started = Instant::now();
        let err = punch(&a, &[silent.local_addr().unwrap()], &Metadata::random())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), TIMEOUT);
    }

    #[tokio::test]
    async fn packets_with_the_wrong_key_are_ignored() {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (addr_a, addr_b) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        let (ours, stranger) = (Metadata::random(), Metadata::random());
        let noise = tokio::spawn(async move {
            for _ in 0..20 {
                send(&b, addr_a, Kind::Hello, &stranger).await;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            b
        });
        let early =
            tokio::time::timeout(Duration::from_millis(300), punch(&a, &[addr_b], &ours)).await;
        assert!(early.is_err());
        drop(noise.await.unwrap());
    }
}
