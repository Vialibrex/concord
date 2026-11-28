use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::RngExt;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

const COOKIE: u32 = 0x2112_A442;
const HEADER: usize = 20;
const BINDING_REQUEST: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTEMPTS: [Duration; 3] = [
    Duration::from_millis(500),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

type TransactionId = [u8; 12];

struct Probe {
    server: SocketAddr,
    raw: [u8; HEADER],
    id: TransactionId,
}

fn probe(server: SocketAddr) -> Probe {
    let id: TransactionId = rand::rng().random();
    let mut raw = [0u8; HEADER];
    let (kind, rest) = raw.split_at_mut(2);
    kind.copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    let (_length, rest) = rest.split_at_mut(2);
    let (cookie, tail) = rest.split_at_mut(4);
    cookie.copy_from_slice(&COOKIE.to_be_bytes());
    tail.copy_from_slice(&id);
    Probe { server, raw, id }
}

pub(super) fn is_message(data: &[u8]) -> bool {
    data.len() >= HEADER && data.get(4..8) == Some(&COOKIE.to_be_bytes())
}

fn transaction_id(data: &[u8]) -> Option<TransactionId> {
    if !is_message(data) {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?));
    if data.len() < HEADER + length {
        return None;
    }
    data.get(8..HEADER)?.try_into().ok()
}

/// The first XOR-MAPPED-ADDRESS in a binding response.
fn mapped_address(data: &[u8], id: &TransactionId) -> Option<SocketAddr> {
    let length = usize::from(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?));
    let mut body = data.get(HEADER..HEADER + length)?;
    let mut key = [0u8; 16];
    key.get_mut(..4)?.copy_from_slice(&COOKIE.to_be_bytes());
    key.get_mut(4..)?.copy_from_slice(id);
    while body.len() >= 4 {
        let kind = u16::from_be_bytes(body.get(0..2)?.try_into().ok()?);
        let size = usize::from(u16::from_be_bytes(body.get(2..4)?.try_into().ok()?));
        let padded = (size + 3) & !3;
        let value = body.get(4..4 + size)?;
        let next = body.get(4 + padded..)?;
        if kind != XOR_MAPPED_ADDRESS {
            body = next;
            continue;
        }
        let family = *value.get(1)?;
        let port = u16::from_be_bytes(value.get(2..4)?.try_into().ok()?) ^ (COOKIE >> 16) as u16;
        let masked = value.get(4..)?;
        let unmask = |bytes: &[u8]| -> Vec<u8> {
            bytes
                .iter()
                .zip(key)
                .map(|(byte, key)| byte ^ key)
                .collect()
        };
        let ip = match (family, masked.len()) {
            (0x01, 4) => {
                let octets: [u8; 4] = unmask(masked).try_into().ok()?;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            (0x02, 16) => {
                let octets: [u8; 16] = unmask(masked).try_into().ok()?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return None,
        };
        return Some(SocketAddr::new(ip, port));
    }
    None
}

async fn collect(
    socket: &UdpSocket,
    probes: &[Probe],
    pending: &mut HashSet<TransactionId>,
    deadline: Instant,
) -> io::Result<Vec<SocketAddr>> {
    let mut found = Vec::new();
    let mut buf = [0u8; 1500];
    while !pending.is_empty() {
        let (read, _from) = match timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(received) => received?,
            Err(_) => break,
        };
        let Some(data) = buf.get(..read) else {
            continue;
        };
        let Some(id) = transaction_id(data) else {
            continue;
        };
        if !pending.remove(&id) {
            continue;
        }
        if let Some(address) = probes
            .iter()
            .find(|probe| probe.id == id)
            .and_then(|probe| mapped_address(data, &probe.id))
        {
            found.push(address);
        }
    }
    Ok(found)
}

/// Binding requests to every server from `socket`, retried up to three times
/// with growing waits, and every distinct address any server saw it at.
pub(super) async fn discover(
    socket: &UdpSocket,
    servers: &[SocketAddr],
) -> io::Result<Vec<SocketAddr>> {
    if servers.is_empty() {
        return Err(io::Error::other("no STUN servers"));
    }
    let probes: Vec<Probe> = servers.iter().copied().map(probe).collect();
    let mut pending: HashSet<TransactionId> = probes.iter().map(|probe| probe.id).collect();
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    let mut last_error = None;
    for wait in ATTEMPTS {
        if pending.is_empty() {
            break;
        }
        let mut sent = 0;
        let mut send_error = None;
        for probe in probes.iter().filter(|probe| pending.contains(&probe.id)) {
            match socket.send_to(&probe.raw, probe.server).await {
                Ok(_) => sent += 1,
                Err(err) => {
                    send_error = Some(io::Error::new(
                        err.kind(),
                        format!("send STUN request to {}: {err}", probe.server),
                    ));
                }
            }
        }
        if sent == 0 {
            last_error = send_error.or(Some(io::Error::other("no STUN requests sent")));
        } else if send_error.is_some() {
            last_error = send_error;
        }
        for address in collect(socket, &probes, &mut pending, Instant::now() + wait).await? {
            if seen.insert(address) {
                result.push(address);
            }
        }
    }
    if !result.is_empty() {
        return Ok(result);
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no STUN responses received")))
}

#[cfg(test)]
pub(super) fn answer(request: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    let id = transaction_id(request)?;
    let mut key = [0u8; 16];
    key[..4].copy_from_slice(&COOKIE.to_be_bytes());
    key[4..].copy_from_slice(&id);
    let mut value = vec![0u8, if from.is_ipv4() { 1 } else { 2 }];
    value.extend_from_slice(&(from.port() ^ (COOKIE >> 16) as u16).to_be_bytes());
    let octets = match from.ip() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    value.extend(octets.iter().zip(key).map(|(byte, key)| byte ^ key));
    let mut out = vec![0x01, 0x01];
    out.extend_from_slice(&((value.len() + 4) as u16).to_be_bytes());
    out.extend_from_slice(&COOKIE.to_be_bytes());
    out.extend_from_slice(&id);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(&value);
    Some(out)
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "the tests talk to loopback sockets directly"
)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_request_has_the_fixed_header() {
        let request = probe("192.0.2.1:3478".parse().unwrap());
        assert_eq!(&request.raw[..2], &[0, 1]);
        assert_eq!(&request.raw[2..4], &[0, 0]);
        assert_eq!(&request.raw[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&request.raw[8..], &request.id);
        assert!(is_message(&request.raw));
    }

    #[test]
    fn the_mapped_address_round_trips_for_both_families() {
        for text in ["203.0.113.7:54321", "[2001:db8::7]:4000"] {
            let from: SocketAddr = text.parse().unwrap();
            let request = probe("192.0.2.1:3478".parse().unwrap());
            let response = answer(&request.raw, from).unwrap();
            assert_eq!(transaction_id(&response), Some(request.id));
            assert_eq!(mapped_address(&response, &request.id), Some(from));
        }
    }

    #[test]
    fn a_known_response_decodes() {
        let id = [1u8; 12];
        let mut response = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xA4, 0x42];
        response.extend_from_slice(&id);
        response.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        response.extend_from_slice(&(4000u16 ^ 0x2112).to_be_bytes());
        for (octet, key) in [192u8, 0, 2, 5].iter().zip([0x21, 0x12, 0xA4, 0x42]) {
            response.push(octet ^ key);
        }
        assert_eq!(
            mapped_address(&response, &id),
            Some("192.0.2.5:4000".parse().unwrap())
        );
    }

    #[test]
    fn junk_is_not_a_message() {
        assert!(!is_message(&[0u8; 19]));
        assert!(!is_message(&[0u8; 40]));
        assert_eq!(transaction_id(&[0u8; 40]), None);
        let mut truncated = vec![0x01, 0x01, 0x00, 0x40, 0x21, 0x12, 0xA4, 0x42];
        truncated.extend_from_slice(&[0u8; 12]);
        assert_eq!(transaction_id(&truncated), None);
    }

    #[tokio::test]
    async fn discovery_collects_each_distinct_mapping() {
        let one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let servers = [one.local_addr().unwrap(), two.local_addr().unwrap()];
        for (server, fake) in [(one, "198.51.100.1:1111"), (two, "198.51.100.1:2222")] {
            let fake: SocketAddr = fake.parse().unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                while let Ok((read, from)) = server.recv_from(&mut buf).await {
                    if let Some(reply) = answer(&buf[..read], fake) {
                        let _ = server.send_to(&reply, from).await;
                    }
                }
            });
        }
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut found = discover(&client, &servers).await.unwrap();
        found.sort();
        assert_eq!(
            found,
            ["198.51.100.1:1111", "198.51.100.1:2222"].map(|text| text.parse().unwrap())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_server_ends_discovery_after_three_attempts() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let started = Instant::now();
        let err = discover(&client, &[silent.local_addr().unwrap()])
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "no STUN responses received");
        assert_eq!(started.elapsed(), Duration::from_millis(6500));
    }
}
