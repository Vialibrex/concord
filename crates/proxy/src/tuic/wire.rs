use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use concord_common::Address;
use concord_quic::Fragment as Part;
#[cfg(feature = "server")]
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::util::invalid_data;

pub(crate) const CMD_AUTH: u8 = 0;
pub(crate) const CMD_CONNECT: u8 = 1;
pub(crate) const CMD_PACKET: u8 = 2;
pub(crate) const CMD_DISSOCIATE: u8 = 3;
pub(crate) const CMD_HEARTBEAT: u8 = 4;
pub(crate) const CMD_RESPONSE: u8 = 0xff;

const ATYP_DOMAIN: u8 = 0;
const ATYP_V4: u8 = 1;
const ATYP_V6: u8 = 2;
const ATYP_NONE: u8 = 255;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Version {
    V4,
    V5,
}

impl Version {
    #[cfg(feature = "server")]
    pub(crate) fn of(byte: u8) -> Option<Version> {
        match byte {
            4 => Some(Version::V4),
            5 => Some(Version::V5),
            _ => None,
        }
    }

    pub(crate) fn byte(self) -> u8 {
        match self {
            Version::V4 => 4,
            Version::V5 => 5,
        }
    }
}

pub(crate) fn put_addr(out: &mut Vec<u8>, addr: &Address) -> io::Result<()> {
    match addr {
        Address::Socket(SocketAddr::V4(v4)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&v4.ip().octets());
        }
        Address::Socket(SocketAddr::V6(v6)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&v6.ip().octets());
        }
        Address::Domain(host, _) => {
            let len = u8::try_from(host.len()).map_err(|_| invalid_data("domain name too long"))?;
            out.push(ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    Ok(())
}

/// `Ok(None)` when `input` ends inside the address. The inner `None` is the
/// "no address" marker of a non-first fragment.
pub(crate) fn get_addr(input: &[u8]) -> io::Result<Option<(Option<Address>, usize)>> {
    let Some((&kind, rest)) = input.split_first() else {
        return Ok(None);
    };
    let (host_len, host_start) = match kind {
        ATYP_NONE => return Ok(Some((None, 1))),
        ATYP_V4 => (4, 1),
        ATYP_V6 => (16, 1),
        ATYP_DOMAIN => match rest.first() {
            Some(len) => (usize::from(*len), 2),
            None => return Ok(None),
        },
        _ => return Err(invalid_data("unknown address type")),
    };
    let end = host_start + host_len + 2;
    let Some(body) = input.get(host_start..end) else {
        return Ok(None);
    };
    let (host, port) = body.split_at(host_len);
    let port = match port {
        [hi, lo] => u16::from_be_bytes([*hi, *lo]),
        _ => return Ok(None),
    };
    let addr = match kind {
        ATYP_V4 => {
            let octets: [u8; 4] = host.try_into().map_err(|_| invalid_data("address"))?;
            Address::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        ATYP_V6 => {
            let octets: [u8; 16] = host.try_into().map_err(|_| invalid_data("address"))?;
            Address::from(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Address::Domain(String::from_utf8_lossy(host).as_ref().into(), port),
    };
    Ok(Some((Some(addr), end)))
}

/// The address of a Connect, read to its end and no further: its type and first byte say
/// how long it is.
#[cfg(feature = "server")]
pub(crate) async fn read_addr<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Address> {
    let mut buf = [0u8; 1 + 1 + 255 + 2];
    let head = buf.get_mut(..2).unwrap_or_default();
    reader.read_exact(head).await?;
    let len = match head {
        [ATYP_V4, _] => 1 + 4 + 2,
        [ATYP_V6, _] => 1 + 16 + 2,
        [ATYP_DOMAIN, host] => 2 + usize::from(*host) + 2,
        [ATYP_NONE, _] => return Err(invalid_data("connect without an address")),
        _ => return Err(invalid_data("unknown address type")),
    };
    reader
        .read_exact(buf.get_mut(2..len).unwrap_or_default())
        .await?;
    match get_addr(buf.get(..len).unwrap_or_default())? {
        Some((Some(addr), _)) => Ok(addr),
        _ => Err(invalid_data("address")),
    }
}

/// One relayed datagram or fragment of it, whichever version carried it.
pub(crate) struct Incoming {
    pub(crate) assoc: u32,
    pub(crate) part: Part<Address>,
}

pub(crate) enum Command {
    #[cfg(feature = "server")]
    Auth(Credential),
    Packet(Incoming),
    #[cfg(feature = "server")]
    Dissociate(u32),
    Heartbeat,
    Other,
}

#[cfg(feature = "server")]
pub(crate) enum Credential {
    V4 { token: [u8; 32] },
    V5 { uuid: [u8; 16], token: [u8; 32] },
}

/// Parses one command from a datagram or a unidirectional stream. A version
/// byte that is not ours is an error.
pub(crate) fn parse_command(version: Version, input: &Bytes) -> io::Result<Command> {
    let [ver, kind, ..] = input.as_ref() else {
        return Err(invalid_data("short tuic command"));
    };
    if *ver != version.byte() {
        return Err(invalid_data("unexpected tuic version"));
    }
    match *kind {
        CMD_HEARTBEAT => Ok(Command::Heartbeat),
        CMD_PACKET => parse_packet(version, input).map(Command::Packet),
        #[cfg(feature = "server")]
        CMD_AUTH => parse_auth(version, input.get(2..).unwrap_or_default()).map(Command::Auth),
        #[cfg(feature = "server")]
        CMD_DISSOCIATE => {
            let assoc = match (version, input.get(2..).unwrap_or_default()) {
                (Version::V5, [a, b, ..]) => u32::from(u16::from_be_bytes([*a, *b])),
                (Version::V4, [a, b, c, d, ..]) => u32::from_be_bytes([*a, *b, *c, *d]),
                _ => return Err(invalid_data("short tuic command")),
            };
            Ok(Command::Dissociate(assoc))
        }
        _ => Ok(Command::Other),
    }
}

#[cfg(feature = "server")]
fn parse_auth(version: Version, body: &[u8]) -> io::Result<Credential> {
    let short = || invalid_data("short tuic command");
    let token = |bytes: &[u8]| -> io::Result<[u8; 32]> {
        bytes
            .get(..32)
            .ok_or_else(short)?
            .try_into()
            .map_err(|_| short())
    };
    Ok(match version {
        Version::V5 => {
            let (uuid, rest) = body.split_at_checked(16).ok_or_else(short)?;
            Credential::V5 {
                uuid: uuid.try_into().map_err(|_| short())?,
                token: token(rest)?,
            }
        }
        Version::V4 => Credential::V4 {
            token: token(body)?,
        },
    })
}

fn parse_packet(version: Version, input: &Bytes) -> io::Result<Incoming> {
    let body = input.get(2..).unwrap_or_default();
    let short = || invalid_data("short tuic packet");
    let (assoc, packet, total, fragment, size, rest) = match version {
        Version::V5 => match body {
            [a, b, c, d, total, fragment, e, f, rest @ ..] => (
                u32::from(u16::from_be_bytes([*a, *b])),
                u16::from_be_bytes([*c, *d]),
                *total,
                *fragment,
                usize::from(u16::from_be_bytes([*e, *f])),
                rest,
            ),
            _ => return Err(short()),
        },
        Version::V4 => match body {
            [a, b, c, d, e, f, rest @ ..] => (
                u32::from_be_bytes([*a, *b, *c, *d]),
                0,
                1,
                0,
                usize::from(u16::from_be_bytes([*e, *f])),
                rest,
            ),
            _ => return Err(short()),
        },
    };
    let (addr, used) = get_addr(rest)?.ok_or_else(short)?;
    let start = input.len() - rest.len() + used;
    let end = start + size;
    if input.len() < end {
        return Err(short());
    }
    Ok(Incoming {
        assoc,
        part: Part {
            packet,
            index: fragment,
            total,
            addr,
            data: input.slice(start..end),
        },
    })
}

pub(crate) fn auth_v5(uuid: &[u8; 16], token: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![5, CMD_AUTH];
    out.extend_from_slice(uuid);
    out.extend_from_slice(token);
    out
}

pub(crate) fn auth_v4(token: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![4, CMD_AUTH];
    out.extend_from_slice(token);
    out
}

pub(crate) fn connect(version: Version, dst: &Address) -> io::Result<Vec<u8>> {
    let mut out = vec![version.byte(), CMD_CONNECT];
    put_addr(&mut out, dst)?;
    Ok(out)
}

pub(crate) fn dissociate(version: Version, assoc: u32) -> Vec<u8> {
    let mut out = vec![version.byte(), CMD_DISSOCIATE];
    match version {
        Version::V5 => out.extend_from_slice(&(assoc as u16).to_be_bytes()),
        Version::V4 => out.extend_from_slice(&assoc.to_be_bytes()),
    }
    out
}

/// Fixed part of a v5 packet plus the longest address, which is what the
/// relay-size limits are computed against.
pub(crate) const V5_OVERHEAD: usize = 2 + 2 + 2 + 1 + 1 + 2 + 19;
pub(crate) const V4_OVERHEAD: usize = 2 + 4 + 2 + 19;

pub(crate) struct Fragment<'a> {
    pub(crate) assoc: u32,
    pub(crate) packet: u16,
    pub(crate) total: u8,
    pub(crate) id: u8,
    pub(crate) addr: Option<&'a Address>,
    pub(crate) data: &'a [u8],
}

pub(crate) fn packet(version: Version, part: &Fragment<'_>) -> io::Result<Vec<u8>> {
    let size = u16::try_from(part.data.len()).map_err(|_| invalid_data("datagram too large"))?;
    let mut out = Vec::with_capacity(V5_OVERHEAD + part.data.len());
    out.push(version.byte());
    out.push(CMD_PACKET);
    match version {
        Version::V5 => {
            out.extend_from_slice(&(part.assoc as u16).to_be_bytes());
            out.extend_from_slice(&part.packet.to_be_bytes());
            out.push(part.total);
            out.push(part.id);
            out.extend_from_slice(&size.to_be_bytes());
        }
        Version::V4 => {
            out.extend_from_slice(&part.assoc.to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
        }
    }
    match part.addr {
        Some(addr) => put_addr(&mut out, addr)?,
        None => out.push(ATYP_NONE),
    }
    out.extend_from_slice(part.data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dst() -> Address {
        Address::new("example.com", 443)
    }

    #[test]
    fn addresses_round_trip() {
        for addr in [
            dst(),
            Address::new("1.2.3.4", 53),
            Address::new("2001:db8::1", 8080),
        ] {
            let mut out = Vec::new();
            put_addr(&mut out, &addr).unwrap();
            assert_eq!(get_addr(&out).unwrap(), Some((Some(addr), out.len())));
        }
        assert_eq!(get_addr(&[255]).unwrap(), Some((None, 1)));
        assert_eq!(get_addr(&[1, 1, 2]).unwrap(), None);
        assert!(get_addr(&[9]).is_err());
    }

    #[test]
    fn a_v5_packet_round_trips() {
        let data = b"payload";
        let wire = packet(
            Version::V5,
            &Fragment {
                assoc: 0x1234,
                packet: 7,
                total: 1,
                id: 0,
                addr: Some(&dst()),
                data,
            },
        )
        .unwrap();
        assert_eq!(&wire[..8], &[5, 2, 0x12, 0x34, 0, 7, 1, 0]);
        let Command::Packet(parsed) = parse_command(Version::V5, &Bytes::from(wire)).unwrap()
        else {
            panic!("expected a packet");
        };
        let part = &parsed.part;
        assert_eq!((parsed.assoc, part.packet, part.total), (0x1234, 7, 1));
        assert_eq!(part.addr, Some(dst()));
        assert_eq!(&part.data[..], data);
    }

    #[test]
    fn a_v4_packet_round_trips() {
        let wire = packet(
            Version::V4,
            &Fragment {
                assoc: 0xdead_beef,
                packet: 0,
                total: 1,
                id: 0,
                addr: Some(&dst()),
                data: b"x",
            },
        )
        .unwrap();
        assert_eq!(&wire[..8], &[4, 2, 0xde, 0xad, 0xbe, 0xef, 0, 1]);
        let Command::Packet(parsed) = parse_command(Version::V4, &Bytes::from(wire)).unwrap()
        else {
            panic!("expected a packet");
        };
        assert_eq!(parsed.assoc, 0xdead_beef);
        assert_eq!(&parsed.part.data[..], b"x");
    }

    #[test]
    fn a_wrong_version_or_short_input_is_an_error() {
        assert!(parse_command(Version::V5, &Bytes::from_static(&[4, 2])).is_err());
        assert!(parse_command(Version::V5, &Bytes::from_static(&[5])).is_err());
        assert!(parse_command(Version::V5, &Bytes::from_static(&[5, 2, 0, 1])).is_err());
    }

    #[cfg(feature = "server")]
    #[test]
    fn the_server_reads_what_the_client_writes() {
        let parse = |version, frame: Vec<u8>| parse_command(version, &Bytes::from(frame)).unwrap();
        let Command::Auth(Credential::V5 { uuid, token }) =
            parse(Version::V5, auth_v5(&[1; 16], &[2; 32]))
        else {
            panic!("expected a v5 auth");
        };
        assert_eq!((uuid, token), ([1; 16], [2; 32]));
        let Command::Auth(Credential::V4 { token }) = parse(Version::V4, auth_v4(&[3; 32])) else {
            panic!("expected a v4 auth");
        };
        assert_eq!(token, [3; 32]);
        assert!(matches!(
            parse(Version::V5, dissociate(Version::V5, 0x0102)),
            Command::Dissociate(0x0102)
        ));
        assert!(matches!(
            parse(Version::V4, dissociate(Version::V4, 7)),
            Command::Dissociate(7)
        ));
        assert!(
            parse_command(
                Version::V5,
                &Bytes::from(auth_v5(&[1; 16], &[2; 32])[..40].to_vec())
            )
            .is_err()
        );
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn a_connect_address_is_read_without_the_data_after_it() {
        for dst in [
            dst(),
            Address::new("1.2.3.4", 80),
            Address::new("2001:db8::1", 443),
        ] {
            let frame = connect(Version::V5, &dst).unwrap();
            let mut input = frame.get(2..).unwrap().to_vec();
            input.extend_from_slice(b"data");
            let mut reader = input.as_slice();
            assert_eq!(read_addr(&mut reader).await.unwrap(), dst);
            assert_eq!(reader, b"data");
        }
        let mut cut: &[u8] = &[ATYP_DOMAIN, 3, b'a'];
        assert!(read_addr(&mut cut).await.is_err());
        let mut none: &[u8] = &[ATYP_NONE];
        assert!(read_addr(&mut none).await.is_err());
    }

    #[test]
    fn auth_and_connect_frames_match_the_protocol() {
        assert_eq!(&auth_v5(&[1; 16], &[2; 32])[..2], &[5, 0]);
        assert_eq!(auth_v4(&[2; 32]).len(), 34);
        let connect = connect(Version::V5, &Address::new("1.2.3.4", 80)).unwrap();
        assert_eq!(connect, [5, 1, 1, 1, 2, 3, 4, 0, 80]);
        assert_eq!(dissociate(Version::V5, 0x0102), [5, 3, 1, 2]);
        assert_eq!(dissociate(Version::V4, 1), [4, 3, 0, 0, 0, 1]);
    }
}
