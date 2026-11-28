use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use concord_common::{Network, ProcessInfo};

const XSO_SOCKET: u32 = 0x1;
const XSO_INPCB: u32 = 0x10;
const INP_IPV4: u8 = 0x1;
const INP_IPV6: u8 = 0x2;
const MIN_INPCB: usize = 80;
const MIN_SOCKET: usize = 88;
const SS_NOFDREF: u16 = 0x1;
const SOF_MP_SUBFLOW: u32 = 0x0100_0000;
const PATH_MAX: usize = 4096;
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const SOCKINFO_IN: u32 = 1;
const SOCKINFO_TCP: u32 = 2;
const SOCKET_FDINFO: usize = 792;
const SOI_PROTOCOL: usize = 24 + 156;
const SOI_KIND: usize = 24 + 232;
const INSI: usize = 24 + 240;

#[derive(Debug, PartialEq, Eq)]
pub struct Pcb {
    pub local: SocketAddr,
    pub v4: bool,
    pub pid: u32,
}

fn word(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// `pcblist_n` is a stream of `{len, kind, ..}` records per socket after an `xinpgen`
/// header, each padded to 8 bytes, so the walk does not depend on per-release struct sizes.
pub fn parse_pcblist(buf: &[u8]) -> Vec<Pcb> {
    let mut sockets = Vec::new();
    let mut pending: Option<(SocketAddr, bool)> = None;
    let mut at = word(buf, 0).unwrap_or(0) as usize;
    while let (Some(len), Some(kind)) = (word(buf, at), word(buf, at + 4)) {
        let len = len as usize;
        let Some(record) = buf.get(at..at + len).filter(|_| len >= 8) else {
            break;
        };
        at += len.next_multiple_of(8);
        if kind == XSO_INPCB && len >= MIN_INPCB {
            pending = parse_inpcb(record);
        } else if kind == XSO_SOCKET
            && len >= MIN_SOCKET
            && let (Some((local, v4)), Some(pid)) = (pending.take(), word(record, 68))
            && has_descriptor(record)
        {
            sockets.push(Pcb { local, v4, pid });
        }
    }
    sockets
}

/// A closed socket lingering on a live socket's address keeps its last pid. MPTCP subflows never
/// have a descriptor; xnu's `soreceive` exempts them the same way. `pack(4)` puts `so_flags` at 84.
fn has_descriptor(socket: &[u8]) -> bool {
    let state = socket
        .get(26..28)
        .map_or(0, |b| u16::from_ne_bytes([b[0], b[1]]));
    let flags = word(socket, 84).unwrap_or(0);
    state & SS_NOFDREF == 0 || flags & SOF_MP_SUBFLOW != 0
}

fn parse_inpcb(record: &[u8]) -> Option<(SocketAddr, bool)> {
    let port = u16::from_be_bytes(record.get(18..20)?.try_into().ok()?);
    local_addr(port, *record.get(44)?, record.get(64..80)?)
}

/// `flags` says which address `addr` holds; an IPv4 one sits in its last four bytes, as both
/// `xinpcb_n` and `in_sockinfo` keep it.
fn local_addr(port: u16, flags: u8, addr: &[u8]) -> Option<(SocketAddr, bool)> {
    if flags & INP_IPV4 != 0 {
        let octets: [u8; 4] = addr.get(12..16)?.try_into().ok()?;
        Some((
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port),
            true,
        ))
    } else if flags & INP_IPV6 != 0 {
        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?);
        let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
        Some((SocketAddr::new(ip, port), false))
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bound {
    Exactly,
    /// A UDP socket bound to the unspecified address, which answers when no socket has `src`.
    Wildcard,
}

fn bound(local: SocketAddr, v4: bool, network: Network, src: SocketAddr) -> Option<Bound> {
    if local.port() != src.port() || v4 != src.is_ipv4() {
        None
    } else if local.ip() == src.ip() {
        Some(Bound::Exactly)
    } else if network == Network::Udp && local.ip().is_unspecified() {
        Some(Bound::Wildcard)
    } else {
        None
    }
}

pub fn select(sockets: &[Pcb], network: Network, src: SocketAddr) -> Option<u32> {
    let with = |want| {
        sockets
            .iter()
            .find(|pcb| bound(pcb.local, pcb.v4, network, src) == Some(want))
    };
    with(Bound::Exactly)
        .or_else(|| with(Bound::Wildcard))
        .map(|pcb| pcb.pid)
}

fn read_pcblist(network: Network) -> Option<Vec<u8>> {
    let name = match network {
        Network::Tcp => c"net.inet.tcp.pcblist_n",
        Network::Udp => c"net.inet.udp.pcblist_n",
    };
    for _ in 0..4 {
        let mut len = 0usize;
        // SAFETY: a null buffer only asks for the size.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let mut buf = vec![0u8; len + len / 4 + 8192];
        let mut size = buf.len();
        // SAFETY: `buf` is writable for `size` bytes, which the call updates to the bytes written.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            buf.truncate(size);
            return Some(buf);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return None;
        }
    }
    None
}

fn path_of(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; PATH_MAX];
    // SAFETY: `buf` is writable for the PATH_MAX bytes passed.
    let written =
        unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr().cast(), PATH_MAX as u32) };
    let written = usize::try_from(written).ok().filter(|len| *len > 0)?;
    buf.truncate(written);
    String::from_utf8(buf).ok()
}

/// macOS 27 lists in `pcblist_n` only the caller's own sockets when a third-party app started the
/// caller, as a desktop host app starts Concord. libproc still reads the descriptors of every
/// process of the same user, as lsof does, so a miss there falls back to walking them.
pub fn find(network: Network, src: SocketAddr) -> Option<ProcessInfo> {
    let listed = read_pcblist(network).and_then(|dump| select(&parse_pcblist(&dump), network, src));
    let pid = listed.or_else(|| find_by_descriptors(network, src))?;
    let path = path_of(pid)?;
    let name = Path::new(&path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    Some(ProcessInfo {
        uid: None,
        name,
        path,
    })
}

/// The process the last descriptor walk found, tried first: a browser opens its connections in
/// bursts from one process.
static LAST_FOUND: AtomicI32 = AtomicI32::new(0);

fn find_by_descriptors(network: Network, src: SocketAddr) -> Option<u32> {
    let last = LAST_FOUND.load(Ordering::Relaxed);
    let mut walk = DescriptorWalk::new(network, src);
    if last > 0 && walk.holds(last) {
        return u32::try_from(last).ok();
    }
    let found = all_pids()
        .into_iter()
        .find(|&pid| pid > 0 && pid != last && walk.holds(pid));
    if let Some(pid) = found {
        LAST_FOUND.store(pid, Ordering::Relaxed);
    }
    u32::try_from(found.or(walk.wildcard)?).ok()
}

struct DescriptorWalk {
    network: Network,
    src: SocketAddr,
    fds: Vec<libc::proc_fdinfo>,
    info: Vec<u8>,
    wildcard: Option<i32>,
}

impl DescriptorWalk {
    fn new(network: Network, src: SocketAddr) -> Self {
        Self {
            network,
            src,
            fds: Vec::new(),
            info: vec![0; SOCKET_FDINFO],
            wildcard: None,
        }
    }

    /// Whether `pid` holds a socket bound to `src`; a wildcard UDP socket is kept for the end.
    fn holds(&mut self, pid: i32) -> bool {
        list_fds(pid, &mut self.fds);
        for fd in &self.fds {
            if i64::from(fd.proc_fdtype) != i64::from(libc::PROX_FDTYPE_SOCKET) {
                continue;
            }
            let Some((local, v4)) = socket(&mut self.info, self.network, pid, fd.proc_fd) else {
                continue;
            };
            match bound(local, v4, self.network, self.src) {
                Some(Bound::Exactly) => return true,
                Some(Bound::Wildcard) => {
                    self.wildcard.get_or_insert(pid);
                }
                None => {}
            }
        }
        false
    }
}

/// The local address of an Internet socket of `network`, read into `info` as `struct socket_fdinfo`.
fn socket(info: &mut [u8], network: Network, pid: i32, fd: i32) -> Option<(SocketAddr, bool)> {
    let size = libc::c_int::try_from(info.len()).ok()?;
    // SAFETY: `info` is writable for the `size` bytes passed.
    let written = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if usize::try_from(written).ok() != Some(SOCKET_FDINFO) {
        return None;
    }
    let kind = word(info, SOI_KIND)?;
    let ours = match network {
        Network::Tcp => kind == SOCKINFO_TCP,
        Network::Udp => {
            kind == SOCKINFO_IN
                && i64::from(word(info, SOI_PROTOCOL)?) == i64::from(libc::IPPROTO_UDP)
        }
    };
    if !ours {
        return None;
    }
    // in_sockinfo: insi_lport at 4 keeps the port in network order, insi_vflag at 24 takes the
    // INP_IPV4/INP_IPV6 values, insi_laddr at 48.
    let port = u16::from_be_bytes(info.get(INSI + 4..INSI + 6)?.try_into().ok()?);
    local_addr(port, *info.get(INSI + 24)?, info.get(INSI + 48..INSI + 64)?)
}

fn all_pids() -> Vec<i32> {
    // SAFETY: a null buffer only asks for the count.
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let mut pids = vec![0i32; usize::try_from(count).unwrap_or(0)];
    for _ in 0..4 {
        pids.resize(pids.len() + pids.len() / 4 + 64, 0);
        let bytes =
            libc::c_int::try_from(pids.len() * size_of::<i32>()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `pids` is writable for the `bytes` passed.
        let listed = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        let Ok(listed) = usize::try_from(listed) else {
            return Vec::new();
        };
        if listed < pids.len() {
            pids.truncate(listed);
            return pids;
        }
    }
    pids
}

/// Fills `fds` with the descriptors of `pid`, or empties it when `pid` is gone or another user's.
fn list_fds(pid: i32, fds: &mut Vec<libc::proc_fdinfo>) {
    const EMPTY: libc::proc_fdinfo = libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    };
    let entry = size_of::<libc::proc_fdinfo>();
    // SAFETY: a null buffer only asks for the size.
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let Ok(needed) = usize::try_from(needed) else {
        fds.clear();
        return;
    };
    fds.clear();
    fds.resize(needed / entry + 16, EMPTY);
    let bytes = libc::c_int::try_from(fds.len() * entry).unwrap_or(libc::c_int::MAX);
    // SAFETY: `fds` is writable for the `bytes` passed.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            bytes,
        )
    };
    fds.truncate(usize::try_from(written).map_or(0, |written| written / entry));
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream, UdpSocket};

    use socket2::{Domain, Socket, Type};

    use super::*;

    #[allow(
        clippy::disallowed_methods,
        reason = "tests bind loopback sockets directly"
    )]
    fn bind_udp(addr: &str) -> UdpSocket {
        UdpSocket::bind(addr).unwrap()
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "tests connect to a loopback listener directly"
    )]
    fn connect_tcp(addr: SocketAddr) -> TcpStream {
        TcpStream::connect(addr).unwrap()
    }

    fn record(kind: u32, len: usize, fill: &[(usize, &[u8])]) -> Vec<u8> {
        let mut bytes = vec![0u8; len.next_multiple_of(8)];
        bytes[..4].copy_from_slice(&(len as u32).to_ne_bytes());
        bytes[4..8].copy_from_slice(&kind.to_ne_bytes());
        for (at, value) in fill {
            bytes[*at..*at + value.len()].copy_from_slice(value);
        }
        bytes
    }

    #[test]
    fn records_pair_a_pcb_with_the_following_socket() {
        let header = record(0, 24, &[]);
        let inpcb = record(
            XSO_INPCB,
            104,
            &[
                (18, &8080u16.to_be_bytes()),
                (44, &[INP_IPV4]),
                (76, &[10, 0, 0, 7]),
            ],
        );
        let socket = record(XSO_SOCKET, 120, &[(68, &4321u32.to_ne_bytes())]);
        let ignored = record(0x20, 204, &[]);
        let trailer = record(0x10, 24, &[]);

        let dump = [header, inpcb, socket, ignored, trailer].concat();
        let sockets = parse_pcblist(&dump);
        assert_eq!(
            sockets,
            vec![Pcb {
                local: "10.0.0.7:8080".parse().unwrap(),
                v4: true,
                pid: 4321
            }]
        );
        assert_eq!(
            select(&sockets, Network::Tcp, "10.0.0.7:8080".parse().unwrap()),
            Some(4321)
        );
        assert_eq!(
            select(&sockets, Network::Tcp, "10.0.0.8:8080".parse().unwrap()),
            None
        );
    }

    #[test]
    fn udp_falls_back_to_the_wildcard_socket() {
        let sockets = vec![Pcb {
            local: "0.0.0.0:5353".parse().unwrap(),
            v4: true,
            pid: 9,
        }];
        let src: SocketAddr = "192.168.1.5:5353".parse().unwrap();
        assert_eq!(select(&sockets, Network::Udp, src), Some(9));
        assert_eq!(select(&sockets, Network::Tcp, src), None);
    }

    #[test]
    fn this_process_owns_its_sockets() {
        let _spawn = concord_common::sync::lock(&crate::SPAWN_GUARD);
        let exe = std::env::current_exe().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = connect_tcp(listener.local_addr().unwrap());
        let udp = bind_udp("127.0.0.1:0");

        for (network, addr) in [
            (Network::Tcp, listener.local_addr().unwrap()),
            (Network::Tcp, client.local_addr().unwrap()),
            (Network::Udp, udp.local_addr().unwrap()),
        ] {
            let info =
                find(network, addr).unwrap_or_else(|| panic!("no owner for {network} {addr}"));
            assert_eq!(Path::new(&info.path).file_name(), exe.file_name());
            assert_eq!(info.name, exe.file_name().unwrap().to_string_lossy());
        }
    }

    #[test]
    fn a_socket_without_a_descriptor_is_skipped_unless_it_is_a_subflow() {
        let inpcb = record(
            XSO_INPCB,
            104,
            &[
                (18, &8080u16.to_be_bytes()),
                (44, &[INP_IPV4]),
                (76, &[127, 0, 0, 1]),
            ],
        );
        let socket = |pid: u32, state: u16, flags: u32| {
            record(
                XSO_SOCKET,
                104,
                &[
                    (26, &state.to_ne_bytes()),
                    (68, &pid.to_ne_bytes()),
                    (84, &flags.to_ne_bytes()),
                ],
            )
        };
        let dump = [
            record(0, 24, &[]),
            inpcb.clone(),
            socket(1, SS_NOFDREF, 0),
            inpcb.clone(),
            socket(2, SS_NOFDREF, SOF_MP_SUBFLOW),
            inpcb,
            socket(3, 0, 0),
        ]
        .concat();
        let pids: Vec<u32> = parse_pcblist(&dump).iter().map(|pcb| pcb.pid).collect();
        assert_eq!(pids, [2, 3]);
    }

    #[test]
    fn a_closed_socket_on_the_same_port_is_not_listed() {
        let _spawn = concord_common::sync::lock(&crate::SPAWN_GUARD);
        // Newer than the live socket, the closed one comes first in the list until its peer closes.
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let reusable = || {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
            socket.set_reuse_address(true).unwrap();
            socket
        };
        let live = reusable();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        live.bind(&any.into()).unwrap();
        live.connect(&second.local_addr().unwrap().into()).unwrap();
        let src = live.local_addr().unwrap().as_socket().unwrap();
        let closed = reusable();
        closed.bind(&src.into()).unwrap();
        closed.connect(&first.local_addr().unwrap().into()).unwrap();
        let _peer = first.accept().unwrap();
        drop(closed);

        // Under load the kernel can list a just-closed socket with its descriptor for a moment;
        // one that was never filtered stays listed while its peer is open, so it still fails.
        let listed = || {
            let sockets = parse_pcblist(&read_pcblist(Network::Tcp).unwrap());
            sockets.iter().filter(|pcb| pcb.local == src).count()
        };
        let mut seen = listed();
        for _ in 0..100 {
            if seen == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            seen = listed();
        }
        assert_eq!(seen, 1);
    }

    #[test]
    fn an_unused_port_has_no_owner() {
        let _spawn = concord_common::sync::lock(&crate::SPAWN_GUARD);
        let port = concord_test_support::port_to_bind_later();
        let unused = bind_udp(&format!("127.0.0.1:{port}"));
        let addr = unused.local_addr().unwrap();
        drop(unused);
        assert!(find(Network::Udp, addr).is_none());
    }

    #[test]
    fn descriptors_name_the_process_holding_a_socket() {
        let _spawn = concord_common::sync::lock(&crate::SPAWN_GUARD);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut nc = std::process::Command::new("/usr/bin/nc")
            .arg("127.0.0.1")
            .arg(listener.local_addr().unwrap().port().to_string())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let (_peer, src) = listener.accept().unwrap();
        let nc_pid = i32::try_from(nc.id()).unwrap();

        for _ in 0..2 {
            assert_eq!(
                find_by_descriptors(Network::Tcp, src),
                u32::try_from(nc_pid).ok()
            );
            assert_eq!(LAST_FOUND.load(Ordering::Relaxed), nc_pid);
        }
        let elsewhere = SocketAddr::new("127.0.0.2".parse().unwrap(), src.port());
        assert_eq!(find_by_descriptors(Network::Tcp, elsewhere), None);
        assert_eq!(find_by_descriptors(Network::Udp, src), None);
        nc.kill().unwrap();
        nc.wait().unwrap();
    }

    #[test]
    fn descriptors_fall_back_to_a_wildcard_udp_socket() {
        let _spawn = concord_common::sync::lock(&crate::SPAWN_GUARD);
        let own = std::process::id();
        let exact = bind_udp("127.0.0.1:0");
        let addr = exact.local_addr().unwrap();
        assert_eq!(find_by_descriptors(Network::Udp, addr), Some(own));

        let port = concord_test_support::port_to_bind_later();
        let any = bind_udp(&format!("0.0.0.0:{port}"));
        let src = SocketAddr::new(
            "127.0.0.1".parse().unwrap(),
            any.local_addr().unwrap().port(),
        );
        assert_eq!(find_by_descriptors(Network::Udp, src), Some(own));
        assert_eq!(find_by_descriptors(Network::Tcp, src), None);
    }
}
