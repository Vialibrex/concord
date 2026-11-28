use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use concord_common::{
    Address, ClockOffset, CoreError, DialCx, DialEnv, Initiator, IpVersion, PacketBuf, Tasks,
    recv_packet, send_packet,
};
use rand::RngExt;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

const NTP_UNIX_GAP_SECS: u64 = 2_208_988_800;
const PACKET_LEN: usize = 48;
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
const ATTEMPTS: usize = 3;
const NANOS: i128 = 1_000_000_000;

pub(crate) struct NtpSettings {
    pub server: String,
    pub port: u16,
    pub interval: Duration,
    pub dialer_proxy: String,
    pub write_to_system: bool,
}

type SystemClockWriter = Box<dyn Fn(SystemTime) -> io::Result<()> + Send + Sync>;

struct Reply {
    server_time: SystemTime,
    offset_nanos: i128,
}

fn ntp_stamp(time: SystemTime) -> u64 {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() + NTP_UNIX_GAP_SECS;
    let frac = ((u128::from(since.subsec_nanos()) << 32) + 500_000_000) / 1_000_000_000;
    (secs << 32).wrapping_add(u64::try_from(frac).unwrap_or(0))
}

fn stamp_nanos(stamp: u64) -> i128 {
    let secs = i128::from(stamp >> 32);
    let frac = i128::from(stamp & 0xFFFF_FFFF);
    secs * NANOS + ((frac * NANOS + (1 << 31)) >> 32)
}

fn unix_nanos(stamp: u64) -> i128 {
    stamp_nanos(stamp) - i128::from(NTP_UNIX_GAP_SECS) * NANOS
}

fn request(transmit: u64) -> [u8; PACKET_LEN] {
    let mut packet = [0u8; PACKET_LEN];
    if let Some(first) = packet.first_mut() {
        *first = (3 << 6) | (4 << 3) | 3;
    }
    if let Some(slot) = packet.get_mut(40..48) {
        slot.copy_from_slice(&transmit.to_be_bytes());
    }
    packet
}

fn field(packet: &[u8], at: usize) -> Option<u64> {
    let bytes: [u8; 8] = packet.get(at..at + 8)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// mihomo takes whatever 48 bytes arrive; this also requires a server-mode reply with a
/// real stratum that echoes the request's transmit stamp, so a stray or forged datagram
/// cannot move the clock.
fn parse(
    packet: &[u8],
    sent: u64,
    sent_at: SystemTime,
    received_at: SystemTime,
) -> io::Result<Reply> {
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("ntp: {what}"));
    if packet.len() < PACKET_LEN {
        return Err(bad("short reply"));
    }
    if packet.first().map(|byte| byte & 7) != Some(4) {
        return Err(bad("not a server reply"));
    }
    if packet.get(1).copied().unwrap_or(0) == 0 {
        return Err(bad("kiss of death"));
    }
    if field(packet, 24) != Some(sent) {
        return Err(bad("reply does not answer the request"));
    }
    let (Some(receive), Some(transmit)) = (field(packet, 32), field(packet, 40)) else {
        return Err(bad("short reply"));
    };
    let origin = stamp_nanos(ntp_stamp(sent_at));
    let destination = stamp_nanos(ntp_stamp(received_at));
    let offset_nanos =
        ((stamp_nanos(receive) - origin) + (stamp_nanos(transmit) - destination)) / 2;
    let transmit_unix = unix_nanos(transmit);
    let server_time = u64::try_from(transmit_unix)
        .ok()
        .map(Duration::from_nanos)
        .and_then(|since| UNIX_EPOCH.checked_add(since))
        .ok_or_else(|| bad("time before 1970"))?;
    Ok(Reply {
        server_time,
        offset_nanos,
    })
}

async fn query(env: &DialEnv, settings: &NtpSettings) -> io::Result<Reply> {
    let target = Address::new(&settings.server, settings.port);
    let transmit: u64 = rand::rng().random();
    let packet = request(transmit);
    let sent_at = SystemTime::now();
    let started = Instant::now();
    let answer = if settings.dialer_proxy.is_empty() {
        direct(env, &target, &packet).await?
    } else {
        through(env, &settings.dialer_proxy, &target, &packet).await?
    };
    parse(&answer, transmit, sent_at, sent_at + started.elapsed())
}

async fn direct(env: &DialEnv, target: &Address, packet: &[u8]) -> io::Result<Vec<u8>> {
    let ip = match target {
        Address::Socket(addr) => addr.ip(),
        Address::Domain(host, _) => env
            .resolver
            .lookup(host, IpVersion::Dual, Initiator::Other)
            .await?
            .first(IpVersion::Dual)
            .ok_or_else(|| CoreError::IpNotFound(host.to_string()))?,
    };
    let addr = env.sockets.ip4p(SocketAddr::new(ip, target.port()));
    if addr.is_ipv6() && !env.ipv6 {
        return Err(CoreError::Ipv6Disabled.into());
    }
    let socket: UdpSocket = env.sockets.bind_udp(addr.ip(), &env.sock_opts)?;
    socket.connect(addr).await?;
    socket.send(packet).await?;
    let mut buf = [0u8; 128];
    let len = socket.recv(&mut buf).await?;
    Ok(buf.get(..len).unwrap_or_default().to_vec())
}

async fn through(env: &DialEnv, via: &str, target: &Address, packet: &[u8]) -> io::Result<Vec<u8>> {
    let cx = DialCx::new(env, Initiator::Other, None);
    let session = env.nodes.associate_via(via, &cx, target).await?;
    let mut out = PacketBuf::with_headroom(session.headroom());
    out.extend_from_slice(packet);
    let result = async {
        send_packet(&*session, &mut out, target).await?;
        let (buf, _from) = recv_packet(&*session).await?;
        Ok(buf.as_slice().to_vec())
    }
    .await;
    session.close();
    result
}

struct Service {
    settings: NtpSettings,
    env: Arc<DialEnv>,
    clock: Arc<ClockOffset>,
    write: SystemClockWriter,
    stop: CancellationToken,
}

impl Service {
    async fn update(&mut self) -> io::Result<()> {
        let mut last = io::Error::other("ntp: no attempt made");
        for _ in 0..ATTEMPTS {
            let result = tokio::select! {
                () = self.stop.cancelled() => return Ok(()),
                result = timeout(EXCHANGE_TIMEOUT, query(&self.env, &self.settings)) => result,
            };
            let reply = match result {
                Ok(Ok(reply)) => reply,
                Ok(Err(err)) => {
                    last = err;
                    continue;
                }
                Err(_) => {
                    last = io::Error::from(io::ErrorKind::TimedOut);
                    continue;
                }
            };
            let offset = Duration::from_nanos(
                u64::try_from(reply.offset_nanos.unsigned_abs()).unwrap_or(u64::MAX),
            );
            if reply.offset_nanos > 0 {
                tracing::info!("System clock is behind NTP time by {offset:?}");
            } else if reply.offset_nanos < 0 {
                tracing::info!("System clock is ahead of NTP time by {offset:?}");
            }
            self.clock
                .set(i64::try_from(reply.offset_nanos).unwrap_or(0));
            if self.settings.write_to_system {
                match (self.write)(reply.server_time) {
                    Ok(()) => tracing::info!("Sync system time success: {:?}", reply.server_time),
                    Err(err) => {
                        tracing::error!("Write time to system: {err}");
                        self.settings.write_to_system = false;
                    }
                }
            }
            return Ok(());
        }
        Err(last)
    }

    async fn run(mut self) {
        tracing::info!(
            "NTP service start, sync system time is {}",
            self.settings.write_to_system
        );
        loop {
            if let Err(err) = self.update().await {
                tracing::warn!("Sync time failed: {err}");
            }
            tokio::select! {
                () = self.stop.cancelled() => break,
                () = sleep(self.settings.interval) => {}
            }
        }
        self.clock.set(0);
        tracing::info!("NTP service stop");
    }
}

/// `ReCreateNTPService`: the caller cancels `stop` to end the service, which also
/// drops the offset it set.
pub(crate) fn start(
    tasks: &Tasks,
    settings: NtpSettings,
    env: Arc<DialEnv>,
    clock: Arc<ClockOffset>,
    stop: CancellationToken,
) {
    let service = Service {
        settings,
        env,
        clock,
        write: Box::new(concord_platform::set_system_time),
        stop,
    };
    tasks.spawn_to_end(service.run());
}

#[cfg(test)]
fn start_with(
    handle: &tokio::runtime::Handle,
    settings: NtpSettings,
    env: Arc<DialEnv>,
    clock: Arc<ClockOffset>,
    write: SystemClockWriter,
    stop: CancellationToken,
) {
    handle.spawn(
        Service {
            settings,
            env,
            clock,
            write,
            stop,
        }
        .run(),
    );
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use concord_common::{
        BoxStream, HostResolver, LookupIps, NodeDialer, NullSink, PacketSession, SockOpts,
    };
    use concord_net::Sockets;
    use concord_platform::NativePlatform;

    use super::*;

    use concord_common::sync::lock;

    const HOUR: i64 = 3_600_000_000_000;

    struct NoResolver;

    #[async_trait]
    impl HostResolver for NoResolver {
        async fn lookup(&self, host: &str, _: IpVersion, _: Initiator) -> io::Result<LookupIps> {
            Err(CoreError::IpNotFound(host.to_string()).into())
        }
    }

    struct ViaSkewed {
        skew: i64,
        asked: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl NodeDialer for ViaSkewed {
        async fn dial_via(&self, name: &str, _: &DialCx<'_>, _: &Address) -> io::Result<BoxStream> {
            Err(CoreError::UnknownNode(name.to_string()).into())
        }

        async fn associate_via(
            &self,
            name: &str,
            _: &DialCx<'_>,
            hint: &Address,
        ) -> io::Result<Arc<dyn PacketSession>> {
            lock(&self.asked).push(format!("{name} {hint}"));
            Ok(Arc::new(SkewedSession {
                skew: self.skew,
                replies: Mutex::new(VecDeque::new()),
            }))
        }
    }

    struct SkewedSession {
        skew: i64,
        replies: Mutex<VecDeque<Vec<u8>>>,
    }

    impl PacketSession for SkewedSession {
        fn poll_send(
            &self,
            _: &mut Context<'_>,
            pkt: &mut PacketBuf,
            _: &Address,
        ) -> Poll<io::Result<()>> {
            lock(&self.replies).push_back(reply_to(pkt.as_slice(), self.skew));
            Poll::Ready(Ok(()))
        }

        fn poll_recv(&self, _: &mut Context<'_>, buf: &mut PacketBuf) -> Poll<io::Result<Address>> {
            match lock(&self.replies).pop_front() {
                Some(reply) => {
                    buf.extend_from_slice(&reply);
                    Poll::Ready(Ok(Address::new("127.0.0.1", 123)))
                }
                None => Poll::Pending,
            }
        }
    }

    fn skewed(skew: i64) -> SystemTime {
        let now = SystemTime::now();
        let shift = Duration::from_nanos(skew.unsigned_abs());
        if skew >= 0 { now + shift } else { now - shift }
    }

    fn reply_to(request: &[u8], skew: i64) -> Vec<u8> {
        let mut reply = vec![0u8; PACKET_LEN];
        reply[0] = (4 << 3) | 4;
        reply[1] = 2;
        reply[24..32].copy_from_slice(&request[40..48]);
        let stamp = ntp_stamp(skewed(skew)).to_be_bytes();
        reply[32..40].copy_from_slice(&stamp);
        reply[40..48].copy_from_slice(&stamp);
        reply
    }

    fn env(nodes: Arc<dyn NodeDialer>) -> Arc<DialEnv> {
        Arc::new(DialEnv {
            sockets: Arc::new(Sockets::new(Arc::new(NativePlatform::new()))),
            resolver: Arc::new(NoResolver),
            nodes,
            events: Arc::new(NullSink),
            sock_opts: SockOpts::default(),
            tcp_concurrent: false,
            ipv6: true,
        })
    }

    fn settings(server: &str, port: u16, via: &str, write: bool) -> NtpSettings {
        NtpSettings {
            server: server.into(),
            port,
            interval: Duration::from_millis(50),
            dialer_proxy: via.into(),
            write_to_system: write,
        }
    }

    async fn server(skew: i64) -> u16 {
        #[allow(clippy::disallowed_methods, reason = "a loopback test server")]
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 128];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let request = buf.get(..len).unwrap_or_default();
                if request.len() >= PACKET_LEN {
                    let _ = socket.send_to(&reply_to(request, skew), peer).await;
                }
            }
        });
        port
    }

    async fn settled(clock: &ClockOffset, until: impl Fn(i64) -> bool) -> bool {
        for _ in 0..100 {
            if until(clock.nanos()) {
                return true;
            }
            sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn recorder() -> (SystemClockWriter, Arc<Mutex<Vec<SystemTime>>>) {
        let written = Arc::new(Mutex::new(Vec::new()));
        let sink = written.clone();
        (
            Box::new(move |time| {
                lock(&sink).push(time);
                Ok(())
            }),
            written,
        )
    }

    fn near(nanos: i64, want: i64) -> bool {
        (nanos - want).abs() < 2_000_000_000
    }

    #[test]
    fn the_wire_form_matches_the_rfc() {
        let packet = request(0x0102_0304_0506_0708);
        assert_eq!(packet[0], 0xE3);
        assert_eq!(&packet[40..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        let stamp = ntp_stamp(UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000));
        assert_eq!(stamp >> 32, 1_700_000_000 + NTP_UNIX_GAP_SECS);
        assert_eq!(stamp & 0xFFFF_FFFF, 1 << 31);
        assert_eq!(unix_nanos(stamp), 1_700_000_000_500_000_000);
    }

    #[test]
    fn a_reply_that_does_not_answer_the_request_is_refused() {
        let now = SystemTime::now();
        let mut reply = reply_to(&request(7), 0);
        assert!(parse(&reply, 7, now, now).is_ok());
        assert!(parse(&reply, 8, now, now).is_err());
        reply[1] = 0;
        assert!(parse(&reply, 7, now, now).is_err());
        reply[1] = 2;
        reply[0] = (4 << 3) | 3;
        assert!(parse(&reply, 7, now, now).is_err());
        assert!(parse(&reply[..40], 7, now, now).is_err());
    }

    #[test]
    fn the_offset_is_server_minus_client_over_the_round_trip() {
        let sent_at = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let received_at = sent_at + Duration::from_millis(200);
        let server_clock = sent_at + Duration::from_secs(60) + Duration::from_millis(100);
        let mut reply = reply_to(&request(9), 0);
        let stamp = ntp_stamp(server_clock).to_be_bytes();
        reply[32..40].copy_from_slice(&stamp);
        reply[40..48].copy_from_slice(&stamp);
        let parsed = parse(&reply, 9, sent_at, received_at).unwrap();
        assert!(
            (parsed.offset_nanos - 60 * NANOS).abs() < 1_000,
            "{}",
            parsed.offset_nanos
        );
        assert_eq!(parsed.server_time, server_clock);
    }

    #[tokio::test]
    async fn a_direct_server_sets_the_offset_and_stopping_clears_it() {
        let port = server(HOUR).await;
        let clock = Arc::new(ClockOffset::default());
        let stop = CancellationToken::new();
        let (write, written) = recorder();
        start_with(
            &tokio::runtime::Handle::current(),
            settings("127.0.0.1", port, "", false),
            env(Arc::new(ViaSkewed {
                skew: 0,
                asked: Mutex::default(),
            })),
            clock.clone(),
            write,
            stop.clone(),
        );
        assert!(settled(&clock, |nanos| near(nanos, HOUR)).await);
        assert!(lock(&written).is_empty(), "the system clock was written");

        stop.cancel();
        assert!(settled(&clock, |nanos| nanos == 0).await);
    }

    #[tokio::test]
    async fn the_system_clock_is_written_only_when_asked() {
        let port = server(-HOUR).await;
        let clock = Arc::new(ClockOffset::default());
        let stop = CancellationToken::new();
        let (write, written) = recorder();
        start_with(
            &tokio::runtime::Handle::current(),
            settings("127.0.0.1", port, "", true),
            env(Arc::new(ViaSkewed {
                skew: 0,
                asked: Mutex::default(),
            })),
            clock.clone(),
            write,
            stop.clone(),
        );
        assert!(settled(&clock, |nanos| near(nanos, -HOUR)).await);
        let written = lock(&written).clone();
        assert!(!written.is_empty());
        let behind = SystemTime::now().duration_since(written[0]).unwrap();
        assert!(behind > Duration::from_secs(3_500), "{behind:?}");
        stop.cancel();
    }

    #[tokio::test]
    async fn a_failed_write_is_not_tried_again() {
        let port = server(HOUR).await;
        let clock = Arc::new(ClockOffset::default());
        let stop = CancellationToken::new();
        let calls = Arc::new(Mutex::new(0));
        let counted = calls.clone();
        start_with(
            &tokio::runtime::Handle::current(),
            settings("127.0.0.1", port, "", true),
            env(Arc::new(ViaSkewed {
                skew: 0,
                asked: Mutex::default(),
            })),
            clock.clone(),
            Box::new(move |_| {
                *lock(&counted) += 1;
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }),
            stop.clone(),
        );
        assert!(settled(&clock, |nanos| near(nanos, HOUR)).await);
        sleep(Duration::from_millis(300)).await;
        assert_eq!(*lock(&calls), 1);
        stop.cancel();
    }

    #[tokio::test]
    async fn a_dialer_proxy_carries_the_exchange_to_the_named_server() {
        let nodes = Arc::new(ViaSkewed {
            skew: 2 * HOUR,
            asked: Mutex::default(),
        });
        let clock = Arc::new(ClockOffset::default());
        let stop = CancellationToken::new();
        let (write, _) = recorder();
        start_with(
            &tokio::runtime::Handle::current(),
            settings("time.example", 123, "relay", false),
            env(nodes.clone()),
            clock.clone(),
            write,
            stop.clone(),
        );
        assert!(settled(&clock, |nanos| near(nanos, 2 * HOUR)).await);
        assert_eq!(lock(&nodes.asked)[0], "relay time.example:123");
        stop.cancel();
    }

    #[tokio::test]
    async fn an_unreachable_server_leaves_the_clock_alone() {
        let clock = Arc::new(ClockOffset::default());
        let stop = CancellationToken::new();
        let (write, _) = recorder();
        start_with(
            &tokio::runtime::Handle::current(),
            settings("time.invalid", 123, "", false),
            env(Arc::new(ViaSkewed {
                skew: 0,
                asked: Mutex::default(),
            })),
            clock.clone(),
            write,
            stop.clone(),
        );
        sleep(Duration::from_millis(200)).await;
        assert_eq!(clock.nanos(), 0);
        stop.cancel();
    }
}
