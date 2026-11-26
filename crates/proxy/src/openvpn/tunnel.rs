use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Buf;
use concord_common::{DialCx, Tasks};
use concord_platform::UDP_BATCH;
use gotatun::packet::{Packet, PacketBufPool};
use gotatun::tun::IpSend;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tokio_util::sync::CancellationToken;

use super::config::Config;
use super::control::Control;
use super::data::Keys;
use super::link::{self, Link, Reader};
use super::push::PushReply;
use super::wire::{PING, is_control, is_data, key_id, opcode};
use crate::node::Egress;
use crate::stack::{Stack, StackConfig, StackDriver, StackRecv, StackSend};
use crate::wireguard::dns::RemoteDns;

const CONTROL_QUEUE: usize = 64;
const LZO_NONE: u8 = 0xFA;
const LZO_COMPRESSED: u8 = 0x66;

/// When the tunnel last sent and received data, for ping and ping-restart.
struct Activity {
    base: Instant,
    sent: AtomicU64,
    received: AtomicU64,
}

impl Activity {
    fn new() -> Activity {
        Activity {
            base: Instant::now(),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
        }
    }

    fn mark(&self, slot: &AtomicU64) {
        let millis = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        slot.store(millis, Ordering::Relaxed);
    }

    fn at(&self, slot: &AtomicU64) -> Instant {
        self.base + Duration::from_millis(slot.load(Ordering::Relaxed))
    }
}

pub(super) struct Tunnel {
    pub(super) stack: Arc<Stack>,
    pub(super) dns: RemoteDns,
    stop: CancellationToken,
    driver: StackDriver,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.close();
    }
}

struct Wiring {
    link: Arc<Link>,
    keys: Arc<ArcSwap<Keys>>,
    activity: Arc<Activity>,
    lzo: bool,
}

impl Tunnel {
    pub(super) fn usable(&self) -> bool {
        !self.stop.is_cancelled()
    }

    pub(super) fn close(&self) {
        self.stop.cancel();
        self.driver.stop();
    }

    pub(super) async fn connect(
        config: &Arc<Config>,
        cx: &DialCx<'_>,
        egress: &Egress,
        tasks: &Tasks,
    ) -> io::Result<Arc<Tunnel>> {
        let (link, reader) = link::open(cx, egress, &config.server, config.tcp).await?;
        let link = Arc::new(link);
        let mut control = Control::new(config.clone(), link.clone(), reader);
        let established = control.handshake(None).await?;
        let push = &established.push;
        let shown = |nets: &[ipnetwork::IpNetwork]| {
            nets.iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        };
        tracing::debug!(
            "openvpn handshake complete: prefixes={:?} routes={:?} peer-id={} dns={:?} redirect={} block-ipv6={}",
            shown(&push.prefixes),
            shown(&push.routes),
            push.peer_id,
            push.dns,
            push.redirect,
            push.block_ipv6
        );
        let addrs: Vec<IpAddr> = push.prefixes.iter().map(|prefix| prefix.ip()).collect();
        let (ping, ping_restart) = keepalive_timers(config, push);
        let wired = Stack::start(
            &StackConfig {
                addrs: addrs.clone(),
                mtu: config.mtu,
            },
            tasks,
        );
        let keys = Arc::new(ArcSwap::from_pointee(Keys::first(Arc::new(
            established.key,
        ))));
        let (queue, queued) = mpsc::channel(CONTROL_QUEUE);
        let reader = control
            .attach(keys.clone(), queued)
            .ok_or_else(|| io::Error::other("OpenVPN server reader already taken"))?;
        let wiring = Arc::new(Wiring {
            link,
            keys,
            activity: Arc::new(Activity::new()),
            lzo: config.comp_lzo,
        });
        let tunnel = Arc::new(Tunnel {
            stack: wired.stack,
            dns: RemoteDns::new(config.dns.clone(), addrs.iter().any(IpAddr::is_ipv6)),
            stop: tasks.child_token(),
            driver: wired.driver,
        });
        tunnel.spawn(tasks, "send", send(wired.recv, wiring.clone()));
        tunnel.spawn(
            tasks,
            "receive",
            receive(reader, wired.send, queue, wiring.clone()),
        );
        tunnel.spawn(tasks, "control", control.run());
        if ping.is_some() || ping_restart.is_some() {
            tunnel.spawn(tasks, "keepalive", keepalive(wiring, ping, ping_restart));
        }
        Ok(tunnel)
    }

    /// Runs one of the tunnel's tasks; whichever ends first takes the tunnel down, and the
    /// next dial builds a new one.
    fn spawn(
        &self,
        tasks: &Tasks,
        role: &'static str,
        work: impl Future<Output = io::Result<()>> + Send + 'static,
    ) {
        let stop = self.stop.clone();
        let driver = self.driver.clone();
        tasks.spawn(async move {
            tokio::select! {
                () = stop.cancelled() => {}
                result = work => {
                    if let Err(err) = result {
                        tracing::warn!("openvpn {role} ended: {err}");
                    }
                    stop.cancel();
                    driver.stop();
                }
            }
        });
    }
}

/// The node's `ping` and `ping-restart`, each falling back to the pushed value as in
/// OpenVPN 2.6; mihomo uses only the node's.
pub(super) fn keepalive_timers(
    config: &Config,
    push: &PushReply,
) -> (Option<Duration>, Option<Duration>) {
    let pushed = |value: Option<u64>| value.filter(|secs| *secs > 0).map(Duration::from_secs);
    (
        config.ping.or_else(|| pushed(push.ping)),
        config.ping_restart.or_else(|| pushed(push.ping_restart)),
    )
}

pub(super) fn lzo_prefix(lzo: bool) -> &'static [u8] {
    if lzo { &[LZO_NONE] } else { &[] }
}

async fn send(mut outgoing: StackRecv, wiring: Arc<Wiring>) -> io::Result<()> {
    let mut packets: Vec<Packet> = Vec::with_capacity(UDP_BATCH);
    let mut sealed: Vec<Vec<u8>> = Vec::new();
    let prefix = lzo_prefix(wiring.lzo);
    loop {
        packets.clear();
        outgoing.recv_many(&mut packets, UDP_BATCH).await?;
        if sealed.len() < packets.len() {
            sealed.resize_with(packets.len(), Vec::new);
        }
        {
            let keys = wiring.keys.load();
            let Some(key) = keys.sender(std::time::Instant::now()) else {
                continue;
            };
            for (packet, out) in packets.iter().zip(sealed.iter_mut()) {
                key.seal(prefix, packet, out)?;
            }
        }
        wiring
            .link
            .send_all(sealed.get(..packets.len()).unwrap_or_default())
            .await?;
        wiring.activity.mark(&wiring.activity.sent);
    }
}

pub(super) enum Opened {
    Packet(Packet),
    /// Authenticated, but nothing for the stack: a ping, or a payload whose comp-lzo
    /// framing is bad.
    Nothing,
}

/// Opens one data packet into a buffer from `pool`; `None` when it does not authenticate
/// or replays. The comp-lzo header comes off before the ping check, since OpenVPN frames
/// pings like any other packet.
pub(super) fn open_data(
    raw: &[u8],
    keys: &Keys,
    lzo: bool,
    pool: &PacketBufPool,
    now: std::time::Instant,
) -> Option<Opened> {
    let (key, primary) = keys.receiver(key_id(*raw.first()?), now)?;
    let mut packet = pool.get();
    packet.buf_mut().resize(raw.len(), 0);
    let (mut start, end) = key.open(raw, &mut packet[..]).ok()?;
    if primary {
        key.mark_peer_active();
    }
    if lzo {
        match packet.get(start) {
            Some(&LZO_NONE) => start += 1,
            Some(&LZO_COMPRESSED) => {
                let Ok(plain) = lzokay_native::decompress_all_bounded(
                    packet.get(start + 1..end).unwrap_or_default(),
                    usize::from(u16::MAX),
                ) else {
                    return Some(Opened::Nothing);
                };
                if plain == PING {
                    return Some(Opened::Nothing);
                }
                let mut out = pool.get();
                out.buf_mut().clear();
                out.buf_mut().extend_from_slice(&plain);
                return Some(Opened::Packet(out));
            }
            _ => return Some(Opened::Nothing),
        }
    }
    if packet.get(start..end).is_none_or(|payload| payload == PING) {
        return Some(Opened::Nothing);
    }
    packet.truncate(end);
    packet.buf_mut().advance(start);
    Some(Opened::Packet(packet))
}

async fn receive(
    mut reader: Reader,
    mut incoming: StackSend,
    control: mpsc::Sender<Vec<u8>>,
    wiring: Arc<Wiring>,
) -> io::Result<()> {
    let pool = PacketBufPool::new(0);
    let mut ready: Vec<Packet> = Vec::new();
    loop {
        let mut now = None;
        let mut heard = false;
        reader
            .recv(|raw| {
                let Some(&first) = raw.first() else {
                    return;
                };
                if is_data(opcode(first)) {
                    let keys = wiring.keys.load();
                    let now = *now.get_or_insert_with(std::time::Instant::now);
                    match open_data(raw, &keys, wiring.lzo, &pool, now) {
                        Some(Opened::Packet(packet)) => {
                            heard = true;
                            ready.push(packet);
                        }
                        Some(Opened::Nothing) => heard = true,
                        None => {}
                    }
                } else if is_control(opcode(first)) {
                    let _ = control.try_send(raw.to_vec());
                }
            })
            .await?;
        if heard {
            wiring.activity.mark(&wiring.activity.received);
        }
        for packet in ready.drain(..) {
            if let Ok(packet) = packet.try_into_ip() {
                incoming.send(packet).await?;
            }
        }
    }
}

/// `ping` sends a ping once nothing went out for that long; `ping-restart` ends the tunnel
/// once nothing came in for that long.
async fn keepalive(
    wiring: Arc<Wiring>,
    ping: Option<Duration>,
    restart: Option<Duration>,
) -> io::Result<()> {
    let prefix = lzo_prefix(wiring.lzo);
    let mut out = Vec::new();
    loop {
        let now = Instant::now();
        let mut wake: Option<Instant> = None;
        if let Some(restart) = restart {
            let due = wiring.activity.at(&wiring.activity.received) + restart;
            if now >= due {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("ping-restart: no packet received for {restart:?}"),
                ));
            }
            wake = Some(due);
        }
        if let Some(ping) = ping {
            let due = wiring.activity.at(&wiring.activity.sent) + ping;
            if now >= due {
                out.clear();
                {
                    let keys = wiring.keys.load();
                    if let Some(key) = keys.sender(now.into_std()) {
                        key.seal(prefix, &PING, &mut out)?;
                    }
                }
                if !out.is_empty() {
                    wiring.link.send(&out).await?;
                }
                wiring.activity.mark(&wiring.activity.sent);
                continue;
            }
            wake = Some(wake.map_or(due, |wake| wake.min(due)));
        }
        match wake {
            Some(wake) => sleep_until(wake).await,
            None => std::future::pending().await,
        }
    }
}
