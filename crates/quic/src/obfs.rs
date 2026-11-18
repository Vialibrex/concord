use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use std::sync::atomic::{AtomicU32, Ordering};

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rand::Rng;
use sha2::Sha256;

type Blake2b256 = Blake2b<U32>;

const SALT_LEN: usize = 8;
const MASK_LEN: usize = 32;

const FRAGMENT_FLAG: u8 = 0x80;
const GECKO_HEADER: usize = 5;
const GECKO_MIN_CHUNKS: usize = 2;
const GECKO_MAX_CHUNKS: usize = 8;
const GECKO_MAX_ON_WIRE: usize = 2048;
const REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const MAX_REASSEMBLY: usize = 4096;
const MAX_PER_SOURCE: usize = 8;

pub(crate) const GECKO_DEFAULT_MIN: usize = 512;
pub(crate) const GECKO_DEFAULT_MAX: usize = 1200;

#[derive(Debug, thiserror::Error)]
#[error("gecko: invalid packet size range")]
pub struct GeckoRange;

#[derive(Clone)]
pub(crate) struct Salamander {
    password: Vec<u8>,
}

impl Salamander {
    pub(crate) fn new(password: &[u8]) -> Self {
        Salamander {
            password: password.to_vec(),
        }
    }

    fn mask(&self, salt: &[u8]) -> [u8; MASK_LEN] {
        let mut hasher = Blake2b256::new();
        hasher.update(&self.password);
        hasher.update(salt);
        hasher.finalize().into()
    }

    pub(crate) fn seal(&self, payload: &[u8], out: &mut Vec<u8>) {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill(&mut salt);
        let mask = self.mask(&salt);
        out.extend_from_slice(&salt);
        out.extend(
            payload
                .iter()
                .zip(mask.iter().cycle())
                .map(|(byte, key)| byte ^ key),
        );
    }

    /// Decodes in place and moves the payload to the front; `None` for a packet
    /// too short to carry one.
    pub(crate) fn open(&self, packet: &mut [u8]) -> Option<usize> {
        if packet.len() <= SALT_LEN {
            return None;
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(packet.get(..SALT_LEN)?);
        let mask = self.mask(&salt);
        for (byte, key) in packet
            .get_mut(SALT_LEN..)?
            .iter_mut()
            .zip(mask.iter().cycle())
        {
            *byte ^= key;
        }
        packet.copy_within(SALT_LEN.., 0);
        Some(packet.len() - SALT_LEN)
    }
}

/// A stateless wrapper around each datagram that grows it by a fixed amount.
pub(crate) trait Seal: Send + Sync {
    fn overhead(&self) -> usize;
    fn seal(&self, payload: &[u8], out: &mut Vec<u8>);
    /// Decodes in place and moves the payload to the front.
    fn open(&self, packet: &mut [u8]) -> Option<usize>;
}

impl Seal for Salamander {
    fn overhead(&self) -> usize {
        SALT_LEN
    }

    fn seal(&self, payload: &[u8], out: &mut Vec<u8>) {
        Salamander::seal(self, payload, out);
    }

    fn open(&self, packet: &mut [u8]) -> Option<usize> {
        Salamander::open(self, packet)
    }
}

const XPLUS_SALT: usize = 16;
const WECHAT_HEADER: [u8; 13] = [
    0xa1, 0x08, 0, 0, 0, 0, 0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30,
];

/// Hysteria 1's `obfs`: the payload is XORed with `SHA-256(key || salt)`.
#[derive(Clone)]
pub(crate) struct XPlus {
    key: Vec<u8>,
}

impl XPlus {
    pub(crate) fn new(key: &[u8]) -> Self {
        XPlus { key: key.to_vec() }
    }

    fn mask(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, &self.key);
        sha2::Digest::update(&mut hasher, salt);
        sha2::Digest::finalize(hasher).into()
    }
}

impl Seal for XPlus {
    fn overhead(&self) -> usize {
        XPLUS_SALT
    }

    fn seal(&self, payload: &[u8], out: &mut Vec<u8>) {
        let mut salt = [0u8; XPLUS_SALT];
        rand::rng().fill(&mut salt);
        let mask = self.mask(&salt);
        out.extend_from_slice(&salt);
        out.extend(
            payload
                .iter()
                .zip(mask.iter().cycle())
                .map(|(byte, key)| byte ^ key),
        );
    }

    fn open(&self, packet: &mut [u8]) -> Option<usize> {
        if packet.len() <= XPLUS_SALT {
            return None;
        }
        let mask = self.mask(packet.get(..XPLUS_SALT)?);
        for (byte, key) in packet
            .get_mut(XPLUS_SALT..)?
            .iter_mut()
            .zip(mask.iter().cycle())
        {
            *byte ^= key;
        }
        packet.copy_within(XPLUS_SALT.., 0);
        Some(packet.len() - XPLUS_SALT)
    }
}

/// Hysteria 1's `wechat-video` protocol: a fixed 13-byte header with a
/// counter in front of each datagram, optionally `obfs`-ed as well.
pub(crate) struct WeChat {
    inner: Option<XPlus>,
    counter: AtomicU32,
}

impl WeChat {
    pub(crate) fn new(key: Option<&[u8]>) -> Self {
        WeChat {
            inner: key.map(XPlus::new),
            counter: AtomicU32::new(rand::rng().random::<u32>() & 0xffff),
        }
    }
}

impl Seal for WeChat {
    fn overhead(&self) -> usize {
        WECHAT_HEADER.len() + self.inner.as_ref().map_or(0, |inner| inner.overhead())
    }

    fn seal(&self, payload: &[u8], out: &mut Vec<u8>) {
        let mut header = WECHAT_HEADER;
        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        if let Some(slot) = header.get_mut(2..6) {
            slot.copy_from_slice(&counter.to_be_bytes());
        }
        out.extend_from_slice(&header);
        match &self.inner {
            Some(inner) => inner.seal(payload, out),
            None => out.extend_from_slice(payload),
        }
    }

    fn open(&self, packet: &mut [u8]) -> Option<usize> {
        let body = packet.get_mut(WECHAT_HEADER.len()..)?;
        let len = match &self.inner {
            Some(inner) => inner.open(body)?,
            None if body.is_empty() => return None,
            None => body.len(),
        };
        packet.copy_within(WECHAT_HEADER.len()..WECHAT_HEADER.len() + len, 0);
        Some(len)
    }
}

pub(crate) enum Opened {
    /// A packet that now sits at the front of the datagram, of this length.
    Whole(usize),
    Joined(Vec<u8>),
    Dropped,
}

struct Pending {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    deadline: Instant,
}

/// Salamander plus, for QUIC long-header packets, Hysteria2's fragmenting
/// `gecko` framing with random padding.
pub(crate) struct Gecko {
    salamander: Salamander,
    min: usize,
    max: usize,
    next_id: u8,
    pending: HashMap<(SocketAddr, u8), Pending>,
    per_source: HashMap<SocketAddr, usize>,
    last_sweep: Instant,
}

impl Gecko {
    pub(crate) fn new(password: &[u8], min: usize, max: usize) -> Result<Self, GeckoRange> {
        let min = if min == 0 { GECKO_DEFAULT_MIN } else { min };
        let max = if max == 0 { GECKO_DEFAULT_MAX } else { max };
        if min > max || max > GECKO_MAX_ON_WIRE {
            return Err(GeckoRange);
        }
        Ok(Gecko {
            salamander: Salamander::new(password),
            min,
            max,
            next_id: 0,
            pending: HashMap::new(),
            per_source: HashMap::new(),
            last_sweep: Instant::now(),
        })
    }

    /// Appends the datagrams that carry `packet`, each one sealed.
    pub(crate) fn seal(&mut self, packet: &[u8], out: &mut Vec<Vec<u8>>) {
        if packet
            .first()
            .is_none_or(|first| first & FRAGMENT_FLAG == 0)
        {
            let mut datagram = Vec::with_capacity(packet.len() + SALT_LEN);
            self.salamander.seal(packet, &mut datagram);
            out.push(datagram);
            return;
        }
        let mut rng = rand::rng();
        let chunks = rng.random_range(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS);
        let size = packet.len() / chunks;
        self.next_id = self.next_id.wrapping_add(1);
        for index in 0..chunks {
            let start = index * size;
            let end = if index + 1 < chunks {
                start + size
            } else {
                packet.len()
            };
            let chunk = packet.get(start..end).unwrap_or_default();
            let pad = self.pad_len(chunk.len());
            let mut frame = Vec::with_capacity(GECKO_HEADER + pad + chunk.len());
            frame.push(FRAGMENT_FLAG);
            frame.push(self.next_id);
            frame.push(((index as u8) << 4) | (chunks as u8 & 0x0f));
            frame.extend_from_slice(&(pad as u16).to_be_bytes());
            frame.resize(GECKO_HEADER + pad, 0);
            if let Some(padding) = frame.get_mut(GECKO_HEADER..) {
                rng.fill(padding);
            }
            frame.extend_from_slice(chunk);
            let mut datagram = Vec::with_capacity(frame.len() + SALT_LEN);
            self.salamander.seal(&frame, &mut datagram);
            out.push(datagram);
        }
    }

    fn pad_len(&self, chunk: usize) -> usize {
        let base = SALT_LEN + GECKO_HEADER + chunk;
        let low = self.min.max(base);
        if low > self.max {
            return 0;
        }
        low - base + rand::rng().random_range(0..=self.max - low)
    }

    /// Opens one received datagram in place. A fragment that completes a packet
    /// returns the whole of it, which is longer than the datagram it arrived in.
    pub(crate) fn open(&mut self, packet: &mut [u8], from: SocketAddr) -> Opened {
        let Some(len) = self.salamander.open(packet) else {
            return Opened::Dropped;
        };
        let Some(frame) = packet.get(..len) else {
            return Opened::Dropped;
        };
        match frame.first() {
            Some(first) if first & FRAGMENT_FLAG == 0 => return Opened::Whole(len),
            Some(_) => {}
            None => return Opened::Dropped,
        }
        let [_, id, position, hi, lo, ..] = *frame else {
            return Opened::Dropped;
        };
        let pad = usize::from(u16::from_be_bytes([hi, lo]));
        let (index, total) = (usize::from(position >> 4), usize::from(position & 0x0f));
        if !(GECKO_MIN_CHUNKS..=GECKO_MAX_CHUNKS).contains(&total) || index >= total {
            return Opened::Dropped;
        }
        let Some(payload) = frame.get(GECKO_HEADER + pad..) else {
            return Opened::Dropped;
        };
        match self.accept(from, id, index, total, payload.to_vec()) {
            Some(joined) => Opened::Joined(joined),
            None => Opened::Dropped,
        }
    }

    fn accept(
        &mut self,
        from: SocketAddr,
        id: u8,
        index: usize,
        total: usize,
        payload: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let now = Instant::now();
        if now.duration_since(self.last_sweep) >= REASSEMBLY_TTL / 2 {
            self.sweep(now);
        }
        let key = (from, id);
        if !self.pending.contains_key(&key) {
            if self.per_source.get(&from).copied().unwrap_or(0) >= MAX_PER_SOURCE {
                return None;
            }
            if self.pending.len() >= MAX_REASSEMBLY {
                self.evict_oldest();
            }
            self.pending.insert(
                key,
                Pending {
                    chunks: vec![None; total],
                    received: 0,
                    deadline: now + REASSEMBLY_TTL,
                },
            );
            *self.per_source.entry(from).or_default() += 1;
        }
        let entry = self.pending.get_mut(&key)?;
        if entry.chunks.len() != total {
            return None;
        }
        let slot = entry.chunks.get_mut(index)?;
        if slot.is_some() {
            return None;
        }
        *slot = Some(payload);
        entry.received += 1;
        if entry.received < total {
            return None;
        }
        let done = self.drop_entry(&key)?;
        Some(done.chunks.into_iter().flatten().flatten().collect())
    }

    fn drop_entry(&mut self, key: &(SocketAddr, u8)) -> Option<Pending> {
        let entry = self.pending.remove(key)?;
        if let Some(count) = self.per_source.get_mut(&key.0) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_source.remove(&key.0);
            }
        }
        Some(entry)
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .pending
            .iter()
            .min_by_key(|(_, entry)| entry.deadline)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.drop_entry(&key);
        }
    }

    fn sweep(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, entry)| now > entry.deadline)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.drop_entry(&key);
        }
        self.last_sweep = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "127.0.0.1:9".parse().unwrap()
    }

    #[test]
    fn salamander_seals_and_opens() {
        let salamander = Salamander::new(b"obfs-password");
        let mut sealed = Vec::new();
        salamander.seal(b"hello quic", &mut sealed);
        assert_eq!(sealed.len(), 18);
        let len = salamander.open(&mut sealed).unwrap();
        assert_eq!(&sealed[..len], b"hello quic");
    }

    #[test]
    fn salamander_matches_the_reference_mask() {
        let salamander = Salamander::new(b"pw");
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut hasher = Blake2b256::new();
        hasher.update(b"pw");
        hasher.update(salt);
        let mask: [u8; 32] = hasher.finalize().into();
        let mut packet = salt.to_vec();
        packet.extend(b"abc".iter().zip(mask).map(|(a, b)| a ^ b));
        let len = salamander.open(&mut packet).unwrap();
        assert_eq!(&packet[..len], b"abc");
    }

    #[test]
    fn xplus_matches_the_reference_mask() {
        let xplus = XPlus::new(b"Vaundy");
        let mut sealed = Vec::new();
        xplus.seal(b"HelloWorld", &mut sealed);
        assert_eq!(sealed.len(), 26);
        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, b"Vaundy");
        sha2::Digest::update(&mut hasher, &sealed[..16]);
        let mask: [u8; 32] = sha2::Digest::finalize(hasher).into();
        let expected: Vec<u8> = b"HelloWorld".iter().zip(mask).map(|(a, b)| a ^ b).collect();
        assert_eq!(&sealed[16..], &expected[..]);
        let len = xplus.open(&mut sealed).unwrap();
        assert_eq!(&sealed[..len], b"HelloWorld");
        assert!(xplus.open(&mut [0u8; 16]).is_none());
    }

    #[test]
    fn wechat_prefixes_a_counting_header() {
        for key in [None, Some(&b"k"[..])] {
            let wechat = WeChat::new(key);
            let (mut first, mut second) = (Vec::new(), Vec::new());
            wechat.seal(b"payload", &mut first);
            wechat.seal(b"payload", &mut second);
            assert_eq!(first.len(), 13 + 7 + key.map_or(0, |_| 16));
            assert_eq!(&first[..2], &[0xa1, 0x08]);
            assert_eq!(&first[6..13], &WECHAT_HEADER[6..]);
            let count = |packet: &[u8]| u32::from_be_bytes(packet[2..6].try_into().unwrap());
            assert_eq!(count(&second), count(&first) + 1);
            let len = wechat.open(&mut first).unwrap();
            assert_eq!(&first[..len], b"payload");
        }
        assert!(WeChat::new(None).open(&mut [0u8; 13]).is_none());
    }

    #[test]
    fn a_short_packet_is_dropped() {
        assert!(Salamander::new(b"x").open(&mut [0u8; 8]).is_none());
    }

    #[test]
    fn gecko_passes_short_header_packets_whole() {
        let mut gecko = Gecko::new(b"pw", 0, 0).unwrap();
        let mut datagrams = Vec::new();
        gecko.seal(&[0x41, 1, 2, 3], &mut datagrams);
        assert_eq!(datagrams.len(), 1);
        let mut datagram = datagrams.remove(0);
        let Opened::Whole(len) = gecko.open(&mut datagram, peer()) else {
            panic!("expected a whole packet");
        };
        assert_eq!(&datagram[..len], &[0x41, 1, 2, 3]);
    }

    #[test]
    fn gecko_fragments_long_header_packets_and_reassembles_them() {
        let mut gecko = Gecko::new(b"pw", 512, 1200).unwrap();
        let packet: Vec<u8> = std::iter::once(0xc0)
            .chain((0..1100u32).map(|i| (i % 251) as u8))
            .collect();
        let mut datagrams = Vec::new();
        gecko.seal(&packet, &mut datagrams);
        assert!((2..=8).contains(&datagrams.len()));
        assert!(
            datagrams
                .iter()
                .all(|d| (512..=1200).contains(&d.len()) || d.len() < 1200)
        );
        let mut whole = None;
        datagrams.reverse();
        for mut datagram in datagrams {
            if let Opened::Joined(joined) = gecko.open(&mut datagram, peer()) {
                whole = Some(joined);
            }
        }
        assert_eq!(whole.unwrap(), packet);
    }

    #[test]
    fn gecko_rejects_a_bad_size_range() {
        assert!(Gecko::new(b"pw", 900, 800).is_err());
        assert!(Gecko::new(b"pw", 10, 4096).is_err());
    }

    #[test]
    fn a_fragment_with_an_impossible_header_is_dropped() {
        let mut gecko = Gecko::new(b"pw", 0, 0).unwrap();
        let salamander = Salamander::new(b"pw");
        let mut datagram = Vec::new();
        salamander.seal(&[FRAGMENT_FLAG, 1, 0x91, 0, 0, 7], &mut datagram);
        assert!(matches!(gecko.open(&mut datagram, peer()), Opened::Dropped));
    }

    #[test]
    fn gecko_reads_what_the_go_implementation_sends() {
        let wire = [
            "a4fef5a76350f7168226db59c581fa9c11e60d774e09e09aaf11ece4c96e50",
            "a1375211b2e715eedb4b081bd58d21a04a7f1aaa766bd89e6e1a0fc51274",
            "9db4f65450f7486048fd609273300341a44f1582378b4a3031a2c3b912b722cb155de69963ffc0f4611968f28c35a17b39727c2a950a99233e50f0db",
            "85230b805b4ff6fbc40a7cf29556c79dc13a0c07f5d6eceedfd6b4ec18c90d25240946e2d749a9bf4b1b5ae09d",
            "82709f9323d1693d4ffe517c089ed5877a7a2d4d37c6e7a2b3c2ca0c4ae94947c48c4e",
            "a587111e36de7dc40eb22f72ef179b7a652ad0fdc768c7c60e4bfc1758",
            "32a712bdc1b863c7f7b2e16380c6269285a150240c9c4370ccf55e3f8e5c1b3dbd1b68d33f61dd495497a345b1",
        ];
        let mut gecko = Gecko::new(b"gecko-pw", 1, 64).unwrap();
        let mut whole = None;
        for datagram in wire {
            let mut bytes = hex::decode(datagram).unwrap();
            if let Opened::Joined(joined) = gecko.open(&mut bytes, peer()) {
                whole = Some(joined);
            }
        }
        let expected: Vec<u8> = std::iter::once(0xc0)
            .chain((1..40u32).map(|i| (i % 251) as u8))
            .collect();
        assert_eq!(whole.unwrap(), expected);
    }
}
