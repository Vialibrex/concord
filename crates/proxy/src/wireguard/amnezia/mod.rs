mod mac;
mod template;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use concord_common::sync::lock;
use concord_config::proxy::AmneziaWgOpts;
use rand::RngExt;

use self::mac::{COOKIE_REPLY, INITIATION, Macs, RESPONSE};
use self::template::Template;
use crate::ctx::BuildError;

const INIT: usize = 0;
const REPLY: usize = 1;
const COOKIE: usize = 2;
const TRANSPORT: usize = 3;

const SIZES: [usize; 4] = [INITIATION, RESPONSE, COOKIE_REPLY, 32];
const MAX_DATAGRAM: usize = 65_535;
const NONCE: usize = 12;
const TRAILER_WINDOW: usize = 500;
const TRANSPORT_HEADER: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Flavour {
    Legacy,
    V3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    lo: u32,
    hi: u32,
}

impl Span {
    const fn one(value: u32) -> Self {
        Span {
            lo: value,
            hi: value,
        }
    }

    fn contains(self, value: u32) -> bool {
        self.lo <= value && value <= self.hi
    }

    fn overlaps(self, other: Span) -> bool {
        self.lo <= other.hi && other.lo <= self.hi
    }

    fn parse(text: &str) -> Result<Span, String> {
        let number = |part: &str| {
            part.parse::<u32>()
                .map_err(|_| format!("invalid header {text:?}"))
        };
        let (lo, hi) = match text.split_once('-') {
            Some((lo, hi)) => (number(lo)?, number(hi)?),
            None => {
                let value = number(text)?;
                (value, value)
            }
        };
        if hi < lo {
            return Err(format!("invalid header {text:?}: min is above max"));
        }
        Ok(Span { lo, hi })
    }

    /// The legacy implementation never picks the upper bound of a range, the later ones may.
    fn pick(self, flavour: Flavour) -> u32 {
        if self.lo == self.hi {
            return self.lo;
        }
        let upper = match flavour {
            Flavour::Legacy => self.hi,
            Flavour::V3 => self.hi.saturating_add(1),
        };
        rand::rng().random_range(self.lo..upper)
    }
}

#[derive(Debug)]
pub(super) struct Settings {
    flavour: Flavour,
    junk_count: u32,
    junk_min: u32,
    junk_max: u32,
    pad: [usize; 4],
    headers: [Span; 4],
    special: Vec<Template>,
    controlled: Vec<Template>,
    interval: Duration,
    protect: Option<[u8; 32]>,
    trailers: bool,
}

fn default_headers() -> [Span; 4] {
    [Span::one(1), Span::one(2), Span::one(3), Span::one(4)]
}

fn invalid(message: impl Into<String>) -> BuildError {
    BuildError::invalid(format!("amnezia-wg-option: {}", message.into()))
}

impl Settings {
    /// None when the options leave the wire format as plain WireGuard has it.
    pub(super) fn parse(opts: &AmneziaWgOpts) -> Result<Option<Settings>, BuildError> {
        let flavour = if opts.version == 3 {
            Flavour::V3
        } else {
            Flavour::Legacy
        };
        let pads = [opts.s1, opts.s2, opts.s3, opts.s4];
        let mut settings = Settings {
            flavour,
            junk_count: opts.jc,
            junk_min: opts.jmin,
            junk_max: opts.jmax,
            pad: pads.map(|pad| pad as usize),
            headers: default_headers(),
            special: Vec::new(),
            controlled: Vec::new(),
            interval: Duration::ZERO,
            protect: None,
            trailers: false,
        };
        match flavour {
            Flavour::Legacy => settings.legacy(opts)?,
            Flavour::V3 => settings.v3(opts)?,
        }
        if settings.is_plain() {
            return Ok(None);
        }
        Ok(Some(settings))
    }

    fn is_plain(&self) -> bool {
        self.junk_count == 0
            && self.pad == [0; 4]
            && self.headers == default_headers()
            && self.special.is_empty()
            && self.controlled.is_empty()
            && self.protect.is_none()
            && !self.trailers
    }

    fn legacy(&mut self, opts: &AmneziaWgOpts) -> Result<(), BuildError> {
        let v3_only = [
            (
                "header-protection-key",
                !opts.header_protection_key.is_empty(),
            ),
            (
                "content-padding-addition",
                !opts.content_padding_addition.is_empty(),
            ),
            ("rekey-after-time", !opts.rekey_after_time.is_empty()),
            ("rekey-timeout", !opts.rekey_timeout.is_empty()),
            ("reject-after-time", !opts.reject_after_time.is_empty()),
            ("keepalive-timeout", !opts.keepalive_timeout.is_empty()),
            (
                "max-handshake-attempts",
                !opts.max_handshake_attempts.is_empty(),
            ),
            ("random-trailers", opts.random_trailers),
            ("disable-cookies", opts.disable_cookies),
        ];
        if let Some((name, _)) = v3_only.iter().find(|(_, set)| *set) {
            return Err(invalid(format!("{name} needs version 3")));
        }
        if self.junk_count > 0 && self.junk_max == self.junk_min {
            self.junk_max = self.junk_max.saturating_add(1);
        }
        if self.junk_max as usize >= MAX_DATAGRAM {
            return Err(invalid(format!(
                "jmax {} should be smaller than {MAX_DATAGRAM}",
                self.junk_max
            )));
        }
        if self.junk_max < self.junk_min {
            return Err(invalid(format!(
                "jmax {} should be greater than jmin {}",
                self.junk_max, self.junk_min
            )));
        }
        for (index, text) in opts.h.iter().enumerate() {
            if text.is_empty() {
                continue;
            }
            let span = Span::parse(text).map_err(invalid)?;
            if span.lo > 4
                && let Some(slot) = self.headers.get_mut(index)
            {
                *slot = span;
            }
        }
        let mut sorted = self.headers;
        sorted.sort_by_key(|span| span.lo);
        if sorted.windows(2).any(|pair| match pair {
            [a, b] => a.hi >= b.lo,
            _ => false,
        }) {
            return Err(invalid("magic headers should not overlap"));
        }
        let sizes: Vec<usize> = SIZES.iter().zip(self.pad).map(|(a, b)| a + b).collect();
        if sizes.iter().any(|size| *size >= MAX_DATAGRAM) {
            return Err(invalid("a junk size is larger than a datagram"));
        }
        let mut distinct = sizes.clone();
        distinct.sort_unstable();
        distinct.dedup();
        if distinct.len() != 4 {
            return Err(invalid(
                "the message sizes after s1 to s4 should differ from each other",
            ));
        }
        self.special = legacy_templates(&opts.i, "i")?;
        self.controlled = legacy_templates(&opts.j, "j")?;
        if opts.itime > 0 {
            self.interval = Duration::from_secs(opts.itime.unsigned_abs());
        }
        Ok(())
    }

    fn v3(&mut self, opts: &AmneziaWgOpts) -> Result<(), BuildError> {
        if opts.j.iter().any(|text| !text.is_empty()) {
            return Err(invalid("j1 to j3 are not part of version 3"));
        }
        if opts.itime != 0 {
            return Err(invalid("itime is not part of version 3"));
        }
        if self.pad.iter().any(|pad| *pad > usize::from(u16::MAX)) {
            return Err(invalid("s1 to s4 should fit in 16 bits"));
        }
        if self.junk_count > 0 && self.junk_max < self.junk_min {
            return Err(invalid(format!(
                "jmax {} should be greater than jmin {}",
                self.junk_max, self.junk_min
            )));
        }
        for (index, text) in opts.h.iter().enumerate() {
            if text.is_empty() {
                continue;
            }
            if let Some(slot) = self.headers.get_mut(index) {
                *slot = Span::parse(text).map_err(invalid)?;
            }
        }
        for (index, left) in self.headers.iter().enumerate() {
            if self
                .headers
                .iter()
                .skip(index + 1)
                .any(|right| left.overlaps(*right))
            {
                return Err(invalid("headers must not overlap"));
            }
        }
        if !opts.header_protection_key.is_empty() {
            let raw = STANDARD
                .decode(opts.header_protection_key.trim())
                .map_err(|err| invalid(format!("decode header protection key: {err}")))?;
            let key = <[u8; 32]>::try_from(raw.as_slice())
                .map_err(|_| invalid("header-protection-key should be 32 bytes"))?;
            if self.pad.iter().any(|pad| *pad < NONCE) {
                return Err(invalid(format!(
                    "s1 to s4 should be at least {NONCE} to use header-protection-key"
                )));
            }
            self.protect = Some(key);
        }
        for (index, text) in opts.i.iter().enumerate() {
            if text.is_empty() {
                continue;
            }
            let template = template::parse_chain(text)
                .map_err(|err| invalid(format!("failed to parse i{}: {err}", index + 1)))?;
            if !template.is_empty() {
                self.special.push(template);
            }
        }
        self.trailers = opts.random_trailers;
        Ok(())
    }
}

fn legacy_templates(values: &[String], name: &str) -> Result<Vec<Template>, BuildError> {
    let set: Vec<usize> = values
        .iter()
        .enumerate()
        .filter(|(_, text)| !text.is_empty())
        .map(|(index, _)| index)
        .collect();
    if set.iter().enumerate().any(|(slot, index)| slot != *index) {
        return Err(invalid(format!(
            "{name} packet index should be consecutive"
        )));
    }
    set.iter()
        .filter_map(|index| values.get(*index).map(|text| (*index, text)))
        .map(|(index, text)| {
            template::parse_legacy(text)
                .map_err(|err| invalid(format!("invalid {name}{}: {err}", index + 1)))
        })
        .collect()
}

#[derive(Default)]
struct Clock {
    next: Option<Instant>,
}

/// The wire format of AmneziaWG wrapped around the datagrams of an unmodified WireGuard
/// implementation: junk packets, replaced message types, padding in front of messages and the
/// header protection of the newer versions.
pub(super) struct Amnezia {
    settings: Arc<Settings>,
    own: Macs,
    peers: Vec<Macs>,
    endpoints: ArcSwap<HashMap<SocketAddr, usize>>,
    counter: AtomicU64,
    clock: Mutex<Clock>,
}

impl Amnezia {
    pub(super) fn new(settings: Arc<Settings>, own_public: &[u8; 32], peers: &[[u8; 32]]) -> Self {
        Amnezia {
            settings,
            own: Macs::new(own_public),
            peers: peers.iter().map(Macs::new).collect(),
            endpoints: ArcSwap::from_pointee(HashMap::new()),
            counter: AtomicU64::new(0),
            clock: Mutex::new(Clock::default()),
        }
    }

    pub(super) fn set_endpoint(&self, peer: usize, endpoint: SocketAddr) {
        let mut map = (**self.endpoints.load()).clone();
        map.retain(|_, held| *held != peer);
        map.insert(endpoint, peer);
        self.endpoints.store(Arc::new(map));
    }

    fn peer(&self, address: SocketAddr) -> Option<&Macs> {
        match self.endpoints.load().get(&address) {
            Some(index) => self.peers.get(*index),
            None if self.peers.len() == 1 => self.peers.first(),
            None => None,
        }
    }

    fn cipher(&self, datagram: &[u8]) -> Option<ChaCha20> {
        let key = self.settings.protect.as_ref()?;
        let nonce = datagram.get(..NONCE)?;
        ChaCha20::new_from_slices(key, nonce).ok()
    }

    fn junk(&self) -> Vec<Vec<u8>> {
        let settings = &*self.settings;
        let mut rng = rand::rng();
        (0..settings.junk_count)
            .map(|_| {
                let span = settings.junk_max.saturating_sub(settings.junk_min);
                let extra = if span == 0 {
                    0
                } else {
                    rng.random_range(0..span)
                };
                let mut bytes = vec![0u8; (settings.junk_min + extra) as usize];
                rng.fill(bytes.as_mut_slice());
                bytes
            })
            .collect()
    }

    async fn prelude(&self) -> Vec<Vec<u8>> {
        let settings = &*self.settings;
        let mut out = Vec::new();
        match settings.flavour {
            Flavour::Legacy => {
                let due = {
                    let mut clock = lock(&self.clock);
                    let due = !settings.special.is_empty()
                        && clock.next.is_none_or(|next| Instant::now() > next);
                    if due {
                        clock.next = Some(Instant::now() + settings.interval);
                    }
                    due
                };
                let templates = if due {
                    &settings.special
                } else {
                    &settings.controlled
                };
                for template in templates {
                    out.push(template.render(&self.counter).await);
                    self.counter.fetch_sub(1, Ordering::Relaxed);
                }
                if !templates.is_empty() {
                    self.counter
                        .fetch_add(u64::from(settings.junk_count), Ordering::Relaxed);
                }
            }
            Flavour::V3 => {
                for template in &settings.special {
                    out.push(template.render(&self.counter).await);
                }
            }
        }
        out.extend(self.junk());
        out
    }

    /// Turns one datagram of the WireGuard implementation into the datagrams to put on the wire.
    pub(super) async fn frame(&self, packet: &[u8], destination: SocketAddr) -> Vec<Vec<u8>> {
        let settings = &*self.settings;
        let kind = match (
            packet
                .first_chunk::<4>()
                .map(|head| u32::from_le_bytes(*head)),
            packet.len(),
        ) {
            (Some(1), INITIATION) => INIT,
            (Some(2), RESPONSE) => REPLY,
            (Some(3), COOKIE_REPLY) => COOKIE,
            (Some(4), len) if len >= SIZES[TRANSPORT] => TRANSPORT,
            _ => return vec![packet.to_vec()],
        };
        let pad = settings.pad.get(kind).copied().unwrap_or(0);
        let header = settings
            .headers
            .get(kind)
            .map_or(kind as u32 + 1, |span| span.pick(settings.flavour));

        let mut out = Vec::new();
        if kind == INIT {
            out = self.prelude().await;
        }

        let trailer = if settings.trailers && kind != TRANSPORT {
            TRAILER_WINDOW
                .checked_sub(pad + packet.len())
                .filter(|room| *room > 0)
                .map_or(0, |room| rand::rng().random_range(0..room))
        } else {
            0
        };
        let mut datagram = vec![0u8; pad + packet.len() + trailer];
        rand::rng().fill(datagram.as_mut_slice());
        if let Some(body) = datagram.get_mut(pad..pad + packet.len()) {
            body.copy_from_slice(packet);
            if let Some(slot) = body.get_mut(..4) {
                slot.copy_from_slice(&header.to_le_bytes());
            }
            if (kind == INIT || kind == REPLY)
                && let Some(macs) = self.peer(destination)
            {
                macs.stamp(body, kind == INIT);
            }
        }
        if let Some(mut cipher) = self.cipher(&datagram) {
            let covered = if kind == TRANSPORT {
                TRANSPORT_HEADER
            } else {
                packet.len()
            };
            if let Some(region) = datagram.get_mut(pad..pad + covered) {
                cipher.apply_keystream(region);
            }
        }
        out.push(datagram);
        if !settings.special.is_empty() || !settings.controlled.is_empty() {
            self.counter.fetch_add(out.len() as u64, Ordering::Relaxed);
        }
        out
    }

    /// Turns a received datagram back into what the WireGuard implementation expects, in place.
    /// None means the datagram is not for it: junk, a cookie reply, a bad MAC or an unknown type.
    pub(super) fn unframe(&self, datagram: &mut [u8], from: SocketAddr) -> Option<usize> {
        if datagram.len() < SIZES[TRANSPORT] {
            return None;
        }
        let (kind, start, len) = match self.settings.flavour {
            Flavour::Legacy => self.classify_legacy(datagram)?,
            Flavour::V3 => self.classify_v3(datagram)?,
        };
        if kind == TRANSPORT && len < SIZES[TRANSPORT] {
            return None;
        }
        let message = datagram.get_mut(start..start + len)?;
        if (kind == INIT || kind == REPLY) && !self.own.check_mac1(message) {
            return None;
        }
        message
            .get_mut(..4)?
            .copy_from_slice(&(kind as u32 + 1).to_le_bytes());
        match kind {
            COOKIE => {
                self.peer(from)?.take_cookie(message);
                return None;
            }
            INIT | REPLY => {
                self.own.stamp(message, false);
            }
            _ => {}
        }
        datagram.copy_within(start..start + len, 0);
        Some(len)
    }

    fn classify_legacy(&self, datagram: &[u8]) -> Option<(usize, usize, usize)> {
        let settings = &*self.settings;
        let size = datagram.len();
        let header_of = |at: usize| -> Option<usize> {
            let value = u32::from_le_bytes(*datagram.get(at..)?.first_chunk::<4>()?);
            settings
                .headers
                .iter()
                .position(|span| span.contains(value))
        };
        let sized = SIZES
            .iter()
            .zip(settings.pad)
            .position(|(base, pad)| base + pad == size);
        if let Some(kind) = sized {
            let pad = settings.pad.get(kind).copied()?;
            if header_of(pad) == Some(kind) {
                return Some((kind, pad, size.checked_sub(pad)?));
            }
        }
        let pad = settings.pad.get(TRANSPORT).copied()?;
        if header_of(pad)? != TRANSPORT {
            return None;
        }
        Some((TRANSPORT, pad, size.checked_sub(pad)?))
    }

    fn classify_v3(&self, datagram: &mut [u8]) -> Option<(usize, usize, usize)> {
        let settings = &*self.settings;
        let size = datagram.len();
        let mut cipher = self.cipher(datagram);
        let mut hash = [0u8; 4];
        if let Some(cipher) = cipher.as_mut() {
            cipher.apply_keystream(&mut hash);
        }
        let (kind, pad, plain) = (0..4).find_map(|kind| {
            let pad = settings.pad.get(kind).copied()?;
            let expected = pad + SIZES.get(kind).copied()?;
            let fits = if kind == TRANSPORT {
                size >= expected
            } else {
                size == expected || settings.trailers && size > expected
            };
            if !fits {
                return None;
            }
            let raw = datagram.get(pad..pad + 4)?;
            let mut value = [0u8; 4];
            for (slot, (byte, mask)) in value.iter_mut().zip(raw.iter().zip(hash)) {
                *slot = byte ^ mask;
            }
            settings
                .headers
                .get(kind)?
                .contains(u32::from_le_bytes(value))
                .then_some((kind, pad, value))
        })?;
        datagram.get_mut(pad..pad + 4)?.copy_from_slice(&plain);
        let len = if kind == TRANSPORT {
            size.checked_sub(pad)?
        } else {
            SIZES.get(kind).copied()?
        };
        let covered = if kind == TRANSPORT {
            TRANSPORT_HEADER
        } else {
            len
        };
        if let Some(cipher) = cipher.as_mut() {
            let region = datagram.get_mut(pad + 4..pad + covered)?;
            cipher.apply_keystream(region);
        }
        Some((kind, pad, len))
    }
}
