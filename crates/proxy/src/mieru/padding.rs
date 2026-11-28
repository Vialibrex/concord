use std::io;

use rand::seq::SliceRandom;
use rand::{Rng, RngExt};
use sha2::{Digest, Sha256};

use super::meta::invalid;

pub(super) const CHUNK: usize = 8;
const RECOMMENDED_ASCII: usize = 24;
const TARGET_PROBABILITY: f64 = 0.325;

fn skewed(max: usize) -> usize {
    let mut rng = rand::rng();
    let base: f64 = rng.random();
    let scale = (base * base * base).sqrt();
    (rng.random_range(0..=max) as f64 * scale) as usize
}

fn printable(bytes: &mut [u8]) {
    let mut rng = rand::rng();
    for byte in bytes {
        *byte = 0x20 + u8::try_from(rng.next_u32() % 95).unwrap_or(0);
    }
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rand::rng().fill_bytes(&mut out);
    out
}

pub(super) fn middle_padding(max: usize) -> Vec<u8> {
    random_bytes(skewed(max))
}

pub(super) fn session_padding(max: usize, overhead: usize, user: &str) -> Vec<u8> {
    let strategy = Sha256::digest(user.as_bytes())
        .first()
        .copied()
        .unwrap_or(0)
        & 1;
    if strategy == 0 {
        let min = max.min(RECOMMENDED_ASCII + rand::rng().random_range(0..17));
        let len = min + skewed(max - min);
        let mut out = random_bytes(len);
        let begin = if len > min {
            rand::rng().random_range(0..len - min)
        } else {
            0
        };
        if let Some(run) = out.get_mut(begin..begin + min) {
            printable(run);
        }
        return out;
    }
    let lower_bits = overhead * 4;
    let min_bits = (lower_bits as f64 / TARGET_PROBABILITY - (overhead * 8) as f64).max(0.0);
    let min_bytes = (min_bits as usize).div_ceil(8);
    let len = if min_bytes >= max {
        max
    } else {
        min_bytes + skewed(max - min_bytes)
    };
    let flips = (((overhead + len) * 8) as f64 * TARGET_PROBABILITY - lower_bits as f64)
        .max(0.0)
        .min((len * 8) as f64) as usize;
    let mut out = vec![0xffu8; len];
    if len > 0 {
        let mut rng = rand::rng();
        for _ in 0..flips {
            let bit = rng.random_range(0..len * 8);
            if let Some(byte) = out.get_mut(bit / 8) {
                *byte &= !(1 << (bit % 8));
            }
        }
    }
    out
}

pub(super) struct Params {
    pub(super) source_bytes: usize,
    pub(super) mask_ones: u32,
}

pub(super) fn params(mode: u8) -> io::Result<Params> {
    let (source_bytes, mask_ones) = match mode {
        1 => (4, 16),
        2 => (5, 20),
        3 => (6, 24),
        4 => (7, 28),
        _ => return Err(invalid("invalid low entropy mode")),
    };
    Ok(Params {
        source_bytes,
        mask_ones,
    })
}

pub(super) fn valid_rotation(rotation: u8) -> bool {
    rotation <= 15 || rotation.is_multiple_of(16)
}

pub(super) fn encoded_len(extracted: usize, mode: u8) -> io::Result<usize> {
    let params = params(mode)?;
    if extracted == 0 {
        return Err(invalid("empty low entropy payload"));
    }
    let chunks = extracted.div_ceil(params.source_bytes);
    if chunks > usize::from(u16::MAX) / CHUNK {
        return Err(invalid("low entropy payload too long"));
    }
    Ok(chunks * CHUNK)
}

pub(super) fn max_fragment(mode: u8) -> usize {
    match params(mode) {
        Ok(params) => {
            (usize::from(u16::MAX) / CHUNK * params.source_bytes).min(super::meta::MAX_PDU)
        }
        Err(_) => super::meta::MAX_PDU,
    }
}

pub(super) fn new_half_mask(mode: u8) -> io::Result<u32> {
    let params = params(mode)?;
    let mut positions: Vec<u32> = (0..32).collect();
    positions.shuffle(&mut rand::rng());
    Ok(positions
        .iter()
        .take(params.mask_ones as usize)
        .fold(0u32, |mask, bit| mask | (1 << bit)))
}

fn chunk_mask(half: u32, rotation: u8, index: usize) -> u64 {
    let initial = (u64::from(half) << 32) | u64::from(half);
    if rotation == 0 || index == 0 {
        return initial;
    }
    let steps = u32::try_from(index % 64).unwrap_or(0);
    if rotation <= 15 {
        initial.rotate_right(steps * u32::from(rotation))
    } else {
        initial.rotate_left(steps * u32::from(rotation / 16))
    }
}

fn pdep(source: u64, mask: u64) -> u64 {
    let (mut out, mut bit, mut rest) = (0u64, 1u64, mask);
    while rest != 0 {
        let lowest = rest.isolate_lowest_one();
        if source & bit != 0 {
            out |= lowest;
        }
        bit <<= 1;
        rest &= rest - 1;
    }
    out
}

fn pext(source: u64, mask: u64) -> u64 {
    let (mut out, mut bit, mut rest) = (0u64, 1u64, mask);
    while rest != 0 {
        let lowest = rest.isolate_lowest_one();
        if source & lowest != 0 {
            out |= bit;
        }
        bit <<= 1;
        rest &= rest - 1;
    }
    out
}

fn low_bits(count: usize) -> u64 {
    if count >= 64 {
        u64::MAX
    } else {
        (1u64 << count) - 1
    }
}

fn check(mode: u8, half: u32, rotation: u8) -> io::Result<Params> {
    let params = params(mode)?;
    if half.count_ones() != params.mask_ones {
        return Err(invalid("low entropy mask population"));
    }
    if !valid_rotation(rotation) {
        return Err(invalid("invalid low entropy mask rotation"));
    }
    Ok(params)
}

pub(super) fn encode_low(
    source: &[u8],
    mode: u8,
    half: u32,
    rotation: u8,
    padding_bit: bool,
) -> io::Result<Vec<u8>> {
    let params = check(mode, half, rotation)?;
    let mut out = Vec::with_capacity(encoded_len(source.len(), mode)?);
    for (index, part) in source.chunks(params.source_bytes).enumerate() {
        let mut scratch = [0u8; CHUNK];
        if let Some(tail) = scratch.get_mut(CHUNK - part.len()..) {
            tail.copy_from_slice(part);
        }
        let mask = chunk_mask(half, rotation, index);
        let data_mask = pdep(low_bits(part.len() * 8), mask);
        let mut chunk = pdep(u64::from_be_bytes(scratch), mask);
        if padding_bit {
            chunk |= !data_mask;
        }
        out.extend_from_slice(&chunk.to_be_bytes());
    }
    Ok(out)
}

pub(super) fn decode_low(
    encoded: &[u8],
    extracted: usize,
    mode: u8,
    half: u32,
    rotation: u8,
) -> io::Result<Vec<u8>> {
    let params = check(mode, half, rotation)?;
    if encoded.len() != encoded_len(extracted, mode)? {
        return Err(invalid("low entropy payload length"));
    }
    let mut out = Vec::with_capacity(extracted);
    let mut padding_bit = false;
    for (index, raw) in encoded.as_chunks::<CHUNK>().0.iter().enumerate() {
        let part_len = params
            .source_bytes
            .min(extracted - index * params.source_bytes);
        let chunk = u64::from_be_bytes(*raw);
        let mask = chunk_mask(half, rotation, index);
        let padding_mask = !pdep(low_bits(part_len * 8), mask);
        let padding = chunk & padding_mask;
        if index == 0 {
            padding_bit = match padding {
                0 => false,
                p if p == padding_mask => true,
                _ => return Err(invalid("low entropy padding is mixed")),
            };
        } else if (!padding_bit && padding != 0) || (padding_bit && padding != padding_mask) {
            return Err(invalid("low entropy padding is not uniform"));
        }
        let scratch = pext(chunk, mask).to_be_bytes();
        out.extend_from_slice(scratch.get(CHUNK - part_len..).unwrap_or_default());
    }
    Ok(out)
}
