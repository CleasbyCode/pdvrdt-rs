use crate::common::span_has_range;
use crate::crypto::{chacha20_ietf_keystream, CHACHA20_IETF_NONCEBYTES};
use crate::encryption::{
    derive_carrier_keys_from_pin, derive_legacy_carrier_key_from_pin, has_pdvrdt_profile_markers,
    minimum_stream_cipher_size, CarrierKeys, CARRIER_CHACHA_KEY_BYTES, DEFAULT_OFFSETS,
};
use crate::image::{require_valid_png_decode, retain_pixel_decode_chunks};
use crate::pin_codec::RecoveryPin;
use anyhow::{anyhow, bail, Context, Result};
use std::io::Cursor;
use zeroize::{Zeroize, Zeroizing};

use crate::common::MAX_DECODE_BYTES;

// Carrier keying.
//
// Every sample position and whitening bit derives from a carrier key, so
// finding the known header under a candidate key confirms that an image carries
// a payload. Versions 4 and 3 key ChaCha20 with a 256-bit key from Argon2id:
// the Feistel round functions are tables of ChaCha20 output and the whitening
// bits are ChaCha20 keystream, so there is no cheaper way to test a key than
// the Argon2 derivation itself. The two differ only in that derivation (see
// derive_carrier_keys_from_pin): version 4, the only one conceal writes, comes
// from a 128-bit recovery KEY, version 3 from an old 64-bit PIN. Versions 1 and
// 2 used splitmix64 under a 64-bit key -- fast, but not a cryptographic
// function, so a direct search of that key space bypassed Argon2. Versions 1-3
// are retained only for recovery, version 1 with its cheap PIN hash.
//
// This protects *position*, not contents; the payload underneath is
// secretstream-encrypted under the Argon2id key either way.
const PERMUTATION_DOMAIN: u64 = 0x9f6abc142d337e51;
const HEADER_DOMAIN: u64 = 0x684452c3a109f5d7;
const PAYLOAD_DOMAIN: u64 = 0x5041594c4f414431;

const CARRIER_MAGIC: &[u8; 8] = b"PNGSTEG1";
const CARRIER_VERSION: u8 = 4;
const V3_CARRIER_VERSION: u8 = 3; // recovery only, old numeric PINs
const V2_CARRIER_VERSION: u8 = 2; // recovery only
const LEGACY_CARRIER_VERSION: u8 = 1; // recovery only
                                      // Scheme 2: KeyedPermutation uses the next power-of-two domain rather than the
                                      // next even-power one.
                                      //
                                      // Where the cover's sample count has an even bit length the permutation is
                                      // unchanged, so a scheme-1 image still decodes and is then rejected by
                                      // validate_carrier_header with a clear "unsupported carrier format". Where it is
                                      // odd every carrier position moves, the header does not decode at all, and the
                                      // image is indistinguishable from one holding no payload. Scheme 1 images from
                                      // odd-bit-length covers are therefore not recoverable by this build.
const CARRIER_SCHEME: u8 = 2;

const HEADER_COPIES: usize = 3;
const HEADER_SIZE: usize = 24;
const HEADER_BITS: usize = HEADER_SIZE * 8;
const HEADER_SLOTS: usize = HEADER_BITS * HEADER_COPIES;
// 15 carrier samples per 4-bit nibble, with at most one sample changed -- the
// F5/matrix-embedding reading of "(15,4)" (n samples, k bits), not the
// coding-theory (n,k) for the underlying Hamming code, which would be written
// (15,11). The syndrome is the XOR of the 1-based positions of the odd samples,
// so moving it to any target costs a single flip.
const GROUP_SAMPLES: usize = 15;

pub struct RedditPngCarrier {
    rgb: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub payload_capacity: usize,
}

#[derive(Clone, Copy)]
struct ChangeChoice {
    cost: f64,
    value: u8,
}

const fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

/// Version 3 keystreams: separate ChaCha20 (IETF, RFC 8439) streams under the
/// version-3 key, told apart by their 96-bit nonce, each starting at block 0.
#[derive(Clone, Copy)]
#[repr(u8)]
enum V3Stream {
    Permutation = 1,
    Header = 2,
    Payload = 3,
    TieBreak = 4,
}

fn chacha_keystream(
    key: &[u8; CARRIER_CHACHA_KEY_BYTES],
    stream: V3Stream,
    out: &mut [u8],
) -> Result<()> {
    let mut nonce = [0u8; CHACHA20_IETF_NONCEBYTES];
    nonce[..8].copy_from_slice(b"PDVRDTv3");
    nonce[8] = stream as u8;
    chacha20_ietf_keystream(key, &nonce, out)
        .map_err(|_| anyhow!("Internal Error: Reddit carrier keystream failed."))
}

/// Eight-round Feistel permutation over the smallest power-of-two domain
/// containing the sample count. Cycle walking restricts it to the exact RGB
/// sample range without allocating a carrier-index array.
///
/// The halves are allowed to differ in width by one bit, so the domain is always
/// the next power of two rather than the next *even* power. Rounding the bit
/// count up to an even number (scheme 1) doubled the domain again whenever that
/// count was odd, and cycle walking then ran ~4 iterations per lookup instead of
/// ~2 -- a cliff an image could fall off by being one pixel wider.
///
/// An odd bit count makes the halves unequal, so their widths swap on every
/// round: even rounds take the `right_bits`-wide half and produce a
/// `left_bits`-wide one, odd rounds the reverse. The round count is even, which
/// puts them back. The round is still invertible, so this remains a permutation
/// of the whole domain. Where the bit count is even the halves are equal and the
/// swap is a no-op.
///
/// The round function is the only difference between carrier versions:
/// splitmix64 under a 64-bit key for versions 1 and 2, a table of ChaCha20
/// output for 3.
struct KeyedPermutation {
    round_keys: [u64; KeyedPermutation::ROUNDS], // versions 1 and 2
    tables: Vec<u32>,                            // version 3
    table_stride: usize,
    size: u64,
    right_bits: u32,
    left_mask: u64,
    right_mask: u64,
}

impl KeyedPermutation {
    const ROUNDS: usize = 8;

    fn with_geometry(size: usize) -> Result<Self> {
        let size = u64::try_from(size)
            .map_err(|_| anyhow!("Internal Error: Reddit carrier sample domain is too large."))?;
        if size < 2 {
            bail!("Internal Error: Reddit carrier sample domain is too small.");
        }
        let bits = u64::BITS - (size - 1).leading_zeros();
        let left_bits = bits / 2;
        let right_bits = bits - left_bits;
        Ok(Self {
            round_keys: [0; Self::ROUNDS],
            tables: Vec::new(),
            table_stride: 0,
            size,
            right_bits,
            left_mask: (1u64 << left_bits) - 1,
            right_mask: (1u64 << right_bits) - 1,
        })
    }

    /// Versions 1 and 2. Round keys are derived once here: they depend only on
    /// the round index and the carrier key.
    fn new(size: usize, carrier_key: u64) -> Result<Self> {
        let mut permutation = Self::with_geometry(size)?;
        for (round, key) in permutation.round_keys.iter_mut().enumerate() {
            *key = splitmix64(
                carrier_key ^ PERMUTATION_DOMAIN ^ (round as u64).wrapping_mul(0x9e3779b97f4a7c15),
            );
        }
        Ok(permutation)
    }

    /// Version 3. Each round function is a table with one entry per possible
    /// input half, filled from ChaCha20. Round r's table occupies entries
    /// `[r * 2^right_bits, (r + 1) * 2^right_bits)` of one keystream, read as
    /// little-endian 32-bit words masked to the round's output width; odd
    /// rounds, whose input is only `left_bits` wide, use the first
    /// `2^left_bits` of theirs. At most 512 KiB, filled by one keystream call.
    fn new_v3(size: usize, key: &[u8; CARRIER_CHACHA_KEY_BYTES]) -> Result<Self> {
        let mut permutation = Self::with_geometry(size)?;
        let stride = 1usize << permutation.right_bits;
        let mut keystream = Zeroizing::new(vec![0u8; Self::ROUNDS * stride * 4]);
        chacha_keystream(key, V3Stream::Permutation, &mut keystream)?;
        permutation.table_stride = stride;
        permutation.tables = keystream
            .chunks_exact(4)
            .enumerate()
            .map(|(entry, word)| {
                let mask = permutation.round_mask(entry / stride) as u32;
                u32::from_le_bytes([word[0], word[1], word[2], word[3]]) & mask
            })
            .collect();
        Ok(permutation)
    }

    fn round_mask(&self, round: usize) -> u64 {
        if round.is_multiple_of(2) {
            self.left_mask
        } else {
            self.right_mask
        }
    }

    #[cfg(test)]
    fn map_one(&self, ordinal: usize) -> Result<usize> {
        let mut sample = [0usize; 1];
        self.map(ordinal, &mut sample)?;
        Ok(sample[0])
    }

    /// `out[i] = permutation(first + i)`. Batched because a single lookup is a
    /// chain of eight dependent rounds ended by an unpredictable cycle-walking
    /// branch, which serialises the pipeline: here the rounds run branch-free
    /// across a block, so independent lookups overlap, and only values still
    /// outside the domain go round again. Every value is exactly what a single
    /// lookup returns.
    fn map(&self, first: usize, out: &mut [usize]) -> Result<()> {
        let first = first as u64;
        if first > self.size || out.len() as u64 > self.size - first {
            bail!("Internal Error: Reddit carrier index is out of range.");
        }
        if self.tables.is_empty() {
            self.map_blocks::<false>(first, out);
        } else {
            self.map_blocks::<true>(first, out);
        }
        Ok(())
    }

    #[inline(always)]
    fn permute_power_of_two<const TABLES: bool>(&self, value: u64) -> u64 {
        // The round count is even, so the halves finish at the widths they
        // started with and the recombination below is the inverse of the split.
        const _: () = assert!(KeyedPermutation::ROUNDS.is_multiple_of(2));

        let mut left = value >> self.right_bits;
        let mut right = value & self.right_mask;
        for round in 0..Self::ROUNDS {
            let function = if TABLES {
                u64::from(self.tables[round * self.table_stride + right as usize])
            } else {
                splitmix64(right ^ self.round_keys[round])
            };
            let next_right = (left ^ function) & self.round_mask(round);
            left = right;
            right = next_right;
        }
        (left << self.right_bits) | right
    }

    fn map_blocks<const TABLES: bool>(&self, first: u64, out: &mut [usize]) {
        const BLOCK: usize = 64;
        let mut values = [0u64; BLOCK];
        let mut slots = [0usize; BLOCK];
        for (block_index, block) in out.chunks_mut(BLOCK).enumerate() {
            let base = first + (block_index * BLOCK) as u64;
            let mut pending = block.len();
            for i in 0..pending {
                values[i] = base + i as u64;
                slots[i] = i;
            }
            while pending != 0 {
                for value in &mut values[..pending] {
                    *value = self.permute_power_of_two::<TABLES>(*value);
                }
                // Branch-free compaction: every value is written to its slot,
                // and one still outside the domain is kept for another pass,
                // whose result then overwrites it.
                let mut kept = 0;
                for i in 0..pending {
                    let value = values[i];
                    block[slots[i]] = value as usize;
                    values[kept] = value;
                    slots[kept] = slots[i];
                    kept += usize::from(value >= self.size);
                }
                pending = kept;
            }
        }
    }
}

// The round keys and tables are as good as the carrier key: either locates the
// payload.
impl Drop for KeyedPermutation {
    fn drop(&mut self) {
        self.round_keys.zeroize();
        self.tables.zeroize();
    }
}

/// Header and payload whitening. Versions 1 and 2 compute each mask from the
/// 64-bit key with splitmix64; version 3 XORs the header with 24 keystream
/// bytes (bit i is bit 7 - i % 8 of byte i / 8) and each payload nibble with
/// the matching nibble of a keystream as long as the payload.
enum CarrierMasks {
    Splitmix(Zeroizing<u64>),
    ChaCha {
        key: Zeroizing<[u8; CARRIER_CHACHA_KEY_BYTES]>,
        header: Zeroizing<[u8; HEADER_SIZE]>,
        payload: Zeroizing<Vec<u8>>,
    },
}

impl CarrierMasks {
    fn new(key: u64) -> Self {
        Self::Splitmix(Zeroizing::new(key))
    }

    fn new_v3(key: &[u8; CARRIER_CHACHA_KEY_BYTES]) -> Result<Self> {
        let mut header = Zeroizing::new([0u8; HEADER_SIZE]);
        chacha_keystream(key, V3Stream::Header, &mut header[..])?;
        Ok(Self::ChaCha {
            key: Zeroizing::new(*key),
            header,
            payload: Zeroizing::new(Vec::new()),
        })
    }

    /// Version 3 sizes its payload keystream once the payload length is known.
    fn prepare_payload(&mut self, payload_size: usize) -> Result<()> {
        if let Self::ChaCha { key, payload, .. } = self {
            payload.resize(payload_size, 0);
            chacha_keystream(key, V3Stream::Payload, payload)?;
        }
        Ok(())
    }

    fn header(&self, bit_index: usize) -> usize {
        match self {
            Self::Splitmix(key) => {
                (splitmix64(
                    **key ^ HEADER_DOMAIN ^ (bit_index as u64).wrapping_mul(0x9e3779b97f4a7c15),
                ) & 1) as usize
            }
            Self::ChaCha { header, .. } => {
                usize::from((header[bit_index / 8] >> (7 - (bit_index % 8))) & 1)
            }
        }
    }

    fn payload(&self, group_index: usize) -> usize {
        match self {
            Self::Splitmix(key) => {
                (splitmix64(
                    **key ^ PAYLOAD_DOMAIN ^ (group_index as u64).wrapping_mul(0x9e3779b97f4a7c15),
                ) & 0x0f) as usize
            }
            Self::ChaCha { payload, .. } => {
                let mask = payload[group_index / 2];
                usize::from(if group_index & 1 == 0 {
                    mask >> 4
                } else {
                    mask & 0x0f
                })
            }
        }
    }
}

/// Conceal's tie-break between equally costly +1 and -1 changes. Recovery never
/// reads it, so it only needs to be unbiased; it is indexed by carrier ordinal,
/// the order samples are visited, so it is read sequentially rather than
/// missing cache on every tie as a per-sample table did.
struct TieBreakBits(Zeroizing<Vec<u8>>);

impl TieBreakBits {
    fn new(key: &[u8; CARRIER_CHACHA_KEY_BYTES], ordinals: usize) -> Result<Self> {
        let mut bits = Zeroizing::new(vec![0u8; ordinals.div_ceil(8)]);
        chacha_keystream(key, V3Stream::TieBreak, &mut bits)?;
        Ok(Self(bits))
    }

    fn take_higher(&self, ordinal: usize) -> bool {
        (self.0[ordinal / 8] >> (ordinal % 8)) & 1 != 0
    }
}

/// Hint the CPU to start fetching `index` while other work proceeds. A pure
/// performance hint with no memory effects: it cannot fault and cannot change
/// behaviour, so a target without the instruction simply does nothing.
#[inline(always)]
fn prefetch(bytes: &[u8], index: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        if index < bytes.len() {
            // SAFETY: `index` is in bounds, so the pointer is valid to form.
            // _mm_prefetch is a non-faulting hint that reads nothing.
            unsafe {
                std::arch::x86_64::_mm_prefetch::<{ std::arch::x86_64::_MM_HINT_T0 }>(
                    bytes.as_ptr().add(index) as *const i8,
                );
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (bytes, index);
    }
}

fn theoretical_capacity(rgb_samples: usize) -> usize {
    if rgb_samples <= HEADER_SLOTS {
        return 0;
    }
    let groups = (rgb_samples - HEADER_SLOTS) / GROUP_SAMPLES;
    groups / 2
}

fn make_header(payload: &[u8]) -> Result<[u8; HEADER_SIZE]> {
    let payload_size = u32::try_from(payload.len()).map_err(|_| {
        anyhow!("Data File Size Error: Reddit carrier payload exceeds its format limit.")
    })?;

    let mut header = [0u8; HEADER_SIZE];
    header[..CARRIER_MAGIC.len()].copy_from_slice(CARRIER_MAGIC);
    header[8] = CARRIER_VERSION;
    header[9] = CARRIER_SCHEME;
    header[10] = HEADER_COPIES as u8;
    header[11] = 0;
    header[12..16].copy_from_slice(&payload_size.to_le_bytes());
    header[16..20].copy_from_slice(&crc32fast::hash(payload).to_le_bytes());
    let header_crc = crc32fast::hash(&header[..20]);
    header[20..24].copy_from_slice(&header_crc.to_le_bytes());
    Ok(header)
}

fn header_bit(header: &[u8; HEADER_SIZE], bit_index: usize) -> usize {
    usize::from((header[bit_index / 8] >> (7 - (bit_index % 8))) & 1)
}

fn set_header_bit(header: &mut [u8; HEADER_SIZE], bit_index: usize, bit: usize) {
    let mask = 1u8 << (7 - (bit_index % 8));
    if bit != 0 {
        header[bit_index / 8] |= mask;
    } else {
        header[bit_index / 8] &= !mask;
    }
}

fn luminance(rgb: &[u8], pixel: usize) -> u32 {
    let offset = pixel * 3;
    (77 * u32::from(rgb[offset])
        + 150 * u32::from(rgb[offset + 1])
        + 29 * u32::from(rgb[offset + 2])
        + 128)
        >> 8
}

fn build_activity_map(carrier: &RedditPngCarrier) -> Result<Vec<u8>> {
    if carrier.width > i32::MAX as u32 || carrier.height > i32::MAX as u32 {
        bail!("Image Size Error: Reddit carrier dimensions are too large.");
    }
    let width = carrier.width as i32;
    let height = carrier.height as i32;
    let pixels = (carrier.width as usize)
        .checked_mul(carrier.height as usize)
        .ok_or_else(|| anyhow!("Image Size Error: Reddit carrier pixel count overflow."))?;
    let mut activity = Vec::new();
    activity
        .try_reserve_exact(pixels)
        .map_err(|_| anyhow!("Image Size Error: Unable to allocate Reddit activity map."))?;
    activity.resize(pixels, 0);

    // Each pixel's luminance is read by its own cell and by the eight around it,
    // so computing it on demand evaluated the same three multiplies nine times
    // over. One byte per pixel of scratch removes that: measured 155ms -> 99ms on
    // a 9-megapixel cover, with a bit-identical activity map.
    let mut luma = Vec::new();
    luma.try_reserve_exact(pixels)
        .map_err(|_| anyhow!("Image Size Error: Unable to allocate Reddit luminance plane."))?;
    luma.extend((0..pixels).map(|pixel| luminance(&carrier.rgb, pixel) as u8));

    let y_at = |x: i32, y: i32| -> i32 {
        let x = x.clamp(0, width - 1);
        let y = y.clamp(0, height - 1);
        let pixel = y as usize * width as usize + x as usize;
        i32::from(luma[pixel])
    };
    let directional_score = |center: i32, first: i32, second: i32| -> i32 {
        ((center - first).abs() + (center - second).abs() + (first - second).abs()) / 3
    };

    for y in 0..height {
        for x in 0..width {
            let center = y_at(x, y);
            let horizontal = directional_score(center, y_at(x - 1, y), y_at(x + 1, y));
            let vertical = directional_score(center, y_at(x, y - 1), y_at(x, y + 1));
            let diagonal_down = directional_score(center, y_at(x - 1, y - 1), y_at(x + 1, y + 1));
            let diagonal_up = directional_score(center, y_at(x + 1, y - 1), y_at(x - 1, y + 1));
            let least = horizontal
                .min(vertical)
                .min(diagonal_down)
                .min(diagonal_up)
                .min(255);
            activity[y as usize * width as usize + x as usize] = least as u8;
        }
    }
    Ok(activity)
}

fn smoothed_activity(activity: &[u8], width: u32, height: u32, pixel: usize) -> f64 {
    let width_i32 = width as i32;
    let height_i32 = height as i32;
    let x = (pixel % width as usize) as i32;
    let y = (pixel / width as usize) as i32;
    let mut total = 0u32;
    let mut count = 0u32;
    for dy in -1..=1 {
        let neighbor_y = (y + dy).clamp(0, height_i32 - 1);
        for dx in -1..=1 {
            let neighbor_x = (x + dx).clamp(0, width_i32 - 1);
            total +=
                u32::from(activity[neighbor_y as usize * width as usize + neighbor_x as usize]);
            count += 1;
        }
    }
    f64::from(total) / f64::from(count)
}

fn neighbor_difference(carrier: &RedditPngCarrier, sample: usize, candidate: u8) -> u32 {
    let pixel = sample / 3;
    let channel = sample % 3;
    let width = carrier.width as i32;
    let height = carrier.height as i32;
    let x = (pixel % carrier.width as usize) as i32;
    let y = (pixel / carrier.width as usize) as i32;
    let mut total = 0u32;
    for dy in -1..=1 {
        for dx in -1..=1 {
            if dx == 0 && dy == 0 {
                continue;
            }
            let neighbor_x = (x + dx).clamp(0, width - 1);
            let neighbor_y = (y + dy).clamp(0, height - 1);
            let neighbor_pixel = neighbor_y as usize * carrier.width as usize + neighbor_x as usize;
            let neighbor = carrier.rgb[neighbor_pixel * 3 + channel];
            total += (i32::from(candidate) - i32::from(neighbor)).unsigned_abs();
        }
    }
    total
}

fn choose_change(
    carrier: &RedditPngCarrier,
    activity: &[u8],
    tie_takes_higher: bool,
    sample: usize,
) -> ChangeChoice {
    let original = carrier.rgb[sample];
    let pixel = sample / 3;
    let channel = sample % 3;
    let local_activity = smoothed_activity(activity, carrier.width, carrier.height, pixel);
    const CHANNEL_WEIGHT: [f64; 3] = [1.05, 1.25, 0.90];
    let base_cost = (1.0 + 256.0 / (local_activity + 4.0)) * CHANNEL_WEIGHT[channel];

    let mut candidates = [0u8; 2];
    let mut candidate_count = 0usize;
    if original > 0 {
        candidates[candidate_count] = original - 1;
        candidate_count += 1;
    }
    if original < 255 {
        candidates[candidate_count] = original + 1;
        candidate_count += 1;
    }

    let mut best = ChangeChoice {
        cost: f64::INFINITY,
        value: original,
    };
    for &candidate in &candidates[..candidate_count] {
        let cost = base_cost + f64::from(neighbor_difference(carrier, sample, candidate)) / 512.0;
        if cost < best.cost || (cost == best.cost && tie_takes_higher) {
            best = ChangeChoice {
                cost,
                value: candidate,
            };
        }
    }
    best
}

fn embed_header(
    carrier: &mut RedditPngCarrier,
    activity: &[u8],
    permutation: &KeyedPermutation,
    masks: &CarrierMasks,
    ties: &TieBreakBits,
    header: &[u8; HEADER_SIZE],
) -> Result<()> {
    let mut samples = [0usize; HEADER_SLOTS];
    permutation.map(0, &mut samples)?;
    for bit in 0..HEADER_BITS {
        let target = header_bit(header, bit) ^ masks.header(bit);
        for copy in 0..HEADER_COPIES {
            let ordinal = bit * HEADER_COPIES + copy;
            let sample = samples[ordinal];
            if usize::from(carrier.rgb[sample] & 1) != target {
                carrier.rgb[sample] =
                    choose_change(carrier, activity, ties.take_higher(ordinal), sample).value;
            }
        }
    }
    Ok(())
}

/// Groups whose sample positions are resolved per batched permutation call.
const GROUPS_PER_BATCH: usize = 256;

fn prefetch_group(carrier: &RedditPngCarrier, activity: &[u8], samples: &[usize]) {
    let row_bytes = carrier.width as usize * 3;
    for &sample in samples {
        prefetch(&carrier.rgb, sample);
        if sample >= row_bytes {
            prefetch(&carrier.rgb, sample - row_bytes);
        }
        prefetch(&carrier.rgb, sample + row_bytes);
        prefetch(activity, sample / 3);
    }
}

fn embed_payload(
    carrier: &mut RedditPngCarrier,
    activity: &[u8],
    permutation: &KeyedPermutation,
    masks: &CarrierMasks,
    ties: &TieBreakBits,
    payload: &[u8],
) -> Result<()> {
    let nibble_count = payload
        .len()
        .checked_mul(2)
        .ok_or_else(|| anyhow!("Data File Size Error: Reddit payload size overflow."))?;

    // This loop is memory-bound, not arithmetic-bound. The permutation
    // deliberately scatters a group's 15 samples across the whole image, so on
    // any cover larger than cache each choose_change() below stalls on cold
    // lines. Positions are resolved a batch at a time, and the next group's
    // pixel neighbourhoods are prefetched while this one is costed, so those
    // misses overlap instead of serialising.
    //
    // Things tried here that did NOT help, so they are not worth re-attempting:
    // precomputing the 3x3 smoothed-activity map once per pixel rather than once
    // per channel, and deferring the 15 choose_change() calls until delta is
    // known to be non-zero. Both are output-preserving and both measured as no
    // change -- the arithmetic they remove is not the bottleneck.
    let mut positions = vec![0usize; nibble_count.min(GROUPS_PER_BATCH) * GROUP_SAMPLES];
    for batch_start in (0..nibble_count).step_by(GROUPS_PER_BATCH) {
        let batch_groups = GROUPS_PER_BATCH.min(nibble_count - batch_start);
        let batch = &mut positions[..batch_groups * GROUP_SAMPLES];
        permutation.map(HEADER_SLOTS + batch_start * GROUP_SAMPLES, batch)?;
        let batch = &*batch;
        prefetch_group(carrier, activity, &batch[..GROUP_SAMPLES]);

        for (in_batch, samples) in batch.chunks_exact(GROUP_SAMPLES).enumerate() {
            let group = batch_start + in_batch;
            let first_ordinal = HEADER_SLOTS + group * GROUP_SAMPLES;
            if let Some(next) =
                batch.get((in_batch + 1) * GROUP_SAMPLES..(in_batch + 2) * GROUP_SAMPLES)
            {
                prefetch_group(carrier, activity, next);
            }

            let mut choices = [ChangeChoice {
                cost: 0.0,
                value: 0,
            }; GROUP_SAMPLES];
            let mut syndrome = 0usize;
            for (position, (&sample, choice)) in samples.iter().zip(choices.iter_mut()).enumerate()
            {
                if carrier.rgb[sample] & 1 != 0 {
                    syndrome ^= position + 1;
                }
                *choice = choose_change(
                    carrier,
                    activity,
                    ties.take_higher(first_ordinal + position),
                    sample,
                );
            }

            let nibble = if group & 1 == 0 {
                usize::from(payload[group / 2] >> 4)
            } else {
                usize::from(payload[group / 2] & 0x0f)
            };
            let delta = syndrome ^ nibble ^ masks.payload(group);
            if delta == 0 {
                continue;
            }

            let single = delta - 1;
            let mut best_cost = choices[single].cost;
            let mut first = single;
            let mut second = GROUP_SAMPLES;

            for first_index in 1usize..=15 {
                let second_index = first_index ^ delta;
                if !(1..=15).contains(&second_index) || first_index >= second_index {
                    continue;
                }
                let pair_cost = choices[first_index - 1].cost + choices[second_index - 1].cost;
                if pair_cost < best_cost {
                    best_cost = pair_cost;
                    first = first_index - 1;
                    second = second_index - 1;
                }
            }

            carrier.rgb[samples[first]] = choices[first].value;
            if second != GROUP_SAMPLES {
                carrier.rgb[samples[second]] = choices[second].value;
            }
        }
    }
    Ok(())
}

fn extract_header(
    carrier: &RedditPngCarrier,
    permutation: &KeyedPermutation,
    masks: &CarrierMasks,
) -> Result<[u8; HEADER_SIZE]> {
    let mut samples = [0usize; HEADER_SLOTS];
    permutation.map(0, &mut samples)?;
    let mut header = [0u8; HEADER_SIZE];
    for bit in 0..HEADER_BITS {
        let ones: usize = samples[bit * HEADER_COPIES..(bit + 1) * HEADER_COPIES]
            .iter()
            .map(|&sample| usize::from(carrier.rgb[sample] & 1))
            .sum();
        let whitened = usize::from(ones > HEADER_COPIES / 2);
        set_header_bit(&mut header, bit, whitened ^ masks.header(bit));
    }
    Ok(header)
}

fn read_le_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes(data.try_into().expect("four-byte Reddit header field"))
}

fn validate_carrier_header(
    header: &[u8; HEADER_SIZE],
    payload_capacity: usize,
    expected_version: u8,
) -> Result<()> {
    const CORRUPT_HEADER: &str = "File Recovery Error: Reddit carrier header is corrupt.";
    if header[8] != expected_version
        || header[9] != CARRIER_SCHEME
        || header[10] != HEADER_COPIES as u8
        || header[11] != 0
    {
        bail!("File Recovery Error: Unsupported Reddit carrier format.");
    }

    let expected_crc = read_le_u32(&header[20..24]);
    let actual_crc = crc32fast::hash(&header[..20]);
    // A zero-length payload is never produced (embed_reddit_png_payload refuses
    // an empty one), so reject it here rather than leaving it to be caught
    // further downstream by the profile check: crc32 of nothing is a value an
    // attacker can put in the header, and this is the cheapest place to say no.
    let declared_size = read_le_u32(&header[12..16]) as usize;
    if expected_crc != actual_crc || declared_size == 0 || declared_size > payload_capacity {
        bail!("{}", CORRUPT_HEADER);
    }
    Ok(())
}

fn extract_payload(
    carrier: &RedditPngCarrier,
    permutation: &KeyedPermutation,
    masks: &CarrierMasks,
    payload_size: usize,
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_size)
        .map_err(|_| anyhow!("File Recovery Error: Unable to allocate Reddit payload."))?;
    payload.resize(payload_size, 0);
    let nibble_count = payload_size
        .checked_mul(2)
        .ok_or_else(|| anyhow!("File Recovery Error: Reddit payload size overflow."))?;

    let mut positions = vec![0usize; nibble_count.min(GROUPS_PER_BATCH) * GROUP_SAMPLES];
    for batch_start in (0..nibble_count).step_by(GROUPS_PER_BATCH) {
        let batch_groups = GROUPS_PER_BATCH.min(nibble_count - batch_start);
        let batch = &mut positions[..batch_groups * GROUP_SAMPLES];
        permutation.map(HEADER_SLOTS + batch_start * GROUP_SAMPLES, batch)?;
        // Every read below is a cache miss on a large cover; issuing them all
        // first lets them overlap.
        for &sample in batch.iter() {
            prefetch(&carrier.rgb, sample);
        }

        for (in_batch, samples) in batch.chunks_exact(GROUP_SAMPLES).enumerate() {
            let group = batch_start + in_batch;
            let syndrome = samples
                .iter()
                .enumerate()
                .filter(|&(_, &sample)| carrier.rgb[sample] & 1 != 0)
                .fold(0usize, |syndrome, (position, _)| syndrome ^ (position + 1));

            let nibble = syndrome ^ masks.payload(group);
            if group & 1 == 0 {
                payload[group / 2] = (nibble << 4) as u8;
            } else {
                payload[group / 2] |= nibble as u8;
            }
        }
    }
    Ok(payload)
}

fn is_pdvrdt_reddit_profile(profile: &[u8]) -> Result<bool> {
    if !has_pdvrdt_profile_markers(profile, &DEFAULT_OFFSETS) {
        return Ok(false);
    }
    if !span_has_range(
        profile,
        DEFAULT_OFFSETS.encrypted_file,
        minimum_stream_cipher_size(),
    ) {
        bail!("File Recovery Error: Reddit embedded pdvrdt profile is truncated.");
    }
    Ok(true)
}

fn encode_rgb_png(carrier: &RedditPngCarrier) -> Result<Vec<u8>> {
    let expected_size = (carrier.width as usize)
        .checked_mul(carrier.height as usize)
        .and_then(|pixels| pixels.checked_mul(3))
        .ok_or_else(|| anyhow!("Image Size Error: Reddit RGB buffer size overflow."))?;
    if carrier.rgb.len() != expected_size {
        bail!("Image Encode Error: Reddit carrier has an unexpected RGB buffer size.");
    }

    let mut encoded = Vec::new();
    {
        let mut encoder =
            png::Encoder::new(Cursor::new(&mut encoded), carrier.width, carrier.height);
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().context("PNG Reddit encode error")?;
        writer
            .write_image_data(&carrier.rgb)
            .context("PNG Reddit encode error")?;
        writer.finish().context("PNG Reddit encode error")?;
    }
    Ok(encoded)
}

struct DecodedCarrier {
    carrier: RedditPngCarrier,
    fully_opaque: bool,
}

fn decode_carrier(png_bytes: &[u8]) -> Result<DecodedCarrier> {
    require_valid_png_decode(png_bytes)?;
    let mut decoder = png::Decoder::new(Cursor::new(png_bytes));
    decoder.set_limits(png::Limits {
        bytes: MAX_DECODE_BYTES,
    });
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().context("PNG Reddit decode error")?;
    let output_size = reader.output_buffer_size();
    if output_size > MAX_DECODE_BYTES {
        bail!("PNG Error: Decoded image exceeds safety limit.");
    }

    let mut decoded_pixels = Vec::new();
    decoded_pixels
        .try_reserve_exact(output_size)
        .map_err(|_| anyhow!("PNG Error: Unable to allocate decoded Reddit image."))?;
    decoded_pixels.resize(output_size, 0);
    let info = reader
        .next_frame(&mut decoded_pixels)
        .context("PNG Reddit decode error")?;
    decoded_pixels.truncate(info.buffer_size());
    if info.bit_depth != png::BitDepth::Eight {
        bail!("Image Decode Error: Reddit carrier did not decode to 8-bit samples.");
    }

    let pixels = (info.width as usize)
        .checked_mul(info.height as usize)
        .ok_or_else(|| anyhow!("Image Size Error: Reddit carrier pixel count overflow."))?;
    let rgba_limit = pixels
        .checked_mul(4)
        .ok_or_else(|| anyhow!("Image Size Error: Reddit RGBA buffer size overflow."))?;
    if rgba_limit > MAX_DECODE_BYTES {
        bail!("PNG Error: Decoded image exceeds safety limit.");
    }
    let rgb_size = pixels
        .checked_mul(3)
        .ok_or_else(|| anyhow!("Image Size Error: Reddit RGB buffer size overflow."))?;
    let mut rgb = Vec::new();
    rgb.try_reserve_exact(rgb_size)
        .map_err(|_| anyhow!("PNG Error: Unable to allocate Reddit RGB image."))?;
    let mut fully_opaque = true;

    match info.color_type {
        png::ColorType::Grayscale => {
            if decoded_pixels.len() != pixels {
                bail!(
                    "Image Decode Error: Reddit carrier has an unexpected grayscale buffer size."
                );
            }
            for value in decoded_pixels {
                rgb.extend_from_slice(&[value, value, value]);
            }
        }
        png::ColorType::GrayscaleAlpha => {
            if decoded_pixels.len() != pixels * 2 {
                bail!("Image Decode Error: Reddit carrier has an unexpected grayscale-alpha buffer size.");
            }
            for sample in decoded_pixels.chunks_exact(2) {
                rgb.extend_from_slice(&[sample[0], sample[0], sample[0]]);
                fully_opaque &= sample[1] == 255;
            }
        }
        png::ColorType::Rgb => {
            if decoded_pixels.len() != rgb_size {
                bail!("Image Decode Error: Reddit carrier has an unexpected RGB buffer size.");
            }
            rgb = decoded_pixels;
        }
        png::ColorType::Rgba => {
            if decoded_pixels.len() != rgba_limit {
                bail!("Image Decode Error: Reddit carrier has an unexpected RGBA buffer size.");
            }
            for sample in decoded_pixels.chunks_exact(4) {
                rgb.extend_from_slice(&sample[..3]);
                fully_opaque &= sample[3] == 255;
            }
        }
        png::ColorType::Indexed => {
            bail!("Image Decode Error: Reddit indexed carrier was not expanded to RGB.");
        }
    }

    let payload_capacity = theoretical_capacity(rgb.len());
    Ok(DecodedCarrier {
        carrier: RedditPngCarrier {
            rgb,
            width: info.width,
            height: info.height,
            payload_capacity,
        },
        fully_opaque,
    })
}

pub fn prepare_reddit_png_carrier(png_bytes: &[u8]) -> Result<RedditPngCarrier> {
    let decoded = decode_carrier(png_bytes)?;
    if !decoded.fully_opaque {
        bail!("Image Format Error: Reddit cover contains transparency; flatten it first.");
    }
    Ok(decoded.carrier)
}

/// Embed with carrier version 4, keyed by `carrier_keys.chacha` from
/// `derive_carrier_keys_from_pin` on a 128-bit KEY, which uses Argon2id.
pub fn embed_reddit_png_payload(
    carrier: &mut RedditPngCarrier,
    carrier_keys: &CarrierKeys,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.is_empty() {
        bail!("Data File Size Error: Reddit carrier payload is empty.");
    }
    if payload.len() > carrier.payload_capacity {
        bail!("Data File Size Error: Encrypted Reddit payload exceeds the cover image's theoretical adaptive capacity.");
    }

    // Conceal only ever holds a 128-bit KEY, whose keys are version 4's.
    if carrier_keys.chacha_version != CARRIER_VERSION {
        bail!("Internal Error: Reddit carrier key is not a version-4 key.");
    }
    let header = make_header(payload)?;
    let permutation = KeyedPermutation::new_v3(carrier.rgb.len(), &carrier_keys.chacha)?;
    let mut masks = CarrierMasks::new_v3(&carrier_keys.chacha)?;
    masks.prepare_payload(payload.len())?;
    let ties = TieBreakBits::new(
        &carrier_keys.chacha,
        HEADER_SLOTS + payload.len() * 2 * GROUP_SAMPLES,
    )?;
    let activity = build_activity_map(carrier)?;
    embed_header(carrier, &activity, &permutation, &masks, &ties, &header)?;
    embed_payload(carrier, &activity, &permutation, &masks, &ties, payload)?;
    encode_rgb_png(carrier)
}

// Only absent magic permits another key/version attempt. A recognized header
// with a bad version, length or CRC is an error. Return the raw payload so a
// generic PNGSTEG1 carrier also ends the search before the pdvrdt profile check.
fn try_extract_payload(
    carrier: &RedditPngCarrier,
    permutation: &KeyedPermutation,
    masks: &mut CarrierMasks,
    expected_version: u8,
) -> Result<Option<Vec<u8>>> {
    let header = extract_header(carrier, permutation, masks)?;
    if &header[..CARRIER_MAGIC.len()] != CARRIER_MAGIC {
        return Ok(None);
    }

    validate_carrier_header(&header, carrier.payload_capacity, expected_version)?;
    let payload_size = read_le_u32(&header[12..16]) as usize;
    masks.prepare_payload(payload_size)?;
    let payload = extract_payload(carrier, permutation, masks, payload_size)?;
    let expected_crc = read_le_u32(&header[16..20]);
    if expected_crc != crc32fast::hash(&payload) {
        bail!("File Recovery Error: Reddit embedded data is corrupt.");
    }
    Ok(Some(payload))
}

/// Versions 1 and 2 share the splitmix64 construction under a 64-bit key.
fn try_extract_payload_with_key(
    carrier: &RedditPngCarrier,
    carrier_key: u64,
    expected_version: u8,
) -> Result<Option<Vec<u8>>> {
    let permutation = KeyedPermutation::new(carrier.rgb.len(), carrier_key)?;
    let mut masks = CarrierMasks::new(carrier_key);
    try_extract_payload(carrier, &permutation, &mut masks, expected_version)
}

fn try_extract_payload_with_v3_key(
    carrier: &RedditPngCarrier,
    carrier_key: &[u8; CARRIER_CHACHA_KEY_BYTES],
    expected_version: u8,
) -> Result<Option<Vec<u8>>> {
    let permutation = KeyedPermutation::new_v3(carrier.rgb.len(), carrier_key)?;
    let mut masks = CarrierMasks::new_v3(carrier_key)?;
    try_extract_payload(carrier, &permutation, &mut masks, expected_version)
}

/// Decode an untrusted image for carrier recovery. Needs no secret, so recover
/// runs it before asking for the KEY/PIN: `None` for an image that cannot hold a
/// carrier (transparency, too few samples); decode failures are errors.
pub fn decode_reddit_recovery_carrier(png_bytes: &mut Vec<u8>) -> Result<Option<RedditPngCarrier>> {
    // The decoder buffers every non-IDAT chunk it meets, so everything it would
    // skip anyway is dropped first, in place. decode_carrier() then runs the
    // geometry and IDAT preflight on what is left.
    retain_pixel_decode_chunks(png_bytes)?;
    let decoded = decode_carrier(png_bytes)?;
    if !decoded.fully_opaque || decoded.carrier.rgb.len() <= HEADER_SLOTS {
        return Ok(None);
    }
    Ok(Some(decoded.carrier))
}

/// Returns `None` for a carrier that does not decode under `recovery_pin`, or a
/// CRC-valid generic PNGSTEG1 carrier that is not a pdvrdt profile. A 128-bit
/// KEY tries only version 4. An old numeric PIN tries versions 3, 2 and 1 in
/// that order. Each key accepts only its own version.
pub fn extract_reddit_png_payload(
    carrier: &RedditPngCarrier,
    recovery_pin: &RecoveryPin,
) -> Result<Option<Vec<u8>>> {
    // Argon2 errors propagate before considering the recovery-only legacy key.
    // A KEY derives only the version-4 key. One Argon2 run on an old PIN
    // yields the version-3 and version-2 keys; only version 1 needs another,
    // cheap, derivation.
    let mut carrier_keys = CarrierKeys::default();
    derive_carrier_keys_from_pin(recovery_pin, &mut carrier_keys)?;
    let chacha_version = if recovery_pin.is_key() {
        CARRIER_VERSION
    } else {
        V3_CARRIER_VERSION
    };
    if carrier_keys.chacha_version != chacha_version {
        bail!("Internal Error: Reddit carrier key version mismatch.");
    }
    let mut payload =
        try_extract_payload_with_v3_key(carrier, &carrier_keys.chacha, chacha_version)?;
    if payload.is_none() && carrier_keys.has_v2 {
        payload = try_extract_payload_with_key(carrier, *carrier_keys.v2, V2_CARRIER_VERSION)?;
    }
    if payload.is_none() && !recovery_pin.is_key() {
        let mut legacy_key = Zeroizing::new(0u64);
        derive_legacy_carrier_key_from_pin(recovery_pin, &mut legacy_key)?;
        payload = try_extract_payload_with_key(carrier, *legacy_key, LEGACY_CARRIER_VERSION)?;
    }
    let Some(payload) = payload else {
        return Ok(None);
    };
    if !is_pdvrdt_reddit_profile(&payload)? {
        return Ok(None);
    }
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{
        KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_SENTINEL, KDF_SENTINEL_OFFSET, PDVRDT_SIG,
    };

    const KEY: &str = "112d-rXXU-ifSr-RnXL-GbXg-8Eyf";
    const OTHER_KEY: &str = "YcVf-xkQb-6JRz-qk5k-F2tN-Lvdj";

    fn key_pin(text: &str) -> RecoveryPin {
        let mut pin = RecoveryPin::default();
        crate::pin_codec::parse_recovery_pin_text(text.as_bytes(), &mut pin).unwrap();
        assert!(pin.is_key());
        pin
    }

    fn old_pin(value: u64) -> RecoveryPin {
        let mut pin = RecoveryPin::default();
        pin.set_legacy(value);
        pin
    }

    fn keys(pin: &RecoveryPin) -> CarrierKeys {
        let mut keys = CarrierKeys::default();
        derive_carrier_keys_from_pin(pin, &mut keys).unwrap();
        keys
    }

    fn legacy_key(pin: &RecoveryPin) -> u64 {
        let mut key = Zeroizing::new(0u64);
        derive_legacy_carrier_key_from_pin(pin, &mut key).unwrap();
        *key
    }

    fn recover_payload(encoded: &[u8], pin: &RecoveryPin) -> Result<Option<Vec<u8>>> {
        match decode_reddit_recovery_carrier(&mut encoded.to_vec())? {
            Some(carrier) => extract_reddit_png_payload(&carrier, pin),
            None => Ok(None),
        }
    }

    fn test_profile() -> Vec<u8> {
        let mut profile = vec![0u8; DEFAULT_OFFSETS.encrypted_file + minimum_stream_cipher_size()];
        let kdf = DEFAULT_OFFSETS.kdf_metadata;
        profile[kdf..kdf + 4].copy_from_slice(b"KDF3");
        profile[kdf + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
        profile[kdf + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;
        let sig = DEFAULT_OFFSETS.pdv_signature;
        profile[sig..sig + PDVRDT_SIG.len()].copy_from_slice(PDVRDT_SIG);
        profile
    }

    #[test]
    fn theoretical_capacity_matches_reference_values() {
        assert_eq!(theoretical_capacity(1024 * 1024 * 3), 104_838);
        assert_eq!(theoretical_capacity(4096 * 4096 * 3), 1_677_702);
    }

    fn test_carrier(width: u32, height: u32) -> RedditPngCarrier {
        let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
        for y in 0..height {
            for x in 0..width {
                rgb.extend_from_slice(&[
                    (x.wrapping_mul(3).wrapping_add(y) & 0xff) as u8,
                    (y.wrapping_mul(5).wrapping_add(x) & 0xff) as u8,
                    (x.wrapping_add(y.wrapping_mul(2)) & 0xff) as u8,
                ]);
            }
        }
        RedditPngCarrier {
            payload_capacity: theoretical_capacity(rgb.len()),
            rgb,
            width,
            height,
        }
    }

    /// Any version's key, so tests can build deliberately mismatched
    /// key/version pairs; conceal itself writes only version 4.
    #[derive(Clone, Copy)]
    enum TestKey {
        Splitmix(u64),
        ChaCha([u8; CARRIER_CHACHA_KEY_BYTES]),
    }

    impl TestKey {
        fn parts(self, samples: usize) -> (KeyedPermutation, CarrierMasks) {
            match self {
                Self::Splitmix(key) => (
                    KeyedPermutation::new(samples, key).unwrap(),
                    CarrierMasks::new(key),
                ),
                Self::ChaCha(key) => (
                    KeyedPermutation::new_v3(samples, &key).unwrap(),
                    CarrierMasks::new_v3(&key).unwrap(),
                ),
            }
        }
    }

    // Tie-breaks only choose between equally costly changes, never what
    // decodes, so test embeds under any key can share one fixed stream.
    fn test_ties(ordinals: usize) -> TieBreakBits {
        TieBreakBits::new(&[0u8; CARRIER_CHACHA_KEY_BYTES], ordinals).unwrap()
    }

    fn embed_under(
        carrier: &mut RedditPngCarrier,
        key: TestKey,
        header: &[u8; HEADER_SIZE],
        payload: &[u8],
    ) {
        let (permutation, mut masks) = key.parts(carrier.rgb.len());
        masks.prepare_payload(payload.len()).unwrap();
        let ties = test_ties(HEADER_SLOTS + payload.len() * 2 * GROUP_SAMPLES);
        let activity = build_activity_map(carrier).unwrap();
        embed_header(carrier, &activity, &permutation, &masks, &ties, header).unwrap();
        if !payload.is_empty() {
            embed_payload(carrier, &activity, &permutation, &masks, &ties, payload).unwrap();
        }
    }

    fn header_under(carrier: &RedditPngCarrier, key: TestKey) -> [u8; HEADER_SIZE] {
        let (permutation, masks) = key.parts(carrier.rgb.len());
        extract_header(carrier, &permutation, &masks).unwrap()
    }

    fn header_with_version(payload: &[u8], version: u8) -> [u8; HEADER_SIZE] {
        let mut header = make_header(payload).unwrap();
        header[8] = version;
        let crc = crc32fast::hash(&header[..20]);
        header[20..24].copy_from_slice(&crc.to_le_bytes());
        header
    }

    fn png_under(key: TestKey, payload: &[u8], version: u8) -> Vec<u8> {
        let mut carrier = test_carrier(64, 64);
        embed_under(
            &mut carrier,
            key,
            &header_with_version(payload, version),
            payload,
        );
        encode_rgb_png(&carrier).unwrap()
    }

    #[test]
    fn carrier_v4_roundtrip_preserves_profile_and_rejects_wrong_secrets() {
        let pin = key_pin(KEY);
        let keys = keys(&pin);
        assert!(keys.chacha_version == 4 && !keys.has_v2);
        let old = old_pin(1);
        let old_keys = keys_for_old(&old);
        let profile = test_profile();
        for (width, height, parity) in [(64, 64, 0), (64, 96, 1)] {
            let mut carrier = test_carrier(width, height);
            assert_eq!(
                (usize::BITS - (carrier.rgb.len() - 1).leading_zeros()) % 2,
                parity
            );
            let encoded = embed_reddit_png_payload(&mut carrier, &keys, &profile).unwrap();
            let header = header_under(&carrier, TestKey::ChaCha(*keys.chacha));
            assert_eq!((header[8], header[9]), (CARRIER_VERSION, 2));
            assert_eq!(
                recover_payload(&encoded, &pin).unwrap(),
                Some(profile.clone())
            );
            // A v4 carrier must reveal nothing under an old PIN's keys.
            assert!(
                try_extract_payload_with_key(&carrier, *old_keys.v2, V2_CARRIER_VERSION)
                    .unwrap()
                    .is_none()
            );
            assert!(try_extract_payload_with_key(
                &carrier,
                legacy_key(&old),
                LEGACY_CARRIER_VERSION
            )
            .unwrap()
            .is_none());
            assert!(recover_payload(&encoded, &key_pin(OTHER_KEY))
                .unwrap()
                .is_none());
            assert!(recover_payload(&encoded, &old).unwrap().is_none());
        }
        // Conceal refuses an old PIN's version-3 key.
        let mut carrier = test_carrier(64, 64);
        assert!(embed_reddit_png_payload(&mut carrier, &old_keys, &profile).is_err());
    }

    fn keys_for_old(pin: &RecoveryPin) -> CarrierKeys {
        let keys = keys(pin);
        assert!(keys.chacha_version == 3 && keys.has_v2);
        keys
    }

    #[test]
    fn older_carrier_versions_still_recover() {
        let pin = old_pin(0x8000_0000_0000_0000);
        let keys = keys_for_old(&pin);
        let profile = test_profile();
        for (key, version) in [
            (TestKey::ChaCha(*keys.chacha), V3_CARRIER_VERSION),
            (TestKey::Splitmix(*keys.v2), V2_CARRIER_VERSION),
            (TestKey::Splitmix(legacy_key(&pin)), LEGACY_CARRIER_VERSION),
        ] {
            assert_eq!(
                recover_payload(&png_under(key, &profile, version), &pin).unwrap(),
                Some(profile.clone())
            );
        }
    }

    #[test]
    fn carrier_versions_are_bound_to_their_keys() {
        let profile = test_profile();
        let key = key_pin(KEY);
        let v4 = TestKey::ChaCha(*keys(&key).chacha);
        for wrong_version in [3, 2, 1] {
            let error = recover_payload(&png_under(v4, &profile, wrong_version), &key).unwrap_err();
            assert!(error
                .to_string()
                .contains("Unsupported Reddit carrier format"));
        }
        let old = old_pin(1);
        let old_keys = keys_for_old(&old);
        let v3 = TestKey::ChaCha(*old_keys.chacha);
        let v2 = TestKey::Splitmix(*old_keys.v2);
        let v1 = TestKey::Splitmix(legacy_key(&old));
        for (key, wrong_version) in [
            (v3, 4),
            (v3, 2),
            (v3, 1),
            (v2, 3),
            (v2, 1),
            (v1, 4),
            (v1, 3),
            (v1, 2),
        ] {
            let error =
                recover_payload(&png_under(key, &profile, wrong_version), &old).unwrap_err();
            assert!(error
                .to_string()
                .contains("Unsupported Reddit carrier format"));
        }
    }

    #[test]
    fn recognized_current_carrier_corruption_does_not_fall_back() {
        let pin = key_pin(KEY);
        let keys = keys(&pin);
        let key = TestKey::ChaCha(*keys.chacha);
        let profile = test_profile();
        for corrupt_header in [true, false] {
            let mut carrier = test_carrier(64, 64);
            embed_reddit_png_payload(&mut carrier, &keys, &profile).unwrap();
            let expected_error = if corrupt_header {
                let mut header = header_under(&carrier, key);
                header[20] ^= 1;
                embed_under(&mut carrier, key, &header, &[]);
                "Reddit carrier header is corrupt"
            } else {
                let (permutation, _) = key.parts(carrier.rgb.len());
                carrier.rgb[permutation.map_one(HEADER_SLOTS).unwrap()] ^= 1;
                "Reddit embedded data is corrupt"
            };
            let encoded = encode_rgb_png(&carrier).unwrap();
            let error = recover_payload(&encoded, &pin).unwrap_err();
            assert!(error.to_string().contains(expected_error));
        }
    }

    #[test]
    fn generic_carrier_is_not_exposed_as_a_pdvrdt_profile() {
        let pin = key_pin(KEY);
        let keys = keys(&pin);
        let mut carrier = test_carrier(64, 64);
        let encoded = embed_reddit_png_payload(&mut carrier, &keys, b"generic carrier").unwrap();
        assert_eq!(
            try_extract_payload_with_v3_key(&carrier, &keys.chacha, CARRIER_VERSION).unwrap(),
            Some(b"generic carrier".to_vec())
        );
        assert!(recover_payload(&encoded, &pin).unwrap().is_none());
    }

    /// The original single-lookup Feistel, kept verbatim as the reference that
    /// the batched `map` must reproduce exactly: versions 1 and 2 are
    /// recovery-only, so any change to their positions would orphan images.
    fn reference_permutation(size: u64, key: u64, ordinal: u64) -> u64 {
        let mut round_keys = [0u64; 8];
        for (round, round_key) in round_keys.iter_mut().enumerate() {
            *round_key = splitmix64(
                key ^ PERMUTATION_DOMAIN ^ (round as u64).wrapping_mul(0x9e3779b97f4a7c15),
            );
        }
        let bits = u64::BITS - (size - 1).leading_zeros();
        let mask_for = |bits: u32| (1u64 << bits) - 1;
        let mut value = ordinal;
        loop {
            let (mut left_bits, mut right_bits) = (bits / 2, bits - bits / 2);
            let mut left = value >> right_bits;
            let mut right = value & mask_for(right_bits);
            for &round_key in &round_keys {
                let function = splitmix64(right ^ round_key);
                let next_right = (left ^ function) & mask_for(left_bits);
                left = right;
                right = next_right;
                std::mem::swap(&mut left_bits, &mut right_bits);
            }
            value = (left << right_bits) | right;
            if value < size {
                return value;
            }
        }
    }

    #[test]
    fn batched_permutation_matches_original_and_v3_is_a_bijection() {
        for size in [2usize, 3, 577, 4096, 4097, 12288, 1_000_003] {
            let key = 0x0123_4567_89ab_cdef ^ size as u64;
            let permutation = KeyedPermutation::new(size, key).unwrap();
            let count = size.min(5000);
            let first = size - count;
            let mut batch = vec![0usize; count];
            permutation.map(first, &mut batch).unwrap();
            for (i, &sample) in batch.iter().enumerate() {
                assert_eq!(
                    sample as u64,
                    reference_permutation(size as u64, key, (first + i) as u64)
                );
            }

            let mut v3_key = [0u8; CARRIER_CHACHA_KEY_BYTES];
            v3_key[0] = size as u8;
            v3_key[1] = 7;
            let v3 = KeyedPermutation::new_v3(size, &v3_key).unwrap();
            let mut all = vec![0usize; size];
            v3.map(0, &mut all).unwrap();
            let mut hit = vec![false; size];
            for sample in all {
                assert!(sample < size && !hit[sample]);
                hit[sample] = true;
            }
        }
    }
}
