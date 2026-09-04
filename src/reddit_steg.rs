use crate::common::span_has_range;
use crate::encryption::{has_pdvrdt_profile_markers, minimum_stream_cipher_size, DEFAULT_OFFSETS};
use crate::image::require_geometry_within_decode_limit;
use anyhow::{anyhow, bail, Context, Result};
use std::io::Cursor;

use crate::common::MAX_DECODE_BYTES;

// Carrier keying.
//
// Every sample position and every whitening bit derives from a `carrier_key`
// supplied by the caller, which since v5 is a cheap hash of the recovery PIN
// (see derive_carrier_key_from_pin). Before v5 this was a hard-coded constant,
// with the consequence that anyone holding the source could recompute the 576
// header sample positions, undo the whitening and test any image for the
// PNGSTEG1 magic in a few hundred LSB reads -- the carrier was locatable
// without the PIN.
//
// Keying it from the PIN removes that: without the PIN the positions are
// unknown, so "does this image carry a payload?" stops being answerable by
// anyone but the holder.
//
// This protects *position*, not contents; the payload underneath is
// secretstream-encrypted under the Argon2id key either way.
const PERMUTATION_DOMAIN: u64 = 0x9f6abc142d337e51;
const HEADER_DOMAIN: u64 = 0x684452c3a109f5d7;
const PAYLOAD_DOMAIN: u64 = 0x5041594c4f414431;
const DIRECTION_DOMAIN: u64 = 0x444952454354494f;

const CARRIER_MAGIC: &[u8; 8] = b"PNGSTEG1";
const CARRIER_VERSION: u8 = 1;
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

/// Eight-round Feistel permutation over the smallest power-of-two domain
/// containing the sample count. Cycle walking restricts it to the exact RGB
/// sample range without allocating a carrier-index array.
///
/// The halves are allowed to differ in width by one bit, so the domain is always
/// the next power of two rather than the next *even* power. Rounding the bit
/// count up to an even number (scheme 1) doubled the domain again whenever that
/// count was odd, and cycle walking then ran ~4 iterations per lookup instead of
/// ~2 -- a cliff an image could fall off by being one pixel wider. Measured on a
/// near-full payload, 1183x1183 cost 60% more than 1182x1182 for that reason
/// alone.
///
/// An odd bit count makes the halves unequal, so their widths swap on every
/// round; the round count is even, which puts them back. The round is still
/// invertible (right is carried across unchanged, left is recovered by XORing
/// the same round function), so this remains a permutation of the whole domain.
/// Where the bit count is even the halves are equal, the swap is a no-op, and
/// the result is bit-for-bit what scheme 1 produced.
struct KeyedPermutation {
    round_keys: [u64; 8],
    size: u64,
    left_bits: u32,
    right_bits: u32,
}

impl KeyedPermutation {
    const ROUNDS: usize = 8;

    /// Round keys are derived once here rather than inside
    /// `permute_power_of_two`: they depend only on the round index and the
    /// carrier key, so recomputing them per call cost eight splitmix64
    /// evaluations per Feistel pass on a function invoked once per sample.
    fn new(size: usize, carrier_key: u64) -> Result<Self> {
        let size = u64::try_from(size)
            .map_err(|_| anyhow!("Internal Error: Reddit carrier sample domain is too large."))?;
        if size < 2 {
            bail!("Internal Error: Reddit carrier sample domain is too small.");
        }

        let bits = u64::BITS - (size - 1).leading_zeros();
        let left_bits = bits / 2;
        let right_bits = bits - left_bits;
        let mut round_keys = [0u64; 8];
        for (round, key) in round_keys.iter_mut().enumerate() {
            *key = splitmix64(
                carrier_key ^ PERMUTATION_DOMAIN ^ (round as u64).wrapping_mul(0x9e3779b97f4a7c15),
            );
        }
        Ok(Self {
            round_keys,
            size,
            left_bits,
            right_bits,
        })
    }

    fn map(&self, ordinal: usize) -> Result<usize> {
        let ordinal = u64::try_from(ordinal)
            .map_err(|_| anyhow!("Internal Error: Reddit carrier index is out of range."))?;
        if ordinal >= self.size {
            bail!("Internal Error: Reddit carrier index is out of range.");
        }

        let mut value = ordinal;
        loop {
            value = self.permute_power_of_two(value);
            if value < self.size {
                return usize::try_from(value)
                    .map_err(|_| anyhow!("Internal Error: Reddit carrier index is out of range."));
            }
        }
    }

    fn permute_power_of_two(&self, value: u64) -> u64 {
        // The round count is even, so the halves finish at the widths they
        // started with and the recombination below is the inverse of the split.
        const _: () = assert!(KeyedPermutation::ROUNDS.is_multiple_of(2));

        let mask_for = |bits: u32| (1u64 << bits) - 1;
        let (mut left_bits, mut right_bits) = (self.left_bits, self.right_bits);
        let mut left = value >> right_bits;
        let mut right = value & mask_for(right_bits);
        for &round_key in &self.round_keys {
            let function = splitmix64(right ^ round_key);
            let next_left = right; // right_bits wide
            let next_right = (left ^ function) & mask_for(left_bits); // left_bits wide
            left = next_left;
            right = next_right;
            // The halves have exchanged widths.
            std::mem::swap(&mut left_bits, &mut right_bits);
        }
        (left << right_bits) | right
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

fn header_mask(carrier_key: u64, bit_index: usize) -> usize {
    (splitmix64(carrier_key ^ HEADER_DOMAIN ^ (bit_index as u64).wrapping_mul(0x9e3779b97f4a7c15))
        & 1) as usize
}

fn payload_mask(carrier_key: u64, group_index: usize) -> usize {
    (splitmix64(
        carrier_key ^ PAYLOAD_DOMAIN ^ (group_index as u64).wrapping_mul(0x9e3779b97f4a7c15),
    ) & 0x0f) as usize
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
    carrier_key: u64,
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
        if cost < best.cost
            || (cost == best.cost
                && splitmix64(carrier_key ^ DIRECTION_DOMAIN ^ sample as u64) & 1 != 0)
        {
            best = ChangeChoice {
                cost,
                value: candidate,
            };
        }
    }
    best
}

fn set_parity(
    carrier: &mut RedditPngCarrier,
    activity: &[u8],
    carrier_key: u64,
    sample: usize,
    target: usize,
) {
    if usize::from(carrier.rgb[sample] & 1) != target {
        carrier.rgb[sample] = choose_change(carrier, activity, carrier_key, sample).value;
    }
}

fn embed_header(
    carrier: &mut RedditPngCarrier,
    activity: &[u8],
    permutation: &KeyedPermutation,
    carrier_key: u64,
    header: &[u8; HEADER_SIZE],
) -> Result<()> {
    for bit in 0..HEADER_BITS {
        let target = header_bit(header, bit) ^ header_mask(carrier_key, bit);
        for copy in 0..HEADER_COPIES {
            let ordinal = bit * HEADER_COPIES + copy;
            set_parity(
                carrier,
                activity,
                carrier_key,
                permutation.map(ordinal)?,
                target,
            );
        }
    }
    Ok(())
}

fn embed_payload(
    carrier: &mut RedditPngCarrier,
    activity: &[u8],
    permutation: &KeyedPermutation,
    carrier_key: u64,
    payload: &[u8],
) -> Result<()> {
    let nibble_count = payload
        .len()
        .checked_mul(2)
        .ok_or_else(|| anyhow!("Data File Size Error: Reddit payload size overflow."))?;
    let row_bytes = carrier.width as usize * 3;

    for group in 0..nibble_count {
        let mut samples = [0usize; GROUP_SAMPLES];
        let mut choices = [ChangeChoice {
            cost: 0.0,
            value: 0,
        }; GROUP_SAMPLES];

        // This loop is memory-bound, not arithmetic-bound. The permutation
        // deliberately scatters a group's 15 samples across the whole image, so
        // on any cover larger than cache each choose_change() below stalls on
        // cold lines. Resolving all 15 indices up front and prefetching their
        // pixel neighbourhoods lets those independent misses overlap instead of
        // serialising. Format-neutral: same samples, same visit order, same
        // values written.
        //
        // Things tried here that did NOT help, so they are not worth
        // re-attempting: precomputing the 3x3 smoothed-activity map once per
        // pixel rather than once per channel, and deferring the 15
        // choose_change() calls until delta is known to be non-zero. Both are
        // output-preserving and both measured as no change -- the arithmetic
        // they remove is not the bottleneck.
        for (position, slot) in samples.iter_mut().enumerate() {
            let ordinal = HEADER_SLOTS + group * GROUP_SAMPLES + position;
            let sample = permutation.map(ordinal)?;
            *slot = sample;

            prefetch(&carrier.rgb, sample);
            if sample >= row_bytes {
                prefetch(&carrier.rgb, sample - row_bytes);
            }
            prefetch(&carrier.rgb, sample + row_bytes);
            prefetch(activity, sample / 3);
        }

        let mut syndrome = 0usize;
        for (position, (&sample, choice)) in samples.iter().zip(choices.iter_mut()).enumerate() {
            if carrier.rgb[sample] & 1 != 0 {
                syndrome ^= position + 1;
            }
            *choice = choose_change(carrier, activity, carrier_key, sample);
        }

        let nibble = if group & 1 == 0 {
            usize::from(payload[group / 2] >> 4)
        } else {
            usize::from(payload[group / 2] & 0x0f)
        };
        let delta = syndrome ^ nibble ^ payload_mask(carrier_key, group);
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
    Ok(())
}

fn extract_header(
    carrier: &RedditPngCarrier,
    permutation: &KeyedPermutation,
    carrier_key: u64,
) -> Result<[u8; HEADER_SIZE]> {
    let mut header = [0u8; HEADER_SIZE];
    for bit in 0..HEADER_BITS {
        let mut ones = 0usize;
        for copy in 0..HEADER_COPIES {
            let ordinal = bit * HEADER_COPIES + copy;
            ones += usize::from(carrier.rgb[permutation.map(ordinal)?] & 1);
        }
        let whitened = usize::from(ones > HEADER_COPIES / 2);
        set_header_bit(&mut header, bit, whitened ^ header_mask(carrier_key, bit));
    }
    Ok(header)
}

fn read_le_u32(data: &[u8]) -> u32 {
    u32::from_le_bytes(data.try_into().expect("four-byte Reddit header field"))
}

fn validate_carrier_header(header: &[u8; HEADER_SIZE], payload_capacity: usize) -> Result<()> {
    const CORRUPT_HEADER: &str = "File Recovery Error: Reddit carrier header is corrupt.";
    if header[8] != CARRIER_VERSION
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
    carrier_key: u64,
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

    for group in 0..nibble_count {
        let mut syndrome = 0usize;
        for position in 0..GROUP_SAMPLES {
            let ordinal = HEADER_SLOTS + group * GROUP_SAMPLES + position;
            let sample = permutation.map(ordinal)?;
            if carrier.rgb[sample] & 1 != 0 {
                syndrome ^= position + 1;
            }
        }

        let nibble = syndrome ^ payload_mask(carrier_key, group);
        if group & 1 == 0 {
            payload[group / 2] = (nibble << 4) as u8;
        } else {
            payload[group / 2] |= nibble as u8;
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

/// `carrier_key` fixes every sample position and whitening bit; see
/// `derive_carrier_key_from_pin`.
pub fn embed_reddit_png_payload(
    carrier: &mut RedditPngCarrier,
    carrier_key: u64,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if payload.is_empty() {
        bail!("Data File Size Error: Reddit carrier payload is empty.");
    }
    if payload.len() > carrier.payload_capacity {
        bail!("Data File Size Error: Encrypted Reddit payload exceeds the cover image's theoretical adaptive capacity.");
    }

    let header = make_header(payload)?;
    let permutation = KeyedPermutation::new(carrier.rgb.len(), carrier_key)?;
    let activity = build_activity_map(carrier)?;
    embed_header(carrier, &activity, &permutation, carrier_key, &header)?;
    embed_payload(carrier, &activity, &permutation, carrier_key, payload)?;
    encode_rgb_png(carrier)
}

/// Returns `None` for an ordinary PNG, for a PNG whose carrier does not decode
/// under `carrier_key` (a wrong PIN is indistinguishable from no carrier -- that
/// is the point of keying it), or for a CRC-valid generic PNGSTEG1 carrier that
/// is not a pdvrdt profile.
pub fn extract_reddit_png_payload(png_bytes: &[u8], carrier_key: u64) -> Result<Option<Vec<u8>>> {
    // Recovery is the one path that hands fully untrusted bytes to the PNG
    // decoder. The `png` crate's byte limit in decode_carrier already caps the
    // damage, but only once the decoder is running: on a crafted header that
    // still cost ~240 MiB for a 240 KB input. Checking the declared geometry
    // first turns that into an immediate rejection, and matches what the C++
    // conceal path has always done via its own preflight.
    require_geometry_within_decode_limit(png_bytes)?;

    let decoded = decode_carrier(png_bytes)?;
    if !decoded.fully_opaque || decoded.carrier.rgb.len() <= HEADER_SLOTS {
        return Ok(None);
    }

    let permutation = KeyedPermutation::new(decoded.carrier.rgb.len(), carrier_key)?;
    let header = extract_header(&decoded.carrier, &permutation, carrier_key)?;
    if &header[..CARRIER_MAGIC.len()] != CARRIER_MAGIC {
        return Ok(None);
    }

    validate_carrier_header(&header, decoded.carrier.payload_capacity)?;
    let payload_size = read_le_u32(&header[12..16]) as usize;
    let payload = extract_payload(&decoded.carrier, &permutation, carrier_key, payload_size)?;
    let expected_crc = read_le_u32(&header[16..20]);
    if expected_crc != crc32fast::hash(&payload) {
        bail!("File Recovery Error: Reddit embedded data is corrupt.");
    }
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

    fn test_profile() -> Vec<u8> {
        let mut profile = vec![0u8; DEFAULT_OFFSETS.encrypted_file + minimum_stream_cipher_size()];
        let kdf = DEFAULT_OFFSETS.kdf_metadata;
        profile[kdf..kdf + 4].copy_from_slice(b"KDF2");
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

    #[test]
    fn carrier_roundtrip_preserves_profile() {
        let width = 64u32;
        let height = 64u32;
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
        let mut carrier = RedditPngCarrier {
            payload_capacity: theoretical_capacity(rgb.len()),
            rgb,
            width,
            height,
        };
        let profile = test_profile();
        const KEY: u64 = 0x0123_4567_89ab_cdef;
        let encoded = embed_reddit_png_payload(&mut carrier, KEY, &profile).unwrap();
        let recovered = extract_reddit_png_payload(&encoded, KEY).unwrap().unwrap();
        assert_eq!(recovered, profile);

        // A different carrier key must find nothing: that indistinguishability is
        // the whole point of keying the permutation from the PIN.
        assert!(extract_reddit_png_payload(&encoded, KEY ^ 1)
            .unwrap()
            .is_none());
    }
}
