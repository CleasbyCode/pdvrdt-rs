use crate::encryption::{
    find_pdvrdt_iccp_payload, has_pdvrdt_profile_markers, DEFAULT_OFFSETS, PDVRDT_IDAT_PREFIX,
};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;

pub struct ImageCheckResult {
    pub has_bad_dims: bool,
}

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const PNG_HEADER_SIZE: usize = PNG_SIGNATURE.len();
const CHUNK_OVERHEAD: usize = 12;
const IHDR_DATA_SIZE: usize = 13;
const MAX_DECODE_BYTES: usize = 256 * 1024 * 1024;

const INDEXED_PLTE: u8 = 3;
const TRUECOLOR_RGB: u8 = 2;
const TRUECOLOR_RGBA: u8 = 6;

const TYPE_IHDR: [u8; 4] = *b"IHDR";
const TYPE_PLTE: [u8; 4] = *b"PLTE";
const TYPE_TRNS: [u8; 4] = *b"tRNS";
const TYPE_IDAT: [u8; 4] = *b"IDAT";
const TYPE_IEND: [u8; 4] = *b"IEND";
const TYPE_CHRM: [u8; 4] = *b"cHRM";
const TYPE_GAMA: [u8; 4] = *b"gAMA";
const TYPE_ICCP: [u8; 4] = *b"iCCP";
const TYPE_SRGB: [u8; 4] = *b"sRGB";
const TYPE_SBIT: [u8; 4] = *b"sBIT";
const TYPE_CICP: [u8; 4] = *b"cICP";
const TYPE_MDCV: [u8; 4] = *b"mDCV";
const TYPE_CLLI: [u8; 4] = *b"cLLI";
const TYPE_ACTL: [u8; 4] = *b"acTL";
const TYPE_FCTL: [u8; 4] = *b"fcTL";
const TYPE_FDAT: [u8; 4] = *b"fdAT";

#[derive(Clone, Copy)]
struct PngChunk<'a> {
    offset: usize,
    total_size: usize,
    kind: [u8; 4],
    data: &'a [u8],
}

#[derive(Debug)]
struct PngPreflight {
    width: u32,
    height: u32,
    color_type: u8,
    bit_depth: u8,
}

struct DecodedImage {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    png_color_type: u8,
    png_bit_depth: u8,
    raw_color_type: u8,
}

fn checked_add(lhs: usize, rhs: usize, message: &str) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| anyhow!(message.to_owned()))
}

fn checked_mul(lhs: usize, rhs: usize, message: &str) -> Result<usize> {
    lhs.checked_mul(rhs)
        .ok_or_else(|| anyhow!(message.to_owned()))
}

fn read_png_chunk<'a>(
    png: &'a [u8],
    offset: usize,
    header_error: &str,
    length_error: &str,
    crc_error: &str,
) -> Result<PngChunk<'a>> {
    let header_end = checked_add(offset, 8, header_error)?;
    if header_end > png.len() {
        bail!(header_error.to_owned());
    }

    let length = u32::from_be_bytes(
        png[offset..offset + 4]
            .try_into()
            .expect("four-byte PNG length"),
    ) as usize;
    let type_index = offset + 4;
    let data_index = offset + 8;
    let data_end = checked_add(data_index, length, length_error)?;
    let chunk_end = checked_add(data_end, 4, length_error)?;
    if chunk_end > png.len() {
        bail!(length_error.to_owned());
    }

    let kind: [u8; 4] = png[type_index..data_index]
        .try_into()
        .expect("four-byte PNG type");
    let data = &png[data_index..data_end];
    let stored_crc = u32::from_be_bytes(
        png[data_end..chunk_end]
            .try_into()
            .expect("four-byte PNG CRC"),
    );
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&kind);
    hasher.update(data);
    if stored_crc != hasher.finalize() {
        bail!(crc_error.to_owned());
    }

    Ok(PngChunk {
        offset,
        total_size: chunk_end - offset,
        kind,
        data,
    })
}

fn require_png_signature(png: &[u8], message: &str) -> Result<()> {
    if !png.starts_with(PNG_SIGNATURE) {
        bail!(message.to_owned());
    }
    Ok(())
}

fn read_required_ihdr(png: &[u8]) -> Result<PngChunk<'_>> {
    require_png_signature(png, "PNG Error: Invalid PNG signature.")?;
    let ihdr = read_png_chunk(
        png,
        PNG_HEADER_SIZE,
        "PNG Error: Corrupt IHDR chunk header.",
        "PNG Error: Corrupt IHDR chunk length.",
        "PNG Error: Corrupt IHDR chunk CRC.",
    )?;
    if ihdr.kind != TYPE_IHDR || ihdr.data.len() != IHDR_DATA_SIZE {
        bail!("PNG Error: Missing or corrupt IHDR chunk.");
    }
    Ok(ihdr)
}

fn is_apng_chunk(kind: [u8; 4]) -> bool {
    kind == TYPE_ACTL || kind == TYPE_FCTL || kind == TYPE_FDAT
}

fn is_color_metadata(kind: [u8; 4]) -> bool {
    matches!(
        kind,
        TYPE_CHRM
            | TYPE_GAMA
            | TYPE_ICCP
            | TYPE_SRGB
            | TYPE_SBIT
            | TYPE_CICP
            | TYPE_MDCV
            | TYPE_CLLI
    )
}

/// sBIT's length is fixed by the image's color type (PNG spec 11.3.3). Zero for
/// a color type that has no valid sBIT, which the IHDR checks have already ruled
/// out by the time this runs.
fn sbit_length_for_color_type(color_type: u8) -> usize {
    match color_type {
        0 => 1,             // greyscale
        TRUECOLOR_RGB => 3, // truecolor
        INDEXED_PLTE => 3,  // indexed -- significance of the palette's RGB samples
        4 => 2,             // greyscale + alpha
        TRUECOLOR_RGBA => 4,
        _ => 0,
    }
}

/// Every color-metadata chunk pdvrdt keeps is copied into the output verbatim,
/// byte range and all. The `png` crate never surfaces them and read_png_chunk
/// only checks the CRC, so without this a cover can hand pdvrdt a malformed
/// chunk that it then faithfully re-emits -- producing an image that fails PNG
/// validators through no fault of the payload, and giving the cover an
/// unvalidated channel for planting arbitrary bytes in whatever gets shared.
/// Each chunk's length (and, where it is cheap, its contents) is checked against
/// the spec here, once, in the preflight both output paths run.
fn require_valid_color_metadata_chunk(chunk: &PngChunk, color_type: u8, bit_depth: u8) -> Result<()> {
    let require_length = |expected: usize, name: &str| -> Result<()> {
        if chunk.data.len() != expected {
            bail!(
                "PNG Error: Invalid color metadata. {} chunk must be {} bytes.",
                name,
                expected
            );
        }
        Ok(())
    };

    match chunk.kind {
        TYPE_CHRM => require_length(32, "cHRM")?,
        TYPE_GAMA => require_length(4, "gAMA")?,
        TYPE_CICP => require_length(4, "cICP")?,
        TYPE_MDCV => require_length(24, "mDCv")?,
        TYPE_CLLI => require_length(8, "cLLi")?,
        TYPE_SRGB => {
            require_length(1, "sRGB")?;
            if chunk.data[0] > 3 {
                bail!("PNG Error: Invalid color metadata. sRGB rendering intent must be 0-3.");
            }
        }
        TYPE_SBIT => {
            let expected = sbit_length_for_color_type(color_type);
            if expected == 0 || chunk.data.len() != expected {
                bail!(
                    "PNG Error: Invalid color metadata. sBIT chunk must be {} bytes for color type {}.",
                    expected,
                    color_type
                );
            }
            // A palette's entries are 8-bit samples whatever the image's bit
            // depth, which is only the width of the index.
            let sample_bits = if color_type == INDEXED_PLTE { 8 } else { bit_depth };
            if chunk
                .data
                .iter()
                .any(|&significant_bits| significant_bits == 0 || significant_bits > sample_bits)
            {
                bail!(
                    "PNG Error: Invalid color metadata. sBIT significant-bit counts must be 1-{}.",
                    sample_bits
                );
            }
        }
        TYPE_ICCP => {
            // Profile name (1-79 bytes), NUL, compression method, deflate stream.
            match chunk.data.iter().position(|&b| b == 0) {
                Some(name_length) if (1..=79).contains(&name_length) => {
                    if chunk.data.len() < name_length + 3 {
                        bail!("PNG Error: Invalid color metadata. iCCP chunk carries no compressed profile.");
                    }
                    if chunk.data[name_length + 1] != 0 {
                        bail!("PNG Error: Invalid color metadata. iCCP compression method must be 0 (deflate).");
                    }
                }
                _ => bail!(
                    "PNG Error: Invalid color metadata. iCCP profile name must be 1-79 bytes followed by a null separator."
                ),
            }
        }
        _ => {}
    }
    Ok(())
}

fn channels_for_color_type(color_type: u8) -> Result<usize> {
    match color_type {
        0 => Ok(1),
        TRUECOLOR_RGB => Ok(3),
        INDEXED_PLTE => Ok(1),
        4 => Ok(2),
        TRUECOLOR_RGBA => Ok(4),
        _ => bail!("PNG Error: Unsupported PNG color type."),
    }
}

fn valid_bit_depth(bit_depth: u8, color_type: u8) -> bool {
    match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        TRUECOLOR_RGB => matches!(bit_depth, 8 | 16),
        INDEXED_PLTE => matches!(bit_depth, 1 | 2 | 4 | 8),
        4 | TRUECOLOR_RGBA => matches!(bit_depth, 8 | 16),
        _ => false,
    }
}

/// Bytes the decoder inflates the IDAT stream into for a single (sub-)image: one
/// filter byte plus a byte-padded row of samples, per row.
fn filtered_image_bytes(width: usize, height: usize, bits_per_pixel: usize) -> Result<usize> {
    const OVERFLOW_ERROR: &str = "PNG Error: Inflated image size overflow.";
    if width == 0 || height == 0 {
        return Ok(0);
    }
    let row_bits = checked_mul(width, bits_per_pixel, OVERFLOW_ERROR)?;
    let row_bytes = checked_add(row_bits / 8, usize::from(row_bits % 8 != 0), OVERFLOW_ERROR)?;
    checked_mul(
        checked_add(row_bytes, 1, OVERFLOW_ERROR)?,
        height,
        OVERFLOW_ERROR,
    )
}

/// Total inflated size, honouring the interlace method. Adam7 splits the image
/// into seven sub-images, each with its own byte-padded rows and its own filter
/// byte per row, which comes to *more* than the non-interlaced layout (~1.875x
/// the filter bytes, plus per-pass row padding). Using the non-interlaced formula
/// for an interlaced cover would therefore under-count and let the safety limit
/// be exceeded, so each pass is measured.
fn inflated_image_bytes(
    width: usize,
    height: usize,
    bits_per_pixel: usize,
    interlace_method: u8,
) -> Result<usize> {
    const OVERFLOW_ERROR: &str = "PNG Error: Inflated image size overflow.";
    if interlace_method == 0 {
        return filtered_image_bytes(width, height, bits_per_pixel);
    }

    // Adam7 pass origins and strides (PNG spec, 4.7 "Interlaced data order").
    const X_START: [usize; 7] = [0, 4, 0, 2, 0, 1, 0];
    const Y_START: [usize; 7] = [0, 0, 4, 0, 2, 0, 1];
    const X_STEP: [usize; 7] = [8, 8, 4, 4, 2, 2, 1];
    const Y_STEP: [usize; 7] = [8, 8, 8, 4, 4, 2, 2];

    let mut total = 0usize;
    for pass in 0..7 {
        if width <= X_START[pass] || height <= Y_START[pass] {
            continue; // Empty pass: no rows, so no filter bytes either.
        }
        let pass_width = (width - X_START[pass]).div_ceil(X_STEP[pass]);
        let pass_height = (height - Y_START[pass]).div_ceil(Y_STEP[pass]);
        total = checked_add(
            total,
            filtered_image_bytes(pass_width, pass_height, bits_per_pixel)?,
            OVERFLOW_ERROR,
        )?;
    }
    Ok(total)
}

/// Reject a PNG whose declared IHDR geometry would inflate past the decoder's
/// safety ceiling, before anything is allocated for it.
///
/// This is the half of the decode preflight that bounds *work*, split out from
/// the cover-image chunk policy below because both paths need it: conceal
/// reaches it through `preflight_png`, and recover through
/// `extract_reddit_png_payload`, which is the one recovery path that decodes
/// pixels. The `png` crate's own byte limit already caps the damage, but it
/// only bites once the decoder is running -- checking the header first turns a
/// quarter-gigabyte allocation into an immediate rejection.
pub(crate) fn require_geometry_within_decode_limit(png: &[u8]) -> Result<()> {
    geometry_within_decode_limit(png).map(|_| ())
}

fn geometry_within_decode_limit(png: &[u8]) -> Result<PngPreflight> {
    let ihdr = read_required_ihdr(png)?;

    let width = u32::from_be_bytes(ihdr.data[0..4].try_into().expect("IHDR width"));
    let height = u32::from_be_bytes(ihdr.data[4..8].try_into().expect("IHDR height"));
    let bit_depth = ihdr.data[8];
    let color_type = ihdr.data[9];
    let compression_method = ihdr.data[10];
    let filter_method = ihdr.data[11];
    let interlace_method = ihdr.data[12];

    if width == 0
        || height == 0
        || compression_method != 0
        || filter_method != 0
        || !matches!(interlace_method, 0 | 1)
        || !valid_bit_depth(bit_depth, color_type)
    {
        bail!("PNG Error: Invalid IHDR metadata.");
    }

    let width_usize = width as usize;
    let height_usize = height as usize;
    let pixel_count = checked_mul(
        width_usize,
        height_usize,
        "PNG Error: Pixel count overflow.",
    )?;
    let decoded_rgba_size = checked_mul(pixel_count, 4, "PNG Error: Decoded image size overflow.")?;
    if decoded_rgba_size > MAX_DECODE_BYTES {
        bail!("PNG Error: Decoded image exceeds safety limit.");
    }

    let bits_per_pixel = checked_mul(
        channels_for_color_type(color_type)?,
        bit_depth as usize,
        "PNG Error: Scanline size overflow.",
    )?;
    let inflated_size =
        inflated_image_bytes(width_usize, height_usize, bits_per_pixel, interlace_method)?;
    if inflated_size > MAX_DECODE_BYTES {
        bail!("PNG Error: Inflated image exceeds safety limit.");
    }

    Ok(PngPreflight {
        width,
        height,
        color_type,
        bit_depth,
    })
}

fn preflight_png(png: &[u8]) -> Result<PngPreflight> {
    const MIN_PNG_SIZE: usize = PNG_HEADER_SIZE + CHUNK_OVERHEAD + IHDR_DATA_SIZE + CHUNK_OVERHEAD;
    if png.len() < MIN_PNG_SIZE {
        bail!("PNG Error: File too small to contain valid PNG structure.");
    }

    let ihdr = read_required_ihdr(png)?;
    // read_required_ihdr has already fixed the length at IHDR_DATA_SIZE.
    let ihdr_bit_depth = ihdr.data[8];
    let ihdr_color_type = ihdr.data[9];
    let mut pos = ihdr.offset + ihdr.total_size;
    let mut has_iend = false;
    let mut has_iccp = false;
    let mut has_srgb = false;

    while pos < png.len() {
        let chunk = read_png_chunk(
            png,
            pos,
            "PNG Error: Corrupt PNG chunk header.",
            "PNG Error: Corrupt PNG chunk length.",
            "PNG Error: Corrupt PNG chunk CRC.",
        )?;

        if is_apng_chunk(chunk.kind) {
            bail!("PNG Error: APNG covers are not supported.");
        }
        if chunk.kind == TYPE_IHDR {
            bail!("PNG Error: Corrupt PNG structure. Duplicate IHDR.");
        }
        if is_color_metadata(chunk.kind) {
            require_valid_color_metadata_chunk(&chunk, ihdr_color_type, ihdr_bit_depth)?;
        }
        if chunk.kind == TYPE_ICCP {
            if has_iccp || has_srgb {
                bail!(
                    "PNG Error: Invalid color metadata. Duplicate iCCP or conflicting sRGB chunk."
                );
            }
            has_iccp = true;
        } else if chunk.kind == TYPE_SRGB {
            if has_srgb || has_iccp {
                bail!(
                    "PNG Error: Invalid color metadata. Duplicate sRGB or conflicting iCCP chunk."
                );
            }
            has_srgb = true;
        }

        if chunk.kind == TYPE_IEND {
            if !chunk.data.is_empty() {
                bail!("PNG Error: Corrupt PNG structure. Invalid IEND.");
            }
            has_iend = true;
            break;
        }
        pos = checked_add(
            pos,
            chunk.total_size,
            "PNG Error: Corrupt PNG chunk length.",
        )?;
    }
    if !has_iend {
        bail!("PNG Error: Missing IEND chunk.");
    }

    geometry_within_decode_limit(png)
}

fn looks_like_pdvrdt_idat(chunk_data: &[u8]) -> bool {
    chunk_data.starts_with(PDVRDT_IDAT_PREFIX)
        && has_pdvrdt_profile_markers(&chunk_data[PDVRDT_IDAT_PREFIX.len()..], &DEFAULT_OFFSETS)
}

/// A previous pdvrdt Mastodon payload must be removed when its image is reused as
/// a cover, while a genuine ICC profile must be preserved. find_pdvrdt_iccp_payload()
/// is the shared decision the recover side uses, so the two can never disagree.
fn looks_like_pdvrdt_iccp(chunk_data: &[u8]) -> bool {
    find_pdvrdt_iccp_payload(chunk_data).is_some()
}

/// Drop image data that sits past the end of the PNG's own zlib stream.
///
/// The concatenated IDAT data must be exactly one zlib stream, as the PNG spec
/// requires. Anything after it is a spare IDAT some other tool appended: the
/// stream already ended, so those bytes are provably not part of the picture and
/// can simply be removed, leaving a cover that is perfectly usable.
///
/// Removing them is not optional here the way it might look. The `png` crate
/// stops at the end of the stream and ignores the remainder, and the
/// non-palettized path copies IDAT chunks across verbatim -- so left in place,
/// the foreign bytes would be propagated straight into the output image.
///
/// remove_existing_pdvrdt_payload_chunks() runs first, so any IDAT this tool
/// wrote is already gone and whatever is left over really is foreign.
///
/// Truncation is at byte granularity, not chunk granularity: the boundary
/// usually falls exactly at the end of a chunk, but nothing guarantees it, and
/// keeping a partial chunk correct is just a length and a CRC.
///
/// Returns true when something was removed. A stream that never ends is left
/// alone for the decoder to report in its own words -- this must not silently
/// truncate a genuinely corrupt image down to whatever happened to inflate.
fn strip_trailing_idat_data(png: &mut Vec<u8>) -> Result<bool> {
    let mut decompress = flate2::Decompress::new(true);
    let mut scratch = vec![0u8; 64 * 1024];
    let mut stream_ended = false;
    let mut consumed_total = 0usize;
    let mut idat_total = 0usize;

    let ihdr = read_required_ihdr(png)?;
    let first_chunk_pos = ihdr.offset + ihdr.total_size;
    let mut pos = first_chunk_pos;
    while pos < png.len() {
        let chunk = read_png_chunk(
            png,
            pos,
            "PNG Error: Corrupt PNG chunk header.",
            "PNG Error: Corrupt PNG chunk length.",
            "PNG Error: Corrupt PNG chunk CRC.",
        )?;

        if chunk.kind == TYPE_IDAT {
            idat_total += chunk.data.len();
            let mut offset = 0usize;
            while offset < chunk.data.len() && !stream_ended {
                let consumed_before = decompress.total_in();
                let status = decompress
                    .decompress(
                        &chunk.data[offset..],
                        &mut scratch,
                        flate2::FlushDecompress::None,
                    )
                    .map_err(|_| anyhow!("PNG decode error: corrupt image data stream."))?;
                let consumed = (decompress.total_in() - consumed_before) as usize;
                offset += consumed;
                consumed_total += consumed;
                match status {
                    flate2::Status::StreamEnd => stream_ended = true,
                    // No input consumed and no output produced means the stream
                    // cannot advance; leave it to the decoder to report properly.
                    flate2::Status::BufError if consumed == 0 => return Ok(false),
                    _ => {}
                }
            }
        }

        if chunk.kind == TYPE_IEND {
            break;
        }
        pos = checked_add(
            pos,
            chunk.total_size,
            "PNG Error: Corrupt PNG chunk length.",
        )?;
    }

    if !stream_ended || consumed_total >= idat_total {
        return Ok(false);
    }

    // Rebuild, keeping only the first `consumed_total` bytes of IDAT payload.
    let mut kept = 0usize;
    let mut rebuilt = Vec::new();
    rebuilt
        .try_reserve_exact(png.len())
        .context("PNG Error: Unable to allocate repaired PNG.")?;
    rebuilt.extend_from_slice(&png[..first_chunk_pos]);

    let mut pos = first_chunk_pos;
    while pos < png.len() {
        let chunk = read_png_chunk(
            png,
            pos,
            "PNG Error: Corrupt PNG chunk header.",
            "PNG Error: Corrupt PNG chunk length.",
            "PNG Error: Corrupt PNG chunk CRC.",
        )?;
        let is_iend = chunk.kind == TYPE_IEND;

        if chunk.kind != TYPE_IDAT {
            rebuilt.extend_from_slice(&png[chunk.offset..chunk.offset + chunk.total_size]);
        } else {
            let take = (consumed_total - kept).min(chunk.data.len());
            kept += take;
            if take == chunk.data.len() {
                rebuilt.extend_from_slice(&png[chunk.offset..chunk.offset + chunk.total_size]);
            } else if take > 0 {
                // Partial chunk: re-emit it with a corrected length and CRC.
                rebuilt.extend_from_slice(&(take as u32).to_be_bytes());
                rebuilt.extend_from_slice(&TYPE_IDAT);
                rebuilt.extend_from_slice(&chunk.data[..take]);
                let mut hasher = crc32fast::Hasher::new();
                hasher.update(&TYPE_IDAT);
                hasher.update(&chunk.data[..take]);
                rebuilt.extend_from_slice(&hasher.finalize().to_be_bytes());
            }
        }

        if is_iend {
            break;
        }
        pos = checked_add(
            pos,
            chunk.total_size,
            "PNG Error: Corrupt PNG chunk length.",
        )?;
    }

    *png = rebuilt;
    Ok(true)
}

fn compact_chunks_after_ihdr<F>(
    png: &mut Vec<u8>,
    first_chunk_pos: usize,
    mut keep: F,
) -> Result<()>
where
    F: FnMut([u8; 4], &[u8]) -> bool,
{
    if first_chunk_pos > png.len() {
        bail!("PNG Error: Corrupt PNG chunk header.");
    }

    let mut cleaned = Vec::new();
    cleaned
        .try_reserve_exact(png.len())
        .context("PNG Error: Unable to allocate cleaned PNG.")?;
    cleaned.extend_from_slice(&png[..first_chunk_pos]);

    let mut pos = first_chunk_pos;
    let mut has_iend = false;
    while pos < png.len() {
        let chunk = read_png_chunk(
            png,
            pos,
            "PNG Error: Corrupt PNG chunk header.",
            "PNG Error: Corrupt PNG chunk length.",
            "PNG Error: Corrupt PNG chunk CRC.",
        )?;
        if chunk.kind == TYPE_IEND && !chunk.data.is_empty() {
            bail!("PNG Error: Corrupt PNG structure. Invalid IEND.");
        }
        if keep(chunk.kind, chunk.data) {
            cleaned.extend_from_slice(&png[chunk.offset..chunk.offset + chunk.total_size]);
        }

        pos = checked_add(
            pos,
            chunk.total_size,
            "PNG Error: Corrupt PNG chunk length.",
        )?;
        if chunk.kind == TYPE_IEND {
            has_iend = true;
            break;
        }
    }
    if !has_iend {
        bail!("PNG Error: Missing IEND chunk.");
    }

    *png = cleaned;
    Ok(())
}

fn remove_existing_pdvrdt_payload_chunks(png: &mut Vec<u8>) -> Result<()> {
    let ihdr = read_required_ihdr(png)?;
    let first_chunk_pos = ihdr.offset + ihdr.total_size;
    compact_chunks_after_ihdr(png, first_chunk_pos, |kind, data| {
        !((kind == TYPE_IDAT && looks_like_pdvrdt_idat(data))
            || (kind == TYPE_ICCP && looks_like_pdvrdt_iccp(data)))
    })
}

fn make_png_chunk(kind: [u8; 4], data: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(data.len())
        .map_err(|_| anyhow!("PNG Error: Chunk payload exceeds PNG chunk size limit."))?;
    let total_size = checked_add(
        data.len(),
        CHUNK_OVERHEAD,
        "PNG Error: Chunk size overflow.",
    )?;
    let mut chunk = Vec::new();
    chunk
        .try_reserve_exact(total_size)
        .context("PNG Error: Unable to allocate metadata chunk.")?;
    chunk.extend_from_slice(&length.to_be_bytes());
    chunk.extend_from_slice(&kind);
    chunk.extend_from_slice(data);

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&kind);
    hasher.update(data);
    chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
    Ok(chunk)
}

fn palette_sbit_chunk(rgba_sbit: &[u8]) -> Result<Vec<u8>> {
    if rgba_sbit.len() != 4 {
        bail!("PNG Error: Invalid RGBA sBIT metadata.");
    }
    make_png_chunk(TYPE_SBIT, &rgba_sbit[..3])
}

fn collect_color_metadata(png: &[u8], palette_from_rgba: bool) -> Result<Vec<u8>> {
    let ihdr = read_required_ihdr(png)?;
    let mut metadata = Vec::new();
    let mut pos = ihdr.offset + ihdr.total_size;

    while pos < png.len() {
        let chunk = read_png_chunk(
            png,
            pos,
            "PNG Error: Corrupt PNG chunk header.",
            "PNG Error: Corrupt PNG chunk length.",
            "PNG Error: Corrupt PNG chunk CRC.",
        )?;
        // As in strip_and_copy_chunks: a stale pdvrdt iCCP payload was already
        // removed by remove_existing_pdvrdt_payload_chunks(), so no re-test here.
        if is_color_metadata(chunk.kind) {
            if palette_from_rgba && chunk.kind == TYPE_SBIT {
                metadata.extend_from_slice(&palette_sbit_chunk(chunk.data)?);
            } else {
                metadata.extend_from_slice(&png[chunk.offset..chunk.offset + chunk.total_size]);
            }
        }
        pos = checked_add(
            pos,
            chunk.total_size,
            "PNG Error: Corrupt PNG chunk length.",
        )?;
        if chunk.kind == TYPE_IEND {
            break;
        }
    }
    Ok(metadata)
}

fn insert_color_metadata_after_ihdr(png: &mut Vec<u8>, metadata: &[u8]) -> Result<()> {
    if metadata.is_empty() {
        return Ok(());
    }
    let ihdr = read_required_ihdr(png)?;
    let insert_pos = ihdr.offset + ihdr.total_size;
    let final_size = checked_add(
        png.len(),
        metadata.len(),
        "PNG Error: Encoded image size overflow.",
    )?;
    let mut with_metadata = Vec::new();
    with_metadata
        .try_reserve_exact(final_size)
        .context("PNG Error: Unable to allocate encoded image.")?;
    with_metadata.extend_from_slice(&png[..insert_pos]);
    with_metadata.extend_from_slice(metadata);
    with_metadata.extend_from_slice(&png[insert_pos..]);
    *png = with_metadata;
    Ok(())
}

fn decode_image(png: &[u8], preflight: &PngPreflight) -> Result<DecodedImage> {
    let mut decoder = png::Decoder::new(Cursor::new(png));
    decoder.set_limits(png::Limits {
        bytes: MAX_DECODE_BYTES,
    });
    // Match LodePNG's default RGBA8-style statistics input closely enough for
    // palette decisions: expand tRNS/palette samples and strip 16-bit decoded
    // samples. Source bit depth still controls whether a rewrite is permitted.
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().context("PNG decode error")?;
    let output_size = reader.output_buffer_size();
    if output_size > MAX_DECODE_BYTES {
        bail!("PNG Error: Decoded image exceeds safety limit.");
    }

    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(output_size)
        .context("PNG Error: Unable to allocate decoded image.")?;
    pixels.resize(output_size, 0);
    let output_info = reader.next_frame(&mut pixels).context("PNG decode error")?;
    pixels.truncate(output_info.buffer_size());

    let color_type = match output_info.color_type {
        png::ColorType::Grayscale => 0,
        png::ColorType::Rgb => TRUECOLOR_RGB,
        png::ColorType::Indexed => INDEXED_PLTE,
        png::ColorType::GrayscaleAlpha => 4,
        png::ColorType::Rgba => TRUECOLOR_RGBA,
    };
    let raw_bit_depth = match output_info.bit_depth {
        png::BitDepth::One => 1,
        png::BitDepth::Two => 2,
        png::BitDepth::Four => 4,
        png::BitDepth::Eight => 8,
        png::BitDepth::Sixteen => 16,
    };

    if output_info.width != preflight.width || output_info.height != preflight.height {
        bail!("PNG Error: Decoded image metadata does not match IHDR.");
    }
    if raw_bit_depth != 8 {
        bail!("PNG Error: Decoder did not produce 8-bit optimization pixels.");
    }

    Ok(DecodedImage {
        pixels,
        width: output_info.width,
        height: output_info.height,
        png_color_type: preflight.color_type,
        png_bit_depth: preflight.bit_depth,
        raw_color_type: color_type,
    })
}

fn rgba_key(pixel: &[u8], has_alpha: bool) -> u32 {
    ((pixel[0] as u32) << 24)
        | ((pixel[1] as u32) << 16)
        | ((pixel[2] as u32) << 8)
        | if has_alpha { pixel[3] as u32 } else { 255 }
}

fn collect_unique_colors(image: &[u8], channels: usize) -> Result<Option<Vec<u32>>> {
    const MAX_PALETTE_SIZE: usize = 256;
    if channels != 3 && channels != 4 {
        bail!("convertToPalette: Unsupported decoded color type.");
    }
    if !image.chunks_exact(channels).remainder().is_empty() {
        bail!("Image Error: Decoded image size does not match PNG dimensions.");
    }

    let has_alpha = channels == 4;
    let mut seen = HashSet::with_capacity(MAX_PALETTE_SIZE + 1);
    let mut colors = Vec::with_capacity(MAX_PALETTE_SIZE);
    for pixel in image.chunks_exact(channels) {
        let key = rgba_key(pixel, has_alpha);
        if seen.insert(key) {
            colors.push(key);
        }
        if colors.len() > MAX_PALETTE_SIZE {
            return Ok(None);
        }
    }

    Ok(Some(colors))
}

fn convert_to_palette(
    image_file_vec: &mut Vec<u8>,
    decoded: &DecodedImage,
    colors: &[u32],
    color_metadata: &[u8],
) -> Result<()> {
    const MAX_PALETTE_SIZE: usize = 256;
    if colors.is_empty() {
        bail!("convertToPalette: Palette is empty.");
    }
    if colors.len() > MAX_PALETTE_SIZE {
        bail!(
            "convertToPalette: Palette has {} colors, exceeds maximum of {}.",
            colors.len(),
            MAX_PALETTE_SIZE
        );
    }
    if decoded.png_bit_depth != 8
        || (decoded.png_color_type != TRUECOLOR_RGB && decoded.png_color_type != TRUECOLOR_RGBA)
    {
        bail!("convertToPalette: Expected 8-bit RGB or RGBA input.");
    }

    let channels = if decoded.raw_color_type == TRUECOLOR_RGBA {
        4
    } else if decoded.raw_color_type == TRUECOLOR_RGB {
        3
    } else {
        bail!("convertToPalette: Decoder did not produce RGB or RGBA pixels.");
    };
    let pixel_count = checked_mul(
        decoded.width as usize,
        decoded.height as usize,
        "Image Error: Pixel count overflow.",
    )?;
    let expected_size = checked_mul(
        pixel_count,
        channels,
        "Image Error: Decoded image size overflow.",
    )?;
    if decoded.pixels.len() != expected_size {
        bail!("Image Error: Decoded image size does not match PNG dimensions.");
    }

    let mut color_to_index = HashMap::with_capacity(colors.len());
    let mut palette = Vec::with_capacity(colors.len() * 3);
    let mut transparency = Vec::with_capacity(colors.len());
    let mut has_transparency = false;
    for (index, key) in colors.iter().copied().enumerate() {
        let palette_index = u8::try_from(index).expect("palette is capped at 256 entries");
        color_to_index.insert(key, palette_index);
        palette.extend_from_slice(&[
            ((key >> 24) & 0xff) as u8,
            ((key >> 16) & 0xff) as u8,
            ((key >> 8) & 0xff) as u8,
        ]);
        let alpha = (key & 0xff) as u8;
        transparency.push(alpha);
        has_transparency |= alpha != 255;
    }

    let has_alpha = channels == 4;
    let mut indexed = Vec::new();
    indexed
        .try_reserve_exact(pixel_count)
        .context("Image Error: Unable to allocate indexed image.")?;
    for (pixel_index, pixel) in decoded.pixels.chunks_exact(channels).enumerate() {
        let key = rgba_key(pixel, has_alpha);
        let index = color_to_index.get(&key).copied().ok_or_else(|| {
            anyhow!(
                "convertToPalette: Pixel {} has color 0x{:08X} not found in palette.",
                pixel_index,
                key
            )
        })?;
        indexed.push(index);
    }

    let mut output = Vec::new();
    {
        let mut encoder =
            png::Encoder::new(Cursor::new(&mut output), decoded.width, decoded.height);
        encoder.set_color(png::ColorType::Indexed);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_palette(palette);
        if has_transparency {
            encoder.set_trns(transparency);
        }
        let mut writer = encoder.write_header().context("PNG encode error")?;
        writer
            .write_image_data(&indexed)
            .context("PNG encode error")?;
        writer.finish().context("PNG encode error")?;
    }
    insert_color_metadata_after_ihdr(&mut output, color_metadata)?;
    *image_file_vec = output;
    Ok(())
}

fn strip_and_copy_chunks(image_file_vec: &mut Vec<u8>, color_type: u8) -> Result<()> {
    let ihdr = read_required_ihdr(image_file_vec)?;
    let first_chunk_pos = ihdr.offset + ihdr.total_size;
    // Any pdvrdt IDAT or iCCP payload is already gone: optimize_image() runs
    // remove_existing_pdvrdt_payload_chunks() before this. Re-testing here would
    // be dead weight on every chunk of every cover -- and looks_like_pdvrdt_iccp()
    // inflates a prefix, so it is not free.
    compact_chunks_after_ihdr(image_file_vec, first_chunk_pos, |kind, _data| {
        (kind == TYPE_PLTE && color_type == INDEXED_PLTE)
            || kind == TYPE_TRNS
            || is_color_metadata(kind)
            || kind == TYPE_IDAT
            || kind == TYPE_IEND
    })
}

fn has_unsupported_share_dimensions(width: u32, height: u32, max_dimension: u32) -> bool {
    const MIN_DIMENSION: u32 = 68;
    width < MIN_DIMENSION
        || height < MIN_DIMENSION
        || width > max_dimension
        || height > max_dimension
}

/// Validation-only cover preparation for the Reddit carrier.
///
/// Applies the same cover policy as `optimize_image` -- geometry bound, chunk
/// validation, APNG rejection -- and strips any stale pdvrdt payload from a
/// reused cover, then stops. It deliberately does NOT decode, palettize or
/// re-encode: the carrier decodes the cover itself, so everything
/// `optimize_image` builds past this point is discarded unread. On a low-colour
/// cover that discarded work is a full palette conversion plus a complete PNG
/// re-encode.
pub fn prepare_cover_for_reddit_carrier(image_file_vec: &mut Vec<u8>) -> Result<()> {
    preflight_png(image_file_vec)?;
    // A stale pdvrdt payload in a reused cover sits after the real image data, so
    // leaving it would make the concatenated IDAT stream look like trailing
    // garbage to the decoder. Removing it by chunk here is exact and costs a
    // walk; letting the carrier's decode discover it costs a whole extra inflate
    // to find where the real stream ends.
    remove_existing_pdvrdt_payload_chunks(image_file_vec)?;
    Ok(())
}

pub fn optimize_image(image_file_vec: &mut Vec<u8>) -> Result<ImageCheckResult> {
    const MAX_PALETTE_DIMENSION: u32 = 4096;
    const MAX_TRUECOLOR_DIMENSION: u32 = 900;

    let preflight = preflight_png(image_file_vec)?;
    remove_existing_pdvrdt_payload_chunks(image_file_vec)?;
    // A cover carrying a spare IDAT appended by some other tool is usable: the
    // bytes past the end of its zlib stream are not part of the picture, so drop
    // them rather than refusing the image.
    if strip_trailing_idat_data(image_file_vec)? {
        println!("\nNote: removed a stray IDAT chunk left in the cover image by another tool.");
    }
    let decoded = decode_image(image_file_vec, &preflight)?;

    let is_truecolor =
        decoded.png_color_type == TRUECOLOR_RGB || decoded.png_color_type == TRUECOLOR_RGBA;
    let can_palettize = is_truecolor && decoded.png_bit_depth == 8;
    if can_palettize {
        let channels = if decoded.raw_color_type == TRUECOLOR_RGBA {
            4
        } else if decoded.raw_color_type == TRUECOLOR_RGB {
            3
        } else {
            bail!("convertToPalette: Decoder did not produce RGB or RGBA pixels.");
        };
        if let Some(colors) = collect_unique_colors(&decoded.pixels, channels)? {
            let metadata =
                collect_color_metadata(image_file_vec, decoded.png_color_type == TRUECOLOR_RGBA)?;
            convert_to_palette(image_file_vec, &decoded, &colors, &metadata)?;
            return Ok(ImageCheckResult {
                has_bad_dims: has_unsupported_share_dimensions(
                    decoded.width,
                    decoded.height,
                    MAX_PALETTE_DIMENSION,
                ),
            });
        }
    }

    strip_and_copy_chunks(image_file_vec, decoded.png_color_type)?;
    let max_dimension = if decoded.png_color_type == INDEXED_PLTE {
        MAX_PALETTE_DIMENSION
    } else {
        MAX_TRUECOLOR_DIMENSION
    };
    Ok(ImageCheckResult {
        has_bad_dims: has_unsupported_share_dimensions(
            decoded.width,
            decoded.height,
            max_dimension,
        ),
    })
}

pub fn prepare_image_for_mastodon_embedding(image_file_vec: &mut Vec<u8>) -> Result<()> {
    let ihdr = read_required_ihdr(image_file_vec)?;
    let first_chunk_pos = ihdr.offset + ihdr.total_size;
    compact_chunks_after_ihdr(image_file_vec, first_chunk_pos, |kind, _| {
        kind != TYPE_ICCP && kind != TYPE_SRGB
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{
        KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_SENTINEL, KDF_SENTINEL_OFFSET, MASTODON_OFFSETS,
        PDVRDT_ICCP_PREFIX, PDVRDT_SIG,
    };
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn ihdr(width: u32, height: u32, bit_depth: u8, color_type: u8) -> Vec<u8> {
        let mut data = Vec::with_capacity(IHDR_DATA_SIZE);
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[bit_depth, color_type, 0, 0, 0]);
        data
    }

    fn structural_png(width: u32, height: u32, extra_chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut png = PNG_SIGNATURE.to_vec();
        png.extend_from_slice(
            &make_png_chunk(TYPE_IHDR, &ihdr(width, height, 8, TRUECOLOR_RGB)).unwrap(),
        );
        for chunk in extra_chunks {
            png.extend_from_slice(chunk);
        }
        png.extend_from_slice(&make_png_chunk(TYPE_IEND, &[]).unwrap());
        png
    }

    fn mark_supported_profile(profile: &mut [u8], kdf_offset: usize, sig_offset: usize) {
        profile[kdf_offset..kdf_offset + 4].copy_from_slice(b"KDF2");
        profile[kdf_offset + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
        profile[kdf_offset + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;
        profile[sig_offset..sig_offset + PDVRDT_SIG.len()].copy_from_slice(PDVRDT_SIG);
    }

    #[test]
    fn exact_default_payload_detection_requires_fixed_markers() {
        let mut profile = vec![0u8; DEFAULT_OFFSETS.pdv_signature + PDVRDT_SIG.len()];
        mark_supported_profile(
            &mut profile,
            DEFAULT_OFFSETS.kdf_metadata,
            DEFAULT_OFFSETS.pdv_signature,
        );
        let mut idat = PDVRDT_IDAT_PREFIX.to_vec();
        idat.extend_from_slice(&profile);
        assert!(looks_like_pdvrdt_idat(&idat));

        let last = idat.len() - 1;
        idat[last] ^= 1;
        assert!(!looks_like_pdvrdt_idat(&idat));
    }

    #[test]
    fn trailing_idat_data_is_stripped_not_rejected() {
        fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
            let mut out = (data.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(kind);
            out.extend_from_slice(data);
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(kind);
            hasher.update(data);
            out.extend_from_slice(&hasher.finalize().to_be_bytes());
            out
        }

        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&1u32.to_be_bytes()); // width
        ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
        ihdr.extend_from_slice(&[8, TRUECOLOR_RGB, 0, 0, 0]);

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&[0u8, 1, 2, 3]).unwrap(); // filter byte + one RGB pixel
        let idat = encoder.finish().unwrap();

        let mut png = PNG_SIGNATURE.to_vec();
        png.extend_from_slice(&chunk(&TYPE_IHDR, &ihdr));
        png.extend_from_slice(&chunk(&TYPE_IDAT, &idat));
        let clean_len = png.len();
        png.extend_from_slice(&chunk(&TYPE_IEND, &[]));

        // A clean cover is left exactly as it is.
        let mut clean = png.clone();
        assert!(!strip_trailing_idat_data(&mut clean).unwrap());
        assert_eq!(clean, png);

        // A spliced-in second IDAT (the image stream has already ended) is
        // removed, restoring the original bytes rather than failing the cover.
        let mut tampered = png[..clean_len].to_vec();
        tampered.extend_from_slice(&chunk(&TYPE_IDAT, b"\x78\x5e\x5ctrailing"));
        tampered.extend_from_slice(&chunk(&TYPE_IEND, &[]));
        assert!(strip_trailing_idat_data(&mut tampered).unwrap());
        assert_eq!(tampered, png);

        // Junk appended inside the last real IDAT, so the stream ends mid-chunk:
        // the chunk is re-emitted truncated, with a corrected length and CRC.
        let mut partial = PNG_SIGNATURE.to_vec();
        partial.extend_from_slice(&chunk(&TYPE_IHDR, &ihdr));
        let mut fat = idat.clone();
        fat.extend_from_slice(b"\xAB\xCD\xEF");
        partial.extend_from_slice(&chunk(&TYPE_IDAT, &fat));
        partial.extend_from_slice(&chunk(&TYPE_IEND, &[]));
        assert!(strip_trailing_idat_data(&mut partial).unwrap());
        assert_eq!(partial, png);

        // A truncated stream never ends, so it must be left for the decoder to
        // report -- never silently cut down to whatever happened to inflate.
        let mut truncated = PNG_SIGNATURE.to_vec();
        truncated.extend_from_slice(&chunk(&TYPE_IHDR, &ihdr));
        truncated.extend_from_slice(&chunk(&TYPE_IDAT, &idat[..idat.len() / 2]));
        truncated.extend_from_slice(&chunk(&TYPE_IEND, &[]));
        let before = truncated.clone();
        assert!(!strip_trailing_idat_data(&mut truncated).unwrap());
        assert_eq!(truncated, before);
    }

    #[test]
    fn exact_mastodon_payload_detection_uses_bounded_prefix() {
        let mut profile = vec![0u8; MASTODON_OFFSETS.pdv_signature + PDVRDT_SIG.len()];
        mark_supported_profile(
            &mut profile,
            MASTODON_OFFSETS.kdf_metadata,
            MASTODON_OFFSETS.pdv_signature,
        );
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&profile).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut iccp = PDVRDT_ICCP_PREFIX.to_vec();
        iccp.extend_from_slice(&compressed);
        assert!(looks_like_pdvrdt_iccp(&iccp));

        iccp.truncate(PDVRDT_ICCP_PREFIX.len() + 2);
        assert!(!looks_like_pdvrdt_iccp(&iccp));
    }

    #[test]
    fn preflight_rejects_apng_and_profile_conflicts() {
        let apng = structural_png(68, 68, &[make_png_chunk(TYPE_ACTL, &[0; 8]).unwrap()]);
        assert!(preflight_png(&apng)
            .unwrap_err()
            .to_string()
            .contains("APNG covers are not supported"));

        let conflict = structural_png(
            68,
            68,
            &[
                make_png_chunk(TYPE_ICCP, b"p\0\0x").unwrap(),
                make_png_chunk(TYPE_SRGB, &[0]).unwrap(),
            ],
        );
        assert!(preflight_png(&conflict)
            .unwrap_err()
            .to_string()
            .contains("conflicting iCCP"));
    }

    #[test]
    fn preflight_bounds_dimensions_before_decode() {
        let png = structural_png(100_000, 100_000, &[]);
        assert!(preflight_png(&png)
            .unwrap_err()
            .to_string()
            .contains("Decoded image exceeds safety limit"));
    }

    #[test]
    fn compaction_discards_bytes_after_iend() {
        let mut png = structural_png(68, 68, &[]);
        png.extend_from_slice(b"trailing garbage");
        let ihdr = read_required_ihdr(&png).unwrap();
        let first_chunk_pos = ihdr.offset + ihdr.total_size;
        compact_chunks_after_ihdr(&mut png, first_chunk_pos, |_, _| true).unwrap();
        assert!(png.ends_with(&make_png_chunk(TYPE_IEND, &[]).unwrap()));
    }

    #[test]
    fn rgba_sbit_is_rewritten_as_valid_palette_sbit() {
        let chunk = palette_sbit_chunk(&[8, 7, 6, 5]).unwrap();
        let parsed = read_png_chunk(&chunk, 0, "header", "length", "crc").unwrap();
        assert_eq!(parsed.kind, TYPE_SBIT);
        assert_eq!(parsed.data, &[8, 7, 6]);
        assert_eq!(parsed.total_size, chunk.len());
    }

    // Reference implementation of the Adam7 layout, written straight from the
    // spec tables rather than sharing inflated_image_bytes()' loop, so the two
    // can disagree if the real one is wrong.
    fn adam7_reference(width: usize, height: usize, bits_per_pixel: usize) -> usize {
        const PASSES: [(usize, usize, usize, usize); 7] = [
            (0, 0, 8, 8),
            (4, 0, 8, 8),
            (0, 4, 4, 8),
            (2, 0, 4, 4),
            (0, 2, 2, 4),
            (1, 0, 2, 2),
            (0, 1, 1, 2),
        ];
        let mut total = 0;
        for (x_start, y_start, x_step, y_step) in PASSES {
            if width <= x_start || height <= y_start {
                continue;
            }
            let pass_width = (width - x_start).div_ceil(x_step);
            let pass_height = (height - y_start).div_ceil(y_step);
            total += ((pass_width * bits_per_pixel).div_ceil(8) + 1) * pass_height;
        }
        total
    }

    #[test]
    fn interlaced_inflated_size_matches_adam7_layout() {
        for &(w, h) in &[
            (1usize, 1usize),
            (3, 5),
            (8, 8),
            (9, 9),
            (17, 13),
            (64, 1),
            (1, 64),
            (100, 37),
            (900, 900),
        ] {
            for &bpp in &[8usize, 24, 32] {
                let non_interlaced = inflated_image_bytes(w, h, bpp, 0).unwrap();
                let interlaced = inflated_image_bytes(w, h, bpp, 1).unwrap();

                assert_eq!(non_interlaced, ((w * bpp).div_ceil(8) + 1) * h);
                assert_eq!(interlaced, adam7_reference(w, h, bpp));
                // Adam7 always costs more than the flat layout: ~1.875x the
                // filter bytes, plus per-pass row padding. The pre-fix estimate
                // used the flat formula for both, so it under-counted here.
                assert!(
                    interlaced >= non_interlaced,
                    "{w}x{h} bpp={bpp}: interlaced {interlaced} < flat {non_interlaced}"
                );
            }
        }
    }

    #[test]
    fn inflated_size_overflow_is_reported_not_wrapped() {
        assert!(inflated_image_bytes(usize::MAX, usize::MAX, 32, 0).is_err());
        assert!(inflated_image_bytes(usize::MAX, usize::MAX, 32, 1).is_err());
        assert_eq!(inflated_image_bytes(0, 10, 32, 0).unwrap(), 0);
        assert_eq!(inflated_image_bytes(10, 0, 32, 1).unwrap(), 0);
    }
}
