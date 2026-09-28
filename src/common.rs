// PNG Data Vehicle (pdvrdt) Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Conceal,
    Recover,
    Capsize,
}

/// Platform-specific conceal mode (default IDAT, Mastodon iCCP, or Reddit pixels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformOption {
    None,
    Mastodon,
    Reddit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTypeCheck {
    CoverImage,
    EmbeddedImage,
    DataFile,
    RedditCoverImage,
}

pub struct PlatformLimits {
    pub name: &'static str,
    pub max_size: usize,
    pub requires_good_dims: bool,
}

pub const PLATFORM_LIMITS: &[PlatformLimits] = &[
    PlatformLimits {
        name: "Flickr",
        max_size: 200 * 1024 * 1024,
        requires_good_dims: false,
    },
    PlatformLimits {
        name: "ImgBB",
        max_size: 32 * 1024 * 1024,
        requires_good_dims: false,
    },
    PlatformLimits {
        name: "PostImage",
        max_size: 32 * 1024 * 1024,
        requires_good_dims: false,
    },
    PlatformLimits {
        name: "ImgPile",
        max_size: 8 * 1024 * 1024,
        requires_good_dims: false,
    },
    PlatformLimits {
        name: "X-Twitter",
        max_size: 5 * 1024 * 1024,
        requires_good_dims: true,
    },
];

/// PNG signature (8) + full IHDR chunk (length 4 + type 4 + data 13 + CRC 4 = 25) = 33.
/// Mastodon-mode iCCP is inserted immediately after the IHDR chunk.
pub const MASTODON_ICCP_INSERT_INDEX: usize = 8 + 12 + 13; // 0x21

/// IEND is always length=0, so the on-disk chunk is 12 bytes (len + type + CRC).
/// Default-mode IDAT payload is inserted immediately before the trailing IEND.
pub const IEND_CHUNK_TOTAL_SIZE: usize = 12;

/// Absolute program size ceiling used for input validation and inflate bounds.
pub const MAX_PROGRAM_FILE_SIZE: usize = 3 * 1024 * 1024 * 1024;

/// Largest cover image conceal mode will accept, in bytes. Reported by `--info`
/// and named in the rejection message so the rule is discoverable before it bites.
///
/// The default and Mastodon modes share the first budget: their payload rides in
/// a PNG chunk appended to the cover, so cover size is spent directly against the
/// platform output limits. The Reddit carrier instead rewrites the pixels of a
/// cover it re-encodes from scratch, and capacity scales with dimensions, so it
/// takes a larger cover -- but one still below `REDDIT_UPLOAD_SIZE_LIMIT`, which
/// is what the finished image must satisfy.
pub const MAX_COVER_IMAGE_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_REDDIT_COVER_IMAGE_SIZE: usize = 16 * 1024 * 1024;

/// Reddit's own upload ceiling. Applies to the payload input and to the finished
/// "file-embedded" image, neither of which is bounded by the cover limit above.
pub const REDDIT_UPLOAD_SIZE_LIMIT: usize = 20 * 1024 * 1024;

/// Ceiling on the inflated size of any zlib stream inside a cover PNG, i.e. the
/// decompression-bomb guard.
///
/// Sized to clear the largest cover the conceal modes accept. The binding case is
/// the Reddit carrier's 8192x8192 limit at 8-bit RGBA, whose filtered scanlines
/// come to 8192 * (1 + 8192*4) = 268,443,648 bytes -- 8 KiB past a flat 256 MiB,
/// which is why that is not the number here. 272 MiB clears it with a little room
/// and stops there: deeper 8192-square covers (16-bit colour, at 384 MiB and up)
/// stay rejected, as they were before.
///
/// This is the single definition. `image.rs` rejects covers whose declared IHDR
/// geometry would exceed it, so the check the user sees is a clear error rather
/// than an opaque decode failure inside the `png` crate; `reddit_steg.rs` bounds
/// its own decode by the same number. All must agree for that to hold.
pub const MAX_DECODE_BYTES: usize = 272 * 1024 * 1024;

/// True if `[index, index + length)` is within `data`.
pub fn span_has_range(data: &[u8], index: usize, length: usize) -> bool {
    index <= data.len() && length <= data.len().saturating_sub(index)
}

/// Bounds-checked byte comparison at an offset: false rather than a panic when
/// the range does not fit.
pub fn bytes_equal_at(data: &[u8], index: usize, expected: &[u8]) -> bool {
    span_has_range(data, index, expected.len()) && &data[index..index + expected.len()] == expected
}

/// Bail with `message` if `[index, index + length)` is out of range.
pub fn require_span_range(data: &[u8], index: usize, length: usize, message: &str) -> Result<()> {
    if !span_has_range(data, index, length) {
        bail!("{}", message);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_range_accepts_in_bounds() {
        let data = [1u8, 2, 3, 4];
        assert!(span_has_range(&data, 0, 4));
        assert!(span_has_range(&data, 2, 2));
        assert!(span_has_range(&data, 4, 0));
        assert!(!span_has_range(&data, 3, 2));
        assert!(!span_has_range(&data, 5, 0));
    }

    #[test]
    fn insertion_constants_match_png_layout() {
        assert_eq!(MASTODON_ICCP_INSERT_INDEX, 0x21);
        assert_eq!(IEND_CHUNK_TOTAL_SIZE, 12);
    }
}
