// PNG Data Vehicle (pdvrdt) Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Conceal,
    Recover,
}

/// Platform-specific conceal mode (default IDAT, or Mastodon iCCP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformOption {
    None,
    Mastodon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTypeCheck {
    CoverImage,
    EmbeddedImage,
    DataFile,
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
pub const MAX_COVER_IMAGE_SIZE: usize = 8 * 1024 * 1024;

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
