// PNG Data Vehicle (pdvrdt v4.8) Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023

#[allow(dead_code)]
pub const TAG_BYTES: usize = 16; // crypto_secretbox_MACBYTES

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Conceal,
    Recover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Option_ {
    None,
    Mastodon,
    Reddit,
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
