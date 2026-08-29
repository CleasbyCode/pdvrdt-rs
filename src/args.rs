use crate::common::{Mode, PlatformOption, MAX_COVER_IMAGE_SIZE, REDDIT_UPLOAD_SIZE_LIMIT};
use anyhow::{bail, Result};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

// The limits quoted in the --info text below are prose, so pin them to the
// constants they describe: the help text cannot silently drift out of date.
const _: () = assert!(
    MAX_COVER_IMAGE_SIZE == 8 * 1024 * 1024,
    "--info quotes an 8 MB cover-image limit; keep it in step with MAX_COVER_IMAGE_SIZE."
);
const _: () = assert!(
    REDDIT_UPLOAD_SIZE_LIMIT == 20 * 1024 * 1024,
    "--info quotes a 20 MiB Reddit input limit; keep it in step with REDDIT_UPLOAD_SIZE_LIMIT."
);

pub struct ProgramArgs {
    pub mode: Mode,
    pub option: PlatformOption,
    pub image_file_path: PathBuf,
    pub data_file_path: PathBuf,
}

/// Single source of truth for the reported version: taken from Cargo.toml, so
/// bumping the package version is the only edit needed. Displayed as MAJOR.MINOR
/// to match the C++ implementation's `--info` output.
const DISPLAY_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION_MAJOR"),
    ".",
    env!("CARGO_PKG_VERSION_MINOR")
);

pub fn display_info() {
    print!("\n\nPNG Data Vehicle (pdvrdt-rs v{DISPLAY_VERSION})\n");
    print!(
        r#"Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023.

pdvrdt-rs is a "steganography-like" command-line tool used for concealing and extracting
any file type within and from a PNG image. Default and Mastodon modes carry the payload
in PNG metadata chunks; Reddit mode carries it in the image pixels themselves.

──────────────────────────
Build & install (Linux)
──────────────────────────

  Requirements: Rust toolchain (rustup), libsodium-dev, pkg-config.

  $ sudo apt install libsodium-dev pkg-config
  $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

  $ cargo build --release

  Build complete. Binary at 'target/release/pdvrdt-rs'.

  $ sudo cp target/release/pdvrdt-rs /usr/bin

──────────────────────────
Usage
──────────────────────────

  pdvrdt-rs conceal [-m|-r] <cover_image> <secret_file>
  pdvrdt-rs recover <cover_image>
  pdvrdt-rs capsize <cover_image>
  pdvrdt-rs --info

──────────────────────────
Platform compatibility & size limits
──────────────────────────

Input limit: the PNG cover image must normally be 8 MiB or smaller. Reddit mode
instead permits a cover up to 20 MiB and also limits its payload input to 20 MiB.
Other modes have no separate payload-input limit; their output limit applies
after compression.

Share your "file-embedded" PNG image on the following compatible sites.

Except for Reddit's adaptive in-pixel carrier, size limits are measured by the
combined size of cover image + compressed data file:

The original file may be larger than a platform limit. The limit is applied
after compression, so a larger, highly compressible input can still succeed.

	• Flickr    (200 MB)
	• ImgBB     (32 MB)
	• PostImage (32 MB)
	• Mastodon  (16 MiB) — (use -m option).
	• Reddit    (20 MiB input limit per cover and payload) — (use -r option).
	• ImgPile   (8 MB)
	• X-Twitter (5 MB)  — (*Dimension size limits).

X-Twitter Image Dimension Size Limits:

	• PNG-32/24 (Truecolor) 68x68 Min. <-> 900x900 Max.
	• PNG-8 (Indexed-color) 68x68 Min. <-> 4096x4096 Max.

──────────────────────────
Modes
──────────────────────────

  conceal - Compresses, encrypts and embeds your secret data file within a PNG cover image.
  recover - Decrypts, uncompresses and extracts the concealed data file from a PNG cover image
            (recovery PIN required).
  capsize - Test-prepares a cover image and reports its adaptive Reddit carrier capacity.
            This information applies only to conceal -r; no image is saved.

──────────────────────────
Platform option for conceal mode
──────────────────────────

  -m (Mastodon) : Creates compatible "file-embedded" PNG images for posting on Mastodon.

      $ pdvrdt-rs conceal -m my_image.png hidden.doc

  -r (Reddit) : Creates an adaptive spatial "file-embedded" RGB PNG for Reddit.

      $ pdvrdt-rs conceal -r my_image.png hidden.doc

      Use "pdvrdt-rs capsize my_image.png" to inspect a Reddit cover before choosing a payload.

      Method: content-adaptive spatial embedding in the pixel LSBs. Each 4 bits of
      payload is carried by 15 RGB samples drawn from a permutation keyed by the
      recovery PIN, using (1,15,4) Hamming-syndrome matrix embedding: the syndrome
      is moved to the target by a single +/-1 change (LSB matching, not LSB
      replacement). Which sample to change is chosen by a per-sample distortion
      cost from local image activity and channel sensitivity, so edits land in
      textured regions rather than flat ones. Where two changes cost less than the
      one required change, it takes them -- measured on a 4.3-megapixel cover, 93%
      of groups need one change, 0.4% take two and 6% need none, about 4.25 bits
      per changed sample.

      Because the sample positions come from the PIN, an image reveals nothing
      without it: a wrong PIN and an ordinary PNG are indistinguishable.

      Reddit cover and payload input files must each be no larger than 20 MiB.
      The payload is compressed before its carrier-capacity check.

──────────────────────────
Notes
──────────────────────────

• To correctly download images from X-Twitter, click image within the post to fully expand it before saving.
• ImgPile: sign in to an account before sharing; otherwise, the embedded data will not be preserved.
• Animated PNG (APNG) covers are not supported. Static PNG color metadata is preserved.
• Mastodon mode accepts iCCP/sRGB covers. Because its payload uses iCCP, those profile declarations are replaced; compatible color metadata is retained.
• Reddit mode emits a non-interlaced, metadata-free, 8-bit RGB PNG. Covers containing transparency are not supported.
• Default and Mastodon modes carry the payload in a PNG chunk. That a chunk is present is visible to
  anyone; what is hidden is its contents. Reddit mode instead derives its carrier positions from the
  recovery PIN, so without the PIN there is nothing to locate.

"#
    );
}

impl ProgramArgs {
    pub fn parse(args: &[OsString]) -> Result<Option<ProgramArgs>> {
        let prog = args
            .first()
            .and_then(|arg0| std::path::Path::new(arg0).file_name())
            .filter(|name| !name.is_empty())
            .map(OsStr::to_string_lossy)
            .unwrap_or_else(|| "pdvrdt-rs".into());

        let prefix = "Usage: ";
        let indent = " ".repeat(prefix.len());
        let usage = format!(
            "{prefix}{prog} conceal [-m|-r] <cover_image> <secret_file>\n\
             {indent}{prog} recover <cover_image>\n\
             {indent}{prog} capsize <cover_image>\n\
             {indent}{prog} --info"
        );

        if args.len() < 2 {
            bail!("{}", usage);
        }

        if args.len() == 2 && args[1] == OsStr::new("--info") {
            display_info();
            return Ok(None);
        }

        let mode = args[1].as_os_str();

        if mode == OsStr::new("conceal") {
            let mut i = 2;
            let mut option = PlatformOption::None;

            if i < args.len() && (args[i] == OsStr::new("-m") || args[i] == OsStr::new("-r")) {
                option = if args[i] == OsStr::new("-m") {
                    PlatformOption::Mastodon
                } else {
                    PlatformOption::Reddit
                };
                i += 1;
            }

            if args.len() != i + 2 || args[i].is_empty() || args[i + 1].is_empty() {
                bail!("{}", usage);
            }

            return Ok(Some(ProgramArgs {
                mode: Mode::Conceal,
                option,
                image_file_path: PathBuf::from(&args[i]),
                data_file_path: PathBuf::from(&args[i + 1]),
            }));
        }

        if mode == OsStr::new("recover") {
            if args.len() != 3 || args[2].is_empty() {
                bail!("{}", usage);
            }
            return Ok(Some(ProgramArgs {
                mode: Mode::Recover,
                option: PlatformOption::None,
                image_file_path: PathBuf::from(&args[2]),
                data_file_path: PathBuf::new(),
            }));
        }

        if mode == OsStr::new("capsize") {
            if args.len() != 3 || args[2].is_empty() {
                bail!("{}", usage);
            }
            return Ok(Some(ProgramArgs {
                mode: Mode::Capsize,
                option: PlatformOption::Reddit,
                image_file_path: PathBuf::from(&args[2]),
                data_file_path: PathBuf::new(),
            }));
        }

        bail!("{}", usage);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(|part| OsString::from(*part)).collect()
    }

    #[test]
    fn parse_conceal_default() {
        let a = args(&["pdvrdt-rs", "conceal", "cover.png", "secret.txt"]);
        let p = ProgramArgs::parse(&a).unwrap().unwrap();
        assert_eq!(p.mode, Mode::Conceal);
        assert_eq!(p.option, PlatformOption::None);
        assert_eq!(p.image_file_path, PathBuf::from("cover.png"));
        assert_eq!(p.data_file_path, PathBuf::from("secret.txt"));
    }

    #[test]
    fn parse_conceal_platform_flags() {
        let m = ProgramArgs::parse(&args(&["pdvrdt-rs", "conceal", "-m", "a.png", "b.bin"]))
            .unwrap()
            .unwrap();
        assert_eq!(m.option, PlatformOption::Mastodon);

        let r = ProgramArgs::parse(&args(&["pdvrdt-rs", "conceal", "-r", "a.png", "b.bin"]))
            .unwrap()
            .unwrap();
        assert_eq!(r.option, PlatformOption::Reddit);
    }

    #[test]
    fn parse_recover() {
        let p = ProgramArgs::parse(&args(&["pdvrdt-rs", "recover", "out.png"]))
            .unwrap()
            .unwrap();
        assert_eq!(p.mode, Mode::Recover);
        assert_eq!(p.image_file_path, PathBuf::from("out.png"));
    }

    #[test]
    fn parse_capsize() {
        let p = ProgramArgs::parse(&args(&["pdvrdt-rs", "capsize", "cover.png"]))
            .unwrap()
            .unwrap();
        assert_eq!(p.mode, Mode::Capsize);
        assert_eq!(p.option, PlatformOption::Reddit);
        assert_eq!(p.image_file_path, PathBuf::from("cover.png"));
        assert!(p.data_file_path.as_os_str().is_empty());
    }

    #[test]
    fn parse_info_returns_none() {
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "--info"]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_rejects_bad_usage() {
        assert!(ProgramArgs::parse(&[]).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs"])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "conceal", "only.png"])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "recover"])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "capsize"])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "capsize", "a.png", "b.png"])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "nope"])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "conceal", "", "secret.txt"])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "recover", ""])).is_err());
        assert!(ProgramArgs::parse(&args(&["pdvrdt-rs", "capsize", ""])).is_err());
    }

    #[test]
    fn empty_or_non_utf8_program_name_uses_safe_usage_label() {
        let empty_error = ProgramArgs::parse(&args(&[""])).err().unwrap().to_string();
        assert!(empty_error.starts_with("Usage: pdvrdt-rs conceal"));

        let raw_program = OsString::from_vec(b"pdvrdt-\xFF".to_vec());
        let raw_error = ProgramArgs::parse(&[raw_program])
            .err()
            .unwrap()
            .to_string();
        assert!(raw_error.starts_with("Usage: pdvrdt-\u{FFFD} conceal"));
    }

    #[test]
    fn parse_preserves_non_utf8_path_bytes() {
        let cover = OsString::from_vec(b"cover-\xFF.png".to_vec());
        let secret = OsString::from_vec(b"secret-\xFE.bin".to_vec());
        let parsed = ProgramArgs::parse(&[
            OsString::from("pdvrdt-rs"),
            OsString::from("conceal"),
            cover.clone(),
            secret.clone(),
        ])
        .unwrap()
        .unwrap();

        assert_eq!(
            parsed.image_file_path.as_os_str().as_bytes(),
            cover.as_bytes()
        );
        assert_eq!(
            parsed.data_file_path.as_os_str().as_bytes(),
            secret.as_bytes()
        );
    }
}
