use crate::common::{Mode, Option_};
use anyhow::{bail, Result};
use std::path::PathBuf;

pub struct ProgramArgs {
    pub mode: Mode,
    pub option: Option_,
    pub image_file_path: PathBuf,
    pub data_file_path: PathBuf,
}

pub fn display_info() {
    print!(
        r#"

PNG Data Vehicle (pdvrdt-rs v4.8 Rust port).
Created by Nicholas Cleasby (@CleasbyCode) 24/01/2023.

pdvrdt-rs is a fast, easy-to-use metadata "steganography-like" command-line tool
used for concealing and extracting any file type via a PNG image.

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

  $ pdvrdt-rs

  Usage: pdvrdt-rs conceal [-m|-r] <cover_image> <secret_file>
         pdvrdt-rs recover <cover_image>
         pdvrdt-rs --info

──────────────────────────
Platform compatibility & size limits
──────────────────────────

Share your "file-embedded" PNG image on the following compatible sites.

Size limit is measured by the combined size of cover image + compressed data file:

	• Flickr    (200 MB)
	• ImgBB     (32 MB)
	• PostImage (32 MB)
	• Reddit    (19 MB) — (use -r option).
	• Mastodon  (16 MB) — (use -m option).
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

──────────────────────────
Platform options for conceal mode
──────────────────────────

  -m (Mastodon) : Creates compatible "file-embedded" PNG images for posting on Mastodon.

      $ pdvrdt-rs conceal -m my_image.png hidden.doc

  -r (Reddit) : Creates compatible "file-embedded" PNG images for posting on Reddit.

      $ pdvrdt-rs conceal -r my_image.png secret.mp3

    From the Reddit site, click "Create Post", then select the "Images & Video" tab to attach the PNG image.
    These images are only compatible for posting on Reddit.

──────────────────────────
Notes
──────────────────────────

• To correctly download images from X-Twitter or Reddit, click image within the post to fully expand it before saving.
• ImgPile: sign in to an account before sharing; otherwise, the embedded data will not be preserved.

"#
    );
}

impl ProgramArgs {
    pub fn parse(args: &[String]) -> Result<Option<ProgramArgs>> {
        let prog = std::path::Path::new(&args[0])
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("pdvrdt-rs");

        let prefix = "Usage: ";
        let indent = " ".repeat(prefix.len());
        let usage = format!(
            "{prefix}{prog} conceal [-m|-r] <cover_image> <secret_file>\n\
             {indent}{prog} recover <cover_image>\n\
             {indent}{prog} --info"
        );

        if args.len() < 2 {
            bail!("{}", usage);
        }

        if args.len() == 2 && args[1] == "--info" {
            display_info();
            return Ok(None);
        }

        let mode_str = &args[1];

        if mode_str == "conceal" {
            let mut i = 2;
            let mut option = Option_::None;

            if i < args.len() && args[i] == "-m" {
                option = Option_::Mastodon;
                i += 1;
            } else if i < args.len() && args[i] == "-r" {
                option = Option_::Reddit;
                i += 1;
            }

            if args.len() != i + 2 {
                bail!("{}", usage);
            }

            return Ok(Some(ProgramArgs {
                mode: Mode::Conceal,
                option,
                image_file_path: PathBuf::from(&args[i]),
                data_file_path: PathBuf::from(&args[i + 1]),
            }));
        }

        if mode_str == "recover" {
            if args.len() != 3 {
                bail!("{}", usage);
            }
            return Ok(Some(ProgramArgs {
                mode: Mode::Recover,
                option: Option_::None,
                image_file_path: PathBuf::from(&args[2]),
                data_file_path: PathBuf::new(),
            }));
        }

        bail!("{}", usage);
    }
}
