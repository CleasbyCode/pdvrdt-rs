# pdvrdt-rs
***This is an experimental Rust port of my C++ steganography tool [***pdvrdt***](https://github.com/CleasbyCode/pdvrdt)***

***pdvrdt-rs*** is a fast, easy-to-use steganography command-line tool for concealing and extracting any file type via a **PNG** image. ***Linux only***.

It is format-compatible with the C++ ***pdvrdt***: either build can recover the other's images.

Your data file is compressed with ***flate2/zlib***, then encrypted with ***XChaCha20-Poly1305*** (***libsodium*** secretstream, via the Rust ***alkali*** bindings) under a key derived by ***Argon2id*** from a randomly generated ***recovery PIN***, and finally embedded in the cover image. The PIN is displayed once, at the end of ***conceal***, and is never stored anywhere: without it the concealed file cannot be recovered.

Using the ***default conceal mode***, you can conceal any file type, with the finished image capped at ***2GiB***. The other platform conceal modes and the compatible social media sites (*listed below*) have their own ***much smaller*** size limits and other requirements.

There is also a [***Web edition***](https://cleasbycode.co.uk/pdvrdt/app/), which you can use immediately, as a convenient alternative to downloading and compiling the CLI source code. Web file uploads are limited to **20MiB**.

![Demo Image](https://github.com/CleasbyCode/pdvrdt_rust/blob/main/demo_image/prdt_634400.png)  
*Demo Image: **"Wolf"** / ***PIN: 9120618556985469671****

## How pdvrdt-rs conceals data

Unlike the common [***LSB***](https://ctf101.org/forensics/what-is-stegonagraphy/) (*Least Significant Bit*) steganography method of concealing data within the pixels of a cover image, ***pdvrdt-rs*** mostly hides data within the ***chunks*** of a ***PNG*** image (IDAT, iCCP).

| Conceal mode | Where the data goes | Share the output image on |
| --- | --- | --- |
| *(no option)* | IDAT chunk | X-Twitter, ImgPile, PostImage, ImgBB, Flickr |
| ***-m*** | iCCP profile chunk | ***Mastodon*** (also X-Twitter, within its limits) |
| ***-r*** | RGB pixel samples (***adaptive matrix embedding***) | ***Reddit*** only |

The one platform exception to the default chunk storage method is ***Reddit***, which has its own conceal mode. ***Reddit*** re-encodes uploaded images and discards the metadata chunks the default mode relies on, so ***-r*** is the only mode that works there, and it carries the payload in the image's pixels instead.

For the ***Reddit*** conceal mode (***-r***), we use the advanced steganography method [***content-adaptive LSB matching with Hamming-code matrix embedding***](https://www.google.com/search?q=content-adaptive+LSB+matching+with+Hamming+code+matrix+embedding), a spatial-domain [***syndrome coding***](https://www.google.com/search?q=matrix+embedding+syndrome+coding+steganography) scheme, as this is the only storage method that currently works for ***Reddit***. The matrix-embedding half is the construction popularised by [***F5***](https://www.google.com/search?q=F5+steganography+algorithm), moved from JPEG coefficients to image pixels.

Each 4 bits of payload are carried by 15 RGB samples drawn from a permutation keyed by the recovery PIN, using ***(1,15,4) Hamming-syndrome matrix embedding***: the syndrome is moved to the target by a single ±1 change (*LSB matching, not LSB replacement*).  

Which sample to change is chosen by a per-sample distortion cost derived from local image activity and channel sensitivity, so edits land in textured regions rather than flat ones. Where two changes cost less than the one required change, it takes them — measured on a 4.3-megapixel cover, 93% of groups need one change, 0.4% take two and 6% need none, about 4.25 bits per changed sample.

Carrier positions are derived from the recovery PIN using ***Argon2id*** and ***ChaCha20***, so testing whether an image holds a payload costs a full ***Argon2id*** PIN guess, and recovery reports the same error for a wrong PIN as for an ordinary PNG. Keyed positions alone do not guarantee that an image is undetectable as steganography.  

***Reddit*** images created with ***pdvrdt-rs 5.2*** (or ***pdvrdt 5.2***) or later cannot be recovered by older versions. Images created with ***5.0*** and ***5.1*** remain recoverable; recreate them to gain the stronger protection.  

In the default and ***-m*** modes, by contrast, the presence of a payload-carrying chunk is visible to anyone; what is hidden is its contents.

To maximise storage capacity for the ***Reddit*** platform, use a cover image with large dimension sizes, up to the **8192x8192** maximum.  Quality of cover image is not important for this method and should be kept basic for the largest dimensions to help minimise cover image file size.

The ***-r*** mode carries far less data than the default mode, so use ***capsize*** to measure a cover image before choosing a payload (see [Checking capacity](#checking-capacity-with-capsize)).  

https://github.com/user-attachments/assets/76732196-815b-45ac-b71d-6e1aca672e25  

https://github.com/user-attachments/assets/7b448218-fe6a-4c3a-8a02-c126dd4cd830

## Requirements & Compilation (Linux)

Building requires a Rust toolchain (installed with ***rustup***) and a C compiler: ***libsodium*** is compiled from source and statically linked by `libsodium-sys-stable`, so no system ***libsodium*** package is needed.

```console
$ sudo apt update
$ sudo apt install build-essential curl

$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ source "$HOME/.cargo/env"

$ cargo build --release --locked

$ sudo cp target/release/pdvrdt-rs /usr/bin
```

## Usage

```console
$ pdvrdt-rs

Usage: pdvrdt-rs conceal [-m|-r] <cover_image> <secret_file>
       pdvrdt-rs recover <cover_image>
       pdvrdt-rs capsize <cover_image>
       pdvrdt-rs --info
```

Run `pdvrdt-rs --info` for the full built-in guide to modes, platform options and size limits.

```console
$ pdvrdt-rs conceal your_cover_image.png your_secret_file.doc

Platform compatibility for output image:-

 ✓ Flickr
 ✓ ImgBB
 ✓ PostImage
 ✓ ImgPile
 ✓ X-Twitter

Saved "file-embedded" PNG image: prdt_151529.png (143029 bytes).

Recovery PIN: [***2166776980318349924***]

Important: Keep your PIN safe, so that you can extract the hidden file.

Complete!

$ pdvrdt-rs recover prdt_151529.png

PIN: *******************

Extracted hidden file: your_secret_file.doc (6165 bytes).

Complete! Please check your file.

```

pdvrdt-rs ***mode*** arguments:

  ***conceal*** - Compresses, encrypts and embeds your secret data file within a ***PNG*** cover image.  
  ***recover*** - Decrypts, uncompresses and extracts the concealed data file from a ***PNG*** cover image.  
  ***capsize*** - Reports the adaptive carrier capacity of a cover image for ***-r*** mode. No image is saved.

Requirements for the cover image:

● PNG only. The cover must be **4MiB** or smaller in the default and ***-m*** modes; ***-r*** instead allows a cover up to **16MiB**.

● Neither side may exceed **4096** pixels in the default and ***-m*** modes. ***-r*** allows up to **8192x8192**, because its capacity comes from the pixels themselves rather than from a chunk appended to the image.

● Animated PNG (***APNG***) covers are rejected. Static PNG colour metadata is preserved.

● ***-m*** mode accepts covers with iCCP or sRGB declarations, but because its payload occupies the iCCP chunk, those declarations are replaced in the output while compatible colour metadata is retained.

● ***-r*** mode emits a non-interlaced, metadata-free, 8-bit RGB PNG, and rejects covers containing transparency.

Requirements for the secret data file:

● The embedded filename must be no longer than **20 bytes**, must not begin with `.` or `-` or end with a space or `.`, and must not contain control characters. The name is stored in the image and restored on ***recover***.

● Your data file is compressed before encryption. Recognised already-compressed file types (`.zip`, `.7z`, `.mp4`, `.jpg`, `.png`, etc) are stored in a level-0 zlib stream instead. For anything else destined for a small platform limit, consider compressing it yourself first (*zip, rar, 7z, etc.*) so that you know its exact stored size.

## Compatible Platforms

*Posting size limit measured by the ***combined*** size of the ***cover image*** + ***compressed data file:****

● ***Flickr*** (**200MB**), ***ImgBB*** (**32MB**), ***PostImage*** (**32MB**), ***ImgPile*** (**8MB**), ***X-Twitter*** (**5MB** + **dimension limits, see below*).

The source file may be larger than a platform limit: ***pdvrdt-rs*** applies the limit to the resulting compressed/encrypted representation, so a highly compressible input remains eligible when the final PNG fits.

*X-Twitter image dimension size limits:*

● ***PNG-32/24*** (*Truecolor*) **68x68** Min. — **900x900** Max.

● ***PNG-8*** (*Indexed-color*) **68x68** Min. — **4096x4096** Max.

**Other: platforms with their own conceal mode:**

● ***Mastodon*** (***-m option***). The finished "*file-embedded*" ***PNG*** must not exceed **16MiB**, so the cover image (itself capped at **4MiB** and **4096x4096**) and the compressed data file share one budget. Because the ***-m*** payload lives in a small chunk rather than the pixels, these images also remain postable on ***X-Twitter*** when they fit its own limits (**10KiB** iCCP chunk and dimensions requirements).

● ***Reddit*** (***-r option***). The cover image must be no larger than **16MiB** and **8192x8192** pixels; the data file and the finished image must each stay within Reddit's **20MiB** upload ceiling. The actual carrier capacity of the cover is ***much smaller*** than any of those numbers and depends on its dimension sizes. Use `pdvrdt-rs capsize` to measure it.

For platforms such as ***X-Twitter*** & ***ImgPile***, which have smaller data size limits, you may want to focus on data that compresses well, such as text files, etc.

***ImgPile***: sign in to an account before sharing, otherwise the embedded data will not be preserved.

## Checking capacity with capsize

***capsize*** prepares the cover image exactly as ***conceal -r*** would, then reports how much encrypted payload it can carry. Nothing is written to disk. The figures apply only to the ***Reddit*** carrier; the default and ***-m*** modes are limited by output size, not by pixel capacity.

```console
$ pdvrdt-rs capsize basic_img_large_dims.png

Reddit capacity check for conceal -r mode only.

Cover Image: 5400KiB, 1600x1600, Non-interlaced 8-bit RGB PNG, Adaptive (1,15,4) matrix embedding.

Theoretical adaptive capacity limit for this cover image:              255980 bytes (~249KiB).
Conservative maximum compressed capacity with a 20-character filename: 255762 bytes (~249KiB).
Recommended  maximum compressed capacity with a 20-character filename: 254738 bytes (~248KiB).
```

The figure reported is the total encrypted ***envelope*** capacity, not a raw secret-file limit: for a payload contained in one encryption frame, the filename, encryption and recovery metadata consume 199 to 218 bytes, and larger payloads add framing overhead. Don't aim at the theoretical limit — where capacity allows, keep the compressed payload at least **1KiB** below the conservative maximum. The size check performed by ***conceal*** is the authoritative one.

## Conceal mode platform options

To create compatible "*file-embedded*" ***PNG*** images for posting on the ***Mastodon*** platform, you must use the ***-m*** option with ***conceal*** mode.
  ```console
  $ pdvrdt-rs conceal -m my_image.png hidden.doc
```

To create compatible "*data-concealed*" ***PNG*** images for posting on the ***Reddit*** platform, you must use the ***-r*** option with ***conceal*** mode.
  ```console
  $ pdvrdt-rs conceal -r my_image.png hidden.doc
```

  These images are only compatible for posting on ***Reddit***. Your embedded data file will be lost if posted on a different platform.

  When saving/downloading an image from ***Reddit*** or ***X-Twitter*** make sure to click on the image within the post to fully expand it before saving.

## Tests

```console
$ cargo test --release --locked                # unit tests and native safety tests
$ bash src/tests/run_smoke.sh                  # quick conceal/recover smoke test
```

The remaining scripts reuse the C++ ***pdvrdt*** test fixtures, expected at `../src/tests` (a C++ ***pdvrdt*** checkout alongside this one); set `PDVRDT_CPP_TESTS` to point elsewhere. `PDVRDT_RS_BIN` selects the binary to test (default: `target/release/pdvrdt-rs`).

```console
$ bash src/tests/run_shared_regressions.sh     # C++ golden, round-trip, image, recovery-path and terminal suites
$ PDVRDT_CPP_BIN=/path/to/pdvrdt bash src/scripts/interop_matrix.sh   # C++ <-> Rust cross-recovery, both ways
$ PDVRDT_CPP_BIN=/path/to/pdvrdt bash src/scripts/parity_smoke.sh     # C++ / Rust --info text parity
```

## Third-Party Software and Assets

  This project uses or incorporates:

  - [alkali](https://github.com/tom25519/alkali) — safe Rust bindings for libsodium.
    - License: MIT OR Apache-2.0

  - [libsodium-sys-stable](https://github.com/jedisct1/libsodium-sys-stable) — libsodium FFI and
  build integration.
    - License: MIT OR Apache-2.0

  - [libsodium](https://github.com/jedisct1/libsodium) — cryptographic random generation, Argon2id
  key derivation, BLAKE2b, ChaCha20 keystreams and XChaCha20-Poly1305 secret streams.
    - Bundled version: 1.0.22, compiled and statically linked by `libsodium-sys-stable`
    - License: [ISC License](https://github.com/jedisct1/libsodium/blob/master/LICENSE)
    - Copyright (c) 2013-2026 Frank Denis

  - [png](https://github.com/image-rs/image-png) — PNG decoding and encoding.
    - License: MIT OR Apache-2.0

  - [flate2](https://github.com/rust-lang/flate2-rs) — DEFLATE and zlib-format compression and
  decompression using its pure-Rust backend.
    - License: MIT OR Apache-2.0

  - [crc32fast](https://github.com/srijs/rust-crc32fast) — CRC-32 calculation.
    - License: MIT OR Apache-2.0

  - [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) — secure clearing of
  sensitive values from memory.
    - License: MIT OR Apache-2.0

  - [anyhow](https://github.com/dtolnay/anyhow) — application error handling.
    - License: MIT OR Apache-2.0

  - [libc](https://github.com/rust-lang/libc) — Linux/POSIX system-call and terminal interfaces.
    - License: MIT OR Apache-2.0

  - [Compact ICC Profiles](https://github.com/saucecontrol/Compact-ICC-Profiles) — the Mastodon ICC
  carrier template is derived from `sRGB-v2-nano.icc`.
    - License: [CC0 1.0 Universal](https://github.com/saucecontrol/Compact-ICC-Profiles/blob/master/license)

##
