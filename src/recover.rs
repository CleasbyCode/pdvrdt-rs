use crate::binary_io::get_value;
use crate::common::{require_span_range, span_has_range};
use crate::compression::{zlib_inflate_span_bounded, zlib_inflate_to_file};
use crate::crypto::randombytes_uniform;
use crate::encryption::{
    decrypt_data_file_with_pin, find_pdvrdt_iccp_payload, has_pdvrdt_profile_markers,
    minimum_stream_cipher_size, ProfileOffsets, DEFAULT_OFFSETS, MASTODON_OFFSETS,
    MAX_MASTODON_PROFILE_BYTES, PDVRDT_IDAT_PREFIX,
};
use crate::file_utils::{
    close_file_or_throw, fsync_parent_directory_no_throw, has_safe_embedded_filename,
    neutralize_unsafe_code_points, open_write_new_nofollow, printable_filename,
};
use crate::pin_input::get_pin;
use crate::reddit_steg::extract_reddit_png_payload;
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroize;
use zeroize::Zeroizing;

struct StagedOutputFile {
    path: PathBuf,
    file: Option<File>,
}

#[derive(Debug)]
struct EmbeddedProfile {
    is_mastodon: bool,
    // Default mode points into the original PNG allocation. Mastodon mode owns
    // the bounded inflate result in `decompressed`.
    offset: usize,
    length: usize,
    decompressed: Vec<u8>,
}

fn single_filename_component(path: &Path) -> Option<&OsStr> {
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Some(name),
        _ => None,
    }
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    // A dangling or looping symlink still occupies this name. Inspect the
    // directory entry without following it; publication remains no-replace.
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("Write File Error: Failed to check output path"),
    }
}

/// Linux NAME_MAX: the longest single path component the kernel accepts.
const MAX_FILENAME_BYTES: usize = 255;

/// The embedded filename, validated as a bare, safe name in the current
/// directory. C1 controls and bidi-formatting characters are replaced rather
/// than refused, so a payload from an older or foreign release is still
/// recoverable.
fn validated_recovery_name(decrypted_filename: OsString) -> Result<PathBuf> {
    let raw = Zeroizing::new(decrypted_filename.into_vec());
    if raw.is_empty() {
        bail!("File Recovery Error: Recovered filename is unsafe.");
    }

    let parsed = PathBuf::from(OsString::from_vec(neutralize_unsafe_code_points(&raw)));
    let filename_component = single_filename_component(&parsed)
        .ok_or_else(|| anyhow!("File Recovery Error: Recovered filename is unsafe."))?;

    let filename_path = Path::new(filename_component);
    if !has_safe_embedded_filename(filename_path) {
        bail!("File Recovery Error: Recovered filename is unsafe.");
    }
    Ok(PathBuf::from(filename_component))
}

/// `base` with "_<index>" inserted before its extension, shortened where needed
/// to stay within NAME_MAX. The encryption layer allows 255-byte names, so
/// appending the suffix untrimmed could produce a name the kernel refuses. The
/// stem is cut on a UTF-8 sequence boundary; a pathologically long extension is
/// dropped.
fn numbered_recovery_name(base: &Path, index: usize) -> PathBuf {
    let mut stem = base
        .file_stem()
        .map(|s| s.as_bytes().to_vec())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| b"recovered".to_vec());
    let mut ext = base
        .extension()
        .map(|e| {
            let mut with_dot = b".".to_vec();
            with_dot.extend_from_slice(e.as_bytes());
            with_dot
        })
        .unwrap_or_default();
    let suffix = format!("_{index}").into_bytes();

    if ext.len() + suffix.len() >= MAX_FILENAME_BYTES {
        ext.clear();
    }
    let max_stem = MAX_FILENAME_BYTES - ext.len() - suffix.len();
    if stem.len() > max_stem {
        let mut cut = max_stem;
        while cut > 0 && stem[cut] & 0xC0 == 0x80 {
            cut -= 1;
        }
        stem.truncate(cut);
        if stem.is_empty() {
            stem = b"recovered".to_vec();
        }
    }

    let mut name = stem;
    name.extend_from_slice(&suffix);
    name.extend_from_slice(&ext);
    PathBuf::from(OsString::from_vec(name))
}

/// First free name for `base`: itself, then base_1, base_2, ...
fn find_available_recovery_path(base: &Path) -> Result<PathBuf> {
    if !path_entry_exists(base)? {
        return Ok(base.to_path_buf());
    }
    for i in 1..=10000usize {
        let next = numbered_recovery_name(base, i);
        if !path_entry_exists(&next)? {
            return Ok(next);
        }
    }
    bail!("Write File Error: Unable to create a unique output filename.");
}

/// Staged in the current directory -- the only place a recovered file is ever
/// written -- under a short fixed-shape name. Deriving the name from the
/// recovered filename would push a long (up to 255-byte) name past NAME_MAX.
fn create_staged_output_file() -> Result<StagedOutputFile> {
    const MAX_ATTEMPTS: usize = 1024;

    for _ in 0..MAX_ATTEMPTS {
        let rand_num = 100000 + randombytes_uniform(900000);
        let candidate = PathBuf::from(format!(".pdvrdt_tmp_{rand_num}"));

        match open_write_new_nofollow(&candidate)? {
            Some(file) => {
                return Ok(StagedOutputFile {
                    path: candidate,
                    file: Some(file),
                })
            }
            None => continue,
        }
    }

    bail!("Write File Error: Unable to allocate temporary output filename.");
}

fn cleanup_path_no_throw(path: &Path) {
    let _ = fs::remove_file(path);
}

/// Linux-only atomic commit using renameat2(RENAME_NOREPLACE). Returns
/// `Ok(false)` if `output_path` was taken after it was chosen, so the caller
/// can pick the next free name.
fn try_commit_recovered_output(staged_path: &Path, output_path: &Path) -> Result<bool> {
    let staged_c = CString::new(staged_path.as_os_str().as_bytes().to_vec())
        .map_err(|_| anyhow!("Write File Error: Invalid staged output path."))?;
    let output_c = CString::new(output_path.as_os_str().as_bytes().to_vec())
        .map_err(|_| anyhow!("Write File Error: Invalid output path."))?;

    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            staged_c.as_ptr(),
            libc::AT_FDCWD,
            output_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    if rc == 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EEXIST) => Ok(false),
        _ => bail!("Write File Error: Failed to commit recovered file: {}", err),
    }
}

/// Publish the staged file under the first free name derived from `base_name`.
/// Losing the race for a name is retried with the next free one rather than
/// thrown away after a full decrypt and inflate.
fn commit_to_available_name(staged_path: &Path, base_name: &Path) -> Result<PathBuf> {
    const MAX_COMMIT_ATTEMPTS: usize = 16;
    for _ in 0..MAX_COMMIT_ATTEMPTS {
        let output_path = find_available_recovery_path(base_name)?;
        if try_commit_recovered_output(staged_path, &output_path)? {
            return Ok(output_path);
        }
    }
    bail!("Write File Error: Unable to create a unique output filename.");
}

/// The payload fingerprint plus enough ciphertext to actually decrypt. Conceal's
/// stripping predicate deliberately omits the length half; see
/// has_pdvrdt_profile_markers().
fn is_recoverable_profile(profile: &[u8], offsets: &ProfileOffsets) -> bool {
    has_pdvrdt_profile_markers(profile, offsets)
        && span_has_range(
            profile,
            offsets.encrypted_file,
            minimum_stream_cipher_size(),
        )
}

fn try_locate_default_profile_in_idat(
    data_index: usize,
    idat_data: &[u8],
) -> Option<(usize, usize)> {
    if !idat_data.starts_with(PDVRDT_IDAT_PREFIX) {
        return None;
    }

    let profile = &idat_data[PDVRDT_IDAT_PREFIX.len()..];
    if !is_recoverable_profile(profile, &DEFAULT_OFFSETS) {
        return None;
    }
    Some((data_index + PDVRDT_IDAT_PREFIX.len(), profile.len()))
}

fn try_extract_mastodon_profile_from_iccp(iccp_data: &[u8]) -> Result<Option<Vec<u8>>> {
    // The cheap prefix-only identification is shared with conceal's stripping path.
    // A matching candidate is then inflated fully under the 64 MiB recovery ceiling.
    let Some(compressed_profile) = find_pdvrdt_iccp_payload(iccp_data) else {
        return Ok(None);
    };

    let profile = match zlib_inflate_span_bounded(compressed_profile, MAX_MASTODON_PROFILE_BYTES) {
        Ok(profile) => profile,
        Err(_) => return Ok(None),
    };
    if !is_recoverable_profile(&profile, &MASTODON_OFFSETS) {
        return Ok(None);
    }
    Ok(Some(profile))
}

fn locate_metadata_embedded_data(png_vec: &mut Vec<u8>) -> Result<Option<EmbeddedProfile>> {
    const PNG_SIG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const TYPE_IHDR: &[u8] = &[0x49, 0x48, 0x44, 0x52];
    const TYPE_IDAT: &[u8] = &[0x49, 0x44, 0x41, 0x54];
    const TYPE_ICCP: &[u8] = &[0x69, 0x43, 0x43, 0x50];
    const TYPE_IEND: &[u8] = &[0x49, 0x45, 0x4E, 0x44];

    require_span_range(
        png_vec,
        0,
        PNG_SIG.len(),
        "Image File Error: This is not a pdvrdt image.",
    )?;
    if &png_vec[..PNG_SIG.len()] != PNG_SIG {
        bail!("Image File Error: This is not a pdvrdt image.");
    }

    let mut embedded_profile: Option<EmbeddedProfile> = None;
    let mut has_iend = false;
    let mut has_ihdr = false;
    let mut has_iccp = false;
    let mut end_offset = 0usize;

    let mut pos = PNG_SIG.len();
    while pos < png_vec.len() {
        require_span_range(
            png_vec,
            pos,
            8,
            "Image File Error: Corrupt PNG chunk header.",
        )?;

        let chunk_len = get_value(png_vec, pos, 4)?;
        let type_index = pos + 4;
        let data_index = type_index + 4;
        if chunk_len > png_vec.len().saturating_sub(data_index)
            || 4 > png_vec.len().saturating_sub(data_index + chunk_len)
        {
            bail!("Image File Error: Corrupt PNG chunk length.");
        }

        let crc_index = data_index + chunk_len;
        require_span_range(
            png_vec,
            data_index,
            chunk_len,
            "Image File Error: Corrupt PNG chunk length.",
        )?;
        require_span_range(
            png_vec,
            crc_index,
            4,
            "Image File Error: Corrupt PNG chunk CRC.",
        )?;

        let stored_crc = get_value(png_vec, crc_index, 4)? as u32;
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&png_vec[type_index..type_index + 4 + chunk_len]);
        let computed_crc = hasher.finalize();
        if stored_crc != computed_crc {
            bail!("Image File Error: Corrupt PNG chunk CRC.");
        }

        let chunk_type = &png_vec[type_index..type_index + 4];
        let chunk_data = &png_vec[data_index..data_index + chunk_len];

        if !has_ihdr {
            if chunk_type != TYPE_IHDR || chunk_len != 13 {
                bail!("Image File Error: Corrupt PNG structure. Missing IHDR.");
            }
            has_ihdr = true;
        } else if chunk_type == TYPE_IHDR {
            bail!("Image File Error: Corrupt PNG structure. Duplicate IHDR.");
        }
        if chunk_type == TYPE_IEND && chunk_len != 0 {
            bail!("Image File Error: Corrupt PNG structure. Invalid IEND.");
        }

        if chunk_type == TYPE_ICCP {
            if has_iccp {
                bail!("Image File Error: Corrupt PNG structure. Duplicate iCCP chunk.");
            }
            has_iccp = true;
            if let Some(profile) = try_extract_mastodon_profile_from_iccp(chunk_data)? {
                if embedded_profile.is_some() {
                    bail!("Image File Error: Multiple embedded payloads detected.");
                }
                embedded_profile = Some(EmbeddedProfile {
                    is_mastodon: true,
                    offset: 0,
                    length: 0,
                    decompressed: profile,
                });
            }
        } else if chunk_type == TYPE_IDAT {
            if let Some((offset, length)) =
                try_locate_default_profile_in_idat(data_index, chunk_data)
            {
                if embedded_profile.is_some() {
                    bail!("Image File Error: Multiple embedded payloads detected.");
                }
                embedded_profile = Some(EmbeddedProfile {
                    is_mastodon: false,
                    offset,
                    length,
                    decompressed: Vec::new(),
                });
            }
        }

        if chunk_type == TYPE_IEND {
            has_iend = true;
            end_offset = crc_index + 4;
            break;
        }

        pos = crc_index + 4;
    }

    if !has_iend {
        bail!("Image File Error: Corrupt PNG structure. Missing IEND.");
    }
    // Drop anything past IEND rather than refusing the image, matching conceal:
    // compact_chunks_after_ihdr truncates a cover there without comment. Those
    // bytes are not part of the image and not part of the payload -- the chunk
    // carrying it sits before IEND and its CRC has already been checked -- so
    // failing on them only made an otherwise intact file unrecoverable. The
    // Reddit carrier below reads pixels, which the same reasoning covers.
    if end_offset != png_vec.len() {
        png_vec.truncate(end_offset);
    }

    Ok(embedded_profile)
}

pub fn recover_data(png_vec: &mut Vec<u8>) -> Result<()> {
    let outcome = (|| -> Result<()> {
        let mut is_mastodon = false;
        let mut recovery_pin = Zeroizing::new(0u64);
        if let Some(embedded) = locate_metadata_embedded_data(png_vec)? {
            // Metadata modes carry the payload in a chunk, which is locatable
            // without any secret; the PIN is only needed to decrypt.
            is_mastodon = embedded.is_mastodon;
            if is_mastodon {
                *png_vec = embedded.decompressed;
            } else {
                require_span_range(
                    png_vec,
                    embedded.offset,
                    embedded.length,
                    "Image File Error: Corrupt embedded profile location.",
                )?;
                png_vec.copy_within(embedded.offset..embedded.offset + embedded.length, 0);
                png_vec[embedded.length..].zeroize();
                png_vec.truncate(embedded.length);
            }
            get_pin(&mut recovery_pin)?;
        } else {
            // Carrier recovery derives the version-2 Argon2id key and supports
            // the version-1 key for older images. Missing carriers and wrong
            // PINs share a message; recognized corruption propagates as an error.
            get_pin(&mut recovery_pin)?;

            match extract_reddit_png_payload(png_vec, &recovery_pin)? {
                Some(profile) => *png_vec = profile,
                None => bail!("File Recovery Error: Invalid PIN, or this is not a pdvrdt image."),
            }
        }

        let result = decrypt_data_file_with_pin(png_vec, &recovery_pin, is_mastodon)?;
        let decrypted_filename = match result {
            Some(name) => name,
            None => bail!("File Recovery Error: Invalid PIN or file is corrupt."),
        };

        let base_name = validated_recovery_name(decrypted_filename)?;
        let mut staged = create_staged_output_file()?;

        let recovered_size = (|| -> Result<usize> {
            let file = staged.file.as_mut().ok_or_else(|| {
                anyhow!("Write File Error: Temporary output file is unavailable.")
            })?;
            let output_bytes = zlib_inflate_to_file(png_vec, file)?;
            file.sync_all()
                .context("Write File Error: Failed to finalize output file.")?;
            let file = staged.file.take().ok_or_else(|| {
                anyhow!("Write File Error: Temporary output file is unavailable.")
            })?;
            close_file_or_throw(file)?;
            Ok(output_bytes)
        })();

        match recovered_size {
            Ok(output_size) => {
                let output_path = match commit_to_available_name(&staged.path, &base_name) {
                    Ok(path) => path,
                    Err(err) => {
                        cleanup_path_no_throw(&staged.path);
                        return Err(err);
                    }
                };
                // renameat2() is atomic with respect to the directory entry, but
                // without this a crash can leave the final filename pointing at a
                // truncated or empty file.
                fsync_parent_directory_no_throw(&output_path);

                // The name came from the image, so escape anything a terminal
                // might act on.
                println!(
                    "\nExtracted hidden file: {} ({} bytes).\n\nComplete! Please check your file.\n",
                    printable_filename(output_path.as_os_str().as_bytes()),
                    output_size
                );
                Ok(())
            }
            Err(err) => {
                drop(staged.file.take());
                cleanup_path_no_throw(&staged.path);
                Err(err)
            }
        }
    })();

    // After decryption this allocation contains the plaintext filename prefix
    // and compressed payload. Scrub it on every success and error path.
    png_vec.zeroize();
    outcome
}

// Silence unused import if OsStringExt is only needed for from_vec in encryption.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{
        KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET, KDF_SENTINEL, KDF_SENTINEL_OFFSET, PDVRDT_SIG,
    };

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = Vec::with_capacity(data.len() + 12);
        chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(kind);
        hasher.update(data);
        chunk.extend_from_slice(&hasher.finalize().to_be_bytes());
        chunk
    }

    fn ihdr_chunk() -> Vec<u8> {
        png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0])
    }

    fn default_payload_chunk() -> Vec<u8> {
        let min_ciphertext = minimum_stream_cipher_size();
        let mut profile = vec![0u8; DEFAULT_OFFSETS.encrypted_file + min_ciphertext];
        let kdf = DEFAULT_OFFSETS.kdf_metadata;
        profile[kdf..kdf + 4].copy_from_slice(b"KDF2");
        profile[kdf + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
        profile[kdf + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;
        let sig = DEFAULT_OFFSETS.pdv_signature;
        profile[sig..sig + PDVRDT_SIG.len()].copy_from_slice(PDVRDT_SIG);
        let mut data = b"\x78\x5e\x5c".to_vec();
        data.extend_from_slice(&profile);
        png_chunk(b"IDAT", &data)
    }

    fn png_with_chunks(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        for chunk in chunks {
            png.extend_from_slice(chunk);
        }
        png
    }

    #[test]
    fn single_component_rejects_paths() {
        assert!(single_filename_component(Path::new("file.txt")).is_some());
        assert!(single_filename_component(Path::new("a/b.txt")).is_none());
        assert!(single_filename_component(Path::new("../x")).is_none());
    }

    #[test]
    fn safe_recovery_rejects_unsafe_names() {
        assert!(validated_recovery_name(OsString::from(".hidden")).is_err());
        assert!(validated_recovery_name(OsString::from("-dash")).is_err());
        assert!(validated_recovery_name(OsString::from("a/b")).is_err());
        assert!(validated_recovery_name(OsString::new()).is_err());
    }

    #[test]
    fn recovery_neutralizes_control_and_bidi_code_points() {
        let name = OsString::from_vec(b"inv\xE2\x80\xAEfdp.exe".to_vec());
        assert_eq!(
            validated_recovery_name(name).unwrap(),
            PathBuf::from("inv_fdp.exe")
        );
        let name = OsString::from_vec(b"a\xC2\x9B31mb.txt".to_vec());
        assert_eq!(
            validated_recovery_name(name).unwrap(),
            PathBuf::from("a_31mb.txt")
        );
    }

    #[test]
    fn numbered_names_stay_within_name_max() {
        assert_eq!(
            numbered_recovery_name(Path::new("file.txt"), 3),
            PathBuf::from("file_3.txt")
        );

        // A 255-byte name must still produce a usable numbered variant.
        let long = format!("{}.txt", "a".repeat(251));
        let numbered = numbered_recovery_name(Path::new(&long), 10000);
        assert_eq!(numbered.as_os_str().len(), MAX_FILENAME_BYTES);
        assert!(numbered.as_os_str().as_bytes().ends_with(b"_10000.txt"));

        // The stem is never cut inside a multi-byte UTF-8 sequence.
        // 254 bytes: "ab" then 126 two-byte 'é'. The 253-byte cut lands on the
        // second byte of an 'é', so the stem must back off to 252.
        let mut stem = b"ab".to_vec();
        stem.extend(std::iter::repeat(b"\xC3\xA9").take(126).flatten());
        let base = PathBuf::from(OsString::from_vec(stem));
        let numbered = numbered_recovery_name(&base, 7);
        assert_eq!(numbered.as_os_str().len(), 252 + 2);
        assert!(std::str::from_utf8(numbered.as_os_str().as_bytes()).is_ok());

        // A pathologically long extension is dropped rather than overflowing.
        let long_ext = format!("a.{}", "e".repeat(252));
        let numbered = numbered_recovery_name(Path::new(&long_ext), 1);
        assert!(numbered.as_os_str().len() <= MAX_FILENAME_BYTES);
    }

    #[test]
    fn locator_rejects_malformed_png_structure() {
        let iend = png_chunk(b"IEND", &[]);

        let mut missing_ihdr = png_with_chunks(&[default_payload_chunk(), iend.clone()]);
        assert!(locate_metadata_embedded_data(&mut missing_ihdr)
            .unwrap_err()
            .to_string()
            .contains("Missing IHDR"));

        let mut duplicate_ihdr = png_with_chunks(&[ihdr_chunk(), ihdr_chunk(), iend.clone()]);
        assert!(locate_metadata_embedded_data(&mut duplicate_ihdr)
            .unwrap_err()
            .to_string()
            .contains("Duplicate IHDR"));

        let mut invalid_iend = png_with_chunks(&[ihdr_chunk(), png_chunk(b"IEND", &[0])]);
        assert!(locate_metadata_embedded_data(&mut invalid_iend)
            .unwrap_err()
            .to_string()
            .contains("Invalid IEND"));

        // Bytes past IEND are dropped rather than rejected, matching conceal,
        // so an otherwise intact carrier stays recoverable.
        let clean = png_with_chunks(&[ihdr_chunk(), iend]);
        let mut trailing = clean.clone();
        trailing.extend_from_slice(b"TRAILING");
        assert!(locate_metadata_embedded_data(&mut trailing)
            .unwrap()
            .is_none());
        assert_eq!(trailing, clean);
    }

    #[test]
    fn locator_rejects_duplicate_iccp_and_embedded_payloads() {
        let mut duplicate_iccp = png_with_chunks(&[
            ihdr_chunk(),
            png_chunk(b"iCCP", b"ordinary\0\0profile"),
            png_chunk(b"iCCP", b"ordinary2\0\0profile"),
            png_chunk(b"IEND", &[]),
        ]);
        assert!(locate_metadata_embedded_data(&mut duplicate_iccp)
            .unwrap_err()
            .to_string()
            .contains("Duplicate iCCP"));

        let mut duplicate_payload = png_with_chunks(&[
            ihdr_chunk(),
            default_payload_chunk(),
            default_payload_chunk(),
            png_chunk(b"IEND", &[]),
        ]);
        assert!(locate_metadata_embedded_data(&mut duplicate_payload)
            .unwrap_err()
            .to_string()
            .contains("Multiple embedded payloads"));
    }
}
