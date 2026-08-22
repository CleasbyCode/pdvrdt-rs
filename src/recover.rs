use crate::binary_io::get_value;
use crate::common::{require_span_range, span_has_range};
use crate::compression::{zlib_inflate_span_bounded, zlib_inflate_to_file};
use crate::crypto::randombytes_uniform;
use crate::encryption::{
    decrypt_data_file, find_pdvrdt_iccp_payload, has_pdvrdt_profile_markers,
    minimum_stream_cipher_size, ProfileOffsets, DEFAULT_OFFSETS, MASTODON_OFFSETS,
    MAX_MASTODON_PROFILE_BYTES, PDVRDT_IDAT_PREFIX,
};
use crate::file_utils::{
    close_file_or_throw, fsync_parent_directory_no_throw, has_safe_embedded_filename,
    open_write_new_nofollow,
};
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroize;

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

fn safe_recovery_path(decrypted_filename: OsString) -> Result<PathBuf> {
    if decrypted_filename.is_empty() {
        bail!("File Recovery Error: Recovered filename is unsafe.");
    }

    let parsed = PathBuf::from(decrypted_filename);
    let filename_component = single_filename_component(&parsed)
        .ok_or_else(|| anyhow!("File Recovery Error: Recovered filename is unsafe."))?;

    let filename_path = Path::new(filename_component);
    if !has_safe_embedded_filename(filename_path) {
        bail!("File Recovery Error: Recovered filename is unsafe.");
    }

    let candidate = PathBuf::from(filename_component);
    if !candidate
        .try_exists()
        .context("Write File Error: Failed to check output path")?
    {
        return Ok(candidate);
    }

    let stem = candidate
        .file_stem()
        .map(|s| s.to_os_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| OsString::from("recovered"));
    let ext = candidate
        .extension()
        .map(|e| {
            let mut with_dot = OsString::from(".");
            with_dot.push(e);
            with_dot
        })
        .unwrap_or_default();

    for i in 1..=10000usize {
        let mut next_name = stem.clone();
        next_name.push(format!("_{}", i));
        next_name.push(&ext);
        let next = PathBuf::from(next_name);
        if !next
            .try_exists()
            .context("Write File Error: Failed to check output path")?
        {
            return Ok(next);
        }
    }

    bail!("Write File Error: Unable to create a unique output filename.");
}

fn create_staged_output_file(output_path: &Path) -> Result<StagedOutputFile> {
    const MAX_ATTEMPTS: usize = 1024;
    let parent = output_path.parent().unwrap_or_else(|| Path::new(""));
    let base = output_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| OsString::from("recovered"));

    let mut prefix = OsString::from(".");
    prefix.push(&base);
    prefix.push(".pdvrdt_tmp_");

    for _ in 0..MAX_ATTEMPTS {
        let rand_num = 100000 + randombytes_uniform(900000);
        let mut candidate_name = prefix.clone();
        candidate_name.push(format!("{}", rand_num));
        let candidate = parent.join(candidate_name);

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

/// Linux-only atomic commit using renameat2(RENAME_NOREPLACE).
fn commit_recovered_output(staged_path: &Path, output_path: &Path) -> Result<()> {
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
        return Ok(());
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EEXIST) => bail!("Write File Error: Output file already exists."),
        _ => bail!("Write File Error: Failed to commit recovered file: {}", err),
    }
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

fn locate_embedded_data(png_vec: &[u8]) -> Result<EmbeddedProfile> {
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
    if end_offset != png_vec.len() {
        bail!("Image File Error: Corrupt PNG structure. Unexpected trailing data after IEND.");
    }

    embedded_profile.ok_or_else(|| anyhow!("Image File Error: This is not a pdvrdt image."))
}

pub fn recover_data(png_vec: &mut Vec<u8>) -> Result<()> {
    let outcome = (|| -> Result<()> {
        let embedded = locate_embedded_data(png_vec)?;
        let is_mastodon = embedded.is_mastodon;
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

        let result = decrypt_data_file(png_vec, is_mastodon)?;
        let decrypted_filename = match result {
            Some(name) => name,
            None => bail!("File Recovery Error: Invalid PIN or file is corrupt."),
        };

        let output_path = safe_recovery_path(decrypted_filename)?;
        let mut staged = create_staged_output_file(&output_path)?;

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
                if let Err(err) = commit_recovered_output(&staged.path, &output_path) {
                    cleanup_path_no_throw(&staged.path);
                    return Err(err);
                }
                // renameat2() is atomic with respect to the directory entry, but
                // without this a crash can leave the final filename pointing at a
                // truncated or empty file.
                fsync_parent_directory_no_throw(&output_path);

                println!(
                    "\nExtracted hidden file: {} ({} bytes).\n\nComplete! Please check your file.\n",
                    output_path.display(),
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
        assert!(safe_recovery_path(OsString::from(".hidden")).is_err());
        assert!(safe_recovery_path(OsString::from("-dash")).is_err());
        assert!(safe_recovery_path(OsString::from("a/b")).is_err());
        assert!(safe_recovery_path(OsString::new()).is_err());
    }

    #[test]
    fn locator_rejects_malformed_png_structure() {
        let iend = png_chunk(b"IEND", &[]);

        let missing_ihdr = png_with_chunks(&[default_payload_chunk(), iend.clone()]);
        assert!(locate_embedded_data(&missing_ihdr)
            .unwrap_err()
            .to_string()
            .contains("Missing IHDR"));

        let duplicate_ihdr = png_with_chunks(&[ihdr_chunk(), ihdr_chunk(), iend.clone()]);
        assert!(locate_embedded_data(&duplicate_ihdr)
            .unwrap_err()
            .to_string()
            .contains("Duplicate IHDR"));

        let invalid_iend = png_with_chunks(&[ihdr_chunk(), png_chunk(b"IEND", &[0])]);
        assert!(locate_embedded_data(&invalid_iend)
            .unwrap_err()
            .to_string()
            .contains("Invalid IEND"));

        let mut trailing = png_with_chunks(&[ihdr_chunk(), iend]);
        trailing.push(0);
        assert!(locate_embedded_data(&trailing)
            .unwrap_err()
            .to_string()
            .contains("Unexpected trailing data"));
    }

    #[test]
    fn locator_rejects_duplicate_iccp_and_embedded_payloads() {
        let duplicate_iccp = png_with_chunks(&[
            ihdr_chunk(),
            png_chunk(b"iCCP", b"ordinary\0\0profile"),
            png_chunk(b"iCCP", b"ordinary2\0\0profile"),
            png_chunk(b"IEND", &[]),
        ]);
        assert!(locate_embedded_data(&duplicate_iccp)
            .unwrap_err()
            .to_string()
            .contains("Duplicate iCCP"));

        let duplicate_payload = png_with_chunks(&[
            ihdr_chunk(),
            default_payload_chunk(),
            default_payload_chunk(),
            png_chunk(b"IEND", &[]),
        ]);
        assert!(locate_embedded_data(&duplicate_payload)
            .unwrap_err()
            .to_string()
            .contains("Multiple embedded payloads"));
    }
}
