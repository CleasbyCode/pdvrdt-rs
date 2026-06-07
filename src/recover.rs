use crate::binary_io::get_value;
use crate::compression::{zlib_inflate_span_bounded, zlib_inflate_to_file};
use crate::encryption::{
    decrypt_data_file, ProfileOffsets, DEFAULT_OFFSETS, KDF_ALG_ARGON2ID13, KDF_ALG_OFFSET,
    KDF_MAGIC_OFFSET, KDF_METADATA_REGION_BYTES, KDF_SENTINEL, KDF_SENTINEL_OFFSET,
    MASTODON_OFFSETS,
};
use crate::file_utils::has_valid_filename;
use anyhow::{anyhow, bail, Context, Result};
use crate::crypto::randombytes_uniform;
use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

struct StagedOutputFile {
    path: PathBuf,
    file: Option<File>,
}

struct EmbeddedProfile {
    profile: Vec<u8>,
    is_mastodon: bool,
}

fn span_has_range(data: &[u8], index: usize, length: usize) -> bool {
    index <= data.len() && length <= data.len().saturating_sub(index)
}

fn require_span_range(data: &[u8], index: usize, length: usize, message: &str) -> Result<()> {
    if !span_has_range(data, index, length) {
        bail!("{}", message);
    }
    Ok(())
}

fn single_filename_component(path: &Path) -> Option<&OsStr> {
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Some(name),
        _ => None,
    }
}

fn safe_recovery_path(decrypted_filename: String) -> Result<PathBuf> {
    if decrypted_filename.is_empty() {
        bail!("File Recovery Error: Recovered filename is unsafe.");
    }

    let parsed = PathBuf::from(decrypted_filename);
    let filename_component = single_filename_component(&parsed)
        .ok_or_else(|| anyhow!("File Recovery Error: Recovered filename is unsafe."))?;

    let filename_path = Path::new(filename_component);
    if !has_valid_filename(filename_path) {
        bail!("File Recovery Error: Recovered filename is unsafe.");
    }

    let candidate = PathBuf::from(filename_component);
    if !candidate.exists() {
        return Ok(candidate);
    }

    let stem = candidate
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("recovered");
    let ext = candidate
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e))
        .unwrap_or_default();

    for i in 1..=10000usize {
        let next = PathBuf::from(format!("{}_{}{}", stem, i, ext));
        if !next.exists() {
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
        .and_then(|n| n.to_str())
        .unwrap_or("recovered");
    let prefix = format!(".{}.pdvrdt_tmp_", base);

    for _ in 0..MAX_ATTEMPTS {
        let rand_num = 100000 + randombytes_uniform(900000);
        let candidate = parent.join(format!("{}{}", prefix, rand_num));

        let mut open_opts = OpenOptions::new();
        open_opts.write(true).create_new(true).mode(0o600);

        let mut flags = libc::O_CLOEXEC;
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "macos",
            target_os = "ios"
        ))]
        {
            flags |= libc::O_NOFOLLOW;
        }
        open_opts.custom_flags(flags);

        match open_opts.open(&candidate) {
            Ok(file) => {
                return Ok(StagedOutputFile {
                    path: candidate,
                    file: Some(file),
                })
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                bail!(
                    "Write File Error: Unable to create temp output file: {}",
                    err
                );
            }
        }
    }

    bail!("Write File Error: Unable to allocate temporary output filename.");
}

fn cleanup_path_no_throw(path: &Path) {
    let _ = fs::remove_file(path);
}

fn commit_recovered_output(staged_path: &Path, output_path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
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
            Some(libc::ENOSYS) | Some(libc::EINVAL) => {}
            Some(libc::EEXIST) => bail!("Write File Error: Output file already exists."),
            _ => bail!("Write File Error: Failed to commit recovered file: {}", err),
        }
    }

    if output_path.exists() {
        bail!("Write File Error: Output file already exists.");
    }
    fs::rename(staged_path, output_path)
        .with_context(|| "Write File Error: Failed to commit recovered file.")?;
    Ok(())
}

fn has_kdf_metadata(profile: &[u8], offsets: &ProfileOffsets) -> bool {
    if !span_has_range(profile, offsets.kdf_metadata, KDF_METADATA_REGION_BYTES) {
        return false;
    }

    let base = offsets.kdf_metadata;
    let magic = &profile[base + KDF_MAGIC_OFFSET..base + KDF_MAGIC_OFFSET + 4];
    magic == b"KDF2"
        && profile[base + KDF_ALG_OFFSET] == KDF_ALG_ARGON2ID13
        && profile[base + KDF_SENTINEL_OFFSET] == KDF_SENTINEL
        && offsets.encrypted_file < profile.len()
}

fn has_pdv_signature(data: &[u8]) -> bool {
    const PDV_SIG: &[u8] = &[0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9];
    data.windows(PDV_SIG.len()).any(|w| w == PDV_SIG)
}

fn try_extract_default_profile_from_idat(idat_data: &[u8]) -> Option<Vec<u8>> {
    const IDAT_PREFIX: &[u8] = &[0x78, 0x5E, 0x5C];
    if !idat_data.starts_with(IDAT_PREFIX) {
        return None;
    }

    let profile = &idat_data[IDAT_PREFIX.len()..];
    if profile.is_empty()
        || !has_kdf_metadata(profile, &DEFAULT_OFFSETS)
        || !has_pdv_signature(profile)
    {
        return None;
    }
    Some(profile.to_vec())
}

fn try_extract_mastodon_profile_from_iccp(iccp_data: &[u8]) -> Result<Option<Vec<u8>>> {
    const ICCP_PREFIX: &[u8] = &[0x69, 0x63, 0x63, 0x00, 0x00]; // "icc\0" + deflate method
    const MAX_MASTODON_PROFILE_INFLATE_SIZE: usize = 64 * 1024 * 1024;

    if !iccp_data.starts_with(ICCP_PREFIX) {
        return Ok(None);
    }

    let compressed_profile = &iccp_data[ICCP_PREFIX.len()..];
    if compressed_profile.is_empty() {
        return Ok(None);
    }

    let profile = zlib_inflate_span_bounded(compressed_profile, MAX_MASTODON_PROFILE_INFLATE_SIZE)?;
    if profile.is_empty()
        || !has_kdf_metadata(&profile, &MASTODON_OFFSETS)
        || !has_pdv_signature(&profile)
    {
        return Ok(None);
    }
    Ok(Some(profile))
}

fn locate_embedded_data(png_vec: &[u8]) -> Result<EmbeddedProfile> {
    const PNG_SIG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
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

    let mut default_profile: Option<Vec<u8>> = None;
    let mut mastodon_profile: Option<Vec<u8>> = None;
    let mut has_iend = false;

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

        if chunk_type == TYPE_ICCP {
            if let Some(profile) = try_extract_mastodon_profile_from_iccp(chunk_data)? {
                mastodon_profile = Some(profile);
            }
        } else if chunk_type == TYPE_IDAT {
            if let Some(profile) = try_extract_default_profile_from_idat(chunk_data) {
                default_profile = Some(profile);
            }
        }

        if chunk_type == TYPE_IEND {
            has_iend = true;
            break;
        }

        pos = crc_index + 4;
    }

    if !has_iend {
        bail!("Image File Error: Corrupt PNG structure. Missing IEND.");
    }

    if let Some(profile) = mastodon_profile {
        return Ok(EmbeddedProfile {
            profile,
            is_mastodon: true,
        });
    }
    if let Some(profile) = default_profile {
        return Ok(EmbeddedProfile {
            profile,
            is_mastodon: false,
        });
    }
    bail!("Image File Error: This is not a pdvrdt image.");
}

pub fn recover_data(png_vec: &mut Vec<u8>) -> Result<()> {
    let embedded = locate_embedded_data(png_vec)?;
    *png_vec = embedded.profile;

    let result = decrypt_data_file(png_vec, embedded.is_mastodon)?;
    let decrypted_filename = match result {
        Some(name) => name,
        None => bail!("File Recovery Error: Invalid PIN or file is corrupt."),
    };

    let output_path = safe_recovery_path(decrypted_filename)?;
    let mut staged = create_staged_output_file(&output_path)?;

    let recovered_size = (|| -> Result<usize> {
        let file = staged
            .file
            .as_mut()
            .ok_or_else(|| anyhow!("Write File Error: Temporary output file is unavailable."))?;
        let output_bytes = zlib_inflate_to_file(png_vec, file)?;
        file.sync_all()
            .context("Write File Error: Failed to finalize output file.")?;
        Ok(output_bytes)
    })();

    match recovered_size {
        Ok(output_size) => {
            drop(staged.file.take());
            if let Err(err) = commit_recovered_output(&staged.path, &output_path) {
                cleanup_path_no_throw(&staged.path);
                return Err(err);
            }

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
}
