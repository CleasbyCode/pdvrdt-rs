use crate::common::{
    FileTypeCheck, PlatformOption, IEND_CHUNK_TOTAL_SIZE, MASTODON_ICCP_INSERT_INDEX,
    PLATFORM_LIMITS, REDDIT_UPLOAD_SIZE_LIMIT,
};
use crate::compression::{zlib_deflate_file, zlib_store_span};
use crate::crypto::randombytes_uniform;
use crate::encryption::{
    derive_carrier_key_from_pin, encrypt_compressed_file_to_profile,
    encrypt_prepared_data_to_profile, MAX_MASTODON_PROFILE_BYTES,
};
use crate::file_utils::{
    close_file_or_throw, embedded_filename_problem, fsync_parent_directory_no_throw,
    has_file_extension, open_input_file, open_write_new_nofollow,
};
use crate::image::{optimize_image, prepare_image_for_mastodon_embedding};
use crate::reddit_steg::{embed_reddit_png_payload, prepare_reddit_png_carrier, RedditPngCarrier};
use anyhow::{anyhow, bail, Result};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// Profile template for default mode: data stored in a custom IDAT chunk.
const DEFAULT_PROFILE: &[u8] = &[
    0x75, 0x5D, 0x19, 0x3D, 0x72, 0xCE, 0x28, 0xA5, 0x60, 0x59, 0x17, 0x98, 0x13, 0x40, 0xB4, 0xDB,
    0x3D, 0x18, 0xEC, 0x10, 0xFA, 0xE8, 0xA1, 0xC3, 0x99, 0xD1, 0xCC, 0x34, 0x72, 0xA3, 0xC5, 0xB1,
    0xEF, 0xF6, 0x12, 0x18, 0x26, 0xF3, 0xAF, 0x77, 0x16, 0x44, 0x95, 0xEA, 0xBB, 0x27, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9, 0x90, 0x82,
];

// ICC color profile template for Mastodon mode: data stored in an iCCP chunk.
const MASTODON_PROFILE: &[u8] = &[
    0x00, 0x00, 0x02, 0x98, 0x6C, 0x63, 0x6D, 0x73, 0x02, 0x10, 0x00, 0x00, 0x6D, 0x6E, 0x74, 0x72,
    0x52, 0x47, 0x42, 0x20, 0x58, 0x59, 0x5A, 0x20, 0x07, 0xE2, 0x00, 0x03, 0x00, 0x14, 0x00, 0x09,
    0x00, 0x0E, 0x00, 0x1D, 0x61, 0x63, 0x73, 0x70, 0x4D, 0x53, 0x46, 0x54, 0x00, 0x00, 0x00, 0x00,
    0x73, 0x61, 0x77, 0x73, 0x63, 0x74, 0x72, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF6, 0xD6, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xD3, 0x2D,
    0x68, 0x61, 0x6E, 0x64, 0xEB, 0x77, 0x1F, 0x3C, 0xAA, 0x53, 0x51, 0x02, 0xE9, 0x3E, 0x28, 0x6C,
    0x91, 0x46, 0xAE, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x09, 0x64, 0x65, 0x73, 0x63, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x00, 0x1C,
    0x77, 0x74, 0x70, 0x74, 0x00, 0x00, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x14, 0x72, 0x58, 0x59, 0x5A,
    0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x14, 0x67, 0x58, 0x59, 0x5A, 0x00, 0x00, 0x01, 0x34,
    0x00, 0x00, 0x00, 0x14, 0x62, 0x58, 0x59, 0x5A, 0x00, 0x00, 0x01, 0x48, 0x00, 0x00, 0x00, 0x14,
    0x72, 0x54, 0x52, 0x43, 0x00, 0x00, 0x01, 0x5C, 0x00, 0x00, 0x00, 0x34, 0x67, 0x54, 0x52, 0x43,
    0x00, 0x00, 0x01, 0x5C, 0x00, 0x00, 0x00, 0x34, 0x62, 0x54, 0x52, 0x43, 0x00, 0x00, 0x01, 0x5C,
    0x00, 0x00, 0x00, 0x34, 0x63, 0x70, 0x72, 0x74, 0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x01,
    0x64, 0x65, 0x73, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x6E, 0x52, 0x47, 0x42,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x58, 0x59, 0x5A, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF3, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x16, 0xC9,
    0x58, 0x59, 0x5A, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6F, 0xA0, 0x00, 0x00, 0x38, 0xF2,
    0x00, 0x00, 0x03, 0x8F, 0x58, 0x59, 0x5A, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x96,
    0x00, 0x00, 0xB7, 0x89, 0x00, 0x00, 0x18, 0xDA, 0x58, 0x59, 0x5A, 0x20, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x24, 0xA0, 0x00, 0x00, 0x0F, 0x85, 0x00, 0x00, 0xB6, 0xC4, 0x63, 0x75, 0x72, 0x76,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01, 0x07, 0x02, 0xB5, 0x05, 0x6B,
    0x09, 0x36, 0x0E, 0x50, 0x14, 0xB1, 0x1C, 0x80, 0x25, 0xC8, 0x30, 0xA1, 0x3D, 0x19, 0x4B, 0x40,
    0x5B, 0x27, 0x6C, 0xDB, 0x80, 0x6B, 0x95, 0xE3, 0xAD, 0x50, 0xC6, 0xC2, 0xE2, 0x31, 0xFF, 0xFF,
    0x00, 0x12, 0xB7, 0x19, 0x18, 0xA4, 0xEF, 0x15, 0x8F, 0x9E, 0x7B, 0xB4, 0xF3, 0xAA, 0x0A, 0x5C,
    0x80, 0x54, 0xAF, 0xC8, 0x0E, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9, 0x90,
];

fn size_limit_for_option(option: PlatformOption) -> (usize, &'static str) {
    const MAX_SIZE_DEFAULT: usize = 2 * 1024 * 1024 * 1024;
    const MAX_SIZE_MASTODON: usize = 16 * 1024 * 1024;

    match option {
        PlatformOption::Mastodon => (MAX_SIZE_MASTODON, "Mastodon"),
        PlatformOption::Reddit => (REDDIT_UPLOAD_SIZE_LIMIT, "Reddit"),
        PlatformOption::None => (MAX_SIZE_DEFAULT, "pdvrdt"),
    }
}

const PNG_CHUNK_OVERHEAD: usize = 12;
const DEFAULT_IDAT_PREFIX_BYTES: usize = 3;
const MASTODON_ICCP_PREFIX_BYTES: usize = 5;

fn validate_data_filename(data_file_path: &Path, data_filename: &[u8]) -> Result<()> {
    const FILENAME_MAX_LEN: usize = 20;

    if let Some(problem) = embedded_filename_problem(data_file_path) {
        bail!("Data File Error: Embedded filename is unsafe: {}.", problem);
    }

    if data_filename.len() > FILENAME_MAX_LEN {
        bail!("Data File Error: For compatibility requirements, length of data filename must not exceed 20 characters.");
    }

    Ok(())
}

fn validate_size_limit(output_size: usize, option: PlatformOption, subject: &str) -> Result<()> {
    let (limit, label) = size_limit_for_option(option);
    if output_size > limit {
        bail!(
            "File Size Error: {} exceeds maximum size limit for {}.",
            subject,
            label
        );
    }

    Ok(())
}

/// What is left of the platform's output budget once the cover image and the
/// fixed cost of the chunk carrying the payload are accounted for.
fn payload_budget(
    optimized_png_size: usize,
    option: PlatformOption,
    chunk_prefix_bytes: usize,
) -> Result<usize> {
    let (output_limit, label) = size_limit_for_option(option);
    let fixed_output_size = checked_add_size(
        optimized_png_size,
        PNG_CHUNK_OVERHEAD + chunk_prefix_bytes,
        "File Size Error: Final output size overflow.",
    )?;
    if fixed_output_size >= output_limit {
        bail!(
            "File Size Error: Cover image leaves no payload capacity for {}.",
            label
        );
    }
    Ok(output_limit - fixed_output_size)
}

fn maximum_mastodon_compressed_profile_size(optimized_png_size: usize) -> Result<usize> {
    payload_budget(
        optimized_png_size,
        PlatformOption::Mastodon,
        MASTODON_ICCP_PREFIX_BYTES,
    )
}

fn maximum_profile_size_for_encryption(
    optimized_png_size: usize,
    option: PlatformOption,
) -> Result<usize> {
    if option == PlatformOption::Mastodon {
        // The Mastodon profile is *stored* (level 0) into its iCCP chunk, so the
        // compressed form is never smaller than the profile itself -- the compressed
        // budget is therefore a valid upper bound on the profile too. Failing
        // against it here aborts encryption as soon as the payload provably cannot
        // fit, instead of building up to the 64 MiB recovery ceiling first and only
        // then discovering it is ~4x over the Mastodon limit.
        //
        // MAX_MASTODON_PROFILE_BYTES stays as the other half of the min: conceal
        // must never emit an image whose profile its own recovery path would refuse
        // to inflate.
        return Ok(
            MAX_MASTODON_PROFILE_BYTES.min(maximum_mastodon_compressed_profile_size(
                optimized_png_size,
            )?),
        );
    }
    payload_budget(optimized_png_size, option, DEFAULT_IDAT_PREFIX_BYTES)
}

/// PNG spec 5.3: a chunk's length field "must not exceed 2^31-1", not the 2^32-1
/// the four-byte field could hold. The output size limits happen to keep every
/// chunk we emit under this today, but by only ~80 bytes -- so enforce it
/// directly rather than leaving spec compliance resting on that margin.
const PNG_MAX_CHUNK_DATA_SIZE: usize = 0x7FFF_FFFF;

fn checked_chunk_data_size(payload_size: usize, chunk_diff: usize) -> Result<u32> {
    if payload_size > PNG_MAX_CHUNK_DATA_SIZE.saturating_sub(chunk_diff) {
        bail!("PNG Error: Chunk payload exceeds PNG chunk size limit.");
    }
    Ok((payload_size + chunk_diff) as u32)
}

fn checked_chunk_total_size(payload_size: usize, chunk_diff: usize) -> Result<usize> {
    Ok(checked_chunk_data_size(payload_size, chunk_diff)? as usize + PNG_CHUNK_OVERHEAD)
}

fn checked_chunk_data_size_from_parts(parts: &[&[u8]]) -> Result<u32> {
    let mut total = 0usize;
    for part in parts {
        if part.len() > PNG_MAX_CHUNK_DATA_SIZE.saturating_sub(total) {
            bail!("PNG Error: Chunk payload exceeds PNG chunk size limit.");
        }
        total += part.len();
    }
    Ok(total as u32)
}

fn checked_add_size(lhs: usize, rhs: usize, message: &str) -> Result<usize> {
    lhs.checked_add(rhs).ok_or_else(|| anyhow!("{}", message))
}

fn create_unique_output_file() -> Result<(PathBuf, File)> {
    const MAX_ATTEMPTS: usize = 2048;

    for _ in 0..MAX_ATTEMPTS {
        let rand_num = 100000 + randombytes_uniform(900000);
        let candidate = PathBuf::from(format!("prdt_{}.png", rand_num));

        match open_write_new_nofollow(&candidate)? {
            Some(file) => return Ok((candidate, file)),
            None => continue,
        }
    }

    bail!("Write Error: Unable to allocate output filename.")
}

fn write_all_or_throw(file: &mut File, data: &[u8]) -> Result<()> {
    file.write_all(data)
        .map_err(|err| anyhow!("Write Error: Failed to write complete output file: {}", err))
}

fn write_u32_or_throw(file: &mut File, value: u32) -> Result<()> {
    write_all_or_throw(file, &value.to_be_bytes())
}

fn write_chunk_from_parts(file: &mut File, chunk_type: &[u8; 4], parts: &[&[u8]]) -> Result<()> {
    let chunk_data_size = checked_chunk_data_size_from_parts(parts)?;
    write_u32_or_throw(file, chunk_data_size)?;
    write_all_or_throw(file, chunk_type)?;

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(chunk_type);

    for part in parts {
        write_all_or_throw(file, part)?;
        hasher.update(part);
    }

    write_u32_or_throw(file, hasher.finalize())
}

/// iCCP requires its profile to be a zlib stream, so the encrypted profile has to
/// be wrapped -- but it must not be *deflated*. The profile is ciphertext, which
/// is incompressible by construction: measured against a real Mastodon payload,
/// deflating it costs ~88 ms per 5.5 MiB and produces slightly *more* output than
/// storing it. Store it.
fn store_mastodon_profile(profile_data: &[u8], max_compressed_size: usize) -> Result<Vec<u8>> {
    let mut compressed_profile = Vec::new();
    zlib_store_span(profile_data, |chunk| {
        if chunk.len() > max_compressed_size.saturating_sub(compressed_profile.len()) {
            bail!("File Size Error: Compressed profile exceeds the Mastodon output size limit.");
        }
        compressed_profile.try_reserve(chunk.len()).map_err(|_| {
            anyhow!("File Size Error: Unable to allocate compressed profile buffer.")
        })?;
        compressed_profile.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(compressed_profile)
}

fn get_compatible_platforms(
    option: PlatformOption,
    output_size: usize,
    has_bad_dims: bool,
    twitter_iccp_compatible: bool,
) -> Vec<String> {
    if option == PlatformOption::Mastodon {
        if twitter_iccp_compatible && !has_bad_dims {
            return vec!["Mastodon and X-Twitter.".to_string()];
        }
        return vec![
            "Mastodon. (Only share this \"file-embedded\" PNG image on Mastodon).".to_string(),
        ];
    }
    if option == PlatformOption::Reddit {
        return vec![
            "Reddit. (Only share this \"file-embedded\" PNG image on Reddit).".to_string(),
        ];
    }

    let mut platforms: Vec<String> = Vec::new();
    for p in PLATFORM_LIMITS {
        if output_size <= p.max_size && (!p.requires_good_dims || !has_bad_dims) {
            platforms.push(p.name.to_string());
        }
    }

    if platforms.is_empty() {
        platforms.push(
            "Unknown!\n\n Due to the large file size of the output PNG image, I'm unaware of any\n\
             compatible platforms that this image can be posted on. Local use only?"
                .to_string(),
        );
    }

    platforms
}

struct SigpipeIgnoreGuard {
    old_action: libc::sigaction,
    active: bool,
}

impl SigpipeIgnoreGuard {
    fn new() -> Result<Self> {
        let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut ignore_action: libc::sigaction = unsafe { std::mem::zeroed() };
        ignore_action.sa_sigaction = libc::SIG_IGN;
        if unsafe { libc::sigemptyset(&mut ignore_action.sa_mask) } != 0
            || unsafe { libc::sigaction(libc::SIGPIPE, &ignore_action, &mut old_action) } != 0
        {
            bail!(
                "Output Error: Unable to protect output reporting: {}",
                io::Error::last_os_error()
            );
        }
        Ok(Self {
            old_action,
            active: true,
        })
    }

    fn finish(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        if unsafe { libc::sigaction(libc::SIGPIPE, &self.old_action, std::ptr::null_mut()) } != 0 {
            bail!(
                "Output Error: Unable to restore SIGPIPE handling: {}",
                io::Error::last_os_error()
            );
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for SigpipeIgnoreGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::sigaction(libc::SIGPIPE, &self.old_action, std::ptr::null_mut());
            }
        }
    }
}

fn write_stdout_checked(text: &[u8]) -> Result<()> {
    let mut sigpipe_guard = SigpipeIgnoreGuard::new()?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(text).map_err(|err| {
        anyhow!(
            "Output Error: Unable to reliably report the output filename and recovery PIN: {}",
            err
        )
    })?;
    stdout.flush().map_err(|err| {
        anyhow!(
            "Output Error: Unable to reliably report the output filename and recovery PIN: {}",
            err
        )
    })?;
    sigpipe_guard.finish()
}

fn report_output_or_throw(output_path: &Path, output_size: usize, pin: &u64) -> Result<()> {
    let report = Zeroizing::new(format!(
        "\nSaved \"file-embedded\" PNG image: {} ({} bytes).\n\nRecovery PIN: [***{}***]\n\nImportant: Keep your PIN safe, so that you can extract the hidden file.\n\nComplete!\n\n",
        output_path.display(), output_size, pin
    ));
    write_stdout_checked(report.as_bytes())
}

fn verify_file_size(file: &File, expected_size: usize) -> Result<()> {
    let actual_size = file
        .metadata()
        .map_err(|err| anyhow!("Write Error: Unable to verify output file size: {}", err))?
        .len();
    if actual_size != expected_size as u64 {
        bail!(
            "Write Error: Output file size mismatch. Expected {} bytes, wrote {} bytes.",
            expected_size,
            actual_size
        );
    }
    Ok(())
}

fn write_output_file<F>(output_size: usize, pin: &u64, writer: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    let (output_path, output_file) = create_unique_output_file()?;
    let mut output_file = Some(output_file);
    let write_result = (|| -> Result<()> {
        let file = output_file
            .as_mut()
            .ok_or_else(|| anyhow!("Write Error: Output file is unavailable."))?;
        writer(file)?;
        verify_file_size(file, output_size)?;
        file.sync_all()
            .map_err(|err| anyhow!("Write Error: Failed to finalize output file: {}", err))?;
        close_file_or_throw(
            output_file
                .take()
                .ok_or_else(|| anyhow!("Write Error: Output file is unavailable."))?,
        )?;
        fsync_parent_directory_no_throw(&output_path);
        report_output_or_throw(&output_path, output_size, pin)?;
        Ok(())
    })();

    if let Err(err) = write_result {
        // Deliberate, including when report_output_or_throw() fails *after* a
        // complete image was written and closed: the PIN exists only in this
        // process and is wiped on the way out, so an image whose PIN never
        // reached the user can never be recovered by anyone. Leaving it behind
        // would only be a confusing, permanently opaque file. Do not "fix" this
        // into keeping the output.
        drop(output_file.take());
        let _ = fs::remove_file(&output_path);
        return Err(err);
    }

    Ok(())
}

fn report_platform_compatibility(
    option: PlatformOption,
    output_size: usize,
    has_bad_dims: bool,
    twitter_iccp_compatible: bool,
) -> Result<()> {
    let platforms =
        get_compatible_platforms(option, output_size, has_bad_dims, twitter_iccp_compatible);
    let mut report = String::from("\nPlatform compatibility for output image:-\n\n");
    for platform in platforms {
        report.push_str(&format!(" ✓ {}\n", platform));
    }
    write_stdout_checked(report.as_bytes())
}

fn is_likely_compressed_input_file(path: &Path) -> bool {
    has_file_extension(
        path,
        &[
            ".zip", ".jar", ".rar", ".7z", ".bz2", ".gz", ".xz", ".lz", ".lz4", ".cab", ".rpm",
            ".deb", ".mp4", ".mp3", ".exe", ".jpg", ".jpeg", ".jfif", ".png", ".webp", ".gif",
            ".ogg", ".flac",
        ],
    )
}

fn validate_reddit_preliminary_limits(cover_size: usize, payload_size: usize) -> Result<()> {
    let cover_too_large = cover_size > REDDIT_UPLOAD_SIZE_LIMIT;
    let payload_too_large = payload_size > REDDIT_UPLOAD_SIZE_LIMIT;
    if cover_too_large && payload_too_large {
        bail!("File Size Error: Cover image and payload file exceed Reddit's 20 MiB upload size limit.");
    }
    if cover_too_large {
        bail!("Image File Size Error: Cover image exceeds Reddit's 20 MiB upload size limit.");
    }
    if payload_too_large {
        bail!("Data File Size Error: Payload file exceeds Reddit's 20 MiB upload size limit.");
    }
    Ok(())
}

fn compress_reddit_payload(
    data_file: &crate::file_utils::OpenInputFile,
    is_compressed_file: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut compressed = Zeroizing::new(Vec::new());
    zlib_deflate_file(data_file, is_compressed_file, |chunk| {
        compressed.try_reserve(chunk.len()).map_err(|_| {
            anyhow!("Data File Size Error: Reddit compressed payload size overflow.")
        })?;
        compressed.extend_from_slice(chunk);
        Ok(())
    })?;
    if compressed.is_empty() {
        bail!("File Size Error: File is zero bytes. Probable compression failure.");
    }
    Ok(compressed)
}

fn report_reddit_capacity_failure(
    carrier: &RedditPngCarrier,
    compressed_size: usize,
) -> Result<()> {
    let report = format!(
        "\nReddit carrier: {}x{}, non-interlaced 8-bit RGB PNG (adaptive (1,15,4) matrix embedding).\n\
         Compressed payload size: {} bytes.\n\
         Theoretical adaptive payload limit for this cover image: {} bytes.\n",
        carrier.width, carrier.height, compressed_size, carrier.payload_capacity
    );
    write_stdout_checked(report.as_bytes())?;
    bail!(
        "Data File Size Error: Compressed payload file size of {} bytes exceeds the theoretical maximum limit of {} bytes ({} KB) for this cover image.",
        compressed_size,
        carrier.payload_capacity,
        carrier.payload_capacity / 1000
    )
}

fn conceal_reddit_data(
    png_vec: &mut Vec<u8>,
    data_file: &crate::file_utils::OpenInputFile,
    data_file_path: &Path,
    data_filename: &[u8],
) -> Result<()> {
    const LARGE_COMPRESSED_PAYLOAD: usize = 200 * 1024;

    // Apply pdvrdt's normal validation/optimization first, then decode to the
    // metadata-free opaque RGB8 carrier shared with the C++ implementation.
    let _ = optimize_image(png_vec)?;
    let mut carrier = prepare_reddit_png_carrier(png_vec)?;
    *png_vec = Vec::new();

    let is_compressed_file = is_likely_compressed_input_file(data_file_path);
    let compressed = compress_reddit_payload(data_file, is_compressed_file)?;
    if compressed.len() > carrier.payload_capacity {
        return report_reddit_capacity_failure(&carrier, compressed.len());
    }
    if compressed.len() > LARGE_COMPRESSED_PAYLOAD {
        write_stdout_checked(
            b"\nPlease wait. Larger payloads will take longer to complete this process.\n",
        )?;
    }

    let mut profile_vec = DEFAULT_PROFILE.to_vec();
    let mut pin = Zeroizing::new(0u64);
    encrypt_prepared_data_to_profile(
        &mut pin,
        &mut profile_vec,
        &compressed,
        data_filename,
        false,
        carrier.payload_capacity,
    )?;

    // The carrier's sample positions are keyed by the PIN that was just minted,
    // so an image only reveals that it carries anything to whoever holds it.
    let carrier_key = derive_carrier_key_from_pin(&pin)?;
    let embedded_png = embed_reddit_png_payload(&mut carrier, carrier_key, &profile_vec)?;
    let output_size = embedded_png.len();
    validate_size_limit(output_size, PlatformOption::Reddit, "Final output PNG")?;
    report_platform_compatibility(PlatformOption::Reddit, output_size, false, false)?;
    write_output_file(output_size, &pin, |file| {
        write_all_or_throw(file, &embedded_png)
    })
}

pub fn conceal_data(
    png_vec: &mut Vec<u8>,
    option: PlatformOption,
    data_file_path: &Path,
) -> Result<()> {
    const LARGE_FILE_SIZE: usize = 300 * 1024 * 1024;

    let is_mastodon = option == PlatformOption::Mastodon;
    let is_reddit = option == PlatformOption::Reddit;

    let data_file = open_input_file(data_file_path, FileTypeCheck::DataFile)?;
    if is_reddit {
        validate_reddit_preliminary_limits(png_vec.len(), data_file.size())?;
    }

    let data_filename_os = data_file_path
        .file_name()
        .ok_or_else(|| anyhow!("Data File Error: Missing filename."))?;
    let data_filename = data_filename_os.as_bytes();
    validate_data_filename(data_file_path, data_filename)?;

    if data_file.size() > LARGE_FILE_SIZE {
        write_stdout_checked(
            b"\nPlease wait. Larger files will take longer to complete this process.\n",
        )?;
    }

    if is_reddit {
        return conceal_reddit_data(png_vec, &data_file, data_file_path, data_filename);
    }

    let has_bad_dims = optimize_image(png_vec)?.has_bad_dims;
    if is_mastodon {
        prepare_image_for_mastodon_embedding(png_vec)?;
    }

    let is_compressed = is_likely_compressed_input_file(data_file_path);

    // Fail before spending Argon2 + encryption on a payload that provably cannot
    // fit. Sound only for already-compressed inputs: those are *stored*, not
    // deflated (see payload_deflate_level in compression.rs), so the profile is
    // guaranteed to be at least as large as the input. A compressible payload may
    // still shrink under the limit, so it is checked the slow way as it streams.
    if is_mastodon
        && is_compressed
        && data_file.size() > maximum_mastodon_compressed_profile_size(png_vec.len())?
    {
        bail!(
            "File Size Error: \"{}\" is {} bytes and is already in a compressed format, \
             so it cannot be reduced to fit the Mastodon size limit.",
            Path::new(data_filename_os).display(),
            data_file.size()
        );
    }

    // Prepare the profile template.
    let mut profile_vec = if is_mastodon {
        MASTODON_PROFILE.to_vec()
    } else {
        DEFAULT_PROFILE.to_vec()
    };

    let max_profile_size = maximum_profile_size_for_encryption(png_vec.len(), option)?;
    // Owns the PIN from generation until the write finishes or any post-encrypt
    // path fails; encrypt_compressed_file_to_profile() fills it in place.
    let mut pin = Zeroizing::new(0u64);
    encrypt_compressed_file_to_profile(
        &mut pin,
        &mut profile_vec,
        &data_file,
        data_filename,
        is_compressed,
        is_mastodon,
        max_profile_size,
    )?;

    if is_mastodon {
        const TWITTER_ICCP_MAX_CHUNK_SIZE: usize = 10 * 1024;
        const TWITTER_IMAGE_MAX_SIZE: usize = 5 * 1024 * 1024;
        const TYPE_ICCP: &[u8; 4] = b"iCCP";
        const ICCP_PREFIX: &[u8; 5] = b"icc\0\0";

        if MASTODON_ICCP_INSERT_INDEX > png_vec.len() {
            bail!("Image File Error: Invalid PNG insertion point for iCCP chunk.");
        }
        let max_compressed_profile_size = maximum_mastodon_compressed_profile_size(png_vec.len())?;
        let compressed_profile = store_mastodon_profile(&profile_vec, max_compressed_profile_size)?;
        let mastodon_chunk_size =
            checked_chunk_data_size(compressed_profile.len(), MASTODON_ICCP_PREFIX_BYTES)? as usize;
        let output_size = checked_add_size(
            png_vec.len(),
            checked_chunk_total_size(compressed_profile.len(), MASTODON_ICCP_PREFIX_BYTES)?,
            "File Size Error: Final output size overflow.",
        )?;

        let twitter_iccp_compatible = output_size <= TWITTER_IMAGE_MAX_SIZE
            && mastodon_chunk_size <= TWITTER_ICCP_MAX_CHUNK_SIZE;

        validate_size_limit(output_size, option, "Final output PNG")?;
        report_platform_compatibility(option, output_size, has_bad_dims, twitter_iccp_compatible)?;

        write_output_file(output_size, &pin, |file| {
            write_all_or_throw(file, &png_vec[..MASTODON_ICCP_INSERT_INDEX])?;
            write_chunk_from_parts(
                file,
                TYPE_ICCP,
                &[ICCP_PREFIX, compressed_profile.as_slice()],
            )?;
            write_all_or_throw(file, &png_vec[MASTODON_ICCP_INSERT_INDEX..])?;
            Ok(())
        })?;
    } else {
        if png_vec.len() < IEND_CHUNK_TOTAL_SIZE {
            bail!("Image File Error: Invalid PNG insertion point for IDAT chunk.");
        }
        // Insert payload IDAT immediately before the trailing IEND chunk.
        let insert_index = png_vec.len() - IEND_CHUNK_TOTAL_SIZE;
        const TYPE_IDAT: &[u8; 4] = b"IDAT";
        const IDAT_PREFIX: &[u8; 3] = b"\x78\x5E\x5C";

        let output_size = checked_add_size(
            png_vec.len(),
            checked_chunk_total_size(profile_vec.len(), DEFAULT_IDAT_PREFIX_BYTES)?,
            "File Size Error: Final output size overflow.",
        )?;

        validate_size_limit(output_size, option, "Final output PNG")?;
        report_platform_compatibility(option, output_size, has_bad_dims, false)?;

        write_output_file(output_size, &pin, |file| {
            write_all_or_throw(file, &png_vec[..insert_index])?;
            write_chunk_from_parts(file, TYPE_IDAT, &[IDAT_PREFIX, profile_vec.as_slice()])?;
            write_all_or_throw(file, &png_vec[insert_index..])?;
            Ok(())
        })?;
    }

    Ok(())
}
