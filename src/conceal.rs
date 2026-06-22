use crate::common::{FileTypeCheck, Option_, PLATFORM_LIMITS};
use crate::compression::zlib_deflate_span;
use crate::encryption::encrypt_compressed_file_to_profile;
use crate::file_utils::{get_file_size_checked, has_file_extension, has_safe_embedded_filename};
use crate::image::optimize_image;
use anyhow::{anyhow, bail, Result};
use crate::crypto::randombytes_uniform;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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

fn size_limit_for_option(option: Option_) -> (usize, &'static str) {
    const MAX_SIZE_DEFAULT: usize = 2 * 1024 * 1024 * 1024;
    const MAX_SIZE_REDDIT: usize = 20 * 1024 * 1024;
    const MAX_SIZE_MASTODON: usize = 16 * 1024 * 1024;

    match option {
        Option_::Mastodon => (MAX_SIZE_MASTODON, "Mastodon"),
        Option_::Reddit => (MAX_SIZE_REDDIT, "Reddit"),
        Option_::None => (MAX_SIZE_DEFAULT, "pdvrdt"),
    }
}

fn validate_inputs(
    combined_size: usize,
    data_file_path: &Path,
    data_filename: &str,
    option: Option_,
) -> Result<()> {
    const FILENAME_MAX_LEN: usize = 20;

    if !has_safe_embedded_filename(data_file_path) {
        bail!("Data File Error: Embedded filename is unsafe. Filenames may not begin with '.' or '-'.");
    }

    if data_filename.len() > FILENAME_MAX_LEN {
        bail!("Data File Error: For compatibility requirements, length of data filename must not exceed 20 characters.");
    }

    let (limit, label) = size_limit_for_option(option);
    if combined_size > limit {
        bail!(
            "File Size Error: Combined size of image and data file exceeds maximum size limit for {}.",
            label
        );
    }

    Ok(())
}

fn validate_output_size(output_size: usize, option: Option_) -> Result<()> {
    let (limit, label) = size_limit_for_option(option);
    if output_size > limit {
        bail!(
            "File Size Error: Final output PNG exceeds maximum size limit for {}.",
            label
        );
    }

    Ok(())
}

fn checked_chunk_data_size(payload_size: usize, chunk_diff: usize) -> Result<u32> {
    if payload_size > (u32::MAX as usize).saturating_sub(chunk_diff) {
        bail!("PNG Error: Chunk payload exceeds PNG chunk size limit.");
    }
    Ok((payload_size + chunk_diff) as u32)
}

fn checked_chunk_total_size(payload_size: usize, chunk_diff: usize) -> Result<usize> {
    Ok(checked_chunk_data_size(payload_size, chunk_diff)? as usize + 12)
}

fn checked_chunk_data_size_from_parts(parts: &[&[u8]]) -> Result<u32> {
    let mut total = 0usize;
    for part in parts {
        if part.len() > (u32::MAX as usize).saturating_sub(total) {
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
            Ok(file) => return Ok((candidate, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                bail!("Write Error: Unable to create output file: {}", err);
            }
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

fn write_reddit_padding_chunk(file: &mut File) -> Result<()> {
    const REDDIT_PADDING_BYTES: u32 = 0x80000;
    const TYPE_IDAT: &[u8; 4] = b"IDAT";
    const IDAT_REDDIT_CRC: [u8; 4] = [0xA3, 0x1A, 0x50, 0xFA];

    write_u32_or_throw(file, REDDIT_PADDING_BYTES)?;
    write_all_or_throw(file, TYPE_IDAT)?;

    let zeros = [0u8; 8192];
    let mut remaining = REDDIT_PADDING_BYTES as usize;
    while remaining != 0 {
        let chunk_size = remaining.min(zeros.len());
        write_all_or_throw(file, &zeros[..chunk_size])?;
        remaining -= chunk_size;
    }

    write_all_or_throw(file, &IDAT_REDDIT_CRC)
}

fn compute_deflated_size(data: &[u8], option: Option_, is_compressed_file: bool) -> Result<usize> {
    let mut compressed_size = 0usize;
    zlib_deflate_span(data, option, is_compressed_file, |chunk| {
        compressed_size = checked_add_size(
            compressed_size,
            chunk.len(),
            "File Size Error: Final output size overflow.",
        )?;
        Ok(())
    })?;
    Ok(compressed_size)
}

fn write_iccp_chunk_from_profile(
    file: &mut File,
    profile_data: &[u8],
    option: Option_,
    is_compressed_file: bool,
    expected_compressed_size: usize,
) -> Result<()> {
    const TYPE_ICCP: &[u8; 4] = b"iCCP";
    const ICCP_PREFIX: &[u8; 5] = b"icc\0\0";

    write_u32_or_throw(
        file,
        checked_chunk_data_size(expected_compressed_size, ICCP_PREFIX.len())?,
    )?;
    write_all_or_throw(file, TYPE_ICCP)?;

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(TYPE_ICCP);
    write_all_or_throw(file, ICCP_PREFIX)?;
    hasher.update(ICCP_PREFIX);

    let mut actual_compressed_size = 0usize;
    zlib_deflate_span(profile_data, option, is_compressed_file, |chunk| {
        write_all_or_throw(file, chunk)?;
        actual_compressed_size = checked_add_size(
            actual_compressed_size,
            chunk.len(),
            "File Size Error: Final output size overflow.",
        )?;
        hasher.update(chunk);
        Ok(())
    })?;

    if actual_compressed_size != expected_compressed_size {
        bail!("PNG Error: Streamed iCCP chunk size mismatch.");
    }

    write_u32_or_throw(file, hasher.finalize())
}

fn get_compatible_platforms(
    option: Option_,
    output_size: usize,
    has_bad_dims: bool,
    twitter_iccp_compatible: bool,
) -> Vec<String> {
    if option == Option_::Reddit {
        return vec![
            "Reddit. (Only share this \"file-embedded\" PNG image on Reddit).".to_string(),
        ];
    }

    if option == Option_::Mastodon {
        if twitter_iccp_compatible && !has_bad_dims {
            return vec!["Mastodon and X-Twitter.".to_string()];
        }
        return vec![
            "Mastodon. (Only share this \"file-embedded\" PNG image on Mastodon).".to_string(),
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

fn write_output_file<F>(output_size: usize, pin: usize, writer: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    let (output_path, mut output_file) = create_unique_output_file()?;
    let write_result = (|| -> Result<()> {
        writer(&mut output_file)?;
        output_file
            .sync_all()
            .map_err(|err| anyhow!("Write Error: Failed to finalize output file: {}", err))?;
        Ok(())
    })();

    if let Err(err) = write_result {
        drop(output_file);
        let _ = fs::remove_file(&output_path);
        return Err(err);
    }
    drop(output_file);

    println!(
        "\nSaved \"file-embedded\" PNG image: {} ({} bytes).",
        output_path.display(),
        output_size
    );
    println!(
        "\nRecovery PIN: [***{}***]\n\nImportant: Keep your PIN safe, so that you can extract the hidden file.\n\nComplete!\n",
        pin
    );

    Ok(())
}

pub fn conceal_data(png_vec: &mut Vec<u8>, option: Option_, data_file_path: &Path) -> Result<()> {
    const LARGE_FILE_SIZE: usize = 300 * 1024 * 1024;
    const MASTODON_INSERT_INDEX: usize = 0x21;
    const DEFAULT_INSERT_DIFF: usize = 12;

    let is_mastodon = option == Option_::Mastodon;
    let is_reddit = option == Option_::Reddit;

    let data_file_size = get_file_size_checked(data_file_path, FileTypeCheck::DataFile)?;

    if data_file_size > LARGE_FILE_SIZE {
        println!("\nPlease wait. Larger files will take longer to complete this process.");
    }

    let image_result = optimize_image(png_vec)?;

    let data_filename = data_file_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("file")
        .to_string();

    if data_file_size > usize::MAX.saturating_sub(png_vec.len()) {
        bail!("File Size Error: Combined size overflow.");
    }
    validate_inputs(data_file_size + png_vec.len(), data_file_path, &data_filename, option)?;

    let is_compressed = has_file_extension(
        data_file_path,
        &[
            ".zip", ".jar", ".rar", ".7z", ".bz2", ".gz", ".xz", ".tar", ".lz", ".lz4", ".cab",
            ".rpm", ".deb", ".mp4", ".mp3", ".exe", ".jpg", ".jpeg", ".jfif", ".png", ".webp",
            ".bmp", ".gif", ".ogg", ".flac",
        ],
    );

    // Prepare the profile template.
    let mut profile_vec = if is_mastodon {
        MASTODON_PROFILE.to_vec()
    } else {
        DEFAULT_PROFILE.to_vec()
    };

    let pin = encrypt_compressed_file_to_profile(
        &mut profile_vec,
        data_file_path,
        &data_filename,
        option,
        is_compressed,
        is_mastodon,
    )?;

    let mastodon_compressed_profile_size = if is_mastodon {
        compute_deflated_size(&profile_vec, option, is_compressed)?
    } else {
        0
    };

    let mut twitter_iccp_compatible = false;
    let mut output_size = png_vec.len();

    if is_mastodon {
        const TWITTER_ICCP_MAX_CHUNK_SIZE: usize = 10 * 1024;
        const TWITTER_IMAGE_MAX_SIZE: usize = 5 * 1024 * 1024;
        const ICCP_SIZE_DIFF: usize = 5;

        if MASTODON_INSERT_INDEX > png_vec.len() {
            bail!("Image File Error: Invalid PNG insertion point for iCCP chunk.");
        }
        let mastodon_chunk_size =
            checked_chunk_data_size(mastodon_compressed_profile_size, ICCP_SIZE_DIFF)? as usize;
        output_size = checked_add_size(
            output_size,
            checked_chunk_total_size(mastodon_compressed_profile_size, ICCP_SIZE_DIFF)?,
            "File Size Error: Final output size overflow.",
        )?;

        twitter_iccp_compatible = output_size <= TWITTER_IMAGE_MAX_SIZE
            && mastodon_chunk_size <= TWITTER_ICCP_MAX_CHUNK_SIZE;

        validate_output_size(output_size, option)?;
        let platforms = get_compatible_platforms(
            option,
            output_size,
            image_result.has_bad_dims,
            twitter_iccp_compatible,
        );

        println!("\nPlatform compatibility for output image:-\n");
        for platform in &platforms {
            println!(" \u{2713} {}", platform);
        }

        write_output_file(output_size, pin, |file| {
            write_all_or_throw(file, &png_vec[..MASTODON_INSERT_INDEX])?;
            write_iccp_chunk_from_profile(
                file,
                &profile_vec,
                option,
                is_compressed,
                mastodon_compressed_profile_size,
            )?;
            write_all_or_throw(file, &png_vec[MASTODON_INSERT_INDEX..])?;
            Ok(())
        })?;
    } else {
        if png_vec.len() < DEFAULT_INSERT_DIFF {
            bail!("Image File Error: Invalid PNG insertion point for IDAT chunk.");
        }
        let insert_index = png_vec.len() - DEFAULT_INSERT_DIFF;
        const IDAT_SIZE_DIFF: usize = 3;
        const REDDIT_PADDING_CHUNK_TOTAL_SIZE: usize = 0x80000 + 12;
        const TYPE_IDAT: &[u8; 4] = b"IDAT";
        const IDAT_PREFIX: &[u8; 3] = b"\x78\x5E\x5C";

        output_size = checked_add_size(
            output_size,
            checked_chunk_total_size(profile_vec.len(), IDAT_SIZE_DIFF)?,
            "File Size Error: Final output size overflow.",
        )?;
        if is_reddit {
            output_size = checked_add_size(
                output_size,
                REDDIT_PADDING_CHUNK_TOTAL_SIZE,
                "File Size Error: Final output size overflow.",
            )?;
        }

        validate_output_size(output_size, option)?;
        let platforms = get_compatible_platforms(
            option,
            output_size,
            image_result.has_bad_dims,
            twitter_iccp_compatible,
        );

        println!("\nPlatform compatibility for output image:-\n");
        for platform in &platforms {
            println!(" \u{2713} {}", platform);
        }

        write_output_file(output_size, pin, |file| {
            write_all_or_throw(file, &png_vec[..insert_index])?;
            if is_reddit {
                write_reddit_padding_chunk(file)?;
            }
            write_chunk_from_parts(file, TYPE_IDAT, &[IDAT_PREFIX, profile_vec.as_slice()])?;
            write_all_or_throw(file, &png_vec[insert_index..])?;
            Ok(())
        })?;
    }

    Ok(())
}
