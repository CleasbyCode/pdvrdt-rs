use crate::common::FileTypeCheck;
use anyhow::{anyhow, bail, Result};
use std::path::Path;

pub fn has_valid_filename(p: &Path) -> bool {
    let Some(filename) = p.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    if filename.is_empty() {
        return false;
    }
    filename.bytes().all(|c| {
        c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'_' || c == b'@' || c == b'%'
    })
}

pub fn has_file_extension(p: &Path, exts: &[&str]) -> bool {
    let Some(ext) = p.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext_lower = format!(".{}", ext.to_lowercase());
    exts.iter().any(|e| *e == ext_lower)
}

fn validate_and_get_file_size(path: &Path, file_type: FileTypeCheck) -> Result<usize> {
    if !has_valid_filename(path) {
        bail!("Invalid Input Error: Unsupported characters in filename arguments.");
    }

    let metadata = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => {
            bail!(
                "Error: File \"{}\" not found or not a regular file.",
                path.display()
            );
        }
    };
    if !metadata.is_file() {
        bail!(
            "Error: File \"{}\" not found or not a regular file.",
            path.display()
        );
    }

    let raw_file_size = metadata.len();
    if raw_file_size > usize::MAX as u64 || raw_file_size > isize::MAX as u64 {
        bail!("Error: File is too large for this build.");
    }
    let file_size = raw_file_size as usize;

    if file_size == 0 {
        bail!("Error: File is empty.");
    }

    if file_type == FileTypeCheck::CoverImage || file_type == FileTypeCheck::EmbeddedImage {
        if !has_file_extension(path, &[".png"]) {
            bail!("File Type Error: Invalid image extension. Only expecting \".png\".");
        }

        if file_type == FileTypeCheck::CoverImage {
            const MINIMUM_IMAGE_SIZE: usize = 87;
            if file_size < MINIMUM_IMAGE_SIZE {
                bail!("File Error: Invalid image file size.");
            }

            const MAX_IMAGE_SIZE: usize = 8 * 1024 * 1024;
            if file_size > MAX_IMAGE_SIZE {
                bail!("Image File Error: Cover image file exceeds maximum size limit.");
            }
        }
    }

    const MAX_FILE_SIZE: usize = 3 * 1024 * 1024 * 1024;
    if file_size > MAX_FILE_SIZE {
        bail!("Error: File exceeds program size limit.");
    }

    Ok(file_size)
}

pub fn get_file_size_checked(path: &Path, file_type: FileTypeCheck) -> Result<usize> {
    validate_and_get_file_size(path, file_type)
}

pub fn read_file(path: &Path, file_type: FileTypeCheck) -> Result<Vec<u8>> {
    let file_size = get_file_size_checked(path, file_type)?;

    let data =
        std::fs::read(path).map_err(|_| anyhow!("Failed to open file: {}", path.display()))?;
    if data.len() != file_size {
        bail!("Failed to read full file: partial read");
    }

    Ok(data)
}
