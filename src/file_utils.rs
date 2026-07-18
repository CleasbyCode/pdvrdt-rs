use crate::common::{FileTypeCheck, MAX_PROGRAM_FILE_SIZE};
use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::IntoRawFd;
use std::path::Path;

pub struct OpenInputFile {
    file: File,
    size: usize,
}

impl OpenInputFile {
    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

// Blacklist: path separators, the Windows-reserved set, control bytes and DEL.
// Everything else (spaces, '+', '#', non-ASCII bytes >= 0x80, ...) is allowed.
// Operates on raw OS bytes so it matches the C++ blacklist exactly, keeping the
// three implementations mutually recoverable.
fn is_valid_filename_char(c: u8) -> bool {
    match c {
        b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|' => false,
        _ => c >= 0x20 && c != 0x7F,
    }
}

fn is_reserved_embedded_filename(filename: &[u8]) -> bool {
    if filename == b"." || filename == b".." {
        return true;
    }
    if filename.is_empty() {
        return false;
    }
    let first = filename[0];
    let last = *filename.last().unwrap();
    first == b'.' || first == b'-' || last == b' ' || last == b'.'
}

pub fn has_valid_filename(p: &Path) -> bool {
    let Some(name) = p.file_name() else {
        return false;
    };
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes.iter().copied().all(is_valid_filename_char)
}

// has_valid_filename plus the reserved-name rules used for embedded/recovered
// filenames: rejects ".", "..", a leading '.' or '-', and a trailing space or '.'.
pub fn has_safe_embedded_filename(p: &Path) -> bool {
    let Some(name) = p.file_name() else {
        return false;
    };
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.iter().copied().all(is_valid_filename_char)
        && !is_reserved_embedded_filename(bytes)
}

pub fn has_file_extension(p: &Path, exts: &[&str]) -> bool {
    let Some(ext) = p.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let ext_lower = format!(".{}", ext.to_lowercase());
    exts.iter().any(|e| *e == ext_lower)
}

/// Open an existing file for reading without following symlinks (`O_NOFOLLOW`).
pub fn open_read_nofollow(path: &Path) -> Result<File> {
    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.read(true);
    // O_NONBLOCK prevents a path swap to a FIFO from hanging before metadata
    // validation. It has no effect on regular-file reads.
    open_opts.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    open_opts.open(path).map_err(|err| {
        if err.raw_os_error() == Some(libc::ELOOP) {
            anyhow!(
                "Error: File \"{}\" is a symbolic link (not followed).",
                path.display()
            )
        } else {
            anyhow!("Failed to open file: {}", path.display())
        }
    })
}

/// Create a new file for writing with mode 0600, without following symlinks.
///
/// Returns `Ok(None)` if the path already exists (caller may retry with a new name).
pub fn open_write_new_nofollow(path: &Path) -> Result<Option<File>> {
    let mut open_opts = std::fs::OpenOptions::new();
    open_opts
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    match open_opts.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => Err(anyhow!(
            "Write Error: Path is a symbolic link (not followed): {}",
            path.display()
        )),
        Err(err) => Err(anyhow!("Write Error: Unable to create file: {}", err)),
    }
}

fn validate_path_constraints(path: &Path, file_type: FileTypeCheck) -> Result<()> {
    if !has_valid_filename(path) {
        bail!("Invalid Input Error: Unsupported characters in filename arguments.");
    }

    if matches!(
        file_type,
        FileTypeCheck::CoverImage | FileTypeCheck::EmbeddedImage
    ) && !has_file_extension(path, &[".png"])
    {
        bail!("File Type Error: Invalid image extension. Only expecting \".png\".");
    }

    Ok(())
}

fn validate_size_constraints(file_size: usize, file_type: FileTypeCheck) -> Result<()> {
    if file_size == 0 {
        bail!("Error: File is empty.");
    }

    if file_type == FileTypeCheck::CoverImage {
        const MAX_IMAGE_SIZE: usize = 8 * 1024 * 1024;
        if file_size > MAX_IMAGE_SIZE {
            bail!("Image File Error: Cover image file exceeds maximum size limit.");
        }
    }

    if file_size > MAX_PROGRAM_FILE_SIZE {
        bail!("Error: File exceeds program size limit.");
    }

    Ok(())
}

pub fn open_input_file(path: &Path, file_type: FileTypeCheck) -> Result<OpenInputFile> {
    validate_path_constraints(path, file_type)?;

    let file = open_read_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|_| anyhow!("Failed to open file: {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "Error: File \"{}\" not found or not a regular file.",
            path.display()
        );
    }

    let raw_file_size = metadata.len();
    if raw_file_size > usize::MAX as u64 {
        bail!("Error: File is too large for this build.");
    }
    let file_size = raw_file_size as usize;
    validate_size_constraints(file_size, file_type)?;

    Ok(OpenInputFile {
        file,
        size: file_size,
    })
}

pub fn get_file_size_checked(path: &Path, file_type: FileTypeCheck) -> Result<usize> {
    Ok(open_input_file(path, file_type)?.size())
}

pub fn read_file(path: &Path, file_type: FileTypeCheck) -> Result<Vec<u8>> {
    let mut input = open_input_file(path, file_type)?;
    let mut data = Vec::new();
    data.try_reserve_exact(input.size())
        .map_err(|_| anyhow!("Failed to allocate input file buffer."))?;
    data.resize(input.size(), 0);
    input
        .file_mut()
        .read_exact(&mut data)
        .map_err(|_| anyhow!("Failed to read full file: partial read"))?;

    let mut extra = [0u8; 1];
    loop {
        match input.file_mut().read(&mut extra) {
            Ok(0) => break,
            Ok(_) => bail!("Failed to read file reliably: file grew while being read."),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(anyhow!("Failed to read input file: {}", err)),
        }
    }

    Ok(data)
}

/// On Linux close releases the descriptor even when it reports EINTR. Consume
/// the File, call close exactly once, and report every finalisation error.
pub fn close_file_or_throw(file: File) -> Result<()> {
    let fd = file.into_raw_fd();
    if unsafe { libc::close(fd) } != 0 {
        bail!(
            "Write Error: Failed to finalize output file: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn valid_and_safe_filenames() {
        assert!(has_valid_filename(Path::new("photo.png")));
        assert!(has_safe_embedded_filename(Path::new("secret.doc")));
        assert!(!has_safe_embedded_filename(Path::new(".hidden")));
        assert!(!has_safe_embedded_filename(Path::new("-dash")));
        assert!(!has_safe_embedded_filename(Path::new("trail.")));
        assert!(!has_safe_embedded_filename(Path::new("trail ")));
        assert!(!has_safe_embedded_filename(Path::new("..")));
        // Path::file_name() only sees the final component; separators are structural.
        assert!(has_valid_filename(Path::new("dir/name.png")));
        assert!(!has_valid_filename(Path::new("bad:name.png")));
        assert!(!has_valid_filename(Path::new("bad*name.png")));
        assert!(!has_valid_filename(Path::new("bad?name.png")));
    }

    #[test]
    fn extension_check_is_case_insensitive() {
        assert!(has_file_extension(Path::new("a.PNG"), &[".png"]));
        assert!(has_file_extension(Path::new("a.Zip"), &[".zip", ".gz"]));
        assert!(!has_file_extension(Path::new("a.txt"), &[".png"]));
        assert!(!has_file_extension(&PathBuf::from("noext"), &[".png"]));
    }
}
