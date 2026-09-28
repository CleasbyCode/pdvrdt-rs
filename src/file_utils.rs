use crate::common::{
    FileTypeCheck, MAX_COVER_IMAGE_SIZE, MAX_PROGRAM_FILE_SIZE, MAX_REDDIT_COVER_IMAGE_SIZE,
};
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

/// One well-formed UTF-8 sequence starting at `index`: its code point and byte
/// length. `None` for an invalid, overlong, surrogate or truncated sequence.
/// Hand-rolled over raw bytes (not `str`) so it classifies byte-for-byte the
/// same way as the C++ decoder.
fn decode_utf8_at(text: &[u8], index: usize) -> Option<(u32, usize)> {
    let lead = text[index];
    if lead < 0x80 {
        return Some((u32::from(lead), 1));
    }
    let (length, mut code_point, minimum) = if lead & 0xE0 == 0xC0 {
        (2, u32::from(lead & 0x1F), 0x80)
    } else if lead & 0xF0 == 0xE0 {
        (3, u32::from(lead & 0x0F), 0x800)
    } else if lead & 0xF8 == 0xF0 {
        (4, u32::from(lead & 0x07), 0x10000)
    } else {
        return None;
    };
    if length > text.len() - index {
        return None;
    }
    for &next in &text[index + 1..index + length] {
        if next & 0xC0 != 0x80 {
            return None;
        }
        code_point = (code_point << 6) | u32::from(next & 0x3F);
    }
    if code_point < minimum || code_point > 0x10FFFF || (0xD800..=0xDFFF).contains(&code_point) {
        return None;
    }
    Some((code_point, length))
}

/// C1 controls (a terminal may act on e.g. U+009B CSI) and bidirectional
/// formatting characters (which can disguise a filename's extension).
fn is_unsafe_code_point(cp: u32) -> bool {
    (0x80..=0x9F).contains(&cp)          // C1 controls
        || cp == 0x061C                  // arabic letter mark
        || cp == 0x200E || cp == 0x200F  // LRM / RLM
        || (0x202A..=0x202E).contains(&cp) // LRE, RLE, PDF, LRO, RLO
        || (0x2066..=0x2069).contains(&cp) // LRI, RLI, FSI, PDI
}

fn has_unsafe_code_point(name: &[u8]) -> bool {
    let mut i = 0;
    while i < name.len() {
        match decode_utf8_at(name, i) {
            Some((cp, _)) if is_unsafe_code_point(cp) => return true,
            Some((_, len)) => i += len,
            None => i += 1,
        }
    }
    false
}

/// Replace each UTF-8 encoded C1 control and bidirectional formatting character
/// with '_'. Conceal rejects such names outright; recover neutralizes them
/// instead, so a payload made by an older or foreign release stays recoverable.
/// Bytes that are not valid UTF-8 pass through unchanged.
pub fn neutralize_unsafe_code_points(name: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(name.len());
    let mut i = 0;
    while i < name.len() {
        match decode_utf8_at(name, i) {
            Some((cp, len)) => {
                if is_unsafe_code_point(cp) {
                    result.push(b'_');
                } else {
                    result.extend_from_slice(&name[i..i + len]);
                }
                i += len;
            }
            None => {
                result.push(name[i]);
                i += 1;
            }
        }
    }
    result
}

/// `name` made safe to print on a terminal: valid, printable UTF-8 is kept and
/// every other byte (invalid UTF-8, control and bidi code points, backslash) is
/// shown as \xNN. For display only -- never use the result as a path.
pub fn printable_filename(name: &[u8]) -> String {
    let mut result = String::with_capacity(name.len());
    let escape = |out: &mut String, bytes: &[u8]| {
        for byte in bytes {
            out.push_str(&format!("\\x{byte:02X}"));
        }
    };
    let mut i = 0;
    while i < name.len() {
        match decode_utf8_at(name, i) {
            Some((cp, len)) => {
                let is_control = cp < 0x20 || cp == 0x7F;
                if is_control || is_unsafe_code_point(cp) || cp == u32::from(b'\\') {
                    escape(&mut result, &name[i..i + len]);
                } else {
                    // A well-formed sequence of a valid scalar value.
                    result.push(char::from_u32(cp).expect("validated scalar value"));
                }
                i += len;
            }
            None => {
                escape(&mut result, &name[i..=i]);
                i += 1;
            }
        }
    }
    result
}

pub fn has_valid_filename(p: &Path) -> bool {
    let Some(name) = p.file_name() else {
        return false;
    };
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes.iter().copied().all(is_valid_filename_char)
}

/// The specific reason `p` is unusable as an embedded filename, or `None` if it
/// is fine. Callers that report the failure to the user should use this rather
/// than restating a partial version of the rules.
pub fn embedded_filename_problem(p: &Path) -> Option<&'static str> {
    // Note: unlike C++'s std::filesystem::path::filename(), Rust's
    // Path::file_name() returns None for "." and "..", so those land here rather
    // than in the reserved-name branch below. Both are still rejected; only the
    // wording differs from the C++ build.
    let bytes = match p.file_name() {
        Some(name) if !name.as_bytes().is_empty() => name.as_bytes(),
        _ => return Some("it is empty, \".\", or \"..\""),
    };

    if !bytes.iter().copied().all(is_valid_filename_char) {
        return Some(
            "the filename contains a path separator, a control character, \
             or one of the reserved characters : * ? \" < > |",
        );
    }
    if has_unsafe_code_point(bytes) {
        return Some(
            "the filename contains a Unicode control or bidirectional-formatting character",
        );
    }
    // Kept for callers that construct a Path from raw embedded bytes, where a
    // literal "." / ".." component can still reach this point.
    if bytes == b"." || bytes == b".." {
        return Some("\".\" and \"..\" are reserved names");
    }
    let first = bytes[0];
    if first == b'.' || first == b'-' {
        return Some("the filename may not begin with '.' or '-'");
    }
    let last = *bytes.last().expect("checked non-empty above");
    if last == b' ' || last == b'.' {
        return Some("the filename may not end with a space or a '.'");
    }
    None
}

/// has_valid_filename plus the reserved-name rules used for embedded/recovered
/// filenames: rejects ".", "..", a leading '.' or '-', a trailing space or '.',
/// and the C1 control / bidi-formatting code points that
/// neutralize_unsafe_code_points() replaces.
///
/// Single source of truth: the predicate and the user-facing reason can never
/// disagree about which filenames are acceptable.
pub fn has_safe_embedded_filename(p: &Path) -> bool {
    embedded_filename_problem(p).is_none()
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
        FileTypeCheck::CoverImage | FileTypeCheck::EmbeddedImage | FileTypeCheck::RedditCoverImage
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

    if file_type == FileTypeCheck::CoverImage && file_size > MAX_COVER_IMAGE_SIZE {
        bail!(
            "Image File Error: Cover image file exceeds the maximum size limit of {} MiB (image is {} bytes).",
            MAX_COVER_IMAGE_SIZE / (1024 * 1024),
            file_size
        );
    }

    if file_type == FileTypeCheck::RedditCoverImage && file_size > MAX_REDDIT_COVER_IMAGE_SIZE {
        bail!(
            "Image File Size Error: Cover image file exceeds the maximum size limit of {} MiB for Reddit mode (image is {} bytes).",
            MAX_REDDIT_COVER_IMAGE_SIZE / (1024 * 1024),
            file_size
        );
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
/// Flush the directory entry for `path`, so the name itself survives a crash and
/// not just the bytes behind it. Best-effort and silent: a directory that cannot
/// be opened for reading (write+execute but not read) is a permissions quirk, not
/// a sign that the data is at risk, and must not fail an operation that has
/// otherwise fully succeeded.
pub fn fsync_parent_directory_no_throw(path: &Path) {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
}

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
    fn filename_problem_reports_the_rule_that_actually_fired() {
        let reason = |p: &str| embedded_filename_problem(Path::new(p)).unwrap();
        assert!(reason(".hidden").contains("begin with"));
        assert!(reason("-dash").contains("begin with"));
        assert!(reason("trail.").contains("end with"));
        assert!(reason("trail ").contains("end with"));
        // Path::file_name() yields None for "." and "..", so they are reported as
        // the empty/dot case rather than by the reserved-name branch. Still rejected.
        assert!(reason("..").contains("\"..\""));
        assert!(reason(".").contains("\".\""));
        assert!(reason("bad:name").contains("reserved characters"));
        assert!(embedded_filename_problem(Path::new("secret.doc")).is_none());
    }

    #[test]
    fn filename_predicate_and_reason_never_disagree() {
        for name in [
            "secret.doc",
            ".hidden",
            "-dash",
            "trail.",
            "trail ",
            ".",
            "..",
            "bad:name",
            "ok name",
            "a",
            "#hash+plus",
        ] {
            let path = Path::new(name);
            assert_eq!(
                has_safe_embedded_filename(path),
                embedded_filename_problem(path).is_none(),
                "disagreement on {name:?}"
            );
        }
    }

    #[test]
    fn unsafe_code_points_are_rejected_neutralized_and_escaped() {
        use std::ffi::OsStr;
        let path = |b: &[u8]| PathBuf::from(OsStr::from_bytes(b));

        // U+202E RLO, U+009B CSI, U+2066 LRI.
        assert!(!has_safe_embedded_filename(&path(b"inv\xE2\x80\xAEfdp.exe")));
        assert!(!has_safe_embedded_filename(&path(b"a\xC2\x9Bb")));
        assert!(has_safe_embedded_filename(&path(b"caf\xC3\xA9.txt")));
        assert!(has_safe_embedded_filename(&path(b"x\xFF.bin")));

        assert_eq!(neutralize_unsafe_code_points(b"inv\xE2\x80\xAEfdp.exe"), b"inv_fdp.exe");
        assert_eq!(neutralize_unsafe_code_points(b"a\xC2\x9Bb"), b"a_b");
        assert_eq!(neutralize_unsafe_code_points(b"\xE2\x81\xA6z"), b"_z");
        assert_eq!(neutralize_unsafe_code_points(b"caf\xC3\xA9"), b"caf\xC3\xA9");
        assert_eq!(neutralize_unsafe_code_points(b"x\xFFy"), b"x\xFFy");

        assert_eq!(printable_filename(b"ok.txt"), "ok.txt");
        assert_eq!(printable_filename(b"caf\xC3\xA9"), "caf\u{e9}");
        assert_eq!(printable_filename(b"x\xFFy"), "x\\xFFy");
        assert_eq!(printable_filename(b"a\xC2\x9B[31m"), "a\\xC2\\x9B[31m");
        assert_eq!(printable_filename(b"\xC0\xAF"), "\\xC0\\xAF"); // overlong
        assert_eq!(printable_filename(b"\xED\xA0\x80"), "\\xED\\xA0\\x80"); // surrogate
    }

    #[test]
    fn extension_check_is_case_insensitive() {
        assert!(has_file_extension(Path::new("a.PNG"), &[".png"]));
        assert!(has_file_extension(Path::new("a.Zip"), &[".zip", ".gz"]));
        assert!(!has_file_extension(Path::new("a.txt"), &[".png"]));
        assert!(!has_file_extension(&PathBuf::from("noext"), &[".png"]));
    }
}
