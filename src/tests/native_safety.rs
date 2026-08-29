use flate2::write::ZlibEncoder;
use flate2::Compression;
use pdvrdt::common::FileTypeCheck;
use pdvrdt::compression::{zlib_deflate_file, zlib_inflate_span_bounded};
use pdvrdt::file_utils::open_input_file;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for _ in 0..1_000 {
            let sequence = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "pdvrdt-native-safety-{label}-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("failed to create test directory: {error}"),
            }
        }

        panic!("failed to allocate a unique test directory");
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn deflate_validated_file(input: &pdvrdt::file_utils::OpenInputFile) -> anyhow::Result<Vec<u8>> {
    let mut compressed = Vec::new();
    zlib_deflate_file(input, false, |chunk| {
        compressed.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(compressed)
}

fn make_zlib_stream(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .expect("zlib test input should encode");
    encoder.finish().expect("zlib test stream should finish")
}

fn make_fifo(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).expect("temporary path contains NUL");
    // SAFETY: `path` is a live, NUL-terminated pathname and the mode is valid.
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    assert_eq!(
        result,
        0,
        "failed to create FIFO: {}",
        io::Error::last_os_error()
    );
}

#[test]
fn compression_uses_the_validated_descriptor_after_path_replacement() {
    let temp = TestDir::new("descriptor");
    let input_path = temp.join("payload.bin");
    let detached_path = temp.join("original-inode.bin");
    let original = vec![b'A'; 16 * 1024];
    let replacement = vec![b'B'; original.len()];

    fs::write(&input_path, &original).expect("write original input");
    let input = open_input_file(&input_path, FileTypeCheck::DataFile)
        .expect("validate and open original input");

    fs::rename(&input_path, &detached_path).expect("detach original pathname");
    fs::write(&input_path, &replacement).expect("install replacement pathname");

    let compressed = deflate_validated_file(&input).expect("compress original descriptor");
    let inflated = zlib_inflate_span_bounded(&compressed, original.len())
        .expect("inflate compressed descriptor data");

    assert_eq!(inflated, original);
    assert_eq!(fs::read(&input_path).unwrap(), replacement);
}

#[test]
fn compression_rejects_growth_beyond_the_validated_size() {
    let temp = TestDir::new("growth");
    let input_path = temp.join("payload.bin");
    fs::write(&input_path, vec![b'G'; 8 * 1024]).expect("write input");
    let input =
        open_input_file(&input_path, FileTypeCheck::DataFile).expect("validate and open input");

    let mut grower = OpenOptions::new()
        .append(true)
        .open(&input_path)
        .expect("open input for growth");
    grower.write_all(b"unexpected-growth").expect("grow input");
    drop(grower);

    let error = deflate_validated_file(&input).expect_err("growth must be rejected");
    assert!(
        error.to_string().contains("file grew while being read"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn compression_rejects_shrink_and_partial_read() {
    let temp = TestDir::new("shrink");
    let input_path = temp.join("payload.bin");
    fs::write(&input_path, vec![b'S'; 8 * 1024]).expect("write input");
    let input =
        open_input_file(&input_path, FileTypeCheck::DataFile).expect("validate and open input");

    OpenOptions::new()
        .write(true)
        .open(&input_path)
        .expect("open input for truncation")
        .set_len(128)
        .expect("shrink input");

    let error = deflate_validated_file(&input).expect_err("partial read must be rejected");
    assert!(
        error.to_string().contains("partial read"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn fifo_input_is_rejected_without_waiting_for_a_writer() {
    let temp = TestDir::new("fifo");
    let fifo_path = temp.join("input.pipe");
    make_fifo(&fifo_path);

    let (sender, receiver) = mpsc::sync_channel(1);
    let worker_path = fifo_path.clone();
    let worker = thread::spawn(move || {
        let result = open_input_file(&worker_path, FileTypeCheck::DataFile)
            .map(|_| ())
            .map_err(|error| error.to_string());
        let _ = sender.send(result);
    });

    let result = match receiver.recv_timeout(Duration::from_secs(3)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Unblock a regressed, blocking FIFO open before failing, so the
            // test process does not retain a stuck worker thread.
            let writer_path = fifo_path.clone();
            let writer = thread::spawn(move || OpenOptions::new().write(true).open(writer_path));
            let _ = worker.join();
            let _ = writer.join();
            panic!("FIFO input open blocked instead of using O_NONBLOCK");
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            worker.join().expect("FIFO worker panicked");
            panic!("FIFO worker disconnected without reporting a result");
        }
    };

    worker.join().expect("FIFO worker panicked");
    let error = result.expect_err("FIFO must not be accepted as an input file");
    assert!(
        error.contains("not a regular file"),
        "unexpected FIFO rejection: {error}"
    );
}

#[test]
fn bounded_inflate_rejects_trailing_truncated_and_oversized_output() {
    let plain = vec![b'Z'; 64 * 1024];
    let compressed = make_zlib_stream(&plain);
    assert_eq!(
        zlib_inflate_span_bounded(&compressed, plain.len()).unwrap(),
        plain
    );

    let mut trailing = compressed.clone();
    trailing.push(0);
    let trailing_error = zlib_inflate_span_bounded(&trailing, plain.len())
        .expect_err("trailing stream data must be rejected");
    assert!(
        trailing_error.to_string().contains("trailing data"),
        "unexpected trailing-data error: {trailing_error:#}"
    );

    let mut truncated = compressed.clone();
    truncated.pop();
    let truncated_error = zlib_inflate_span_bounded(&truncated, plain.len())
        .expect_err("truncated stream must be rejected");
    assert!(
        truncated_error.to_string().contains("truncated or stalled"),
        "unexpected truncated-stream error: {truncated_error:#}"
    );

    let oversized_error = zlib_inflate_span_bounded(&compressed, plain.len() - 1)
        .expect_err("output beyond the cap must be rejected");
    assert!(
        oversized_error
            .to_string()
            .contains("exceeds maximum program size limit"),
        "unexpected output-cap error: {oversized_error:#}"
    );
}
