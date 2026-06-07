use crate::common::Option_;
use anyhow::{bail, Context, Result};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::cmp::{max, min};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

const ZLIB_BUFSIZE: usize = 2 * 1024 * 1024;
const MAX_INFLATED_OUTPUT_SIZE: usize = 3 * 1024 * 1024 * 1024;
const MIN_INFLATE_INITIAL_RESERVE: usize = 256 * 1024;
const MAX_INFLATE_INITIAL_RESERVE: usize = 64 * 1024 * 1024;

struct ChunkWriter<F> {
    on_chunk: F,
    callback_error: Option<anyhow::Error>,
}

impl<F> ChunkWriter<F> {
    fn new(on_chunk: F) -> Self {
        Self {
            on_chunk,
            callback_error: None,
        }
    }

    fn take_error(&mut self) -> Option<anyhow::Error> {
        self.callback_error.take()
    }
}

impl<F> Write for ChunkWriter<F>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        match (self.on_chunk)(buf) {
            Ok(()) => Ok(buf.len()),
            Err(err) => {
                self.callback_error = Some(err);
                Err(io::Error::other("zlib deflate output handler failed"))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn inflate_reserve_hint(input_size: usize, max_output_size: usize) -> usize {
    if max_output_size == 0 {
        return 0;
    }

    let capped_limit = min(max_output_size, MAX_INFLATE_INITIAL_RESERVE);
    let mut hint = min(max(input_size, MIN_INFLATE_INITIAL_RESERVE), capped_limit);
    if hint <= capped_limit / 2 {
        hint *= 2;
    }
    hint
}

fn inflate_to_vec_bounded(data: &[u8], max_output_size: usize) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut output = Vec::with_capacity(inflate_reserve_hint(data.len(), max_output_size));
    let mut buffer = vec![0u8; ZLIB_BUFSIZE];

    loop {
        let read_len = decoder.read(&mut buffer).context("zlib inflate failed")?;
        if read_len == 0 {
            break;
        }

        if read_len > max_output_size || output.len() > max_output_size - read_len {
            bail!("Zlib Compression Error: Inflated data exceeds maximum program size limit.");
        }
        output.extend_from_slice(&buffer[..read_len]);
    }

    Ok(output)
}

fn inflate_to_file_bounded(data: &[u8], file: &mut File, max_output_size: usize) -> Result<usize> {
    let mut decoder = ZlibDecoder::new(data);
    let mut buffer = vec![0u8; ZLIB_BUFSIZE];
    let mut total_written = 0usize;

    loop {
        let read_len = decoder.read(&mut buffer).context("zlib inflate failed")?;
        if read_len == 0 {
            break;
        }

        if read_len > max_output_size || total_written > max_output_size - read_len {
            bail!("Zlib Compression Error: Inflated data exceeds maximum program size limit.");
        }

        file.write_all(&buffer[..read_len])
            .context("Write File Error: Failed to write complete output file.")?;
        total_written += read_len;
    }

    Ok(total_written)
}

fn deflate_level(option: Option_, is_compressed_file: bool) -> Compression {
    if option == Option_::Mastodon {
        Compression::default()
    } else if is_compressed_file {
        Compression::none()
    } else {
        Compression::best()
    }
}

pub fn zlib_deflate_span<F>(
    data: &[u8],
    option: Option_,
    is_compressed_file: bool,
    on_chunk: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut encoder = ZlibEncoder::new(
        ChunkWriter::new(on_chunk),
        deflate_level(option, is_compressed_file),
    );

    if let Err(err) = encoder.write_all(data) {
        if let Some(callback_error) = encoder.get_mut().take_error() {
            return Err(callback_error);
        }
        return Err(err).context("zlib deflate failed");
    }

    if let Err(err) = encoder.try_finish() {
        if let Some(callback_error) = encoder.get_mut().take_error() {
            return Err(callback_error);
        }
        return Err(err).context("zlib deflate failed");
    }

    if let Some(callback_error) = encoder.get_mut().take_error() {
        return Err(callback_error);
    }

    Ok(())
}

pub fn zlib_deflate_file<F>(
    path: &Path,
    option: Option_,
    is_compressed_file: bool,
    on_chunk: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut file =
        File::open(path).map_err(|_| anyhow::anyhow!("Failed to open file: {}", path.display()))?;
    let mut input_buffer = vec![0u8; ZLIB_BUFSIZE];
    let mut encoder = ZlibEncoder::new(
        ChunkWriter::new(on_chunk),
        deflate_level(option, is_compressed_file),
    );

    loop {
        let read_len = file
            .read(&mut input_buffer)
            .context("Failed to read full file: partial read")?;
        if read_len == 0 {
            break;
        }

        if let Err(err) = encoder.write_all(&input_buffer[..read_len]) {
            if let Some(callback_error) = encoder.get_mut().take_error() {
                return Err(callback_error);
            }
            return Err(err).context("zlib deflate failed");
        }
    }

    if let Err(err) = encoder.try_finish() {
        if let Some(callback_error) = encoder.get_mut().take_error() {
            return Err(callback_error);
        }
        return Err(err).context("zlib deflate failed");
    }

    if let Some(callback_error) = encoder.get_mut().take_error() {
        return Err(callback_error);
    }

    Ok(())
}

pub fn zlib_inflate_span_bounded(data: &[u8], max_output_size: usize) -> Result<Vec<u8>> {
    inflate_to_vec_bounded(data, max_output_size)
}

pub fn zlib_inflate_to_file(data: &[u8], file: &mut File) -> Result<usize> {
    let total_written = inflate_to_file_bounded(data, file, MAX_INFLATED_OUTPUT_SIZE)?;
    if total_written == 0 {
        bail!("Zlib Compression Error: Output file is empty. Inflating file failed.");
    }
    Ok(total_written)
}
