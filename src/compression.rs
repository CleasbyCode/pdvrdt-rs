use crate::common::{PlatformOption, MAX_PROGRAM_FILE_SIZE};
use crate::file_utils::OpenInputFile;
use anyhow::{bail, Context, Result};
use flate2::write::ZlibEncoder;
use flate2::{Compression, Decompress, FlushDecompress, Status};
use std::cmp::{max, min};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::FileExt;
use zeroize::Zeroizing;

const ZLIB_BUFSIZE: usize = 2 * 1024 * 1024;
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

fn inflate_driver<F>(data: &[u8], max_output_size: usize, mut on_output: F) -> Result<usize>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut decoder = Decompress::new(true);
    let mut buffer = Zeroizing::new(vec![0u8; ZLIB_BUFSIZE]);
    let mut input_offset = 0usize;
    let mut total_output = 0usize;

    loop {
        let input_before = decoder.total_in();
        let output_before = decoder.total_out();
        let status = decoder
            .decompress(&data[input_offset..], &mut buffer, FlushDecompress::None)
            .context("zlib inflate failed")?;
        let consumed = (decoder.total_in() - input_before) as usize;
        let produced = (decoder.total_out() - output_before) as usize;
        input_offset = input_offset
            .checked_add(consumed)
            .ok_or_else(|| anyhow::anyhow!("zlib inflate input overflow"))?;

        if produced > max_output_size.saturating_sub(total_output) {
            bail!("Zlib Compression Error: Inflated data exceeds maximum program size limit.");
        }
        if produced != 0 {
            on_output(&buffer[..produced])?;
            total_output += produced;
        }

        if status == Status::StreamEnd {
            if input_offset != data.len() {
                bail!("zlib inflate failed: trailing data after stream.");
            }
            return Ok(total_output);
        }
        if consumed == 0 && produced == 0 {
            bail!("zlib inflate failed: truncated or stalled stream.");
        }
    }
}

fn inflate_to_vec_bounded(data: &[u8], max_output_size: usize) -> Result<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(inflate_reserve_hint(data.len(), max_output_size))
        .map_err(|_| {
            anyhow::anyhow!("Zlib Compression Error: Unable to allocate inflate buffer.")
        })?;
    inflate_driver(data, max_output_size, |chunk| {
        output.try_reserve(chunk.len()).map_err(|_| {
            anyhow::anyhow!("Zlib Compression Error: Unable to allocate inflate buffer.")
        })?;
        output.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(std::mem::take(&mut *output))
}

fn inflate_to_file_bounded(data: &[u8], file: &mut File, max_output_size: usize) -> Result<usize> {
    inflate_driver(data, max_output_size, |chunk| {
        file.write_all(chunk)
            .context("Write File Error: Failed to write complete output file.")?;
        Ok(())
    })
}

fn deflate_level(option: PlatformOption, is_compressed_file: bool) -> Compression {
    if option == PlatformOption::Mastodon {
        Compression::default()
    } else if is_compressed_file {
        Compression::none()
    } else {
        // Match the C++ implementation's level 6: level 9 costs substantially
        // more time for only a marginal ratio improvement.
        Compression::default()
    }
}

pub fn zlib_deflate_span<F>(
    data: &[u8],
    option: PlatformOption,
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
    input: &OpenInputFile,
    option: PlatformOption,
    is_compressed_file: bool,
    on_chunk: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut input_buffer = Zeroizing::new(vec![0u8; ZLIB_BUFSIZE]);
    let mut encoder = ZlibEncoder::new(
        ChunkWriter::new(on_chunk),
        deflate_level(option, is_compressed_file),
    );
    let mut offset = 0usize;

    while offset < input.size() {
        let request_size = (input.size() - offset).min(input_buffer.len());
        let read_len = loop {
            match input
                .file()
                .read_at(&mut input_buffer[..request_size], offset as u64)
            {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                result => break result.context("Failed to read input file")?,
            }
        };
        if read_len == 0 {
            bail!("Failed to read full file: partial read");
        }

        if let Err(err) = encoder.write_all(&input_buffer[..read_len]) {
            if let Some(callback_error) = encoder.get_mut().take_error() {
                return Err(callback_error);
            }
            return Err(err).context("zlib deflate failed");
        }
        offset += read_len;
    }

    let mut extra = [0u8; 1];
    let extra_len = loop {
        match input.file().read_at(&mut extra, input.size() as u64) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            result => break result.context("Failed to read input file")?,
        }
    };
    if extra_len != 0 {
        bail!("Failed to read file reliably: file grew while being read.");
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

pub fn zlib_inflate_prefix(data: &[u8], prefix_size: usize) -> Result<Vec<u8>> {
    if prefix_size == 0 {
        return Ok(Vec::new());
    }

    let mut decoder = Decompress::new(true);
    let mut prefix = Zeroizing::new(Vec::with_capacity(prefix_size));
    let mut input_offset = 0usize;

    while prefix.len() < prefix_size {
        let remaining = prefix_size - prefix.len();
        let mut buffer = Zeroizing::new(vec![0u8; remaining.min(ZLIB_BUFSIZE)]);
        let input_before = decoder.total_in();
        let output_before = decoder.total_out();
        let status = decoder
            .decompress(&data[input_offset..], &mut buffer, FlushDecompress::None)
            .context("zlib inflate prefix failed")?;
        let consumed = (decoder.total_in() - input_before) as usize;
        let produced = (decoder.total_out() - output_before) as usize;
        input_offset += consumed;
        prefix.extend_from_slice(&buffer[..produced]);

        if status == Status::StreamEnd {
            break;
        }
        if consumed == 0 && produced == 0 {
            bail!("zlib inflate prefix failed: truncated or stalled stream.");
        }
    }
    Ok(std::mem::take(&mut *prefix))
}

pub fn zlib_inflate_to_file(data: &[u8], file: &mut File) -> Result<usize> {
    let total_written = inflate_to_file_bounded(data, file, MAX_PROGRAM_FILE_SIZE)?;
    if total_written == 0 {
        bail!("Zlib Compression Error: Output file is empty. Inflating file failed.");
    }
    Ok(total_written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder as ZE;
    use flate2::Compression as C;

    #[test]
    fn inflate_roundtrip_and_bound() {
        let mut enc = ZE::new(Vec::new(), C::default());
        enc.write_all(b"pdvrdt-zlib-test").unwrap();
        let compressed = enc.finish().unwrap();
        let out = zlib_inflate_span_bounded(&compressed, 1024).unwrap();
        assert_eq!(out, b"pdvrdt-zlib-test");
        assert!(zlib_inflate_span_bounded(&compressed, 4).is_err());

        let mut trailing = compressed.clone();
        trailing.push(0);
        assert!(zlib_inflate_span_bounded(&trailing, 1024).is_err());

        let mut truncated = compressed.clone();
        truncated.pop();
        assert!(zlib_inflate_span_bounded(&truncated, 1024).is_err());

        assert_eq!(zlib_inflate_prefix(&compressed, 6).unwrap(), b"pdvrdt");
    }
}
