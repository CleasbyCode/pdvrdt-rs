use crate::common::MAX_PROGRAM_FILE_SIZE;
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

/// Deflate level for a payload that is worth deflating. Level 6, not 9: level 9
/// costs substantially more time for only a marginal ratio improvement. Matches
/// the C++ implementation, which passes libdeflate level 6 here.
///
/// Inputs that already live in a compressed container gain ~0% from a second
/// deflate pass but cost real time, so they are stored instead -- see
/// `store_zlib_*` below. This holds in every mode: the Mastodon budget is the
/// tightest one, but deflating a .zip/.mp4 does not buy any of it back either.
fn payload_deflate_level() -> Compression {
    Compression::default()
}

/// Largest run of bytes a single deflate *stored* block can carry: its length is
/// a 16-bit field, so 65535 is the maximum, and taking the maximum is what makes
/// the stream below byte-identical to the C++ implementation's.
const STORED_BLOCK_MAX_BYTES: usize = 65535;

/// RFC 1950 header for a stored stream: CMF 0x78 (deflate, 32 KiB window) and
/// FLG 0x01 (FLEVEL 0, no preset dictionary, and 0x7801 % 31 == 0 as the format
/// requires).
const ZLIB_STORED_HEADER: [u8; 2] = [0x78, 0x01];

/// Running Adler-32, the RFC 1950 stream checksum.
///
/// Written out here rather than pulled from a crate: it is fifteen lines, and the
/// stored writer below is the only caller. `flate2` computes one internally but
/// does not expose it.
struct Adler32 {
    a: u32,
    b: u32,
}

impl Adler32 {
    /// Largest run that can be summed before `b` could overflow a u32.
    const MAX_RUN: usize = 5552;
    const MODULUS: u32 = 65521;

    fn new() -> Self {
        Self { a: 1, b: 0 }
    }

    fn update(&mut self, data: &[u8]) {
        for run in data.chunks(Self::MAX_RUN) {
            for &byte in run {
                self.a += u32::from(byte);
                self.b += self.a;
            }
            self.a %= Self::MODULUS;
            self.b %= Self::MODULUS;
        }
    }

    fn finish(&self) -> u32 {
        (self.b << 16) | self.a
    }
}

/// Hands compressor output to the caller in large, fixed-size pieces.
///
/// The encryption layer turns each piece it is handed into secretstream frames,
/// splitting only at its own 1 MiB frame size, so the piece boundaries a
/// compressor produces decide the frame layout of the profile. libdeflate hands
/// the C++ implementation one whole compressed buffer, so passing on the small
/// per-block pieces the stored writer produces would frame the payload far more
/// finely and inflate the profile by ~21 bytes per extra frame. Coalescing to a
/// multiple of the frame size reproduces the C++ frame layout exactly, without
/// ever holding the payload whole.
const STORED_COALESCE_BYTES: usize = ZLIB_BUFSIZE;

const _: () = assert!(
    STORED_COALESCE_BYTES.is_multiple_of(1024 * 1024),
    "stored output must be handed on in whole multiples of the encryption frame size, \
     or the profile's frame layout stops matching the C++ implementation's."
);

struct CoalescingSink<F> {
    on_chunk: F,
    buffer: Zeroizing<Vec<u8>>,
}

impl<F> CoalescingSink<F>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    fn new(on_chunk: F) -> Self {
        Self {
            on_chunk,
            buffer: Zeroizing::new(Vec::with_capacity(STORED_COALESCE_BYTES)),
        }
    }

    fn write(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let take = (STORED_COALESCE_BYTES - self.buffer.len()).min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buffer.len() == STORED_COALESCE_BYTES {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            (self.on_chunk)(&self.buffer)?;
            self.buffer.clear();
        }
        Ok(())
    }
}

/// Emits a *stored* (level 0) RFC 1950 stream one block at a time.
///
/// A stored block applies no entropy coding, so once the block split is fixed the
/// encoding is fully determined: the zlib header, then each block as a one-byte
/// type field plus LEN and !LEN little-endian, then the Adler-32 of the input.
/// Only the split is a choice, and encoders do not agree on it -- libdeflate
/// fills each block to the 65535-byte maximum, while zlib stops at 65531 and can
/// add a trailing empty block, so the same bytes stored by zlib come out a few
/// bytes longer. The C++ implementation stores through libdeflate, so writing the
/// blocks here, rather than asking `flate2` for them, is what keeps the two
/// implementations' output identical rather than merely mutually readable.
///
/// Blocks are handed in as they are produced, so a payload is never buffered
/// whole: the file path below reads one block at a time.
struct StoredZlibWriter<F> {
    sink: CoalescingSink<F>,
    adler: Adler32,
}

impl<F> StoredZlibWriter<F>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    fn new(on_chunk: F) -> Result<Self> {
        let mut sink = CoalescingSink::new(on_chunk);
        sink.write(&ZLIB_STORED_HEADER)?;
        Ok(Self {
            sink,
            adler: Adler32::new(),
        })
    }

    /// Write one stored block. `block` must be at most `STORED_BLOCK_MAX_BYTES`,
    /// and every block before the final one must be exactly that size for the
    /// output to match libdeflate's.
    fn write_block(&mut self, block: &[u8], is_final: bool) -> Result<()> {
        debug_assert!(block.len() <= STORED_BLOCK_MAX_BYTES);
        let len = block.len() as u16;
        let header = [
            u8::from(is_final),
            (len & 0xff) as u8,
            (len >> 8) as u8,
            (!len & 0xff) as u8,
            (!len >> 8) as u8,
        ];
        self.sink.write(&header)?;

        if !block.is_empty() {
            self.sink.write(block)?;
            self.adler.update(block);
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.sink.write(&self.adler.finish().to_be_bytes())?;
        self.sink.flush()
    }
}

/// Byte offsets of the blocks a stored stream of `total` bytes is split into.
/// Always yields at least one block, so empty input still produces the empty
/// final block libdeflate emits for it.
fn stored_block_spans(total: usize) -> impl Iterator<Item = (usize, usize, bool)> {
    let mut offset = 0usize;
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let remaining = total - offset;
        let len = remaining.min(STORED_BLOCK_MAX_BYTES);
        let is_final = remaining <= STORED_BLOCK_MAX_BYTES;
        let span = (offset, len, is_final);
        offset += len;
        done = is_final;
        Some(span)
    })
}

/// Wrap `data` in a *stored* (level 0) RFC 1950 stream. Used for the Mastodon
/// iCCP profile, whose contents are ciphertext: deflating it costs real time and
/// yields slightly more output than storing it.
pub fn zlib_store_span<F>(data: &[u8], on_chunk: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut writer = StoredZlibWriter::new(on_chunk)?;
    for (offset, len, is_final) in stored_block_spans(data.len()) {
        writer.write_block(&data[offset..offset + len], is_final)?;
    }
    writer.finish()
}

/// Stored (level 0) stream for a payload file, read one block at a time so the
/// secret is never held whole in memory.
fn zlib_store_file<F>(input: &OpenInputFile, on_chunk: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut writer = StoredZlibWriter::new(on_chunk)?;
    let mut block = Zeroizing::new(vec![0u8; STORED_BLOCK_MAX_BYTES]);

    for (offset, len, is_final) in stored_block_spans(input.size()) {
        if len != 0 {
            // read_exact_at retries on EINTR and reports a short file as
            // UnexpectedEof, which is the partial read the streaming path names.
            input
                .file()
                .read_exact_at(&mut block[..len], offset as u64)
                .map_err(|err| match err.kind() {
                    io::ErrorKind::UnexpectedEof => {
                        anyhow::anyhow!("Failed to read full file: partial read")
                    }
                    _ => anyhow::Error::new(err).context("Failed to read input file"),
                })?;
        }
        writer.write_block(&block[..len], is_final)?;
    }

    require_file_did_not_grow(input)?;
    writer.finish()
}

/// The payload must be exactly the size validated when it was opened: a file that
/// grew underneath us would have been read only in part.
fn require_file_did_not_grow(input: &OpenInputFile) -> Result<()> {
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
    Ok(())
}

pub fn zlib_deflate_file<F>(
    input: &OpenInputFile,
    is_compressed_file: bool,
    on_chunk: F,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    // An already-compressed payload is stored rather than deflated, and stored
    // framing is written directly so it matches the C++ implementation byte for
    // byte -- see StoredZlibWriter.
    if is_compressed_file {
        return zlib_store_file(input, on_chunk);
    }

    let mut input_buffer = Zeroizing::new(vec![0u8; ZLIB_BUFSIZE]);
    let mut encoder = ZlibEncoder::new(ChunkWriter::new(on_chunk), payload_deflate_level());
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

    require_file_did_not_grow(input)?;

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

    #[test]
    fn output_exactly_at_the_bound_is_accepted() {
        // The ceiling is a limit, not a fence: a stream whose output lands
        // exactly on max_output_size must decode, and only one byte more fails.
        let payload = vec![7u8; 4096];
        let mut enc = ZE::new(Vec::new(), C::default());
        enc.write_all(&payload).unwrap();
        let compressed = enc.finish().unwrap();

        assert_eq!(
            zlib_inflate_span_bounded(&compressed, payload.len())
                .unwrap()
                .len(),
            payload.len()
        );
        assert!(zlib_inflate_span_bounded(&compressed, payload.len() - 1).is_err());
    }

    #[test]
    fn stored_framing_matches_the_cpp_implementation_byte_for_byte() {
        // Reference sizes taken from libdeflate at level 0, which is what the C++
        // implementation stores through: 2-byte header + 5 bytes per block +
        // the data + 4-byte Adler-32, with blocks filled to 65535 and at least
        // one block even when there is nothing to store.
        for n in [0usize, 1, 50_000, 65_535, 65_536, 70_000, 131_070, 131_071] {
            let data: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(2_654_435_761) >> 16) as u8).collect();
            let mut stored = Vec::new();
            zlib_store_span(&data, |chunk| {
                stored.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();

            let expected = 2 + 5 * n.div_ceil(65_535).max(1) + n + 4;
            assert_eq!(stored.len(), expected, "stored framing for {n} bytes");
            assert_eq!(&stored[..2], &[0x78, 0x01], "zlib header for {n} bytes");
            assert_eq!(
                zlib_inflate_span_bounded(&stored, n.max(1) * 2).unwrap(),
                data,
                "stored stream for {n} bytes must inflate back"
            );
        }
    }

    #[test]
    fn stored_span_is_a_valid_zlib_stream_that_does_not_deflate() {
        // The Mastodon iCCP profile is ciphertext. zlib_store_span must emit a
        // real RFC 1950 stream (recover-side inflate reads it) whose first
        // deflate block is stored (BTYPE 00), not compressed.
        let ciphertext: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
            .collect();
        let mut stored = Vec::new();
        zlib_store_span(&ciphertext, |chunk| {
            stored.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();

        assert_eq!(stored[0] & 0x0f, 8, "zlib CM must be 8 (deflate)");
        assert_eq!(
            (stored[2] >> 1) & 3,
            0,
            "first deflate block must be stored"
        );
        assert_eq!(
            zlib_inflate_span_bounded(&stored, ciphertext.len() * 2).unwrap(),
            ciphertext
        );
    }
}
