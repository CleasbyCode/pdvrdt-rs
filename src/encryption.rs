use crate::common::bytes_equal_at;
use crate::common::{require_span_range, span_has_range};
use crate::compression::{zlib_deflate_file, zlib_inflate_prefix};
use crate::crypto::argon2id13 as pwhash;
use crate::crypto::randombytes_into;
use crate::crypto::secretstream;
use crate::file_utils::OpenInputFile;
use crate::pin_input::get_pin;
use anyhow::{anyhow, bail, Result};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use zeroize::{Zeroize, Zeroizing};

pub struct ProfileOffsets {
    pub kdf_metadata: usize,
    pub encrypted_file: usize,
    /// PDVRDT_SIG, the second half of the payload fingerprint.
    pub pdv_signature: usize,
}

pub const MASTODON_OFFSETS: ProfileOffsets = ProfileOffsets {
    kdf_metadata: 0x1BE,
    encrypted_file: 0x1FE,
    pdv_signature: 502,
};

pub const DEFAULT_OFFSETS: ProfileOffsets = ProfileOffsets {
    kdf_metadata: 0x02D,
    encrypted_file: 0x06E,
    pdv_signature: 101,
};

pub const KDF_METADATA_REGION_BYTES: usize = 56;
pub const KDF_MAGIC_OFFSET: usize = 0;
pub const KDF_ALG_OFFSET: usize = 4;
pub const KDF_SENTINEL_OFFSET: usize = 5;
pub const KDF_SALT_OFFSET: usize = 8;
pub const KDF_NONCE_OFFSET: usize = 24;

pub const KDF_ALG_ARGON2ID13: u8 = 1;
pub const KDF_SENTINEL: u8 = 0xA5;

const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

/// Wire format: each secretstream frame is preceded by its big-endian length in
/// this many bytes. Part of the on-disk layout, so it is public alongside the
/// offset tables rather than private to this module.
pub const STREAM_FRAME_LEN_BYTES: usize = 4;

/// Smallest ciphertext a well-formed payload can have: the stream header plus one
/// framed TAG_FINAL frame. Used by conceal/recover to reject truncated payloads.
/// Const-evaluated, so an overflow here is a compile-time error.
pub const fn minimum_stream_cipher_size() -> usize {
    secretstream::HEADERBYTES + STREAM_FRAME_LEN_BYTES + secretstream::ABYTES
}
const KDF_METADATA_MAGIC_V2: &[u8; 4] = b"KDF2";
pub const PDVRDT_SIG: &[u8; 7] = &[0xC6, 0x50, 0x3C, 0xEA, 0x5E, 0x9D, 0xF9];
pub const MAX_MASTODON_PROFILE_BYTES: usize = 64 * 1024 * 1024;

/// The two fixed byte strings that introduce an embedded payload: a fake zlib
/// header for the default IDAT layout, and "icc\0" + compression method 0 for
/// the Mastodon iCCP layout.
pub const PDVRDT_IDAT_PREFIX: &[u8; 3] = b"\x78\x5e\x5c";
pub const PDVRDT_ICCP_PREFIX: &[u8; 5] = b"icc\0\0";

#[derive(Clone, Copy, PartialEq, Eq)]
enum KdfMetadataVersion {
    None,
    V2Secretstream,
}

fn read_frame_len(data: &[u8], index: usize) -> u32 {
    u32::from_be_bytes(
        data[index..index + STREAM_FRAME_LEN_BYTES]
            .try_into()
            .unwrap(),
    )
}

fn derive_key_from_pin(
    pin: &u64,
    salt_bytes: &[u8; pwhash::SALTBYTES],
) -> Result<secretstream::Key> {
    let pin_buf = Zeroizing::new(pin.to_string().into_bytes());
    let salt = pwhash::Salt::from_slice(salt_bytes)
        .ok_or_else(|| anyhow!("KDF Error: Invalid salt length."))?;

    let mut key_bytes = Zeroizing::new([0u8; secretstream::KEYBYTES]);
    pwhash::derive_key(
        &mut *key_bytes,
        &pin_buf,
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| anyhow!("KDF Error: Unable to derive encryption key."))?;

    let key = secretstream::Key::from_slice(&key_bytes[..])
        .ok_or_else(|| anyhow!("KDF Error: Invalid derived key length."))?;
    Ok(key)
}

fn append_encrypted_frames(
    encrypted: &mut Vec<u8>,
    plaintext: &[u8],
    stream: &mut secretstream::Stream<secretstream::Push>,
    cipher_chunk: &mut Vec<u8>,
    max_encrypted_size: usize,
    emit_final: bool,
) -> Result<()> {
    if plaintext.is_empty() && !emit_final {
        return Ok(());
    }

    let mut offset = 0usize;
    let mut emit_empty_final = plaintext.is_empty() && emit_final;

    while emit_empty_final || offset < plaintext.len() {
        let remaining = plaintext.len().saturating_sub(offset);
        let chunk_len = remaining.min(STREAM_CHUNK_SIZE);
        let is_final = emit_empty_final || offset + chunk_len == plaintext.len();
        let tag = if emit_final && is_final {
            secretstream::Tag::Final
        } else {
            secretstream::Tag::Message
        };

        stream
            .push_to_vec(
                &plaintext[offset..offset + chunk_len],
                None,
                tag,
                cipher_chunk,
            )
            .map_err(|_| anyhow!("crypto_secretstream push failed."))?;

        if cipher_chunk.len() > u32::MAX as usize {
            bail!("crypto_secretstream frame too large.");
        }

        let final_size = encrypted
            .len()
            .checked_add(STREAM_FRAME_LEN_BYTES)
            .and_then(|size| size.checked_add(cipher_chunk.len()))
            .ok_or_else(|| anyhow!("File Size Error: Encrypted output overflow."))?;
        if final_size > max_encrypted_size {
            bail!(
                "File Size Error: Compressed and encrypted payload exceeds the selected output size limit."
            );
        }

        encrypted
            .try_reserve(final_size - encrypted.len())
            .map_err(|_| anyhow!("File Size Error: Unable to allocate encrypted output buffer."))?;

        encrypted.extend_from_slice(&(cipher_chunk.len() as u32).to_be_bytes());
        encrypted.extend_from_slice(cipher_chunk);

        offset += chunk_len;
        emit_empty_final = false;
    }

    Ok(())
}

fn decrypt_with_secretstream(
    framed_ciphertext: &[u8],
    key: &secretstream::Key,
    header_bytes: &[u8; secretstream::HEADERBYTES],
) -> Result<Option<Vec<u8>>> {
    if !span_has_range(framed_ciphertext, 0, secretstream::HEADERBYTES) {
        return Ok(None);
    }
    if framed_ciphertext[..secretstream::HEADERBYTES] != header_bytes[..] {
        return Ok(None);
    }

    let Some(header) = secretstream::Header::from_slice(header_bytes) else {
        return Ok(None);
    };
    let Ok(mut stream) = secretstream::Stream::init_pull(&header, key) else {
        return Ok(None);
    };
    let reserve_size = framed_ciphertext
        .len()
        .saturating_sub(secretstream::HEADERBYTES);
    let mut decrypted = Zeroizing::new(Vec::new());
    decrypted
        .try_reserve_exact(reserve_size)
        .map_err(|_| anyhow!("File Decryption Error: Unable to allocate plaintext buffer."))?;
    let mut offset = secretstream::HEADERBYTES;
    let mut has_final_tag = false;

    while offset < framed_ciphertext.len() {
        if framed_ciphertext.len() - offset < STREAM_FRAME_LEN_BYTES {
            return Ok(None);
        }

        let frame_len = read_frame_len(framed_ciphertext, offset) as usize;
        offset += STREAM_FRAME_LEN_BYTES;

        if frame_len < secretstream::ABYTES
            || frame_len > framed_ciphertext.len().saturating_sub(offset)
            || frame_len - secretstream::ABYTES > STREAM_CHUNK_SIZE
        {
            return Ok(None);
        }

        let frame = &framed_ciphertext[offset..offset + frame_len];
        let Ok((mut plain_chunk, tag)) = stream.pull(frame, None) else {
            return Ok(None);
        };
        decrypted.extend_from_slice(&plain_chunk);
        plain_chunk.zeroize();

        offset += frame_len;
        if tag == secretstream::Tag::Final {
            has_final_tag = true;
            break;
        }
    }

    if !has_final_tag || offset != framed_ciphertext.len() {
        return Ok(None);
    }

    Ok(Some(std::mem::take(&mut *decrypted)))
}

/// Fills `out_pin` in place rather than returning the secret by value: a moved
/// return leaves an unwiped copy of the PIN in the source slot that nothing owns.
fn generate_recovery_pin(out_pin: &mut Zeroizing<u64>) {
    **out_pin = 0;
    while **out_pin == 0 {
        let mut pin_bytes = [0u8; 8];
        randombytes_into(&mut pin_bytes);
        **out_pin = u64::from_ne_bytes(pin_bytes);
        pin_bytes.zeroize();
    }
}

/// Extract the length-prefixed filename (raw OS bytes; not required to be UTF-8).
fn extract_filename_prefix(payload: &mut Vec<u8>) -> Result<OsString> {
    const CORRUPT_FILE_ERROR: &str = "File Recovery Error: Embedded profile is corrupt.";
    if payload.is_empty() {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    let filename_len = payload[0] as usize;
    if filename_len == 0 {
        bail!("{}", CORRUPT_FILE_ERROR);
    }
    let prefix_len = 1 + filename_len;
    require_span_range(payload, 0, prefix_len, CORRUPT_FILE_ERROR)?;

    let filename = OsString::from_vec(payload[1..prefix_len].to_vec());

    let old_len = payload.len();
    if old_len > prefix_len {
        payload.copy_within(prefix_len.., 0);
    }
    let new_len = old_len - prefix_len;
    payload[new_len..].zeroize();
    payload.truncate(new_len);
    Ok(filename)
}

fn get_kdf_metadata_version(data: &[u8], base_index: usize) -> KdfMetadataVersion {
    if !span_has_range(data, base_index, KDF_METADATA_REGION_BYTES) {
        return KdfMetadataVersion::None;
    }

    let has_common_fields = data[base_index + KDF_ALG_OFFSET] == KDF_ALG_ARGON2ID13
        && data[base_index + KDF_SENTINEL_OFFSET] == KDF_SENTINEL;
    if !has_common_fields {
        return KdfMetadataVersion::None;
    }

    if data
        [base_index + KDF_MAGIC_OFFSET..base_index + KDF_MAGIC_OFFSET + KDF_METADATA_MAGIC_V2.len()]
        == *KDF_METADATA_MAGIC_V2
    {
        KdfMetadataVersion::V2Secretstream
    } else {
        KdfMetadataVersion::None
    }
}

pub fn has_supported_kdf_metadata_at(data: &[u8], base_index: usize) -> bool {
    get_kdf_metadata_version(data, base_index) == KdfMetadataVersion::V2Secretstream
}

/// True if `profile` carries pdvrdt's KDF metadata and signature at the offsets
/// for this layout -- the payload fingerprint.
///
/// Deliberately liberal: conceal uses it to strip a stale payload out of a reused
/// cover, so it must still match one too truncated for recovery to accept. The
/// recover side adds its own length requirement on top.
pub fn has_pdvrdt_profile_markers(profile: &[u8], offsets: &ProfileOffsets) -> bool {
    has_supported_kdf_metadata_at(profile, offsets.kdf_metadata)
        && bytes_equal_at(profile, offsets.pdv_signature, PDVRDT_SIG)
}

/// The zlib-compressed profile inside an iCCP chunk if that chunk is a pdvrdt
/// Mastodon payload, or `None` if it is an ordinary ICC profile.
///
/// Inflates only the fixed metadata/signature prefix, so a genuine profile or a
/// decompression bomb is rejected without expanding it. Single source of truth:
/// conceal must strip such a payload when its image is reused as a cover and
/// recover must extract it, and the two can never be allowed to disagree about
/// which chunks count.
pub fn find_pdvrdt_iccp_payload(iccp_data: &[u8]) -> Option<&[u8]> {
    const PROFILE_PREFIX_SIZE: usize = MASTODON_OFFSETS.pdv_signature + PDVRDT_SIG.len();

    if !iccp_data.starts_with(PDVRDT_ICCP_PREFIX) {
        return None;
    }
    let compressed = &iccp_data[PDVRDT_ICCP_PREFIX.len()..];
    if compressed.is_empty() {
        return None;
    }

    let profile_prefix = zlib_inflate_prefix(compressed, PROFILE_PREFIX_SIZE).ok()?;
    if profile_prefix.len() != PROFILE_PREFIX_SIZE
        || !has_pdvrdt_profile_markers(&profile_prefix, &MASTODON_OFFSETS)
    {
        return None;
    }
    Some(compressed)
}

/// Writes the freshly generated recovery PIN into `out_pin` rather than
/// returning it: see generate_recovery_pin() for why no secret leaves this
/// module by value.
pub fn encrypt_compressed_file_to_profile(
    out_pin: &mut Zeroizing<u64>,
    profile_vec: &mut Vec<u8>,
    data_file: &OpenInputFile,
    data_filename: &[u8],
    is_compressed_file: bool,
    has_mastodon_option: bool,
    max_profile_size: usize,
) -> Result<()> {
    let offsets = if has_mastodon_option {
        &MASTODON_OFFSETS
    } else {
        &DEFAULT_OFFSETS
    };
    const CORRUPT_PROFILE_ERROR: &str = "Internal Error: Corrupt profile template.";

    require_span_range(
        profile_vec,
        offsets.kdf_metadata,
        KDF_METADATA_REGION_BYTES,
        CORRUPT_PROFILE_ERROR,
    )?;
    if offsets.encrypted_file != profile_vec.len() {
        bail!("{}", CORRUPT_PROFILE_ERROR);
    }
    if profile_vec.len() > max_profile_size {
        bail!("File Size Error: Cover image leaves no room for an embedded payload.");
    }

    if data_filename.is_empty() || data_filename.len() > u8::MAX as usize {
        bail!("Data File Error: Invalid data filename length.");
    }

    let mut filename_prefix = Zeroizing::new(vec![0u8; 1 + data_filename.len()]);
    filename_prefix[0] = data_filename.len() as u8;
    filename_prefix[1..].copy_from_slice(data_filename);

    // Generated straight into the caller's storage: there is never a second copy
    // to scrub, and the caller's Zeroizing wipes it on every path out of here.
    generate_recovery_pin(out_pin);
    let mut salt = Zeroizing::new([0u8; pwhash::SALTBYTES]);
    randombytes_into(&mut *salt);

    let key = derive_key_from_pin(out_pin, &salt)?;
    let (mut stream, stream_header) = secretstream::Stream::init_push(&key)
        .map_err(|_| anyhow!("crypto_secretstream init_push failed."))?;

    if stream_header.0.len() > max_profile_size - profile_vec.len() {
        bail!(
            "File Size Error: Compressed and encrypted payload exceeds the selected output size limit."
        );
    }
    profile_vec
        .try_reserve(stream_header.0.len())
        .map_err(|_| anyhow!("File Size Error: Unable to allocate encrypted output buffer."))?;
    profile_vec.extend_from_slice(&stream_header.0);

    let mut cipher_chunk =
        Zeroizing::new(Vec::with_capacity(STREAM_CHUNK_SIZE + secretstream::ABYTES));
    append_encrypted_frames(
        profile_vec,
        &filename_prefix,
        &mut stream,
        &mut cipher_chunk,
        max_profile_size,
        false,
    )?;

    let mut saw_compressed_output = false;
    zlib_deflate_file(data_file, is_compressed_file, |chunk| {
        if chunk.is_empty() {
            return Ok(());
        }

        saw_compressed_output = true;
        append_encrypted_frames(
            profile_vec,
            chunk,
            &mut stream,
            &mut cipher_chunk,
            max_profile_size,
            false,
        )
    })?;

    if !saw_compressed_output {
        bail!("File Size Error: File is zero bytes. Probable compression failure.");
    }

    // Close the secretstream with an empty final frame.
    append_encrypted_frames(
        profile_vec,
        &[],
        &mut stream,
        &mut cipher_chunk,
        max_profile_size,
        true,
    )?;

    let mut random_region = Zeroizing::new([0u8; KDF_METADATA_REGION_BYTES]);
    randombytes_into(&mut *random_region);
    profile_vec[offsets.kdf_metadata..offsets.kdf_metadata + KDF_METADATA_REGION_BYTES]
        .copy_from_slice(&*random_region);

    profile_vec
        [offsets.kdf_metadata + KDF_MAGIC_OFFSET..offsets.kdf_metadata + KDF_MAGIC_OFFSET + 4]
        .copy_from_slice(KDF_METADATA_MAGIC_V2);
    profile_vec[offsets.kdf_metadata + KDF_ALG_OFFSET] = KDF_ALG_ARGON2ID13;
    profile_vec[offsets.kdf_metadata + KDF_SENTINEL_OFFSET] = KDF_SENTINEL;

    require_span_range(
        profile_vec,
        offsets.kdf_metadata + KDF_SALT_OFFSET,
        pwhash::SALTBYTES,
        CORRUPT_PROFILE_ERROR,
    )?;
    require_span_range(
        profile_vec,
        offsets.kdf_metadata + KDF_NONCE_OFFSET,
        secretstream::HEADERBYTES,
        CORRUPT_PROFILE_ERROR,
    )?;

    profile_vec[offsets.kdf_metadata + KDF_SALT_OFFSET
        ..offsets.kdf_metadata + KDF_SALT_OFFSET + pwhash::SALTBYTES]
        .copy_from_slice(&*salt);
    profile_vec[offsets.kdf_metadata + KDF_NONCE_OFFSET
        ..offsets.kdf_metadata + KDF_NONCE_OFFSET + secretstream::HEADERBYTES]
        .copy_from_slice(&stream_header.0);

    Ok(())
}

/// Decrypt embedded payload. Returns `Ok(None)` only for wrong PIN / corrupt crypto
/// (after a well-formed PIN was entered). PIN format errors surface as `Err`.
pub fn decrypt_data_file(
    png_vec: &mut Vec<u8>,
    is_mastodon_file: bool,
) -> Result<Option<OsString>> {
    let offsets = if is_mastodon_file {
        &MASTODON_OFFSETS
    } else {
        &DEFAULT_OFFSETS
    };

    const CORRUPT_FILE_ERROR: &str = "File Recovery Error: Embedded profile is corrupt.";
    require_span_range(
        png_vec,
        offsets.kdf_metadata,
        KDF_METADATA_REGION_BYTES,
        CORRUPT_FILE_ERROR,
    )?;
    if offsets.encrypted_file > png_vec.len() {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    if get_kdf_metadata_version(png_vec, offsets.kdf_metadata) != KdfMetadataVersion::V2Secretstream
    {
        bail!(
            "File Decryption Error: Unsupported legacy encrypted file format. Use an older pdvrdt release to recover this file."
        );
    }

    let mut recovery_pin = Zeroizing::new(0u64);
    get_pin(&mut recovery_pin)?;
    let mut salt = Zeroizing::new([0u8; pwhash::SALTBYTES]);
    let mut stream_header = Zeroizing::new([0u8; secretstream::HEADERBYTES]);

    require_span_range(
        png_vec,
        offsets.kdf_metadata + KDF_SALT_OFFSET,
        pwhash::SALTBYTES,
        CORRUPT_FILE_ERROR,
    )?;
    require_span_range(
        png_vec,
        offsets.kdf_metadata + KDF_NONCE_OFFSET,
        secretstream::HEADERBYTES,
        CORRUPT_FILE_ERROR,
    )?;

    salt.copy_from_slice(
        &png_vec[offsets.kdf_metadata + KDF_SALT_OFFSET
            ..offsets.kdf_metadata + KDF_SALT_OFFSET + pwhash::SALTBYTES],
    );
    stream_header.copy_from_slice(
        &png_vec[offsets.kdf_metadata + KDF_NONCE_OFFSET
            ..offsets.kdf_metadata + KDF_NONCE_OFFSET + secretstream::HEADERBYTES],
    );

    let key = derive_key_from_pin(&recovery_pin, &salt)?;

    let ciphertext_length = png_vec.len() - offsets.encrypted_file;
    if ciphertext_length < minimum_stream_cipher_size() {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    let framed_ciphertext = &png_vec[offsets.encrypted_file..];
    let Some(decrypted) = decrypt_with_secretstream(framed_ciphertext, &key, &stream_header)?
    else {
        return Ok(None);
    };

    *png_vec = decrypted;
    Ok(Some(extract_filename_prefix(png_vec)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_len_roundtrip() {
        let out = 0x01020304u32.to_be_bytes().to_vec();
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(read_frame_len(&out, 0), 0x01020304);
    }

    #[test]
    fn extract_filename_accepts_non_utf8_bytes() {
        let mut payload = vec![3, 0xC3, 0x28, 0x41, b'Z']; // invalid UTF-8 sequence + data
                                                           // 0xC3 0x28 is invalid UTF-8; OsString still accepts the raw bytes.
        payload[0] = 3;
        let name = extract_filename_prefix(&mut payload).unwrap();
        use std::os::unix::ffi::OsStrExt;
        assert_eq!(name.as_bytes(), &[0xC3, 0x28, 0x41]);
        assert_eq!(payload, b"Z");
    }
}
