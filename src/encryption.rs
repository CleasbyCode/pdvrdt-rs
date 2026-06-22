use crate::common::Option_;
use crate::compression::zlib_deflate_file;
use crate::pin_input::get_pin;
use anyhow::{anyhow, bail, Result};
use crate::crypto::argon2id13 as pwhash;
use crate::crypto::secretstream;
use crate::crypto::randombytes_into;
use std::path::Path;
use zeroize::Zeroize;

pub struct ProfileOffsets {
    pub kdf_metadata: usize,
    pub encrypted_file: usize,
}

pub const MASTODON_OFFSETS: ProfileOffsets = ProfileOffsets {
    kdf_metadata: 0x1BE,
    encrypted_file: 0x1FE,
};

pub const DEFAULT_OFFSETS: ProfileOffsets = ProfileOffsets {
    kdf_metadata: 0x02D,
    encrypted_file: 0x06E,
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
const STREAM_FRAME_LEN_BYTES: usize = 4;
const KDF_METADATA_MAGIC_V2: &[u8; 4] = b"KDF2";

#[derive(Clone, Copy, PartialEq, Eq)]
enum KdfMetadataVersion {
    None,
    V2Secretstream,
}

fn span_has_range(data: &[u8], index: usize, length: usize) -> bool {
    index <= data.len() && length <= data.len().saturating_sub(index)
}

fn require_span_range(data: &[u8], index: usize, length: usize, message: &str) -> Result<()> {
    if !span_has_range(data, index, length) {
        bail!("{}", message);
    }
    Ok(())
}

fn write_frame_len(out: &mut Vec<u8>, frame_len: u32) {
    out.extend_from_slice(&frame_len.to_be_bytes());
}

fn read_frame_len(data: &[u8], index: usize) -> u32 {
    u32::from_be_bytes(
        data[index..index + STREAM_FRAME_LEN_BYTES]
            .try_into()
            .unwrap(),
    )
}

fn derive_key_from_pin(
    pin: usize,
    salt_bytes: &[u8; pwhash::SALTBYTES],
) -> Result<secretstream::Key> {
    let mut pin_buf = pin.to_string().into_bytes();
    let salt = pwhash::Salt::from_slice(salt_bytes)
        .ok_or_else(|| anyhow!("KDF Error: Invalid salt length."))?;

    let mut key_bytes = [0u8; secretstream::KEYBYTES];
    pwhash::derive_key(
        &mut key_bytes,
        &pin_buf,
        &salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| anyhow!("KDF Error: Unable to derive encryption key."))?;

    pin_buf.zeroize();
    let key = secretstream::Key::from_slice(&key_bytes)
        .ok_or_else(|| anyhow!("KDF Error: Invalid derived key length."))?;
    key_bytes.zeroize();
    Ok(key)
}

fn append_encrypted_frames(
    encrypted: &mut Vec<u8>,
    plaintext: &[u8],
    stream: &mut secretstream::Stream<secretstream::Push>,
    cipher_chunk: &mut Vec<u8>,
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

        write_frame_len(encrypted, cipher_chunk.len() as u32);
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
) -> Option<Vec<u8>> {
    if !span_has_range(framed_ciphertext, 0, secretstream::HEADERBYTES) {
        return None;
    }
    if framed_ciphertext[..secretstream::HEADERBYTES] != header_bytes[..] {
        return None;
    }

    let header = secretstream::Header::from_slice(header_bytes)?;
    let mut stream = secretstream::Stream::init_pull(&header, key).ok()?;
    let mut decrypted = Vec::with_capacity(
        framed_ciphertext
            .len()
            .saturating_sub(secretstream::HEADERBYTES),
    );
    let mut offset = secretstream::HEADERBYTES;
    let mut has_final_tag = false;

    while offset < framed_ciphertext.len() {
        if framed_ciphertext.len() - offset < STREAM_FRAME_LEN_BYTES {
            return None;
        }

        let frame_len = read_frame_len(framed_ciphertext, offset) as usize;
        offset += STREAM_FRAME_LEN_BYTES;

        if frame_len < secretstream::ABYTES
            || frame_len > framed_ciphertext.len().saturating_sub(offset)
        {
            return None;
        }

        let frame = &framed_ciphertext[offset..offset + frame_len];
        let (plain_chunk, tag) = stream.pull(frame, None).ok()?;
        decrypted.extend_from_slice(&plain_chunk);

        offset += frame_len;
        if tag == secretstream::Tag::Final {
            has_final_tag = true;
            break;
        }
    }

    if !has_final_tag || offset != framed_ciphertext.len() {
        return None;
    }

    Some(decrypted)
}

fn generate_recovery_pin() -> usize {
    let mut pin = 0usize;
    while pin == 0 {
        let mut pin_bytes = [0u8; 8];
        randombytes_into(&mut pin_bytes);
        pin = u64::from_ne_bytes(pin_bytes) as usize;
    }
    pin
}

fn extract_filename_prefix(payload: &mut Vec<u8>) -> Result<String> {
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

    let filename = String::from_utf8(payload[1..prefix_len].to_vec())
        .map_err(|_| anyhow!(CORRUPT_FILE_ERROR))?;

    if payload.len() > prefix_len {
        payload.copy_within(prefix_len.., 0);
    }
    payload.truncate(payload.len() - prefix_len);
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

pub fn encrypt_compressed_file_to_profile(
    profile_vec: &mut Vec<u8>,
    data_file_path: &Path,
    data_filename: &str,
    option: Option_,
    is_compressed_file: bool,
    has_mastodon_option: bool,
) -> Result<usize> {
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

    if data_filename.is_empty() || data_filename.len() > u8::MAX as usize {
        bail!("Data File Error: Invalid data filename length.");
    }

    let mut filename_prefix = vec![0u8; 1 + data_filename.len()];
    filename_prefix[0] = data_filename.len() as u8;
    filename_prefix[1..].copy_from_slice(data_filename.as_bytes());

    let pin = generate_recovery_pin();
    let salt_vec = crate::crypto::randombytes(pwhash::SALTBYTES);
    let mut salt = [0u8; pwhash::SALTBYTES];
    salt.copy_from_slice(&salt_vec);

    let key = derive_key_from_pin(pin, &salt)?;
    let (mut stream, stream_header) = secretstream::Stream::init_push(&key)
        .map_err(|_| anyhow!("crypto_secretstream init_push failed."))?;

    profile_vec.extend_from_slice(&stream_header.0);

    let mut cipher_chunk = Vec::with_capacity(STREAM_CHUNK_SIZE + secretstream::ABYTES);
    append_encrypted_frames(
        profile_vec,
        &filename_prefix,
        &mut stream,
        &mut cipher_chunk,
        false,
    )?;
    filename_prefix.zeroize();

    let mut pending_compressed_chunk = Vec::new();
    let mut saw_compressed_output = false;
    zlib_deflate_file(data_file_path, option, is_compressed_file, |chunk| {
        if chunk.is_empty() {
            return Ok(());
        }

        saw_compressed_output = true;
        if !pending_compressed_chunk.is_empty() {
            append_encrypted_frames(
                profile_vec,
                &pending_compressed_chunk,
                &mut stream,
                &mut cipher_chunk,
                false,
            )?;
            pending_compressed_chunk.zeroize();
            pending_compressed_chunk.clear();
        }

        pending_compressed_chunk.extend_from_slice(chunk);
        Ok(())
    })?;

    if !saw_compressed_output || pending_compressed_chunk.is_empty() {
        bail!("File Size Error: File is zero bytes. Probable compression failure.");
    }

    append_encrypted_frames(
        profile_vec,
        &pending_compressed_chunk,
        &mut stream,
        &mut cipher_chunk,
        true,
    )?;
    pending_compressed_chunk.zeroize();
    pending_compressed_chunk.clear();

    let random_region = crate::crypto::randombytes(KDF_METADATA_REGION_BYTES);
    profile_vec[offsets.kdf_metadata..offsets.kdf_metadata + KDF_METADATA_REGION_BYTES]
        .copy_from_slice(&random_region);

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
        .copy_from_slice(&salt);
    profile_vec[offsets.kdf_metadata + KDF_NONCE_OFFSET
        ..offsets.kdf_metadata + KDF_NONCE_OFFSET + secretstream::HEADERBYTES]
        .copy_from_slice(&stream_header.0);

    Ok(pin)
}

pub fn decrypt_data_file(png_vec: &mut Vec<u8>, is_mastodon_file: bool) -> Result<Option<String>> {
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

    let recovery_pin = get_pin();
    let mut salt = [0u8; pwhash::SALTBYTES];
    let mut stream_header = [0u8; secretstream::HEADERBYTES];

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

    let key = derive_key_from_pin(recovery_pin, &salt)?;

    let ciphertext_length = png_vec.len() - offsets.encrypted_file;
    let min_stream_cipher_size = secretstream::HEADERBYTES
        .checked_add(STREAM_FRAME_LEN_BYTES)
        .and_then(|v| v.checked_add(secretstream::ABYTES))
        .ok_or_else(|| anyhow!(CORRUPT_FILE_ERROR))?;
    if ciphertext_length < min_stream_cipher_size {
        bail!("{}", CORRUPT_FILE_ERROR);
    }

    let framed_ciphertext = &png_vec[offsets.encrypted_file..];
    let Some(decrypted) = decrypt_with_secretstream(framed_ciphertext, &key, &stream_header) else {
        return Ok(None);
    };

    *png_vec = decrypted;
    Ok(Some(extract_filename_prefix(png_vec)?))
}
