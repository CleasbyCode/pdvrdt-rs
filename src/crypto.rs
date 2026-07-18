//! sodiumoxide-shaped API implemented over `alkali`.
//!
//! The rest of the crate calls these names exactly as it called sodiumoxide's,
//! so migrating a file is just repointing its `use` path here. All primitives
//! bottom out in libsodium, so ciphertext is byte-identical to the C++ tool.

use alkali::hash::pbkdf::argon2id as ak_pbkdf;
use alkali::symmetric::cipher_stream::xchacha20poly1305 as ak_stream;

/// Opaque crypto failure (libsodium / alkali error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

pub type Result<T> = core::result::Result<T, Error>;

/// Initialise libsodium via alkali (`sodium_init`). Safe to call multiple times.
pub fn init() -> Result<()> {
    alkali::require_init().map(|_| ()).map_err(|_| Error)
}

/// `randombytes_into` — fill `buf` with CSPRNG bytes from libsodium.
pub fn randombytes_into(buf: &mut [u8]) {
    alkali::random::fill_random(buf).expect("libsodium randombytes failed");
}

/// `randombytes(n)` — allocate `n` random bytes.
pub fn randombytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    randombytes_into(&mut v);
    v
}

/// `randombytes_uniform(bound)` — unbiased uniform value in `[0, bound)`,
/// matching libsodium's rejection-sampling semantics. Used only for padding
/// bytes, whose exact values do not affect interop.
pub fn randombytes_uniform(bound: u32) -> u32 {
    if bound < 2 {
        return 0;
    }
    let reject = bound.wrapping_neg() % bound; // (2^32 - bound) % bound
    loop {
        let mut b = [0u8; 4];
        randombytes_into(&mut b);
        let r = u32::from_le_bytes(b);
        if r >= reject {
            return r % bound;
        }
    }
}

pub mod argon2id13 {
    use super::ak_pbkdf;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    pub const SALTBYTES: usize = ak_pbkdf::SALT_LENGTH;
    pub const OPSLIMIT_INTERACTIVE: usize = ak_pbkdf::OPS_LIMIT_INTERACTIVE;
    pub const MEMLIMIT_INTERACTIVE: usize = ak_pbkdf::MEM_LIMIT_INTERACTIVE;

    /// Mirror of `sodiumoxide`'s `argon2id13::Salt`.
    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct Salt(pub [u8; SALTBYTES]);

    impl Salt {
        pub fn from_slice(bytes: &[u8]) -> Option<Salt> {
            if bytes.len() != SALTBYTES {
                return None;
            }
            let mut s = [0u8; SALTBYTES];
            s.copy_from_slice(bytes);
            Some(Salt(s))
        }
    }

    /// Mirror of `sodiumoxide`'s argument order: `(key_out, password, salt, ops, mem)`.
    pub fn derive_key(
        key_out: &mut [u8],
        password: &[u8],
        salt: &Salt,
        ops: usize,
        mem: usize,
    ) -> super::Result<()> {
        ak_pbkdf::derive_key(password, &salt.0, ops, mem, key_out).map_err(|_| super::Error)?;
        Ok(())
    }
}

pub mod secretstream {
    use super::ak_stream;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    pub const KEYBYTES: usize = ak_stream::KEY_LENGTH;
    pub const HEADERBYTES: usize = ak_stream::HEADER_LENGTH;
    pub const ABYTES: usize = ak_stream::OVERHEAD_LENGTH;

    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct Key(pub [u8; KEYBYTES]);

    impl Key {
        pub fn from_slice(bytes: &[u8]) -> Option<Key> {
            if bytes.len() != KEYBYTES {
                return None;
            }
            let mut k = [0u8; KEYBYTES];
            k.copy_from_slice(bytes);
            Some(Key(k))
        }
    }

    /// Tuple struct so existing call sites that read `header.0` keep working.
    /// Zeroized on drop so residual material does not linger in RAM.
    #[derive(Clone, Zeroize, ZeroizeOnDrop)]
    pub struct Header(pub [u8; HEADERBYTES]);

    impl Header {
        pub fn from_slice(bytes: &[u8]) -> Option<Header> {
            if bytes.len() != HEADERBYTES {
                return None;
            }
            let mut h = [0u8; HEADERBYTES];
            h.copy_from_slice(bytes);
            Some(Header(h))
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Tag {
        Message,
        Final,
    }

    pub enum Push {}
    pub enum Pull {}

    pub struct Stream<Dir> {
        inner: StreamInner,
        _dir: core::marker::PhantomData<Dir>,
    }

    enum StreamInner {
        Enc(ak_stream::EncryptionStream),
        Dec(ak_stream::DecryptionStream),
        /// Tombstone used only transiently when consuming EncryptionStream::finalise.
        Empty,
    }

    impl Stream<Push> {
        /// Returns `(stream, header)` like sodiumoxide's `init_push`.
        pub fn init_push(key: &Key) -> super::Result<(Stream<Push>, Header)> {
            let ak_key = ak_stream::Key::try_from(&key.0[..]).map_err(|_| super::Error)?;
            let enc = ak_stream::EncryptionStream::new(&ak_key).map_err(|_| super::Error)?;
            let hdr_bytes: [u8; HEADERBYTES] = enc.get_header();
            Ok((
                Stream {
                    inner: StreamInner::Enc(enc),
                    _dir: core::marker::PhantomData,
                },
                Header(hdr_bytes),
            ))
        }

        /// Encrypt one chunk, returning ciphertext (len = msg.len() + ABYTES).
        pub fn push(&mut self, msg: &[u8], aad: Option<&[u8]>, tag: Tag) -> super::Result<Vec<u8>> {
            let output_len = msg.len().checked_add(ABYTES).ok_or(super::Error)?;
            let mut ct = Vec::new();
            ct.try_reserve_exact(output_len).map_err(|_| super::Error)?;
            ct.resize(output_len, 0);
            match tag {
                Tag::Message => {
                    let StreamInner::Enc(enc) = &mut self.inner else {
                        return Err(super::Error);
                    };
                    let written = enc.encrypt(msg, aad, &mut ct).map_err(|_| super::Error)?;
                    ct.truncate(written);
                }
                Tag::Final => {
                    let inner = core::mem::replace(&mut self.inner, StreamInner::Empty);
                    let StreamInner::Enc(enc) = inner else {
                        return Err(super::Error);
                    };
                    let written = enc.finalise(msg, aad, &mut ct).map_err(|_| super::Error)?;
                    ct.truncate(written);
                }
            };
            Ok(ct)
        }

        /// sodiumoxide-compatible: encrypt one chunk, replacing `out` with the frame.
        pub fn push_to_vec(
            &mut self,
            msg: &[u8],
            aad: Option<&[u8]>,
            tag: Tag,
            out: &mut Vec<u8>,
        ) -> super::Result<()> {
            let ct = self.push(msg, aad, tag)?;
            out.clear();
            out.extend_from_slice(&ct);
            Ok(())
        }
    }

    impl Stream<Pull> {
        pub fn init_pull(header: &Header, key: &Key) -> super::Result<Stream<Pull>> {
            let ak_key = ak_stream::Key::try_from(&key.0[..]).map_err(|_| super::Error)?;
            let dec =
                ak_stream::DecryptionStream::new(&ak_key, &header.0).map_err(|_| super::Error)?;
            Ok(Stream {
                inner: StreamInner::Dec(dec),
                _dir: core::marker::PhantomData,
            })
        }

        /// Decrypt one chunk, returning `(plaintext, tag)`.
        pub fn pull(&mut self, ct: &[u8], aad: Option<&[u8]>) -> super::Result<(Vec<u8>, Tag)> {
            let StreamInner::Dec(dec) = &mut self.inner else {
                return Err(super::Error);
            };
            if ct.len() < ABYTES {
                return Err(super::Error);
            }
            let output_len = ct.len() - ABYTES;
            let mut plaintext = Vec::new();
            plaintext
                .try_reserve_exact(output_len)
                .map_err(|_| super::Error)?;
            plaintext.resize(output_len, 0);
            let mut pt = zeroize::Zeroizing::new(plaintext);
            let (msg_type, written) = dec.decrypt(ct, aad, &mut pt).map_err(|_| super::Error)?;
            pt.truncate(written);
            let tag = match msg_type {
                ak_stream::MessageType::Final => Tag::Final,
                _ => Tag::Message,
            };
            Ok((core::mem::take(&mut *pt), tag))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_succeeds() {
        assert!(init().is_ok());
    }

    #[test]
    fn randombytes_uniform_in_range() {
        assert_eq!(randombytes_uniform(0), 0);
        assert_eq!(randombytes_uniform(1), 0);
        for _ in 0..64 {
            let r = randombytes_uniform(10);
            assert!(r < 10);
        }
    }

    #[test]
    fn secretstream_roundtrip() {
        init().unwrap();
        let key = secretstream::Key([7u8; secretstream::KEYBYTES]);
        let (mut push, header) = secretstream::Stream::init_push(&key).unwrap();
        let ct = push.push(b"hello", None, secretstream::Tag::Final).unwrap();
        let mut pull = secretstream::Stream::init_pull(&header, &key).unwrap();
        let (pt, tag) = pull.pull(&ct, None).unwrap();
        assert_eq!(pt, b"hello");
        assert_eq!(tag, secretstream::Tag::Final);
    }
}
