//! sodiumoxide-shaped API implemented over `alkali`.
//!
//! The rest of the crate calls these names exactly as it called sodiumoxide's,
//! so migrating a file is just repointing its `use` path here. All primitives
//! bottom out in libsodium, so ciphertext is byte-identical to the C++ tool.

use alkali::hash::pbkdf::argon2id as ak_pbkdf;
use alkali::symmetric::cipher_stream::xchacha20poly1305 as ak_stream;
use zeroize::Zeroize;

/// `sodiumoxide::init()` equivalent. alkali initialises libsodium lazily and is
/// thread-safe, so this is a no-op kept for call-site compatibility.
pub fn init() -> Result<(), ()> {
    Ok(())
}

pub fn memzero(buf: &mut [u8]) {
    buf.zeroize();
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

pub mod secretbox {
    pub const KEYBYTES: usize = 32; // crypto_secretbox_KEYBYTES
}

pub mod argon2id13 {
    use super::ak_pbkdf;

    pub const SALTBYTES: usize = ak_pbkdf::SALT_LENGTH;
    pub const OPSLIMIT_INTERACTIVE: usize = ak_pbkdf::OPS_LIMIT_INTERACTIVE;
    pub const MEMLIMIT_INTERACTIVE: usize = ak_pbkdf::MEM_LIMIT_INTERACTIVE;

    /// Mirror of `sodiumoxide`'s `argon2id13::Salt`.
    #[derive(Clone)]
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
    /// Internally calls alkali's KDF with a caller-provided salt + explicit limits.
    pub fn derive_key(
        key_out: &mut [u8],
        password: &[u8],
        salt: &Salt,
        ops: usize,
        mem: usize,
    ) -> Result<(), ()> {
        // alkali's Salt for argon2id is a type alias: type Salt = [u8; SALT_LENGTH]
        // derive_key signature: (password, &Salt, ops_limit, mem_limit, key_out)
        ak_pbkdf::derive_key(password, &salt.0, ops, mem, key_out).map_err(|_| ())?;
        Ok(())
    }
}

pub mod secretstream {
    use super::ak_stream;

    pub const KEYBYTES: usize = ak_stream::KEY_LENGTH;
    pub const HEADERBYTES: usize = ak_stream::HEADER_LENGTH;
    pub const ABYTES: usize = ak_stream::OVERHEAD_LENGTH;

    #[derive(Clone)]
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
    #[derive(Clone)]
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

    // Marker types so call sites can name `Stream<Push>` / `Stream<Pull>`.
    pub enum Push {}
    pub enum Pull {}

    pub struct Stream<Dir> {
        inner: StreamInner,
        _dir: core::marker::PhantomData<Dir>,
    }

    enum StreamInner {
        Enc(ak_stream::EncryptionStream),
        Dec(ak_stream::DecryptionStream),
        // Tombstone state used only transiently when consuming EncryptionStream::finalise
        Empty,
    }

    impl Stream<Push> {
        /// Returns `(stream, header)` like sodiumoxide's `init_push`.
        pub fn init_push(key: &Key) -> Result<(Stream<Push>, Header), ()> {
            // alkali Key is a hardened buffer; construct via TryFrom<&[u8]>
            let ak_key = ak_stream::Key::try_from(&key.0[..]).map_err(|_| ())?;
            let enc = ak_stream::EncryptionStream::new(&ak_key).map_err(|_| ())?;
            // get_header() returns Header which is [u8; HEADER_LENGTH] (a type alias, not a struct)
            let hdr_bytes: [u8; HEADERBYTES] = enc.get_header();
            Ok((
                Stream { inner: StreamInner::Enc(enc), _dir: core::marker::PhantomData },
                Header(hdr_bytes),
            ))
        }

        /// Encrypt one chunk, returning ciphertext (len = msg.len() + ABYTES).
        pub fn push(&mut self, msg: &[u8], aad: Option<&[u8]>, tag: Tag) -> Result<Vec<u8>, ()> {
            let mut ct = vec![0u8; msg.len() + ABYTES];
            match tag {
                Tag::Message => {
                    let StreamInner::Enc(enc) = &mut self.inner else { return Err(()); };
                    let written = enc.encrypt(msg, aad, &mut ct).map_err(|_| ())?;
                    ct.truncate(written);
                }
                Tag::Final => {
                    // finalise() consumes self; extract the EncryptionStream from the enum
                    let inner = core::mem::replace(&mut self.inner, StreamInner::Empty);
                    let StreamInner::Enc(enc) = inner else { return Err(()); };
                    let written = enc.finalise(msg, aad, &mut ct).map_err(|_| ())?;
                    ct.truncate(written);
                }
            };
            Ok(ct)
        }

        /// sodiumoxide-compatible: encrypt one chunk, REPLACING `out` with the frame.
        pub fn push_to_vec(&mut self, msg: &[u8], aad: Option<&[u8]>, tag: Tag, out: &mut Vec<u8>) -> Result<(), ()> {
            let ct = self.push(msg, aad, tag)?;
            out.clear();
            out.extend_from_slice(&ct);
            Ok(())
        }
    }

    impl Stream<Pull> {
        pub fn init_pull(header: &Header, key: &Key) -> Result<Stream<Pull>, ()> {
            // alkali Key is a hardened buffer; construct via TryFrom<&[u8]>
            let ak_key = ak_stream::Key::try_from(&key.0[..]).map_err(|_| ())?;
            // alkali Header is type Header = [u8; HEADER_LENGTH]; pass the inner array
            let dec = ak_stream::DecryptionStream::new(&ak_key, &header.0).map_err(|_| ())?;
            Ok(Stream { inner: StreamInner::Dec(dec), _dir: core::marker::PhantomData })
        }

        /// Decrypt one chunk, returning `(plaintext, tag)`.
        pub fn pull(&mut self, ct: &[u8], aad: Option<&[u8]>) -> Result<(Vec<u8>, Tag), ()> {
            let StreamInner::Dec(dec) = &mut self.inner else { return Err(()); };
            if ct.len() < ABYTES {
                return Err(());
            }
            let mut pt = vec![0u8; ct.len() - ABYTES];
            // alkali decrypt returns Result<(MessageType, usize), AlkaliError>
            let (msg_type, written) = dec.decrypt(ct, aad, &mut pt).map_err(|_| ())?;
            pt.truncate(written);
            let tag = match msg_type {
                ak_stream::MessageType::Final => Tag::Final,
                _ => Tag::Message,
            };
            Ok((pt, tag))
        }
    }
}
