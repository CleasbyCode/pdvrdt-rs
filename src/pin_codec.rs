//! Recovery KEY codec (mirror of the C++ `pin_codec.{h,cpp}`).
//!
//! A pdvrdt 6.0 KEY is 16 random bytes, read as one big-endian number and
//! written as 22 Base58 characters (Bitcoin alphabet, left-padded with `1`),
//! then two check characters, shown in six groups of four:
//!
//! ```text
//! check = BE32(BLAKE2b-256("pdvrdt key check v1" || key bytes)[0..4]) mod 58^2
//! ```
//!
//! Images made before 6.0 use a numeric PIN, which still parses. Wire format:
//! changing any part of it makes printed KEYs unreadable. Nothing here
//! allocates; every temporary lives on the stack and is wiped.

use zeroize::{Zeroize, Zeroizing};

pub const KEY_BYTES: usize = 16;
pub const KEY_TEXT_CHARS: usize = 24;
pub const KEY_DISPLAY_CHARS: usize = KEY_TEXT_CHARS + KEY_TEXT_CHARS / 4 - 1;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BODY_CHARS: usize = 22;
const CHECK_MODULUS: u32 = 58 * 58;
const CHECK_DOMAIN: &[u8; 19] = b"pdvrdt key check v1";
const MAX_LEGACY_DIGITS: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum PinKind {
    #[default]
    None,
    LegacyPin,
    Key128,
}

/// The secret a payload is recovered with (mirror of the C++ `RecoveryPin`): a
/// 128-bit KEY or, for images made before 6.0, a numeric PIN. Not `Clone`, wiped
/// on drop, and filled in place through `&mut` so no stray copy outlives it.
#[derive(Default)]
pub struct RecoveryPin {
    pub kind: PinKind,
    pub legacy_value: u64,
    pub key: [u8; KEY_BYTES],
}

impl Zeroize for RecoveryPin {
    fn zeroize(&mut self) {
        self.kind = PinKind::None;
        self.legacy_value.zeroize();
        self.key.zeroize();
    }
}

impl Drop for RecoveryPin {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl RecoveryPin {
    pub fn clear(&mut self) {
        self.zeroize();
    }

    pub fn is_key(&self) -> bool {
        self.kind == PinKind::Key128
    }

    pub fn set_legacy(&mut self, value: u64) {
        self.clear();
        self.kind = PinKind::LegacyPin;
        self.legacy_value = value;
    }

    pub fn set_key(&mut self, key: &[u8; KEY_BYTES]) {
        self.clear();
        self.kind = PinKind::Key128;
        self.key.copy_from_slice(key);
    }
}

/// Which word the recovery prompt and its errors use. Default and Mastodon
/// images record whether they take a KEY (6.0+) or a PIN (older). A Reddit
/// carrier cannot be read until after entry -- the secret locates it -- so its
/// prompt names both.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinPrompt {
    Key,
    Pin,
    KeyOrPin,
}

impl PinPrompt {
    pub fn word(self) -> &'static str {
        match self {
            PinPrompt::Key => "KEY",
            PinPrompt::Pin => "PIN",
            PinPrompt::KeyOrPin => "KEY/PIN",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinParseError {
    Malformed,
    Checksum,
}

fn is_separator(c: u8) -> bool {
    c == b' ' || c == b'\t' || c == b'-'
}

fn base58_digit(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

fn check_value(key: &[u8; KEY_BYTES]) -> u32 {
    let mut hash = Zeroizing::new([0u8; 32]);
    let mut msg = Zeroizing::new([0u8; CHECK_DOMAIN.len() + KEY_BYTES]);
    msg[..CHECK_DOMAIN.len()].copy_from_slice(CHECK_DOMAIN);
    msg[CHECK_DOMAIN.len()..].copy_from_slice(key);
    // Unkeyed BLAKE2b-256. Only fails on an invalid output length, which this
    // fixed length is not.
    alkali::hash::generic::hash_custom(&msg[..], None, &mut hash[..])
        .expect("BLAKE2b-256 with a fixed output length");
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % CHECK_MODULUS
}

/// The display form (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`) of a 128-bit KEY, in a
/// stack buffer that is wiped when dropped. Never put it in a `String`.
pub fn encode_key_display(key: &[u8; KEY_BYTES]) -> Zeroizing<[u8; KEY_DISPLAY_CHARS]> {
    let mut out = Zeroizing::new([0u8; KEY_DISPLAY_CHARS]);
    let mut chars = Zeroizing::new([0u8; KEY_TEXT_CHARS]);
    let mut work = Zeroizing::new(*key);

    // Repeated long division by 58, least significant digit last.
    for i in (0..BODY_CHARS).rev() {
        let mut rem: u32 = 0;
        for b in work.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            *b = (cur / 58) as u8;
            rem = cur % 58;
        }
        chars[i] = ALPHABET[rem as usize];
    }
    let check = check_value(key);
    chars[BODY_CHARS] = ALPHABET[(check / 58) as usize];
    chars[BODY_CHARS + 1] = ALPHABET[(check % 58) as usize];

    let mut o = 0;
    for (i, &c) in chars.iter().enumerate() {
        if i != 0 && i % 4 == 0 {
            out[o] = b'-';
            o += 1;
        }
        out[o] = c;
        o += 1;
    }
    out
}

/// Parses what the user typed into `out`. Spaces, tabs and `-` are ignored
/// anywhere. Accepts either an old numeric PIN (1-20 digits, no leading zero,
/// at most 2^64-1, never 0) or a 24-character KEY whose check pair matches.
/// `out` is cleared on failure.
pub fn parse_recovery_pin_text(text: &[u8], out: &mut RecoveryPin) -> Result<(), PinParseError> {
    out.clear();

    let mut sig = Zeroizing::new([0u8; KEY_TEXT_CHARS]);
    let mut n = 0usize;
    let mut all_digits = true;
    for &c in text {
        if is_separator(c) {
            continue;
        }
        if n == sig.len() {
            return Err(PinParseError::Malformed);
        }
        sig[n] = c;
        n += 1;
        if !c.is_ascii_digit() {
            all_digits = false;
        }
    }

    // 1. An old numeric PIN.
    if all_digits && (1..=MAX_LEGACY_DIGITS).contains(&n) {
        if sig[0] == b'0' {
            return Err(PinParseError::Malformed);
        }
        let mut value = Zeroizing::new(0u64);
        for &c in &sig[..n] {
            let d = u64::from(c - b'0');
            if *value > (u64::MAX - d) / 10 {
                return Err(PinParseError::Malformed);
            }
            *value = *value * 10 + d;
        }
        out.set_legacy(*value);
        return Ok(());
    }

    // 2. A 128-bit KEY.
    if n != KEY_TEXT_CHARS {
        return Err(PinParseError::Malformed);
    }

    let mut digits = Zeroizing::new([0u32; KEY_TEXT_CHARS]);
    for i in 0..n {
        digits[i] = base58_digit(sig[i]).ok_or(PinParseError::Malformed)?;
    }

    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    for &digit in &digits[..BODY_CHARS] {
        let mut carry = digit;
        for b in key.iter_mut().rev() {
            let cur = u32::from(*b) * 58 + carry;
            *b = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        // 22 Base58 digits reach past 2^128; anything above it is no KEY.
        if carry != 0 {
            return Err(PinParseError::Malformed);
        }
    }

    if key.iter().all(|&b| b == 0) {
        return Err(PinParseError::Malformed);
    }

    let expected_check = digits[BODY_CHARS] * 58 + digits[BODY_CHARS + 1];
    if check_value(&key) != expected_check {
        return Err(PinParseError::Checksum);
    }

    out.set_key(&key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex16(s: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    // Frozen independently in Python (see the C++ tests/pin_codec_test.cpp).
    // The last two are the check values 0 and 3363.
    const VECTORS: [(&str, &str); 6] = [
        (
            "000102030405060708090a0b0c0d0e0f",
            "112d-rXXU-ifSr-RnXL-GbXg-8Eyf",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "YcVf-xkQb-6JRz-qk5k-F2tN-Lvdj",
        ),
        (
            "00000000000000000000000000000001",
            "1111-1111-1111-1111-1111-12BZ",
        ),
        (
            "80000000000000000000000000000000",
            "GokL-Usho-3eiV-vNYN-d1wg-fywf",
        ),
        (
            "000000000000000000000000000001bb",
            "1111-1111-1111-1111-1111-8e11",
        ),
        (
            "00000000000000000000000000003b26",
            "1111-1111-1111-1111-1115-W5zz",
        ),
    ];

    #[test]
    fn encodes_vectors() {
        for (hex, text) in VECTORS {
            let display = encode_key_display(&hex16(hex));
            assert_eq!(&display[..], text.as_bytes(), "key {hex}");
        }
    }

    #[test]
    fn parses_vectors_with_and_without_separators() {
        for (hex, text) in VECTORS {
            let expected = hex16(hex);
            for form in [
                text.to_string(),
                text.replace('-', ""),
                text.replace('-', " "),
                format!("\t{text} "),
            ] {
                let mut pin = RecoveryPin::default();
                parse_recovery_pin_text(form.as_bytes(), &mut pin).unwrap();
                assert!(pin.is_key() && pin.key == expected, "{form}");
            }
        }
    }

    #[test]
    fn rejects_bad_entries_and_leaves_nothing_behind() {
        use PinParseError::{Checksum, Malformed};
        for (text, expected) in [
            ("112d-rXXU-ifSr-RnXL-GbXg-8Eyg", Checksum),
            ("112d-rXXU-ifSr-RnXL-GbXh-8Eyf", Checksum),
            ("112D-rXXU-ifSr-RnXL-GbXg-8Eyf", Checksum),
            ("112d-rXXU-ifSr-RnXL-GbXg-8Ey", Malformed),
            ("112d-rXXU-ifSr-RnXL-GbXg-8Eyff", Malformed),
            ("112d-rXXU-ifSr-RnXL-GbXg-8Ey0", Malformed),
            ("112d-rXXU-ifSr-RnXL-GbXg-8EyI", Malformed),
            ("1111-1111-1111-1111-1111-1111", Malformed),
            ("zzzz-zzzz-zzzz-zzzz-zzzz-zzzz", Malformed),
            ("", Malformed),
            ("0", Malformed),
            ("0123", Malformed),
            ("18446744073709551616", Malformed),
            ("123456789012345678901", Malformed),
            ("12a4", Malformed),
        ] {
            let mut pin = RecoveryPin::default();
            pin.set_legacy(99);
            assert_eq!(
                parse_recovery_pin_text(text.as_bytes(), &mut pin),
                Err(expected),
                "{text}"
            );
            assert!(pin.kind == PinKind::None && pin.legacy_value == 0, "{text}");
        }
    }

    #[test]
    fn parses_old_numeric_pins() {
        for (text, value) in [
            ("1", 1u64),
            ("18446744073709551615", u64::MAX),
            ("10479510958359240708", 10_479_510_958_359_240_708),
            ("1047 9510-9583\t5924 0708", 10_479_510_958_359_240_708),
        ] {
            let mut pin = RecoveryPin::default();
            parse_recovery_pin_text(text.as_bytes(), &mut pin).unwrap();
            assert!(
                pin.kind == PinKind::LegacyPin && pin.legacy_value == value,
                "{text}"
            );
        }
    }

    #[test]
    fn clear_wipes_both_kinds() {
        let mut pin = RecoveryPin::default();
        pin.set_key(&[0xAB; 16]);
        pin.clear();
        assert!(pin.kind == PinKind::None && pin.key == [0u8; 16]);
    }
}
