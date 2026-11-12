// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The installation key behind `email_hash`: 32 bytes, written as exactly 64
//! lowercase hex digits wherever it is stored or configured. The HMAC and the
//! key id are computed over the decoded bytes, never over the hex text.

use crate::wiped_bytes::WipedBytes;

// Names the NFC data crate so a dependency cleanup cannot drop its exact pin in
// Cargo.toml: `cargo install` honours that pin, and ignores Cargo.lock.
use icu_normalizer_data as _;

/// The key's length in bytes, and so its hex text's length in digits / 2.
const KEY_BYTES: usize = 32;

/// The normalization and hash version records carry as `email_hash_version`.
pub(crate) const VERSION: u32 = 1;

/// Domain separation for version 1: a later version hashes under another
/// prefix, so its hashes cannot collide with these.
const DOMAIN: &[u8] = b"email-v1\0";

/// Normalization v1: NFC, Unicode lowercase, NFC again. The second NFC is
/// needed because lowercasing can emit a decomposed sequence (U+0130 becomes
/// `i` and a combining dot), so one pass alone is not stable under a second.
/// Canonically equivalent spellings meet; compatibility forms (a ligature,
/// fullwidth letters) stay distinct, and the domain is not IDNA-converted.
///
/// The hash must be the same on every build, so no table here is the
/// compiler's: lowercase is the crate's own frozen Unicode 17.0.0 tables
/// (`case_v1`), reproducing the standard library's `str::to_lowercase` at that
/// version exactly, final-sigma rule included; NFC is `icu_normalizer` and its data
/// crate `icu_normalizer_data`, both pinned to an exact version in
/// `Cargo.toml` (`cargo install` ignores Cargo.lock). A change that alters
/// either table needs a new version, and `self_check` refuses to start a
/// build that normalizes differently.
pub(crate) fn normalize(email: &str) -> String {
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc();
    nfc.normalize(&lower_v1(&nfc.normalize(email))).into_owned()
}

/// Version 1's lowercase: the standard library's `str::to_lowercase` at
/// Unicode 17.0.0, over the crate's frozen tables. Each code point goes
/// through the per-code-point table (ASCII by the locale-free ASCII rule);
/// capital Sigma (U+03A3) follows Unicode's Final_Sigma rule: it becomes final
/// sigma when a cased letter precedes it and none follows, skipping
/// case-ignorable characters on both sides. That is the only context-sensitive
/// rule in the default lowercase mapping (SpecialCasing.txt).
/// Version 1's trim (placeholder: replaced once the rows are proved red).
pub(crate) fn trim_v1(text: &str) -> &str {
    text
}

pub(crate) fn lower_v1(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (at, c) in text.char_indices() {
        if c == '\u{3a3}' {
            let word_final = case_v1::case_ignorable_then_cased(text[..at].chars().rev())
                && !case_v1::case_ignorable_then_cased(text[at + c.len_utf8()..].chars());
            out.push(if word_final { '\u{3c2}' } else { '\u{3c3}' });
        } else if c.is_ascii() {
            out.push(c.to_ascii_lowercase());
        } else if let Some(mapped) = case_v1::lower(c) {
            out.extend(mapped);
        } else {
            out.push(c);
        }
    }
    out
}

/// Known answers every build must reproduce, checked when the key server
/// starts: a build whose Unicode data differs from the one that wrote the
/// retained rows would otherwise hash the same address differently and make
/// lookups miss silently. `cargo install` never runs the tests, so the check
/// is part of the program.
const KNOWN_ANSWERS: &[(&str, &str)] = &[
    ("Ada.Lovelace", "ada.lovelace"),
    ("\u{130}x", "i\u{307}x"),
    ("\u{1e9e}", "\u{df}"),
    ("\u{391}\u{3a3}", "\u{3b1}\u{3c2}"),
    (
        "\u{391}\u{3a3}.\u{392}\u{3a3}",
        "\u{3b1}\u{3c3}.\u{3b2}\u{3c2}",
    ),
    ("\u{3a3}", "\u{3c3}"),
    ("\u{13a0}", "\u{ab70}"),
    ("\u{1c90}", "\u{10d0}"),
    ("\u{212b}", "\u{e5}"),
    ("A\u{30a}", "\u{e5}"),
    ("\u{1100}\u{1161}\u{11a8}", "\u{ac01}"),
    ("a\u{307}\u{323}", "\u{1ea1}\u{307}"),
    ("\u{fb01}", "\u{fb01}"),
    ("\u{ff21}", "\u{ff41}"),
];

/// Run [`KNOWN_ANSWERS`] through `normalizer`; the first miss is the error.
pub(crate) fn self_check_with(normalizer: &dyn Fn(&str) -> String) -> Result<(), String> {
    for (input, expected) in KNOWN_ANSWERS {
        let got = normalizer(input);
        if got != *expected {
            return Err(format!(
                "this build's email normalization differs from the one the retained audit rows were \
                 hashed with (input U+{:04X}... gave {} code points, expected {}): rebuild with the \
                 pinned dependencies",
                input.chars().next().map_or(0, u32::from),
                got.chars().count(),
                expected.chars().count()
            ));
        }
    }
    Ok(())
}

/// [`self_check_with`] on the real normalization.
pub(crate) fn self_check() -> Result<(), String> {
    self_check_with(&normalize)
}

mod case_v1;

/// The installation key. `Debug` shows only the length; the bytes are wiped
/// on drop.
#[derive(Debug)]
pub(crate) struct EmailHashKey(WipedBytes);

/// Why a key's text was refused. Never carries the text itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyTextError {
    /// Not 64 characters after the one optional trailing newline.
    Length(usize),
    /// A character other than `0-9` or `a-f`.
    NotLowercaseHex,
}

impl std::fmt::Display for KeyTextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length(n) => write!(
                f,
                "it must hold exactly 64 lowercase hex digits, not {n} characters"
            ),
            Self::NotLowercaseHex => {
                f.write_str("it must hold only lowercase hex digits (0-9, a-f)")
            }
        }
    }
}

impl EmailHashKey {
    /// Parse the stored or configured text: exactly 64 lowercase hex digits,
    /// with one trailing newline allowed (the record key file's rule).
    pub(crate) fn from_hex(text: &str) -> Result<Self, KeyTextError> {
        let digits = text.strip_suffix('\n').unwrap_or(text);
        if digits.len() != 2 * KEY_BYTES {
            return Err(KeyTextError::Length(digits.chars().count()));
        }
        if !digits
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(KeyTextError::NotLowercaseHex);
        }
        // invariant: 64 checked hex digits always decode to 32 bytes.
        let bytes = hex::decode(digits).expect("64 checked hex digits decode");
        Ok(Self(WipedBytes::new(bytes)))
    }

    /// The key id: lowercase hex SHA-256 of the decoded bytes. Names the key
    /// without being it.
    pub(crate) fn key_id(&self) -> String {
        crate::hashing::sha256_hex(self.0.as_bytes())
    }

    /// The `email_hash` of `email`: HMAC-SHA256 under this key of the
    /// version's domain-separation prefix and the normalized address, as 64
    /// lowercase hex digits.
    pub(crate) fn hash(&self, email: &str) -> String {
        let normalized = normalize(email);
        let mut message = Vec::with_capacity(DOMAIN.len() + normalized.len());
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(normalized.as_bytes());
        crate::hashing::hmac_sha256_hex(self.0.as_bytes(), &message)
    }
}

#[cfg(test)]
impl EmailHashKey {
    /// A fixed key (bytes 0x00..0x1f) for rows that need a key server.
    pub(crate) fn for_test() -> std::sync::Arc<Self> {
        std::sync::Arc::new(
            Self::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("a valid fixed key"),
        )
    }
}

#[cfg(test)]
#[path = "email_hash_tests.rs"]
mod tests;
