// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The installation key behind `email_hash`: 32 bytes, written as exactly 64
//! lowercase hex digits wherever it is stored or configured. The HMAC and the
//! key id are computed over the decoded bytes, never over the hex text.

use crate::wiped_bytes::WipedBytes;

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
/// Both tables are Unicode 17.0.0: lowercase from the Rust standard library
/// under the pinned toolchain, NFC from `icu_normalizer_data` 2.3.0 (built
/// from ICU 78). A toolchain or ICU data change that alters either table
/// needs a new version.
pub(crate) fn normalize(email: &str) -> String {
    let nfc = icu_normalizer::ComposingNormalizerBorrowed::new_nfc();
    nfc.normalize(&nfc.normalize(email).to_lowercase())
        .into_owned()
}

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

    /// A second fixed key, so a row can show another key id never matches.
    #[cfg(feature = "webui")]
    pub(crate) fn for_test_other() -> std::sync::Arc<Self> {
        std::sync::Arc::new(
            Self::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
                .expect("a valid fixed key"),
        )
    }
}

#[cfg(test)]
#[path = "email_hash_tests.rs"]
mod tests;
