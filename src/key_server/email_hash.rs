// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The installation key behind `email_hash`: 32 bytes, written as exactly 64
//! lowercase hex digits wherever it is stored or configured. The HMAC and the
//! key id are computed over the decoded bytes, never over the hex text.

use crate::wiped_bytes::WipedBytes;

/// The key's length in bytes, and so its hex text's length in digits / 2.
const KEY_BYTES: usize = 32;

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

    /// `HMAC-SHA256(key, normalized)` as 64 lowercase hex digits. The caller
    /// passes the already normalized email.
    pub(crate) fn hash_normalized(&self, normalized: &str) -> String {
        crate::hashing::hmac_sha256_hex(self.0.as_bytes(), normalized.as_bytes())
    }
}

#[cfg(test)]
#[path = "email_hash_tests.rs"]
mod tests;
