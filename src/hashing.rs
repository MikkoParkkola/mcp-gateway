// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared canonical JSON hashing helpers, and the crate's one HMAC-SHA256
//! type (MIK-8662, MIK-8743).

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The crate's one HMAC-SHA256 type: every keyed SHA-256 MAC in `src/`
/// (signers, transparency log, event delivery, webhooks, journey links)
/// names it, so a change to the construction is made once.
pub(crate) type HmacSha256 = hmac::Hmac<Sha256>;

/// Serialize JSON using the crate's canonical representation.
///
/// This preserves the existing gateway behavior of falling back to an empty
/// string if serialization fails.
pub(crate) fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Compute `HMAC-SHA256(key, message)` and return lowercase hex: the one
/// keyed-hashing helper (the transparency log's segment signatures and
/// MIK-8697's record principals).
pub(crate) fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    use hmac::{KeyInit as _, Mac as _};
    // invariant: HMAC accepts any key length, so this cannot panic.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

/// Compute a SHA-256 digest over a single byte slice and return lowercase hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    sha256_hex_chunks([bytes])
}

/// Compute a SHA-256 digest over multiple chunks and return lowercase hex.
pub(crate) fn sha256_hex_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hex::encode(hasher.finalize())
}

/// SHA-256 of `bytes` in RFC 4648 standard base64 with padding: the form a
/// CSP hash source takes (`'sha256-<this>'`), which the browser compares.
#[cfg(feature = "webui")]
pub(crate) fn sha256_base64(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    // red stub: the real digest lands with the shell's hashed policy.
    let _ = bytes;
    STANDARD.encode(b"")
}

/// `sha256:` followed by [`sha256_hex`] of `bytes`, the tagged form stored in
/// digests that name their algorithm.
pub(crate) fn sha256_tagged(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// Hash a JSON value after canonical serialization.
pub(crate) fn canonical_json_sha256(value: &Value) -> String {
    let canonical = canonical_json(value);
    sha256_hex(canonical.as_bytes())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sha256_is_stable_for_key_order() {
        let first = canonical_json_sha256(&json!({"a": 1, "b": 2}));
        let second = canonical_json_sha256(&json!({"b": 2, "a": 1}));
        assert_eq!(first, second);
    }

    #[test]
    fn chunked_hash_matches_single_buffer_hash() {
        let combined = b"prefix\0payload";
        let chunked = sha256_hex_chunks([&combined[..6], &combined[6..7], &combined[7..]]);
        assert_eq!(chunked, sha256_hex(combined));
    }

    /// The FIPS 180-2 `abc` vector in the CSP's standard, padded base64.
    #[cfg(feature = "webui")]
    #[test]
    fn sha256_base64_is_standard_padded_base64() {
        assert_eq!(
            sha256_base64(b"abc"),
            "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
        assert_eq!(
            sha256_base64(b""),
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        );
    }

    /// MIK-8668: the FIPS 180-2 `abc` vector, tagged.
    #[test]
    fn sha256_tagged_prefixes_the_algorithm() {
        assert_eq!(
            sha256_tagged(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
