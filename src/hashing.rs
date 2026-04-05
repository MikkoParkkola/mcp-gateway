//! Shared canonical JSON hashing helpers.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize JSON using the crate's canonical representation.
///
/// This preserves the existing gateway behavior of falling back to an empty
/// string if serialization fails.
pub(crate) fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
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
}
