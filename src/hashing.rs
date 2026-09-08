// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared canonical JSON hashing helpers.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize JSON using the crate's canonical representation.
///
/// This preserves the existing gateway behavior of falling back to an empty
/// string if serialization fails.
pub(crate) fn canonical_json(value: &Value) -> String {
    let canonical = serde_json::to_string(value).unwrap_or_default();
    // Recorded AFTER the serialization, so the counter marks work done rather
    // than work entered (`cfg(test)` only — production is byte-identical).
    #[cfg(test)]
    observer::record_canonicalization();
    canonical
}

/// Compute a SHA-256 digest over a single byte slice and return lowercase hex.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    sha256_hex_chunks([bytes])
}

/// Compute a SHA-256 digest over multiple chunks and return lowercase hex.
pub(crate) fn sha256_hex_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut hasher = Sha256::new();
    #[cfg(test)]
    let mut observed_bytes = 0u64;
    for chunk in chunks {
        #[cfg(test)]
        {
            observed_bytes += u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        }
        hasher.update(chunk);
    }
    #[cfg(test)]
    observer::record_hash(observed_bytes);
    hex::encode(hasher.finalize())
}

/// Hash a JSON value after canonical serialization.
pub(crate) fn canonical_json_sha256(value: &Value) -> String {
    let canonical = canonical_json(value);
    sha256_hex(canonical.as_bytes())
}

/// `cfg(test)` observation points for the MIK-7377.SIGNING.5 refusal proof.
///
/// Two kinds of real work are counted, both AT the operation rather than
/// inferred from an outcome:
///
/// * the dispatch argument clone in
///   [`crate::gateway::meta_mcp_helpers::parse_tool_arguments`], and
/// * the canonicalization and hashing performed by the transparency
///   request-hash block in `meta_mcp::invoke`.
///
/// The hashing helpers here are SHARED — the same two functions fingerprint a
/// bearer credential during authentication, which is permitted work that runs
/// before any nonce decision. Counting every hash in a request would therefore
/// be a false oracle, so the transparency counters only move inside
/// [`TransparencyScope`], which the request-hash block enters and nothing else
/// does. Stated limit: a premature hash that bypasses that block is not counted
/// by these counters.
///
/// Capture is per-thread. Tests using it declare a current-thread runtime, so a
/// request and its observation share one thread and no cross-test global state
/// exists.
#[cfg(test)]
pub(crate) mod observer {
    use std::cell::Cell;

    thread_local! {
        static TRANSPARENCY_DEPTH: Cell<u32> = const { Cell::new(0) };
        static CANONICALIZATIONS: Cell<u64> = const { Cell::new(0) };
        static HASHES: Cell<u64> = const { Cell::new(0) };
        static HASHED_BYTES: Cell<u64> = const { Cell::new(0) };
        static ARGUMENT_CLONES: Cell<u64> = const { Cell::new(0) };
    }

    /// Work this thread actually performed since the last [`reset`].
    ///
    /// `transparency_hashed_bytes` measures how much input the digest consumed.
    /// It is a WORK measure, never an allocation claim — nothing here observes
    /// the allocator.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Work {
        pub(crate) argument_clones: u64,
        pub(crate) transparency_canonicalizations: u64,
        pub(crate) transparency_hashes: u64,
        pub(crate) transparency_hashed_bytes: u64,
    }

    /// Active only for the duration of the transparency request-hash block.
    ///
    /// Nesting is counted rather than set/cleared, so a nested entry cannot
    /// close an outer scope on drop.
    pub(crate) struct TransparencyScope(());

    impl TransparencyScope {
        pub(crate) fn enter() -> Self {
            TRANSPARENCY_DEPTH.with(|depth| depth.set(depth.get() + 1));
            Self(())
        }
    }

    impl Drop for TransparencyScope {
        fn drop(&mut self) {
            TRANSPARENCY_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }

    fn inside_transparency() -> bool {
        TRANSPARENCY_DEPTH.with(Cell::get) > 0
    }

    pub(crate) fn record_canonicalization() {
        if inside_transparency() {
            CANONICALIZATIONS.with(|count| count.set(count.get() + 1));
        }
    }

    pub(crate) fn record_hash(bytes: u64) {
        if inside_transparency() {
            HASHES.with(|count| count.set(count.get() + 1));
            HASHED_BYTES.with(|total| total.set(total.get().saturating_add(bytes)));
        }
    }

    /// Counted unconditionally: `parse_tool_arguments` is on the dispatch path,
    /// so any call to it during a refused request is work a refusal must not do.
    pub(crate) fn record_argument_clone() {
        ARGUMENT_CLONES.with(|count| count.set(count.get() + 1));
    }

    pub(crate) fn work() -> Work {
        Work {
            argument_clones: ARGUMENT_CLONES.with(Cell::get),
            transparency_canonicalizations: CANONICALIZATIONS.with(Cell::get),
            transparency_hashes: HASHES.with(Cell::get),
            transparency_hashed_bytes: HASHED_BYTES.with(Cell::get),
        }
    }

    /// Clears the four work counters. Deliberately NOT the scope depth: zeroing
    /// a depth a live guard still holds would corrupt its restore on drop.
    pub(crate) fn reset() {
        ARGUMENT_CLONES.with(|count| count.set(0));
        CANONICALIZATIONS.with(|count| count.set(0));
        HASHES.with(|count| count.set(0));
        HASHED_BYTES.with(|total| total.set(0));
    }
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
