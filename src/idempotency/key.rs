// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Idempotency key derivation, re-exported from the parent module.

use serde_json::Value;

use crate::hashing::{canonical_json, sha256_hex_chunks};

/// Derive an idempotency key from `tool_name` and `arguments`.
///
/// The key is the hex-encoded SHA-256 digest of
/// `"{tool_name}\0{canonical_json(arguments)}"`.
/// Using a NUL separator prevents collisions between tool names that share a
/// common prefix and arguments.
///
/// The resulting key is stable: identical `(tool_name, arguments)` pairs
/// always produce the same key regardless of JSON key ordering.
#[must_use]
pub fn derive_key(tool_name: &str, arguments: &Value) -> String {
    let canonical = canonical_json(arguments);
    sha256_hex_chunks([tool_name.as_bytes(), &b"\0"[..], canonical.as_bytes()])
}
