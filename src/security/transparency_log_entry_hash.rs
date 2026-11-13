// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An entry's hash and signature: chaining a record, recomputing an entry's
//! hash, and verifying its HMAC (moved from `transparency_log.rs`).

use std::io;

use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};

use super::TransparencyLogConfig;
use crate::hashing::HmacSha256;

/// Recompute the `entry_hash` for an existing entry read from the log file.
///
/// Strips `entry_hash`, `sig`, and `key_id`, serialises what remains (`BTreeMap`
/// so alphabetically sorted), and returns `"sha256:<hex>"`. Public so incremental
/// consumers (e.g. the SIEM exporter) can tamper-verify one entry at a
/// time instead of re-reading the whole file.
///
/// # Errors
///
/// Returns `io::Error` if `entry` is not a JSON object or cannot be serialised.
pub fn recompute_entry_hash(entry: &serde_json::Value) -> io::Result<String> {
    let obj = entry
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry is not a JSON object"))?;

    // Serialise the entry without the hash-and-sig fields, borrowing every
    // value: the bytes equal those of a cloned filtered map, without a clone
    // of each field per verified line.
    let mut core_json = Vec::with_capacity(256);
    let mut ser = serde_json::Serializer::new(&mut core_json);
    serde::Serializer::collect_map(
        &mut ser,
        obj.iter().filter(|(k, _)| {
            k.as_str() != "entry_hash" && k.as_str() != "sig" && k.as_str() != "key_id"
        }),
    )
    .map_err(io::Error::other)?;
    Ok(crate::hashing::sha256_tagged(&core_json))
}

/// Verify one entry's HMAC `sig` against `secret`, given the entry's
/// already-hash-verified `entry_hash` string (`"sha256:<hex>"`).
///
/// The signature is `HMAC-SHA256(secret, sig_message(entry_hash_bytes, key_id))`
/// where `key_id` is bound INTO the signed message (matching `append_core`), so a
/// stripped/altered `key_id` also fails verification, not only a
/// stripped/altered `sig`. Comparison is constant-time via
/// `Mac::verify_slice`. Under a configured secret every entry must carry both a
/// `sig` and a `key_id`; a missing/malformed field is an error, so neither can
/// be dropped to bypass.
///
/// # Errors
///
/// Returns a human-readable reason string when the signature is absent,
/// malformed, unsigned, or fails to authenticate.
pub fn verify_entry_sig(
    entry: &serde_json::Value,
    entry_hash: &str,
    secret: &[u8],
) -> Result<(), String> {
    let sig = entry
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'sig' while a shared secret is configured".to_string())?;
    let key_id = entry
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'key_id' while a shared secret is configured".to_string())?;
    let sig_hex = sig
        .strip_prefix("hmac-sha256:")
        .ok_or_else(|| format!("malformed sig (expected 'hmac-sha256:' prefix): {sig}"))?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig is not valid hex: {e}"))?;
    let hash_hex = entry_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("malformed entry_hash (expected 'sha256:' prefix): {entry_hash}"))?;
    let hash_bytes =
        hex::decode(hash_hex).map_err(|e| format!("entry_hash is not valid hex: {e}"))?;
    let hash_arr: [u8; 32] = hash_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("entry_hash is not 32 bytes: {entry_hash}"))?;

    let msg = sig_message(&hash_arr, key_id);
    // invariant: HMAC-SHA256 takes a key of any length, so this cannot fail.
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&msg);
    mac.verify_slice(&sig_bytes)
        .map_err(|_| "HMAC sig mismatch (possible re-chain forgery or altered key_id)".to_string())
}

/// Complete one record from its domain `fields`: add `counter` and
/// `prev_entry_hash`, hash the canonical JSON (sorted keys), sign it when a
/// secret is set, and return `(line, entry_hash)`. The one place a record is
/// chained, for caller appends and the logger's own housekeeping records.
pub(super) fn chain_line(
    config: &TransparencyLogConfig,
    mut fields: serde_json::Map<String, serde_json::Value>,
    counter: u64,
    prev_entry_hash: &str,
) -> io::Result<(String, String)> {
    fields.insert("counter".into(), counter.into());
    fields.insert("prev_entry_hash".into(), prev_entry_hash.into());
    let core_json = serde_json::to_string(&serde_json::Value::Object(fields.clone()))
        .map_err(io::Error::other)?;
    let entry_hash_bytes: [u8; 32] = sha256_raw(core_json.as_bytes());
    let entry_hash = format!("sha256:{}", hex::encode(entry_hash_bytes));
    // key_id is bound INTO the signed message.
    if !config.shared_secret.is_empty() {
        let msg = sig_message(&entry_hash_bytes, &config.key_id);
        let sig_hex = crate::hashing::hmac_sha256_hex(config.shared_secret.as_bytes(), &msg);
        fields.insert("sig".into(), format!("hmac-sha256:{sig_hex}").into());
        fields.insert("key_id".into(), config.key_id.clone().into());
    }
    fields.insert("entry_hash".into(), entry_hash.clone().into());
    let line =
        serde_json::to_string(&serde_json::Value::Object(fields)).map_err(io::Error::other)?;
    Ok((line, entry_hash))
}

/// Build the HMAC message for an entry's `sig`: the 32 raw `entry_hash` bytes
/// followed by the `key_id` bytes. Binding `key_id` into the signed material
/// (rather than leaving it as unauthenticated metadata) means it cannot be
/// stripped or altered without invalidating the signature.
pub(super) fn sig_message(entry_hash_bytes: &[u8; 32], key_id: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + key_id.len());
    msg.extend_from_slice(entry_hash_bytes);
    msg.extend_from_slice(key_id.as_bytes());
    msg
}

/// Raw (non-hex) SHA-256 digest.
pub(super) fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
