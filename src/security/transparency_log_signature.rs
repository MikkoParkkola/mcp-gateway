// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One entry's signature state, as every reader of the log shows it: list
//! rows, receipts and both exports call this one helper, so a row can never
//! read `valid` where the receipt reads `invalid`.

use serde::Serialize;
use serde_json::Value;

use super::verify_entry_sig;

/// What a reader can say about one entry's integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignatureState {
    /// The recomputed hash matches and the HMAC verifies.
    Valid,
    /// The entry was altered: its hash or its HMAC does not match.
    Invalid,
    /// Signed, but this gateway holds no secret to check the HMAC with.
    SignedUnverifiable,
    /// Written without a signature; the hash still matches.
    Unsigned,
}

/// The state of `entry` under `secret` (the configured shared secret, if any).
pub(crate) fn signature_state(entry: &Value, secret: Option<&[u8]>) -> SignatureState {
    let Some(stored) = entry.get("entry_hash").and_then(Value::as_str) else {
        return SignatureState::Invalid;
    };
    if entry.get("sig").is_none() {
        return SignatureState::Unsigned;
    }
    match secret {
        None => SignatureState::SignedUnverifiable,
        Some(secret) => match verify_entry_sig(entry, stored, secret) {
            Ok(()) => SignatureState::Valid,
            Err(_) => SignatureState::Invalid,
        },
    }
}

#[cfg(test)]
#[path = "transparency_log_signature_tests.rs"]
mod tests;
