// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One entry's signature state, as every reader of the log shows it: list
//! rows, receipts and both exports call this one helper, so a row can never
//! read `valid` where the receipt reads `invalid`.

use serde::Serialize;
use serde_json::Value;

use super::sigstart::Placed;
use super::{recompute_entry_hash, verify_entry_sig};

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

/// What every reader shows for one entry: its state, why its integrity
/// failed (the exports' `integrity` column), and whether it is a legacy
/// record nothing anchors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Judged {
    pub(crate) state: SignatureState,
    pub(crate) integrity: Option<&'static str>,
    pub(crate) unanchored: bool,
}

impl Judged {
    fn plain(state: SignatureState, integrity: Option<&'static str>) -> Self {
        Self {
            state,
            integrity,
            unanchored: false,
        }
    }
}

/// Judge `entry` under `secret` (the configured shared secret, if any).
/// `place` is asked only for an unsigned entry whose hash recomputes, with
/// a secret set: whether it lies before the log began signing (the signing
/// anchor, `.sigstart`) or is a signed record whose signature was stripped.
pub(crate) fn judge(
    entry: &Value,
    secret: Option<&[u8]>,
    place: impl FnOnce() -> Placed,
) -> Judged {
    let Some(stored) = entry.get("entry_hash").and_then(Value::as_str) else {
        return Judged::plain(SignatureState::Invalid, Some("hash_failed"));
    };
    // The stored hash is what the HMAC signs, so it proves nothing about the
    // fields shown beside it until it is recomputed from them.
    if !recompute_entry_hash(entry).is_ok_and(|h| h == stored) {
        return Judged::plain(SignatureState::Invalid, Some("hash_failed"));
    }
    if !super::verify::is_signed_entry(entry) {
        if secret.is_none_or(<[u8]>::is_empty) {
            return Judged::plain(SignatureState::Unsigned, None);
        }
        return match place() {
            Placed::Legacy { unanchored } => Judged {
                state: SignatureState::Unsigned,
                integrity: None,
                unanchored,
            },
            Placed::Invalid(why) => Judged::plain(SignatureState::Invalid, Some(why)),
        };
    }
    match secret {
        None => Judged::plain(SignatureState::SignedUnverifiable, None),
        Some(secret) => match verify_entry_sig(entry, stored, secret) {
            Ok(()) => Judged::plain(SignatureState::Valid, None),
            Err(_) => Judged::plain(SignatureState::Invalid, Some("sig_failed")),
        },
    }
}

/// The state alone, with every unsigned entry treated as legacy: for the
/// per-entry rows only. Readers call [`judge`] with the log's anchor.
#[cfg(test)]
pub(crate) fn signature_state(entry: &Value, secret: Option<&[u8]>) -> SignatureState {
    judge(entry, secret, || Placed::Legacy { unanchored: false }).state
}

#[cfg(test)]
#[path = "transparency_log_signature_tests.rs"]
mod tests;
