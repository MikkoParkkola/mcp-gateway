// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Progress-token helpers of the stdio transport, split out of
//! `stdio.rs` to keep that file under the size ceiling.

use serde_json::Value;

/// A progress token is a string or a number on the wire; the capture map is
/// keyed by its string form so both spellings of one token agree.
pub(super) fn progress_token_string(token: &Value) -> Option<String> {
    match token {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The caller's progress token as an outgoing request carries it.
///
/// Note the asymmetry with `capture_notification`: a request carries the token
/// under `params._meta`, while an incoming `notifications/progress` carries it
/// as a direct member of `params`. Reading the wrong shape here leaves the
/// stdio leg dead while the HTTP one still looks green.
pub(super) fn request_progress_token(params: Option<&Value>) -> Option<String> {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|meta| meta.get("progressToken"))
        .and_then(progress_token_string)
}
