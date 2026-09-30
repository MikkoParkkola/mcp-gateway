// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH1942.HARDEN.1 row 8: under `security.posture: hardened` every HTTP MCP
//! request carries a per-caller identity, or is refused before its body is
//! read.

use axum::Json;
use axum::http::StatusCode;
use serde_json::Value;

use super::AppState;
use crate::gateway::auth::NamedApiKey;

/// The refusal message, verbatim from the design.
pub(super) const REFUSAL: &str = "per-caller identity required (security.posture=hardened)";

/// `Some(403)` when a hardened gateway cannot tell who is calling; `None`
/// admits.
///
/// A per-caller identity is a grant subject that keys `CallerKey`
/// (`subject_key`; a certificate's display-name fallback does not), or an API
/// key configured `kind: personal`. A dashboard session, a shared API key and
/// the static bearer are shared credentials, so on their own they are refused.
/// stdio never reaches this: it is exempt by design.
pub(super) fn hardened_identity_refusal(
    state: &AppState,
    subject_key: Option<&str>,
    api_key: Option<&NamedApiKey>,
) -> Option<(StatusCode, Json<Value>)> {
    let _ = (
        state.live_config.running().security.posture,
        subject_key,
        api_key.map(NamedApiKey::is_personal),
    );
    // Red-first stub: the gate lands in the next commit.
    let _ = (StatusCode::FORBIDDEN, REFUSAL);
    None
}
