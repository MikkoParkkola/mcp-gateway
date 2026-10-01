// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! GH1942.HARDEN.1 row 10: under `security.posture: hardened` a legacy client
//! must declare elicitation.
//!
//! On `/mcp` only an `initialize` that declares it opens a legacy session, and
//! every other legacy request, GET included, may only resume one. Sessions live
//! in memory and the posture is restart-only, so every live legacy session of a
//! hardened process was opened by a declaring `initialize`; no handshake state
//! is kept. The direct route keeps no session at all, so it serves no legacy
//! request other than a declaring `initialize`.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;

use super::AppState;
use super::helpers::{build_http_error_response, build_http_response};
use crate::protocol::RequestId;
use crate::protocol::meta::{Era, RequestShape};
use crate::security::SecurityPosture;

/// The refusal message, verbatim from the design.
pub(super) const REFUSAL: &str = "client must declare elicitation (security.posture=hardened)";

/// Whether the running posture is `hardened`.
pub(super) fn is_hardened(state: &AppState) -> bool {
    state.live_config.running().security.posture == SecurityPosture::Hardened
}

/// Whether `request` is an `initialize`.
pub(super) fn is_initialize(request: &Value) -> bool {
    request.get("method").and_then(Value::as_str) == Some("initialize")
}

/// Whether `request` is an `initialize` whose capabilities declare
/// elicitation, read by the same parser the handshake uses.
pub(super) fn declares_elicitation(request: &Value) -> bool {
    is_initialize(request)
        && crate::protocol::meta::Declared::from_handshake(request.pointer("/params/capabilities"))
            .has("elicitation")
}

/// The 403 a legacy client without elicitation gets.
pub(super) fn refusal() -> (StatusCode, Json<Value>) {
    build_http_error_response(None, -32600, REFUSAL, StatusCode::FORBIDDEN)
}

/// The direct route's refusal under `hardened`, or `None`.
///
/// The request is classified exactly as `/mcp` classifies it (the same
/// duplicate-safe header read, the same parser, the same checks), so a modern
/// header over a legacy body, a doubled or contradicted header, or an
/// unsupported revision is refused here as there. What remains legacy is
/// refused unless it is a declaring `initialize`.
pub(super) fn direct_refusal(
    state: &AppState,
    headers: &HeaderMap,
    request: &Value,
    method: &str,
    params: Option<&Value>,
    id: &Option<RequestId>,
) -> Option<(StatusCode, Json<Value>)> {
    // Read once, duplicate-safe, as `/mcp` does: a doubled header takes the
    // modern reading and is refused by the single-occurrence check.
    let mut versions = headers.get_all("mcp-protocol-version").iter();
    let declared_version = match (versions.next(), versions.next()) {
        (Some(only), None) => only.to_str().ok(),
        (None, _) => None,
        (Some(_), Some(_)) => Some(crate::protocol::meta::MODERN_VERSIONS[0]),
    };
    let shape = crate::protocol::meta::classify_request(params, declared_version);
    if let RequestShape::Malformed { missing } = &shape {
        return Some(build_http_error_response(
            id.clone(),
            -32602,
            format!("missing required request metadata: {}", missing.join(", ")),
            StatusCode::BAD_REQUEST,
        ));
    }
    if let Some((rpc, status)) = super::handlers::request_check_refusal(
        state,
        headers,
        &shape,
        declared_version,
        method,
        params,
        id,
    ) {
        return Some(build_http_response(&rpc, status));
    }
    (shape.era() == Era::Legacy && !declares_elicitation(request)).then(refusal)
}
