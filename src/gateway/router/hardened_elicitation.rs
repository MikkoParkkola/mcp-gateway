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

/// `/mcp`'s refusal of a request with no session under `hardened`. One that
/// declared the modern revision in its body and omitted a field is told which
/// field, as the direct route and a header-declared request are (MIK-8162);
/// anything else is a legacy client asked to declare elicitation.
pub(super) fn refuse(request: &Value, declared_version: Option<&str>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let params = request.get("params");
    if let RequestShape::Malformed { missing } =
        crate::protocol::meta::classify_request(params, declared_version)
    {
        let id = request
            .get("id")
            .and_then(|id| serde_json::from_value::<RequestId>(id.clone()).ok());
        return build_http_error_response(
            id,
            -32602,
            format!("missing required request metadata: {}", missing.join(", ")),
            StatusCode::BAD_REQUEST,
        )
        .into_response();
    }
    refusal().into_response()
}

/// The direct route's one reading of what a request declared: the header
/// read once, duplicate-safe, then the observing classifier, as `/mcp` reads
/// it (handlers.rs `classify_and_observe`). The hardened refusal and the era a
/// response is shaped for both come from this one reading (MIK-8022).
pub(super) fn classify_direct<'h>(
    headers: &'h HeaderMap,
    method: &str,
    params: Option<&Value>,
) -> (RequestShape, Option<&'h str>) {
    // A doubled header takes the modern reading and is refused by the
    // single-occurrence check.
    let mut versions = headers.get_all("mcp-protocol-version").iter();
    let declared_version = match (versions.next(), versions.next()) {
        (Some(only), None) => only.to_str().ok(),
        (None, _) => None,
        (Some(_), Some(_)) => Some(crate::protocol::meta::MODERN_VERSIONS[0]),
    };
    // No session on this route, so no session revision to consult.
    let shape = crate::protocol::meta::classify_and_observe(method, params, declared_version, None);
    (shape, declared_version)
}

/// The direct route's refusal under `hardened`, or `None`.
///
/// `reading` is [`classify_direct`]'s, so a modern header over a legacy body,
/// a doubled or contradicted header, or an unsupported revision is refused
/// here as on `/mcp`. What remains legacy is refused unless it is a declaring
/// `initialize`.
pub(super) fn direct_refusal(
    state: &AppState,
    headers: &HeaderMap,
    request: &Value,
    (method, params): (&str, Option<&Value>),
    id: Option<&RequestId>,
    (shape, declared_version): (&RequestShape, Option<&str>),
) -> Option<(StatusCode, Json<Value>)> {
    if let RequestShape::Malformed { missing } = shape {
        return Some(build_http_error_response(
            id.cloned(),
            -32602,
            format!("missing required request metadata: {}", missing.join(", ")),
            StatusCode::BAD_REQUEST,
        ));
    }
    if let Some((rpc, status)) = super::handlers::request_checks::request_check_refusal(
        state,
        headers,
        shape,
        declared_version,
        method,
        params,
        id,
    ) {
        return Some(build_http_response(&rpc, status));
    }
    (shape.era() == Era::Legacy && !declares_elicitation(request)).then(refusal)
}
