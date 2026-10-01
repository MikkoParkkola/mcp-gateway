// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The protocol checks `/mcp` runs before anything acts on a request, shared
//! with the direct route under `hardened`.

use axum::http::{HeaderMap, StatusCode};
use serde_json::Value;

use super::unsupported_version_error;
use crate::gateway::router::AppState;
use crate::protocol::{JsonRpcResponse, RequestId};

/// The protocol checks a request faces before anything acts on it: a revision
/// served in neither era, an unsupported modern revision, single-occurrence and
/// header/body mirrored headers, an undeclared required capability, and a
/// method the 2026 revision removed. `None` admits.
///
/// One function for `/mcp` and, under `hardened`, the direct route
/// (GH1942.HARDEN.1 row 10), so the two routes cannot classify one request two
/// ways. Each caller renders the refusal in its own response shape.
pub(in crate::gateway::router) fn request_check_refusal(
    state: &AppState,
    headers: &HeaderMap,
    shape: &crate::protocol::meta::RequestShape,
    declared_version: Option<&str>,
    method: &str,
    params: Option<&Value>,
    id: Option<&RequestId>,
) -> Option<(JsonRpcResponse, StatusCode)> {
    let is_modern = shape.era() == crate::protocol::meta::Era::Modern;
    // The same refusal, reached by a request that declared no era. The check
    // below is inside the `Modern` arm, so a header naming a revision this
    // build serves in neither era — `1999-01-01`, or any spelling older than
    // the first stateless one — classified `Legacy` and took the success path
    // with the header unexamined: the client was answered under a revision it
    // had not named and was never told why.
    //
    // Only when the request is NOT modern. A modern request states its revision
    // in the body, and the header is then evidence to compare against it, not a
    // source to act on: pre-empting the mirrored-header check here would refuse
    // on the header alone, which is the trust inversion that check exists to
    // close (`protocol::headers`).
    if !is_modern
        && let Some(version) = declared_version
        && crate::protocol::meta::served_revision(version).is_none()
    {
        return Some((
            unsupported_version_error(
                id.cloned(),
                version,
                state.live_config.running().server.modern_protocol,
            ),
            StatusCode::BAD_REQUEST,
        ));
    }

    if let crate::protocol::meta::RequestShape::Modern(fields) = shape {
        // A version we cannot serve statelessly. The client is told which ones
        // we can, so it can retry on a shared revision rather than guess.
        let modern_enabled = state.live_config.running().server.modern_protocol;
        if !modern_enabled
            || !crate::protocol::meta::MODERN_VERSIONS.contains(&fields.protocol_version.as_str())
        {
            return Some((
                unsupported_version_error(id.cloned(), &fields.protocol_version, modern_enabled),
                StatusCode::BAD_REQUEST,
            ));
        }

        // Header against body, before anything acts on either. The
        // specification's own rationale for this check is a load balancer
        // routing on the header while the server executes on the body — which
        // is this gateway with the check missing.
        //
        // The mirrored field is chosen by the method, never searched for: a
        // `resources/read` executes on `uri`, and validating a `name` it happens
        // to carry would authorise a decoy while reading something else.
        let body_name = crate::protocol::headers::mcp_name_body_field(method)
            .and_then(|field| params.and_then(|p| p.get(field)))
            .and_then(serde_json::Value::as_str);

        // Exactly one occurrence, or none. Two lines of the same header let one
        // intermediary route on the first and another act on the second, and
        // the disagreement between them is the bypass — the same class of
        // defect the body/header check closes, arriving through the header
        // list instead of past it.
        let single_header = |name: &'static str| -> Result<Option<&str>, &'static str> {
            let mut values = headers.get_all(name).iter();
            match (values.next(), values.next()) {
                (Some(only), None) => Ok(only.to_str().ok()),
                (None, _) => Ok(None),
                (Some(_), Some(_)) => Err(name),
            }
        };
        let duplicated = |name: &'static str| {
            Some((
                JsonRpcResponse::error(
                    id.cloned(),
                    -32020,
                    format!("{name} appears more than once"),
                ),
                StatusCode::BAD_REQUEST,
            ))
        };
        // Three explicit calls rather than a collected array: the conversion
        // back out of a collection needs a fallback, and the only fallback
        // available here blanks the headers, which passes the check it was
        // meant to run.
        let header_protocol_version = match single_header("mcp-protocol-version") {
            Ok(value) => value,
            Err(name) => return duplicated(name),
        };
        let header_method = match single_header("mcp-method") {
            Ok(value) => value,
            Err(name) => return duplicated(name),
        };
        let header_name = match single_header("mcp-name") {
            Ok(value) => value,
            Err(name) => return duplicated(name),
        };
        let check = crate::protocol::headers::HeaderCheck {
            header_protocol_version,
            body_protocol_version: Some(fields.protocol_version.as_str()),
            header_method,
            body_method: method,
            header_name,
            body_name,
        };
        if let Err(mismatch) = check.validate() {
            return Some((
                JsonRpcResponse::error(id.cloned(), -32020, mismatch.to_string()),
                StatusCode::BAD_REQUEST,
            ));
        }

        // A capability the client never declared. Checked before dispatch:
        // a handler that discovers this halfway through has already acted.
        if let Some(capability) = crate::protocol::meta::required_capability(method)
            && !fields.declares_capability(capability)
        {
            let mut rpc = JsonRpcResponse::error(
                id.cloned(),
                -32021,
                format!("client did not declare the '{capability}' capability"),
            );
            if let Some(ref mut error) = rpc.error {
                error.data = Some(serde_json::json!({
                    "requiredCapabilities": [capability],
                }));
            }
            return Some((rpc, StatusCode::BAD_REQUEST));
        }

        // Methods this revision removed. Refusing them is the difference
        // between claiming the revision and speaking it.
        if crate::protocol::meta::REMOVED_IN_2026_07_28.contains(&method) {
            return Some((
                JsonRpcResponse::error(
                    id.cloned(),
                    -32601,
                    format!("method '{method}' was removed in MCP 2026-07-28"),
                ),
                StatusCode::NOT_FOUND,
            ));
        }
    }
    None
}
