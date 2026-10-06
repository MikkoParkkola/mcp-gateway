// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shaping of modern-era responses: cache hints and the list freshness window.

#[cfg(test)]
use axum::http::StatusCode;
#[cfg(test)]
use axum::response::IntoResponse;

use crate::protocol::cacheable::LIST_TTL_MS;

/// Build a response for a request written against 2026-07-28.
///
/// Two differences from the legacy path, and they are the same difference: the
/// connection carries no state. There is no `Mcp-Session-Id`, because the
/// revision deleted protocol sessions; and the result names the server, because
/// there was no handshake in which to say so.
/// The methods whose results carry `ttlMs` and `cacheScope`.
///
/// Five, from the `CacheableResult` interface. `server/discover` requires the
/// fields too, but carries them in its own document (`discover_document`), so
/// that a discovery answered on any route is valid without this shaping.
pub(super) const CACHEABLE_METHODS: &[&str] = &[
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

// Unit-test adapter only: production must shape before security finalization
// and serialize afterward without mutating the signed response.
#[cfg(test)]
pub(super) fn build_modern_response(
    mut response: crate::protocol::JsonRpcResponse,
    status: StatusCode,
    method: &str,
) -> axum::response::Response {
    shape_modern_response(&mut response, method);
    (status, axum::Json(response)).into_response()
}

/// Shape modern metadata before security finalization and signing.
///
/// Crate-visible because both transports answer modern requests: stdio
/// skipping this sent results a 2026-07-28 client rejects (MIK-8009).
pub(crate) fn shape_modern_response(response: &mut crate::protocol::JsonRpcResponse, method: &str) {
    if let Some(ref mut result) = response.result
        && let Some(object) = result.as_object_mut()
    {
        // Required on every result in this revision, and supplied here only
        // when the result does not already carry one.
        //
        // Inserting unconditionally overwrote the discriminator that the
        // multi-round-trip path had just set: an `input_required` result was
        // relabelled `complete` on its way out, so a client saw a finished call
        // where the server was waiting for an answer and could no longer supply
        // one. The comment said this value was safe because interim results own
        // their own; the code then overwrote exactly those.
        object
            .entry("resultType")
            .or_insert_with(|| serde_json::Value::String("complete".to_string()));

        if CACHEABLE_METHODS.contains(&method) {
            object.insert("ttlMs".to_string(), serde_json::json!(LIST_TTL_MS));
            // Per method, from the table that records which ones were
            // assessed. Answering with one method's decision for all five
            // would make `resources/read` inherit `tools/list`'s reasoning.
            object.insert(
                "cacheScope".to_string(),
                serde_json::Value::String(
                    crate::protocol::cacheable::scope_for_method(method)
                        .as_str()
                        .to_string(),
                ),
            );
        }
        let meta = object
            .entry("_meta")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(
                crate::protocol::meta::KEY_SERVER_INFO.to_string(),
                crate::protocol::meta::server_info(),
            );
        }
    }
}
