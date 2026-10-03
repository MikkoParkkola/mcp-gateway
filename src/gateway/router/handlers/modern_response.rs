// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shaping of modern-era responses: cache hints and the list freshness window.

#[cfg(test)]
use axum::http::StatusCode;
#[cfg(test)]
use axum::response::IntoResponse;

/// Build a response for a request written against 2026-07-28.
///
/// Two differences from the legacy path, and they are the same difference: the
/// connection carries no state. There is no `Mcp-Session-Id`, because the
/// revision deleted protocol sessions; and the result names the server, because
/// there was no handshake in which to say so.
/// The methods whose results carry `ttlMs` and `cacheScope`.
///
/// Five, from the `CacheableResult` interface. `server/discover` supports
/// caching too, but is not in this list — its document is built elsewhere and
/// the fields are added there when its own scope is decided.
pub(super) const CACHEABLE_METHODS: &[&str] = &[
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

/// How long a client may consider a list fresh. A freshness hint, not a
/// promise: `listChanged` notifications remain the authority on change, and
/// this only stops a client re-listing on every turn.
pub(super) const LIST_TTL_MS: u64 = 60_000;

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
pub(super) fn shape_modern_response(response: &mut crate::protocol::JsonRpcResponse, method: &str) {
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
                serde_json::json!({
                    "name": "mcp-gateway",
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            );
        }
    }
}
