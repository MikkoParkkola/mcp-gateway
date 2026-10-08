// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shaping of modern-era responses: cache hints and the list freshness window.

#[cfg(test)]
use axum::http::StatusCode;
#[cfg(test)]
use axum::response::IntoResponse;

use crate::gateway::meta_mcp::invoke::relay::GatewayStamps;
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
///
/// Returns the receipt stamps the shaped answer needs: the `serverInfo`
/// written here is the gateway's, so a receipt must not digest it as backend
/// text. A transport takes its stamps from here, never decides them apart.
pub(crate) fn shape_modern_response(
    response: &mut crate::protocol::JsonRpcResponse,
    method: &str,
) -> GatewayStamps {
    if let Some(ref mut result) = response.result
        && let Some(object) = result.as_object_mut()
    {
        use crate::gateway::gateway_writes::{Layer, note};
        let supplied = !object.contains_key("resultType");
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

        let hinted = CACHEABLE_METHODS.contains(&method);
        if hinted {
            // A relayed `resources/read` may carry its backend's own hint. The
            // gateway may shorten it, never lengthen it: raising a backend's
            // `ttlMs: 0` would let a client serve changing contents stale.
            let ttl = object
                .get("ttlMs")
                .and_then(serde_json::Value::as_u64)
                .map_or(LIST_TTL_MS, |hint| hint.min(LIST_TTL_MS));
            // Scope per method, from the table that records which ones were
            // assessed. Answering with one method's decision for all five
            // would make `resources/read` inherit `tools/list`'s reasoning.
            crate::protocol::cacheable::write_cache_hints(object, method, ttl);
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
        // What the shaper wrote is the gateway's, so a receipt leaves it out
        // (MIK-8025): `resultType` only when it supplied one, the cache hints
        // whenever it wrote them. A backend's own `resultType` stays.
        if supplied {
            note(Layer::Answer, &["resultType"], result);
        }
        if hinted {
            note(Layer::Answer, &["cacheScope"], result);
            note(Layer::Answer, &["ttlMs"], result);
        }
    }
    GatewayStamps::Modern
}

#[cfg(test)]
mod tests {
    use super::{GatewayStamps, LIST_TTL_MS, shape_modern_response};
    use crate::protocol::{JsonRpcResponse, RequestId};

    fn shaped_ttl(result: serde_json::Value) -> serde_json::Value {
        let mut response = JsonRpcResponse::success(RequestId::Number(1), result);
        shape_modern_response(&mut response, "resources/read");
        response.result.expect("a success keeps its result")["ttlMs"].clone()
    }

    /// MIK-8009 review: a backend hint is kept when shorter, capped when
    /// longer, and the gateway's window applies only where none was sent.
    #[test]
    fn a_relayed_read_keeps_a_shorter_backend_hint() {
        assert_eq!(
            shaped_ttl(serde_json::json!({"contents": [], "ttlMs": 0})),
            0
        );
        assert_eq!(
            shaped_ttl(serde_json::json!({"contents": [], "ttlMs": 5})),
            5
        );
        assert_eq!(
            shaped_ttl(serde_json::json!({"contents": [], "ttlMs": u64::MAX})),
            LIST_TTL_MS
        );
        assert_eq!(shaped_ttl(serde_json::json!({"contents": []})), LIST_TTL_MS);
        assert_eq!(
            shaped_ttl(serde_json::json!({"contents": [], "ttlMs": "soon"})),
            LIST_TTL_MS
        );
    }

    /// MIK-8009: the answer carries the gateway's `serverInfo`, so its
    /// receipt is stamped modern on every transport that shapes it.
    #[test]
    fn a_shaped_answer_asks_for_modern_receipt_stamps() {
        let mut response = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({}));
        assert_eq!(
            shape_modern_response(&mut response, "tools/call"),
            GatewayStamps::Modern
        );
    }
}
