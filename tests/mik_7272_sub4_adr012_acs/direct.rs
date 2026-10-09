// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct-route request helpers of `mik_7272_sub4_adr012_acs`.

use std::sync::Arc;

use axum::http::StatusCode;
use mcp_gateway::gateway::test_helpers::{AppState, create_router};
use mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{MUTATION, ROUTE_BACKEND};

/// A client's own direct-route `tools/call` frame, carrying `idempotency_key`
/// where a client can actually put it.
///
/// `id` varies per call because a re-issue after a broken stream is a second
/// JSON-RPC request; that is the whole shape the criterion is about.
pub(crate) fn keyed_call(id: u32, key: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": MUTATION,
            "arguments": {},
            "_meta": {IDEMPOTENCY_KEY_META: key}
        }
    })
}

/// POST to the direct backend route and read the status and body back.
pub(crate) async fn post_direct(state: &Arc<AppState>, mut body: Value) -> (StatusCode, Value) {
    // A modern request as `/mcp` requires it, which the direct route now
    // requires too (MIK-8040): the revision and capabilities in `_meta`, and
    // the method and name headers echoing the body.
    let meta = &mut body["params"]["_meta"];
    meta["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
    meta["io.modelcontextprotocol/clientCapabilities"] = json!({});
    let method = body["method"].as_str().unwrap_or_default().to_owned();
    let name = body["params"]["name"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{ROUTE_BACKEND}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(
            serde_json::to_vec(&body).expect("frame serializes"),
        ))
        .expect("request builds");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
