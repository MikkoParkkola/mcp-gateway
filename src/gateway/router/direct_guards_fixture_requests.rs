// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared fixture's request helpers: `/mcp` and `/mcp/{backend}` calls,
//! `initialize`, and raw sends with extra headers. Moved out of
//! `direct_guards_fixture.rs` unchanged.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::Fx;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

/// Build `params._meta` carrying an idempotency key, when one is given.
fn set_idem(params: &mut Value, idem: Option<&str>) {
    if let Some(value) = idem {
        params["_meta"] = json!({ IDEMPOTENCY_KEY_META: value });
    }
}

/// `POST /mcp/{backend}` `tools/call`, as the direct route takes it.
pub(crate) async fn post_direct(
    fx: &Fx,
    backend: &str,
    key: &str,
    tool: &str,
    args: Value,
    idem: Option<&str>,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut params = json!({ "name": tool, "arguments": args });
    set_idem(&mut params, idem);
    send(
        fx,
        &format!("/mcp/{backend}"),
        key,
        "tools/call",
        params,
        session,
    )
    .await
}

/// `POST /mcp` `tools/call gateway_invoke`, the meta-route twin a parity
/// table compares against `post_direct`.
pub(crate) async fn post_meta_invoke(
    fx: &Fx,
    key: &str,
    server: &str,
    tool: &str,
    args: Value,
    idem: Option<&str>,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": { "server": server, "tool": tool, "arguments": args },
    });
    set_idem(&mut params, idem);
    send(fx, "/mcp", key, "tools/call", params, session).await
}

/// `initialize` on `/mcp` for `key`; returns the session id the gateway
/// minted (it never adopts a client-chosen one).
pub(crate) async fn initialize(fx: &Fx, key: &str) -> String {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t8", "version": "1"}
                }
            })
            .to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .expect("initialize mints a session id")
        .to_string()
}

/// [`post_meta_invoke`] carrying a signing `nonce` in the `gateway_invoke`
/// arguments.
pub(crate) async fn post_meta_invoke_nonce(
    fx: &Fx,
    key: &str,
    server: &str,
    tool: &str,
    nonce: &str,
) -> (StatusCode, Value) {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": { "server": server, "tool": tool, "arguments": {}, "nonce": nonce },
    });
    send(fx, "/mcp", key, "tools/call", params, None).await
}

pub(crate) async fn send(
    fx: &Fx,
    uri: &str,
    key: &str,
    method: &str,
    params: Value,
    session: Option<&str>,
) -> (StatusCode, Value) {
    send_with_headers(fx, uri, key, method, params, session, &[]).await
}

/// [`send`] plus extra request headers, such as the modern era's mirrors.
pub(crate) async fn send_with_headers(
    fx: &Fx,
    uri: &str,
    key: &str,
    method: &str,
    params: Value,
    session: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    if let Some(session_id) = session {
        builder = builder.header("mcp-session-id", session_id);
    }
    let request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

/// The admin key `k-admin`, added while `WITH_ADMIN` is set (the web UI's
/// tool route runs only for an admin); off by default, so no other row's key
/// set changes.
pub(super) fn admin_key(auth: &mut crate::config::AuthConfig) {
    if super::WITH_ADMIN.with(std::cell::Cell::get) {
        auth.api_keys.push(crate::config::ApiKeyConfig {
            admin: true,
            ..super::key("k-admin")
        });
    }
}
