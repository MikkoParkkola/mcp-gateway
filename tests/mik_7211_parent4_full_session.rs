// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7211.AC.4 (MCP728.PARENT.4), gateway half: a client opening at
//! 2025-11-25 and at 2025-06-18 still completes a full session, one test per
//! version per transport.
//!
//! A session is: initialize -> notifications/initialized -> tools/list ->
//! tools/call -> ping, and over HTTP the client's DELETE that ends it. Every
//! leg after initialize carries what a real client of that revision sends: the
//! minted `Mcp-Session-Id` and `MCP-Protocol-Version: <negotiated>` over HTTP.
//!
//! The negotiated-version assertion is load-bearing only at 2025-06-18. At
//! 2025-11-25 the asked revision IS the fallback (`PROTOCOL_VERSION`), so the
//! echo and a downgrade are the same string; there the claim is that the rest
//! of the session completes on that revision's headers.

mod common;
#[path = "common/stdio_session.rs"]
mod stdio_session;

use common::*;
use stdio_session::StdioSession;

/// Zero arguments and no backend needed, so the call leg exercises the
/// session rather than a backend.
const META_TOOL: &str = "gateway_list_servers";

fn initialize(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "parent4-client", "version": "1.0.0" }
        }
    })
}

fn request(id: i64, method: &str, params: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

fn tools_call(id: i64) -> Value {
    request(
        id,
        "tools/call",
        &json!({ "name": META_TOOL, "arguments": {} }),
    )
}

/// The `result` of a JSON-RPC response; an `error` envelope fails the leg.
fn result<'a>(response: &'a Value, leg: &str) -> &'a Value {
    assert!(
        response.get("error").is_none(),
        "{leg} returned a JSON-RPC error: {response}"
    );
    response
        .get("result")
        .unwrap_or_else(|| panic!("{leg} carried no result: {response}"))
}

fn assert_initialize(response: &Value, version: &str) {
    let init = result(response, "initialize");
    assert_eq!(
        init.get("protocolVersion").and_then(Value::as_str),
        Some(version),
        "initialize must settle on the revision the client opened at: {init}"
    );
    assert!(
        init.get("capabilities").is_some(),
        "no capabilities: {init}"
    );
    assert!(init.get("serverInfo").is_some(), "no serverInfo: {init}");
}

fn assert_tools_list(response: &Value) {
    let tools = result(response, "tools/list")
        .get("tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("tools/list carried no tools array: {response}"));
    assert!(
        tools
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some(META_TOOL)),
        "tools/list did not surface {META_TOOL}: {tools:?}"
    );
}

fn assert_tools_call(response: &Value) {
    let call = result(response, "tools/call");
    assert_ne!(
        call.get("isError").and_then(Value::as_bool),
        Some(true),
        "tools/call reported a tool error: {call}"
    );
    let content = call
        .get("content")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("tools/call carried no content: {call}"));
    assert!(!content.is_empty(), "tools/call returned empty content");
}

// ============================================================================
// HTTP (streamable HTTP, the shipped default deployment)
// ============================================================================

struct HttpReply {
    status: StatusCode,
    session: Option<String>,
    /// The JSON-RPC message carrying the request's id, from a JSON body or
    /// from the `data:` line of an event-stream body.
    message: Option<Value>,
}

/// POST one frame the way a legacy-era client does: both body shapes offered,
/// no 2026-07-28 header, the session and revision once the handshake set them.
async fn http_post(
    state: &Arc<AppState>,
    body: &Value,
    session: Option<&str>,
    version: Option<&str>,
) -> HttpReply {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(id) = session {
        builder = builder.header("mcp-session-id", id);
    }
    if let Some(v) = version {
        builder = builder.header("mcp-protocol-version", v);
    }
    let response = create_router(Arc::clone(state))
        .oneshot(builder.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("router must answer");
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    let text = String::from_utf8_lossy(&bytes);
    let want = body.get("id").cloned();
    let message = serde_json::from_str::<Value>(&text)
        .ok()
        .into_iter()
        .chain(
            text.lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok()),
        )
        .find(|m| want.is_some() && m.get("id") == want.as_ref());
    HttpReply {
        status,
        session,
        message,
    }
}

async fn http_delete(state: &Arc<AppState>, session: &str, version: &str) -> StatusCode {
    let request = Request::builder()
        .method("DELETE")
        .uri("/mcp")
        .header("mcp-session-id", session)
        .header("mcp-protocol-version", version)
        .body(Body::empty())
        .expect("request");
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer")
        .status()
}

async fn http_full_session(version: &str) {
    let (state, _store_dir) = state(Fixture::default()).await;

    // 1. initialize: no session yet; the gateway mints one.
    let init = http_post(&state, &initialize(version), None, None).await;
    assert_eq!(init.status, StatusCode::OK, "initialize status");
    let session = init.session.expect("initialize must mint Mcp-Session-Id");
    assert_initialize(&init.message.expect("initialize answered"), version);
    let (sid, v) = (Some(session.as_str()), Some(version));

    // 2. notifications/initialized: accepted, nothing to answer.
    let ack = http_post(&state, &initialized(), sid, v).await;
    assert_eq!(
        ack.status,
        StatusCode::ACCEPTED,
        "a notification is answered 202"
    );
    assert_eq!(
        ack.session.as_deref(),
        sid,
        "notifications/initialized must stay on the session initialize minted"
    );

    // 3-5. tools/list, tools/call, ping: on the same session throughout.
    let legs = [
        (request(2, "tools/list", &json!({})), "tools/list"),
        (tools_call(3), "tools/call"),
        (request(4, "ping", &json!({})), "ping"),
    ];
    for (frame, leg) in legs {
        let reply = http_post(&state, &frame, sid, v).await;
        assert_eq!(reply.status, StatusCode::OK, "{leg} status");
        assert_eq!(
            reply.session.as_deref(),
            sid,
            "{leg} must stay on the session initialize minted"
        );
        let message = reply
            .message
            .unwrap_or_else(|| panic!("{leg} carried no response"));
        match leg {
            "tools/list" => assert_tools_list(&message),
            "tools/call" => assert_tools_call(&message),
            _ => {
                result(&message, leg);
            }
        }
    }

    // 6. DELETE: the client ends the session it owns; a second DELETE finds
    // nothing, so the first really ended it.
    assert_eq!(
        http_delete(&state, &session, version).await,
        StatusCode::NO_CONTENT,
        "the session's owner can end it"
    );
    assert_eq!(
        http_delete(&state, &session, version).await,
        StatusCode::NOT_FOUND,
        "an ended session is gone"
    );
}

#[tokio::test]
async fn parent4_http_full_session_at_2025_11_25() {
    http_full_session("2025-11-25").await;
}

#[tokio::test]
async fn parent4_http_full_session_at_2025_06_18() {
    http_full_session("2025-06-18").await;
}

// ============================================================================
// stdio (the shipped binary, spawned the way a stdio client spawns it)
// ============================================================================

async fn stdio_full_session(version: &str) {
    let home = tempfile::tempdir().expect("tempdir");
    let mut session = StdioSession::spawn(home.path());

    session.send(&initialize(version)).await;
    let (_, init) = session.read_until_id(1).await;
    assert_initialize(&init.expect("initialize answered"), version);

    session.send(&initialized()).await;

    session.send(&request(2, "tools/list", &json!({}))).await;
    let (_, list) = session.read_until_id(2).await;
    assert_tools_list(&list.expect("tools/list answered"));

    session.send(&tools_call(3)).await;
    let (_, call) = session.read_until_id(3).await;
    assert_tools_call(&call.expect("tools/call answered"));

    session.send(&request(4, "ping", &json!({}))).await;
    let (_, ping) = session.read_until_id(4).await;
    result(&ping.expect("ping answered"), "ping");

    session.shutdown().await;
}

#[tokio::test]
async fn parent4_stdio_full_session_at_2025_11_25() {
    stdio_full_session("2025-11-25").await;
}

#[tokio::test]
async fn parent4_stdio_full_session_at_2025_06_18() {
    stdio_full_session("2025-06-18").await;
}
