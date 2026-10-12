// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Session-targeted prompts, modern-era sessions and legacy version headers.

use super::*;
use pretty_assertions::assert_eq;

// ── Session-targeted prompts reach the session that asked ─────────────

#[tokio::test]
async fn sampling_prompt_is_delivered_to_the_requesting_session() {
    // GIVEN: a live session listening on its own notification stream
    let (state, _store) = test_router_app_state().await;
    let (session_id, mut rx) = state
        .multiplexer
        .get_or_create_session_for(None, &crate::gateway::session_id::SessionOwner::Anonymous);
    let router = create_router(Arc::clone(&state));

    // WHEN: that session asks the gateway for a sampling round trip
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-session-id", session_id.as_str())
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "sample-1",
                "method": "sampling/createMessage",
                "params": {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
                    "maxTokens": 16
                }
            })
            .to_string(),
        ))
        .unwrap();
    let call = tokio::spawn(async move { router.oneshot(request).await.unwrap() });

    // THEN: the prompt arrives on that session's stream
    let delivered = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the prompt must reach the requesting session, not a literal \"broadcast\" id")
        .expect("the notification stream must stay open");
    assert_eq!(delivered.data["method"], "sampling/createMessage");

    call.abort();
}

#[tokio::test]
async fn sampling_without_a_live_stream_fails_instead_of_hanging() {
    // GIVEN: a caller that only POSTs — it never opened a notification stream
    let (state, _store) = test_router_app_state().await;
    let router = create_router(Arc::clone(&state));

    // WHEN: it asks the gateway for a sampling round trip
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "sample-nostream",
                "method": "sampling/createMessage",
                "params": {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
                    "maxTokens": 16
                }
            })
            .to_string(),
        ))
        .unwrap();

    // THEN: it is told there is nobody to ask, rather than waiting out the
    // 120-second response timeout on a prompt only the handler could hear.
    let response = tokio::time::timeout(Duration::from_secs(5), router.oneshot(request))
        .await
        .expect("an undeliverable prompt must fail fast, not hang until the timeout")
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], -32002, "body: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("No sampling-capable client connected"),
        "body: {body}"
    );
}

/// A modern request gets no session, even when it offers one.
///
/// The pin under `meta_mcp::session_key`, which reads an empty session id as
/// "no session" and refuses the routing-profile meta-tools on that basis. That
/// reading is only sound while this branch holds: mint a session here and the
/// profile becomes per-connection state again, silently reopening ORDER.2
/// (`docs/requirements/RELEASE-4.0.0-requirements.md`). The response header is
/// the observable side of it — `attach_session_header` emits nothing for an
/// empty id, so a minted session would show up here as a header.
#[tokio::test]
async fn ac_order_2_a_modern_request_is_given_no_session_even_when_it_offers_one() {
    let (state, _store) = modern_router_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        // The modern path requires the method in a header as well as the body.
        .header("mcp-method", "tools/list")
        // Offered deliberately: the modern path must decline it, not adopt it.
        .header("mcp-session-id", "sess-offered-by-client")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let session_header = response.headers().get("mcp-session-id").cloned();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // The request must actually REACH modern dispatch. An earlier draft of this
    // test omitted the mcp-method header and params._meta; the router rejected
    // it before dispatch, and a rejection carries no session header either — so
    // the assertion below passed while proving nothing. Pin the success first.
    assert!(
        json["result"]["tools"].is_array(),
        "the request must reach modern dispatch and list tools, or the header \
         assertion below is satisfied by a rejection instead of by the \
         behaviour under test: {json}"
    );
    assert!(
        session_header.is_none(),
        "a 2026-07-28 caller has no session; answering with one would give it \
         per-connection state its own revision removed"
    );
}

/// A modern caller cannot switch the routing profile, through the real stack.
///
/// The unit tests for this live in `meta_mcp::tests` and call the meta-tool
/// directly; this one goes in at the wire, so the refusal is known to survive
/// dispatch rather than only being reachable from inside. Which outcome is
/// asserted matters: "the tool set did not change" is satisfied both by a
/// closed path and by a write that silently landed somewhere useless, and only
/// the refusal tells the two apart.
#[tokio::test]
async fn ac_order_2_a_modern_caller_is_refused_gateway_set_profile() {
    let (state, _store) = modern_router_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        // The modern path requires the method in a header as well as the body.
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_set_profile")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "gateway_set_profile",
                    "arguments": { "profile": "research" },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // The refusal must arrive as a JSON-RPC error, not as a successful result
    // that happens to mention a session: the design decision is that the call
    // BREAKS for a modern client, and the shape is what the client sees.
    let message = json["error"]["message"].as_str().unwrap_or_else(|| {
        panic!("gateway_set_profile must be refused with a JSON-RPC error: {json}")
    });
    assert!(
        message.contains("no session"),
        "the refusal must say why, and the reason must be the true one — the \
         old text told the caller to send a session header, which on this path \
         cannot help: {message}"
    );
}

/// A legacy `tools/list` with the version header a test chooses, and no
/// protocol metadata in the body — the shape that classifies `Legacy`.
///
/// The body is deliberately metadata-free: with a `_meta` declaration the
/// request classifies `Modern` and is answered by the refusal that already
/// existed, so the row would pass whether or not the legacy path was fixed.
async fn post_legacy_with_version(version: Option<&str>) -> (StatusCode, Value) {
    let (state, _store) = test_router_app_state().await;
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some(version) = version {
        builder = builder.header("mcp-protocol-version", version);
    }
    let request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string(),
        ))
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// gh#540 — a revision in neither `SUPPORTED_VERSIONS` nor `MODERN_VERSIONS`
/// is refused, whatever the body declares.
///
/// The refusal lived inside the `RequestShape::Modern` arm, so only a request
/// that declared the modern era could reach it. `1999-01-01` is revision-shaped
/// and older than the first stateless revision, so it declares no era, carries
/// no `_meta`, classifies `Legacy`, and was served normally — a client naming a
/// revision this gateway does not implement got a success answer shaped by a
/// different one.
#[tokio::test]
async fn gh540_an_unserved_version_header_is_refused_on_the_legacy_path() {
    let (status, body) = post_legacy_with_version(Some("1999-01-01")).await;

    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unsupported protocol version must be refused: {body}"
    );
    // The code the modern path returns for the same fault. Asserted rather than
    // the message, and rather than the status alone: every other refusal on
    // this route is also a 400, so the status by itself is satisfied by an
    // unrelated rejection.
    assert_eq!(
        body["error"]["code"],
        json!(crate::protocol::era::UNSUPPORTED_PROTOCOL_VERSION),
        "both eras must refuse an unserved revision the same way: {body}"
    );
}

/// gh#540 — a supported legacy revision is unaffected.
#[tokio::test]
async fn gh540_a_supported_legacy_version_header_is_still_served() {
    let (status, body) = post_legacy_with_version(Some("2025-11-25")).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    // The success is pinned, not the absence of a refusal: a 200 carrying a
    // JSON-RPC error would satisfy a status-only assertion.
    assert!(
        body["result"]["tools"].is_array(),
        "a negotiable revision must still be served: {body}"
    );
}

/// gh#540 — absence is not an unsupported value.
#[tokio::test]
async fn gh540_a_missing_version_header_is_still_served() {
    let (status, body) = post_legacy_with_version(None).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["result"]["tools"].is_array(),
        "a request declaring no revision must still be served: {body}"
    );
}
