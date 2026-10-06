// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7971: with authentication off, a legacy request that resumes no
//! established session must not get a fresh control identity per request.
//! The per-caller controls (tenant guard here) key such requests on one
//! shared identity, so their breadth accumulates; an established session
//! keeps its own.

use super::*;

/// A meta `gateway_invoke` of `alpha/t` naming `tenant`, as a legacy client
/// sends it, carrying `session` as its `mcp-session-id` when given.
async fn invoke(fx: &Fixture, session: Option<&str>, tenant: &str) -> StatusCode {
    let arguments = json!({"server": "alpha", "tool": "t",
                           "arguments": {"rows": [{"customer_id": tenant}]}});
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": "gateway_invoke", "arguments": arguments}});
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    fx.router.clone().oneshot(request).await.unwrap().status()
}

/// A legacy session the gateway established, by its `mcp-session-id`.
async fn open_session(fx: &Fixture) -> String {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "t", "version": "1"}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let session = response
        .headers()
        .get("mcp-session-id")
        .expect("initialize establishes a session")
        .to_str()
        .unwrap()
        .to_string();
    assert!(!session.is_empty());
    session
}

async fn guarded() -> Fixture {
    fixture(Setup {
        tenant_limit: Some(1),
        ..Setup::default()
    })
    .await
}

/// No session header at all: each request used to be minted its own session,
/// so the second tenant was a first call again and dispatched.
#[tokio::test]
async fn requests_without_a_session_share_one_tenant_window() {
    let fx = guarded().await;
    assert_eq!(invoke(&fx, None, "cust-1").await, StatusCode::OK);
    let _ = invoke(&fx, None, "cust-2").await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "the second tenant must be refused: both requests are one caller"
    );
}

/// An `mcp-session-id` the gateway never issued is not an established
/// session: it must not buy a fresh window either.
#[tokio::test]
async fn an_unestablished_session_id_shares_the_same_window() {
    let fx = guarded().await;
    assert_eq!(invoke(&fx, Some("sess-a"), "cust-1").await, StatusCode::OK);
    let _ = invoke(&fx, Some("sess-b"), "cust-2").await;
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "one shared window");
}

/// Positive control: an established session keeps its own window, apart
/// from other sessions and from the shared one.
#[tokio::test]
async fn an_established_session_keeps_its_own_window() {
    let fx = guarded().await;
    let (a, b) = (open_session(&fx).await, open_session(&fx).await);
    assert_ne!(a, b);
    assert_eq!(invoke(&fx, None, "cust-1").await, StatusCode::OK);
    assert_eq!(invoke(&fx, Some(&a), "cust-2").await, StatusCode::OK);
    assert_eq!(invoke(&fx, Some(&b), "cust-3").await, StatusCode::OK);
    assert_eq!(fx.calls.load(Ordering::SeqCst), 3, "three separate windows");
    let _ = invoke(&fx, Some(&a), "cust-4").await;
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        3,
        "session a's own window still counts"
    );
}
