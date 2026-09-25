// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Webhook delivery is scoped by the credential the MCP handler holds on a session.
//!
//! Its own file because `router/tests.rs` is over the 800-line ceiling and the
//! gate ratchets. This row guards the wiring: a handler that creates sessions
//! without holding the caller's credential, or a router that never installs
//! the authorizer, leaves scoped delivery reaching nobody.

use std::sync::Arc;

use serde_json::json;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::gateway::streaming::TaggedNotification;

#[tokio::test]
async fn a_session_created_by_the_mcp_handler_receives_in_scope_webhook_events() {
    let auth: crate::config::AuthConfig = serde_yaml::from_str(
        "enabled: true\napi_keys:\n  - key_sha256: sha256:45baf1c9d0b3c9df3823645cac52658a917f44f89b9fef643c4dcfc7c4729198\n    name: scoped\n    backends: [capabilities]\n",
    )
    .unwrap();
    let (state, _store) = test_router_app_state_with_auth(&auth).await;
    let router = create_router(Arc::clone(&state));

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", "Bearer key-webhook-scope")
        .header("mcp-session-id", "gw-webhook-scope")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string(),
        ))
        .unwrap();
    let _ = router.oneshot(request).await.unwrap();
    assert!(state.multiplexer.has_session("gw-webhook-scope"));

    // The owner resuming its own session: the stream the handler created.
    let owner = format!(
        "credential:{}",
        crate::gateway::auth::principal_of("key-webhook-scope")
    );
    let (_, mut rx) = state
        .multiplexer
        .get_or_create_session_for(Some("gw-webhook-scope"), &owner);
    let notification = TaggedNotification {
        source: "webhook".to_string(),
        event_type: "webhook.cap.hook".to_string(),
        data: json!({"event": "x"}),
        event_id: None,
    };
    let reached = state
        .multiplexer
        .broadcast_to_backend(&notification, "capabilities")
        .await;
    assert_eq!(reached, 1, "the handler must hold the caller's credential");
    assert!(rx.try_recv().is_ok());
}
