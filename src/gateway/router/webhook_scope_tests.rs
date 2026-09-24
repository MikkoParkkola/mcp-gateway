// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Webhook delivery is scoped by the caller the MCP handler records on a session.
//!
//! Its own file because `router/tests.rs` is over the 800-line ceiling and the
//! gate ratchets. This row guards the wiring: a handler that creates sessions
//! without recording the caller would leave every session unscoped, and scoped
//! delivery would then reach nobody.

use std::sync::Arc;

use serde_json::json;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state;
use crate::gateway::streaming::TaggedNotification;

#[tokio::test]
async fn a_session_created_by_the_mcp_handler_receives_in_scope_webhook_events() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(Arc::clone(&state));

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-session-id", "gw-webhook-scope")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string(),
        ))
        .unwrap();
    let _ = router.oneshot(request).await.unwrap();
    assert!(state.multiplexer.has_session("gw-webhook-scope"));

    // The owner resuming its own session: the stream the handler created.
    let (_, mut rx) = state
        .multiplexer
        .get_or_create_session_for(Some("gw-webhook-scope"), "unauthenticated:anonymous");
    let notification = TaggedNotification {
        source: "webhook".to_string(),
        event_type: "webhook.cap.hook".to_string(),
        data: json!({"event": "x"}),
        event_id: None,
    };
    assert_eq!(
        state
            .multiplexer
            .broadcast_to_backend(&notification, "capabilities"),
        1
    );
    assert!(
        rx.try_recv().is_ok(),
        "the handler must record the caller's scope"
    );
}
