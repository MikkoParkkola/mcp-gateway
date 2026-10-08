// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7798 on the legacy session stream (GET `/mcp`): a copy queued while an
//! agent token was live is checked again when the stream writes it (design r6:
//! G6), so a token that expired, or an agent removed, in between is written
//! nothing and its stream ends.
//!
//! The body is not polled between the queueing and the change, so the copy
//! waits unwritten in the session's buffer. Each row pairs the refused stream
//! with a live twin that reads the same broadcast.
use super::super::super::*;
use super::super::support::*;
use super::agent_task_owner::{AGENT_A, agent_gateway, agent_gateway_expiring};
use super::helpers::{ARRIVES_WITHIN, EventStream, StreamEvent, expect_message};
use crate::gateway::streaming::TaggedNotification;

/// An open GET `/mcp` stream as `bearer`, past its `connected` event.
async fn legacy_stream(state: &Arc<AppState>, bearer: &str) -> EventStream {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .header("authorization", format!("Bearer {bearer}"))
        .body(axum::body::Body::empty())
        .expect("a fixture request builds");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer");
    std::assert_eq!(response.status(), StatusCode::OK, "GET /mcp opens");
    let mut stream = EventStream::from_response(response);
    let connected = expect_message(&mut stream, "the connected event").await;
    assert!(connected.get("session_id").is_some(), "{connected}");
    stream
}

/// A backend notification naming `uri`.
fn backend_note(uri: &str) -> TaggedNotification {
    TaggedNotification {
        source: BACKEND.to_string(),
        event_type: "message".to_string(),
        data: json!({
            "jsonrpc": "2.0",
            "method": "notifications/resources/updated",
            "params": { "uri": uri },
        }),
        event_id: None,
    }
}

/// The twin reads `uri`; the refused stream reads nothing and ends.
async fn assert_twin_reads_and_refused_ends(
    kept: &mut EventStream,
    refused: &mut EventStream,
    uri: &str,
    why: &str,
) {
    let read = expect_message(kept, "the live twin's copy").await;
    std::assert_eq!(read["params"]["uri"], uri, "{read}");
    match refused.next(ARRIVES_WITHIN).await {
        StreamEvent::Closed => {}
        StreamEvent::Message(event) => {
            panic!("{why}: its stream must be written nothing, yet it carried {event}")
        }
        StreamEvent::Silent => panic!("{why}: its stream must end at the write, yet stayed open"),
    }
}

/// R8: agent A's token passes `exp` plus the leeway after its copy is queued
/// and before the stream writes it. B's token is still valid.
#[tokio::test]
async fn an_expired_agent_tokens_queued_copy_is_not_written() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store, token_a, token_b) = agent_gateway_expiring(&mock, 60).await;
    let mut expired = legacy_stream(&state, &token_a).await;
    let mut kept = legacy_stream(&state, &token_b).await;

    let note = backend_note("rows://r8");
    let reached = state.multiplexer.broadcast_to_backend(&note, BACKEND).await;
    std::assert_eq!(
        reached,
        2,
        "both tokens are live when the copies are queued"
    );
    state.agent_auth.registry.advance_clock(200);

    assert_twin_reads_and_refused_ends(&mut kept, &mut expired, "rows://r8", "A's token expired")
        .await;
}

/// R14 (legacy leg): agent A leaves the registry after its copy is queued and
/// before the stream writes it. B is still registered.
#[tokio::test]
async fn a_removed_agents_queued_copy_is_not_written() {
    let mock = MockBackend::answering(Answer::ok());
    let (state, _store, token_a, token_b) = agent_gateway(&mock).await;
    let mut removed = legacy_stream(&state, &token_a).await;
    let mut kept = legacy_stream(&state, &token_b).await;

    let note = backend_note("rows://r14");
    let reached = state.multiplexer.broadcast_to_backend(&note, BACKEND).await;
    std::assert_eq!(
        reached,
        2,
        "both agents are registered when the copies are queued"
    );
    state
        .agent_auth
        .registry
        .remove(AGENT_A)
        .expect("agent A was registered");

    assert_twin_reads_and_refused_ends(&mut kept, &mut removed, "rows://r14", "A was removed")
        .await;
}
