// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8504: at the provisional cap a legacy request that would mint a new
//! session is refused before it runs (503, `Retry-After`, `session_capacity`);
//! `initialize` and a caller resuming its own session are still served.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_streaming;
use super::{AppState, create_router};
use crate::config::StreamingConfig;

async fn gateway() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    test_router_app_state_with_streaming(StreamingConfig {
        enabled: true,
        ..StreamingConfig::default()
    })
    .await
}

fn post(body: &Value, session: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn get(session: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    builder.body(Body::empty()).unwrap()
}

fn tools_list() -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
}

fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "session-capacity-test", "version": "1"}
        }
    })
}

async fn assert_capacity_refusal(response: axum::response::Response, id: Value) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("60")
    );
    assert!(response.headers().get("mcp-session-id").is_none());
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    // A POST that accepts an event stream gets the same message as one SSE
    // frame; a GET refusal is plain JSON.
    let text = String::from_utf8_lossy(&bytes);
    let json = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(&text);
    let body: Value = serde_json::from_str(json)
        .unwrap_or_else(|e| panic!("not a JSON-RPC message ({e}): {text:?}"));
    assert_eq!(body["error"]["code"], -32603);
    assert_eq!(body["error"]["data"]["reason"], "session_capacity");
    assert_eq!(body["id"], id);
}

/// MIK-8533: the POST share full does not lock streams out. A sessionless
/// GET still opens its stream, counted in the stream share.
#[tokio::test]
async fn with_the_post_share_full_a_sessionless_get_still_streams() {
    let (state, _dir) = gateway().await;
    state.multiplexer.fill_provisional_cap_for_test();
    let response = create_router(Arc::clone(&state))
        .oneshot(get(None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("mcp-session-id").is_some());
    assert_eq!(state.multiplexer.provisional_shares_for_test().1, 1);
}

/// At the stream share's cap a sessionless GET is refused: a stream cannot
/// run without a session. A POST is unaffected by the stream share.
#[tokio::test]
async fn at_the_stream_cap_a_sessionless_get_is_refused() {
    let (state, _dir) = gateway().await;
    state.multiplexer.fill_stream_cap_for_test();
    let served = create_router(Arc::clone(&state))
        .oneshot(post(&tools_list(), None))
        .await
        .unwrap();
    assert_eq!(served.status(), StatusCode::OK);
    assert!(
        served.headers().get("mcp-session-id").is_some(),
        "POST share has room"
    );
    let response = create_router(Arc::clone(&state))
        .oneshot(get(None))
        .await
        .unwrap();
    assert_capacity_refusal(response, Value::Null).await;
}

#[tokio::test]
async fn at_the_cap_initialize_and_a_resume_are_served() {
    let (state, _dir) = gateway().await;
    state.multiplexer.fill_provisional_cap_for_test();
    let response = create_router(Arc::clone(&state))
        .oneshot(post(&initialize(), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .expect("initialize mints a session");
    let resumed = create_router(Arc::clone(&state))
        .oneshot(post(&tools_list(), Some(&session)))
        .await
        .unwrap();
    assert_eq!(resumed.status(), StatusCode::OK);
}

/// R11 at the handler: a GET stream holds its session while the body is
/// open, and lets go when the body is dropped.
#[tokio::test]
async fn a_get_stream_holds_its_session_until_the_body_is_dropped() {
    let (state, _dir) = gateway().await;
    let response = create_router(Arc::clone(&state))
        .oneshot(get(None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .expect("a stream names its session");
    assert_eq!(state.multiplexer.in_flight_for_test(&session), Some(1));
    drop(response);
    assert_eq!(state.multiplexer.in_flight_for_test(&session), Some(0));
}

/// A POST holds its session while it runs and lets go once its answer is
/// built: the response it returns has already released the hold, so a
/// finished call's session is judged by idle time alone (review round 2).
#[tokio::test]
async fn a_finished_post_has_released_its_session_hold() {
    let (state, _dir) = gateway().await;
    let response = create_router(Arc::clone(&state))
        .oneshot(post(&tools_list(), None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .expect("a legacy POST names its session");
    // The body is still unread here.
    assert_eq!(state.multiplexer.in_flight_for_test(&session), Some(0));
}
