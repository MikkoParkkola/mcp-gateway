// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8533: a fast sessionless legacy client is never refused. At the
//! provisional POST cap a request that would mint a new session is served
//! without one (no `mcp-session-id`), so memory stays bounded and the caller
//! is still answered. Session tools refuse with recovery advice a legacy
//! caller can follow: `initialize`, then retry with its id.

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_streaming;
use super::{AppState, create_router};
use crate::config::StreamingConfig;

/// The provisional POST cap.
const POST_CAP: usize = crate::gateway::streaming::MAX_PROVISIONAL_SESSIONS;

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
        .header("accept", "application/json")
        .header("mcp-protocol-version", "2025-06-18");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn tools_list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
}

fn call(id: u64, name: &str, arguments: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}})
}

fn initialize() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "degrade-at-cap-test", "version": "1"}
        }
    })
}

/// Status, session header and parsed JSON-RPC body of one answer.
async fn answer(response: axum::response::Response) -> (StatusCode, Option<String>, Value) {
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", String::from_utf8_lossy(&bytes)));
    (status, session, body)
}

/// Served, not refused: a 200 with a result, no error, and no session.
fn assert_served_without_session(
    status: StatusCode,
    session: Option<&str>,
    body: &Value,
    what: &str,
) {
    assert_eq!(status, StatusCode::OK, "{what}: {body}");
    assert!(body.get("error").is_none(), "{what}: {body}");
    assert!(body.get("result").is_some(), "{what}: {body}");
    assert!(session.is_none(), "{what}: no session id past the cap");
}

/// LOAD.1 / LOAD.2 at the router: past the POST cap, 12,000 sessionless
/// legacy calls are all answered, none carries a session id, and the store
/// does not grow.
#[tokio::test]
async fn past_the_post_cap_twelve_thousand_sessionless_calls_are_all_served() {
    let (state, _dir) = gateway().await;
    state.multiplexer.fill_provisional_cap_for_test();
    let before = state.multiplexer.session_count();
    let app = create_router(Arc::clone(&state));
    for id in 0..12_000_u64 {
        let (status, session, body) = answer(
            app.clone()
                .oneshot(post(&tools_list(id), None))
                .await
                .unwrap(),
        )
        .await;
        assert_served_without_session(status, session.as_deref(), &body, "tools/list");
    }
    assert_eq!(
        state.multiplexer.session_count(),
        before,
        "nothing minted past the cap"
    );
}

/// A sessionless `tools/call` past the cap runs and returns its result.
#[tokio::test]
async fn past_the_post_cap_a_sessionless_tool_call_runs() {
    let (state, _dir) = gateway().await;
    state.multiplexer.fill_provisional_cap_for_test();
    let app = create_router(Arc::clone(&state));
    let (status, session, body) = answer(
        app.oneshot(post(&call(9, "gateway_list_servers", &json!({})), None))
            .await
            .unwrap(),
    )
    .await;
    assert_served_without_session(status, session.as_deref(), &body, "gateway_list_servers");
    assert_ne!(body["result"]["isError"], json!(true), "{body}");
}

/// Real mints, no fill hook: concurrent sessionless calls fill the POST cap
/// themselves, then every further call is still served, without a session,
/// and the count stops at the cap.
#[tokio::test]
async fn real_mints_fill_the_post_cap_and_later_calls_are_still_served() {
    let (state, _dir) = gateway().await;
    let app = create_router(Arc::clone(&state));
    let total = POST_CAP as u64 + 200;
    let mut tasks = tokio::task::JoinSet::new();
    for lane in 0..32_u64 {
        let app = app.clone();
        tasks.spawn(async move {
            let mut without = 0_u64;
            let mut id = lane;
            while id < total {
                let (status, session, body) = answer(
                    app.clone()
                        .oneshot(post(&tools_list(id), None))
                        .await
                        .unwrap(),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{body}");
                assert!(body.get("error").is_none(), "{body}");
                if session.is_none() {
                    without += 1;
                }
                id += 32;
            }
            without
        });
    }
    let mut served_without = 0;
    while let Some(lane) = tasks.join_next().await {
        served_without += lane.unwrap();
    }
    assert_eq!(
        state.multiplexer.session_count(),
        POST_CAP,
        "the count stops at the cap"
    );
    assert_eq!(
        served_without, 200,
        "the calls past the cap carry no session id"
    );
}

/// Session tools at the cap refuse with advice a legacy caller can follow,
/// and following it works: `initialize`, then retry with its id.
#[tokio::test]
async fn at_the_post_cap_a_session_tool_points_a_legacy_caller_to_initialize() {
    let (state, _dir) = gateway().await;
    state.multiplexer.fill_provisional_cap_for_test();
    let app = create_router(Arc::clone(&state));
    for (name, arguments) in [
        ("gateway_set_state", json!({"state": "review"})),
        ("gateway_set_profile", json!({"profile": "default"})),
        ("gateway_get_profile", json!({})),
    ] {
        let (status, session, body) = answer(
            app.clone()
                .oneshot(post(&call(5, name, &arguments), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
        assert!(session.is_none(), "{name}");
        assert_eq!(body["error"]["code"], json!(-32600), "{name}: {body}");
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("provisional-session capacity is full")
                && message.contains("Send initialize to open a session, then retry with its id."),
            "{name}: {body}"
        );
        assert!(
            !message.contains("2026-07-28"),
            "{name}: not the 2026 advice: {body}"
        );
    }
    let (status, session, _) = answer(
        app.clone()
            .oneshot(post(&initialize(), None))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session = session.expect("initialize is never capped");
    let (status, _, body) = answer(
        app.oneshot(post(
            &call(6, "gateway_set_state", &json!({"state": "review"})),
            Some(&session),
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_ne!(body["result"]["isError"], json!(true), "{body}");
}

/// A session tool the gateway hides keeps its ordinary answer at the cap:
/// the degraded answer is the answer the same hidden tool gets below the cap,
/// so the capacity path reveals nothing about tools the caller cannot see.
#[tokio::test]
async fn at_the_post_cap_a_hidden_session_tool_gets_its_ordinary_answer() {
    let (state, _dir) = super::tests::meta_fixture::test_router_app_state_with_meta(
        &crate::config::AuthConfig::default(),
        None,
        |meta| meta.with_exposed_meta_tools(&["gateway_list_servers".to_string()]),
    )
    .await;
    let app = create_router(Arc::clone(&state));
    let tools = [
        ("gateway_set_state", json!({"state": "review"})),
        ("gateway_set_profile", json!({"profile": "default"})),
        ("gateway_get_profile", json!({})),
    ];
    let mut ordinary = Vec::new();
    for (name, arguments) in &tools {
        let (status, _, body) = answer(
            app.clone()
                .oneshot(post(&call(7, name, arguments), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{name} below the cap: {body}");
        ordinary.push(body);
    }
    state.multiplexer.fill_provisional_cap_for_test();
    for ((name, arguments), below) in tools.iter().zip(&ordinary) {
        let (status, session, body) = answer(
            app.clone()
                .oneshot(post(&call(7, name, arguments), None))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
        assert!(session.is_none(), "{name}: served without a session");
        assert_eq!(
            &body, below,
            "{name}: the hidden tool's answer must not change at the cap"
        );
    }
}
