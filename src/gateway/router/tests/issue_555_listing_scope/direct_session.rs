// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The direct route acts under a session only when the caller owns it: a
//! presented `mcp-session-id` another caller holds selects neither that
//! session's routing profile nor its cost bucket.

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{Auth, fixture_with};

/// A profile registry whose default admits everything and whose `locked`
/// profile denies every `alpha` tool.
fn profiles() -> crate::routing_profile::ProfileRegistry {
    use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};
    let mut configs = std::collections::HashMap::new();
    configs.insert("open".to_string(), RoutingProfileConfig::default());
    configs.insert(
        "locked".to_string(),
        RoutingProfileConfig {
            deny_tools: Some(vec!["alpha_*".to_string()]),
            ..Default::default()
        },
    );
    ProfileRegistry::from_config(&configs, "open")
}

/// POST `body` to `uri` as `key`, presenting `session` if any; the session id
/// the response names and its body.
async fn post(
    router: &axum::Router,
    uri: &str,
    key: &str,
    session: Option<&str>,
    body: &Value,
) -> (Option<String>, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {key}"));
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let response = router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("router answers");
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        session,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_direct_call_never_acts_under_another_callers_session() {
    let f = fixture_with(Auth::Keys, |meta| meta.with_profile_registry(profiles())).await;
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    // GIVEN: u1 holds a legacy session running the `locked` profile
    let (session, _) = post(&f.router, "/mcp", "u1", None, &ping).await;
    let session = session.expect("a legacy POST is given a session");
    f.state
        .meta_mcp
        .session_profiles()
        .set_profile(&session, "locked");

    // WHEN: u2 calls alpha on the direct route, presenting u1's session id
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "alpha_read", "arguments": {} }
    });
    let (_, answer) = post(&f.router, "/mcp/alpha", "u2", Some(&session), &call).await;

    // THEN: u2 runs under its own (default) profile, and u1's session is not charged
    assert!(
        answer.get("error").is_none() && answer.get("result").is_some(),
        "the call ran under the presented session's profile: {answer}"
    );
    assert!(
        f.state
            .meta_mcp
            .cost_tracker()
            .session_snapshot(&session)
            .is_none(),
        "the presented session was charged for the call"
    );
}

#[tokio::test]
async fn a_direct_call_keeps_its_own_session() {
    // Control: the owner presenting its own session id still gets its profile.
    let f = fixture_with(Auth::Keys, |meta| meta.with_profile_registry(profiles())).await;
    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let (session, _) = post(&f.router, "/mcp", "u1", None, &ping).await;
    let session = session.expect("a legacy POST is given a session");
    f.state
        .meta_mcp
        .session_profiles()
        .set_profile(&session, "locked");
    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "alpha_read", "arguments": {} }
    });
    let (_, answer) = post(&f.router, "/mcp/alpha", "u1", Some(&session), &call).await;
    let message = answer["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("'locked' routing profile"),
        "the owner's own profile was not applied: {answer}"
    );
}
