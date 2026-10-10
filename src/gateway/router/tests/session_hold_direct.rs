// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7996: the direct `/mcp/{name}` route records a call's cost under the
//! session it resolved, after the backend answers. A call resolved before its
//! session ended, and still at the backend after both cleanup passes, must not
//! leave that cost behind under the ended id.

use std::sync::Arc;
use std::time::Duration;

use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::backend::Backend;
use crate::config::{AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::session_inflight_tests::Parked;
use crate::gateway::session_lifecycle::{
    END_GRACE, SessionLifecycle, now_unix, wire_meta_session_cleanup,
};

fn request(
    method: &str,
    uri: &str,
    session: Option<&str>,
    body: &Value,
) -> Request<axum::body::Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    builder
        .body(axum::body::Body::from(body.to_string()))
        .expect("a well-formed request")
}

#[tokio::test]
async fn a_direct_call_held_past_both_passes_leaves_no_cost_under_its_session() {
    let (mut state, _store) = super::test_router_app_state_with_auth(&AuthConfig::default()).await;
    let wire = Arc::new(Parked::default());
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    assert!(state.backends.register(backend));
    // Wired the way the server wires it: the cleanup handlers, the reaper
    // that pairs the multiplexer with the lifecycle, and the lifecycle the
    // DELETE handler ends sessions through.
    let lifecycle = Arc::new(SessionLifecycle::new());
    wire_meta_session_cleanup(&lifecycle, &state.meta_mcp);
    state.multiplexer.spawn_reaper_on(Arc::clone(&lifecycle));
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .session_lifecycle = Some(Arc::clone(&lifecycle));
    let router = super::create_router(Arc::clone(&state));

    let ping = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" });
    let opened = router
        .clone()
        .oneshot(request("POST", "/mcp", None, &ping))
        .await
        .expect("router answers");
    let session = opened
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .expect("a legacy POST is given a session")
        .to_owned();

    let call = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "act", "arguments": {} }
    });
    let pending = tokio::spawn(router.clone().oneshot(request(
        "POST",
        "/mcp/svc",
        Some(&session),
        &call,
    )));
    wire.arrivals(1).await;

    // The session ends while its direct call is at the backend, and the
    // grace pass runs before the backend answers.
    let ended = router
        .clone()
        .oneshot(request("DELETE", "/mcp", Some(&session), &Value::Null))
        .await
        .expect("router answers");
    assert_eq!(ended.status(), StatusCode::NO_CONTENT, "the session ended");
    lifecycle.reap(now_unix().expect("clock after 1970") + END_GRACE.as_secs() + 1);
    wire.release.notify_one();
    let answered = pending
        .await
        .expect("the call task completes")
        .expect("router answers");
    assert_eq!(
        answered.status(),
        StatusCode::OK,
        "the direct call is answered"
    );

    assert!(
        state
            .meta_mcp
            .cost_tracker()
            .session_snapshot(&session)
            .is_none(),
        "the direct call's cost outlived its ended session"
    );
}
