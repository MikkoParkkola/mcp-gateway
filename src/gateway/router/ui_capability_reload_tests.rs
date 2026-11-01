// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T24 through the route (MIK-9129): a capability the UI gate admitted as
//! read-only, reloaded as a write before it runs, is refused by the
//! capability executor's own gate. That refusal is now answered as itself,
//! not folded into a tool result, so the route's answer must still be 409
//! `not_run`, with nothing run.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::ui_tool_call_cell_tests::assert_refused_delivery;
use super::ui_tool_call_tests::{ADMIN, Fx, fixture};
use crate::capability::{CapabilityBackend, CapabilityDefinition, CapabilityExecutor};

/// `probe`, declared read-only or not; its REST provider is unreachable, so
/// a call that gets past every gate fails later, for another reason.
fn probe(read_only: bool) -> CapabilityDefinition {
    let yaml = format!(
        r"
name: probe
description: Test capability
metadata:
  read_only: {read_only}
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /probe
"
    );
    crate::capability::parse_capability(&yaml).expect("capability")
}

/// The UI route's answer to an unconfirmed call of the capability `probe`.
async fn try_probe(fx: &Fx, server: &str) -> (StatusCode, Value) {
    let body = json!({"server": server, "tool": "probe", "arguments": {}, "confirm_write": false});
    let request = Request::builder()
        .method("POST")
        .uri("/ui/api/tools/call")
        .header("authorization", format!("Bearer {ADMIN}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let response = create_router(Arc::clone(&fx.state))
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The fixture with `probe` served as a read-only capability.
async fn served() -> (Fx, Arc<CapabilityBackend>) {
    let fx = fixture().await;
    let caps = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.register_capability(probe(true)).expect("registered");
    fx.state.meta_mcp.set_capabilities(Arc::clone(&caps));
    (fx, caps)
}

/// The reloaded write is refused by the executor's gate: 409 `not_run`,
/// recorded refused. Mutant: the UI arm in the capability executor removed
/// (the call then runs, and fails at the unreachable provider).
#[tokio::test]
async fn t24b_a_capability_reloaded_as_a_write_after_the_gate_is_not_run() {
    // Control: the read-only capability passes every gate and is run.
    let (fx, _caps) = served().await;
    let (status, body) = try_probe(&fx, "caps").await;
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "premise: the UI gate admits a read-only capability: {body}"
    );

    let (fx, caps) = served().await;
    let reloaded = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&reloaded);
    let _armed = crate::gateway::meta_mcp::invoke::ui_gate_seam::after_ui_gate(move || {
        caps.register_capability(probe(false)).expect("reloaded");
        flag.store(true, Ordering::SeqCst);
    });
    let (status, body) = try_probe(&fx, "caps").await;
    assert!(
        reloaded.load(Ordering::SeqCst),
        "premise: the gate admitted the call, then it was reloaded: {status} {body}"
    );
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_refused_delivery(&fx);
}
