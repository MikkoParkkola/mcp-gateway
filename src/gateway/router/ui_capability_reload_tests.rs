// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T24 through the route: a capability the UI gate admitted as
//! read-only, reloaded as a write before it runs, is refused by the
//! capability executor's own gate. That refusal is now answered as itself,
//! not folded into a tool result, so the route's answer must still be 409
//! `not_run`, with nothing run.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::ui_tool_call_cell_tests::assert_refused_delivery;
use super::ui_tool_call_tests::{ADMIN, Fx, fixture};
use crate::capability::{CapabilityBackend, CapabilityDefinition, CapabilityExecutor};

/// `probe`, declared read-only or not, reached at `base_url`'s `/probe`.
fn probe(read_only: bool, base_url: &str) -> CapabilityDefinition {
    let yaml = format!(
        "name: probe\ndescription: Test capability\nmetadata:\n  read_only: {read_only}\n\
         providers:\n  primary:\n    service: rest\n    config:\n      \
         base_url: {base_url}\n      path: /probe\n      method: GET\n"
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

/// The fixture with `probe` served as a read-only capability whose provider
/// counts every request it gets; returns the capability backend, the URL
/// `probe` reaches, and the count.
async fn served() -> (Fx, Arc<CapabilityBackend>, String, Arc<AtomicUsize>) {
    let fx = fixture().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/probe",
            axum::routing::get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({"ok": true}))
                }
            }),
        );
        axum::serve(listener, app).await.expect("serve");
    });
    let base_url = crate::test_fixture_host::fixture_url(port);
    let client = crate::test_fixture_host::fixture_client(Duration::from_secs(5));
    let caps = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new().with_test_http_client(client)),
    ));
    caps.register_capability(probe(true, &base_url))
        .expect("registered");
    fx.state.meta_mcp.set_capabilities(Arc::clone(&caps));
    (fx, caps, base_url, hits)
}

/// The reloaded write is refused by the executor's gate: 409 `not_run`,
/// recorded refused, and its provider never reached. Mutant: the UI arm in
/// the capability executor removed (the call then runs).
#[tokio::test]
async fn t24b_a_capability_reloaded_as_a_write_after_the_gate_is_not_run() {
    // Control: the read-only capability passes every gate and runs once.
    let (fx, _caps, _url, hits) = served().await;
    let (status, body) = try_probe(&fx, "caps").await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "premise: the UI gate admits a read-only capability and it runs: {status} {body}"
    );

    let (fx, caps, base_url, hits) = served().await;
    let reloaded = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&reloaded);
    let _armed = crate::gateway::ui_call::gate_seam::after_gate(move || {
        caps.register_capability(probe(false, &base_url))
            .expect("reloaded");
        flag.store(true, Ordering::SeqCst);
    });
    let (status, body) = try_probe(&fx, "caps").await;
    assert!(
        reloaded.load(Ordering::SeqCst),
        "premise: the gate admitted the call, then it was reloaded: {status} {body}"
    );
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["disposition"], "not_run", "{body}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the write never ran");
    assert_refused_delivery(&fx);
}
