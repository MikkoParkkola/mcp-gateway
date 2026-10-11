// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), router entry rows: the same per-user
//! backend as the meta-layer rows (`slot_verdict_fixture`), reached over HTTP
//! `/mcp` and the direct route `/mcp/{name}`. A name alpha's own catalogue
//! withholds or lacks answers as a name the gateway does not know (-32601),
//! and nothing reaches the upstream (O1, O2).

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::r2_identity_keys_tests::transparency_logger;
use super::tests::direct_route_state_with_identity;
use crate::config::InputSchemaEnforcement;
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    Asked, BACKEND, CallerSlot, CountingMint, Surfaced, TOOL, Warmth, per_user_backend, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// The router over one per-user backend, with its upstream counters.
struct Gateway {
    router: axum::Router,
    caller: Arc<Asked>,
    shared: Arc<Asked>,
    _store: tempfile::TempDir,
    _audit: [tempfile::NamedTempFile; 2],
}

impl Gateway {
    fn dispatched(&self) -> usize {
        self.caller.calls() + self.shared.calls()
    }
}

async fn gateway(
    slot: CallerSlot,
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
) -> Gateway {
    gateway_with_shared(slot, &valid(), enforcement, surfaced).await
}

async fn gateway_with_shared(
    slot: CallerSlot,
    shared_schema: &Value,
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
) -> Gateway {
    let (backend, caller, shared) =
        per_user_backend(slot, shared_schema, Warmth::Warm, enforcement);
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let audit = [
        tempfile::NamedTempFile::new().expect("tempfile"),
        tempfile::NamedTempFile::new().expect("tempfile"),
    ];
    let mut meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&state_mut.backends))
        .with_surfaced_tools(surfaced.configs());
    meta.set_identity_propagation(Arc::new(CountingMint(Arc::new(AtomicUsize::new(0)))));
    meta.enable_transparency_log(transparency_logger(&audit[0]));
    meta.set_multi_user(true);
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(transparency_logger(&audit[1]));
    Gateway {
        router: create_router(state),
        caller,
        shared,
        _store: store,
        _audit: audit,
    }
}

/// POST `body` to `uri` as alpha (auth is off in this state, so the verified
/// identity rides in as a request extension).
async fn post_as_alpha(router: &axum::Router, uri: &str, body: &Value) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp.example.invalid".to_string(),
    });
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn tools_call(name: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": {"q": "x"}}})
}

/// C1 over HTTP `/mcp` (withheld, lacked): a surfaced tool alpha's own
/// catalogue withholds or lacks answers exactly as the same call where no
/// configuration surfaces it, and reaches no upstream. RED on base: the
/// shared slot (valid) decides, so it dispatches.
#[tokio::test]
async fn c1_http_per_user_caller_slot_withholds_by_name() {
    let unknown = gateway(CallerSlot::Lacks, CLOSED, Surfaced::No).await;
    let absent = post_as_alpha(&unknown.router, "/mcp", &tools_call(TOOL)).await;
    assert_eq!(
        absent.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: an unknown name answers -32601: {absent:?}"
    );
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, CLOSED, Surfaced::Yes).await;
        let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
        assert_eq!(gw.dispatched(), 0, "C1-http {slot:?}: dispatched; {answer:?}");
        assert_eq!(answer, absent, "C1-http {slot:?}: {answer:?} vs unknown {absent:?}");
    }
}

/// The direct route `/mcp/{BACKEND}`.
fn direct() -> String {
    format!("/mcp/{BACKEND}")
}

/// C6 (withheld, lacked): on the direct route, a tool alpha's own catalogue
/// withholds or lacks answers -32601 as a JSON-RPC error, not a `success`
/// result carrying isError, and reaches no upstream. RED on base (measured
/// 2026-10-11): the withheld tool is dispatched (the upstream answers "ok");
/// the lacked one's refusal is wrapped in `success` (`key_check.rs:45`).
#[tokio::test]
async fn c6_direct_route_caller_slot_withholds() {
    let mut answers = Vec::new();
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, CLOSED, Surfaced::Yes).await;
        let answer = post_as_alpha(&gw.router, &direct(), &tools_call(TOOL)).await;
        assert_eq!(gw.dispatched(), 0, "C6 {slot:?}: dispatched; {answer:?}");
        assert_eq!(
            answer.1.pointer("/error/code"),
            Some(&json!(-32601)),
            "C6 {slot:?}: {answer:?}"
        );
        answers.push(answer);
    }
    assert_eq!(answers[0], answers[1], "C6: withheld vs lacked differ");
}

/// C10b: the same on the direct route with argument-key enforcement Off,
/// where base's F13 check returns before reading the slot
/// (`input_keys.rs:98`). RED on base: dispatched.
#[tokio::test]
async fn c10b_direct_route_visibility_with_enforcement_off() {
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, InputSchemaEnforcement::Off, Surfaced::Yes).await;
        let answer = post_as_alpha(&gw.router, &direct(), &tools_call(TOOL)).await;
        assert_eq!(gw.dispatched(), 0, "C10b {slot:?}: dispatched; {answer:?}");
        assert_eq!(
            answer.1.pointer("/error/code"),
            Some(&json!(-32601)),
            "C10b {slot:?}: {answer:?}"
        );
    }
}

/// F1 (the flip guard, design R5.4) over HTTP `/mcp`: the shared slot holds
/// an INVALID schema for [`TOOL`] and alpha's own slot a valid one. The call
/// reaches alpha's upstream exactly once. RED on base (measured): the route
/// stage withholds it on the shared schema and the meta layer answers it as
/// absent. (Its audit half, that route authorize and the firewall ran on the
/// target, is asserted with the implementation, where the target exists.)
#[tokio::test]
async fn f1_http_invalid_shared_valid_caller_dispatches() {
    let invalid = crate::gateway::meta_mcp::slot_verdict_fixture::invalid();
    let gw = gateway_with_shared(CallerSlot::Valid, &invalid, CLOSED, Surfaced::Yes).await;
    let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
    assert_eq!(gw.caller.calls(), 1, "F1: alpha's valid tool not dispatched: {answer:?}");
}

/// C6b (guard, kills M13): on the direct route, an argument-key refusal for a
/// tool alpha's catalogue offers keeps today's shape: a wrapped tool result
/// with isError, never -32601. Green on base.
#[tokio::test]
async fn c6b_direct_route_argument_key_refusal_unchanged() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x", "invented": 1}}});
    let answer = post_as_alpha(&gw.router, &direct(), &body).await;
    assert_eq!(gw.dispatched(), 0, "premise: an undeclared key was dispatched: {answer:?}");
    assert_eq!(
        answer.1.pointer("/result/isError"),
        Some(&json!(true)),
        "C6b: the argument-key refusal changed shape: {answer:?}"
    );
}
