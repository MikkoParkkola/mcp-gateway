// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), router entry rows: the same per-user
//! backend as the meta-layer rows (`slot_verdict_fixture`), reached over HTTP
//! `/mcp` and the direct route `/mcp/{name}`. A name alpha's own catalogue
//! withholds or lacks answers as a name the gateway does not know (-32601),
//! and nothing reaches the upstream (O1, O2).

use crate::security::transparency_log::temp::TempLog;
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
    Asked, BACKEND, CallerSlot, CountingMint, Surfaced, TOOL, Warmth, per_user_backend_with, valid,
};
use crate::key_server::oidc::VerifiedIdentity;

pub(super) const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// The router over one per-user backend, with its upstream counters.
pub(super) struct Gateway {
    pub(super) router: axum::Router,
    pub(super) meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    pub(super) caller: Arc<Asked>,
    pub(super) shared: Arc<Asked>,
    /// Every credential resolution the gateway made.
    pub(super) mints: Arc<AtomicUsize>,
    _store: crate::gateway::router::tests::FixtureDir,
    _audit: [TempLog; 2],
}

impl Gateway {
    pub(super) fn dispatched(&self) -> usize {
        self.caller.calls() + self.shared.calls()
    }
}

pub(super) async fn gateway(
    slot: CallerSlot,
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
) -> Gateway {
    gateway_with_shared(slot, &valid(), enforcement, surfaced).await
}

pub(super) async fn gateway_with_shared(
    slot: CallerSlot,
    shared_schema: &Value,
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
) -> Gateway {
    gateway_armed(slot, shared_schema, enforcement, surfaced, |_| {}, |_| {}).await
}

/// The router fixture with `configure` applied to the backend's config and
/// `arm` to the Meta-MCP before it is mounted.
async fn gateway_armed(
    slot: CallerSlot,
    shared_schema: &Value,
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
    configure: impl FnOnce(&mut crate::config::BackendConfig),
    arm: impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp),
) -> Gateway {
    gateway_built(
        (slot, shared_schema, Warmth::Warm),
        enforcement,
        surfaced,
        configure,
        arm,
    )
    .await
}

/// The router fixture with alpha's slot cold (never listed).
pub(super) async fn gateway_cold(slot: CallerSlot, surfaced: Surfaced) -> Gateway {
    gateway_built(
        (slot, &valid(), Warmth::Cold),
        CLOSED,
        surfaced,
        |_| {},
        |_| {},
    )
    .await
}

pub(super) async fn gateway_built(
    built: (CallerSlot, &Value, Warmth),
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
    configure: impl FnOnce(&mut crate::config::BackendConfig),
    arm: impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp),
) -> Gateway {
    gateway_tuned(built, enforcement, surfaced, (configure, arm), |_| {}).await
}

/// [`gateway_built`] with `tune` applied to the router state before the
/// backend is registered (the sanitize rows switch `sanitize_input` on).
pub(super) async fn gateway_tuned(
    (slot, shared_schema, warmth): (CallerSlot, &Value, Warmth),
    enforcement: InputSchemaEnforcement,
    surfaced: Surfaced,
    (configure, arm): (
        impl FnOnce(&mut crate::config::BackendConfig),
        impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp),
    ),
    tune: impl FnOnce(&mut super::AppState),
) -> Gateway {
    let (backend, caller, shared) =
        per_user_backend_with(slot, shared_schema, warmth, enforcement, configure);
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    tune(state_mut);
    assert!(state_mut.backends.register(backend), "fixture registration");
    let audit = [TempLog::new(), TempLog::new()];
    let mut meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&state_mut.backends))
        .with_surfaced_tools(surfaced.configs());
    let mints = Arc::new(AtomicUsize::new(0));
    meta.set_identity_propagation(Arc::new(CountingMint(Arc::clone(&mints))));
    meta.enable_transparency_log(transparency_logger(&audit[0]));
    meta.set_multi_user(true);
    arm(&mut meta);
    let meta = Arc::new(meta);
    state_mut.meta_mcp = Arc::clone(&meta);
    state_mut.transparency_log = Some(transparency_logger(&audit[1]));
    Gateway {
        router: create_router(state),
        meta,
        caller,
        shared,
        mints,
        _store: store,
        _audit: audit,
    }
}

/// POST `body` to `uri` as alpha (auth is off in this state, so the verified
/// identity rides in as a request extension).
pub(super) async fn post_as_alpha(
    router: &axum::Router,
    uri: &str,
    body: &Value,
) -> (StatusCode, Value) {
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
        issuer: "https://issuer.example.invalid".to_string(), // the fixture identity's issuer
    });
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub(super) fn tools_call(name: &str) -> Value {
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
        assert_eq!(
            gw.dispatched(),
            0,
            "C1-http {slot:?}: dispatched; {answer:?}"
        );
        assert_eq!(
            answer, absent,
            "C1-http {slot:?}: {answer:?} vs unknown {absent:?}"
        );
    }
}

/// The direct route `/mcp/{BACKEND}`.
pub(super) fn direct() -> String {
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
    assert_eq!(
        gw.caller.calls(),
        1,
        "F1: alpha's valid tool not dispatched: {answer:?}"
    );
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
    assert_eq!(
        gw.dispatched(),
        0,
        "premise: an undeclared key was dispatched: {answer:?}"
    );
    assert_eq!(
        answer.1.pointer("/result/isError"),
        Some(&json!(true)),
        "C6b: the argument-key refusal changed shape: {answer:?}"
    );
}

/// A modern task `tools/call` of `name` on `/mcp` as alpha, with the headers
/// a 2026-07-28 client sends.
pub(super) async fn task_call_as_alpha(router: &axum::Router, name: &str) -> (StatusCode, Value) {
    let mut meta = super::tests::modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("slot-verdict-p4");
    let body = json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": name, "arguments": {"q": "x"}, "task": {}, "_meta": meta}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(), // the fixture identity's issuer
    });
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// P1 + P4 over HTTP (withheld, lacked): a modern task call naming a surfaced
/// tool alpha's own catalogue withholds or lacks gets no confirmation prompt
/// and makes no task: it answers exactly as the same call where nothing
/// surfaces the tool, and reaches no upstream. RED on base: the per-user
/// confirmation gate or the task route acts on the shared slot's verdict.
#[tokio::test]
async fn p1_p4_http_withheld_task_call_gets_no_prompt_and_no_task() {
    let unknown = gateway(CallerSlot::Lacks, CLOSED, Surfaced::No).await;
    let absent = task_call_as_alpha(&unknown.router, TOOL).await;
    assert!(
        absent.1.pointer("/result/taskId").is_none(),
        "premise: an unknown name made a task: {absent:?}"
    );
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, CLOSED, Surfaced::Yes).await;
        let answer = task_call_as_alpha(&gw.router, TOOL).await;
        assert!(
            answer.1.pointer("/result/taskId").is_none(),
            "P4 {slot:?}: a task was made: {answer:?}"
        );
        assert_eq!(gw.dispatched(), 0, "P1/P4 {slot:?}: dispatched; {answer:?}");
        assert_eq!(
            answer, absent,
            "P1/P4 {slot:?}: {answer:?} vs unknown {absent:?}"
        );
    }
}

/// F2 (design R5.4): on a per-user backend the route stage records no
/// shared-slot verdict in the request's memo; the first verdict recorded is
/// the caller's own, taken after the firewall. Probed at the hand-over from
/// the route stage to the dispatch. RED on base (#3807's strict memo): the
/// route stage records its shared-slot answer first.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f2_route_stage_records_no_shared_verdict_for_per_user() {
    use crate::gateway::meta_mcp::visible::seams;
    let gw = gateway(CallerSlot::Invalid, CLOSED, Surfaced::Yes).await;
    let seen = Arc::new(parking_lot::Mutex::new(None));
    let probe = Arc::clone(&seen);
    seams::after_route_stage(move || {
        *probe.lock() =
            Some(crate::gateway::meta_mcp::visible::memo::recorded_visibility(BACKEND, TOOL));
    });
    let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
    let recorded = seen.lock().take();
    assert_eq!(
        recorded,
        Some(None),
        "F2: at the route stage the memo held {recorded:?} (Some(None) = probed, nothing recorded); answer {answer:?}"
    );
}

/// Disable [`TOOL`] through the error budget, which the direct route's first
/// guard (`admit_target`, S1) refuses.
fn disable_tool(meta: &crate::gateway::meta_mcp::MetaMcp) {
    let cfg = meta.capability_budget_config.read().clone();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        meta.kill_switch
            .record_capability_failure(BACKEND, TOOL, &cfg);
    }
}

/// C6d (fold gpt F3): on the direct route the caller verdict runs before
/// `DirectRouteGuards::run`. With [`TOOL`] disabled (an armed S1 refusal), a
/// tool alpha's catalogue withholds answers -32601, not the guard's refusal;
/// alpha's valid tool reaches the guard and is refused by it (control). RED
/// on base: the guard answers first for both.
#[tokio::test]
async fn c6d_direct_route_verdict_precedes_direct_guards() {
    let control = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    disable_tool(&control.meta);
    let refused = post_as_alpha(&control.router, &direct(), &tools_call(TOOL)).await;
    assert_ne!(
        refused.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the armed guard does not refuse alpha's valid tool: {refused:?}"
    );
    assert_eq!(
        control.dispatched(),
        0,
        "premise: the guard let it through: {refused:?}"
    );
    let gw = gateway(CallerSlot::Invalid, CLOSED, Surfaced::Yes).await;
    disable_tool(&gw.meta);
    let answer = post_as_alpha(&gw.router, &direct(), &tools_call(TOOL)).await;
    assert_eq!(
        answer.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "C6d: the direct guard answered before the caller verdict: {answer:?}"
    );
}

/// I2b (index write site: direct-route listing; asked by MIK-8350): after
/// ONLY a complete `tools/list` on `/mcp/{BACKEND}` as alpha, the index names
/// alpha's slot. Red-by-absence on the stub.
#[tokio::test]
async fn i2b_index_written_by_direct_route_listing() {
    use crate::gateway::meta_mcp::slot_verdict_fixture::{BINDING, indexed_binding_for};
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let list = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}});
    let lists = gw.caller.lists();
    let answer = post_as_alpha(&gw.router, &direct(), &list).await;
    assert!(
        gw.caller.lists() > lists || answer.1.pointer("/result/tools").is_some(),
        "premise: the direct listing did not reach alpha's slot: {answer:?}"
    );
    assert_eq!(
        indexed_binding_for(&gw.meta, "alpha").as_deref(),
        Some(BINDING),
        "I2b: the direct-route listing wrote no index entry"
    );
}

/// C4b (gpt tp1 F3, restated kimi tp2 F1): over HTTP, a `gateway_execute`
/// chain with two static targets on the per-user backend, the first one
/// alpha's catalogue offers (`note`) and the second one it withholds
/// ([`TOOL`], invalid in alpha's slot). The second target answers -32601 and
/// is never dispatched; the first dispatching is expected. RED on base: both
/// dispatch on the shared slot's verdict.
#[tokio::test]
async fn c4b_execute_multi_target_withheld_second_target() {
    let gw = gateway(CallerSlot::Invalid, CLOSED, Surfaced::No).await;
    let first = format!("{BACKEND}:note");
    let second = format!("{BACKEND}:{TOOL}");
    let body = json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
    "params": {"name": "gateway_execute", "arguments": {"chain": [
        {"tool": first, "arguments": {"q": "x"}},
        {"tool": second, "arguments": {"q": "y"}}
    ]}}});
    let answer = post_as_alpha(&gw.router, "/mcp", &body).await;
    assert_eq!(
        gw.dispatched(),
        1,
        "C4b: the withheld second target dispatched (or the first did not): {answer:?}"
    );
    assert_eq!(
        answer.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "C4b: the withheld second target did not answer -32601: {answer:?}"
    );
}

/// P3 over HTTP (withheld, lacked): a plain call (no task, so no X14 gate)
/// reaches admission, whose target policy runs S1 (`admit_target`, here an
/// armed capability-disable refusal that names the tool). A tool alpha's
/// own catalogue withholds or lacks answers exactly as the same call where
/// nothing surfaces it; alpha's valid tool gets the admission refusal
/// (control). RED on base: admission targets it on the shared slot's verdict.
#[tokio::test]
async fn p3_http_withheld_call_gets_no_admission_refusal() {
    let control = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    disable_tool(&control.meta);
    let refused = post_as_alpha(&control.router, "/mcp", &tools_call(TOOL)).await;
    assert!(
        refused.1.to_string().contains("temporarily disabled"),
        "premise: the armed admission refusal does not reach alpha's valid tool: {refused:?}"
    );
    let unknown = gateway(CallerSlot::Lacks, CLOSED, Surfaced::No).await;
    disable_tool(&unknown.meta);
    let absent = post_as_alpha(&unknown.router, "/mcp", &tools_call(TOOL)).await;
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, CLOSED, Surfaced::Yes).await;
        disable_tool(&gw.meta);
        let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
        assert!(
            !answer.1.to_string().contains("temporarily disabled"),
            "P3 {slot:?}: the admission refusal reached alpha: {answer:?}"
        );
        assert_eq!(
            answer, absent,
            "P3 {slot:?}: {answer:?} vs unknown {absent:?}"
        );
    }
}

/// P2-order (guard, lead ruling 2026-10-11): P2 has no row of its own on HTTP
/// because, for a verified per-user caller, the X14 confirmation comes
/// BEFORE `refuse_chained_task`. P1 (no prompt for a withheld name) plus
/// MIK-8340 row 1 (a forged `requestState` answers as absent) then cover it.
/// This pins that order: alpha's valid tool on a require-chain backend gets
/// the X14 prompt, not the -32001 refusal. If the chain refusal ever moves
/// ahead of X14, this fails, and P2 needs its own row. Green on base.
#[tokio::test]
async fn p2_order_x14_precedes_the_require_chain_refusal() {
    let gw = gateway_armed(
        CallerSlot::Valid,
        &valid(),
        CLOSED,
        Surfaced::Yes,
        |config| {
            config.signature_chain = crate::config::ChainMode::Require;
            config.chain_origins = vec!["gw-up".to_string()];
            config.chain_signer = Some("gw-up".to_string());
        },
        |meta| {
            meta.set_chain_signer(
                crate::gateway::chain_test_support::signer(),
                crate::config::ChainEmit::Always,
            );
        },
    )
    .await;
    let answer = task_call_as_alpha(&gw.router, TOOL).await;
    assert!(
        answer.1.pointer("/result/inputRequests").is_some(),
        "P2-order: no X14 prompt came first: {answer:?}"
    );
    assert!(
        !answer.1.to_string().contains("signature chain"),
        "P2-order: the require-chain refusal came before X14; P2 needs its own row: {answer:?}"
    );
}
