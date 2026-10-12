// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 HTTP rows, variants: the cold, enforcement-mode and
//! step-shape variants of `slot_verdict_http_tests`, and the HTTP twins of
//! rows that run in-process there, over the same fixture.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::slot_verdict_http_tests::*;
use crate::config::InputSchemaEnforcement;
use crate::gateway::meta_mcp::slot_verdict_fixture::{BACKEND, CallerSlot, Surfaced, TOOL, Warmth};

/// P1 + P4 with alpha's slot cold (SLOTVIS.6; kills M19): the caller verdict
/// fills alpha's slot as alpha before any reader runs, so a modern task call
/// naming a tool alpha's own catalogue withholds or lacks gets no prompt and
/// makes no task. It answers exactly as the same call where nothing surfaces
/// the tool, though the shared slot offers it throughout.
#[tokio::test]
async fn p1_p4_cold_http_withheld_task_call_gets_no_prompt_and_no_task() {
    let unknown = gateway_cold(CallerSlot::Lacks, Surfaced::No).await;
    let absent = task_call_as_alpha(&unknown.router, TOOL).await;
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway_cold(slot, Surfaced::Yes).await;
        let answer = task_call_as_alpha(&gw.router, TOOL).await;
        assert!(
            answer.1.pointer("/result/taskId").is_none(),
            "P4 cold {slot:?}: a task was made: {answer:?}"
        );
        assert_eq!(
            gw.dispatched(),
            0,
            "P1/P4 cold {slot:?}: dispatched; {answer:?}"
        );
        assert_eq!(
            answer, absent,
            "P1/P4 cold {slot:?}: {answer:?} vs unknown {absent:?}"
        );
    }
}

/// A `gateway_execute` chain over `/mcp` as alpha.
async fn execute_as_alpha(gw: &Gateway, steps: &[&str]) -> (StatusCode, Value) {
    let chain: Vec<Value> = steps
        .iter()
        .map(|tool| json!({"tool": format!("{BACKEND}:{tool}"), "arguments": {"q": "x"}}))
        .collect();
    let body = json!({"jsonrpc": "2.0", "id": 13, "method": "tools/call",
        "params": {"name": "gateway_execute", "arguments": {"chain": chain}}});
    post_as_alpha(&gw.router, "/mcp", &body).await
}

/// C11b over HTTP (kills M15): every chain step resolves alpha's credential
/// exactly once. The caller verdict's resolution is carried to the one step
/// it judged; a later step naming the same tool resolves again, and a step
/// naming another tool on the same backend never takes a resolution carried
/// for a different tool. Two steps, two resolutions, in both shapes.
#[tokio::test]
async fn c11b_http_each_step_resolves_once() {
    let sibling = "note";
    for steps in [[TOOL, TOOL], [sibling, TOOL]] {
        let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::No).await;
        let before = gw.mints.load(Ordering::SeqCst);
        let answer = execute_as_alpha(&gw, &steps).await;
        assert_eq!(
            gw.dispatched(),
            2,
            "premise {steps:?}: both steps dispatch: {answer:?}"
        );
        assert_eq!(
            gw.mints.load(Ordering::SeqCst),
            before + 2,
            "C11b-http {steps:?}: resolutions for two steps: {answer:?}"
        );
    }
}

/// C14 over HTTP (design R5.2 step 0; kills M20): a descriptor-blocked target
/// passes route authorize, which judges policy only, and reaches the caller
/// verdict. The verdict judges descriptor and policy before anything else, so
/// no credential is resolved and no slot is filled; the call is refused and
/// nothing is dispatched.
#[tokio::test]
async fn c14_http_descriptor_blocked_target_resolves_nothing() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::No).await;
    gw.meta
        .backends
        .get(BACKEND)
        .expect("the backend")
        .block_tool_for_test(TOOL);
    let mints = gw.mints.load(Ordering::SeqCst);
    let lists = gw.caller.lists() + gw.shared.lists();
    let args = json!({"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}});
    let body = json!({"jsonrpc": "2.0", "id": 14, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": args}});
    let answer = post_as_alpha(&gw.router, "/mcp", &body).await;
    assert!(
        answer.1.get("error").is_some()
            || answer.1.pointer("/result/isError") == Some(&json!(true)),
        "premise: the blocked target is not refused: {answer:?}"
    );
    assert_eq!(gw.dispatched(), 0, "C14-http: dispatched: {answer:?}");
    assert_eq!(
        gw.mints.load(Ordering::SeqCst),
        mints,
        "C14-http: a credential was resolved for a blocked target"
    );
    assert_eq!(
        gw.caller.lists() + gw.shared.lists(),
        lists,
        "C14-http: a slot was filled for a blocked target"
    );
}

/// C10 over HTTP `/mcp` (withheld, lacked): C1 at argument-key enforcement
/// Off. RED on base: F13 returns before reading the slot, so it dispatches.
#[tokio::test]
async fn c10_http_per_user_visibility_runs_with_enforcement_off() {
    let off = InputSchemaEnforcement::Off;
    let unknown = gateway(CallerSlot::Lacks, off, Surfaced::No).await;
    let absent = post_as_alpha(&unknown.router, "/mcp", &tools_call(TOOL)).await;
    assert_eq!(
        absent.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: an unknown name answers -32601 at Off: {absent:?}"
    );
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, off, Surfaced::Yes).await;
        let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
        assert_eq!(
            gw.dispatched(),
            0,
            "C10-http {slot:?}: dispatched; {answer:?}"
        );
        assert_eq!(
            answer, absent,
            "C10-http {slot:?}: {answer:?} vs unknown {absent:?}"
        );
    }
}

/// C6b in Standard mode (guard, kills M13): an undeclared key against a
/// level that states `additionalProperties: false` keeps today's wrapped
/// refusal on the direct route, never -32601. alpha's slot is given the
/// closed schema directly, since `valid()` leaves the level open.
#[tokio::test]
async fn c6b_standard_direct_route_argument_key_refusal_unchanged() {
    use crate::gateway::meta_mcp::slot_verdict_fixture::BINDING;
    let gw = gateway(
        CallerSlot::Valid,
        InputSchemaEnforcement::Standard,
        Surfaced::Yes,
    )
    .await;
    let closed: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "description": "A ledger tool.",
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}},
            "additionalProperties": false}
    }))
    .expect("a tool");
    gw.meta
        .backends
        .get(BACKEND)
        .expect("the backend")
        .store_per_user_tools_for_test(BINDING, vec![closed]);
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
        "C6b-standard: the argument-key refusal changed shape: {answer:?}"
    );
}

/// An upstream whose `tools/list` answers without a tools array: an unreadable
/// page, which the direct route judges as a TRUNCATED listing.
struct UnreadableList;

#[async_trait::async_trait]
impl crate::transport::Transport for UnreadableList {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({"tools": "not-a-list"}),
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// I2b, second half: after ONLY a Truncated `/mcp/{BACKEND}` `tools/list` as
/// alpha, the index holds no entry for alpha. Red-by-absence on the stub.
#[tokio::test]
async fn i2b_truncated_direct_route_listing_leaves_no_index_entry() {
    use crate::gateway::meta_mcp::slot_verdict_fixture::{BINDING, indexed_binding_for};
    let gw = gateway_cold(CallerSlot::Valid, Surfaced::Yes).await;
    gw.meta
        .backends
        .get(BACKEND)
        .expect("the backend")
        .set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: BINDING.to_string(),
            },
            Arc::new(UnreadableList),
        );
    let list = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}});
    let answer = post_as_alpha(&gw.router, &direct(), &list).await;
    assert!(
        answer.1.pointer("/result/tools").is_some(),
        "premise: the direct listing was not answered: {answer:?}"
    );
    assert_eq!(
        indexed_binding_for(&gw.meta, "alpha"),
        None,
        "I2b: a Truncated direct-route listing wrote an index entry"
    );
}

/// A `gateway_invoke` of [`TOOL`] on `BACKEND` over `/mcp` as alpha.
fn invoke_call() -> Value {
    let args = json!({"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}});
    json!({"jsonrpc": "2.0", "id": 15, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": args}})
}

/// C4 over HTTP (withheld, lacked): a `gateway_invoke` target on the per-user
/// backend is judged by alpha's own slot at the entry, before any X14 prompt:
/// a withheld or lacked tool answers -32601 (the same for both), is not
/// dispatched and draws no confirmation challenge; alpha's valid tool
/// dispatches (control). RED on base: the shared slot (valid) decides.
#[tokio::test]
async fn c4_http_gateway_invoke_target_judged_by_the_callers_slot() {
    let control = gateway(CallerSlot::Valid, CLOSED, Surfaced::No).await;
    let ok = post_as_alpha(&control.router, "/mcp", &invoke_call()).await;
    assert_eq!(
        control.caller.calls(),
        1,
        "premise: alpha's valid tool is not dispatched: {ok:?}"
    );
    let mut answers = Vec::new();
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, CLOSED, Surfaced::No).await;
        let answer = post_as_alpha(&gw.router, "/mcp", &invoke_call()).await;
        assert_eq!(
            gw.dispatched(),
            0,
            "C4-http {slot:?}: dispatched; {answer:?}"
        );
        assert_eq!(
            answer.1.pointer("/error/code"),
            Some(&json!(-32601)),
            "C4-http {slot:?}: {answer:?}"
        );
        assert!(
            answer.1.pointer("/result/inputRequests").is_none(),
            "C4-http {slot:?}: a confirmation prompt was issued: {answer:?}"
        );
        answers.push(answer);
    }
    assert_eq!(answers[0], answers[1], "C4-http: withheld vs lacked differ");
}

/// C7 over HTTP: alpha's slot is cold, its own schema valid and the shared one
/// INVALID. The call fills alpha's slot exactly once, mints exactly once and
/// dispatches exactly once. RED on base: the shared slot withholds the tool.
#[tokio::test]
async fn c7_http_cold_caller_first_call_dispatches_on_own_slot() {
    let invalid = crate::gateway::meta_mcp::slot_verdict_fixture::invalid();
    let gw = gateway_built(
        (CallerSlot::Valid, &invalid, Warmth::Cold),
        CLOSED,
        Surfaced::Yes,
        |_| {},
        |_| {},
    )
    .await;
    let (lists, calls) = (gw.caller.lists(), gw.caller.calls());
    let mints = gw.mints.load(Ordering::SeqCst);
    let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
    assert_eq!(
        gw.caller.calls(),
        calls + 1,
        "C7-http: not dispatched once: {answer:?}"
    );
    assert_eq!(
        gw.caller.lists(),
        lists + 1,
        "C7-http: alpha's slot not filled once"
    );
    assert_eq!(
        gw.mints.load(Ordering::SeqCst),
        mints + 1,
        "C7-http: resolutions for one cold call"
    );
}

/// C7b over HTTP (guard, kills M14): a call on alpha's warm slot fetches no
/// catalogue from either upstream; a held answer needs no `tools/list`.
#[tokio::test]
async fn c7b_http_warm_verdict_fetches_nothing() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let lists = gw.caller.lists() + gw.shared.lists();
    let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
    assert_eq!(gw.caller.calls(), 1, "premise: not dispatched: {answer:?}");
    assert_eq!(
        gw.caller.lists() + gw.shared.lists(),
        lists,
        "C7b-http: a warm call listed"
    );
}

/// C11 over HTTP (guard, kills M03): a call of a SURFACED name meets the
/// verdict at the route loop, again in `call_dispatch`, and the funnel; it
/// still resolves alpha's credential exactly once.
#[tokio::test]
async fn c11_http_surfaced_name_resolves_once() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let mints = gw.mints.load(Ordering::SeqCst);
    let answer = post_as_alpha(&gw.router, "/mcp", &tools_call(TOOL)).await;
    assert_eq!(gw.caller.calls(), 1, "premise: not dispatched: {answer:?}");
    assert_eq!(
        gw.mints.load(Ordering::SeqCst),
        mints + 1,
        "C11-http: resolutions for one surfaced call: {answer:?}"
    );
}

/// F3 over HTTP (the step flip guard): a `gateway_execute` step is judged by
/// the caller's slot, not the shared one, in both directions. Shared Invalid
/// with caller Valid dispatches; shared Valid with caller Invalid answers
/// -32601 and does not. RED on base: the shared Invalid withholds the step.
#[tokio::test]
async fn f3_http_execute_step_flip_guard() {
    let invalid = crate::gateway::meta_mcp::slot_verdict_fixture::invalid();
    let gw = gateway_with_shared(CallerSlot::Valid, &invalid, CLOSED, Surfaced::No).await;
    let answer = execute_as_alpha(&gw, &[TOOL]).await;
    assert_eq!(
        gw.dispatched(),
        1,
        "F3-http: a step valid in the caller's slot (invalid in the shared one) did not dispatch: {answer:?}"
    );
    let gw = gateway(CallerSlot::Invalid, CLOSED, Surfaced::No).await;
    let answer = execute_as_alpha(&gw, &[TOOL]).await;
    assert_eq!(
        gw.dispatched(),
        0,
        "F3-http: a step invalid in the caller's slot (valid in the shared one) dispatched: {answer:?}"
    );
    assert_eq!(
        answer.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "F3-http: the reverse step is not answered -32601: {answer:?}"
    );
}

/// A modern `gateway_invoke` of [`TOOL`] on `/mcp` as alpha, keyed `key`;
/// `task` adds the task envelope.
async fn keyed_invoke_as_alpha(gw: &Gateway, key: &str, task: bool) -> (StatusCode, Value) {
    let mut meta = super::tests::modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let name = "gateway_invoke";
    let mut params = json!({"name": name,
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}}, "_meta": meta});
    if task {
        params["task"] = json!({});
    }
    let body = json!({"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: "alpha".to_string(),
            email: "alpha@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.example.invalid".to_string(),
        });
    let response = tower::ServiceExt::oneshot(gw.router.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// R1 (keyed replay after withdrawal): alpha's keyed `gateway_invoke` of
/// [`TOOL`] dispatches while alpha's catalogue offers it. alpha's catalogue
/// then withholds it (invalid schema). The same call with the same key
/// answers -32601, as a name alpha does not have, and is not answered with
/// the stored result. RED before the fix: the stored result is replayed
/// before alpha's catalogue is read.
#[tokio::test]
async fn r1_keyed_replay_after_the_callers_catalogue_withholds_answers_absent() {
    use crate::gateway::meta_mcp::slot_verdict_fixture::{BINDING, invalid};
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::No).await;
    let first = keyed_invoke_as_alpha(&gw, "r1-replay", false).await;
    assert_eq!(
        gw.dispatched(),
        1,
        "premise: the first call dispatches: {first:?}"
    );
    let withheld: crate::protocol::Tool =
        serde_json::from_value(json!({"name": TOOL, "inputSchema": invalid()})).expect("a tool");
    gw.meta
        .backends
        .get(BACKEND)
        .expect("the backend")
        .store_per_user_tools_for_test(BINDING, vec![withheld]);
    let replay = keyed_invoke_as_alpha(&gw, "r1-replay", false).await;
    assert_eq!(
        replay.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "R1: a withheld tool's keyed retry was answered: {replay:?}"
    );
    assert_eq!(gw.dispatched(), 1, "R1: the retry dispatched: {replay:?}");
}

/// R1b (explicit task of a withheld tool): alpha's keyed task
/// `gateway_invoke` naming [`TOOL`], which alpha's catalogue withholds, makes
/// no task and answers -32601. RED before the fix: the shared invocation
/// policy admits the task before the caller's verdict is consulted.
#[tokio::test]
async fn r1b_explicit_task_of_a_withheld_tool_makes_no_task() {
    let gw = gateway(CallerSlot::Invalid, CLOSED, Surfaced::No).await;
    let answer = keyed_invoke_as_alpha(&gw, "r1b-task", true).await;
    assert!(
        answer.1.pointer("/result/taskId").is_none(),
        "R1b: a task was made for a withheld tool: {answer:?}"
    );
    assert_eq!(
        answer.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "R1b: {answer:?}"
    );
    assert_eq!(gw.dispatched(), 0, "R1b: dispatched: {answer:?}");
}

/// I2g (index write site: the direct route's catalogue check): alpha's slot
/// is cold and its catalogue withholds [`TOOL`]. A direct-route call fills
/// alpha's slot to judge it and answers -32601; after ONLY that, the index
/// names alpha's slot, so no later listing shows alpha the shared entry.
/// RED before the fix: the check fills the slot without indexing it.
#[tokio::test]
async fn i2g_index_written_by_the_direct_route_catalogue_check() {
    use crate::gateway::meta_mcp::slot_verdict_fixture::{BINDING, indexed_binding_for};
    let gw = gateway_cold(CallerSlot::Invalid, Surfaced::Yes).await;
    let answer = post_as_alpha(&gw.router, &direct(), &tools_call(TOOL)).await;
    assert_eq!(
        answer.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the direct call answers as absent: {answer:?}"
    );
    assert_eq!(
        gw.caller.lists(),
        1,
        "premise: alpha's slot was filled: {answer:?}"
    );
    assert_eq!(
        indexed_binding_for(&gw.meta, "alpha").as_deref(),
        Some(BINDING),
        "I2g: the direct-route check wrote no index entry"
    );
}

/// A modern keyed `tools/call` of [`TOOL`] on the direct route as alpha.
async fn keyed_direct_call_as_alpha(gw: &Gateway, key: &str) -> (StatusCode, Value) {
    let mut meta = super::tests::modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let body = json!({"jsonrpc": "2.0", "id": 22, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"}, "_meta": meta}});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(direct())
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", TOOL)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: "alpha".to_string(),
            email: "alpha@example.invalid".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://issuer.example.invalid".to_string(),
        });
    let response = tower::ServiceExt::oneshot(gw.router.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// R1-direct (guard; pins the direct route's order): alpha's keyed direct
/// call of [`TOOL`] dispatches while alpha's catalogue offers it; alpha's
/// catalogue then withholds it. The same call with the same key answers
/// -32601 and serves no stored result: the direct route judges the caller's
/// catalogue (`key_refusal`, in `guard_and_sanitize`) before the execution
/// lease can replay. Green at head; the order-swap mutant turns it red.
#[tokio::test]
async fn r1_direct_keyed_replay_after_the_callers_catalogue_withholds_answers_absent() {
    use crate::gateway::meta_mcp::slot_verdict_fixture::{BINDING, invalid};
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let first = keyed_direct_call_as_alpha(&gw, "r1-direct").await;
    assert_eq!(
        gw.dispatched(),
        1,
        "premise: the first call dispatches: {first:?}"
    );
    assert!(
        first.1.get("error").is_none(),
        "premise: the first call is answered: {first:?}"
    );
    let withheld: crate::protocol::Tool =
        serde_json::from_value(json!({"name": TOOL, "inputSchema": invalid()})).expect("a tool");
    gw.meta
        .backends
        .get(BACKEND)
        .expect("the backend")
        .store_per_user_tools_for_test(BINDING, vec![withheld]);
    let replay = keyed_direct_call_as_alpha(&gw, "r1-direct").await;
    assert_eq!(
        replay.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "R1-direct: a withheld tool's keyed retry was answered: {replay:?}"
    );
    assert_eq!(
        gw.dispatched(),
        1,
        "R1-direct: the retry dispatched: {replay:?}"
    );
}

/// `gateway_invoke` of `tool` on [`BACKEND`] over `/mcp` as alpha.
fn invoke_body(tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": 23, "method": "tools/call",
        "params": {"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": tool, "arguments": {"q": "x"}}}})
}

/// S1 (status parity, `gateway_invoke`): a tool alpha's catalogue withholds
/// and one it lacks answer alike, HTTP status included, and both answer as a
/// name the backend has nowhere (normalised for the name). No status or body
/// difference tells withheld from lacked from unknown.
#[tokio::test]
async fn s1_http_invoke_withheld_lacked_and_unknown_answer_alike() {
    let unknown_gw = gateway(CallerSlot::Lacks, CLOSED, Surfaced::No).await;
    let unknown = post_as_alpha(&unknown_gw.router, "/mcp", &invoke_body("nosuch")).await;
    assert_eq!(
        unknown.1.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: an unknown name answers -32601: {unknown:?}"
    );
    let unknown_text = unknown.1.to_string().replace("nosuch", TOOL);
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let gw = gateway(slot, CLOSED, Surfaced::No).await;
        let answer = post_as_alpha(&gw.router, "/mcp", &invoke_body(TOOL)).await;
        assert_eq!(gw.dispatched(), 0, "S1 {slot:?}: dispatched: {answer:?}");
        assert_eq!(
            answer.0, unknown.0,
            "S1 {slot:?}: status differs: {answer:?} vs {unknown:?}"
        );
        assert_eq!(
            answer.1.to_string(),
            unknown_text,
            "S1 {slot:?}: body differs from an unknown name's"
        );
    }
}

/// A `tools/call` of `name` on `/mcp` whose argument carries a NUL, as alpha
/// (`alpha`) or with no identity at all.
async fn nul_call(gw: &Gateway, name: &str, alpha: bool) -> (StatusCode, Value) {
    let body = json!({"jsonrpc": "2.0", "id": 31, "method": "tools/call",
        "params": {"name": name, "arguments": {"q": "a\u{0}b"}}});
    if alpha {
        return post_as_alpha(&gw.router, "/mcp", &body).await;
    }
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(gw.router.clone(), request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The per-user backend as a `passthrough` backend, with input sanitizing on.
async fn sanitizing_gateway(slot: CallerSlot) -> Gateway {
    gateway_tuned(
        (slot, &valid(), Warmth::Warm),
        CLOSED,
        Surfaced::Yes,
        (
            |c: &mut crate::config::BackendConfig| c.passthrough = true,
            |_: &mut _| {},
        ),
        |state: &mut super::AppState| state.sanitize_input = true,
    )
    .await
}

const NUL_REFUSAL: &str = "null bytes";

/// X1 (MIK-8356 ruling (a); the exemption oracle at the per-user verdict and
/// the MIK-8154 sanitize exemption): on a per-user `passthrough` backend with
/// sanitizing on, a call by a surfaced name is never exempt. Intake runs
/// before the caller's own catalogue is read, so an exemption there would
/// let the answer tell a name alpha's catalogue withholds or lacks (exempt,
/// then -32601) from one the backend has nowhere (sanitized). Every surfaced
/// case answers the same null-byte refusal and dispatches nothing: offered,
/// withheld and lacked as alpha, offered with no identity, and an unknown
/// name. Control: `gateway_invoke` naming the backend keeps the passthrough
/// exemption. RED before the fix: the withheld and lacked names, and the
/// offered one, pass intake as exempt.
#[tokio::test]
async fn x1_per_user_surfaced_names_are_always_sanitized() {
    let unknown_gw = sanitizing_gateway(CallerSlot::Valid).await;
    let unknown = nul_call(&unknown_gw, "no_such_tool", true).await;
    assert!(
        unknown.1.to_string().contains(NUL_REFUSAL),
        "premise: an unknown name is sanitized: {unknown:?}"
    );
    let unknown_text = unknown.1.to_string();
    let cases = [
        ("offered", CallerSlot::Valid, true),
        ("withheld", CallerSlot::Invalid, true),
        ("lacked", CallerSlot::Lacks, true),
        ("no identity", CallerSlot::Valid, false),
    ];
    for (case, slot, alpha) in cases {
        let gw = sanitizing_gateway(slot).await;
        let answer = nul_call(&gw, TOOL, alpha).await;
        assert_eq!(gw.dispatched(), 0, "X1 {case}: dispatched: {answer:?}");
        assert_eq!(
            (answer.0, answer.1.to_string()),
            (unknown.0, unknown_text.clone()),
            "X1 {case}: answered unlike an unknown name"
        );
    }
    let gw = sanitizing_gateway(CallerSlot::Valid).await;
    let body = json!({"jsonrpc": "2.0", "id": 32, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments":
            {"server": BACKEND, "tool": TOOL, "arguments": {"q": "a\u{0}b"}}}});
    let invoked = post_as_alpha(&gw.router, "/mcp", &body).await;
    assert!(
        !invoked.1.to_string().contains(NUL_REFUSAL),
        "X1 control: gateway_invoke lost the passthrough exemption: {invoked:?}"
    );
    assert_eq!(
        gw.dispatched(),
        1,
        "X1 control: not dispatched: {invoked:?}"
    );
}
