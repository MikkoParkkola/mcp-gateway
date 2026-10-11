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
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BACKEND, CallerSlot, Surfaced, TOOL, Warmth, valid,
};

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
