// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), meta-layer call-path rows: a call on a
//! per-user backend is judged by the caller's own catalogue slot, never by
//! the shared one. A name the caller's catalogue does not offer (withheld or
//! lacked) answers exactly as a name the gateway does not know (-32601), and
//! nothing is dispatched (O1, O2).

use serde_json::{Value, json};

use super::slot_verdict_fixture::{
    CallerSlot, Surfaced, TOOL, Warmth, call_as_alpha, invalid, per_user, valid,
};
use crate::config::InputSchemaEnforcement;

const CLOSED: InputSchemaEnforcement = InputSchemaEnforcement::Closed;

/// alpha calls [`TOOL`] by its own name; returns the answer and the backend
/// `tools/call` count (alpha's upstream plus the shared one) the call added.
async fn by_name(slot: CallerSlot, enforcement: InputSchemaEnforcement) -> (Value, usize) {
    let fx = per_user(slot, &valid(), Warmth::Warm, enforcement, Surfaced::Yes);
    let before = fx.caller.calls() + fx.shared.calls();
    let answer = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    (answer, fx.caller.calls() + fx.shared.calls() - before)
}

/// The canonical absent answer: the same call where nothing surfaces [`TOOL`].
async fn unknown_name() -> Value {
    let fx = per_user(
        CallerSlot::Lacks,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::No,
    );
    call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await
}

/// C1 (withheld, lacked): a surfaced tool alpha's own catalogue withholds
/// (invalid schema) or lacks answers exactly as an unknown name, and is not
/// dispatched. RED on base: the shared slot (valid) decides, so it dispatches.
#[tokio::test]
async fn c1_per_user_caller_slot_withholds_by_name() {
    let absent = unknown_name().await;
    assert_eq!(
        absent.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: an unknown name answers -32601: {absent}"
    );
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let (answer, dispatched) = by_name(slot, CLOSED).await;
        assert_eq!(dispatched, 0, "C1 {slot:?}: dispatched; answer {answer}");
        assert_eq!(answer, absent, "C1 {slot:?}: {answer} vs unknown {absent}");
    }
}

/// C2: a tool alpha's complete catalogue lacks never answers with text A
/// ("the backend does not list a tool named ..."), which confirms some
/// catalogue has the name. RED on base: the F13 miss answers text A.
#[tokio::test]
async fn c2_per_user_lacked_is_not_text_a() {
    let (answer, _) = by_name(CallerSlot::Lacks, CLOSED).await;
    assert!(
        !answer.to_string().contains("does not list a tool named"),
        "C2: text A reached the caller: {answer}"
    );
}

/// C4 (withheld, lacked): the same through `gateway_invoke`. Its absent twin
/// names the tool on the same server where nothing surfaces it.
#[tokio::test]
async fn c4_per_user_caller_slot_withholds_via_gateway_invoke() {
    let args = json!({"server": super::slot_verdict_fixture::BACKEND, "tool": TOOL, "arguments": {"q": "x"}});
    let control = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::No,
    );
    let _ = call_as_alpha(&control.meta, "gateway_invoke", args.clone()).await;
    assert_eq!(
        control.caller.calls(),
        1,
        "premise: alpha's valid tool is not dispatched"
    );
    let mut answers = Vec::new();
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Warm, CLOSED, Surfaced::No);
        let answer = call_as_alpha(&fx.meta, "gateway_invoke", args.clone()).await;
        assert_eq!(
            fx.caller.calls() + fx.shared.calls(),
            0,
            "C4 {slot:?}: dispatched; {answer}"
        );
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32601)),
            "C4 {slot:?}: {answer}"
        );
        answers.push(answer);
    }
    assert_eq!(answers[0], answers[1], "C4: withheld vs lacked differ");
}

/// C7: alpha's slot is cold, its own schema valid and the shared one invalid.
/// The call fills alpha's slot once and dispatches. RED on base: the shared
/// slot (invalid) withholds the tool.
#[tokio::test]
async fn c7_per_user_cold_caller_first_call_dispatches_on_own_slot() {
    let fx = per_user(
        CallerSlot::Valid,
        &invalid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let (lists, calls) = (fx.caller.lists(), fx.caller.calls());
    let answer = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(fx.caller.calls(), calls + 1, "C7: not dispatched: {answer}");
    assert_eq!(
        fx.caller.lists(),
        lists + 1,
        "C7: alpha's slot not filled once"
    );
}

/// C8 (guard, kills M12): alpha's slot is cold and its upstream refuses
/// `tools/list`. The call answers as a failed backend, never as an unknown
/// name, and dispatches nothing. Green on base, where the dispatch's own F13
/// fill (as the caller) already answers a failed fill as a failed dispatch;
/// the guard keeps the new verdict from answering it -32601.
#[tokio::test]
async fn c8_per_user_cold_fill_failure_is_not_an_unknown_name() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::ColdFailing,
        CLOSED,
        Surfaced::Yes,
    );
    let answer = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(
        fx.caller.calls() + fx.shared.calls(),
        0,
        "C8: dispatched: {answer}"
    );
    assert_ne!(
        answer.pointer("/error/code"),
        Some(&json!(-32601)),
        "C8: answered as unknown: {answer}"
    );
}

/// C10: with argument-key enforcement Off, the caller-slot verdict still
/// runs. RED on base, as C1.
#[tokio::test]
async fn c10_per_user_visibility_runs_with_enforcement_off() {
    let absent = unknown_name().await;
    let (answer, dispatched) = by_name(CallerSlot::Invalid, InputSchemaEnforcement::Off).await;
    assert_eq!(dispatched, 0, "C10: dispatched; answer {answer}");
    assert_eq!(answer, absent, "C10: {answer} vs unknown {absent}");
}

/// C11 (guard, kills M03): a warm caller-valid call resolves alpha's
/// credential exactly once across the verdict and the dispatch.
#[tokio::test]
async fn c11_per_user_one_resolution_per_call() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let before = fx.mints();
    let answer = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(fx.caller.calls(), 1, "premise: not dispatched: {answer}");
    assert_eq!(fx.mints(), before + 1, "C11: resolutions for one call");
}

/// C14 (guard, lead ruling 2026-10-11; design R5.2 step 0): a policy-withheld
/// `gateway_invoke` target on a per-user backend resolves no credential and
/// fills no slot, even with alpha's slot cold. Its answer shape (-32601) is
/// MIK-8361's gate; this row pins only MIK-8356's half: zero fills, zero
/// resolutions. Kills a `caller_verdict` that fills before judging policy.
#[tokio::test]
async fn c14_policy_withheld_invoke_target_fills_and_resolves_nothing() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::No,
    );
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let deny = crate::gateway::authz::DenyOne { tool: TOOL };
    let caller = super::MetaMcpCallerContext {
        authorizer: &deny,
        ..super::identified_caller(&alpha)
    };
    let (lists, mints) = (fx.caller.lists() + fx.shared.lists(), fx.mints());
    let args = json!({"server": super::slot_verdict_fixture::BACKEND, "tool": TOOL, "arguments": {"q": "x"}});
    let response = Box::pin(fx.meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        "gateway_invoke",
        args,
        None,
        caller,
    ))
    .await;
    let answer = serde_json::to_value(&response).expect("a response serialises");
    assert!(
        answer.get("error").is_some() || answer.pointer("/result/isError") == Some(&json!(true)),
        "premise: the policy-withheld target is not refused: {answer}"
    );
    assert_eq!(
        fx.caller.calls() + fx.shared.calls(),
        0,
        "C14: dispatched: {answer}"
    );
    assert_eq!(
        fx.caller.lists() + fx.shared.lists(),
        lists,
        "C14: a slot was filled"
    );
    assert_eq!(fx.mints(), mints, "C14: a credential was resolved");
}

/// A one-step `gateway_execute` chain naming [`TOOL`] on `BACKEND`, as alpha.
async fn chain_step_as_alpha(meta: &super::MetaMcp) -> Value {
    let step = format!("{}:{TOOL}", super::slot_verdict_fixture::BACKEND);
    call_as_alpha(
        meta,
        "gateway_execute",
        json!({"chain": [{"tool": step, "arguments": {"q": "x"}}]}),
    )
    .await
}

/// C5 (withheld, lacked): a `gateway_execute` chain step naming a tool
/// alpha's own catalogue withholds or lacks answers -32601, the same for
/// both, and is not dispatched. RED on base: the withheld step dispatches on
/// the shared slot's verdict, and `step_failure` rewrites a -32601 to -32603
/// (`chain_exec.rs:250`).
#[tokio::test]
async fn c5_chain_step_caller_slot_withholds() {
    let mut answers = Vec::new();
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Warm, CLOSED, Surfaced::No);
        let answer = chain_step_as_alpha(&fx.meta).await;
        assert_eq!(
            fx.caller.calls() + fx.shared.calls(),
            0,
            "C5 {slot:?}: dispatched; {answer}"
        );
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32601)),
            "C5 {slot:?}: {answer}"
        );
        answers.push(answer);
    }
    assert_eq!(answers[0], answers[1], "C5: withheld vs lacked differ");
}

/// C7b (guard, kills M14): a call on alpha's warm slot fetches no catalogue;
/// a held answer needs no `tools/list`.
#[tokio::test]
async fn c7b_per_user_warm_verdict_fetches_nothing() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let lists = fx.caller.lists() + fx.shared.lists();
    let answer = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(fx.caller.calls(), 1, "premise: not dispatched: {answer}");
    assert_eq!(
        fx.caller.lists() + fx.shared.lists(),
        lists,
        "C7b: a warm call listed"
    );
}

/// C11b (guard, kills M15): two chain steps to the same backend resolve
/// alpha's credential once each: a resolution carried to dispatch is used by
/// one invocation, never reused by the next.
#[tokio::test]
async fn c11b_second_step_same_server_resolves_again() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::No,
    );
    let step = format!("{}:{TOOL}", super::slot_verdict_fixture::BACKEND);
    let before = fx.mints();
    let answer = call_as_alpha(
        &fx.meta,
        "gateway_execute",
        json!({"chain": [
            {"tool": step, "arguments": {"q": "x"}},
            {"tool": step, "arguments": {"q": "y"}}
        ]}),
    )
    .await;
    assert_eq!(
        fx.caller.calls(),
        2,
        "premise: both steps not dispatched: {answer}"
    );
    assert_eq!(fx.mints(), before + 2, "C11b: resolutions for two steps");
}

/// L9-call (lead ruling 2026-10-11, design R3.7): an anonymous caller on a
/// `required` per-user backend has no principal, so no slot can hold its
/// catalogue: it lacks every tool there. A call by surfaced name and through
/// `gateway_invoke` answers as a name the gateway does not know (-32601),
/// with no credential resolved, no slot filled and nothing dispatched. RED
/// before the ruling's fix: the call fails credential resolution with a
/// refusal that names the backend.
#[tokio::test]
async fn l9_call_anonymous_on_required_backend_answers_as_absent() {
    let backend = super::slot_verdict_fixture::BACKEND;
    let invoke = json!({"server": backend, "tool": TOOL, "arguments": {"q": "x"}});
    for (name, args) in [(TOOL, json!({"q": "x"})), ("gateway_invoke", invoke)] {
        let fx = per_user(
            CallerSlot::Valid,
            &valid(),
            Warmth::Warm,
            CLOSED,
            Surfaced::Yes,
        );
        let (mints, lists) = (fx.mints(), fx.caller.lists() + fx.shared.lists());
        let answer = anonymous_call(&fx.meta, name, args).await;
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32601)),
            "L9-call {name}: not answered as absent: {answer}"
        );
        assert_eq!(
            fx.caller.calls() + fx.shared.calls(),
            0,
            "L9-call {name}: dispatched"
        );
        assert_eq!(
            fx.mints(),
            mints,
            "L9-call {name}: a credential was resolved"
        );
        assert_eq!(
            fx.caller.lists() + fx.shared.lists(),
            lists,
            "L9-call {name}: a slot was filled"
        );
    }
    // By surfaced name, byte-identical to the same call where nothing
    // surfaces the tool.
    let twin = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::No,
    );
    let absent = anonymous_call(&twin.meta, TOOL, json!({"q": "x"})).await;
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let answer = anonymous_call(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(
        answer, absent,
        "L9-call by name: {answer} vs absent {absent}"
    );
}

/// `name` called by an anonymous caller.
async fn anonymous_call(meta: &super::MetaMcp, name: &str, arguments: Value) -> Value {
    let response = Box::pin(meta.handle_tools_call(
        crate::protocol::RequestId::Number(1),
        name,
        arguments,
        None,
        super::anonymous_caller(),
    ))
    .await;
    serde_json::to_value(&response).expect("a response serialises")
}
