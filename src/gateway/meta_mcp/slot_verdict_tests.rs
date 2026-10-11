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
    let fx = per_user(CallerSlot::Lacks, &valid(), Warmth::Warm, CLOSED, Surfaced::No);
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
    let control = per_user(CallerSlot::Valid, &valid(), Warmth::Warm, CLOSED, Surfaced::No);
    let _ = call_as_alpha(&control.meta, "gateway_invoke", args.clone()).await;
    assert_eq!(control.caller.calls(), 1, "premise: alpha's valid tool is not dispatched");
    let mut answers = Vec::new();
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Warm, CLOSED, Surfaced::No);
        let answer = call_as_alpha(&fx.meta, "gateway_invoke", args.clone()).await;
        assert_eq!(fx.caller.calls() + fx.shared.calls(), 0, "C4 {slot:?}: dispatched; {answer}");
        assert_eq!(answer.pointer("/error/code"), Some(&json!(-32601)), "C4 {slot:?}: {answer}");
        answers.push(answer);
    }
    assert_eq!(answers[0], answers[1], "C4: withheld vs lacked differ");
}

/// C7: alpha's slot is cold, its own schema valid and the shared one invalid.
/// The call fills alpha's slot once and dispatches. RED on base: the shared
/// slot (invalid) withholds the tool.
#[tokio::test]
async fn c7_per_user_cold_caller_first_call_dispatches_on_own_slot() {
    let fx = per_user(CallerSlot::Valid, &invalid(), Warmth::Cold, CLOSED, Surfaced::Yes);
    let (lists, calls) = (fx.caller.lists(), fx.caller.calls());
    let answer = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(fx.caller.calls(), calls + 1, "C7: not dispatched: {answer}");
    assert_eq!(fx.caller.lists(), lists + 1, "C7: alpha's slot not filled once");
}

/// C8 (guard, kills M12): alpha's slot is cold and its upstream refuses
/// `tools/list`. The call answers as a failed backend, never as an unknown
/// name, and dispatches nothing. Green on base, where the dispatch's own F13
/// fill (as the caller) already answers a failed fill as a failed dispatch;
/// the guard keeps the new verdict from answering it -32601.
#[tokio::test]
async fn c8_per_user_cold_fill_failure_is_not_an_unknown_name() {
    let fx = per_user(CallerSlot::Valid, &valid(), Warmth::ColdFailing, CLOSED, Surfaced::Yes);
    let answer = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(fx.caller.calls() + fx.shared.calls(), 0, "C8: dispatched: {answer}");
    assert_ne!(answer.pointer("/error/code"), Some(&json!(-32601)), "C8: answered as unknown: {answer}");
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
    let fx = per_user(CallerSlot::Valid, &valid(), Warmth::Warm, CLOSED, Surfaced::Yes);
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
    let fx = per_user(CallerSlot::Valid, &valid(), Warmth::Cold, CLOSED, Surfaced::No);
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
    assert!(answer.get("error").is_some() || answer.pointer("/result/isError") == Some(&json!(true)),
        "premise: the policy-withheld target is not refused: {answer}");
    assert_eq!(fx.caller.calls() + fx.shared.calls(), 0, "C14: dispatched: {answer}");
    assert_eq!(fx.caller.lists() + fx.shared.lists(), lists, "C14: a slot was filled");
    assert_eq!(fx.mints(), mints, "C14: a credential was resolved");
}

/// alpha lists `BACKEND` through `gateway_list_tools`: a real fill of alpha's
/// own slot, the way a caller's slot becomes warm (and indexed).
async fn warm_by_listing(meta: &super::MetaMcp) {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    meta.list_tools(
        &json!({"server": super::slot_verdict_fixture::BACKEND}),
        None,
        &super::identified_caller(&alpha),
    )
    .await
    .expect("gateway_list_tools answers");
}

/// The disabled-capability list as alpha sees it, with [`TOOL`] disabled.
fn disabled_as_alpha(meta: &super::MetaMcp) -> Value {
    let cfg = meta.capability_budget_config.read().clone();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        meta.kill_switch.record_capability_failure(
            super::slot_verdict_fixture::BACKEND,
            TOOL,
            &cfg,
        );
    }
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    meta.list_disabled_capabilities(super::identified_caller(&alpha).scope(), None)
        .expect("the disabled list answers")
}

fn names_tool(listed: &Value) -> bool {
    listed["disabled_capabilities"]
        .as_array()
        .is_some_and(|all| all.iter().any(|e| e["capability"] == TOOL))
}

/// L1 (SLOTVIS.1): with alpha's slot warm, a disabled tool alpha's own
/// catalogue withholds or lacks is not named; alpha's valid one is. RED on
/// base: the disabled list judges the shared slot (valid).
#[tokio::test]
async fn l1_disabled_list_judges_the_callers_slot() {
    for (slot, named) in [
        (CallerSlot::Valid, true),
        (CallerSlot::Invalid, false),
        (CallerSlot::Lacks, false),
    ] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let listed = disabled_as_alpha(&fx.meta);
        assert_eq!(names_tool(&listed), named, "L1 {slot:?}: {listed}");
    }
}

/// L6a (SLOTVIS.6 listing clause): alpha's slot is cold (never listed), so
/// the disabled list withholds that backend's tools from alpha, even one its
/// own catalogue would offer. RED on base: the shared slot names it.
#[tokio::test]
async fn l6a_cold_caller_disabled_list_withholds() {
    let fx = per_user(CallerSlot::Valid, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
    let listed = disabled_as_alpha(&fx.meta);
    assert!(!names_tool(&listed), "L6a: a cold caller is named the tool: {listed}");
}

/// L3c (SLOTVIS.3, counts): with alpha's slot warm, the backend count alpha
/// is given leaves out a tool alpha's catalogue withholds, exactly as one it
/// lacks; alpha's valid tool is counted. RED on base: counts walk the
/// shared snapshot.
#[tokio::test]
async fn l3c_counts_use_the_callers_slot() {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let mut totals = Vec::new();
    for slot in [CallerSlot::Valid, CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let (total, _) = fx
            .meta
            .admitted_counts(super::identified_caller(&alpha).scope(), None);
        totals.push(total.phrase());
    }
    assert_eq!(totals[1], totals[2], "L3c: withheld vs lacked counts differ");
    assert_ne!(totals[0], totals[1], "L3c: the withheld tool is counted");
}

/// The next-tool predictions alpha is given after `ledger_hub:note`, once
/// another session has taught the shared tracker that `read` follows it.
fn predictions_for_alpha(meta: &super::MetaMcp) -> Vec<Value> {
    let tracker = std::sync::Arc::new(crate::transition::TransitionTracker::new());
    meta.set_transition_tracker(std::sync::Arc::clone(&tracker));
    let (from, to) = ("ledger_hub:note", "ledger_hub:read");
    for _ in 0..8 {
        tracker.record_transition("teacher", from);
        tracker.record_transition("teacher", to);
    }
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    meta.record_and_predict(
        None,
        Some("alpha-session"),
        from,
        super::identified_caller(&alpha).scope(),
    )
}

fn predicts_tool(predicted: &[Value]) -> bool {
    predicted.iter().any(|p| p["tool"] == "ledger_hub:read")
}

/// L2 (SLOTVIS.2): with alpha's slot warm, a predicted tool alpha's own
/// catalogue withholds or lacks is not predicted to alpha; alpha's valid one
/// is. RED on base: predictions judge the shared slot.
#[tokio::test]
async fn l2_predictions_judge_the_callers_slot() {
    for (slot, predicted) in [
        (CallerSlot::Valid, true),
        (CallerSlot::Invalid, false),
        (CallerSlot::Lacks, false),
    ] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let got = predictions_for_alpha(&fx.meta);
        assert_eq!(predicts_tool(&got), predicted, "L2 {slot:?}: {got:?}");
    }
}

/// L3d (SLOTVIS.3, `list_servers`): with alpha's slot warm, the per-backend
/// `tools_count` alpha is given leaves out a tool its catalogue withholds,
/// exactly as one it lacks; alpha's valid tool is counted. RED on base:
/// `list_servers` walks the shared snapshot (`surfaced.rs:234`).
#[tokio::test]
async fn l3d_list_servers_counts_the_callers_slot() {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let mut counts = Vec::new();
    for slot in [CallerSlot::Valid, CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let listed = fx
            .meta
            .list_servers(&super::identified_caller(&alpha), None)
            .await
            .expect("list_servers answers");
        let count = listed
            .to_string()
            .contains("\"tools_count\":1");
        counts.push((count, listed));
    }
    assert!(!counts[0].0, "premise: alpha's valid catalogue counts 2: {}", counts[0].1);
    assert!(counts[1].0, "L3d Invalid: the withheld tool is counted: {}", counts[1].1);
    assert!(counts[2].0, "L3d Lacks: {}", counts[2].1);
}
