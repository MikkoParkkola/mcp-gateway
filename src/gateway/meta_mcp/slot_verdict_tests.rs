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
