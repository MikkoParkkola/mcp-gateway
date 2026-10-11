// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3 (final), meta-layer call-path rows: a call on a
//! per-user backend is judged by the caller's own catalogue slot, never by
//! the shared one. A name the caller's catalogue does not offer (withheld or
//! lacked) answers exactly as a name the gateway does not know (-32601), and
//! nothing is dispatched (O1, O2).

use serde_json::{Value, json};

use super::slot_verdict_fixture::{
    CallerSlot, Surfaced, TOOL, Warmth, call_as_alpha, indexed_binding_for, invalid, per_user,
    valid,
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
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let listed = disabled_as_alpha(&fx.meta);
    assert!(
        !names_tool(&listed),
        "L6a: a cold caller is named the tool: {listed}"
    );
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
    assert_eq!(
        totals[1], totals[2],
        "L3c: withheld vs lacked counts differ"
    );
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
        let count = listed.to_string().contains("\"tools_count\":1");
        counts.push((count, listed));
    }
    assert!(
        !counts[0].0,
        "premise: alpha's valid catalogue counts 2: {}",
        counts[0].1
    );
    assert!(
        counts[1].0,
        "L3d Invalid: the withheld tool is counted: {}",
        counts[1].1
    );
    assert!(counts[2].0, "L3d Lacks: {}", counts[2].1);
}

/// The surfaced [`TOOL`] entry in alpha's plain `tools/list`, if listed.
fn surfaced_entry_for_alpha(meta: &super::MetaMcp) -> Option<Value> {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let response = meta.handle_tools_list_for_session(
        crate::protocol::RequestId::Number(1),
        None,
        super::identified_caller(&alpha).scope(),
    );
    let body = serde_json::to_value(&response).expect("a response serialises");
    body.pointer("/result/tools")?
        .as_array()?
        .iter()
        .find(|t| t["name"] == TOOL)
        .cloned()
}

/// L3a (SLOTVIS.3, surfaced list), on a single-user gateway: with alpha's
/// slot warm, the surfaced [`TOOL`] in alpha's `tools/list` is alpha's own
/// Tool. The shared slot holds a DIFFERENT valid schema, so the bytes tell
/// which slot it came from. A tool alpha's catalogue withholds is not listed,
/// exactly as one it lacks. RED on base (measured 2026-10-11): single-user
/// `tools/list` lists the shared Tool (`resolve_surfaced_tool`).
#[tokio::test]
async fn l3a_surfaced_list_takes_the_callers_tool() {
    let shared = json!({"type": "object", "properties": {"z": {"type": "integer"}}});
    let fx = per_user(
        CallerSlot::Valid,
        &shared,
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    fx.meta.set_multi_user(false);
    warm_by_listing(&fx.meta).await;
    let listed =
        surfaced_entry_for_alpha(&fx.meta).expect("premise: alpha's valid tool is not listed");
    assert_eq!(
        listed["inputSchema"],
        valid(),
        "L3a: not alpha's schema: {listed}"
    );
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &shared, Warmth::Cold, CLOSED, Surfaced::Yes);
        fx.meta.set_multi_user(false);
        warm_by_listing(&fx.meta).await;
        assert_eq!(
            surfaced_entry_for_alpha(&fx.meta),
            None,
            "L3a {slot:?}: listed"
        );
    }
}

/// L3a-multi (guard): on a multi-user gateway an isolated per-user backend's
/// surfaced tool is omitted from `tools/list` altogether (INV-2,
/// `meta_route_isolation_refused`), whatever alpha's slot holds. Green on
/// base; kills a change that lets the caller-slot path bypass INV-2.
#[tokio::test]
async fn l3a_multi_user_keeps_the_isolated_surfaced_tool_out() {
    for slot in [CallerSlot::Valid, CallerSlot::Invalid] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        assert_eq!(
            surfaced_entry_for_alpha(&fx.meta),
            None,
            "L3a-multi {slot:?}: listed"
        );
    }
}

/// L6b (SLOTVIS.6 listing clause): alpha's slot was warm and has been
/// evicted, so it is cold again and the disabled list withholds that
/// backend's tools from alpha. RED on base: the shared slot names it.
#[tokio::test]
async fn l6b_evicted_caller_disabled_list_withholds() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.evict_idle_per_user_entries(std::time::Duration::ZERO) >= 1,
        "premise: alpha's slot was not evicted"
    );
    let listed = disabled_as_alpha(&fx.meta);
    assert!(
        !names_tool(&listed),
        "L6b: an evicted caller is named the tool: {listed}"
    );
}

/// The binding the caller-slot index holds for alpha on `BACKEND`.
fn indexed_binding_for_alpha(meta: &super::MetaMcp) -> Option<String> {
    indexed_binding_for(meta, "alpha")
}

/// I2a (index write site: catalogue fill; asked by MIK-8350): after ONLY a
/// `gateway_list_tools` fill of alpha's slot, the index names alpha's slot.
/// Red-by-absence: nothing writes the index yet (the read API is a stub).
#[tokio::test]
async fn i2a_index_written_by_catalogue_fill() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta),
        None,
        "premise: indexed before any fill"
    );
    warm_by_listing(&fx.meta).await;
    assert_eq!(fx.caller.lists(), 1, "premise: alpha's slot was not filled");
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I2a: the catalogue fill wrote no index entry"
    );
}

/// I2c (index write site: F13 fill): after ONLY a cold call's F13 fill
/// (argument-key enforcement on), the index names alpha's slot. Red-by-absence.
#[tokio::test]
async fn i2c_index_written_by_f13_fill() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(
        fx.caller.lists(),
        1,
        "premise: the call did not fill alpha's slot"
    );
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I2c: the F13 fill wrote no index entry"
    );
}

/// I2d (index write site: the caller verdict's own fill on the dispatch path,
/// kimi r2 F2; asked by MIK-8350): a call-first caller with argument-key
/// enforcement Off, where F13 does not fill. After that call alone the index
/// names alpha's slot. Red-by-absence: on base nothing fills here at all.
#[tokio::test]
async fn i2d_index_written_by_dispatch_fill() {
    let off = InputSchemaEnforcement::Off;
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        off,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I2d: the dispatch-path fill wrote no index entry (lists: {})",
        fx.caller.lists()
    );
}

/// I3b (asked by MIK-8350 AC2): revoking alpha's grant
/// (`evict_identity_slots` on alpha's binding prefix) removes alpha's index
/// entry, and beta's entry under another prefix survives. The premise that
/// both are indexed first is what makes this red on the stub: `None` after
/// the revocation alone would pass trivially. Red-by-absence.
#[tokio::test]
async fn i3b_index_entry_removed_on_grant_revocation() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let _beta_upstream = super::slot_verdict_fixture::add_caller(&fx.meta, "beta", &valid());
    warm_by_listing(&fx.meta).await;
    let beta = super::catalogue_per_caller_tests::identity("beta");
    fx.meta
        .list_tools(
            &json!({"server": super::slot_verdict_fixture::BACKEND}),
            None,
            &super::identified_caller(&beta),
        )
        .await
        .expect("beta lists");
    assert_eq!(
        indexed_binding_for(&fx.meta, "alpha").as_deref(),
        Some("alpha@ledger"),
        "I3b premise: alpha is not indexed"
    );
    assert_eq!(
        indexed_binding_for(&fx.meta, "beta").as_deref(),
        Some("beta@ledger"),
        "I3b premise: beta is not indexed"
    );
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.evict_identity_slots("alpha@") >= 1,
        "premise: alpha's slot not evicted"
    );
    assert_eq!(
        indexed_binding_for(&fx.meta, "alpha"),
        None,
        "I3b: alpha still indexed"
    );
    assert_eq!(
        indexed_binding_for(&fx.meta, "beta").as_deref(),
        Some("beta@ledger"),
        "I3b: beta's entry was removed with alpha's"
    );
}

/// The I2e invariant: every per-user slot whose catalogue has ever been
/// stored is pointed at by the index. A fill site that stores without
/// recording fails here. (After the implementation lands it runs at the end
/// of every row; on the stub it would turn the guards red, so for now it is
/// its own row.)
fn assert_index_covers_populated_slots(meta: &super::MetaMcp, row: &str) {
    let backend = meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    let populated = backend.populated_per_user_bindings_for_test();
    let indexed = backend.indexed_bindings_for_test();
    let missing: Vec<_> = populated.iter().filter(|b| !indexed.contains(b)).collect();
    assert!(
        missing.is_empty(),
        "{row}: populated per-user slots with no index entry: {missing:?}"
    );
}

/// I2e (asked by MIK-8350): every fill path a test drives leaves the index
/// covering the slot it filled. One gateway drives the catalogue fill
/// (alpha) and a cold call's F13 fill (beta); a second gateway drives the
/// dispatch-path fill with enforcement Off (alpha again). Red-by-absence on
/// the stub, from the first half; the second half holds vacuously on base,
/// where nothing fills with enforcement Off.
#[tokio::test]
async fn i2e_index_covers_every_populated_slot() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let _beta_upstream = super::slot_verdict_fixture::add_caller(&fx.meta, "beta", &valid());
    let beta = super::catalogue_per_caller_tests::identity("beta");
    let _ = Box::pin(fx.meta.handle_tools_call(
        crate::protocol::RequestId::Number(2),
        TOOL,
        json!({"q": "x"}),
        None,
        super::identified_caller(&beta),
    ))
    .await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.populated_per_user_bindings_for_test().len() >= 2,
        "premise: alpha's and beta's slots are not both populated: {:?}",
        backend.populated_per_user_bindings_for_test()
    );
    assert_index_covers_populated_slots(&fx.meta, "I2e (catalogue + F13)");

    let off = InputSchemaEnforcement::Off;
    let gx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        off,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&gx.meta, TOOL, json!({"q": "x"})).await;
    assert_index_covers_populated_slots(&gx.meta, "I2e (dispatch-path fill)");
}

/// [`TOOL`] disabled, then the disabled list as `caller` sees it.
fn disabled_for(meta: &super::MetaMcp, caller: &super::MetaMcpCallerContext<'_>) -> Value {
    let cfg = meta.capability_budget_config.read().clone();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        meta.kill_switch.record_capability_failure(
            super::slot_verdict_fixture::BACKEND,
            TOOL,
            &cfg,
        );
    }
    meta.list_disabled_capabilities(caller.scope(), None)
        .expect("the disabled list answers")
}

/// L5 (SLOTVIS.5, parity): with alpha's slot warm, the disabled list and the
/// predictions answer byte-identically whether alpha's catalogue withholds
/// [`TOOL`] (invalid schema) or lacks it. RED on base: the withheld case
/// answers from the shared slot and names the tool.
#[tokio::test]
async fn l5_withheld_answers_exactly_as_lacked() {
    let mut answers = Vec::new();
    for slot in [CallerSlot::Invalid, CallerSlot::Lacks] {
        let fx = per_user(slot, &valid(), Warmth::Cold, CLOSED, Surfaced::Yes);
        warm_by_listing(&fx.meta).await;
        let disabled = disabled_as_alpha(&fx.meta);
        let predicted = predictions_for_alpha(&fx.meta);
        answers.push((disabled, predicted));
    }
    assert_eq!(
        answers[0].0, answers[1].0,
        "L5: disabled list, withheld vs lacked"
    );
    assert_eq!(
        answers[0].1, answers[1].1,
        "L5: predictions, withheld vs lacked"
    );
    // Equal is not enough: on base both answer from the shared slot and name
    // the tool alike. SLOTVIS.5 also says neither names it.
    assert!(
        !names_tool(&answers[0].0),
        "L5: the disabled list names the tool: {}",
        answers[0].0
    );
    assert!(
        !predicts_tool(&answers[0].1),
        "L5: the tool is predicted: {:?}",
        answers[0].1
    );
}

/// L10: two callers on one per-user backend: alpha's catalogue holds
/// [`TOOL`] with an invalid schema, beta's with a valid one, the shared slot
/// valid. alpha is not named the disabled tool; beta is. Neither's entry ever
/// answers for the other. RED on base: alpha is named (the shared slot).
#[tokio::test]
async fn l10_two_callers_judged_each_by_their_own_slot() {
    let fx = per_user(
        CallerSlot::Invalid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    let _beta_upstream = super::slot_verdict_fixture::add_caller(&fx.meta, "beta", &valid());
    warm_by_listing(&fx.meta).await;
    let beta = super::catalogue_per_caller_tests::identity("beta");
    fx.meta
        .list_tools(
            &json!({"server": super::slot_verdict_fixture::BACKEND}),
            None,
            &super::identified_caller(&beta),
        )
        .await
        .expect("beta lists");
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let for_beta = disabled_for(&fx.meta, &super::identified_caller(&beta));
    assert!(
        names_tool(&for_beta),
        "premise: beta's valid tool is not named: {for_beta}"
    );
    let for_alpha = disabled_for(&fx.meta, &super::identified_caller(&alpha));
    assert!(
        !names_tool(&for_alpha),
        "L10: alpha is named a tool its slot withholds: {for_alpha}"
    );
}

/// L9 (case 1, kimi r2 F1): an anonymous caller has no view of a `required`
/// per-user backend, so none of its tools reaches it through the disabled
/// list or the counts. RED on base (measured 2026-10-11): both answer from
/// the shared slot (named; "2 tools").
#[tokio::test]
async fn l9_required_backend_anonymous_caller_sees_none() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let anonymous = super::anonymous_caller();
    let disabled = disabled_for(&fx.meta, &anonymous);
    assert!(
        !names_tool(&disabled),
        "L9: anonymous is named the tool: {disabled}"
    );
    let (total, _) = fx.meta.admitted_counts(anonymous.scope(), None);
    let counted = total.phrase();
    assert!(
        !counted.starts_with('2'),
        "L9: anonymous is counted the tools: {counted}"
    );
}

/// L9-servers (guard): `list_servers` already hides a `required` per-user
/// backend's tools from an anonymous caller (`has_no_view_for`,
/// `tools_count` 0, `tools_known` false). Green on base; keeps the caller-slot
/// change from reopening it.
#[tokio::test]
async fn l9_servers_keep_the_required_backend_hidden() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Warm,
        CLOSED,
        Surfaced::Yes,
    );
    let servers = fx
        .meta
        .list_servers(&super::anonymous_caller(), None)
        .await
        .expect("list_servers answers")
        .to_string();
    assert!(
        servers.contains("\"tools_count\":0") && servers.contains("\"tools_known\":false"),
        "L9-servers: {servers}"
    );
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

/// L11a: alpha's slot holds a TRUNCATED list (a paging drain past its
/// budget) that lacks [`TOOL`]. A partial list proves nothing about an unseen
/// name, so the count alpha is given is a lower bound ("at least"), never an
/// exact total. RED on base: counts walk the shared snapshot and report an
/// exact "2 tools".
#[tokio::test]
async fn l11a_truncated_caller_slot_counts_at_least() {
    let alpha = super::catalogue_per_caller_tests::identity("alpha");
    let fx = per_user(
        CallerSlot::Lacks,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    backend.mark_per_user_truncated_for_test(super::slot_verdict_fixture::BINDING);
    let (total, _) = fx
        .meta
        .admitted_counts(super::identified_caller(&alpha).scope(), None);
    let phrase = total.phrase();
    assert!(
        phrase.starts_with("at least"),
        "L11a: a truncated caller slot gave an exact count: {phrase}"
    );
}

/// L11b: alpha's slot is filled but empty (a complete list with no tools).
/// The disabled list then names none of that backend's tools to alpha. RED
/// on base: the shared slot names [`TOOL`].
#[tokio::test]
async fn l11b_empty_caller_slot_withholds() {
    let fx = per_user(
        CallerSlot::Lacks,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    backend.store_per_user_tools_for_test(super::slot_verdict_fixture::BINDING, Vec::new());
    let listed = disabled_as_alpha(&fx.meta);
    assert!(
        !names_tool(&listed),
        "L11b: an empty caller slot named the tool: {listed}"
    );
}

/// I3 (idle eviction): once alpha's slot is idle-evicted, the index no longer
/// names it. The premise (indexed first) makes this red on the stub.
/// Red-by-absence.
#[tokio::test]
async fn i3_index_entry_removed_on_idle_eviction() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::Cold,
        CLOSED,
        Surfaced::Yes,
    );
    warm_by_listing(&fx.meta).await;
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta).as_deref(),
        Some(super::slot_verdict_fixture::BINDING),
        "I3 premise: alpha is not indexed"
    );
    let backend = fx
        .meta
        .backends
        .get(super::slot_verdict_fixture::BACKEND)
        .expect("the backend");
    assert!(
        backend.evict_idle_per_user_entries(std::time::Duration::ZERO) >= 1,
        "premise: alpha's slot was not evicted"
    );
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta),
        None,
        "I3: still indexed"
    );
}

/// I1 (guard, design R3.5, gpt F7): a fill that fails stores nothing, so it
/// writes no index entry. Green on the stub trivially; after the
/// implementation it kills an index written at credential resolution
/// instead of at the slot store (the r2 design gpt rejected).
#[tokio::test]
async fn i1_failed_fill_writes_no_index_entry() {
    let fx = per_user(
        CallerSlot::Valid,
        &valid(),
        Warmth::ColdFailing,
        CLOSED,
        Surfaced::Yes,
    );
    let _ = call_as_alpha(&fx.meta, TOOL, json!({"q": "x"})).await;
    assert!(fx.caller.lists() >= 1, "premise: no fill was attempted");
    assert_eq!(
        indexed_binding_for_alpha(&fx.meta),
        None,
        "I1: a failed fill was indexed"
    );
}
