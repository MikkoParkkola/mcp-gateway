// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9216.EFFECT.1, the deferred lift: a managed-account replay defers and
//! is lifted after the live proof (every per-caller replay defers, E10), and
//! its record carries the effect of the slot the first execution ran under,
//! read now, never another slot's.

use super::*;

/// `TOOL` declaring `readOnlyHint: hint`, or no hint.
fn declared(hint: Option<bool>) -> crate::protocol::Tool {
    let mut tool = json!({
        "name": TOOL,
        "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}},
    });
    if let Some(hint) = hint {
        tool["annotations"] = json!({"readOnlyHint": hint});
    }
    serde_json::from_value(tool).expect("a tool")
}

/// The decisions of the invocation records in `fx`'s audit log, in order.
fn decisions(fx: &Fx) -> Vec<Value> {
    let dir = fx.audit.as_ref().expect("an audited fixture");
    std::fs::read_to_string(dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|entry| entry.get("decision").cloned())
        .collect()
}

/// The first execution ran on the operator's per-user slot. Before the
/// repeat, that slot declares `read` read-only and the shared slot declares
/// it may-write. The lifted replay records read-only: the stored slot's, not
/// the shared slot's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deferred_lift_records_the_stored_slot_effect() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let params = || invoke_params(Some("e1-lift"), false);
    let first = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let sent = fx.gateway.tool_calls().len();
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let operator = DirectAccountGateway::operator_binding();
    backend.declare_slot_effects_for_test(Some(&operator), vec![declared(Some(true))]);
    backend.declare_slot_effects_for_test(None, vec![declared(Some(false))]);
    let again = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: served: {again}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sent, "premise: not re-sent");
    let all = decisions(&fx);
    let last = all.last().expect("the replay's record");
    assert_eq!(last["decided"], "replayed", "{all:?}");
    assert_eq!(last["declared_effect"], "read_only", "{all:?}");
    assert_eq!(last["declared_effect_source"], "tool_annotation", "{all:?}");
}

/// Three slots, three declarations: the slot the first execution ran under
/// (read-only), the slot the lifting resolution selects now, after a grant
/// rotation (may-write), and the shared slot (no hint, undeclared). The
/// lifted replay records the first execution's slot, never the lift's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lift_after_a_rotation_records_the_first_executions_slot() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let params = || invoke_params(Some("e1-rotate"), false);
    let first = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let stored = DirectAccountGateway::operator_binding();
    fx.gateway.rotate_operator_grant().await;
    let now = fx
        .meta
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the rotated grant has a view");
    assert_ne!(now, stored, "premise: the rotation selects a new slot");
    fx.gateway.rearm_operator_slot_at_for_test(&now);
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    backend.declare_slot_effects_for_test(Some(&stored), vec![declared(Some(true))]);
    backend.declare_slot_effects_for_test(Some(&now), vec![declared(Some(false))]);
    backend.declare_slot_effects_for_test(None, vec![declared(None)]);
    let sent = fx.gateway.tool_calls().len();
    let again = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: served: {again}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sent, "premise: not re-sent");
    let all = decisions(&fx);
    let last = all.last().expect("the replay's record");
    assert_eq!(last["decided"], "replayed", "{all:?}");
    assert_eq!(last["declared_effect"], "read_only", "{all:?}");
    assert_eq!(last["declared_effect_source"], "tool_annotation", "{all:?}");
}

/// The first execution's per-user slot declares `read` read-only, then is
/// evicted; the shared slot declares it may-write. The repeat's own route
/// stage lists the caller's slot again before the lift (resolve.rs: the
/// resolution and its checks precede `lift_deferred`), re-filling the same
/// key from the fixture's listing, whose `read` carries no hint. The lifted
/// replay records that slot as it is now (undeclared): never the declaration
/// the evicted entry held, nor the shared slot's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lift_whose_stored_slot_was_evicted_reads_it_as_refilled() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let params = || invoke_params(Some("e1-evicted"), false);
    let first = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let operator = DirectAccountGateway::operator_binding();
    backend.declare_slot_effects_for_test(Some(&operator), vec![declared(Some(true))]);
    assert_eq!(
        backend.declared_effect_for(Some(&operator), TOOL),
        Some(crate::security::decision_record::Effect::ReadOnly),
        "premise: the stored slot declared read-only before the eviction"
    );
    // Removes the pooled slot itself (it panics if the slot is not pooled).
    backend.retire_per_user_slot_for_test(&operator);
    backend.forget_caller_slots_for_test();
    fx.gateway.rearm_operator_slot_for_test();
    backend.declare_slot_effects_for_test(None, vec![declared(Some(false))]);
    assert_eq!(
        backend.declared_effect_for(Some(&operator), TOOL),
        None,
        "premise: the stored slot is back cold"
    );
    let sent = fx.gateway.tool_calls().len();
    let again = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: served: {again}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sent, "premise: not re-sent");
    assert_eq!(
        backend.declared_effect_for(Some(&operator), TOOL),
        Some(crate::security::decision_record::Effect::Undeclared),
        "premise: the repeat re-filled the stored slot from the fixture's listing"
    );
    let all = decisions(&fx);
    let last = all.last().expect("the replay's record");
    assert_eq!(last["decided"], "replayed", "{all:?}");
    assert_eq!(last["declared_effect"], "undeclared", "{all:?}");
    assert_eq!(last["declared_effect_source"], "tool_annotation", "{all:?}");
}

/// After a grant rotation the old stored slot is evicted and never listed
/// again: the repeat lists only the slot the rotated grant selects. The
/// lifted replay looks the stored slot up as stored, finds nothing, and
/// records no effect, never the new slot's (may-write) or the shared
/// slot's (read-only).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lift_whose_stored_slot_stays_absent_after_a_rotation_records_none() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let params = || invoke_params(Some("e1-rotate-absent"), false);
    let first = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let stored = DirectAccountGateway::operator_binding();
    fx.gateway.rotate_operator_grant().await;
    let now = fx
        .meta
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the rotated grant has a view");
    assert_ne!(now, stored, "premise: the rotation selects a new slot");
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    backend.retire_per_user_slot_for_test(&stored);
    fx.gateway.rearm_operator_slot_at_for_test(&now);
    backend.declare_slot_effects_for_test(Some(&now), vec![declared(Some(false))]);
    backend.declare_slot_effects_for_test(None, vec![declared(Some(true))]);
    let sent = fx.gateway.tool_calls().len();
    let again = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        again.to_string().contains(MARKER),
        "premise: served: {again}"
    );
    assert_eq!(fx.gateway.tool_calls().len(), sent, "premise: not re-sent");
    assert!(
        backend
            .pooled_transport_for_test(&crate::backend::PoolKey::PerUser { binding: stored })
            .is_none(),
        "premise: the stored slot stayed absent"
    );
    let all = decisions(&fx);
    let last = all.last().expect("the replay's record");
    assert_eq!(last["decided"], "replayed", "{all:?}");
    assert!(last.get("declared_effect").is_none(), "{all:?}");
}
