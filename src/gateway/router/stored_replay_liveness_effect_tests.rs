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

/// The first execution's per-user slot is evicted after settle and comes
/// back cold for the lift, while the shared slot declares `read` read-only:
/// the lifted replay records no effect, never the shared slot's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lift_whose_stored_slot_was_evicted_records_none() {
    let fx = fixture_with(false, true).await;
    answer_marker(&fx);
    let params = || invoke_params(Some("e1-evicted"), false);
    let first = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(
        first.to_string().contains(MARKER),
        "premise: dispatched: {first}"
    );
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    backend.forget_caller_slots_for_test();
    fx.gateway.rearm_operator_slot_for_test();
    backend.declare_slot_effects_for_test(None, vec![declared(Some(true))]);
    assert_eq!(
        backend.declared_effect_for(Some(&DirectAccountGateway::operator_binding()), TOOL),
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
    let all = decisions(&fx);
    let last = all.last().expect("the replay's record");
    assert_eq!(last["decided"], "replayed", "{all:?}");
    assert!(last.get("declared_effect").is_none(), "{all:?}");
}
