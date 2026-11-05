// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9216.EFFECT.1, the deferred lift: a managed-account replay defers and
//! is lifted after the live proof (every per-caller replay defers, E10), and
//! its record carries the effect of the slot the first execution ran under,
//! read now, never another slot's.

use super::*;

/// `TOOL` declaring `readOnlyHint: hint`.
fn declared(hint: bool) -> crate::protocol::Tool {
    serde_json::from_value(json!({
        "name": TOOL,
        "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}},
        "annotations": {"readOnlyHint": hint},
    }))
    .expect("a tool")
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
    assert!(first.to_string().contains(MARKER), "premise: dispatched: {first}");
    let sent = fx.gateway.tool_calls().len();
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    let operator = DirectAccountGateway::operator_binding();
    backend.declare_slot_effects_for_test(Some(&operator), vec![declared(true)]);
    backend.declare_slot_effects_for_test(None, vec![declared(false)]);
    let again = send(&fx, "tools/call", "gateway_invoke", params()).await;
    assert!(again.to_string().contains(MARKER), "premise: served: {again}");
    assert_eq!(fx.gateway.tool_calls().len(), sent, "premise: not re-sent");
    let all = decisions(&fx);
    let last = all.last().expect("the replay's record");
    assert_eq!(last["decided"], "replayed", "{all:?}");
    assert_eq!(last["declared_effect"], "read_only", "{all:?}");
    assert_eq!(last["declared_effect_source"], "tool_annotation", "{all:?}");
}
