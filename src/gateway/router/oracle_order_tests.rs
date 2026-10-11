// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 ordering rows (test plan v3): the gate answers a name the caller
//! cannot see before anything caller-specific acts. E1 a mixed chain, K1-K3
//! fills and backend-wide refusals, O1-O3 signing, task admission and replay,
//! B1 the dispatch-time backstop. O4 is folded (see the PR ledger). The
//! twins are `oracle_parity_fixture`'s.

use std::sync::atomic::Ordering;

use serde_json::json;

use super::direct_guards_fixture::{Fx, send};
use super::oracle_parity_fixture::{
    Answered, Entry, Reason, SERVER, SIBLING, STATE_ENTRIES, Side, State, TOOL, Twin, assert_cells,
    mismatch, twin, untraced,
};

/// E1: a visible step followed by a withheld one. The first step dispatches;
/// the withheld step answers as a missing step, unsent.
#[tokio::test]
async fn e1_a_mixed_chain_runs_the_visible_step_and_answers_the_withheld_one_absent() {
    async fn chain(twin: &Twin) -> Answered {
        let params = json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": format!("{SERVER}:{SIBLING}"), "arguments": {}},
            {"tool": format!("{SERVER}:{TOOL}"), "arguments": {}}
        ]}});
        let key = twin.side.key(twin.reason);
        let (status, body) = send(&twin.fx, "/mcp", key, "tools/call", params, None).await;
        twin.answered(status, body)
    }
    let withheld = twin(Side::Withheld, State::WARM).await;
    let absent = twin(Side::Absent, State::WARM).await;
    let (w, a) = (chain(&withheld).await, chain(&absent).await);
    let mut cells = Vec::new();
    if (w.status, &w.body) != (a.status, &a.body) {
        cells.push(format!(
            "E1: withheld {} {} vs absent {} {}",
            w.status, w.body, a.status, a.body
        ));
    }
    if (w.calls, a.calls) != (1, 1) {
        cells.push(format!(
            "E1: sends withheld {} absent {} (expected 1, 1)",
            w.calls, a.calls
        ));
    }
    assert_cells("E1", &cells);
}

/// K1: concurrent cold calls of the withheld name fill the catalogue once.
#[tokio::test]
async fn k1_concurrent_cold_calls_list_once() {
    let state = State {
        warm: false,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for side in [Side::Withheld, Side::Absent] {
        let twin = twin(side, state).await;
        let racing = (0..4).map(|_| twin.call(Entry::Invoke, json!({})));
        let answers = futures::future::join_all(racing).await;
        let lists = twin.lists.load(Ordering::SeqCst);
        if lists != 1 {
            cells.push(format!(
                "K1 {side:?}: {lists} list fetches: {:?}",
                answers[0].body
            ));
        }
    }
    assert_cells("K1", &cells);
}

/// K2 / K3: a killed or unavailable backend refuses both names alike, before
/// any list fetch (backend-wide checks are not existence-sensitive).
#[tokio::test]
async fn k2_k3_backend_wide_refusals_answer_both_names_alike_with_no_fill() {
    let cold = State {
        warm: false,
        ..State::WARM
    };
    let mut cells = Vec::new();
    for (label, arm) in [
        (
            "K2 killed",
            (|fx: &Fx| fx.state.meta_mcp.kill_switch().kill(SERVER)) as fn(&Fx),
        ),
        ("K3 unavailable", |fx: &Fx| {
            fx.state
                .backends
                .get(SERVER)
                .expect("alpha")
                .trip_circuit_breaker_for_test();
        }),
    ] {
        for entry in STATE_ENTRIES {
            let withheld = twin(Side::Withheld, cold).await;
            let absent = twin(Side::Absent, cold).await;
            arm(&withheld.fx);
            arm(&absent.fx);
            let (w, a) = (
                withheld.call(entry, json!({})).await,
                absent.call(entry, json!({})).await,
            );
            let cell = format!("{label} {entry:?}");
            cells.extend(mismatch(&cell, &w, &a));
            if (w.lists, a.lists) != (0, 0) {
                cells.push(format!(
                    "{cell}: list fetches withheld {} absent {}",
                    w.lists, a.lists
                ));
            }
        }
    }
    assert_cells("K2/K3", &cells);
}

/// O1: the gate answers before signing admission. A call of the name under
/// nonce N spends nothing, so N then signs a sibling call that dispatches,
/// on both twins, and the two first answers match.
#[tokio::test]
async fn o1_a_withheld_call_spends_no_signing_nonce() {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let state = State {
        signed: true,
        ..State::WARM
    };
    let signed = json!({"_meta": {NONCE_META: "o1-nonce"}});
    // Control: the sibling under N dispatches on an untouched fixture.
    let probe = twin(Side::Absent, state)
        .await
        .invoke_modern(SIBLING, json!({}), &signed)
        .await;
    assert_eq!(
        probe.calls, 1,
        "premise: the probe did not dispatch: {}",
        probe.body
    );
    let mut cells = Vec::new();
    let mut firsts = Vec::new();
    for side in [Side::Withheld, Side::Absent] {
        let twin = twin(side, state).await;
        let first = twin.invoke_modern(TOOL, json!({}), &signed).await;
        let reuse = twin.invoke_modern(SIBLING, json!({}), &signed).await;
        if reuse.calls != 1 {
            cells.push(format!(
                "O1 {side:?}: the nonce was spent: reuse {}",
                reuse.body
            ));
        }
        firsts.push(first);
    }
    cells.extend(mismatch("O1 first call", &firsts[0], &firsts[1]));
    assert_cells("O1", &cells);
}

/// O2: a task-augmented call of a destructive name creates no task on
/// either twin, and both answer alike.
#[tokio::test]
async fn o2_a_withheld_task_call_creates_no_task() {
    let state = State {
        destructive: true,
        ..State::WARM
    };
    let extra = json!({"task": {}, "_meta": {
        crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "o2"
    }});
    let mut answers = Vec::new();
    let mut cells = Vec::new();
    for side in [Side::Withheld, Side::Absent] {
        let answered = twin(side, state)
            .await
            .invoke_modern(TOOL, json!({}), &extra)
            .await;
        if answered.body.pointer("/result/taskId").is_some() {
            cells.push(format!("O2 {side:?}: a task was made: {}", answered.body));
        }
        answers.push(answered);
    }
    cells.extend(mismatch("O2", &answers[0], &answers[1]));
    assert_cells("O2", &cells);
}

/// O3: a result retained for the same idempotency key is not replayed for a
/// name the caller can no longer see (schema-withheld) or that the catalogue
/// no longer lists: the gate answers first, as an unkeyed call does.
#[tokio::test]
async fn o3_a_retained_result_is_not_replayed_for_an_invisible_name() {
    let state = State {
        reason: Reason::Schema,
        drift: true,
        ..State::WARM
    };
    let keyed = json!({"_meta": {crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "o3"}});
    let mut cells = Vec::new();
    let mut seconds = Vec::new();
    for side in [Side::Withheld, Side::Absent] {
        let twin = twin(side, state).await;
        let first = twin.invoke_modern(TOOL, json!({}), &keyed).await;
        assert_eq!(
            first.calls, 1,
            "premise ({side:?}): first call: {}",
            first.body
        );
        twin.drifted.store(true, Ordering::SeqCst);
        // The slot the check reads is replaced by the drifted list, as a
        // direct listing stores it (`invalidate` alone leaves it fresh).
        let backend = twin.fx.state.backends.get(SERVER).expect("alpha");
        let mut listed = vec![json!({"name": SIBLING, "inputSchema": {"type": "object"}})];
        if side == Side::Withheld {
            listed.push(super::oracle_parity_fixture::listed_tool(
                Reason::Schema,
                false,
            ));
        }
        backend.remember_listed_tools(None, false, &listed);
        let sent = twin.calls.load(Ordering::SeqCst);
        let mut second = twin.invoke_modern(TOOL, json!({}), &keyed).await;
        // Only this call's own sends: the first call dispatched by design.
        second.calls -= sent;
        let unkeyed = twin.invoke_modern(TOOL, json!({}), &json!({})).await;
        if untraced(second.body.clone()) != untraced(unkeyed.body.clone()) {
            cells.push(format!(
                "O3 {side:?}: keyed {} vs unkeyed {}",
                second.body, unkeyed.body
            ));
        }
        seconds.push(second);
    }
    cells.extend(mismatch("O3 second call", &seconds[0], &seconds[1]));
    assert_cells("O3", &cells);
}

/// D1 (one judgement per request, MIK-8340 row 14's pattern): a missing name
/// whose catalogue gains it after the route stage judged it stays absent and
/// unsent. RED on base: the meta layer refills, finds it, and dispatches.
#[tokio::test]
async fn d1_a_refill_after_the_route_stage_keeps_a_missing_name_absent() {
    let state = State {
        gains: true,
        ..State::WARM
    };
    let absent = twin(Side::Absent, state).await;
    let gained = std::sync::Arc::clone(&absent.drifted);
    let backend = absent.fx.state.backends.get(SERVER).expect("alpha");
    crate::gateway::meta_mcp::withheld_gate::seams::after_gate(move || {
        gained.store(true, Ordering::SeqCst);
        // A complete list that now holds the name replaces the slot, as a
        // direct listing landing between the stages would.
        let listed = [
            json!({"name": SIBLING, "inputSchema": {"type": "object"}}),
            json!({"name": TOOL, "description": "Reads a record.", "inputSchema": {"type": "object"}}),
        ];
        backend.remember_listed_tools(None, false, &listed);
    });
    let answered = absent.call(Entry::Invoke, json!({})).await;
    assert_eq!(
        answered.calls, 0,
        "D1: the refilled name was sent: {}",
        answered.body
    );
    assert!(
        answered
            .body
            .to_string()
            .contains("does not list a tool named"),
        "D1: the missing name did not answer absent: {}",
        answered.body
    );
}

/// B1: a withheld target let past the gate (test seam) is answered by the
/// dispatch-time recheck with the absent answer, never its specific refusal,
/// and is not sent. RED on base: the route stage's policy refusal names it.
#[tokio::test]
async fn b1_the_dispatch_backstop_answers_a_withheld_target_absent() {
    let mut cells = Vec::new();
    for entry in [Entry::Invoke, Entry::Direct] {
        let withheld = twin(Side::Withheld, State::WARM).await;
        let absent = twin(Side::Absent, State::WARM).await;
        let _skip = crate::gateway::meta_mcp::withheld_gate::seams::skip_gate_for_test();
        let w = withheld.call(entry, json!({})).await;
        let a = absent.call(entry, json!({})).await;
        cells.extend(mismatch(&format!("B1 {entry:?}"), &w, &a));
    }
    assert_cells("B1", &cells);
}
