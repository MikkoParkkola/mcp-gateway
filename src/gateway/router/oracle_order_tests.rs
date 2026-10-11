// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8361 ordering rows (test plan v3): the gate answers a name the caller
//! cannot see before anything caller-specific acts. E1 a mixed chain, K1-K3
//! fills and backend-wide refusals, O1-O4 signing, task admission, replay
//! and confirmation. The twins are `oracle_parity_fixture`'s.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::direct_guards_fixture::{Fx, send};
use super::oracle_parity_fixture::{
    Answered, Entry, Reason, SERVER, SIBLING, STATE_ENTRIES, Side, State, TOOL, Twin,
    assert_cells, mismatch, twin, untraced,
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
        cells.push(format!("E1: withheld {} {} vs absent {} {}", w.status, w.body, a.status, a.body));
    }
    if (w.calls, a.calls) != (1, 1) {
        cells.push(format!("E1: sends withheld {} absent {} (expected 1, 1)", w.calls, a.calls));
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
        let calls = (0..4).map(|_| twin.call(Entry::Invoke, json!({})));
        let answers = futures::future::join_all(calls).await;
        let lists = twin.lists.load(Ordering::SeqCst);
        if lists != 1 {
            cells.push(format!("K1 {side:?}: {lists} list fetches: {:?}", answers[0].body));
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
        ("K2 killed", (|fx: &Fx| fx.state.meta_mcp.kill_switch().kill(SERVER)) as fn(&Fx)),
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
                cells.push(format!("{cell}: list fetches withheld {} absent {}", w.lists, a.lists));
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
    assert_eq!(probe.calls, 1, "premise: the probe did not dispatch: {}", probe.body);
    let mut cells = Vec::new();
    let mut firsts = Vec::new();
    for side in [Side::Withheld, Side::Absent] {
        let twin = twin(side, state).await;
        let first = twin.invoke_modern(TOOL, json!({}), &signed).await;
        let reuse = twin.invoke_modern(SIBLING, json!({}), &signed).await;
        if reuse.calls != 1 {
            cells.push(format!("O1 {side:?}: the nonce was spent: reuse {}", reuse.body));
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
        let answered = twin(side, state).await.invoke_modern(TOOL, json!({}), &extra).await;
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
        assert_eq!(first.calls, 1, "premise ({side:?}): first call: {}", first.body);
        twin.drifted.store(true, Ordering::SeqCst);
        let backend = twin.fx.state.backends.get(SERVER).expect("alpha");
        backend.invalidate_tools_cache();
        backend.get_tools_shared().await.expect("refill");
        let second = twin.invoke_modern(TOOL, json!({}), &keyed).await;
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

/// O4: a destructive name the caller cannot see draws no X14 confirmation
/// challenge on a task-augmented call; the control (`k-std`, which may see
/// it) is challenged. (A plain modern call is not challenged at all, so the
/// task form is the one that reaches the confirmation gate.)
#[tokio::test]
async fn o4_a_withheld_destructive_call_draws_no_confirmation() {
    let challenged = |body: &Value| {
        body.pointer("/result/resultType") == Some(&json!("input_required"))
            || body.pointer("/error/code") == Some(&json!(-32003))
    };
    let state = State {
        destructive: true,
        ..State::WARM
    };
    let control_twin = twin(Side::Withheld, state).await;
    let control = {
        let mut meta = super::tests::modern_meta();
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("o4");
        let params = json!({"name": "gateway_invoke", "arguments":
            {"server": SERVER, "tool": TOOL, "arguments": {}},
            "task": {}, "_meta": meta});
        let headers = [
            ("mcp-protocol-version", "2026-07-28"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "gateway_invoke"),
        ];
        let (status, body) = super::direct_guards_fixture::send_with_headers(
            &control_twin.fx,
            "/mcp",
            "k-std",
            "tools/call",
            params,
            None,
            &headers,
        )
        .await;
        control_twin.answered(status, body)
    };
    assert!(challenged(&control.body), "premise: the control is not challenged: {}", control.body);
    let extra = json!({"task": {}, "_meta": {crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "o4"}});
    let withheld = twin(Side::Withheld, state).await.invoke_modern(TOOL, json!({}), &extra).await;
    let absent = twin(Side::Absent, state).await.invoke_modern(TOOL, json!({}), &extra).await;
    let mut cells = Vec::new();
    if challenged(&withheld.body) {
        cells.push(format!("O4: the withheld call was challenged: {}", withheld.body));
    }
    cells.extend(mismatch("O4", &withheld, &absent));
    assert_cells("O4", &cells);
}
