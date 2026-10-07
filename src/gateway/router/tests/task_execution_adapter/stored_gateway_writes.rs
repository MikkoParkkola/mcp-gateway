// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7993.STORE.1`: a task row records which members of its stored result
//! the gateway wrote, so a later `tasks/get` receipt can leave exactly those
//! out. Read straight from the row on disk, through the fixture's `TempDir`.
use super::super::*;
use super::support::*;

use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

fn text(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": false})
}

/// The suite's state with `mock` registered and a `block` relay detector over
/// every `mock` tool, so the gateway's receipts are live.
async fn relay_state(mock: &Arc<MockBackend>) -> (Arc<AppState>, tempfile::TempDir) {
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec![format!("{BACKEND}:*")],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.set_firewall(Some(firewall));
            meta
        },
    )
    .await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// The row of task `id`, as the store wrote it.
fn row(store: &tempfile::TempDir, id: &str) -> Value {
    let path = store.path().join("tasks").join(format!("{id}.json"));
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("the row at {} reads: {error}", path.display()));
    serde_json::from_slice(&bytes).expect("a task row is JSON")
}

/// The row's write record entries whose `kind` is `kind`.
fn written(row: &Value, kind: &[&str]) -> Vec<Value> {
    row.get("gatewayWrites")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    entry["kind"].as_array().is_some_and(|k| {
                        k.iter()
                            .map(Value::as_str)
                            .eq(kind.iter().map(|s| Some(*s)))
                    })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// STORE.1: the `trace_id` the gateway writes into every invoke result is
/// stored with the result, and the row records it as the gateway's.
#[tokio::test]
async fn a_task_row_records_the_trace_id_the_gateway_wrote() {
    let mock = MockBackend::answering(Answer::Sequence(vec![text("the backend's answer")]));
    let (state, store) = relay_state(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "writes-trace", json!({}))).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    let row = row(&store, &task);
    assert!(
        row.to_string().contains("trace_id"),
        "premise: the stored result carries the gateway's trace_id: {row}"
    );
    let entries = written(&row, &["trace_id"]);
    assert_eq!(
        entries.len(),
        1,
        "the row records the trace_id the gateway wrote: {row}"
    );
    assert_eq!(entries[0]["layer"], "value", "{row}");
    assert_eq!(entries[0]["dest"], json!(["trace_id"]), "{row}");
}

/// STORE.2: a member the backend sent under a name the gateway also writes
/// elsewhere is the backend's, so the row does not record it.
#[tokio::test]
async fn a_task_row_never_records_a_backend_member_as_the_gateways() {
    let mut answer = text("the backend's answer");
    answer["_cost_warnings"] = json!(["written by the backend, not the gateway"]);
    let mock = MockBackend::answering(Answer::Sequence(vec![answer]));
    let (state, store) = relay_state(&mock).await;
    let created = post(&state, "key-a", task_invoke(1, "writes-backend", json!({}))).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    let row = row(&store, &task);
    assert!(
        row.to_string().contains("written by the backend"),
        "premise: the backend's member is stored: {row}"
    );
    assert!(
        written(&row, &["_cost_warnings"]).is_empty(),
        "a backend member was recorded as the gateway's: {row}"
    );
}

/// STORE.1 on a chain: each step's `trace_id` lives under its step in the
/// stored `results`, and the row records it at that path.
#[tokio::test]
async fn a_chain_task_row_records_each_steps_gateway_writes_under_the_step() {
    let mock = MockBackend::answering(Answer::Sequence(vec![text("step one"), text("step two")]));
    let (state, store) = relay_state(&mock).await;
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {}});
    let plan = keyed(
        modern(
            1,
            "tools/call",
            json!({
                "name": "gateway_execute",
                "arguments": {"chain": [step, step]},
                "task": {}
            }),
            true,
        ),
        "writes-chain",
    );
    let created = post(&state, "key-a", plan).await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    let row = row(&store, &task);
    let entries = written(&row, &["trace_id"]);
    let dests: Vec<&Value> = entries.iter().map(|entry| &entry["dest"]).collect();
    for step in ["0", "1"] {
        assert!(
            dests.contains(&&json!(["results", step, "result", "trace_id"])),
            "step {step}'s trace_id is recorded under its step: {dests:?}; row: {row}"
        );
    }
}

/// r2a: a state-only round the worker resumes on its own is not the stored
/// answer, so its notes are not recorded; only the final round's are.
#[tokio::test]
async fn a_state_only_rounds_notes_are_not_recorded() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        super::input_round::state_only("s-1"),
        text("the final answer"),
    ]));
    let (state, store) = relay_state(&mock).await;
    let created = post(
        &state,
        "key-a",
        super::input_round::create(1, "writes-state-only"),
    )
    .await;
    let task = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    assert_eq!(status_of(&settled), "completed", "premise: {settled}");
    assert_eq!(mock.calls(), 2, "premise: the state-only round was resumed");
    let row = row(&store, &task);
    assert!(
        written(&row, &["requestState"]).is_empty(),
        "a resumed round's continuation was recorded: {row}"
    );
    assert_eq!(
        written(&row, &["trace_id"]).len(),
        1,
        "only the final round's trace_id: {row}"
    );
}
