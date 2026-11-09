// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task-augmented composite (`gateway_execute` chain or
//! `gateway_run_playbook`) whose plan ends on a gateway-refused step writes
//! one `task_settlement` record: refused, the refusing gate's own code, joined
//! to the step it ended on (`joined_by: step_trace`) or, with no usable step
//! trace, to the task id (`joined_by: task_id`).

use super::super::*;
use super::dispatch_refusal_task::{
    clean_answer, contract_state, fail_closed, refusing_final_answer, settled_task, settlements,
};
use super::support::*;
use crate::config::ResponseContractConfig;
use pretty_assertions::assert_eq;

/// A state with a transparency log, and the guards that keep both alive.
struct Fixture {
    state: Arc<AppState>,
    log: Arc<crate::security::TransparencyLogger>,
    _dirs: (
        std::sync::Arc<tempfile::TempDir>,
        crate::gateway::router::tests::FixtureDir,
    ),
}

async fn fixture(contract: Option<ResponseContractConfig>) -> Fixture {
    let (dir, log) = crate::gateway::router::route_matrix_driver_tests::response::temp_log(None);
    let (state, store) = contract_state(Arc::clone(&log), contract).await;
    Fixture {
        state,
        log,
        _dirs: (dir, store),
    }
}

impl Fixture {
    /// One task-augmented `request` as `key`, run to its terminal state: the
    /// task id, its terminal `tasks/get` read and every record in the log. A
    /// log that cannot be read or a line that is not JSON fails the row.
    async fn run(&self, key: &str, request: Value) -> (String, Value, Vec<Value>) {
        use crate::gateway::router::route_matrix_driver_tests::response::delivery_rows;
        let task = task_id(&post(&self.state, key, request).await);
        let settled = poll_until_terminal(&self.state, key, &task).await;
        let _ = delivery_rows(&self.log).await;
        let entries = std::fs::read_to_string(self.log.path())
            .expect("the transparency log reads")
            .lines()
            .map(|line| serde_json::from_str(line).expect("every log line is JSON"))
            .collect();
        (task, settled, entries)
    }
}

/// The result the contract refuses (it carries the mock's final text).
fn refusable() -> Value {
    json!({
        "content": [{"type": "text", "text": "mock-backend-answered"}],
        "isError": false
    })
}

/// The text a clean step delivers, distinct enough to find in a plan's result.
const DELIVERED: &str = "delivered-clean-step";

fn clean() -> Value {
    json!({"content": [{"type": "text", "text": DELIVERED}], "isError": false})
}

/// The task completed and the step result at `step` (a JSON pointer into
/// the plan's result: a chain's `/results/N/result`, a playbook's
/// `/output/NAME`) carries the delivered text in its content items.
fn assert_delivered(settled: &Value, step: &str) {
    assert_eq!(status_of(settled), "completed", "{settled}");
    let result = settled
        .pointer("/result/result")
        .and_then(|plan| plan.pointer(step))
        .unwrap_or_else(|| panic!("a completed task carries step {step}: {settled}"));
    let texts: Vec<&str> = result["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["text"].as_str())
        .collect();
    assert_eq!(texts, [DELIVERED], "step {step} delivered: {settled}");
}

/// A task-augmented `gateway_execute` chain over `tools`.
fn chain_task(key: &str, tools: &[String]) -> Value {
    let steps: Vec<Value> = tools
        .iter()
        .map(|tool| json!({ "tool": tool, "arguments": {} }))
        .collect();
    keyed(
        modern(
            1,
            "tools/call",
            json!({
                "name": "gateway_execute",
                "arguments": { "chain": steps },
                "task": {}
            }),
            true,
        ),
        key,
    )
}

/// A task-augmented run of the playbook `gated`.
fn playbook_task(key: &str) -> Value {
    keyed(
        modern(
            1,
            "tools/call",
            json!({ "name": "gateway_run_playbook", "arguments": { "name": "gated" }, "task": {} }),
            true,
        ),
        key,
    )
}

/// Register a playbook `gated` whose steps all call the mock, `arguments`
/// being each step's arguments.
fn register_playbook(state: &Arc<AppState>, on_error: &str, arguments: &[Value]) {
    let steps: Vec<Value> = arguments
        .iter()
        .enumerate()
        .map(|(n, args)| {
            let name = ["first", "second", "third"][n];
            json!({ "name": name, "tool": TOOL, "server": BACKEND, "arguments": args })
        })
        .collect();
    let definition: crate::playbook::PlaybookDefinition = serde_json::from_value(json!({
        "playbook": "1.0",
        "name": "gated",
        "description": "steps at the mock",
        "on_error": on_error,
        "steps": steps
    }))
    .expect("the fixture playbook deserialises");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    state.meta_mcp.set_playbook_engine(engine);
}

fn mock_tool() -> String {
    format!("{BACKEND}:{TOOL}")
}

/// The one log record of the step the backend answered and the contract
/// refused: a `meta` record for the mock's tool carrying an error code.
fn refused_step_record<'a>(entries: &'a [Value], task: &str) -> &'a Value {
    let found: Vec<&Value> = entries
        .iter()
        .filter(|entry| {
            entry["route"] == "meta"
                && entry["server"] == BACKEND
                && entry["tool"] == TOOL
                && !entry["error_code"].is_null()
        })
        .collect();
    let [record] = found.as_slice() else {
        panic!("task {task}: one refused step record: {entries:#?}");
    };
    record
}

/// The task's one settlement record, checked for a refusal.
fn refused_settlement<'a>(entries: &'a [Value], task: &str) -> &'a Value {
    let records = settlements(entries, task);
    let [record] = records.as_slice() else {
        panic!("task {task}: one task_settlement record: {entries:#?}");
    };
    assert_eq!(record["response_effect"], "refused", "{record}");
    assert_eq!(record["outcome"], "denied", "{record}");
    record
}

/// A chain refused at its last step: refused, joined to that step's own
/// record by trace, with the gate's own code. (composite settlement, chain.)
#[tokio::test]
async fn a_chain_refused_at_its_last_step_is_joined_by_step_trace() {
    let fx = fixture(Some(refusing_final_answer())).await;
    let mock = MockBackend::answering(Answer::Sequence(vec![clean(), refusable()]));
    register(&fx.state, BACKEND, &mock);
    let (task, _settled, entries) = fx
        .run("key-a", chain_task("key-a", &[mock_tool(), mock_tool()]))
        .await;
    assert_eq!(mock.calls(), 2, "premise: both steps ran");
    let record = refused_settlement(&entries, &task);
    let step = refused_step_record(&entries, &task);
    assert_eq!(record["joined_by"], "step_trace", "{record}");
    assert_eq!(record["trace_id"], step["trace_id"], "{record} vs {step}");
    assert_eq!(
        record["error_code"], step["error_code"],
        "{record} vs {step}"
    );
}

/// A playbook (`on_error: abort`) refused at its second step: the same
/// record as a chain's.
#[tokio::test]
async fn an_aborting_playbook_refused_at_a_step_is_joined_by_step_trace() {
    let fx = fixture(Some(refusing_final_answer())).await;
    let mock = MockBackend::answering(Answer::Sequence(vec![clean(), refusable()]));
    register(&fx.state, BACKEND, &mock);
    register_playbook(&fx.state, "abort", &[json!({}), json!({})]);
    let (task, _settled, entries) = fx.run("key-a", playbook_task("key-a")).await;
    assert_eq!(mock.calls(), 2, "premise: both steps ran");
    let record = refused_settlement(&entries, &task);
    let step = refused_step_record(&entries, &task);
    assert_eq!(record["joined_by"], "step_trace", "{record}");
    assert_eq!(record["trace_id"], step["trace_id"], "{record} vs {step}");
    assert_eq!(
        record["error_code"], step["error_code"],
        "{record} vs {step}"
    );
}

/// A sealed continuation envelope the gateway minted, as a backend might
/// echo it in an answer.
async fn sealed_token(state: &Arc<AppState>) -> String {
    let continuation = state.meta_mcp.continuation();
    let payload = continuation
        .begin_exchange(
            "srv".into(),
            None,
            "fp".into(),
            &crate::protocol::continuation::QuotaKey::for_test("fp"),
            "digest".into(),
            crate::protocol::continuation::now_unix_secs(),
        )
        .await
        .expect("a fresh state has a slot");
    continuation.keyring().mint(&payload).expect("seals")
}

/// A playbook whose second step would carry the first step's sealed envelope
/// is refused before that step runs: no usable step trace, so the record
/// joins by task id and names the refusal's own code.
#[tokio::test]
async fn a_later_step_refused_before_it_runs_is_joined_by_task_id() {
    let fx = fixture(None).await;
    let token = sealed_token(&fx.state).await;
    let answer = json!({"content": [{"type": "text", "text": token}], "isError": false});
    let mock = MockBackend::answering(Answer::Result(answer));
    register(&fx.state, BACKEND, &mock);
    register_playbook(&fx.state, "abort", &[json!({}), json!({ "t": "$first" })]);
    let (task, _settled, entries) = fx.run("key-a", playbook_task("key-a")).await;
    assert_eq!(mock.calls(), 1, "premise: only the first step ran");
    let record = refused_settlement(&entries, &task);
    assert_eq!(record["joined_by"], "task_id", "{record}");
    assert_eq!(record["trace_id"], task.as_str(), "{record}");
    assert_eq!(record["error_code"], -32003, "{record}");
}

/// The record names the gateway and the composite tool, not the first
/// backend the chain dispatches to. Two distinct backends in one chain are
/// not reachable here: the fixture credentials see only the mock backend.
#[tokio::test]
async fn a_composite_record_names_the_gateway_and_the_composite_tool() {
    assert_ne!(
        BACKEND, "gateway",
        "premise: the backend is not named as the gateway"
    );
    let fx = fixture(Some(refusing_final_answer())).await;
    let mock = MockBackend::answering(Answer::Sequence(vec![clean(), refusable()]));
    register(&fx.state, BACKEND, &mock);
    let (task, _settled, entries) = fx
        .run("key-a", chain_task("key-a", &[mock_tool(), mock_tool()]))
        .await;
    assert_eq!(mock.calls(), 2, "premise: both steps ran");
    let record = refused_settlement(&entries, &task);
    assert_ne!(record["server"], BACKEND, "{record}");
    assert_eq!(record["server"], "gateway", "{record}");
    assert_eq!(record["tool"], "gateway_execute", "{record}");
}

/// A playbook that carries on past a refused step and delivers writes no
/// refused settlement record.
#[tokio::test]
async fn a_playbook_that_continues_past_a_refusal_writes_no_refused_record() {
    let fx = fixture(Some(refusing_final_answer())).await;
    let mock = MockBackend::answering(Answer::Sequence(vec![refusable(), clean()]));
    register(&fx.state, BACKEND, &mock);
    register_playbook(&fx.state, "continue", &[json!({}), json!({})]);
    let (task, settled, entries) = fx.run("key-a", playbook_task("key-a")).await;
    assert_eq!(mock.calls(), 2, "premise: the second step ran");
    assert_delivered(&settled, "/output/second");
    assert!(
        settlements(&entries, &task)
            .iter()
            .all(|record| record["response_effect"] != "refused"),
        "{entries:#?}"
    );
}

/// A composite that succeeds writes no settlement record.
#[tokio::test]
async fn a_composite_that_succeeds_writes_no_settlement_record() {
    let fx = fixture(Some(refusing_final_answer())).await;
    let mock = MockBackend::answering(Answer::Result(clean()));
    register(&fx.state, BACKEND, &mock);
    let (task, settled, entries) = fx
        .run("key-a", chain_task("key-a", &[mock_tool(), mock_tool()]))
        .await;
    assert_eq!(mock.calls(), 2, "premise: both steps ran");
    assert_delivered(&settled, "/results/1/result");
    assert!(settlements(&entries, &task).is_empty(), "{entries:#?}");
}

/// Guard: a single-target dispatch refusal keeps its record unchanged, with
/// no `joined_by` member.
#[tokio::test]
async fn a_single_target_refusal_record_has_no_join_member() {
    let (task, _settled, entries) =
        Box::pin(settled_task(clean_answer(), Some(fail_closed()))).await;
    let records = settlements(&entries, &task);
    let [record] = records.as_slice() else {
        panic!("task {task}: one task_settlement record: {entries:#?}");
    };
    assert_eq!(record["response_effect"], "refused", "premise: {record}");
    assert!(record.get("joined_by").is_none(), "{record}");
}

/// A playbook whose first step would carry a sealed envelope from the
/// caller's own input is refused before that step runs: no step dispatched,
/// so the record joins by task id and names the refusal's own code.
#[tokio::test]
async fn a_first_step_refused_before_it_runs_is_joined_by_task_id() {
    let fx = fixture(None).await;
    let token = sealed_token(&fx.state).await;
    let mock = MockBackend::answering(Answer::Result(clean()));
    register(&fx.state, BACKEND, &mock);
    register_playbook(&fx.state, "abort", &[json!({ "t": "$inputs.t" })]);
    let request = keyed(
        modern(
            1,
            "tools/call",
            json!({ "name": "gateway_run_playbook",
                    "arguments": { "name": "gated", "arguments": { "t": token } },
                    "task": {} }),
            true,
        ),
        "key-a",
    );
    let (task, _settled, entries) = fx.run("key-a", request).await;
    assert_eq!(mock.calls(), 0, "premise: no step was dispatched");
    let record = refused_settlement(&entries, &task);
    assert_eq!(record["joined_by"], "task_id", "{record}");
    assert_eq!(record["trace_id"], task.as_str(), "{record}");
    assert_eq!(record["error_code"], -32003, "{record}");
}
