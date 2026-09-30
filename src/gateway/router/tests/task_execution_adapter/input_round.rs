// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7311.LIFECYCLE.1 increment 1b: the input round on `POST /mcp`.
//!
//! A backend `input_required` result parks the task as `input_required`;
//! `tasks/update` supplies the answers and the gateway resumes the SAME call
//! through the existing continuation redemption. Each test names the mutant it
//! must fail on (design §5).

use super::super::*;
use super::support::*;

pub(super) const STATE_1: &str = "backend-state-1";

/// One elicitation question under `key`, with the backend's own `state`.
pub(super) fn ask(key: &str, state: &str) -> Value {
    ask_many(&[key], state)
}

pub(super) fn ask_many(keys: &[&str], state: &str) -> Value {
    let requests: serde_json::Map<String, Value> = keys
        .iter()
        .map(|key| {
            (
                (*key).to_string(),
                json!({
                    "method": "elicitation/create",
                    "params": {
                        "message": "confirm?",
                        "requestedSchema": { "type": "object", "properties": {} }
                    }
                }),
            )
        })
        .collect();
    json!({
        "resultType": "input_required",
        "inputRequests": requests,
        "requestState": state
    })
}

/// A round that carries state and asks the client nothing.
pub(super) fn state_only(state: &str) -> Value {
    json!({ "resultType": "input_required", "requestState": state })
}

pub(super) fn done() -> Value {
    let Answer::Result(value) = Answer::ok() else {
        unreachable!("ok is a single result")
    };
    value
}

pub(super) fn answer() -> Value {
    json!({ "action": "accept", "content": {} })
}

/// A task-augmented call from a client that can be asked for input.
pub(super) fn create(id: i64, key: &str) -> Value {
    declaring_elicitation(task_invoke(id, key, json!({ "q": 1 })))
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "every call site passes an owned json! literal, as in `support`"
)]
pub(super) fn update(id: i64, task: &str, responses: Value) -> Value {
    declaring_elicitation(task_method(
        id,
        "tasks/update",
        json!({ "taskId": task, "inputResponses": responses }),
    ))
}

pub(super) fn error_code(body: &Value) -> Option<i64> {
    body.pointer("/error/code").and_then(Value::as_i64)
}

/// Poll until the task shows `input_required`, bounded.
pub(super) async fn wait_input_required(state: &Arc<AppState>, id: &str) -> Value {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let last = get_task(state, "key-a", id).await;
        if status_of(&last) == "input_required" {
            return last;
        }
        std::assert!(
            !is_terminal(&status_of(&last)),
            "task {id} settled instead of waiting for input: {last}"
        );
        std::assert!(
            tokio::time::Instant::now() < deadline,
            "task {id} never reached input_required: {last}"
        );
        tokio::task::yield_now().await;
    }
}

/// Create a task whose backend asks first, and wait for the round.
pub(super) async fn parked(state: &Arc<AppState>, key: &str) -> String {
    let created = post(state, "key-a", create(1, key)).await;
    let id = task_id(&created);
    wait_input_required(state, &id).await;
    id
}

pub(super) async fn settle_quiet() {
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

/// Mutant: produce arm reverted to the abandoned result.
#[tokio::test]
async fn an_input_round_parks_the_task_and_an_update_resumes_the_same_call() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let created = post(&state, "key-a", create(1, "round-e2e")).await;
    let id = task_id(&created);

    let waiting = wait_input_required(&state, &id).await;
    std::assert!(
        waiting.pointer("/result/inputRequests/confirm").is_some(),
        "the parked task shows what the backend asked: {waiting}"
    );
    std::assert!(
        waiting.pointer("/result/requestState").is_none(),
        "no continuation state is ever on the wire task: {waiting}"
    );

    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(
        acked.get("error").is_none(),
        "a complete answer set is accepted: {acked}"
    );

    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    let seen = mock.seen();
    std::assert_eq!(seen.len(), 2, "one first dispatch and one resume: {seen:?}");
    std::assert_eq!(
        seen[1]["name"],
        seen[0]["name"],
        "the resume calls the same tool"
    );
    std::assert_eq!(
        seen[1]["arguments"],
        seen[0]["arguments"],
        "with the same arguments"
    );
    std::assert_eq!(
        seen[1]["requestState"],
        json!(STATE_1),
        "the backend gets its own state back, unsealed: {seen:?}"
    );
    std::assert_eq!(
        seen[1]["inputResponses"],
        json!({ "confirm": answer() }),
        "and the client's answers: {seen:?}"
    );
}

/// Mutant: the outstanding-key check removed.
#[tokio::test]
async fn an_answer_to_a_key_that_is_not_outstanding_is_refused_and_writes_nothing() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "round-unmatched").await;

    let refused = post(
        &state,
        "key-a",
        update(2, &id, json!({ "other": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&refused), Some(-32602), "{refused}");
    settle_quiet().await;
    let after = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&after), "input_required", "{after}");
    std::assert!(
        after.pointer("/result/inputRequests/confirm").is_some(),
        "{after}"
    );
    std::assert_eq!(mock.calls(), 1, "nothing was dispatched");
}

/// Mutant: the subset accepted before the check.
#[tokio::test]
async fn a_mixed_answer_is_refused_whole_and_the_outstanding_key_stays_outstanding() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "round-mixed").await;

    let refused = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer(), "other": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&refused), Some(-32602), "{refused}");
    settle_quiet().await;
    let after = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&after), "input_required", "{after}");
    std::assert!(
        after.pointer("/result/inputRequests/confirm").is_some(),
        "the valid key was not accepted by a refused update: {after}"
    );
    std::assert_eq!(mock.calls(), 1);
}

/// Mutants: resume on the first answer; accepted answers not persisted, or the
/// resume omitting `inputResponses`.
#[tokio::test]
async fn partial_answers_wait_and_the_resume_carries_every_accepted_answer() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        ask_many(&["a", "b"], STATE_1),
        done(),
    ]));
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "round-partial").await;

    let first = post(&state, "key-a", update(2, &id, json!({ "a": { "v": 1 } }))).await;
    std::assert!(
        first.get("error").is_none(),
        "a valid subset is accepted: {first}"
    );
    settle_quiet().await;
    let between = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&between), "input_required", "{between}");
    std::assert!(
        between.pointer("/result/inputRequests/a").is_none(),
        "{between}"
    );
    std::assert!(
        between.pointer("/result/inputRequests/b").is_some(),
        "{between}"
    );
    std::assert_eq!(mock.calls(), 1, "a partial answer dispatches nothing");

    let second = post(&state, "key-a", update(3, &id, json!({ "b": { "v": 2 } }))).await;
    std::assert!(second.get("error").is_none(), "{second}");
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(
        mock.seen()[1]["inputResponses"],
        json!({ "a": { "v": 1 }, "b": { "v": 2 } }),
        "both partial answers reach the backend together"
    );
}

pub(super) fn reason_of(body: &Value) -> Option<&str> {
    body.pointer("/result/result/_meta/io.mcp-gateway~1reason")
        .and_then(Value::as_str)
}

/// Mutant: cancel arm ignoring the input state.
#[tokio::test]
async fn cancel_during_input_settles_cancelled_and_a_later_update_is_refused() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "round-cancel").await;

    let cancelled = post(
        &state,
        "key-a",
        task_method(2, "tasks/cancel", json!({ "taskId": id })),
    )
    .await;
    std::assert!(cancelled.get("error").is_none(), "{cancelled}");
    let after = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&after), "cancelled", "{after}");

    let late = post(
        &state,
        "key-a",
        update(3, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&late), Some(-32602), "{late}");
    settle_quiet().await;
    std::assert_eq!(mock.calls(), 1, "a cancelled round never resumes");
}

/// Pin (passes before and after): a claimed round whose shape `from_result`
/// rejects keeps today's abandoned result. Mutant: the new arm swallows it.
#[tokio::test]
async fn a_rejected_round_shape_keeps_the_abandoned_result() {
    let mock = MockBackend::answering(Answer::Result(json!({
        "resultType": "input_required",
        "inputRequests": "surprise"
    })));
    let (state, _store) = state_with(&mock).await;
    let id = task_id(&post(&state, "key-a", create(1, "round-rejected")).await);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(
        reason_of(&settled),
        Some("input_round_unavailable"),
        "{settled}"
    );
}

/// #2416 (design §4.3d): a question whose `requestState` is present but not
/// a string is a malformed round. It settles the abandoned result and is never
/// parked or resumed. Mutant: a non-string state read as absent.
#[tokio::test]
async fn a_non_string_request_state_keeps_the_abandoned_result() {
    for (key, state) in [
        ("object", json!({ "k": 1 })),
        ("number", json!(7)),
        ("null", json!(null)),
    ] {
        let mut round = ask("q", "unused");
        round["requestState"] = state;
        let mock = MockBackend::answering(Answer::Result(round));
        let (state, _store) = state_with(&mock).await;
        let id = task_id(&post(&state, "key-a", create(1, &format!("state-{key}"))).await);
        let settled = poll_until_terminal(&state, "key-a", &id).await;
        std::assert_eq!(status_of(&settled), "completed", "{key}: {settled}");
        std::assert_eq!(
            reason_of(&settled),
            Some("input_round_unavailable"),
            "{key}: {settled}"
        );
        std::assert_eq!(mock.calls(), 1, "{key}: a malformed round never resumes");
    }
}

/// Mutant: the model error from `require_input` swallowed (a reused key must
/// settle `failed`, never leave a `working` row).
#[tokio::test]
async fn a_round_reusing_an_answered_key_settles_failed() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        ask("confirm", STATE_1),
        ask("confirm", "backend-state-2"),
    ]));
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "round-malformed").await;
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(acked.get("error").is_none(), "{acked}");
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "failed", "{settled}");
    std::assert_eq!(mock.calls(), 2);
}

/// Mutant: the state-only bound removed. Four state-only rounds are resumed
/// by the worker itself; the fifth settles abandoned.
#[tokio::test]
async fn state_only_rounds_resume_without_the_client_up_to_the_ceiling() {
    let mock = MockBackend::answering(Answer::Result(state_only("loop")));
    let (state, _store) = state_with(&mock).await;
    let id = task_id(&post(&state, "key-a", create(1, "round-state-loop")).await);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(
        reason_of(&settled),
        Some("input_round_unavailable"),
        "{settled}"
    );
    settle_quiet().await;
    std::assert_eq!(mock.calls(), 5, "one dispatch plus four state-only resumes");
}

/// Mutant: a state-only round treated as abandoned (no resume).
#[tokio::test]
async fn a_state_only_round_resumes_with_the_backend_state_and_no_answers() {
    let mock = MockBackend::answering(Answer::Sequence(vec![state_only("s-only"), done()]));
    let (state, _store) = state_with(&mock).await;
    let id = task_id(&post(&state, "key-a", create(1, "round-state-once")).await);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    let seen = mock.seen();
    std::assert_eq!(seen.len(), 2, "{seen:?}");
    std::assert_eq!(seen[1]["requestState"], json!("s-only"), "{seen:?}");
    std::assert_eq!(seen[1]["arguments"], seen[0]["arguments"], "{seen:?}");
}

/// Mutant: the resume built from the stored (creating) caller context. The
/// updating client declares no elicitation, so a second question on the
/// resumed call is refused for THAT caller.
#[tokio::test]
async fn the_resume_runs_as_the_caller_of_the_update() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        ask("a", STATE_1),
        ask("b", "backend-state-2"),
        done(),
    ]));
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "round-caller").await;
    let plain = task_method(
        2,
        "tasks/update",
        json!({ "taskId": id, "inputResponses": { "a": answer() } }),
    );
    let acked = post(&state, "key-a", plain).await;
    std::assert!(acked.get("error").is_none(), "{acked}");
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "failed", "{settled}");
    std::assert_eq!(
        settled.pointer("/result/error/code"),
        Some(&json!(-32021)),
        "{settled}"
    );
}
