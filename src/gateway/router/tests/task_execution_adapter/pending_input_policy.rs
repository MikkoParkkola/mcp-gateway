// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2466 — a task parked on an input round shows what the backend asked. That
//! is backend output, so it faces the current invocation policy before it is
//! delivered, as a stored result does (#2450). Test plan: R1-R5 red on the
//! base, G1 and C1 base-green regressions.
use super::super::*;
use super::input_round::{STATE_1, answer, ask, done, parked, update, wait_input_required};
use super::stored_result_policy::{assert_refused, code_mode_call, strip_targets, withhold};
use super::support::*;

/// The backend's question text (`ask`).
const QUESTION: &str = "confirm?";

/// A backend that asks first, then answers the resume.
fn asking() -> Arc<MockBackend> {
    MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]))
}

/// Nothing the backend asked is anywhere in `body`, error data included.
fn assert_no_question(body: &Value) {
    let text = body.to_string();
    assert!(
        !text.contains(QUESTION) && !text.contains("inputRequests"),
        "the backend's question must not be delivered: {body}"
    );
}

/// A one-step `gateway_execute` chain from a client that can be asked.
fn chain(id: i64, key: &str) -> Value {
    declaring_elicitation(code_mode_call(id, key))
}

/// A chain parked on its step's question, with that call recorded at park.
async fn parked_chain(state: &Arc<AppState>, key: &str) -> String {
    let created = post(state, "key-a", chain(1, key)).await;
    let id = task_id(&created);
    let waiting = wait_input_required(state, &id).await;
    assert!(
        waiting.pointer("/result/inputRequests/confirm").is_some(),
        "the chain's round shows the step's question: {waiting}"
    );
    let targets = state.task_executor.service.store.targets_for_test(&id);
    assert!(
        targets
            .iter()
            .any(|t| t.server == BACKEND && t.tool == TOOL),
        "the plan's call is recorded when the round parks: {targets:?}"
    );
    id
}

/// Undo `withhold`: the clean listing, in the same backend scope.
fn restore(state: &Arc<AppState>) {
    let backend = state.backends.get(BACKEND).expect("the mock is registered");
    let clean =
        json!({"name": TOOL, "description": "Reads a file.", "inputSchema": {"type": "object"}});
    let _ = backend.remember_listed_tools(None, false, &[clean]);
    assert!(
        backend.blocked_tool_refusal(None, TOOL).is_none(),
        "the block is cleared"
    );
}

/// R1: a parked direct call is not shown once its tool is withheld.
#[tokio::test]
async fn a_parked_call_is_refused_on_get_once_its_tool_is_withheld() {
    let mock = asking();
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "x2466-r1").await;

    withhold(&state, TOOL);
    let fetched = get_task(&state, "key-a", &id).await;

    assert_refused(&fetched, "withheld");
    assert_no_question(&fetched);
}

/// R2: a parked plan is judged by the call recorded at park.
#[tokio::test]
async fn a_parked_chain_is_refused_on_get_once_its_step_is_withheld() {
    let mock = asking();
    let (state, _store) = state_with(&mock).await;
    let id = parked_chain(&state, "x2466-r2").await;

    withhold(&state, TOOL);
    let fetched = get_task(&state, "key-a", &id).await;

    assert_refused(&fetched, "withheld");
    assert_no_question(&fetched);
}

/// R3: a repeat of a parked chain that has no recorded provenance is refused
/// by the stored-delivery check itself: nothing is withheld, so the repeat's
/// own request-side check passes.
#[tokio::test]
async fn a_repeat_of_a_parked_chain_without_provenance_is_refused() {
    let mock = asking();
    let (state, _store) = state_with(&mock).await;
    let id = parked_chain(&state, "x2466-r3").await;
    strip_targets(&state, &id);

    let repeat = post(&state, "key-a", chain(2, "x2466-r3")).await;

    assert_refused(&repeat, "no recorded provenance");
    assert_no_question(&repeat);
    std::assert_eq!(mock.calls(), 1, "no second dispatch: {:?}", mock.seen());
}

/// R4: a refusal changes nothing. Once the tool is listed cleanly again, the
/// same round is shown and can be answered to completion.
#[tokio::test]
async fn a_refused_round_is_shown_and_answerable_once_policy_admits_it_again() {
    let mock = asking();
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "x2466-r4").await;

    withhold(&state, TOOL);
    let refused = get_task(&state, "key-a", &id).await;
    assert_refused(&refused, "withheld");
    assert_no_question(&refused);

    restore(&state);
    let shown = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&shown), "input_required", "{shown}");
    assert!(
        shown.pointer("/result/inputRequests/confirm").is_some(),
        "the same round is outstanding: {shown}"
    );
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    assert!(
        acked.get("error").is_none(),
        "the answer is accepted: {acked}"
    );
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
    std::assert_eq!(
        mock.calls(),
        2,
        "one dispatch and one resume: {:?}",
        mock.seen()
    );
}

/// R5: a parked chain written before targets were recorded has no provenance.
#[tokio::test]
async fn a_parked_chain_without_provenance_is_refused_on_get() {
    let mock = asking();
    let (state, _store) = state_with(&mock).await;
    let id = parked_chain(&state, "x2466-r5").await;
    strip_targets(&state, &id);

    let fetched = get_task(&state, "key-a", &id).await;

    assert_refused(&fetched, "no recorded provenance");
    assert_no_question(&fetched);
}

/// G1: a repeat of a parked direct call is refused by its own request-side
/// check once the tool is withheld, and nothing is dispatched again.
#[tokio::test]
async fn a_repeat_of_a_parked_call_is_refused_once_its_tool_is_withheld() {
    let mock = asking();
    let (state, _store) = state_with(&mock).await;
    parked(&state, "x2466-g1").await;

    withhold(&state, TOOL);
    let repeat = post(&state, "key-a", super::input_round::create(2, "x2466-g1")).await;

    assert_refused(&repeat, "withheld");
    assert_no_question(&repeat);
    std::assert_eq!(mock.calls(), 1, "no second dispatch: {:?}", mock.seen());
}

/// C1: with nothing withheld, a repeat is still the same parked task (X12).
#[tokio::test]
async fn a_repeat_of_a_parked_call_is_the_same_task_when_nothing_is_withheld() {
    let mock = asking();
    let (state, _store) = state_with(&mock).await;
    let id = parked(&state, "x2466-c1").await;

    let repeat = post(&state, "key-a", super::input_round::create(2, "x2466-c1")).await;

    std::assert_eq!(task_id(&repeat), id, "{repeat}");
    assert!(
        repeat.to_string().contains(QUESTION),
        "the same round: {repeat}"
    );
    std::assert_eq!(mock.calls(), 1, "no second dispatch: {:?}", mock.seen());
}
