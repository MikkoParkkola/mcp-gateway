// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2429: an input round closes at its stored continuation's deadline, never
//! resuming into a redemption that must fail. #2430: a resumed call audits the
//! updating request's declared agent label. Each test names its mutant.

use super::super::*;
use super::input_round::*;
use super::input_round_races::state_with_config;
use super::support::*;
use crate::gateway::task_service::CONTINUATION_DEADLINE_MARGIN_SECS;
use std::time::Duration;

fn store(state: &Arc<AppState>) -> &crate::gateway::task_service::TaskStore {
    &state.task_executor.service.store
}

/// Freeze the store's clock at unix second `secs`.
fn clock(state: &Arc<AppState>, secs: u64) {
    let at = chrono::DateTime::from_timestamp(i64::try_from(secs).unwrap(), 0).unwrap();
    store(state).set_clock_for_test(Some(at));
}

fn revision(state: &Arc<AppState>, id: &str) -> u64 {
    store(state).input_round_for_test(id).1
}

/// The deadline the parked round carries.
fn deadline(state: &Arc<AppState>, id: &str) -> u64 {
    let (round, _) = store(state).input_round_for_test(id);
    round
        .expect("the task has an open round")
        .continuation_deadline
        .expect("a round with a stored continuation carries its deadline")
}

fn message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn status_message(body: &Value) -> &str {
    body.pointer("/result/statusMessage")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

async fn parked_round(key: &str) -> (Arc<MockBackend>, Arc<AppState>, tempfile::TempDir, String) {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, dir) = state_with(&mock).await;
    let id = parked(&state, key).await;
    (mock, state, dir, id)
}

/// Mutants: no deadline stored; deadline from park time instead of the
/// envelope; the margin dropped.
#[tokio::test]
async fn the_parked_round_carries_the_envelope_deadline_less_the_margin() {
    let (_mock, state, _dir, id) = parked_round("deadline-recorded").await;
    let (round, _) = store(&state).input_round_for_test(&id);
    let round = round.expect("an open round");
    let token = round.request_state.clone().expect("a stored continuation");
    let sealed = state
        .meta_mcp
        .continuation()
        .keyring()
        .open(&token, crate::protocol::continuation::now_unix_secs())
        .expect("the stored continuation opens with the minting keyring");
    std::assert_eq!(
        round.continuation_deadline,
        Some(sealed.expires_at - CONTINUATION_DEADLINE_MARGIN_SECS),
        "{round:?}"
    );
}

/// Pin: the funnel seals a continuation even when the backend sent no state
/// of its own, so such a round is bounded by a deadline too.
#[tokio::test]
async fn a_round_without_backend_state_still_has_a_deadline() {
    let mut question = ask("confirm", STATE_1);
    question.as_object_mut().unwrap().remove("requestState");
    let mock = MockBackend::answering(Answer::Sequence(vec![question, done()]));
    let (state, _dir) = state_with(&mock).await;
    let id = parked(&state, "deadline-stateless").await;
    let _ = deadline(&state, &id);
}

/// Mutant: the refusal removed (the #2429 symptom: `working`, then `failed`).
#[tokio::test]
async fn a_complete_answer_after_the_deadline_is_refused_and_closes_the_round() {
    let (mock, state, _dir, id) = parked_round("deadline-complete").await;
    let before = revision(&state, &id);
    clock(&state, deadline(&state, &id) + 1);
    let late = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&late), Some(-32602), "{late}");
    std::assert!(message(&late).contains("continuation deadline"), "{late}");
    assert_closed_at_once(&state, &id, before, "continuation deadline").await;
    settle_quiet().await;
    std::assert_eq!(mock.calls(), 1, "a closed round never resumes");
}

/// Mutant: the deadline checked only on the completing branch.
#[tokio::test]
async fn a_partial_answer_after_the_deadline_is_refused_and_closes_the_round() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        ask_many(&["a", "b"], STATE_1),
        done(),
    ]));
    let (state, _dir) = state_with(&mock).await;
    let id = parked(&state, "deadline-partial").await;
    let before = revision(&state, &id);
    clock(&state, deadline(&state, &id) + 1);
    let late = post(&state, "key-a", update(2, &id, json!({ "a": answer() }))).await;
    std::assert_eq!(error_code(&late), Some(-32602), "{late}");
    std::assert!(message(&late).contains("continuation deadline"), "{late}");
    assert_closed_at_once(&state, &id, before, "continuation deadline").await;
}

/// The refused update closed the round in one write, never accepting the
/// answers or moving it to `working`, and the task says why.
async fn assert_closed_at_once(state: &Arc<AppState>, id: &str, before: u64, why: &str) {
    let seen = get_task(state, "key-a", id).await;
    std::assert_eq!(status_of(&seen), "cancelled", "{seen}");
    std::assert!(status_message(&seen).contains(why), "{seen}");
    std::assert_eq!(revision(state, id), before + 1, "one write: the close");
}

/// Control: one second before the deadline the answer is taken and resumes.
/// Mutant (second half): `>` for `>=`, so an answer AT the deadline resumes.
#[tokio::test]
async fn the_deadline_second_itself_is_closed_and_the_one_before_is_open() {
    let (mock, state, _dir, id) = parked_round("deadline-before").await;
    clock(&state, deadline(&state, &id) - 1);
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(acked.get("error").is_none(), "{acked}");
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
    std::assert_eq!(mock.calls(), 2, "the answer before the deadline resumed");

    let (_mock, state, _dir, id) = parked_round("deadline-at").await;
    clock(&state, deadline(&state, &id));
    let at = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&at), Some(-32602), "{at}");
}

/// Poll `tasks/get` until the task is `cancelled`, bounded.
async fn wait_cancelled(state: &Arc<AppState>, id: &str) -> Value {
    let bound = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let seen = get_task(state, "key-a", id).await;
        if status_of(&seen) == "cancelled" {
            return seen;
        }
        std::assert_eq!(status_of(&seen), "input_required", "{seen}");
        std::assert!(
            tokio::time::Instant::now() < bound,
            "never cancelled: {seen}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A round the sweep has settled at its deadline.
async fn swept(
    key: &str,
) -> (
    Arc<MockBackend>,
    Arc<AppState>,
    tempfile::TempDir,
    String,
    u64,
    Value,
) {
    let (mock, state, dir, id) = parked_round(key).await;
    let before = revision(&state, &id);
    let sweep = state
        .task_executor
        .start_expiry(Duration::from_millis(50))
        .expect("the sweep starts");
    clock(&state, deadline(&state, &id));
    let cancelled = wait_cancelled(&state, &id).await;
    drop(sweep);
    (mock, state, dir, id, before, cancelled)
}

/// Mutants: the selector ignores the deadline (the row waits for its TTL);
/// the settlement split into a status write and a cancel write.
#[tokio::test]
async fn the_sweep_cancels_the_round_at_its_deadline_in_one_write_naming_it() {
    let (mock, state, _dir, id, before, cancelled) = swept("deadline-swept").await;
    std::assert!(
        status_message(&cancelled).contains("continuation deadline"),
        "{cancelled}"
    );
    let (round, after) = store(&state).input_round_for_test(&id);
    std::assert!(round.is_none(), "the stored continuation is dropped");
    std::assert_eq!(after, before + 1, "one write settles the round");
    std::assert_eq!(mock.calls(), 1, "a closed round never resumes");
}

/// Mutant: the generic "no round outstanding" answer to a late update.
#[tokio::test]
async fn a_late_update_to_a_cancelled_task_is_told_why() {
    let (_mock, state, _dir, id, _before, _cancelled) = swept("deadline-late").await;
    let late = post(
        &state,
        "key-a",
        update(3, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&late), Some(-32602), "{late}");
    std::assert!(message(&late).contains("cancelled"), "{late}");
    std::assert!(message(&late).contains("continuation deadline"), "{late}");

    let (_mock, state, _dir, id) = parked_round("deadline-client-cancel").await;
    let cancel = task_method(2, "tasks/cancel", json!({ "taskId": id }));
    std::assert!(post(&state, "key-a", cancel).await.get("error").is_none());
    let late = post(
        &state,
        "key-a",
        update(3, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&late), Some(-32602), "{late}");
    std::assert!(message(&late).contains("cancelled"), "{late}");
}

/// Mutant: the refusal checks only the continuation deadline, so a round
/// whose task TTL ran out first still takes answers until the sweep.
#[tokio::test]
async fn an_answer_after_the_task_ttl_is_refused_naming_the_ttl() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let mut config = crate::config::Config::default();
    config.tasks.default_ttl_ms = 60_000;
    let (state, _dir) = state_with_config(&mock, config).await;
    let id = parked(&state, "ttl-refused").await;
    let before = revision(&state, &id);
    let past_ttl = crate::protocol::continuation::now_unix_secs() + 61;
    std::assert!(
        past_ttl < deadline(&state, &id),
        "the TTL closes first here"
    );
    clock(&state, past_ttl);
    let late = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert_eq!(error_code(&late), Some(-32602), "{late}");
    std::assert!(message(&late).contains("TTL"), "{late}");
    assert_closed_at_once(&state, &id, before, "TTL").await;
    std::assert_eq!(mock.calls(), 1);
}

/// Mutant: the resume worker dispatches without re-checking the deadline, so
/// an answer taken just in time but redeemed late settles `failed`.
#[tokio::test]
async fn a_resume_that_reaches_dispatch_past_the_deadline_settles_cancelled() {
    let (mock, state, _dir, id) = parked_round("deadline-resume").await;
    let due = deadline(&state, &id);
    clock(&state, due - 1);
    let late = chrono::DateTime::from_timestamp(i64::try_from(due + 1).unwrap(), 0).unwrap();
    store(&state).set_clock_after_next_resume(late);
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(
        acked.get("error").is_none(),
        "taken before the deadline: {acked}"
    );
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "cancelled", "{settled}");
    std::assert!(
        status_message(&settled).contains("continuation deadline"),
        "{settled}"
    );
    std::assert_eq!(mock.calls(), 1, "never dispatched into a dead continuation");
}

/// Mutant: park ignores a deadline that has already passed, leaving a round
/// that can only fail.
#[tokio::test]
async fn a_round_already_past_its_deadline_at_park_keeps_the_abandoned_result() {
    let (mock, mut gate) =
        MockBackend::holding(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _dir) = state_with(&mock).await;
    let id = task_id(&post(&state, "key-a", create(1, "deadline-at-park")).await);
    gate.wait_for_dispatch().await;
    // Minted after this instant, so its deadline is at most LIFETIME ahead;
    // well inside the one-day default TTL.
    clock(
        &state,
        crate::protocol::continuation::now_unix_secs() + 3_600,
    );
    gate.release_all();
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    std::assert_eq!(
        reason_of(&settled),
        Some("input_round_unavailable"),
        "{settled}"
    );
    std::assert_eq!(mock.calls(), 1);
}

#[derive(Clone, Default)]
struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Answer the parked round (optionally declaring an agent label) and return
/// the `tool invoked` audit events the resume emitted.
///
/// The capture is thread-local and starts after the park, so it sees the
/// resume only: this test runs on a current-thread runtime, where the spawned
/// resume and its invoke run on this thread. The process-wide TRACE registry
/// keeps callsite interest open, as in `agent_identity_audit_tests`.
async fn resumed_invocations(state: &Arc<AppState>, id: &str, label: Option<&str>) -> Vec<Value> {
    crate::test_log_capture::keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let body = update(2, id, json!({ "confirm": answer() }));
    let acked = match label {
        Some(label) => post_with_header(state, "key-a", body, ("x-agent-id", label)).await,
        None => post(state, "key-a", body).await,
    };
    std::assert!(acked.get("error").is_none(), "{acked}");
    let settled = poll_until_terminal(state, "key-a", id).await;
    drop(guard);
    assert_carries_the_backend_result(&settled);
    let bytes = sink.0.lock().unwrap().clone();
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["fields"]["message"] == "tool invoked")
        .collect()
}

/// #2430. Mutants: `RecoveryCaller` never fills the label; `update_caller`
/// passes `None`.
#[tokio::test]
async fn the_resumed_call_audits_the_updating_requests_declared_label() {
    let (_mock, state, _dir, id) = parked_round("label-resume").await;
    let events = resumed_invocations(&state, &id, Some("planner-9")).await;
    std::assert_eq!(events.len(), 1, "exactly the resume: {events:?}");
    std::assert_eq!(
        events[0]["fields"]["agent_declared"],
        "planner-9",
        "{events:?}"
    );
}

/// Control (green before the fix): the label is the UPDATING request's, never
/// the creating one's. Mutant: the label read from the stored context.
#[tokio::test]
async fn a_resume_without_a_label_audits_none_even_if_the_creator_declared_one() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _dir) = state_with(&mock).await;
    let created = post_with_header(
        &state,
        "key-a",
        create(1, "label-creator"),
        ("x-agent-id", "creator-1"),
    )
    .await;
    let id = task_id(&created);
    wait_input_required(&state, &id).await;
    let events = resumed_invocations(&state, &id, None).await;
    std::assert_eq!(events.len(), 1, "exactly the resume: {events:?}");
    std::assert!(
        events[0]["fields"]["agent_declared"].is_null(),
        "{events:?}"
    );
}
