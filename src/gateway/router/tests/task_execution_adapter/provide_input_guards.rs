// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TaskExecutor::provide_input`'s own refusals, driven directly: the route
//! checks the same facts first, so only a race reaches them over HTTP.
use super::super::*;
use super::input_round::{STATE_1, answer, ask, create, done, parked, update, wait_input_required};
use super::input_round_races::{HANG_GUARD, STRETCHED_WAIT};
use super::support::*;

use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::task_service::host::TaskHost;
use crate::gateway::task_service::{InputOutcome, OwnedCallerContext};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::meta::Declared;

/// The admission principal the route derives for `key-a`.
fn alice() -> String {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@adapter.test".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp.adapter.test".to_string(),
    }
    .stable_actor_id()
}

fn caller(host: TaskHost, owner: &str) -> OwnedCallerContext {
    OwnedCallerContext::new(
        host,
        OwnedRouterAuthorizer::capture(None, None, None),
        None,
        None,
        None,
        None,
        None,
        owner.to_owned(),
        crate::gateway::meta_mcp::Authentication::Anonymous,
        crate::security::audit::CredentialKind::None,
        false,
        Declared::NONE,
        None,
        None,
        None,
    )
}

fn live(state: &Arc<AppState>, owner: &str) -> OwnedCallerContext {
    caller(TaskHost::Http(Arc::downgrade(state)), owner)
}

fn answers(value: &Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().expect("an object")
}

/// Mutant: any of the owner, absence or round-state refusals removed, so a
/// foreign, absent or not-waiting task takes answers.
#[tokio::test]
async fn provide_input_refuses_an_unattributable_foreign_absent_or_not_waiting_task() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let owner = alice();
    let id = parked(&state, "guards-a").await;
    let full = || answers(&json!({ "confirm": answer() }));
    let exec = &state.task_executor;

    let refused = [
        (
            "empty principal",
            exec.provide_input(live(&state, ""), "", &id, full()).await,
        ),
        (
            "foreign principal",
            exec.provide_input(live(&state, "mallory"), "mallory", &id, full())
                .await,
        ),
        (
            "absent task",
            exec.provide_input(live(&state, &owner), &owner, "no-such-task", full())
                .await,
        ),
    ];
    for (why, outcome) in refused {
        assert!(matches!(outcome, InputOutcome::NotFound), "{why}");
    }
    std::assert_eq!(
        status_of(&get_task(&state, "key-a", &id).await),
        "input_required"
    );

    // Positive control: the owner's own request is accepted and the call resumes.
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(acked.get("error").is_none(), "{acked}");
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);

    // A settled task is no longer waiting.
    let settled = exec
        .provide_input(live(&state, &owner), &owner, &id, full())
        .await;
    assert!(matches!(settled, InputOutcome::NotOutstanding));
}

/// Mutant: the record-size refusal removed, so answers past the cap are
/// written or the round is lost.
#[tokio::test]
async fn provide_input_refuses_answers_past_the_record_cap_and_keeps_the_round() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let owner = alice();
    let id = parked(&state, "guards-b").await;
    let revision = state.tasks.get(&owner, &id).expect("parked").revision;
    let big = "x".repeat(600 * 1024);
    let oversized = answers(&json!({ "confirm": { "action": "accept", "content": { "v": big } } }));
    let outcome = state
        .task_executor
        .provide_input(live(&state, &owner), &owner, &id, oversized)
        .await;
    assert!(matches!(outcome, InputOutcome::TooLarge));
    std::assert_eq!(
        status_of(&get_task(&state, "key-a", &id).await),
        "input_required"
    );
    std::assert_eq!(
        state.tasks.get(&owner, &id).expect("parked").revision,
        revision,
        "the refusal wrote nothing"
    );
    std::assert_eq!(mock.calls(), 1, "nothing resumed");

    // Positive control: bounded answers are then accepted and the call resumes.
    let acked = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(acked.get("error").is_none(), "{acked}");
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
}

/// Mutant: an update on a store that cannot be read is reported as accepted
/// or as absent.
#[tokio::test]
async fn provide_input_on_a_closed_store_is_unavailable() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        ask("confirm", STATE_1),
        done(),
        ask("confirm", STATE_1),
        done(),
    ]));
    let (state, _store) = state_with(&mock).await;
    let owner = alice();
    // Positive control: before the shutdown the same kind of request is accepted.
    let first = parked(&state, "guards-c0").await;
    let acked = post(
        &state,
        "key-a",
        update(2, &first, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(acked.get("error").is_none(), "{acked}");
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &first).await);
    let id = parked(&state, "guards-c").await;
    state.tasks.shutdown().await.expect("custody released");
    let outcome = state
        .task_executor
        .provide_input(
            live(&state, &owner),
            &owner,
            &id,
            answers(&json!({ "confirm": answer() })),
        )
        .await;
    assert!(matches!(outcome, InputOutcome::Unavailable));
}

/// Mutant: a resume whose host is gone dispatches anyway, or leaves the task
/// working forever.
#[tokio::test]
async fn a_resume_with_no_live_host_settles_interrupted_and_calls_no_backend() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let owner = alice();
    let id = parked(&state, "guards-d").await;
    let (gone, _gone_store) = fixture_state(&two_principal_auth()).await;
    let host = TaskHost::Http(Arc::downgrade(&gone));
    drop(gone);
    let outcome = state
        .task_executor
        .provide_input(
            caller(host, &owner),
            &owner,
            &id,
            answers(&json!({ "confirm": answer() })),
        )
        .await;
    assert!(matches!(outcome, InputOutcome::Accepted));
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(
        settled.pointer("/result/result/_meta/io.mcp-gateway~1reason"),
        Some(&json!("gateway_interrupted_before_dispatch")),
        "{settled}"
    );
    std::assert_eq!(mock.calls(), 1, "the resume reached no backend");
}

/// MIK-7757. Mutant: the provide-input worker is spawned outside the shutdown
/// token, so answers given after a shutdown cancelled the workers still
/// resume the task and call the backend.
#[tokio::test]
async fn provide_input_after_a_shutdown_cancel_runs_nothing() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let owner = alice();
    let id = parked(&state, "guards-e").await;
    state
        .task_executor
        .cancel_remaining(std::time::Duration::from_secs(1))
        .await;
    let outcome = state
        .task_executor
        .provide_input(
            live(&state, &owner),
            &owner,
            &id,
            answers(&json!({ "confirm": answer() })),
        )
        .await;
    assert!(matches!(outcome, InputOutcome::Unavailable));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    std::assert_eq!(mock.calls(), 1, "nothing resumed after the shutdown");
}

/// An answer that reaches the executor while the row is `working` is refused,
/// even when the resume then asks again and releases the handoff while that
/// update would still be waiting (#3678). The route read the row first, so
/// only this window reaches the executor's own round-state check.
///
/// The update carries round 2's key: a later round cannot reuse an earlier
/// round's key (that round is invalid), so a key-for-key stale round-1 answer
/// is refused by the store anyway.
///
/// Two checks refuse it, and either alone is enough: the executor's own
/// round-state read, and the wait's `keep_waiting` read on its first pass,
/// which returns `Moved` without parking. Mutant: both removed, so the update
/// waits for the handoff and is applied to round 2 when it opens. Removing
/// only the first leaves the outcome unchanged at every input but a commit
/// landing between two back-to-back reads with no await between them, where
/// it answers as for an update an instant later (#3678).
#[tokio::test]
async fn an_answer_sent_while_the_resume_runs_is_not_held_for_the_next_round() {
    let (mock, mut gate) = MockBackend::holding(Answer::Sequence(vec![
        ask("confirm", STATE_1),
        ask("again", "backend-state-2"),
        done(),
    ]));
    let (state, _store) = state_with(&mock).await;
    // Long past the hang guard: an early update that waits for the handoff is
    // still waiting when round 2 opens, never timed out first.
    state
        .task_executor
        .stretch_produce_seam_wait_for_test(STRETCHED_WAIT);
    let owner = alice();
    let id = task_id(&post(&state, "key-a", create(1, "early-answer")).await);
    gate.wait_for_dispatch().await;
    gate.release();
    wait_input_required(&state, &id).await;

    // Round 1 answered: the resume owns the handoff, the row reads `working`,
    // and its backend call is held.
    let won = post(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert!(won.get("error").is_none(), "{won}");
    gate.wait_for_dispatch().await;

    let early = {
        let (state, owner, id) = (Arc::clone(&state), owner.clone(), id.clone());
        tokio::spawn(async move {
            let for_round_2 = answers(&json!({ "again": answer() }));
            state
                .task_executor
                .provide_input(live(&state, &owner), &owner, &id, for_round_2)
                .await
        })
    };
    // Either it was refused at once, or it parked behind the resume.
    let decided_by = tokio::time::Instant::now() + HANG_GUARD;
    while !early.is_finished() && state.task_executor.release_waiters_for_test() == 0 {
        std::assert!(
            tokio::time::Instant::now() < decided_by,
            "the early update neither answered nor parked"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The resume asks again: round 2 opens and the handoff is released.
    gate.release();
    let outcome = tokio::time::timeout(HANG_GUARD, early)
        .await
        .expect("the early update answers")
        .expect("the early update joins");
    std::assert!(
        matches!(outcome, InputOutcome::NotOutstanding),
        "an answer sent while no round was open must not be held for round 2"
    );
    let round_2 = wait_input_required(&state, &id).await;
    std::assert_eq!(status_of(&round_2), "input_required", "{round_2}");
    std::assert_eq!(mock.calls(), 2, "round 2 waits for its own answer");
    gate.release_all();
}
