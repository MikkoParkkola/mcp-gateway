// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8204 (AUDIT-ORDER.2, .3; test plan t4): before `spawn_worker` spawns a
//! worker, every grant decision in the open slot is appended, and the append
//! has completed. Every row runs on `#[tokio::test]`'s current-thread
//! runtime, so the S1-S4 seams (thread-locals) see only this row, and a
//! caller that spawns without waiting reaches `spawn_worker` before the row
//! can observe the hold.
use std::time::Duration;

use super::super::*;
use super::grant_decisions::{armed, personal_invoke, signing, with_nonce};
use super::support::*;

use crate::gateway::meta_mcp::grant_audit::seams::{
    Inject, appends_for_test, fail_append_at_for_test, hold_next_write_for_test,
    inject_note_for_test, worker_spawns_for_test,
};
use crate::gateway::meta_mcp::grant_audit_fixture::{decisions, invocations, trace_of};
use crate::security::audit::AuditFailurePolicy;

const BOUND: Duration = Duration::from_secs(5);

fn as_task(mut body: Value, key: &str) -> Value {
    body["params"]["task"] = json!({});
    keyed(body, key)
}

fn signed_task(key: &str) -> Value {
    as_task(with_nonce(personal_invoke(1)), key)
}

fn spawns() -> usize {
    worker_spawns_for_test().len()
}

fn committed(state: &Arc<AppState>) -> usize {
    state.task_executor.service.store.committed_count_for_test()
}

fn code(body: &Value) -> Option<i64> {
    body.pointer("/error/code").and_then(Value::as_i64)
}

/// Records naming `(server, tool)`, as an injected note writes them.
fn named<'a>(records: &'a [Value], (server, tool): (&str, &str)) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|r| r["capability"] == json!(server) && r["tool"] == json!(tool))
        .collect()
}

fn spawn_post(state: &Arc<AppState>, body: Value) -> tokio::task::JoinHandle<Value> {
    let state = Arc::clone(state);
    tokio::spawn(async move { post(&state, "key-a", body).await })
}

/// O1a. Submission: while the preparation record's write is held, no worker
/// has been spawned. Red on base: there the first write happens after the
/// spawn, so the hold sees a spawned worker. Mutants mFlush, mAwait.
#[tokio::test]
async fn a_signed_task_appends_its_preparation_record_before_its_worker_spawns() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, signing).await;
    let start = spawns();
    let hold = hold_next_write_for_test();
    let request = spawn_post(&row.state, signed_task("o1a"));
    tokio::time::timeout(BOUND, hold.held())
        .await
        .expect("a write reaches the hold");
    std::assert_eq!(
        spawns() - start,
        0,
        "a worker spawned before its cause was appended"
    );
    std::assert_eq!(
        row.endpoint.arrivals(),
        0,
        "the backend ran before its cause was appended"
    );
    hold.release();
    let created = request.await.expect("the request completes");
    let settled = poll_until_terminal(&row.state, "key-a", &task_id(&created)).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
    let records = decisions(&row.dir);
    let invocation = invocations(&row.dir).pop().expect("an invocation record");
    assert_ne!(trace_of(&records[0]), trace_of(&invocation), "{records:#?}");
    std::assert_eq!(trace_of(&records[1]), trace_of(&invocation), "{records:#?}");
}

/// O2a. `FailClosed` submission whose preparation append fails: refused with
/// -32005, nothing spawned, the backend never called, no row committed.
/// Red on base. Mutant mPolicy.
#[tokio::test]
async fn a_failed_preparation_append_refuses_the_task_under_fail_closed() {
    let row = armed(true, false, AuditFailurePolicy::FailClosed, signing).await;
    let (start, rows) = (spawns(), committed(&row.state));
    fail_append_at_for_test(1);
    let (status, answer) = post_full(&row.state, "key-a", signed_task("o2a")).await;
    std::assert_eq!(code(&answer), Some(-32005), "{answer}");
    std::assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    std::assert_eq!(
        spawns() - start,
        0,
        "a worker spawned without its cause on record"
    );
    std::assert_eq!(
        row.endpoint.arrivals(),
        0,
        "the backend ran without its cause on record"
    );
    std::assert_eq!(
        committed(&row.state),
        rows,
        "a task row was committed: {answer}"
    );
}

const FIRST: (&str, &str) = ("o2c-first-server", "o2c-first-tool");

/// O2c. Two notes; the 2nd append (the preparation record) fails. The 1st is
/// in the log, the 2nd is not, and `FailClosed` refuses. Red on base.
#[tokio::test]
async fn a_later_append_failing_in_the_batch_refuses_under_fail_closed() {
    let row = armed(true, false, AuditFailurePolicy::FailClosed, signing).await;
    let (start, rows) = (spawns(), committed(&row.state));
    inject_note_for_test(FIRST.0, FIRST.1, Inject::NextSlotOpen);
    fail_append_at_for_test(2);
    let answer = post(&row.state, "key-a", signed_task("o2c")).await;
    std::assert_eq!(code(&answer), Some(-32005), "{answer}");
    let records = decisions(&row.dir);
    std::assert_eq!(
        named(&records, FIRST).len(),
        1,
        "{FIRST:?} is appended: {records:#?}"
    );
    std::assert_eq!(
        records.len(),
        1,
        "the 2nd note (the preparation of {CAPS_PERSONAL}) is not: {records:#?}"
    );
    std::assert_eq!(spawns() - start, 0);
    std::assert_eq!(row.endpoint.arrivals(), 0);
    std::assert_eq!(committed(&row.state), rows);
}

const CAPS_PERSONAL: &str = "(CAPS, PERSONAL)";

/// O2d. The `BestEffort` companion: the failure is logged, the task runs.
/// Guard: green on base.
#[tokio::test]
async fn a_failed_append_under_best_effort_still_runs_the_task() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, signing).await;
    let (start, rows) = (spawns(), committed(&row.state));
    inject_note_for_test(FIRST.0, FIRST.1, Inject::NextSlotOpen);
    fail_append_at_for_test(2);
    let created = post(&row.state, "key-a", signed_task("o2d")).await;
    let id = task_id(&created);
    std::assert_eq!(spawns() - start, 1, "{created}");
    std::assert_eq!(committed(&row.state), rows + 1, "{created}");
    let settled = poll_until_terminal(&row.state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "{settled}");
}

/// O3. The caller is cancelled while the preparation write is held: the
/// record is still appended exactly once (the write is owned by its own
/// task), and no worker is spawned, so no row is committed. Red on base.
/// Mutants mDropOnCancel, mAwait.
#[tokio::test]
async fn a_cancelled_submission_keeps_its_record_and_spawns_nothing() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, signing).await;
    let (start, rows) = (spawns(), committed(&row.state));
    let hold = hold_next_write_for_test();
    let request = spawn_post(&row.state, signed_task("o3"));
    tokio::time::timeout(BOUND, hold.held())
        .await
        .expect("a write reaches the hold");
    request.abort();
    std::assert!(request.await.is_err(), "the request was cancelled");
    hold.release();
    let deadline = tokio::time::Instant::now() + BOUND;
    while decisions(&row.dir).is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    settle_quiet().await;
    let records = decisions(&row.dir);
    std::assert_eq!(
        records.len(),
        1,
        "the preparation record, once: {records:#?}"
    );
    std::assert_eq!(
        spawns() - start,
        0,
        "a worker spawned for a cancelled submission"
    );
    std::assert_eq!(committed(&row.state), rows, "a row was committed");
}

async fn settle_quiet() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

/// Signals each terminal commit, read where the worker commits it, so the
/// row never reads the task through `tasks/get` (which adds a record).
pub(super) struct Terminal(pub(super) tokio::sync::Notify);

#[async_trait::async_trait]
impl crate::gateway::task_service::CommitObserver for Terminal {
    async fn reached(&self, stage: crate::gateway::task_service::CommitStage, _task_id: &str) {
        if stage == crate::gateway::task_service::CommitStage::Transitioned {
            self.0.notify_one();
        }
    }
}

const AFTER: (&str, &str) = ("o4-after-server", "o4-after-tool");

/// O4. A note before the hand-off (the preparation) and one after it, with
/// distinct identities, are each written once across the early and the
/// request-end flush. Guard: green on base. Mutant mClone.
#[tokio::test]
async fn notes_before_and_after_the_hand_off_are_each_written_once() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, signing).await;
    let terminal = Arc::new(Terminal(tokio::sync::Notify::new()));
    row.state.task_executor.observe_commits(
        Arc::clone(&terminal) as Arc<dyn crate::gateway::task_service::CommitObserver>
    );
    inject_note_for_test(AFTER.0, AFTER.1, Inject::AfterNextSpawn);
    let created = post(&row.state, "key-a", signed_task("o4")).await;
    task_id(&created);
    tokio::time::timeout(BOUND, terminal.0.notified())
        .await
        .expect("the worker commits a terminal state");
    settle_quiet().await;
    let records = decisions(&row.dir);
    let invocation = invocations(&row.dir).pop().expect("an invocation record");
    let worker = records
        .iter()
        .filter(|r| trace_of(r).is_some() && trace_of(r) == trace_of(&invocation))
        .count();
    let after = named(&records, AFTER).len();
    std::assert_eq!(after, 1, "the after-hand-off note, once: {records:#?}");
    std::assert_eq!(worker, 1, "the worker's record, once: {records:#?}");
    std::assert_eq!(
        records.len() - after - worker,
        1,
        "the preparation record, once: {records:#?}"
    );
}

/// O5. An unsigned task's slot is empty at the hand-off: at the moment the
/// worker spawns, no grant append has run and the armed hold has not fired.
/// The capability is public, so no decision is noted at submit either: since
/// MIK-8315 a personal capability's submit-time decision is appended before
/// the spawn (row 4 of `submit_authz_audit`). Guard: green on base.
#[tokio::test]
async fn an_empty_slot_appends_nothing_before_the_spawn() {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, |meta| meta).await;
    row.state.meta_mcp.set_capabilities(
        crate::gateway::meta_mcp::grant_audit_fixture::capability_backend_exposed(
            row.endpoint.port,
            super::grant_decisions::OWNER,
            "public",
        ),
    );
    let (start, appends) = (spawns(), appends_for_test());
    let hold = hold_next_write_for_test();
    // Bounded: an append before the spawn would meet the held write and block
    // the submit, so a regression fails here instead of hanging the suite.
    let created = tokio::time::timeout(
        Duration::from_secs(10),
        post(&row.state, "key-a", as_task(personal_invoke(1), "o5")),
    )
    .await
    .expect("the submit blocked on a held write: an append ran before the spawn");
    task_id(&created);
    let edge = worker_spawns_for_test()
        .get(start)
        .copied()
        .unwrap_or_else(|| panic!("the worker spawned: {created}"));
    std::assert_eq!(edge.appends, appends, "an append ran before the spawn");
    std::assert_eq!(edge.holds_signalled, 0, "a write started before the spawn");
    drop(hold);
}

/// The input-round route with a transparency log under `policy`.
async fn logged_round(
    policy: AuditFailurePolicy,
) -> (Arc<AppState>, tempfile::TempDir, tempfile::TempDir, String) {
    use super::input_round::{STATE_1, ask, done, parked};
    let dir = tempfile::tempdir().expect("a private log directory");
    let sink = crate::gateway::meta_mcp::grant_audit_fixture::logger(&dir, policy);
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        move |mut meta| {
            meta.enable_transparency_log(sink);
            meta
        },
    )
    .await;
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    register(&state, BACKEND, &mock);
    let id = parked(&state, "o1b").await;
    (state, dir, store, id)
}

const RESUME: (&str, &str) = ("o1b-resume-server", "o1b-resume-tool");

/// O1b. Input-round resume: the resuming request's decision is appended
/// before the resume worker spawns. Red on base. Mutant mResume.
#[tokio::test]
async fn a_resume_appends_its_decision_before_the_resume_worker_spawns() {
    use super::input_round::{answer, update};
    let (state, dir, _store, id) = logged_round(AuditFailurePolicy::BestEffort).await;
    inject_note_for_test(RESUME.0, RESUME.1, Inject::NextSlotOpen);
    let hold = hold_next_write_for_test();
    let parked_at = spawns();
    let request = spawn_post(&state, update(2, &id, json!({ "confirm": answer() })));
    tokio::time::timeout(BOUND, hold.held())
        .await
        .expect("a write reaches the hold");
    std::assert_eq!(
        spawns() - parked_at,
        0,
        "the resume worker spawned before its cause"
    );
    hold.release();
    let acked = request.await.expect("the update completes");
    std::assert!(acked.get("error").is_none(), "{acked}");
    std::assert_eq!(spawns() - parked_at, 1, "{acked}");
    std::assert_eq!(named(&decisions(&dir), RESUME).len(), 1);
}

/// O2b. `FailClosed` resume whose append fails: -32005, no resume worker, the
/// round stays parked. Red on base.
#[tokio::test]
async fn a_failed_resume_append_refuses_the_update_under_fail_closed() {
    use super::input_round::{answer, update};
    let (state, _dir, _store, id) = logged_round(AuditFailurePolicy::FailClosed).await;
    inject_note_for_test(RESUME.0, RESUME.1, Inject::NextSlotOpen);
    fail_append_at_for_test(1);
    let parked_at = spawns();
    let (status, answer) = post_full(
        &state,
        "key-a",
        update(2, &id, json!({ "confirm": answer() })),
    )
    .await;
    std::assert_eq!(code(&answer), Some(-32005), "{answer}");
    std::assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{answer}");
    std::assert_eq!(
        spawns() - parked_at,
        0,
        "a resume worker spawned without its cause"
    );
    let task = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&task), "input_required", "{task}");
}
