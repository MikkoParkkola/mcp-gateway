// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R2h (MIK-8202.AC.16, AC.2): a read queued behind a worker whose settle is
//! waiting out a store clock before 1970.
use super::*;

use std::future::{Future, ready};
use std::ops::ControlFlow;

use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::test_wait::HANG_BOUND;

fn task_store(state: &Arc<AppState>) -> &crate::gateway::task_service::TaskStore {
    &state.task_executor.service.store
}

/// Poll `holds` until it is true, failing after [`HANG_BOUND`].
async fn within_hang_bound<F, Fut>(what: &str, mut holds: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let waited = crate::test_wait::wait_until(HANG_BOUND, || {
        let done = holds();
        async move {
            if done.await {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(format!("{what}: not yet"))
            }
        }
    })
    .await;
    if let Err(last) = waited {
        panic!("{what} did not happen within {HANG_BOUND:?} ({last})");
    }
}

/// R2h, MIK-8202 P4a lead ruling B: the worker following an upstream job
/// holds the record's query lease through its settle, including a settle
/// that waits for a readable clock. GIVEN that wait is in progress, WHEN the
/// owner's `tasks/get` queues behind the lease and the clock then reads,
/// THEN the queued read serves the worker's committed outcome and asks the
/// peer nothing, the task has exactly one `task_recovery` record, and the
/// backend sees no further `tools/call`.
///
/// Stated limit (the ruling): a queued read of that one record waits up to
/// the task's ttl behind a dark-clock settle. The invariants above are what
/// that limit buys.
///
/// Mutant M2j, "lease released before the settle": the queued read takes the
/// free slot, finds the row still `working` and queries the peer, so the peer
/// is asked one more time (the query count), and its own settlement writes a
/// second `task_recovery` record (the record count).
#[tokio::test]
async fn r2h_a_read_queued_behind_a_dark_clock_settle_asks_nothing_further() {
    let (state, transport, adapter, _store) = armed_fixture(Script::Hold).await;
    let log_dir = tempfile::tempdir().expect("a log directory");
    let state = with_audit_log(state, &log_dir);
    let executor = Arc::clone(&state.task_executor);

    let id = submit(&state, "mik-8202-r2h").await;
    within_hang_bound("the worker's query held at the barrier", || {
        ready(adapter.queries() >= 1)
    })
    .await;

    // Dark before the terminal answer, so the worker's settle meets it while
    // the worker still holds the lease. Two refusals: it is looping in the
    // clock wait, not past a single stray read.
    let refused = task_store(&state).refused_reads_for_test();
    task_store(&state).set_clock_for_test(chrono::DateTime::from_timestamp(-1, 0));
    adapter.release_all();
    within_hang_bound("the worker's settle waiting on the dark clock", || {
        ready(task_store(&state).refused_reads_for_test() >= refused + 2)
    })
    .await;

    let claims_before = adapter.claims_seen();
    let reader = tokio::spawn({
        let (state, id) = (Arc::clone(&state), id.clone());
        async move { get_task(&state, "key-a", &id).await }
    });
    within_hang_bound("the owner's read reaching its trust check", || {
        ready(adapter.claims_seen() > claims_before)
    })
    .await;
    // Queued: the worker's lease (two clones) plus the reader's one. Or, with
    // the lease gone, the reader's own query: the wait ends either way, and
    // the counts below decide which.
    let (slots, barrier, record) = (&executor, &adapter, &id);
    within_hang_bound(
        "the owner's read queued behind the worker's lease",
        move || async move {
            barrier.queries() >= 2 || slots.query_slot_clones_for_test(record).await == Some(3)
        },
    )
    .await;

    let pending_at_flip = !reader.is_finished();
    task_store(&state).set_clock_for_test(None);
    let fetched = tokio::time::timeout(HANG_BOUND, reader)
        .await
        .expect("the queued read answers once the clock reads")
        .expect("the owner's read must answer");
    let joined = tokio::time::timeout(HANG_BOUND, executor.drain(HANG_BOUND))
        .await
        .expect("the worker settles once the clock reads");
    std::assert!(joined.is_clean(), "the worker must finish: {joined:?}");

    std::assert_eq!(
        adapter.queries(),
        1,
        "the queued read must find the worker's committed outcome and issue NO further \
         terminal query; the peer was asked {} times (M2j: the lease was released \
         before the settle, and the read queried the peer one more time)",
        adapter.queries()
    );
    let recovery_records = recovery_records(&log_dir);
    std::assert_eq!(
        recovery_records.len(),
        1,
        "exactly one `task_recovery` record per recovered task: {recovery_records:?}"
    );
    std::assert_eq!(
        recovery_records[0]["task_id"],
        json!(id),
        "{recovery_records:?}"
    );
    std::assert_eq!(
        transport.calls(),
        1,
        "one dispatch, and no further backend `tools/call`"
    );
    std::assert_eq!(
        status_of(&fetched),
        "completed",
        "the queued read serves the worker's committed outcome: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/structuredContent/marker"),
        Some(&json!("upstream-answered")),
        "the committed outcome is the backend's output: {fetched}"
    );
    std::assert!(
        pending_at_flip,
        "the read was still queued when the clock was made readable: it answered \
         after the flip, not before"
    );
}

/// `state` with a best-effort transparency log in `log_dir`, the sink the
/// `task_recovery` records are counted from.
fn with_audit_log(state: Arc<AppState>, log_dir: &tempfile::TempDir) -> Arc<AppState> {
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: log_dir
            .path()
            .join("audit.jsonl")
            .to_string_lossy()
            .into_owned(),
        key_id: "r2h".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log")
    .with_failure_policy(AuditFailurePolicy::BestEffort);
    let mut app = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture state is exclusive"));
    let mut meta =
        Arc::try_unwrap(app.meta_mcp).unwrap_or_else(|_| panic!("fixture meta is exclusive"));
    meta.enable_transparency_log(Arc::new(log));
    app.meta_mcp = Arc::new(meta);
    Arc::new(app)
}

/// The `task_recovery` records the log in `log_dir` holds.
fn recovery_records(log_dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(log_dir.path().join("audit.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["route"] == "task_recovery")
        .collect()
}
