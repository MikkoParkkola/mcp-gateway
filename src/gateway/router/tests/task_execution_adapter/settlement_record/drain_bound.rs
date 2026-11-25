// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker join under a host stall: its bound counts runtime time, not
//! wall time, and a worker that never finishes still fails it.
use super::*;

/// A host that stalls for twice the join's bound before the worker can
/// finish still joins clean. The stall runs on the blocking pool, which
/// keeps a paused clock from moving, so only real progress ends the wait.
#[tokio::test]
async fn flake1_a_stall_past_the_join_bound_still_joins_clean() {
    let fx = fixture(
        Setup::answering(Terminal::Completed(result_naming_cust9(""))),
        Path::Worker,
    )
    .await;
    let id = fx.submit("min1-settlement-flake1").await;
    // Premise: the worker is parked on its query, holding its permit.
    fx.recovery.wait_for_queries(1).await;
    let stall = tokio::task::spawn_blocking({
        let recovery = Arc::clone(&fx.recovery);
        move || {
            std::thread::sleep(Duration::from_secs(10));
            recovery.release_all();
        }
    });
    join_workers(&fx.state).await;
    stall.await.expect("the stalling thread returns");

    let fetched = get_task(&fx.state, "key-a", &id).await;
    std::assert_eq!(status_of(&fetched), "completed", "{fetched}");
    std::assert_eq!(fx.recovery.queries(), 1, "one upstream query, no retry");
    let record = fx.only_settlement(Path::Worker);
    std::assert_eq!(record["task_id"], json!(id), "{record}");
}

/// A worker that is never released still fails the join, naming the one
/// permit it holds.
#[tokio::test]
async fn flake2_a_worker_never_released_fails_the_join() {
    let fx = fixture(
        Setup::answering(Terminal::Completed(result_naming_cust9(""))),
        Path::Worker,
    )
    .await;
    let _id = fx.submit("min1-settlement-flake2").await;
    fx.recovery.wait_for_queries(1).await;
    std::assert_eq!(
        join_panic(join_workers(&fx.state)).await,
        "the worker must finish: DrainOutcome { timed_out: true, acquired: 1 }"
    );
}
