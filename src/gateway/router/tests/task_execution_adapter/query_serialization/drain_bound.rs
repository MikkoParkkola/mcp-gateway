// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker join and the arrival wait under a host stall: both bounds count
//! runtime time, not wall time, and a missing event still fails them.
use super::*;

/// One submitted task whose worker has reached the adapter `seen` times.
struct Held {
    state: Arc<AppState>,
    adapter: Arc<BarrierRecovery>,
    task: String,
    _dir: crate::gateway::router::tests::FixtureDir,
}

async fn submitted(script: Script, key: &str) -> Held {
    let (state, _peer, adapter, dir) = armed_fixture(script).await;
    let task = submit(&state, key).await;
    Held {
        state,
        adapter,
        task,
        _dir: dir,
    }
}

async fn held(script: Script, key: &str, seen: usize) -> Held {
    let held = submitted(script, key).await;
    held.adapter.wait_for_queries(seen).await;
    held
}

/// Open the adapter's gate from the blocking pool after 20 s of real time:
/// a host stall of twice the arrival bound, started by the row itself just
/// before it waits, so the stall and the bound start together.
fn open_gate_after_a_stall(adapter: &Arc<BarrierRecovery>) -> tokio::task::JoinHandle<()> {
    let adapter = Arc::clone(adapter);
    tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_secs(20));
        adapter.open_gate();
    })
}

impl Held {
    async fn status(&self) -> String {
        status_of(&get_task(&self.state, "key-a", &self.task).await)
    }

    fn asked_once_for_the_peer_handle(&self) {
        std::assert_eq!(self.adapter.queries(), 1, "the worker asked once");
        std::assert_eq!(
            self.adapter.handles(),
            vec![UPSTREAM_HANDLE.to_string()],
            "it asked about the handle the peer issued"
        );
    }
}

/// A host that stalls for twice the join's bound before the held query can
/// answer still joins clean: the stall runs on the blocking pool, which keeps
/// a paused clock from moving.
#[tokio::test]
async fn q_flake1_a_stall_past_the_join_bound_still_joins_clean() {
    let held = held(Script::Hold, "q-drain-bound-stall", 1).await;
    let stall = tokio::task::spawn_blocking({
        let adapter = Arc::clone(&held.adapter);
        move || {
            std::thread::sleep(Duration::from_secs(10));
            adapter.release_all();
        }
    });
    join_workers(&held.state).await;
    stall.await.expect("the stalling thread returns");

    std::assert_eq!(held.status().await, "completed");
    held.asked_once_for_the_peer_handle();
    std::assert_eq!(held.adapter.max_in_flight(), 1, "never two at once");
}

/// A held query that is never released still fails the join, naming the one
/// permit its worker keeps.
#[tokio::test]
async fn q_flake2_a_worker_never_released_fails_the_join() {
    let held = held(Script::Hold, "q-drain-bound-stuck", 1).await;
    std::assert_eq!(
        join_panic(join_workers(&held.state)).await,
        "the worker must finish: DrainOutcome { timed_out: true, acquired: 1 }"
    );
}

/// While the join waits on a held worker, real time moves and tokio time does
/// not. A join left on the real clock fails here whatever its bound, even one
/// longer than any stall the rows above inject.
#[tokio::test]
async fn q_flake3_the_join_waits_on_a_paused_clock() {
    let held = held(Script::Hold, "q-drain-bound-paused", 1).await;
    let mut joined = std::pin::pin!(join_workers(&held.state));
    assert!(
        futures::poll!(joined.as_mut()).is_pending(),
        "the held worker keeps the join open"
    );
    let tokio_then = tokio::time::Instant::now();
    let real_then = std::time::Instant::now();
    while std::time::Instant::now() == real_then {
        std::hint::spin_loop();
    }
    std::assert_eq!(
        tokio::time::Instant::now(),
        tokio_then,
        "tokio time moved while the join waited"
    );
    held.adapter.release_all();
    joined.await;
}

/// A first query counted only after a host stall longer than the arrival bound
/// has still arrived: the stall is on the blocking pool, so a paused clock does
/// not move while it runs.
#[tokio::test]
async fn q_arrival_a_first_query_late_by_a_stall_still_arrives() {
    let held = submitted(Script::GateFirstQuery, "q-arrival-late").await;
    // The wait's deadline is set on its first poll, so take that poll before
    // the stall begins: a descheduled row cannot start its bound late.
    let mut arrived = std::pin::pin!(held.adapter.wait_for_queries(1));
    assert!(
        futures::poll!(arrived.as_mut()).is_pending(),
        "the gate holds the first query"
    );
    let stall = open_gate_after_a_stall(&held.adapter);
    arrived.await;
    stall.await.expect("the stalling thread returns");
    held.asked_once_for_the_peer_handle();
    held.adapter.release_all();
    join_workers(&held.state).await;
    std::assert_eq!(held.status().await, "completed");
}

/// A reader whose claim reaches the adapter only after a host stall longer
/// than the arrival bound has still reached it.
#[tokio::test]
async fn q_arrival_a_reader_claim_late_by_a_stall_still_arrives() {
    let held = held(Script::GateReaderClaim, "q-claim-late", 1).await;
    let claims_before = held.adapter.claims_seen();
    // Only the worker's own claim has passed, ungated, so the gate can hold
    // the reader and nothing else.
    std::assert_eq!(claims_before, 1, "the worker claimed once before querying");
    let reader = tokio::spawn({
        let (state, task) = (Arc::clone(&held.state), held.task.clone());
        async move { get_task(&state, "key-a", &task).await }
    });
    let mut reached = std::pin::pin!(held.adapter.wait_for_claims_after(claims_before));
    assert!(
        futures::poll!(reached.as_mut()).is_pending(),
        "the gate holds the reader's claim"
    );
    let stall = open_gate_after_a_stall(&held.adapter);
    reached.await;
    stall.await.expect("the stalling thread returns");
    std::assert_eq!(
        held.adapter.claims_seen(),
        claims_before + 1,
        "one reader claim"
    );
    held.adapter.release_all();
    let read = reader.await.expect("the reader answers");
    join_workers(&held.state).await;
    std::assert_eq!(status_of(&read), "completed", "{read}");
}

/// Waiting for a second query that never comes still fails the arrival wait,
/// naming how many did arrive.
#[tokio::test]
#[should_panic(expected = "only 1 upstream queries entered the adapter in 10s; 2 were expected")]
async fn q_arrival_a_query_that_never_comes_fails_the_wait() {
    held(Script::Hold, "q-arrival-missing", 2).await;
}
