// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7311.LIFECYCLE.1 increment 1b: ownership, capacity, expiry and races of
//! the input round on `POST /mcp`. Each test names the mutant it must fail on.

use super::super::*;
use super::input_round::*;
use super::support::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::time::timeout;

/// What a race test stretches the produce-seam wait to: past [`HANG_GUARD`],
/// so an update that waited it out fails the test instead of passing slowly.
const STRETCHED_WAIT: Duration = Duration::from_secs(60);
const HANG_GUARD: Duration = Duration::from_secs(30);

/// Holds the producing worker right after it committed `input_required`, so
/// the worker still owns the task's handoff. Holds once.
struct ProducerHold {
    armed: AtomicBool,
    arrived: tokio::sync::mpsc::UnboundedSender<()>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl crate::gateway::task_service::CommitObserver for ProducerHold {
    async fn reached(&self, stage: crate::gateway::task_service::CommitStage, _task_id: &str) {
        if stage == crate::gateway::task_service::CommitStage::InputRequired
            && self.armed.swap(false, Ordering::SeqCst)
        {
            let _ = self.arrived.send(());
            self.release
                .acquire()
                .await
                .expect("hold semaphore stays open")
                .forget();
        }
    }
}

struct Producer {
    arrived: tokio::sync::mpsc::UnboundedReceiver<()>,
    release: Arc<tokio::sync::Semaphore>,
}

impl Producer {
    async fn wait(&mut self) {
        tokio::time::timeout(Duration::from_secs(10), self.arrived.recv())
            .await
            .expect("the producer committed an input round")
            .expect("the observer is alive");
    }

    fn let_go(&self) {
        self.release.add_permits(1);
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        self.release.add_permits(1);
    }
}

fn hold_producer(state: &Arc<AppState>) -> Producer {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let observer = Arc::new(ProducerHold {
        armed: AtomicBool::new(true),
        arrived: tx,
        release: Arc::clone(&release),
    });
    state
        .task_executor
        .observe_commits(observer as Arc<dyn crate::gateway::task_service::CommitObserver>);
    Producer {
        arrived: rx,
        release,
    }
}

fn completing(id: i64, task: &str) -> Value {
    update(id, task, json!({ "confirm": answer() }))
}

async fn cancel(state: &Arc<AppState>, task: &str) -> Value {
    post(
        state,
        "key-a",
        task_method(90, "tasks/cancel", json!({ "taskId": task })),
    )
    .await
}

/// Mutant: no wait on `released` (the producer still owns the handoff when
/// the round becomes visible). A second task settling meanwhile wakes the
/// waiter spuriously; it must re-check its own id and keep waiting.
#[tokio::test]
async fn an_update_sent_the_instant_the_round_is_visible_succeeds() {
    let mock = MockBackend::answering(Answer::Sequence(vec![
        ask("confirm", STATE_1),
        done(),
        done(),
    ]));
    let (state, _store) = state_with(&mock).await;
    let mut producer = hold_producer(&state);
    let id = task_id(&post(&state, "key-a", create(1, "seam-a")).await);
    producer.wait().await;
    let visible = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&visible), "input_required", "{visible}");

    let started = tokio::time::Instant::now();
    let racing = {
        let (state, id) = (Arc::clone(&state), id.clone());
        tokio::spawn(async move { post(&state, "key-a", completing(2, &id)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    // A second live task settles while the update waits: one global
    // `released` wake that is not this task's.
    let other = task_id(&post(&state, "key-a", create(3, "seam-b")).await);
    let other = poll_until_terminal(&state, "key-a", &other).await;
    assert_carries_the_backend_result(&other);
    tokio::time::sleep(Duration::from_millis(100)).await;
    producer.let_go();

    let mut acked = racing.await.expect("the update task joins");
    // An update waits at most one second for the producer (`PRODUCE_SEAM_WAIT`)
    // and then answers "task busy, retry" with the round still open. On a slow
    // runner the steps above can outlast that bound, and the seam is then not
    // what ran; the retry the answer asks for must still succeed. Inside the
    // bound the first answer must succeed.
    let outran_the_bound = started.elapsed() >= Duration::from_millis(900);
    if outran_the_bound
        && acked.pointer("/error/message").and_then(Value::as_str) == Some("task busy, retry")
    {
        let still_open = get_task(&state, "key-a", &id).await;
        std::assert_eq!(status_of(&still_open), "input_required", "{still_open}");
        acked = post(&state, "key-a", completing(4, &id)).await;
    }
    std::assert!(
        acked.get("error").is_none(),
        "the seam update succeeds: {acked}"
    );
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    assert_carries_the_backend_result(&settled);
    std::assert_eq!(mock.calls(), 3);
}

/// Mutants: CAS removed from the transition (two resumes); overwrite-on-insert
/// handoff (cancel misses the winner); loser takes the timeout path (-32603).
#[tokio::test]
async fn two_completing_updates_make_one_resume_and_the_winner_stays_cancellable() {
    let (mock, mut gate) =
        MockBackend::holding(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    let mut producer = hold_producer(&state);
    let id = task_id(&post(&state, "key-a", create(1, "race-two")).await);
    gate.wait_for_dispatch().await;
    gate.release();
    producer.wait().await;

    let spawn_update = |n: i64| {
        let (state, id) = (Arc::clone(&state), id.clone());
        tokio::spawn(async move { post(&state, "key-a", completing(n, &id)).await })
    };
    let (first, second) = (spawn_update(2), spawn_update(3));
    tokio::time::sleep(Duration::from_millis(100)).await;
    producer.let_go();

    // The winner's resume reaches the backend and is held there past the
    // 1 s produce-seam wait.
    gate.wait_for_dispatch().await;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let answers = [first.await.expect("joins"), second.await.expect("joins")];
    let accepted = answers.iter().filter(|a| a.get("error").is_none()).count();
    let refused: Vec<_> = answers.iter().filter_map(error_code).collect();
    std::assert_eq!(accepted, 1, "exactly one update resumes: {answers:?}");
    std::assert_eq!(
        refused,
        vec![-32602],
        "the loser is told no round is outstanding: {answers:?}"
    );

    let cancelled = cancel(&state, &id).await;
    std::assert!(cancelled.get("error").is_none(), "{cancelled}");
    gate.release_all();
    settle_quiet().await;
    let after = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&after),
        "cancelled",
        "cancel reached the one worker: {after}"
    );
    std::assert_eq!(mock.calls(), 2, "exactly one resume dispatch");
}

/// An update losing to a running resume is refused at once: the row already
/// reads `working`, so the route refuses it before the executor
/// (`task_route.rs`), and it never reaches the produce-seam wait. The wait
/// applied regardless of row state is caught by the parked loser below, the
/// one path where the row moves while an update waits.
#[tokio::test]
async fn an_update_losing_to_a_running_resume_is_refused_at_once() {
    let (mock, mut gate) =
        MockBackend::holding(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    state
        .task_executor
        .stretch_produce_seam_wait_for_test(STRETCHED_WAIT);
    let id = task_id(&post(&state, "key-a", create(1, "race-lost")).await);
    gate.wait_for_dispatch().await;
    gate.release();
    wait_input_required(&state, &id).await;

    let won = post(&state, "key-a", completing(2, &id)).await;
    std::assert!(won.get("error").is_none(), "{won}");
    gate.wait_for_dispatch().await;

    // The wait outlasts the hang guard, so a lost race that waited for the
    // owner does not answer inside it.
    let lost = timeout(HANG_GUARD, post(&state, "key-a", completing(3, &id)))
        .await
        .expect("a lost race is refused without the produce-seam wait");
    gate.release_all();
    std::assert_eq!(error_code(&lost), Some(-32602), "{lost}");
}

/// MIK-7662 (`GH2417.1`, `GH2417.2`). Mutants: no wake when the resume commits
/// `working`; the wake sent before the write commits.
///
/// The loser parks while the winner owns the handoff and its write is held.
/// The winner keeps the handoff through the resume, whose backend call is
/// held too, so nothing but the commit itself can wake the loser. Its wait is
/// stretched past the hang guard, so it answers inside the guard only if the
/// commit wakes it: the oracle is an outcome, not an elapsed time (MIK-8222).
///
/// Current-thread runtime on purpose: the loser subscribes, fails to take the
/// handoff and reads the row with no await in between, so once this task sees
/// the subscriber the loser has already read `input_required` and parked.
#[tokio::test]
async fn a_loser_parked_behind_a_resume_answers_when_the_resume_commits() {
    let (mock, mut gate) =
        MockBackend::holding(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let (state, _store) = state_with(&mock).await;
    state
        .task_executor
        .stretch_produce_seam_wait_for_test(STRETCHED_WAIT);
    let id = task_id(&post(&state, "key-a", create(1, "wake-a")).await);
    gate.wait_for_dispatch().await;
    gate.release();
    wait_input_required(&state, &id).await;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let release_rx = std::sync::Mutex::new(release_rx);
    let armed = AtomicBool::new(true);
    // One shot: the resumed call's own writes later pass straight through.
    let barrier: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        if armed.swap(false, Ordering::SeqCst) {
            let _ = entered_tx.send(());
            // A barrier never released fails the winner's write, and the
            // test with it, instead of passing a stall off as a slow write.
            release_rx
                .lock()
                .expect("release lock")
                .recv_timeout(Duration::from_secs(5))
                .expect("the test releases the barrier");
        }
    });
    state.task_executor.barrier_on_record_write(barrier).await;

    let spawn_update = |n: i64| {
        let (state, id) = (Arc::clone(&state), id.clone());
        tokio::spawn(async move { post(&state, "key-a", completing(n, &id)).await })
    };
    let winner = spawn_update(2);
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(10)))
        .await
        .expect("joins")
        .expect("the winner's write reached the barrier");
    let held = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&held), "input_required", "{held}");
    // Nothing else waits on the release signal here, so the next subscriber
    // can only be the loser.
    std::assert_eq!(state.task_executor.release_waiters_for_test(), 0);

    let loser = spawn_update(3);
    // The winner's own subscription ended when it took the handoff, so a
    // subscriber now is the loser parked in its wait.
    let parked_by = tokio::time::Instant::now() + Duration::from_secs(10);
    while state.task_executor.release_waiters_for_test() == 0 {
        std::assert!(tokio::time::Instant::now() < parked_by, "the loser parks");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    release_tx.send(()).expect("the barrier is waiting");
    let lost = timeout(HANG_GUARD, loser)
        .await
        .expect("the loser answers when the resume commits, not at the end of its wait")
        .expect("the loser joins");
    std::assert_eq!(error_code(&lost), Some(-32602), "{lost}");
    let won = winner.await.expect("the winner joins");
    std::assert!(won.get("error").is_none(), "{won}");
    // Only now does the resumed call reach the backend and settle.
    gate.wait_for_dispatch().await;
    gate.release_all();
    assert_carries_the_backend_result(&poll_until_terminal(&state, "key-a", &id).await);
}

pub(super) async fn state_with_config(
    mock: &Arc<MockBackend>,
    config: crate::config::Config,
) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) =
        test_router_app_state_with_auth_and_config(&two_principal_auth(), config).await;
    register(&state, BACKEND, mock);
    (state, store)
}

/// Mutant: CAS before permit acquisition (the task would move to `working`
/// with no worker to run it).
#[tokio::test]
async fn a_resume_with_the_pool_full_is_refused_and_the_round_stays_open() {
    let (mock, mut gate) = MockBackend::holding(Answer::Sequence(vec![
        ask("confirm", STATE_1),
        done(),
        done(),
    ]));
    let mut config = crate::config::Config::default();
    config.tasks.max_workers = 1;
    let (state, _store) = state_with_config(&mock, config).await;

    let parked_id = task_id(&post(&state, "key-a", create(1, "pool-a")).await);
    gate.wait_for_dispatch().await;
    gate.release();
    wait_input_required(&state, &parked_id).await;
    // The producer returns its permit just after the round is visible.
    settle_quiet().await;
    // The only worker is now busy with another task.
    let busy = task_id(&post(&state, "key-a", create(2, "pool-b")).await);
    gate.wait_for_dispatch().await;

    let refused = post(&state, "key-a", completing(3, &parked_id)).await;
    std::assert_eq!(error_code(&refused), Some(-32603), "{refused}");
    std::assert_eq!(
        refused.pointer("/error/message").and_then(Value::as_str),
        Some("task worker pool is full, retry"),
        "{refused}"
    );
    let after = get_task(&state, "key-a", &parked_id).await;
    std::assert_eq!(status_of(&after), "input_required", "{after}");
    std::assert!(
        after.pointer("/result/inputRequests/confirm").is_some(),
        "the answers were not applied: {after}"
    );

    gate.release();
    poll_until_terminal(&state, "key-a", &busy).await;
    // The worker returns its permit just after it settles, so the terminal
    // status is visible a moment before the pool has room: a refusal that
    // still says "pool is full" is the retry the error asks for, bounded.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut retried = post(&state, "key-a", completing(4, &parked_id)).await;
    while retried.pointer("/error/message").and_then(Value::as_str)
        == Some("task worker pool is full, retry")
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        retried = post(&state, "key-a", completing(4, &parked_id)).await;
    }
    std::assert!(
        retried.get("error").is_none(),
        "a retry after the pool frees resumes: {retried}"
    );
    gate.wait_for_dispatch().await;
    gate.release_all();
    let settled = poll_until_terminal(&state, "key-a", &parked_id).await;
    assert_carries_the_backend_result(&settled);
}

/// Mutant: expiry skips `input_required` rows.
#[tokio::test]
async fn an_input_round_past_its_ttl_is_cancelled_by_the_expiry_pass() {
    let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
    let mut config = crate::config::Config::default();
    config.tasks.default_ttl_ms = 600;
    let (state, _store) = state_with_config(&mock, config).await;
    let _sweep = state
        .task_executor
        // The cancelled row lives one interval before the next pass deletes it;
        // a slow runner must not out-stall that window between two polls.
        .start_expiry(Duration::from_millis(1000))
        .expect("a non-zero interval starts the sweep");
    let id = parked(&state, "expiry-round").await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let seen = get_task(&state, "key-a", &id).await;
        if status_of(&seen) == "cancelled" {
            // #2429: the sweep says why it closed the round.
            let why = seen
                .pointer("/result/statusMessage")
                .and_then(Value::as_str);
            std::assert!(why.is_some_and(|why| why.contains("TTL")), "{seen}");
            break;
        }
        std::assert_eq!(
            status_of(&seen),
            "input_required",
            "an expiring round is cancelled before it is deleted: {seen}"
        );
        std::assert!(
            tokio::time::Instant::now() < deadline,
            "never expired: {seen}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let late = post(&state, "key-a", completing(2, &id)).await;
    std::assert!(
        late.get("error").is_some(),
        "an expired round takes no answers: {late}"
    );
    std::assert_eq!(mock.calls(), 1);
}

/// Mutants: a resume spawned without `cancel_rx`; a state-only round that
/// spawns a second worker.
#[tokio::test]
async fn cancel_aborts_a_worker_resuming_a_state_only_round() {
    let (mock, mut gate) =
        MockBackend::holding(Answer::Sequence(vec![state_only("s-held"), done()]));
    let (state, _store) = state_with(&mock).await;
    let id = task_id(&post(&state, "key-a", create(1, "state-cancel")).await);
    gate.wait_for_dispatch().await;
    gate.release();
    // The worker's own resume of the state-only round, held in the backend.
    gate.wait_for_dispatch().await;
    let working = get_task(&state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&working),
        "working",
        "a state-only loop stays working: {working}"
    );

    let cancelled = cancel(&state, &id).await;
    std::assert!(cancelled.get("error").is_none(), "{cancelled}");
    gate.release_all();
    settle_quiet().await;
    let after = get_task(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&after), "cancelled", "{after}");
    std::assert_eq!(mock.calls(), 2);
}

/// A completing update whose request is dropped mid-flight never leaves the
/// task `working` with no worker: the round is either still open or it is
/// resumed to the backend's answer. Mutant: the completing write awaited on
/// the request future, with the spawn after it.
#[tokio::test]
async fn a_dropped_completing_update_never_strands_the_task() {
    for delay_us in [0_u64, 200, 1_000, 5_000] {
        let mock = MockBackend::answering(Answer::Sequence(vec![ask("confirm", STATE_1), done()]));
        let (state, _store) = state_with(&mock).await;
        let id = parked(&state, &format!("dropped-{delay_us}")).await;
        let _ = tokio::time::timeout(
            Duration::from_micros(delay_us),
            post(&state, "key-a", completing(2, &id)),
        )
        .await;
        settle_quiet().await;
        let current = get_task(&state, "key-a", &id).await;
        if status_of(&current) == "input_required" {
            continue;
        }
        let settled = poll_until_terminal(&state, "key-a", &id).await;
        assert_carries_the_backend_result(&settled);
    }
}
