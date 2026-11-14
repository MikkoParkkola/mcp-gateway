// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the restart cancel floor (fake adapters; real owners come later).
//! Every row runs on a paused clock, so deadlines are exact instants.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt as _;
use futures::future::BoxFuture;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::restart_floor::{
    CancelReason, Cancelled, FloorAdapter, FloorFault, FloorOwner, FloorSetupError, FloorStage,
    LateDecision, StopSaveOutcome, StopSaveOwner, all_settled, run_checkpoint, settle_stop_save,
    validate_owners,
};

/// The checkpoint deadline every row gives, and the watchdog past it.
const WINDOW: Duration = Duration::from_secs(10);
const WATCHDOG: Duration = Duration::from_secs(11);

type Log = Arc<Mutex<Vec<String>>>;

/// What a fake's pause or checkpoint does.
#[derive(Clone, Copy)]
enum Step {
    Ok,
    Fail(FloorFault),
    /// Signals `entered`, then never returns.
    Never,
    /// Takes this long on the paused clock, then succeeds.
    Takes(Duration),
    /// Returns at exactly the deadline instant, with this result.
    AtDeadline(Result<(), FloorFault>),
    /// Signals `entered`, then panics on its next poll.
    Panic,
}

struct Fake {
    owner: FloorOwner,
    pause: Step,
    checkpoint: Step,
    log: Log,
    entered: Arc<Notify>,
    late_work: Arc<AtomicBool>,
    deadlines: Arc<Mutex<Vec<Instant>>>,
}

fn step(
    s: Step,
    deadline: Instant,
    entered: Arc<Notify>,
) -> BoxFuture<'static, Result<(), FloorFault>> {
    Box::pin(async move {
        match s {
            Step::Ok => Ok(()),
            Step::Fail(f) => Err(f),
            Step::Never => {
                entered.notify_one();
                std::future::pending().await
            }
            Step::Takes(d) => {
                tokio::time::sleep(d).await;
                Ok(())
            }
            Step::AtDeadline(r) => {
                tokio::time::sleep_until(deadline).await;
                r
            }
            Step::Panic => {
                entered.notify_one();
                tokio::task::yield_now().await;
                panic!("the fake's call panics");
            }
        }
    })
}

impl Fake {
    fn note(&self, what: &str) {
        self.log
            .lock()
            .expect("log")
            .push(format!("{what} {:?}", self.owner));
    }
}

impl FloorAdapter for Fake {
    fn owner(&self) -> FloorOwner {
        self.owner
    }
    fn pause(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        self.note("pause");
        self.deadlines.lock().expect("deadlines").push(deadline);
        step(self.pause, deadline, Arc::clone(&self.entered))
    }
    fn checkpoint(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        self.note("checkpoint");
        self.deadlines.lock().expect("deadlines").push(deadline);
        step(self.checkpoint, deadline, Arc::clone(&self.entered))
    }
    fn resume(&mut self) {
        self.note("resume");
    }
    fn release_for_stop(&mut self) {
        self.note("release");
    }
    fn commit(&mut self) {
        self.note("commit");
    }
    fn settled(&self) -> bool {
        !self.late_work.load(Ordering::SeqCst)
    }
}

/// Shared handles a row reads after the run.
#[derive(Default, Clone)]
struct Seen {
    log: Log,
    entered: Arc<Notify>,
    late_work: Arc<AtomicBool>,
    deadlines: Arc<Mutex<Vec<Instant>>>,
}

const OWNERS: [FloorOwner; 3] = [
    FloorOwner::TaskStore,
    FloorOwner::Config,
    FloorOwner::Health,
];

fn fake(seen: &Seen, owner: FloorOwner, pause: Step, checkpoint: Step) -> Box<dyn FloorAdapter> {
    Box::new(Fake {
        owner,
        pause,
        checkpoint,
        log: Arc::clone(&seen.log),
        entered: Arc::clone(&seen.entered),
        late_work: Arc::clone(&seen.late_work),
        deadlines: Arc::clone(&seen.deadlines),
    })
}

/// The three owners, all succeeding except `odd`, which gets the given steps.
fn three(seen: &Seen, odd: Option<(FloorOwner, Step, Step)>) -> Vec<Box<dyn FloorAdapter>> {
    OWNERS
        .into_iter()
        .map(|o| match odd {
            Some((owner, p, c)) if owner == o => fake(seen, o, p, c),
            _ => fake(seen, o, Step::Ok, Step::Ok),
        })
        .collect()
}

/// How many times each owner got `what`, in owner order.
fn calls(seen: &Seen, what: &str) -> [usize; 3] {
    let log = seen.log.lock().expect("log");
    OWNERS.map(|o| {
        log.iter()
            .filter(|l| **l == format!("{what} {o:?}"))
            .count()
    })
}

fn deadline() -> Instant {
    Instant::now() + WINDOW
}

async fn expect_cancel(adapters: &mut [Box<dyn FloorAdapter>], deadline: Instant) -> Cancelled {
    let run = tokio::time::timeout(WATCHDOG, run_checkpoint(adapters, deadline));
    match run
        .await
        .expect("row watchdog: the run outlived its deadline + 1 s")
    {
        Ok(_) => panic!("the checkpoint certified; a cancel was required"),
        Err(c) => c,
    }
}

fn at(owner: FloorOwner, stage: FloorStage, reason: CancelReason) -> Cancelled {
    Cancelled {
        owner,
        stage,
        reason,
    }
}

/// A pause that never returns is dropped at the deadline,
/// attributed to its owner and stage, and every owner is resumed once.
#[tokio::test(start_paused = true)]
async fn a_pause_that_never_returns_is_dropped_at_the_deadline() {
    let seen = Seen::default();
    let mut a = three(&seen, Some((FloorOwner::Config, Step::Never, Step::Ok)));
    let d = deadline();
    let c = expect_cancel(&mut a, d).await;
    assert_eq!(
        c,
        at(
            FloorOwner::Config,
            FloorStage::Pause,
            CancelReason::DeadlineExceeded
        )
    );
    assert_eq!(Instant::now(), d, "cancelled at the deadline instant");
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
    assert_eq!(calls(&seen, "release"), [0, 0, 0]);
}

/// A pause that returns Ok at the deadline instant is late: the check after the
/// call blames that pause, not the next owner or stage.
#[tokio::test(start_paused = true)]
async fn a_pause_that_returns_at_the_deadline_is_late_at_its_own_stage() {
    let seen = Seen::default();
    let mut a = three(
        &seen,
        Some((FloorOwner::Config, Step::AtDeadline(Ok(())), Step::Ok)),
    );
    let c = expect_cancel(&mut a, deadline()).await;
    assert_eq!(
        c,
        at(
            FloorOwner::Config,
            FloorStage::Pause,
            CancelReason::DeadlineExceeded
        )
    );
    assert_eq!(
        calls(&seen, "pause"),
        [1, 1, 0],
        "no pause after the late one"
    );
}

/// A late Err keeps the adapter's own fault: its report is the more specific.
#[tokio::test(start_paused = true)]
async fn a_late_fault_keeps_its_own_reason() {
    let seen = Seen::default();
    let late = Step::AtDeadline(Err(FloorFault::SaveFailed));
    let mut a = three(&seen, Some((FloorOwner::Config, Step::Ok, late)));
    let c = expect_cancel(&mut a, deadline()).await;
    assert_eq!(
        c,
        at(
            FloorOwner::Config,
            FloorStage::Checkpoint,
            CancelReason::SaveFailed
        )
    );
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
    assert_eq!(calls(&seen, "release"), [0, 0, 0]);
}

/// The same for a checkpoint that never returns.
#[tokio::test(start_paused = true)]
async fn a_checkpoint_that_never_returns_is_dropped_at_the_deadline() {
    let seen = Seen::default();
    let mut a = three(&seen, Some((FloorOwner::Config, Step::Ok, Step::Never)));
    let d = deadline();
    let c = expect_cancel(&mut a, d).await;
    assert_eq!(
        c,
        at(
            FloorOwner::Config,
            FloorStage::Checkpoint,
            CancelReason::DeadlineExceeded
        )
    );
    assert_eq!(Instant::now(), d, "cancelled at the deadline instant");
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
}

/// The deadline is absolute: time an earlier call used is not given back.
#[tokio::test(start_paused = true)]
async fn the_deadline_is_absolute_not_per_call() {
    let seen = Seen::default();
    let mut a = vec![
        fake(
            &seen,
            FloorOwner::TaskStore,
            Step::Takes(Duration::from_secs(6)),
            Step::Ok,
        ),
        fake(&seen, FloorOwner::Config, Step::Ok, Step::Ok),
        fake(&seen, FloorOwner::Health, Step::Ok, Step::Never),
    ];
    let d = deadline();
    let c = expect_cancel(&mut a, d).await;
    assert_eq!(
        c,
        at(
            FloorOwner::Health,
            FloorStage::Checkpoint,
            CancelReason::DeadlineExceeded
        )
    );
    assert_eq!(Instant::now(), d, "at the one deadline, not 6 s past it");
}

/// A checkpoint that returns Ok at the deadline instant still cancels: the window is gone.
#[tokio::test(start_paused = true)]
async fn a_checkpoint_that_returns_at_the_deadline_cancels() {
    let seen = Seen::default();
    let mut a = three(
        &seen,
        Some((FloorOwner::Health, Step::Ok, Step::AtDeadline(Ok(())))),
    );
    let c = expect_cancel(&mut a, deadline()).await;
    assert_eq!(
        c,
        at(
            FloorOwner::Health,
            FloorStage::Checkpoint,
            CancelReason::DeadlineExceeded
        )
    );
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
}

/// Drop the run once a fake signals it is inside the call that never returns.
async fn drop_once_entered(adapters: &mut [Box<dyn FloorAdapter>], seen: &Seen) {
    let run = run_checkpoint(adapters, deadline());
    tokio::pin!(run);
    tokio::select! {
        biased;
        () = seen.entered.notified() => {}
        r = &mut run => panic!("the run ended before the call was entered (certified: {})", r.is_ok()),
    }
}

/// A run dropped mid-checkpoint (a stop signal won)
/// releases every pause for the stop, and resumes none.
#[tokio::test(start_paused = true)]
async fn a_run_dropped_mid_checkpoint_releases_every_pause_for_the_stop() {
    let seen = Seen::default();
    let mut a = three(&seen, Some((FloorOwner::Config, Step::Ok, Step::Never)));
    drop_once_entered(&mut a, &seen).await;
    assert_eq!(calls(&seen, "checkpoint"), [1, 1, 0]);
    assert_eq!(calls(&seen, "release"), [1, 1, 1]);
    assert_eq!(calls(&seen, "resume"), [0, 0, 0]);
}

/// The same for a run dropped mid-pause.
#[tokio::test(start_paused = true)]
async fn a_run_dropped_mid_pause_releases_every_pause_for_the_stop() {
    let seen = Seen::default();
    let mut a = three(&seen, Some((FloorOwner::Config, Step::Never, Step::Ok)));
    drop_once_entered(&mut a, &seen).await;
    assert_eq!(calls(&seen, "pause"), [1, 1, 0]);
    assert_eq!(calls(&seen, "release"), [1, 1, 1]);
    assert_eq!(calls(&seen, "resume"), [0, 0, 0]);
}

/// A panic unwinding through the run (test profile; release builds abort)
/// releases every pause on the way out.
#[tokio::test(start_paused = true)]
async fn a_panicking_checkpoint_releases_every_pause_on_unwind() {
    let seen = Seen::default();
    let mut a = three(&seen, Some((FloorOwner::Config, Step::Ok, Step::Panic)));
    let run = std::panic::AssertUnwindSafe(run_checkpoint(&mut a, deadline()));
    assert!(
        run.catch_unwind().await.is_err(),
        "the fake's panic unwinds through the run"
    );
    assert_eq!(calls(&seen, "release"), [1, 1, 1]);
    assert_eq!(calls(&seen, "resume"), [0, 0, 0]);
}

/// A certified attempt dropped without a decision releases every pause for the stop.
#[tokio::test(start_paused = true)]
async fn an_undecided_certified_attempt_releases_every_pause_when_dropped() {
    let seen = Seen::default();
    let mut a = three(&seen, None);
    match run_checkpoint(&mut a, deadline()).await {
        Ok(certified) => drop(certified),
        Err(c) => panic!("all three certify, got {c:?}"),
    }
    assert_eq!(calls(&seen, "release"), [1, 1, 1]);
    assert_eq!(calls(&seen, "resume"), [0, 0, 0]);
}

/// Commit reaches every adapter once and releases none.
#[tokio::test(start_paused = true)]
async fn commit_reaches_every_adapter_once_and_releases_none() {
    let seen = Seen::default();
    let mut a = three(&seen, None);
    let Ok(certified) = run_checkpoint(&mut a, deadline()).await else {
        panic!("all three certify");
    };
    assert_eq!(certified.commit(), Ok(()));
    assert_eq!(calls(&seen, "commit"), [1, 1, 1]);
    assert_eq!(calls(&seen, "resume"), [0, 0, 0]);
    assert_eq!(calls(&seen, "release"), [0, 0, 0]);
}

/// abort resumes every adapter and releases none.
#[tokio::test(start_paused = true)]
async fn abort_resumes_every_adapter() {
    let seen = Seen::default();
    let mut a = three(&seen, None);
    let Ok(certified) = run_checkpoint(&mut a, deadline()).await else {
        panic!("all three certify");
    };
    certified.abort();
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
    assert_eq!(calls(&seen, "release"), [0, 0, 0]);
}

/// A commit after the deadline is late: refused, and every adapter is resumed.
#[tokio::test(start_paused = true)]
async fn a_commit_after_the_deadline_is_late_and_resumes() {
    let seen = Seen::default();
    let mut a = three(&seen, None);
    let Ok(certified) = run_checkpoint(&mut a, deadline()).await else {
        panic!("all three certify");
    };
    tokio::time::advance(WINDOW).await;
    assert_eq!(certified.commit(), Err(LateDecision));
    assert_eq!(calls(&seen, "commit"), [0, 0, 0]);
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
}

/// Every adapter gets the one deadline it was given.
#[tokio::test(start_paused = true)]
async fn every_adapter_gets_the_one_deadline() {
    let seen = Seen::default();
    let mut a = three(&seen, None);
    // Not now + WINDOW: a fresh deadline of the usual length must not match it.
    let d = Instant::now() + Duration::from_secs(7);
    let Ok(certified) = run_checkpoint(&mut a, d).await else {
        panic!("all three certify");
    };
    certified.abort();
    let given = seen.deadlines.lock().expect("deadlines").clone();
    assert_eq!(
        given,
        vec![d; 6],
        "three pauses and three checkpoints, all given d"
    );
}

/// all_settled is false while one owner's late work runs, true after it ends.
#[test]
fn all_settled_waits_for_late_work() {
    let seen = Seen::default();
    let a = three(&seen, None);
    seen.late_work.store(true, Ordering::SeqCst);
    assert!(
        !all_settled(&a),
        "late work of an earlier attempt still runs"
    );
    seen.late_work.store(false, Ordering::SeqCst);
    assert!(all_settled(&a));
}

async fn save_error_cancels(owner: FloorOwner) {
    let seen = Seen::default();
    let mut a = three(
        &seen,
        Some((owner, Step::Ok, Step::Fail(FloorFault::SaveFailed))),
    );
    let c = expect_cancel(&mut a, deadline()).await;
    assert_eq!(
        c,
        at(owner, FloorStage::Checkpoint, CancelReason::SaveFailed)
    );
    assert_eq!(
        calls(&seen, "resume"),
        [1, 1, 1],
        "every owner resumes exactly once"
    );
    assert_eq!(calls(&seen, "release"), [0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn a_task_store_save_error_cancels_and_resumes_all() {
    save_error_cancels(FloorOwner::TaskStore).await;
}

#[tokio::test(start_paused = true)]
async fn a_config_save_error_cancels_and_resumes_all() {
    save_error_cancels(FloorOwner::Config).await;
}

#[tokio::test(start_paused = true)]
async fn a_health_save_error_cancels_and_resumes_all() {
    save_error_cancels(FloorOwner::Health).await;
}

#[tokio::test(start_paused = true)]
async fn a_lost_worker_result_cancels_with_that_reason() {
    let seen = Seen::default();
    let mut a = three(
        &seen,
        Some((
            FloorOwner::Config,
            Step::Ok,
            Step::Fail(FloorFault::WorkerLost),
        )),
    );
    assert_eq!(
        expect_cancel(&mut a, deadline()).await.reason,
        CancelReason::WorkerLost
    );
}

#[tokio::test(start_paused = true)]
async fn an_unavailable_owner_cancels_with_that_reason() {
    let seen = Seen::default();
    let mut a = three(
        &seen,
        Some((
            FloorOwner::Health,
            Step::Ok,
            Step::Fail(FloorFault::Unavailable),
        )),
    );
    assert_eq!(
        expect_cancel(&mut a, deadline()).await.reason,
        CancelReason::Unavailable
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_pause_cancels_at_the_pause_stage_and_skips_later_owners() {
    let seen = Seen::default();
    let mut a = three(
        &seen,
        Some((
            FloorOwner::Config,
            Step::Fail(FloorFault::Unavailable),
            Step::Ok,
        )),
    );
    let c = expect_cancel(&mut a, deadline()).await;
    assert_eq!((c.owner, c.stage), (FloorOwner::Config, FloorStage::Pause));
    assert_eq!(calls(&seen, "pause"), [1, 1, 0]);
    assert_eq!(calls(&seen, "checkpoint"), [0, 0, 0]);
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
}

#[tokio::test(start_paused = true)]
async fn a_checkpoint_past_the_deadline_cancels() {
    let seen = Seen::default();
    let slow = Step::Takes(Duration::from_millis(60));
    let mut a = three(&seen, Some((FloorOwner::Config, Step::Ok, slow)));
    let d = Instant::now() + Duration::from_millis(20);
    assert_eq!(
        expect_cancel(&mut a, d).await.reason,
        CancelReason::DeadlineExceeded
    );
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
}

#[tokio::test(start_paused = true)]
async fn a_deadline_already_past_cancels_before_any_pause() {
    let seen = Seen::default();
    let mut a = three(&seen, None);
    let c = expect_cancel(&mut a, Instant::now()).await;
    assert_eq!(
        c,
        at(
            FloorOwner::TaskStore,
            FloorStage::Pause,
            CancelReason::DeadlineExceeded
        )
    );
    assert_eq!(calls(&seen, "pause"), [0, 0, 0]);
    assert_eq!(calls(&seen, "checkpoint"), [0, 0, 0]);
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
}

#[tokio::test(start_paused = true)]
async fn a_certified_checkpoint_holds_every_pause_until_abort() {
    let seen = Seen::default();
    let mut a = three(&seen, None);
    let Ok(certified) = run_checkpoint(&mut a, deadline()).await else {
        panic!("all three certify");
    };
    assert_eq!(calls(&seen, "resume"), [0, 0, 0], "no resume before abort");
    certified.abort();
    assert_eq!(calls(&seen, "resume"), [1, 1, 1]);
}

#[tokio::test(start_paused = true)]
async fn a_recoverable_fault_cancels_once_then_the_retry_certifies() {
    let seen = Seen::default();
    let mut bad = three(
        &seen,
        Some((
            FloorOwner::TaskStore,
            Step::Ok,
            Step::Fail(FloorFault::SaveFailed),
        )),
    );
    let _ = expect_cancel(&mut bad, deadline()).await;
    let mut good = three(&seen, None);
    let Ok(certified) = run_checkpoint(&mut good, deadline()).await else {
        panic!("the retry certifies");
    };
    certified.abort();
}

#[test]
fn exactly_three_distinct_floor_owners_are_required() {
    let seen = Seen::default();
    assert_eq!(validate_owners(&three(&seen, None)), Ok(()));
    let two = vec![
        fake(&seen, FloorOwner::TaskStore, Step::Ok, Step::Ok),
        fake(&seen, FloorOwner::Config, Step::Ok, Step::Ok),
    ];
    assert_eq!(
        validate_owners(&two),
        Err(FloorSetupError::NotExactlyThreeOwners)
    );
    let dup = vec![
        fake(&seen, FloorOwner::TaskStore, Step::Ok, Step::Ok),
        fake(&seen, FloorOwner::Config, Step::Ok, Step::Ok),
        fake(&seen, FloorOwner::Config, Step::Ok, Step::Ok),
    ];
    assert_eq!(
        validate_owners(&dup),
        Err(FloorSetupError::NotExactlyThreeOwners)
    );
}

#[test]
fn the_cancel_audit_detail_names_owner_stage_and_reason_only() {
    let d = at(
        FloorOwner::Health,
        FloorStage::Checkpoint,
        CancelReason::SaveFailed,
    )
    .audit_detail();
    assert_eq!(d["owner"], "health");
    assert_eq!(d["stage"], "checkpoint");
    assert_eq!(d["reason"], "save_failed");
    assert_eq!(d.len(), 3);
}

#[test]
fn a_counters_save_error_and_a_later_floor_save_error_log_and_proceed() {
    for owner in [
        StopSaveOwner::Counters,
        StopSaveOwner::Floor(FloorOwner::TaskStore),
        StopSaveOwner::Floor(FloorOwner::Config),
        StopSaveOwner::Floor(FloorOwner::Health),
    ] {
        assert_eq!(
            settle_stop_save(owner, Err("disk full")),
            StopSaveOutcome::FailedLoggedProceeding
        );
        assert_eq!(
            settle_stop_save::<&str>(owner, Ok(())),
            StopSaveOutcome::Saved
        );
    }
}
