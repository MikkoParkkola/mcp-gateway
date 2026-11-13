// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The custody release off the stop path: a stalled release ends a bounded
//! shutdown at its deadline, a later call never reports Released while a
//! release is pending, and a failed spawn never drops the store on the caller.
//!
//! The stall is real: the provider's `Drop` runs inside the service's drop and
//! blocks, so a synchronous release does not return. Rows that need a clock use
//! a paused one, so no wall-clock window decides them; a past deadline gives a
//! zero window with no clock at all.

use std::path::Path;

use super::*;

/// The ERROR lines `run` logged on this thread, from the library's log capture.
fn errors_logged(run: impl FnOnce()) -> String {
    crate::test_log_capture::capture_at(tracing::Level::ERROR, run).1
}

/// A hang bound only: every wait here is released by an event.
const HANG_BOUND: Duration = Duration::from_secs(60);

fn paused<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("paused runtime")
        .block_on(fut)
}

/// The two ends of a stalled release: a signal that the drop was entered, and
/// the release that lets it go.
struct Stall {
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::Sender<()>,
}

impl Stall {
    fn wait_entered(&self) {
        self.entered
            .recv_timeout(HANG_BOUND)
            .expect("the release entered the stalled drop");
    }

    fn let_go(&self) {
        let _ = self.release.send(());
    }
}

fn stall_release(fx: &Fixture) -> Stall {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *fx.provider.drop_gate.lock().expect("drop gate") = Some((entered_tx, release_rx));
    Stall {
        entered: entered_rx,
        release: release_tx,
    }
}

/// Whether both file locks are free: the store opens, then is closed again.
fn store_is_free(root: &Path) -> bool {
    match PersonalAccountStore::open(config(root)) {
        Ok(store) => {
            drop(store);
            true
        }
        Err(_) => false,
    }
}

/// `MIK-9460.CUSTODY.1`: with the release stalled, a bounded shutdown ends at
/// its deadline, not when the release returns; the release runs off the caller.
#[test]
fn a_stalled_release_ends_the_bounded_shutdown_at_its_deadline() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    current_thread(async {
        // Paused here, in the row itself: the clock is virtual from the first poll.
        tokio::time::pause();
        let fx = start(tmp.path(), 2);
        let stall = stall_release(&fx);
        let began = tokio::time::Instant::now();
        let given = Duration::from_secs(2);
        let end = refuse_scaffold(
            fx.handle.shutdown_by(began + given).await,
            "bounded shutdown",
        )
        .expect("an outcome");
        assert_eq!(
            end,
            ShutdownEnd::ReleasePending,
            "the release is still running"
        );
        assert_eq!(
            began.elapsed(),
            given,
            "the stop ended at the given deadline"
        );
        stall.wait_entered();
        stall.let_go();
    });
}

/// `MIK-9460.CUSTODY.2`: a release that finishes inside the deadline behaves as
/// today: Released, and the locks are free while the handle is still alive.
#[test]
fn a_release_inside_the_deadline_frees_the_locks() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    // Real clock: the release runs on a real thread, and a paused clock would
    // jump to the deadline while that thread is still working.
    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let end = refuse_scaffold(
            fx.handle
                .shutdown_by(tokio::time::Instant::now() + HANG_BOUND)
                .await,
            "bounded shutdown",
        )
        .expect("an outcome");
        assert_eq!(end, ShutdownEnd::Released);
        assert!(
            store_is_free(tmp.path()),
            "both locks are free after Released"
        );
        assert_eq!(
            fx.observer_calls.load(Ordering::SeqCst),
            0,
            "nothing extra was released"
        );
    });
}

/// `MIK-9460.CUSTODY.3`: a release still running at the deadline is reported
/// once, however many calls meet it, and no line names an account or a secret.
#[test]
fn a_pending_release_is_reported_once_and_names_no_account() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    let log = errors_logged(|| {
        paused(async {
            let fx = start(tmp.path(), 2);
            let stall = stall_release(&fx);
            let past = tokio::time::Instant::now();
            for call in ["first", "second"] {
                let end =
                    refuse_scaffold(fx.handle.shutdown_by(past).await, call).expect("outcome");
                assert_eq!(end, ShutdownEnd::ReleasePending, "{call} call");
            }
            stall.wait_entered();
            stall.let_go();
        });
    });
    assert_eq!(log.lines().count(), 1, "exactly one report line: {log:?}");
    let seeded = unexpired();
    for private in [
        "alice",
        "identity.example",
        "google-workspace-personal",
        seeded.access_token.as_str(),
    ] {
        assert!(
            !log.contains(private),
            "the report names {private}: {log:?}"
        );
    }
}

/// In-flight work still holding a permit at the deadline: nothing is taken, the
/// store stays held, and the call says so once.
#[test]
fn in_flight_work_past_the_deadline_leaves_the_store_untaken() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    let log = errors_logged(|| {
        multi_thread(async {
            let fx = start(tmp.path(), 2);
            let (entered, release) = fx.provider.hold(&alice());
            let op = {
                let handle = Arc::clone(&fx.handle);
                tokio::spawn(async move { handle.refresh_if_expired(&alice()).await })
            };
            tokio::time::timeout(HANG_BOUND, entered)
                .await
                .expect("the provider was entered")
                .expect("entry signal");
            // A past deadline: no clock decides this row.
            let end = refuse_scaffold(
                fx.handle.shutdown_by(tokio::time::Instant::now()).await,
                "bounded shutdown",
            )
            .expect("outcome");
            assert_eq!(end, ShutdownEnd::InFlightPending);
            assert!(
                !store_is_free(tmp.path()),
                "the store was taken while work was in flight"
            );
            let _ = release.send(());
            let _ = op.await;
        });
    });
    assert_eq!(log.lines().count(), 1, "one report line: {log:?}");
}

/// A second, unbounded `shutdown()` during a pending release does not return
/// until the release is done, and the locks are free after it: Ok means free.
#[test]
fn a_second_shutdown_waits_for_the_pending_release() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let stall = stall_release(&fx);
        let first = refuse_scaffold(
            fx.handle.shutdown_by(tokio::time::Instant::now()).await,
            "first shutdown",
        )
        .expect("outcome");
        assert_eq!(first, ShutdownEnd::ReleasePending);
        stall.wait_entered();
        let (second_fut, second_pending) = first_pending({
            let handle = Arc::clone(&fx.handle);
            async move { handle.shutdown().await }
        });
        let second = tokio::spawn(second_fut);
        tokio::time::timeout(HANG_BOUND, second_pending)
            .await
            .expect("the second shutdown pends while the release is stalled")
            .expect("pending signal");
        assert!(
            !second.is_finished(),
            "the second shutdown returned during the stall"
        );
        stall.let_go();
        refuse_scaffold(second.await.expect("task"), "second shutdown").expect("Ok means released");
        assert!(
            store_is_free(tmp.path()),
            "the locks are free after the second Ok"
        );
    });
}

/// A late waiter: the release finished before the second call, which returns
/// Released at once and finds the locks free.
#[test]
fn a_shutdown_after_the_release_finished_returns_released_at_once() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        refuse_scaffold(fx.handle.shutdown().await, "first").expect("first");
        let again = refuse_scaffold(
            fx.handle.shutdown_by(tokio::time::Instant::now()).await,
            "second",
        )
        .expect("outcome");
        assert_eq!(again, ShutdownEnd::Released);
        assert!(store_is_free(tmp.path()));
    });
}

/// A failed release spawn never drops the store on the caller: the outcome is
/// `Stuck`, nothing waits on it, nothing reports it released, and the locks stay
/// held (the store is leaked to process exit, not dropped inline).
#[test]
fn a_failed_release_spawn_leaves_the_store_stuck_and_never_drops_it_inline() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    paused(async {
        let fx = start(tmp.path(), 2);
        let stall = stall_release(&fx);
        fx.handle.fail_next_release_spawn();
        let end = refuse_scaffold(
            fx.handle
                .shutdown_by(tokio::time::Instant::now() + Duration::from_secs(2))
                .await,
            "bounded shutdown",
        )
        .expect("outcome");
        assert_eq!(end, ShutdownEnd::Stuck);
        assert!(
            stall.entered.try_recv().is_err(),
            "the stalled drop ran: the store was dropped inline on the caller"
        );
        assert!(
            !store_is_free(tmp.path()),
            "the locks must stay held when stuck"
        );
        stall.let_go();
    });
}

/// After a failed release spawn, an UNBOUNDED `shutdown()` must not wait for a
/// done signal that can never come: it returns `ReleaseStuck` at once.
#[test]
fn an_unbounded_shutdown_on_a_stuck_store_returns_an_error_at_once() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let stall = stall_release(&fx);
        fx.handle.fail_next_release_spawn();
        let first = refuse_scaffold(
            fx.handle.shutdown_by(tokio::time::Instant::now()).await,
            "bounded shutdown",
        )
        .expect("outcome");
        assert_eq!(first, ShutdownEnd::Stuck);
        let unbounded = tokio::time::timeout(HANG_BOUND, fx.handle.shutdown())
            .await
            .expect("the unbounded call returned instead of waiting forever");
        assert!(
            matches!(unbounded, Err(CustodyError::ReleaseStuck)),
            "unbounded shutdown on a stuck store: {unbounded:?}"
        );
        stall.let_go();
    });
}

/// `detach_release()` never waits: with the release stalled it returns at once
/// and the drop runs on another thread (the custody stage skipped at a zero
/// window still leaves no store to drop on the runtime worker).
#[test]
fn detach_release_returns_at_once_and_the_drop_runs_elsewhere() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let stall = stall_release(&fx);
        let caller = std::thread::current().id();
        let began = std::time::Instant::now();
        fx.handle.detach_release();
        // A detach that dropped inline would sit in the stalled drop for its whole
        // hang guard; a real one returns at once with the release still stalled.
        // The bound is that whole guard, so only an inline drop reaches it.
        assert!(
            began.elapsed() < RELEASE_HANG_GUARD,
            "detach_release waited on the stalled release"
        );
        stall.wait_entered();
        // The service drops its store (the locks) before the provider, so the
        // locks are already free here: this row proves the call returned and the
        // drop is running elsewhere, not that the locks stay held.
        stall.let_go();
        refuse_scaffold(fx.handle.shutdown().await, "shutdown after the detach").expect("released");
        let dropped_on = fx
            .provider
            .drop_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expect("the store was dropped by now");
        assert_ne!(dropped_on, caller, "the drop ran on the calling thread");
    });
}

/// The final owner is an in-flight operation: `detach_release()` takes the
/// handle's reference, the operation holds the last one, and the release is only
/// done when that operation lets go (the done signal comes from the service's
/// own drop, wherever it happens).
#[test]
fn the_release_is_done_only_when_the_last_owner_lets_go() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let (entered, release) = fx.provider.hold(&alice());
        let op = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.refresh_if_expired(&alice()).await })
        };
        tokio::time::timeout(HANG_BOUND, entered)
            .await
            .expect("the provider was entered")
            .expect("entry signal");
        fx.handle.detach_release();
        assert!(
            !store_is_free(tmp.path()),
            "the operation still owns the store"
        );
        let _ = release.send(());
        let _ = op.await;
        refuse_scaffold(fx.handle.shutdown().await, "shutdown after the operation")
            .expect("released");
        assert!(store_is_free(tmp.path()));
    });
}

/// A release thread that panics still signals done and reports once; the locks
/// are free afterwards (unwinding dropped what was left). The report comes from
/// the release thread, outside this thread's log capture, so the row reads the
/// shared report flag.
#[test]
fn a_panicking_release_still_signals_done_and_frees_the_locks() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        fx.provider.panic_on_drop.store(true, Ordering::SeqCst);
        let end = refuse_scaffold(
            fx.handle
                .shutdown_by(tokio::time::Instant::now() + HANG_BOUND)
                .await,
            "bounded shutdown",
        )
        .expect("outcome");
        assert_eq!(end, ShutdownEnd::Released, "the guard signals on unwind");
        assert!(store_is_free(tmp.path()), "unwinding freed the locks");
        // The thread reports after `catch_unwind` returns, which can come after
        // the done signal the unwinding guard sent: wait for it, bounded.
        let report_by = std::time::Instant::now() + HANG_BOUND;
        while !fx.handle.reported.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < report_by,
                "the panic was reported"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

/// Cancelling the bounded shutdown (the stop budget's timeout drops the future)
/// strands nothing: the release thread keeps running and a later call sees it.
#[test]
fn cancelling_the_bounded_shutdown_strands_nothing() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    paused(async {
        let fx = start(tmp.path(), 2);
        let stall = stall_release(&fx);
        let far = tokio::time::Instant::now() + Duration::from_secs(600);
        // Poll it once, then drop it: the way a stop timeout cancels a stage, with
        // no clock deciding when.
        let cancelled = tokio::select! {
            biased;
            _ = fx.handle.shutdown_by(far) => false,
            () = std::future::ready(()) => true,
        };
        assert!(cancelled, "the shutdown pended and was cancelled");
        stall.wait_entered();
        let later = refuse_scaffold(
            fx.handle.shutdown_by(tokio::time::Instant::now()).await,
            "later call",
        )
        .expect("outcome");
        assert_eq!(
            later,
            ShutdownEnd::ReleasePending,
            "the slot was not stranded"
        );
        stall.let_go();
    });
}

/// `MIK-9460.CUSTODY.4`: the stdio teardown cuts its custody step while an
/// operation still holds a permit, then ends with the final no-wait detach. The
/// store's last drop must then not happen on the thread that drops the gateway
/// (the one that runs `run_stdio`): the detach took the handle's reference, so
/// the operation's own thread drops last. Without the detach, the handle is the
/// last owner and the gateway's drop releases the store on the caller.
#[test]
fn after_a_cut_custody_step_the_final_detach_keeps_the_last_drop_off_the_caller() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let caller = std::thread::current().id();
        let (entered, release) = fx.provider.hold(&alice());
        let op = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.refresh_if_expired(&alice()).await })
        };
        tokio::time::timeout(HANG_BOUND, entered)
            .await
            .expect("the provider was entered")
            .expect("entry signal");
        // The custody step, cut: an operation still holds a permit.
        let cut = tokio::time::timeout(
            HANG_BOUND,
            fx.handle.shutdown_by(tokio::time::Instant::now()),
        )
        .await
        .expect("the cut custody step returned instead of waiting for the operation");
        let cut = refuse_scaffold(cut, "cut custody step").expect("outcome");
        assert_eq!(cut, ShutdownEnd::InFlightPending);
        // The end of the teardown.
        fx.handle.detach_release();
        let _ = release.send(());
        let _ = op.await;
        let provider = Arc::clone(&fx.provider);
        // The gateway is dropped last, as `run_stdio` returns.
        drop(fx);
        let dropped_on = provider
            .drop_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expect("the store was dropped by now");
        assert_ne!(
            dropped_on, caller,
            "the last drop of the store ran on the thread that drops the gateway"
        );
    });
}

/// Hold `alice` in the provider through a real operation, which keeps one permit
/// until the returned sender lets it go. Returns once the provider is entered.
async fn hold_a_permit(fx: &Fixture) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let (entered, release) = fx.provider.hold(&alice());
    let op = {
        let handle = Arc::clone(&fx.handle);
        tokio::spawn(async move {
            let _ = handle.refresh_if_expired(&alice()).await;
        })
    };
    tokio::time::timeout(HANG_BOUND, entered)
        .await
        .expect("the provider was entered")
        .expect("entry signal");
    (release, op)
}

/// Yield on a current-thread runtime until a spawned shutdown has refused new
/// work: it then has read the slot and is parked in the permit drain, because
/// nothing between the refusal and the drain awaits.
async fn until_draining(fx: &Fixture) {
    while !fx.handle.shutting_down.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
}

/// A shutdown that read `Open` and drained behind an operation must not wait on
/// done when, meanwhile, a detach could not start its thread and left the store
/// stuck: the unbounded call returns `ReleaseStuck` instead of hanging.
#[test]
fn a_shutdown_draining_behind_a_failed_detach_reports_stuck_not_a_hang() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    current_thread(async {
        let fx = start(tmp.path(), 2);
        let (release, op) = hold_a_permit(&fx).await;
        let waiting = {
            let handle = Arc::clone(&fx.handle);
            tokio::spawn(async move { handle.shutdown().await })
        };
        until_draining(&fx).await;
        fx.handle.fail_next_release_spawn();
        fx.handle.detach_release();
        let _ = release.send(());
        let _ = op.await;
        let outcome = tokio::time::timeout(HANG_BOUND, waiting)
            .await
            .expect("the draining shutdown returned instead of waiting forever")
            .expect("the shutdown task");
        assert!(
            matches!(outcome, Err(CustodyError::ReleaseStuck)),
            "a stuck store after the drain: {outcome:?}"
        );
    });
}

/// A bounded shutdown whose drain runs out after a detach already started the
/// release reports that release (`ReleasePending`), not `InFlightPending`.
#[test]
fn a_drain_cut_after_a_detach_reports_the_running_release() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    current_thread(async {
        let fx = start(tmp.path(), 2);
        let (release, op) = hold_a_permit(&fx).await;
        let waiting = {
            let handle = Arc::clone(&fx.handle);
            let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
            tokio::spawn(async move { handle.shutdown_by(deadline).await })
        };
        until_draining(&fx).await;
        fx.handle.detach_release();
        let end = tokio::time::timeout(HANG_BOUND, waiting)
            .await
            .expect("the bounded shutdown returned")
            .expect("the shutdown task");
        let end = refuse_scaffold(end, "bounded shutdown").expect("outcome");
        // The operation still owns the service, so the release cannot be done yet.
        assert_eq!(end, ShutdownEnd::ReleasePending);
        let _ = release.send(());
        let _ = op.await;
        refuse_scaffold(fx.handle.shutdown().await, "shutdown after the release")
            .expect("released");
        assert!(store_is_free(tmp.path()));
    });
}

/// A standalone (unbounded) shutdown whose release thread cannot start drops the
/// store on the blocking pool, never inline and never leaked: it returns Ok, the
/// locks are free, and the drop ran off the calling thread.
#[test]
fn an_unbounded_shutdown_whose_spawn_fails_still_releases_off_the_caller() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let caller = std::thread::current().id();
        fx.handle.fail_next_release_spawn();
        let done = tokio::time::timeout(HANG_BOUND, fx.handle.shutdown())
            .await
            .expect("the unbounded shutdown returned");
        refuse_scaffold(done, "unbounded shutdown").expect("released");
        assert!(store_is_free(tmp.path()), "the locks were not freed");
        let dropped_on = fx
            .provider
            .drop_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expect("the store was dropped by now");
        assert_ne!(dropped_on, caller, "the drop ran on the calling thread");
    });
}

/// A serve that ends by any path (an early error return, a cancelled future)
/// drops its guard: the guard hands the store to a release thread and returns at
/// once, so the gateway's own drop never releases the store on that thread.
#[test]
fn dropping_the_serve_guard_detaches_the_release() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), unexpired())]);

    multi_thread(async {
        let fx = start(tmp.path(), 2);
        let stall = stall_release(&fx);
        let caller = std::thread::current().id();
        let began = std::time::Instant::now();
        drop(fx.handle.detach_on_drop());
        // Only an inline drop, stalled for the whole hang guard, reaches it.
        assert!(
            began.elapsed() < RELEASE_HANG_GUARD,
            "the guard's drop waited on the stalled release"
        );
        assert!(
            stall.entered.recv_timeout(HANG_BOUND).is_ok(),
            "the guard's drop started no release"
        );
        stall.let_go();
        refuse_scaffold(fx.handle.shutdown().await, "shutdown after the guard").expect("released");
        let dropped_on = fx
            .provider
            .drop_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .expect("the store was dropped by now");
        assert_ne!(dropped_on, caller, "the drop ran on the calling thread");
    });
}

/// Cancelling the bounded shutdown while it waits in the permit drain (the stop
/// budget cuts the stage there) takes nothing: the store stays in the handle,
/// and a later shutdown releases it once the operation lets go.
#[test]
fn cancelling_the_shutdown_in_its_drain_takes_nothing() {
    let _serial = worker_test_lock();
    let tmp = tempfile::TempDir::new().expect("root");
    seed(tmp.path(), &[(&alice(), grant())]);

    current_thread(async {
        let fx = start(tmp.path(), 2);
        let (release, op) = hold_a_permit(&fx).await;
        {
            let pending = fx
                .handle
                .shutdown_by(tokio::time::Instant::now() + HANG_BOUND);
            tokio::pin!(pending);
            // One poll parks it in the drain, behind the operation's permit.
            assert!(
                futures::poll!(pending.as_mut()).is_pending(),
                "the shutdown did not wait for the operation"
            );
        }
        assert!(
            !fx.handle.release_started(),
            "a shutdown cancelled in its drain took the store"
        );
        let _ = release.send(());
        let _ = op.await;
        refuse_scaffold(fx.handle.shutdown().await, "later shutdown").expect("released");
        assert!(
            store_is_free(tmp.path()),
            "the later shutdown freed the locks"
        );
    });
}
