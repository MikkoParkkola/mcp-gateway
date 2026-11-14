// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Contract rows K7, K9, K10 and K12 of the config floor: deadlines never fault
//! inside the adapter, a dropped pause future leaves the gate Paused, the
//! admission race decides against recorded state, and the four synchronous
//! calls never take a certification lock.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::seams::{AttemptEvent, LockVerdict, ReloadSource};
use super::support::{self, Booted};
use super::{AdmitKind, GateState, Refusal};
use crate::gateway::restart_floor::{CancelReason, FloorAdapter, FloorStage, run_checkpoint};

/// Polls a checkpoint future once: true when it is still pending.
async fn pending_now<F: std::future::Future + Unpin>(fut: &mut F) -> bool {
    futures::poll!(fut).is_pending()
}

/// Runs `floor` through the coordinator's `run_checkpoint` against a 10 s
/// deadline and returns the cancel it ended with, if any.
async fn coordinator_cancel(
    floor: super::ConfigFloor,
) -> Option<crate::gateway::restart_floor::Cancelled> {
    let mut adapters: Vec<Box<dyn FloorAdapter>> = vec![Box::new(floor)];
    let deadline = Instant::now() + Duration::from_secs(10);
    run_checkpoint(&mut adapters, deadline).await.err()
}

#[tokio::test(start_paused = true)]
async fn k7a_reload_lock_wait_past_deadline_stays_pending() {
    const ROW: &str = "K7a";
    // GIVEN: an outside holder of the reload lock and a paused adapter
    let booted = Booted::new(support::BASE);
    let held = booted.registry.reload_lock_handle().lock_owned().await;
    let mut floor = booted.floor();
    let deadline = Instant::now() + Duration::from_secs(10);
    floor.pause(deadline).await.expect("pause answers Ok");
    // WHEN: the clock passes the deadline and the checkpoint is polled
    let mut fut = floor.checkpoint(deadline);
    assert!(
        pending_now(&mut fut).await,
        "{ROW}: checkpoint must wait on the held reload lock"
    );
    tokio::time::advance(Duration::from_secs(11)).await;
    // THEN: still Pending, no fault for the elapsed time
    assert!(
        pending_now(&mut fut).await,
        "{ROW}: past the deadline the future stays pending, never a fault"
    );
    drop(fut);
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn k7a_coordinator_ends_the_reload_lock_wait() {
    const ROW: &str = "K7a-run";
    // GIVEN: an outside holder of the reload lock
    let booted = Booted::new(support::BASE);
    let held = booted.registry.reload_lock_handle().lock_owned().await;
    // WHEN: the coordinator runs the checkpoint under its deadline
    let cancel = coordinator_cancel(booted.floor()).await;
    // THEN: only its timeout_at ends it, at the checkpoint stage
    let cancel = cancel.unwrap_or_else(|| panic!("{ROW}: the run must cancel at the deadline"));
    assert_eq!(cancel.reason, CancelReason::DeadlineExceeded, "{ROW}");
    assert_eq!(cancel.stage, FloorStage::Checkpoint, "{ROW}");
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn k7b_config_lock_busy_stays_pending_with_one_busy_attempt() {
    const ROW: &str = "K7b";
    // GIVEN: the config-lock acquisition answers Busy as at its deadline
    let booted = Booted::new(support::BASE);
    let mut floor = booted.floor();
    floor.set_lock_hook(Some(Arc::new(|_| LockVerdict::Busy)));
    let deadline = Instant::now() + Duration::from_secs(10);
    floor.pause(deadline).await.expect("pause answers Ok");
    // the log handle is cloned first: the future borrows the adapter mutably
    let attempts = floor.seams.attempts.clone();
    let attempt = floor.attempt();
    // WHEN: the checkpoint is polled, then polled again after the Busy
    let mut fut = floor.checkpoint(deadline);
    assert!(
        pending_now(&mut fut).await,
        "{ROW}: checkpoint must not complete before the lock answers"
    );
    // the acquisition runs on the blocking pool, so a yield wait cannot starve it
    support::wait_until("the lock acquisition recorded its Busy", || {
        busy_count(&attempts.snapshot(), attempt) > 0
    });
    tokio::time::advance(Duration::from_secs(11)).await;
    // THEN: Pending, no fault, exactly one Busy acquisition (no respawn loop)
    assert!(
        pending_now(&mut fut).await,
        "{ROW}: a Busy lock wait stays pending, never a fault"
    );
    assert_eq!(
        busy_count(&attempts.snapshot(), attempt),
        1,
        "{ROW}: exactly one Busy acquisition for the attempt"
    );
    drop(fut);
}

#[tokio::test(start_paused = true)]
async fn k7b_coordinator_ends_the_config_lock_wait() {
    const ROW: &str = "K7b-run";
    // GIVEN: the config-lock acquisition answers Busy
    let booted = Booted::new(support::BASE);
    let mut floor = booted.floor();
    floor.set_lock_hook(Some(Arc::new(|_| LockVerdict::Busy)));
    // WHEN: the coordinator runs the checkpoint under its deadline
    let cancel = coordinator_cancel(floor).await;
    // THEN: only its timeout_at ends it
    let cancel = cancel.unwrap_or_else(|| panic!("{ROW}: the run must cancel at the deadline"));
    assert_eq!(cancel.reason, CancelReason::DeadlineExceeded, "{ROW}");
}

/// Busy acquisitions the attempt log holds for `attempt`.
fn busy_count(log: &[super::seams::AttemptEntry], attempt: u64) -> usize {
    log.iter()
        .filter(|e| e.attempt == attempt && e.event == AttemptEvent::LockBusy)
        .count()
}

/// A booted config whose file was edited outside to `environment: a1`, with the
/// file event the OS would deliver recorded; nothing has reloaded it yet.
fn planted() -> Booted {
    let booted = Booted::new(support::BASE);
    booted
        .cfg
        .rewrite(&format!("{}environment: \"a1\"\n", support::BASE));
    booted.gate.record_file_event();
    booted
}

#[tokio::test]
async fn k9_dropped_unpolled_pause_leaves_gate_paused_and_resume_replays() {
    const ROW: &str = "K9";
    // GIVEN: a planted trigger and a pause() whose future is dropped unpolled
    let booted = planted();
    let mut floor = booted.floor();
    drop(floor.pause(Instant::now() + Duration::from_secs(10)));
    // THEN: the adapter, not the future, holds the pause
    assert!(
        matches!(booted.gate.state(), GateState::Paused(_)),
        "{ROW}: state after the dropped pause must be Paused"
    );
    // WHEN: resume() and one tick
    floor.resume();
    support::tick(&support::WatcherFixture::new(&booted)).await;
    // THEN: exactly one replay carrying the planted value
    assert_eq!(
        support::reload_values(&booted.gate, ReloadSource::Replay),
        vec!["a1".to_owned()],
        "{ROW}: the replay after resume"
    );
}

#[tokio::test]
async fn k9_dropped_unpolled_pause_then_stop_replays_nothing() {
    const ROW: &str = "K9-stop";
    // GIVEN: the same planted trigger and dropped pause
    let booted = planted();
    let mut floor = booted.floor();
    drop(floor.pause(Instant::now() + Duration::from_secs(10)));
    // WHEN: release_for_stop() and one tick
    floor.release_for_stop();
    support::tick(&support::WatcherFixture::new(&booted)).await;
    // THEN: no reload, state Released
    assert!(
        support::reload_log(&booted.gate).is_empty(),
        "{ROW}: a stop replays nothing"
    );
    assert_eq!(booted.gate.state(), GateState::Released, "{ROW}");
    // GIVEN: an adapter never paused, WHEN resume() and a tick
    let idle = Booted::new(support::BASE);
    idle.floor().resume();
    support::tick(&support::WatcherFixture::new(&idle)).await;
    // THEN: still Open, no reload
    assert_eq!(idle.gate.state(), GateState::Open, "{ROW}: never paused");
    assert!(support::reload_log(&idle.gate).is_empty(), "{ROW}");
}

const ITERATIONS: usize = 1_000;

/// Runs `submit` and `other` on their own threads, each released by a message;
/// the two releases are sent in order (`submit` first in the first half of the
/// iterations, `other` first in the second), and both joins are bounded.
fn race_ordered<A: Send + 'static>(
    i: usize,
    submit: impl FnOnce() -> A + Send + 'static,
    other: impl FnOnce() + Send + 'static,
) -> A {
    let (tx_s, rx_s) = std::sync::mpsc::channel::<()>();
    let (tx_o, rx_o) = std::sync::mpsc::channel::<()>();
    let s = std::thread::spawn(move || {
        support::recv_bounded(&rx_s, "the submission's release");
        submit()
    });
    let o = std::thread::spawn(move || {
        support::recv_bounded(&rx_o, "the other side's release");
        other();
    });
    let _ = if i < ITERATIONS / 2 {
        (tx_s.send(()), tx_o.send(()))
    } else {
        (tx_o.send(()), tx_s.send(()))
    };
    support::join_bounded(o, &format!("iteration {i}: other side"));
    support::join_bounded(s, &format!("iteration {i}: submission"))
}

/// A Paused gate with its adapter, ready for the race.
async fn paused(booted: &Booted) -> super::ConfigFloor {
    let mut floor = booted.floor();
    let deadline = Instant::now() + Duration::from_secs(30);
    floor.pause(deadline).await.expect("pause answers Ok");
    floor
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k10_submission_racing_resume_matches_its_recorded_state() {
    const ROW: &str = "K10";
    let (mut admitted, mut refused) = (0_usize, 0_usize);
    for i in 0..ITERATIONS {
        // GIVEN: a fresh fixture with the gate Paused
        let booted = Booted::new(support::BASE);
        let mut floor = paused(&booted).await;
        let gate = booted.gate.clone();
        // WHEN: a Write submission races resume(); this row is a direct gate
        // client, so it calls admit itself
        let got = race_ordered(
            i,
            move || gate.admit(AdmitKind::Write).is_ok(),
            move || floor.resume(),
        );
        // THEN: its one decision says admitted exactly when the state was Open
        let log = booted.gate.decisions();
        assert_eq!(log.len(), 1, "{ROW}: iteration {i}: one decision recorded");
        let d = log[0];
        assert_eq!(d.admitted, got, "{ROW}: iteration {i}: outcome vs record");
        assert_eq!(
            d.admitted,
            d.state == GateState::Open,
            "{ROW}: iteration {i}: {d:?}"
        );
        assert!(
            matches!(d.state, GateState::Open | GateState::Paused(_)),
            "{ROW}: {i}: {d:?}"
        );
        if got { admitted += 1 } else { refused += 1 }
    }
    assert!(
        admitted > 0 && refused > 0,
        "{ROW}: both outcomes: {admitted}/{refused}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k10_manual_reload_racing_commit_matches_its_recorded_state() {
    const ROW: &str = "K10-commit";
    let (mut owed, mut restarting) = (0_usize, 0_usize);
    for i in 0..ITERATIONS {
        // GIVEN: a fresh fixture certified, the gate in Certified
        let booted = Booted::new(support::BASE);
        let mut floor = paused(&booted).await;
        let deadline = Instant::now() + Duration::from_secs(30);
        floor
            .checkpoint(deadline)
            .await
            .expect("checkpoint certifies");
        let gate = booted.gate.clone();
        // WHEN: a manual reload (a direct gate client here) races commit()
        let got = race_ordered(
            i,
            move || gate.admit(AdmitKind::ManualReload).err(),
            move || floor.commit(),
        );
        // THEN: the refusal and replay_owed match the state at the decision
        let log = booted.gate.decisions();
        assert_eq!(log.len(), 1, "{ROW}: iteration {i}: one decision recorded");
        let want = match log[0].state {
            GateState::Certified(_) => (Some(Refusal::ReplayOwed), true),
            GateState::Terminal => (Some(Refusal::Restarting), false),
            other => panic!("{ROW}: iteration {i}: unexpected state {other:?}"),
        };
        assert_eq!(
            (got, booted.gate.replay_owed()),
            want,
            "{ROW}: iteration {i}"
        );
        if want.1 { owed += 1 } else { restarting += 1 }
    }
    assert!(
        owed > 0 && restarting > 0,
        "{ROW}: both kinds: {owed}/{restarting}"
    );
}

/// Calls `call` on a fresh Paused adapter from another thread while an outside
/// holder keeps both certification locks, and returns its result and the gate
/// state afterwards. The join is bounded: a call that took a lock would hang.
async fn sync_call_under_held_locks<R: Send + 'static>(
    what: &str,
    call: impl FnOnce(&mut super::ConfigFloor) -> R + Send + 'static,
) -> (R, GateState) {
    let booted = Booted::new(support::BASE);
    let mut floor = paused(&booted).await;
    let _reload = booted
        .registry
        .reload_lock_handle()
        .try_lock_owned()
        .expect("outside holder takes the reload lock");
    let lock = crate::config_persistence::lock::lock_path(&booted.cfg.path);
    let _config = crate::fs_lock::ExclusiveFileLock::try_acquire(&lock)
        .expect("outside holder takes the config lock");
    let join = std::thread::spawn(move || call(&mut floor));
    let result = support::join_bounded(join, what);
    (result, booted.gate.state())
}

#[tokio::test]
async fn k12_sync_calls_never_take_a_certification_lock() {
    const ROW: &str = "K12";
    // WHEN each of the four calls runs against held locks, THEN it returns and
    // leaves the state its duty names
    let ((), state) = sync_call_under_held_locks("resume", |f| f.resume()).await;
    assert_eq!(state, GateState::Open, "{ROW}: resume");
    let ((), state) =
        sync_call_under_held_locks("release_for_stop", |f| f.release_for_stop()).await;
    assert_eq!(state, GateState::Released, "{ROW}: release_for_stop");
    let ((), state) = sync_call_under_held_locks("commit", |f| f.commit()).await;
    assert_eq!(state, GateState::Terminal, "{ROW}: commit");
    let (settled, _) = sync_call_under_held_locks("settled", |f| f.settled()).await;
    assert!(settled, "{ROW}: settled with no late work");
}
