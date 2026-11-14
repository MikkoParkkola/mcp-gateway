// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task store adapter against the floor contract v2:
//! futures returned before any work, no fault for elapsed time, the state
//! table's calls and repeats, superseded late work, settled. Written before
//! the adapter: against the stub every row fails on its own assertion.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::record::PreparedTask;
use super::super::store::gate::GateState;
use super::super::store::{StoreError, StoreWriteStage, TaskStore};
use super::OWNER;
use super::floor::{certify, counting, deadline, floor, seeded, task_save_cancel, three, within};
use super::support::*;
use crate::gateway::restart_floor::{CancelReason, FloorAdapter, FloorFault, run_checkpoint};

/// A create by `OWNER` as an External caller, run on its own task.
fn spawn_create(
    store: &TaskStore,
    identity: u64,
) -> tokio::task::JoinHandle<Result<(), StoreError>> {
    let store = store.clone();
    tokio::spawn(async move {
        store
            .create(PreparedTask::for_test(&task(), OWNER, identity))
            .await
            .map(drop)
    })
}

/// Wait until `n` submitters are parked at the gate.
async fn parked(row: &str, store: &TaskStore, n: usize) {
    within(row, async {
        while store.gate_for_test().parked() < n {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

// C1: pause and checkpoint return their futures before any work: the pause
// call alone sets the gate; a checkpoint future never polled spawns nothing.
#[tokio::test]
async fn c1_futures_are_returned_before_any_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let (hook, renames) = counting(StoreWriteStage::Rename, false);
    store.set_hook(Some(hook)).await;
    let mut floor = floor(&store);
    let deadline = deadline();
    drop(floor.pause(deadline));
    assert_eq!(
        store.gate_for_test().state(),
        GateState::Paused(1),
        "the pause call alone set the gate"
    );
    drop(floor.checkpoint(deadline));
    tokio::task::yield_now().await;
    assert_eq!(renames.load(Ordering::SeqCst), 0, "nothing re-saved");
    assert!(floor.settled(), "nothing spawned");
}

// C2: a checkpoint held past the deadline stays pending with no fault of its
// own: the coordinator drops it and reports DeadlineExceeded at the task store.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[expect(
    clippy::await_holding_lock,
    reason = "holding the ordering lock keeps the re-save from finishing before the deadline"
)]
async fn c2_a_checkpoint_held_past_the_deadline_is_dropped_without_a_fault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let resumes = Arc::new(AtomicUsize::new(0));
    let mut adapters = three(&store, &resumes);
    let held = store.hold_order_for_test();
    let outcome = within("C2", run_checkpoint(&mut adapters, deadline()))
        .await
        .map(drop);
    assert_eq!(
        outcome,
        Err(task_save_cancel(CancelReason::DeadlineExceeded))
    );
    drop(held);
    assert_eq!(
        store.gate_for_test().state(),
        GateState::Open,
        "the cancel resumed the store"
    );
}

/// Bring `floor` to Draining: create A parks during a pause, resume admits it
/// as the cohort while the ordering lock is held (so it stays in flight), and
/// create B then parks behind the drain. The caller drops the guard to let A
/// finish. Returns the guard and both creates.
#[expect(
    clippy::await_holding_lock,
    reason = "the held ordering lock is what keeps the cohort member in flight"
)]
async fn draining<'a>(
    row: &str,
    store: &'a TaskStore,
    floor: &mut super::super::store::floor::TaskFloor,
) -> (
    std::sync::MutexGuard<'a, ()>,
    tokio::task::JoinHandle<Result<(), StoreError>>,
    tokio::task::JoinHandle<Result<(), StoreError>>,
) {
    assert_eq!(within(row, floor.pause(deadline())).await, Ok(()));
    let a = spawn_create(store, 11);
    parked(row, store, 1).await;
    let held = store.hold_order_for_test();
    floor.resume();
    within(row, async {
        while store.gate_for_test().in_flight() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let b = spawn_create(store, 12);
    parked(row, store, 1).await;
    assert_eq!(
        store.gate_for_test().state(),
        GateState::Draining { left: 1 },
        "{row}: the cohort member holds the drain"
    );
    (held, a, b)
}

// C3a: a pause dropped part way, and a checkpoint dropped while its re-save
// waits, are each cleared by resume (gate Open) and by release_for_stop
// (gate Released); a new write then lands.
#[tokio::test]
#[expect(
    clippy::await_holding_lock,
    reason = "the held ordering lock keeps the dropped checkpoint's re-save waiting"
)]
async fn c3a_a_dropped_pause_or_checkpoint_is_cleared_by_resume_and_by_release() {
    for release in [false, true] {
        for drop_checkpoint in [false, true] {
            let case = format!("release={release} checkpoint={drop_checkpoint}");
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("tasks");
            let (store, _) = seeded(&path, 1).await;
            let mut floor = floor(&store);
            let deadline = deadline();
            drop(floor.pause(deadline));
            if drop_checkpoint {
                let held = store.hold_order_for_test();
                {
                    let mut checkpoint = floor.checkpoint(deadline);
                    assert!(
                        futures::poll!(checkpoint.as_mut()).is_pending(),
                        "{case}: the re-save waits on the held lock"
                    );
                }
                drop(held);
            }
            if release {
                floor.release_for_stop();
            } else {
                floor.resume();
            }
            let want = if release {
                GateState::Released
            } else {
                GateState::Open
            };
            assert_eq!(store.gate_for_test().state(), want, "{case}");
            let landed = within(&case, spawn_create(&store, 5)).await.unwrap();
            assert_eq!(landed, Ok(()), "{case}: a new write lands");
        }
    }
}

// C3b: resume from Paused and from Certified opens the gate.
#[tokio::test]
async fn c3b_resume_from_paused_or_certified_opens_the_gate() {
    for certified in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let (store, _) = seeded(&path, 1).await;
        let mut floor = floor(&store);
        let before = if certified {
            assert_eq!(certify("C3b", &mut floor).await, Ok(()));
            GateState::Certified(1)
        } else {
            assert_eq!(within("C3b", floor.pause(deadline())).await, Ok(()));
            GateState::Paused(1)
        };
        assert_eq!(store.gate_for_test().state(), before);
        floor.resume();
        assert_eq!(
            store.gate_for_test().state(),
            GateState::Open,
            "from {before:?}"
        );
    }
}

// C3c (and C11, a pin): release_for_stop from Paused, Certified and Draining
// releases the gate; parked work (cohort and Draining parker alike) lands with
// no ordering; nothing is replayed and a sweep may run again.
#[tokio::test]
#[expect(
    clippy::await_holding_lock,
    reason = "the held ordering lock keeps the cohort member in flight until the release"
)]
async fn c3c_release_from_paused_certified_or_draining_releases_parked_work() {
    for from in ["Paused", "Certified", "Draining"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let (store, _) = seeded(&path, 1).await;
        let mut floor = floor(&store);
        let mut waiting = Vec::new();
        let mut held = None;
        match from {
            "Paused" => {
                assert_eq!(within(from, floor.pause(deadline())).await, Ok(()));
                waiting.push(spawn_create(&store, 21));
                parked(from, &store, 1).await;
            }
            "Certified" => {
                assert_eq!(certify(from, &mut floor).await, Ok(()));
                waiting.push(spawn_create(&store, 21));
                parked(from, &store, 1).await;
            }
            _ => {
                let (guard, a, b) = draining(from, &store, &mut floor).await;
                held = Some(guard);
                waiting.extend([a, b]);
            }
        }
        floor.release_for_stop();
        assert_eq!(store.gate_for_test().state(), GateState::Released, "{from}");
        assert!(store.sweeps_allowed(), "{from}: a sweep may run again");
        drop(held);
        for write in waiting {
            let landed = within(from, write).await.unwrap();
            assert_eq!(landed, Ok(()), "{from}: parked work lands");
        }
    }
}

// C3d and C9: while Draining, pause and checkpoint answer Unavailable and
// resume and commit change nothing; settled() is false until the drain opens
// the gate, then true.
#[tokio::test]
#[expect(
    clippy::await_holding_lock,
    reason = "the held ordering lock keeps the drain open while the calls run"
)]
async fn c3d_calls_while_draining_change_nothing_and_settled_waits_for_the_drain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let mut floor = floor(&store);
    let (held, a, b) = draining("C3d", &store, &mut floor).await;
    let draining = store.gate_for_test().state();
    assert!(!floor.settled(), "C9: the drain is late work");
    assert_eq!(
        within("C3d", floor.pause(deadline())).await,
        Err(FloorFault::Unavailable)
    );
    assert_eq!(
        within("C3d", floor.checkpoint(deadline())).await,
        Err(FloorFault::Unavailable)
    );
    floor.resume();
    floor.commit();
    assert_eq!(
        store.gate_for_test().state(),
        draining,
        "no call changed it"
    );
    drop(held);
    assert_eq!(within("C3d a", a).await.unwrap(), Ok(()));
    assert_eq!(within("C3d b", b).await.unwrap(), Ok(()));
    assert_eq!(store.gate_for_test().state(), GateState::Open);
    assert!(
        floor.settled(),
        "C9: settled once the drain opened the gate"
    );
}

// C3e: a checkpoint in any state but Paused(this attempt) answers Unavailable
// with no state change and no re-save.
#[tokio::test]
async fn c3e_checkpoint_outside_its_paused_attempt_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let (hook, renames) = counting(StoreWriteStage::Rename, false);
    store.set_hook(Some(hook)).await;
    let mut floor = floor(&store);
    assert_eq!(
        within("C3e open", floor.checkpoint(deadline())).await,
        Err(FloorFault::Unavailable),
        "no pause started"
    );
    assert_eq!(certify("C3e", &mut floor).await, Ok(()));
    let resaved = renames.load(Ordering::SeqCst);
    assert_eq!(
        within("C3e certified", floor.checkpoint(deadline())).await,
        Err(FloorFault::Unavailable),
        "already certified"
    );
    assert_eq!(store.gate_for_test().state(), GateState::Certified(1));
    assert_eq!(renames.load(Ordering::SeqCst), resaved, "no second re-save");
}

// C4 and C10: a re-save held at its second record, whose checkpoint is dropped
// and whose attempt is resumed, stops at its next record and sets no gate;
// settled() is false while it runs and true after; then a new attempt
// certifies.
#[tokio::test]
async fn c4_a_superseded_resave_stops_at_its_next_record_and_a_new_attempt_certifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 3).await;
    let renames = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Mutex::new(released);
    store
        .set_hook(Some(Arc::new({
            let (renames, entered) = (Arc::clone(&renames), Arc::clone(&entered));
            move |stage| {
                if stage == StoreWriteStage::Rename && renames.fetch_add(1, Ordering::SeqCst) == 1 {
                    entered.notify_one();
                    let _ = released.lock().map(|rx| rx.recv());
                }
                Ok(())
            }
        })))
        .await;
    let mut floor = floor(&store);
    let deadline = deadline();
    assert_eq!(within("C4 pause", floor.pause(deadline)).await, Ok(()));
    {
        let mut checkpoint = floor.checkpoint(deadline);
        within("C4 second record", async {
            tokio::select! {
                _ = &mut checkpoint => panic!("C4: the re-save finished past its hold"),
                () = entered.notified() => {}
            }
        })
        .await;
    }
    floor.resume();
    assert!(!floor.settled(), "the superseded re-save still runs");
    let _ = release.send(());
    within("C4 settles", async {
        while !floor.settled() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        renames.load(Ordering::SeqCst),
        2,
        "stopped at its next record"
    );
    assert_eq!(
        store.gate_for_test().state(),
        GateState::Open,
        "no gate set"
    );
    store.set_hook(None).await;
    assert_eq!(certify("C10", &mut floor).await, Ok(()));
}

// C5: commit from Certified makes the gate Terminal: an External create parked
// before it runs, a new External create is refused Restarting, and an
// Internal write is admitted.
#[tokio::test]
async fn c5_commit_from_certified_is_terminal_at_the_edge() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 1).await;
    let revision = store.get(OWNER, &ids[0]).unwrap().revision;
    let mut floor = floor(&store);
    assert_eq!(certify("C5", &mut floor).await, Ok(()));
    let before = spawn_create(&store, 31);
    parked("C5", &store, 1).await;
    floor.commit();
    assert_eq!(store.gate_for_test().state(), GateState::Terminal);
    let landed = within("C5 parked before", before).await.unwrap();
    assert_eq!(landed, Ok(()), "parked before the commit: runs");
    let fresh = within("C5 new", spawn_create(&store, 32)).await.unwrap();
    assert_eq!(
        fresh,
        Err(StoreError::Restarting),
        "a new External is refused"
    );
    store
        .mark_dispatched(OWNER, &ids[0], revision)
        .await
        .expect("an Internal write is admitted");
}

// C6: on Released and on Terminal every call changes nothing (pause and
// checkpoint answer Unavailable); resume on an Open gate with no pause is a
// no-op.
#[tokio::test]
async fn c6_released_and_terminal_ignore_every_call() {
    for end in ["Released", "Terminal"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let (store, _) = seeded(&path, 1).await;
        let mut floor = floor(&store);
        assert_eq!(certify(end, &mut floor).await, Ok(()));
        if end == "Released" {
            floor.release_for_stop();
        } else {
            floor.commit();
        }
        let state = store.gate_for_test().state();
        assert_eq!(
            within(end, floor.pause(deadline())).await,
            Err(FloorFault::Unavailable),
            "{end}"
        );
        assert_eq!(
            within(end, floor.checkpoint(deadline())).await,
            Err(FloorFault::Unavailable),
            "{end}"
        );
        floor.resume();
        floor.release_for_stop();
        floor.commit();
        assert_eq!(store.gate_for_test().state(), state, "{end}: unchanged");
    }
    let dir = tempfile::tempdir().unwrap();
    let (store, _) = seeded(&dir.path().join("tasks"), 1).await;
    let mut floor = floor(&store);
    floor.resume();
    assert_eq!(
        store.gate_for_test().state(),
        GateState::Open,
        "no pause: no-op"
    );
}

// C8 (a pin: the stub passes it too): the sync calls complete while late work
// holds the ordering lock.
#[tokio::test]
async fn c8_the_sync_calls_never_wait_on_the_ordering_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let mut floor = floor(&store);
    assert_eq!(within("C8", floor.pause(deadline())).await, Ok(()));
    let held = store.hold_order_for_test();
    let calls = std::thread::spawn(move || {
        floor.resume();
        floor.release_for_stop();
        floor.commit();
        floor.settled()
    });
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !calls.is_finished() {
        assert!(
            std::time::Instant::now() < bound,
            "C8: a sync call waited on the ordering lock"
        );
        std::thread::yield_now();
    }
    drop(held);
    assert!(calls.join().is_ok(), "C8: no sync call panicked");
}
