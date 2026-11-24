// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the health floor adapter (restart slice 6b, test plan r3): the
//! HEALTH rows G1-G8, the wiring rows W1-W2 and the fixtures every row shares
//! (the contract rows are in `health_floor_contract_tests.rs` and
//! `health_floor_matrix_tests.rs`). Every row that saves takes
//! `file::saves_test_lock()`, counts writes as deltas, and ends once
//! `settled()` is true, so nothing writes after it.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use super::super::health_wiring::{Health, SampleInputs, sampler_closure, saver_closure};
use super::HealthFloor;
use crate::clock::ClockBeforeEpoch;
use crate::gateway::restart_floor::{FloorAdapter, FloorFault};
use crate::health_history::gate::{Closure, GateState};
use crate::health_history::pause_points::{Point, arm};
use crate::health_history::{HealthHistory, Restores, file};

pub(super) const T0: u64 = 1_800_000_000;
pub(super) const M1: u64 = 1_000;
pub(super) const M2: u64 = 5_000;
pub(super) const M3: u64 = 9_000;
pub(super) const S2: usize = 7;
/// The hang guard for every bounded wait (the timing gate's floor is 10 s).
pub(super) const GUARD: Duration = Duration::from_secs(30);

#[expect(
    clippy::unnecessary_wraps,
    reason = "the adapter's Clock type returns a Result"
)]
pub(super) fn at_t0() -> Result<u64, ClockBeforeEpoch> {
    Ok(T0)
}

pub(super) fn no_clock() -> Result<u64, ClockBeforeEpoch> {
    Err(ClockBeforeEpoch)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "SampleInputs.memory returns an Option"
)]
pub(super) fn m1() -> Option<u64> {
    Some(M1)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "SampleInputs.memory returns an Option"
)]
pub(super) fn m2() -> Option<u64> {
    Some(M2)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "SampleInputs.memory returns an Option"
)]
pub(super) fn m3() -> Option<u64> {
    Some(M3)
}

/// One history, its file and its gate, as `start_history` builds them.
pub(super) struct Rig {
    _dir: Arc<tempfile::TempDir>,
    pub(super) path: PathBuf,
    pub(super) health: Health,
}

impl Rig {
    pub(super) fn new() -> Self {
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = dir.path().join("health.json");
        let history = Arc::new(HealthHistory::start(None, Restores::Counted(0), T0).0);
        let health = Health {
            history,
            path: Some(path.clone()),
            gate: Arc::default(),
            sample_inputs: Arc::default(),
        };
        Self {
            _dir: dir,
            path,
            health,
        }
    }

    pub(super) fn adapter(&self) -> HealthFloor {
        self.health.floor_adapter(at_t0)
    }

    pub(super) fn saver(&self) -> impl Fn() + Send + Sync + 'static + use<> {
        saver_closure(
            Arc::clone(&self.health.gate),
            Arc::clone(&self.health.history),
            self.health.path.clone(),
            at_t0,
        )
    }

    /// The production sampler closure, sampling `memory` and S2 sessions.
    pub(super) fn sampler(
        &self,
        memory: fn() -> Option<u64>,
    ) -> impl Fn() + Send + Sync + 'static + use<> {
        let inputs = Arc::new(OnceLock::new());
        let _ = inputs.set(SampleInputs {
            memory,
            sessions: Arc::new(|| S2),
        });
        sampler_closure(
            Arc::clone(&self.health.gate),
            Arc::clone(&self.health.history),
            inputs,
            at_t0,
        )
    }

    /// The inputs `spawn_sampler` sets, which the adapter's replay reads.
    pub(super) fn set_replay_inputs(&self, memory: fn() -> Option<u64>) {
        let _ = self.health.sample_inputs.set(SampleInputs {
            memory,
            sessions: Arc::new(|| S2),
        });
    }

    pub(super) fn writes(&self) -> u64 {
        file::write_count(&self.path)
    }

    pub(super) fn key(&self) -> String {
        file::path_key(&self.path)
    }

    pub(super) fn hkey(&self) -> String {
        self.health.history.key()
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).unwrap_or_default()
    }

    pub(super) fn on_disk(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(&self.path).expect("health.json")).expect("json")
    }

    pub(super) fn encoded(&self) -> serde_json::Value {
        serde_json::from_slice(&self.health.history.encode(T0).expect("encodes")).expect("json")
    }

    pub(super) fn gate(&self) -> GateState {
        self.health.gate.state()
    }

    pub(super) fn marked(&self, which: Closure) -> bool {
        self.health.gate.marked(which)
    }
}

/// The largest `key` value anywhere in `json` (the history keeps maxima per window).
pub(super) fn max_of(json: &serde_json::Value, key: &str) -> Option<u64> {
    match json {
        serde_json::Value::Object(map) => map
            .iter()
            .filter_map(|(k, v)| if k == key { v.as_u64() } else { max_of(v, key) })
            .max(),
        serde_json::Value::Array(items) => items.iter().filter_map(|v| max_of(v, key)).max(),
        _ => None,
    }
}

/// Wait (bounded) until `done` holds; `what` names the behaviour a timeout means is missing.
pub(super) fn wait_until(what: &str, done: impl Fn() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < GUARD, "{what}");
        std::thread::yield_now();
    }
}

/// Run `f` on its own thread (a periodic closure as the scheduler runs it).
pub(super) fn on_thread(f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    std::thread::spawn(f)
}

/// Pause and check the gate moved.
pub(super) async fn pause(adapter: &mut HealthFloor, rig: &Rig) {
    adapter
        .pause(tokio::time::Instant::now() + GUARD)
        .await
        .expect("pause");
    assert_eq!(
        rig.gate(),
        GateState::Paused,
        "the gate is not Paused after pause()"
    );
}

/// Start `run` until a thread arrives at `parked`: a saver that found SAVES
/// held by another test's save skipped as busy without arriving, so it is
/// started again.
pub(super) fn start_parked(
    run: impl Fn() -> std::thread::JoinHandle<()>,
    parked: &crate::health_history::pause_points::Parked,
    missing: &str,
) -> std::thread::JoinHandle<()> {
    let start = std::time::Instant::now();
    let mut thread = run();
    while !parked.arrived() {
        if thread.is_finished() {
            thread.join().expect("the closure ends");
            thread = run();
        }
        assert!(start.elapsed() < GUARD, "{missing}");
        std::thread::yield_now();
    }
    thread
}

/// Run the production saver until it marks (a busy skip does not mark).
pub(super) fn mark_save(rig: &Rig) {
    let saver = rig.saver();
    wait_until("the saver did not mark while Paused", || {
        saver();
        rig.marked(Closure::Save)
    });
}

/// Pause, mark both closures while SAVES is free, and assert the marks.
pub(super) async fn pause_and_mark(adapter: &mut HealthFloor, rig: &Rig) {
    pause(adapter, rig).await;
    mark_save(rig);
    (rig.sampler(m2))();
    assert!(
        rig.marked(Closure::Sample),
        "the sampler did not mark while Paused"
    );
}

pub(super) fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + GUARD
}

/// G1 (HEALTH.1): a periodic save in flight holds SAVES with its older
/// snapshot; the checkpoint waits for it and then writes the newer cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_an_in_flight_save_delays_the_cut() {
    let _serial = file::saves_test_lock_async().await;
    let rig = Rig::new();
    (rig.sampler(m1))();
    let mut in_flight = arm(Point::AfterSnapshot, &rig.key(), 1);
    let saver = start_parked(
        || on_thread(rig.saver()),
        &in_flight,
        "the periodic save never reached its write",
    );
    (rig.sampler(m2))();
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    let before = rig.writes();
    let waiting = arm(Point::WorkerWaiting, &rig.key(), 1);
    let checkpoint = adapter.checkpoint(deadline());
    waiting.reached("the checkpoint started no worker that waits on SAVES");
    drop(waiting);
    assert!(
        rig.health.history.lock_is_free(),
        "something other than SAVES blocks the worker"
    );
    in_flight.release();
    saver.join().expect("the saver ends");
    assert_eq!(checkpoint.await, Ok(()));
    assert_eq!(
        rig.writes() - before,
        2,
        "the saver and then the checkpoint each write once"
    );
    assert_eq!(
        max_of(&rig.on_disk(), "memory_max"),
        Some(M2),
        "the cut is older than the in-flight save"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
}

/// G2 (HEALTH.1): a saver that reached its lock before the pause but takes
/// SAVES after the cut sees Paused under SAVES, marks, and writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g2_a_saver_delayed_past_the_cut_skips_and_marks() {
    let _serial = file::saves_test_lock_async().await;
    // An unrelated test's save can hold SAVES when the delayed saver tries it:
    // that attempt is a busy skip, which proves nothing here, so it runs again.
    for _ in 0..100 {
        let rig = Rig::new();
        let mut delayed = arm(Point::SaverBeforeLock, &rig.key(), 1);
        let saver = on_thread(rig.saver());
        delayed.reached("the periodic save never reached its lock");
        let mut adapter = rig.adapter();
        pause(&mut adapter, &rig).await;
        let before = rig.writes();
        assert_eq!(adapter.checkpoint(deadline()).await, Ok(()));
        assert_eq!(rig.writes() - before, 1, "checkpoint wrote nothing");
        let (cut, flag, at_cut) = (rig.bytes(), rig.health.history.incomplete(), rig.writes());
        delayed.release();
        saver.join().expect("the saver ends");
        let busy = file::last_outcome(&rig.path) == Some(file::SaveOutcome::Busy);
        if !busy {
            assert_eq!(rig.writes(), at_cut, "a saver admitted after the cut wrote");
            assert_eq!(rig.bytes(), cut, "the certified file changed");
            assert_eq!(
                rig.health.history.incomplete(),
                flag,
                "a skipped save touched the flag"
            );
            assert_eq!(
                file::last_outcome(&rig.path),
                Some(file::SaveOutcome::GateSkipped)
            );
            assert!(rig.marked(Closure::Save), "the delayed saver did not mark");
        }
        adapter.resume();
        wait_until("the adapter never settled", || adapter.settled());
        if !busy {
            return;
        }
    }
    panic!("every attempt met a busy SAVES");
}

/// G3 (HEALTH.1): (a) a sample before the pause is in the cut; (c) the sample
/// and the tick share one history lock, and a checkpoint started while a
/// sampler holds it includes that sample.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g3_the_sample_cut_runs_under_one_history_lock() {
    let _serial = file::saves_test_lock_async().await;
    let rig = Rig::new();
    (rig.sampler(m1))();
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    let before = rig.writes();
    assert_eq!(adapter.checkpoint(deadline()).await, Ok(()));
    assert_eq!(rig.writes() - before, 1, "checkpoint wrote nothing");
    assert_eq!(
        max_of(&rig.on_disk(), "memory_max"),
        Some(M1),
        "(a) the earlier sample is not in the cut"
    );
    adapter.resume();
    wait_until("the adapter never settled after resume", || {
        adapter.settled()
    });
    let mut parked = arm(Point::SampleBeforeTick, &rig.hkey(), 1);
    let sampler = on_thread(rig.sampler(m3));
    parked.reached("the sampler never applied its sample");
    assert!(
        !rig.health.history.lock_is_free(),
        "(c) the sample and the tick are under two locks"
    );
    pause(&mut adapter, &rig).await;
    let checkpoint = adapter.checkpoint(deadline());
    parked.release();
    sampler.join().expect("the sampler ends");
    assert_eq!(checkpoint.await, Ok(()));
    assert_eq!(
        max_of(&rig.on_disk(), "memory_max"),
        Some(M3),
        "(c) the parked sample is not in the cut"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
}

/// G3(b) (HEALTH.1; the round-3 HIGH, closed by functional proof): a sampler
/// that reached the history lock while Open but takes it after the cut sees
/// Paused under the lock and changes nothing. The encode assert comes first,
/// so the red run fails here, and the "admission read before the history lock"
/// mutant (it read Open at entry) fails here too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g3b_a_sampler_delayed_past_the_cut_changes_nothing() {
    let _serial = file::saves_test_lock_async().await;
    let rig = Rig::new();
    let mut delayed = arm(Point::SamplerBeforeLock, &rig.hkey(), 1);
    let late = on_thread(rig.sampler(m2));
    delayed.reached("the sampler never reached the history lock");
    let mut adapter = rig.adapter();
    let _ = adapter.pause(deadline()).await;
    let _ = adapter.checkpoint(deadline()).await;
    let at_cut = rig.encoded();
    delayed.release();
    late.join().expect("the sampler ends");
    assert_eq!(
        rig.encoded(),
        at_cut,
        "a sampler admitted after the cut changed the history"
    );
    assert_eq!(rig.gate(), GateState::Paused, "premise: the gate is Paused");
    assert!(
        rig.marked(Closure::Sample),
        "the delayed sampler did not mark"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
}

/// A task or config owner for the coordinator rows: Ok at once, or a pause
/// held until the row lets it go (it says when the pause is entered).
pub(super) struct Fake {
    pub(super) owner: crate::gateway::restart_floor::FloorOwner,
    pub(super) hold: Option<tokio::sync::oneshot::Receiver<()>>,
    pub(super) entered: Option<std::sync::mpsc::Sender<()>>,
}

impl Fake {
    pub(super) fn ready(owner: crate::gateway::restart_floor::FloorOwner) -> Box<dyn FloorAdapter> {
        Box::new(Self {
            owner,
            hold: None,
            entered: None,
        })
    }
}

impl FloorAdapter for Fake {
    fn owner(&self) -> crate::gateway::restart_floor::FloorOwner {
        self.owner
    }

    fn pause(
        &mut self,
        _deadline: tokio::time::Instant,
    ) -> futures::future::BoxFuture<'_, Result<(), FloorFault>> {
        let (hold, entered) = (self.hold.take(), self.entered.take());
        Box::pin(async move {
            if let Some(entered) = entered {
                let _ = entered.send(());
            }
            if let Some(hold) = hold {
                let _ = hold.await;
            }
            Ok(())
        })
    }

    fn checkpoint(
        &mut self,
        _deadline: tokio::time::Instant,
    ) -> futures::future::BoxFuture<'_, Result<(), FloorFault>> {
        Box::pin(async { Ok(()) })
    }

    fn resume(&mut self) {}

    fn release_for_stop(&mut self) {}

    fn commit(&mut self) {}

    fn settled(&self) -> bool {
        true
    }
}

/// Run the production saver until it writes once (another test's save may
/// hold SAVES for a moment, which makes one attempt skip as busy).
pub(super) fn save_once(rig: &Rig) {
    let before = rig.writes();
    let saver = rig.saver();
    for _ in 0..1_000 {
        saver();
        if rig.writes() > before {
            return;
        }
        std::thread::yield_now();
    }
    panic!("the periodic save never wrote while Open");
}

/// G4 (HEALTH.2): through the real coordinator, a checkpoint whose worker
/// waits on SAVES past the deadline cancels with `DeadlineExceeded`; the worker
/// later ends without writing, and the next periodic save writes.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[expect(
    clippy::await_holding_lock,
    reason = "holding SAVES past the deadline is the window under test"
)]
async fn g4_a_save_lock_held_past_the_deadline_cancels_and_saving_goes_on() {
    use crate::gateway::restart_floor::{
        CancelReason, Cancelled, FloorOwner, FloorStage, run_checkpoint,
    };
    let _serial = file::saves_test_lock_async().await;
    let rig = Rig::new();
    let held = file::hold_saves();
    let mut adapters = vec![
        Fake::ready(FloorOwner::TaskStore),
        Fake::ready(FloorOwner::Config),
        Box::new(rig.adapter()) as Box<dyn FloorAdapter>,
    ];
    let waiting = arm(Point::WorkerWaiting, &rig.key(), 1);
    let flag = rig.health.history.incomplete();
    let outcome = {
        let run = run_checkpoint(
            &mut adapters,
            tokio::time::Instant::now() + Duration::from_secs(10),
        );
        tokio::pin!(run);
        assert!(
            futures::poll!(&mut run).is_pending(),
            "the checkpoint started no worker that waits on SAVES"
        );
        waiting.reached("the checkpoint started no worker that waits on SAVES");
        drop(waiting);
        tokio::time::advance(Duration::from_secs(10)).await;
        run.await.err()
    };
    assert_eq!(
        outcome,
        Some(Cancelled {
            owner: FloorOwner::Health,
            stage: FloorStage::Checkpoint,
            reason: CancelReason::DeadlineExceeded,
        })
    );
    assert_eq!(
        rig.gate(),
        GateState::Open,
        "the coordinator did not resume the health gate"
    );
    assert!(
        !adapters[2].settled(),
        "settled() while the worker still waits on SAVES"
    );
    let before = rig.writes();
    drop(held);
    wait_until("the late worker never ended", || adapters[2].settled());
    assert_eq!(
        rig.writes(),
        before,
        "the late worker wrote after its attempt was cancelled"
    );
    assert_eq!(
        rig.health.history.incomplete(),
        flag,
        "the late worker touched the flag"
    );
    (rig.sampler(m2))();
    save_once(&rig);
    assert_eq!(
        max_of(&rig.on_disk(), "memory_max"),
        Some(M2),
        "saving did not go on after the cancel"
    );
}

/// G5 (HEALTH.3): a write error is `SaveFailed`; the flag is set; the gate stays Paused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g5_a_write_error_cancels_with_save_failed() {
    let _serial = file::saves_test_lock_async().await;
    let rig = Rig::new();
    std::fs::create_dir(&rig.path).expect("a directory where the file goes");
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    assert!(
        !rig.health.history.incomplete(),
        "premise: the history starts complete"
    );
    let before = rig.writes();
    assert_eq!(
        adapter.checkpoint(deadline()).await,
        Err(FloorFault::SaveFailed)
    );
    assert!(
        rig.health.history.incomplete(),
        "a failed checkpoint left the history complete"
    );
    assert_eq!(rig.writes(), before, "a failed checkpoint counted a write");
    assert_eq!(
        rig.gate(),
        GateState::Paused,
        "a failed checkpoint resumed itself"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
}

/// The refusal rows' shared asserts: Unavailable, no worker, nothing written.
pub(super) async fn refused_without_a_worker(mut adapter: HealthFloor, rig: &Rig) {
    pause(&mut adapter, rig).await;
    let (before, flag) = (rig.writes(), rig.health.history.incomplete());
    assert_eq!(
        adapter.checkpoint(deadline()).await,
        Err(FloorFault::Unavailable)
    );
    assert!(adapter.settled(), "a refused checkpoint started a worker");
    assert_eq!(rig.writes(), before, "a refused checkpoint wrote");
    assert_eq!(
        rig.health.history.incomplete(),
        flag,
        "a refused checkpoint touched the flag"
    );
    assert_eq!(
        rig.gate(),
        GateState::Paused,
        "a refused checkpoint resumed itself"
    );
    adapter.resume();
}

/// G6 (HEALTH.3): an invalid clock refuses at once, with no worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g6_an_invalid_clock_is_unavailable_without_a_worker() {
    let _serial = file::saves_test_lock_async().await;
    let rig = Rig::new();
    refused_without_a_worker(rig.health.floor_adapter(no_clock), &rig).await;
}

/// G7 (HEALTH.3): saves off for this run (the undecodable file could not be
/// moved aside) refuses at once, with no worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g7_saves_off_is_unavailable_without_a_worker() {
    let _serial = file::saves_test_lock_async().await;
    let mut rig = Rig::new();
    rig.health.path = super::super::health_wiring::save_path(
        true,
        rig.path.clone(),
        T0,
        &rig.health.history,
        |_, _| Err(std::io::Error::other("cannot move aside")),
    );
    assert_eq!(rig.health.path, None, "premise: saves are off");
    refused_without_a_worker(rig.adapter(), &rig).await;
}

/// G8 (HEALTH.3): a checkpoint records no clean stop, in the file or in memory;
/// the ordinary stop's shutdown save still does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g8_a_checkpoint_records_no_clean_stop() {
    let _serial = file::saves_test_lock_async().await;
    let rig = Rig::new();
    (rig.sampler(m1))();
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    let before = rig.writes();
    assert_eq!(adapter.checkpoint(deadline()).await, Ok(()));
    assert_eq!(rig.writes() - before, 1, "checkpoint wrote nothing");
    let on_disk = rig.on_disk();
    assert_eq!(
        max_of(&on_disk, "memory_max"),
        Some(M1),
        "the checkpoint wrote another snapshot"
    );
    assert_eq!(
        on_disk["clean_stop"],
        serde_json::Value::Null,
        "the checkpoint recorded a clean stop"
    );
    assert_eq!(
        rig.encoded()["clean_stop"],
        serde_json::Value::Null,
        "the checkpoint stopped the history"
    );
    adapter.commit();
    wait_until("the adapter never settled", || adapter.settled());
    rig.health.shutdown_save().run_now();
    assert_ne!(
        rig.on_disk()["clean_stop"],
        serde_json::Value::Null,
        "premise: the shutdown save records the stop"
    );
}

/// Let the scheduler task run after a clock advance.
pub(super) async fn settle_tasks() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// W1 (HEALTH.1): the production periodic save (`start_history`'s own closure)
/// skips and marks while Paused; resume replays it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn w1_the_production_periodic_save_obeys_the_gate() {
    let _serial = file::saves_test_lock_async().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = dir.path().join("health.json");
    let (stop, stopped) = tokio::sync::broadcast::channel(1);
    let (health, saver) =
        super::super::health_wiring::start_history(dir.path(), T0, Restores::Counted(0), stopped);
    let mut adapter = health.floor_adapter(at_t0);
    adapter.pause(deadline()).await.expect("pause");
    let before = file::write_count(&path);
    settle_tasks().await;
    // Each tick's save runs on its own thread; one that met SAVES held by an
    // unrelated test's save skipped as busy, so the next tick is the retry.
    for _ in 0..50 {
        file::forget_outcome(&path);
        tokio::time::advance(
            super::super::counter_wiring::COUNTER_SAVE_INTERVAL + Duration::from_secs(1),
        )
        .await;
        settle_tasks().await;
        wait_until("the periodic save never ran on its tick", || {
            file::last_outcome(&path).is_some()
        });
        if file::last_outcome(&path) != Some(file::SaveOutcome::Busy) {
            break;
        }
    }
    assert_eq!(
        file::last_outcome(&path),
        Some(file::SaveOutcome::GateSkipped),
        "the periodic save was not turned away while Paused"
    );
    assert!(
        health.gate.marked(Closure::Save),
        "the periodic save never marked while Paused"
    );
    assert_eq!(
        file::write_count(&path),
        before,
        "the periodic save wrote while Paused"
    );
    adapter.resume();
    wait_until("resume did not replay the periodic save", || {
        file::write_count(&path) > before
    });
    wait_until("the adapter never settled", || adapter.settled());
    let _ = stop.send(());
    saver.await.expect("the scheduler ends");
}

/// W2 (HEALTH.1): the production sampler (`spawn_sampler`'s own closure) skips
/// and marks while Paused, leaving the history unchanged.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn w2_the_production_sampler_obeys_the_gate() {
    let _serial = file::saves_test_lock_async().await;
    let dir = crate::test_dir_keep::kept_tempdir();
    let (stop, stopped) = tokio::sync::broadcast::channel(2);
    let (health, saver) =
        super::super::health_wiring::start_history(dir.path(), T0, Restores::Counted(0), stopped);
    let sampler = health.spawn_sampler(|| S2, stop.subscribe());
    let mut adapter = health.floor_adapter(at_t0);
    adapter.pause(deadline()).await.expect("pause");
    let before = health.history.encode(T0).expect("encodes");
    settle_tasks().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    settle_tasks().await;
    wait_until("the periodic sample never marked while Paused", || {
        health.gate.marked(Closure::Sample)
    });
    assert_eq!(
        health.history.encode(T0).expect("encodes"),
        before,
        "the periodic sample changed the history while Paused"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
    let _ = stop.send(());
    saver.await.expect("the saver ends");
    sampler.await.expect("the sampler ends");
}
