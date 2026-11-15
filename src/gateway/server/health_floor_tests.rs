// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the health floor adapter (restart slice 6b, test plan r3): the
//! HEALTH rows G1-G8, the wiring rows W1-W2 and the contract rows C1-C18.
//! Every row that saves takes `file::saves_test_lock()`, counts writes as
//! deltas, and ends once `settled()` is true, so nothing writes after it.

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

const T0: u64 = 1_800_000_000;
const M1: u64 = 1_000;
const M2: u64 = 5_000;
const M3: u64 = 9_000;
const S2: usize = 7;
/// The hang guard for every bounded wait (the timing gate's floor is 10 s).
const GUARD: Duration = Duration::from_secs(30);

fn at_t0() -> Result<u64, ClockBeforeEpoch> {
    Ok(T0)
}

fn no_clock() -> Result<u64, ClockBeforeEpoch> {
    Err(ClockBeforeEpoch)
}

fn m1() -> Option<u64> {
    Some(M1)
}

fn m2() -> Option<u64> {
    Some(M2)
}

fn m3() -> Option<u64> {
    Some(M3)
}

/// One history, its file and its gate, as `start_history` builds them.
struct Rig {
    _dir: Arc<tempfile::TempDir>,
    path: PathBuf,
    health: Health,
}

impl Rig {
    fn new() -> Self {
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

    fn adapter(&self) -> HealthFloor {
        self.health.floor_adapter(at_t0)
    }

    fn saver(&self) -> impl Fn() + Send + Sync + 'static + use<> {
        saver_closure(
            Arc::clone(&self.health.gate),
            Arc::clone(&self.health.history),
            self.health.path.clone(),
            at_t0,
        )
    }

    /// The production sampler closure, sampling `memory` and S2 sessions.
    fn sampler(&self, memory: fn() -> Option<u64>) -> impl Fn() + Send + Sync + 'static + use<> {
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
    fn set_replay_inputs(&self, memory: fn() -> Option<u64>) {
        let _ = self.health.sample_inputs.set(SampleInputs {
            memory,
            sessions: Arc::new(|| S2),
        });
    }

    fn writes(&self) -> u64 {
        file::write_count(&self.path)
    }

    fn key(&self) -> String {
        file::path_key(&self.path)
    }

    fn hkey(&self) -> String {
        self.health.history.key()
    }

    fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).unwrap_or_default()
    }

    fn on_disk(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(&self.path).expect("health.json")).expect("json")
    }

    fn encoded(&self) -> serde_json::Value {
        serde_json::from_slice(&self.health.history.encode(T0).expect("encodes")).expect("json")
    }

    fn gate(&self) -> GateState {
        self.health.gate.state()
    }

    fn marked(&self, which: Closure) -> bool {
        self.health.gate.marked(which)
    }
}

/// The largest `key` value anywhere in `json` (the history keeps maxima per window).
fn max_of(json: &serde_json::Value, key: &str) -> Option<u64> {
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
fn wait_until(what: &str, done: impl Fn() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(start.elapsed() < GUARD, "{what}");
        std::thread::yield_now();
    }
}

/// Run `f` on its own thread (a periodic closure as the scheduler runs it).
fn on_thread(f: impl FnOnce() + Send + 'static) -> std::thread::JoinHandle<()> {
    std::thread::spawn(f)
}

/// Pause and check the gate moved.
async fn pause(adapter: &mut HealthFloor, rig: &Rig) {
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
fn start_parked(
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
fn mark_save(rig: &Rig) {
    let saver = rig.saver();
    wait_until("the saver did not mark while Paused", || {
        saver();
        rig.marked(Closure::Save)
    });
}

/// Pause, mark both closures while SAVES is free, and assert the marks.
async fn pause_and_mark(adapter: &mut HealthFloor, rig: &Rig) {
    pause(adapter, rig).await;
    mark_save(rig);
    (rig.sampler(m2))();
    assert!(
        rig.marked(Closure::Sample),
        "the sampler did not mark while Paused"
    );
}

fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + GUARD
}

/// G1 (HEALTH.1): a periodic save in flight holds SAVES with its older
/// snapshot; the checkpoint waits for it and then writes the newer cut.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g1_an_in_flight_save_delays_the_cut() {
    let _serial = file::saves_test_lock();
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
    let _serial = file::saves_test_lock();
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
    let _serial = file::saves_test_lock();
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
    let _serial = file::saves_test_lock();
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
struct Fake {
    owner: crate::gateway::restart_floor::FloorOwner,
    hold: Option<tokio::sync::oneshot::Receiver<()>>,
    entered: Option<std::sync::mpsc::Sender<()>>,
}

impl Fake {
    fn ready(owner: crate::gateway::restart_floor::FloorOwner) -> Box<dyn FloorAdapter> {
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
fn save_once(rig: &Rig) {
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
/// waits on SAVES past the deadline cancels with DeadlineExceeded; the worker
/// later ends without writing, and the next periodic save writes.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn g4_a_save_lock_held_past_the_deadline_cancels_and_saving_goes_on() {
    use crate::gateway::restart_floor::{
        CancelReason, Cancelled, FloorOwner, FloorStage, run_checkpoint,
    };
    let _serial = file::saves_test_lock();
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

/// G5 (HEALTH.3): a write error is SaveFailed; the flag is set; the gate stays Paused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g5_a_write_error_cancels_with_save_failed() {
    let _serial = file::saves_test_lock();
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
async fn refused_without_a_worker(mut adapter: HealthFloor, rig: &Rig) {
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
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    refused_without_a_worker(rig.health.floor_adapter(no_clock), &rig).await;
}

/// G7 (HEALTH.3): saves off for this run (the undecodable file could not be
/// moved aside) refuses at once, with no worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn g7_saves_off_is_unavailable_without_a_worker() {
    let _serial = file::saves_test_lock();
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
    let _serial = file::saves_test_lock();
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
    let (_, shutdown_save) = rig.health.shutdown_save();
    shutdown_save();
    assert_ne!(
        rig.on_disk()["clean_stop"],
        serde_json::Value::Null,
        "premise: the shutdown save records the stop"
    );
}

/// Let the scheduler task run after a clock advance.
async fn settle_tasks() {
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// W1 (HEALTH.1): the production periodic save (start_history's own closure)
/// skips and marks while Paused; resume replays it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn w1_the_production_periodic_save_obeys_the_gate() {
    let _serial = file::saves_test_lock();
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

/// W2 (HEALTH.1): the production sampler (spawn_sampler's own closure) skips
/// and marks while Paused, leaving the history unchanged.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn w2_the_production_sampler_obeys_the_gate() {
    let _serial = file::saves_test_lock();
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

/// Start a checkpoint with SAVES held, poll it once (pending), wait for its
/// worker, then drop the future (the polled drop; C16 is the unpolled one).
async fn drop_while_waiting(adapter: &mut HealthFloor, rig: &Rig) {
    let waiting = arm(Point::WorkerWaiting, &rig.key(), 1);
    let mut checkpoint = adapter.checkpoint(deadline());
    assert!(
        futures::poll!(&mut checkpoint).is_pending(),
        "the checkpoint started no worker that waits on SAVES"
    );
    waiting.reached("the checkpoint started no worker that waits on SAVES");
    drop(waiting);
    drop(checkpoint);
}

/// C1: a checkpoint dropped while its worker waits writes nothing; resume
/// replays the marked sample and then the marked save, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c1_a_dropped_checkpoint_then_resume_replays_once() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    rig.set_replay_inputs(m2);
    let mut adapter = rig.adapter();
    pause_and_mark(&mut adapter, &rig).await;
    let before = rig.writes();
    let held = file::hold_saves();
    drop_while_waiting(&mut adapter, &rig).await;
    let mut replay = arm(Point::ReplayBeforeSample, &rig.hkey(), 1);
    adapter.resume();
    replay.reached("resume did not replay the marked closures");
    drop(held);
    wait_until("the dropped attempt's worker never ended", || {
        adapter.worker_finished()
    });
    assert_eq!(rig.writes(), before, "the dropped attempt's worker wrote");
    replay.release();
    wait_until("the adapter never settled", || adapter.settled());
    assert_eq!(
        rig.writes() - before,
        1,
        "the replay did not save exactly once"
    );
    assert_eq!(
        max_of(&rig.on_disk(), "memory_max"),
        Some(M2),
        "the replayed sample is not in the replayed save"
    );
    assert_eq!(rig.gate(), GateState::Open);
}

/// C1a: the drop guard alone stops the worker's write (SAVES is released
/// before any resume or release could clear the attempt).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c1a_the_drop_guard_alone_stops_the_write() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    pause_and_mark(&mut adapter, &rig).await;
    let before = rig.writes();
    let held = file::hold_saves();
    drop_while_waiting(&mut adapter, &rig).await;
    drop(held);
    wait_until("the dropped attempt's worker never ended", || {
        adapter.worker_finished()
    });
    assert_eq!(rig.writes(), before, "the dropped attempt's worker wrote");
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
}

/// C2: a superseded worker already past its live check writes once; a new
/// checkpoint is refused until it ends, then proceeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c2_a_superseded_worker_writes_once_and_blocks_a_new_checkpoint() {
    use futures::FutureExt as _;
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    let before = rig.writes();
    let mut past = arm(Point::AfterLiveCheck, &rig.key(), 1);
    {
        let checkpoint = adapter.checkpoint(deadline());
        past.reached("the checkpoint started no worker");
        drop(checkpoint);
    }
    adapter.resume();
    pause(&mut adapter, &rig).await;
    let second = adapter.checkpoint(deadline()).now_or_never();
    assert_eq!(
        second,
        Some(Err(FloorFault::Unavailable)),
        "a checkpoint started over an unfinished worker"
    );
    assert!(
        !adapter.settled(),
        "settled() while the superseded worker runs"
    );
    past.release();
    wait_until("the superseded worker never ended", || adapter.settled());
    assert_eq!(
        rig.writes() - before,
        1,
        "the superseded worker did not write exactly once"
    );
    assert_eq!(adapter.checkpoint(deadline()).await, Ok(()));
    assert_eq!(
        rig.writes() - before,
        2,
        "the checkpoint after the late worker did not write"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
}

/// C3: resume replays each marked closure once, the sample before the save;
/// release_for_stop replays nothing and lets the closures run again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c3_resume_replays_and_release_for_stop_does_not() {
    let _serial = file::saves_test_lock();
    let (a, b) = (Rig::new(), Rig::new());
    a.set_replay_inputs(m2);
    b.set_replay_inputs(m2);
    let (mut fa, mut fb) = (a.adapter(), b.adapter());
    pause_and_mark(&mut fa, &a).await;
    pause_and_mark(&mut fb, &b).await;
    let (wa, sa) = (a.writes(), a.health.history.sample_count());
    let (wb, sb) = (b.writes(), b.health.history.sample_count());
    let mut replay = arm(Point::ReplayBeforeSample, &a.hkey(), 1);
    fa.resume();
    replay.reached("resume did not replay the marked closures");
    assert_eq!(a.writes(), wa, "the replay saved before it sampled");
    replay.release();
    wait_until("A never settled", || fa.settled());
    assert_eq!(a.writes() - wa, 1, "resume did not replay the save once");
    assert_eq!(
        a.health.history.sample_count() - sa,
        1,
        "resume did not replay the sample once"
    );
    fb.release_for_stop();
    wait_until("B never settled", || fb.settled());
    assert_eq!(b.writes(), wb, "release_for_stop replayed a save");
    assert_eq!(
        b.health.history.sample_count(),
        sb,
        "release_for_stop replayed a sample"
    );
    assert_eq!(b.gate(), GateState::Released);
    assert!(
        b.marked(Closure::Save) && b.marked(Closure::Sample),
        "release_for_stop claimed the marks"
    );
    save_once(&b);
}

/// C4: commit makes the gate Terminal: the closures then skip without
/// marking, resume replays nothing, and the shutdown save still records the stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c4_commit_is_terminal() {
    let _serial = file::saves_test_lock();
    let (a, b) = (Rig::new(), Rig::new());
    let mut fa = a.adapter();
    pause(&mut fa, &a).await;
    assert_eq!(fa.checkpoint(deadline()).await, Ok(()));
    fa.commit();
    assert_eq!(
        a.gate(),
        GateState::Terminal,
        "the gate is not Terminal after commit()"
    );
    let (writes, encoded) = (a.writes(), a.encoded());
    (a.saver())();
    (a.sampler(m2))();
    assert!(
        !a.marked(Closure::Save) && !a.marked(Closure::Sample),
        "a closure marked after commit"
    );
    assert_eq!(a.writes(), writes, "a save ran after commit");
    assert_eq!(a.encoded(), encoded, "a sample ran after commit");
    b.set_replay_inputs(m2);
    let mut fb = b.adapter();
    pause_and_mark(&mut fb, &b).await;
    assert_eq!(fb.checkpoint(deadline()).await, Ok(()));
    fb.commit();
    let writes = b.writes();
    fb.resume();
    wait_until("B never settled", || fb.settled());
    assert_eq!(b.writes(), writes, "resume after commit replayed a save");
    assert_eq!(
        b.gate(),
        GateState::Terminal,
        "resume reopened a committed gate"
    );
    let (_, shutdown_save) = b.health.shutdown_save();
    shutdown_save();
    assert_ne!(
        b.on_disk()["clean_stop"],
        serde_json::Value::Null,
        "the shutdown save did not record the stop"
    );
    wait_until("A never settled", || fa.settled());
}

/// C5: settled() is false while a checkpoint worker runs and true otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_settled_tracks_the_checkpoint_worker() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    assert!(adapter.settled(), "settled() false before any call");
    let held = file::hold_saves();
    pause(&mut adapter, &rig).await;
    drop_while_waiting(&mut adapter, &rig).await;
    assert!(
        !adapter.settled(),
        "settled() while the worker waits on SAVES"
    );
    drop(held);
    wait_until("settled() never became true after the worker ended", || {
        adapter.settled()
    });
    assert_eq!(adapter.checkpoint(deadline()).await, Ok(()));
    assert!(
        adapter.settled(),
        "settled() false after a completed checkpoint"
    );
    adapter.resume();
}

/// The two periodic closures, for the race rows.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Save,
    Sample,
}

impl Kind {
    const BOTH: [Kind; 2] = [Kind::Save, Kind::Sample];

    fn run_on_thread(self, rig: &Rig) -> std::thread::JoinHandle<()> {
        match self {
            Kind::Save => on_thread(rig.saver()),
            Kind::Sample => on_thread(rig.sampler(m2)),
        }
    }

    /// Run it once while Paused so that it marks (the saver retries a busy skip).
    fn mark(self, rig: &Rig) {
        match self {
            Kind::Save => mark_save(rig),
            Kind::Sample => {
                self.run_on_thread(rig).join().expect("the closure ends");
            }
        }
    }

    /// Its effects so far: completed writes, or applied samples.
    fn effects(self, rig: &Rig) -> u64 {
        match self {
            Kind::Save => rig.writes(),
            Kind::Sample => rig.health.history.sample_count(),
        }
    }

    /// The key its admission point is armed under (its lock's owner).
    fn key(self, rig: &Rig) -> String {
        match self {
            Kind::Save => rig.key(),
            Kind::Sample => rig.hkey(),
        }
    }

    fn which(self) -> Closure {
        match self {
            Kind::Save => Closure::Save,
            Kind::Sample => Closure::Sample,
        }
    }
}

/// Pause a fresh rig, start `kind` and park it between its mark and its second read.
async fn parked_at_mark(
    kind: Kind,
) -> (
    Rig,
    HealthFloor,
    crate::health_history::pause_points::Parked,
    std::thread::JoinHandle<()>,
    u64,
) {
    let rig = Rig::new();
    rig.set_replay_inputs(m2);
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    let before = kind.effects(&rig);
    let parked = arm(Point::AdmissionMark, &kind.key(&rig), 1);
    let closure = start_parked(
        || kind.run_on_thread(&rig),
        &parked,
        &format!("the {kind:?} closure never reached its admission mark"),
    );
    (rig, adapter, parked, closure, before)
}

/// C6(a): resume claims the mark while the closure is parked: the closure
/// skips, the replay runs it: exactly one run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c6a_resume_while_parked_runs_it_once_by_the_replay() {
    let _serial = file::saves_test_lock();
    for kind in Kind::BOTH {
        let (rig, mut adapter, mut parked, closure, before) = parked_at_mark(kind).await;
        adapter.resume();
        parked.release();
        closure.join().expect("the closure ends");
        wait_until("the adapter never settled", || adapter.settled());
        assert_eq!(
            kind.effects(&rig) - before,
            1,
            "{kind:?}: not exactly one run"
        );
        assert!(!rig.marked(kind.which()), "{kind:?}: a mark is left behind");
    }
}

/// C6(b): the closure skips first (still Paused), then resume replays it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c6b_skip_then_resume_runs_it_once() {
    let _serial = file::saves_test_lock();
    for kind in Kind::BOTH {
        let (rig, mut adapter, mut parked, closure, before) = parked_at_mark(kind).await;
        parked.release();
        closure.join().expect("the closure ends");
        assert_eq!(kind.effects(&rig), before, "{kind:?}: ran while Paused");
        adapter.resume();
        wait_until("the adapter never settled", || adapter.settled());
        assert_eq!(
            kind.effects(&rig) - before,
            1,
            "{kind:?}: not exactly one run"
        );
    }
}

/// C6(c): release_for_stop while parked: the closure sees Released, claims
/// its own mark and runs once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c6c_release_while_parked_runs_it_once_itself() {
    let _serial = file::saves_test_lock();
    for kind in Kind::BOTH {
        let (rig, mut adapter, mut parked, closure, before) = parked_at_mark(kind).await;
        adapter.release_for_stop();
        parked.release();
        closure.join().expect("the closure ends");
        wait_until("the adapter never settled", || adapter.settled());
        assert_eq!(
            kind.effects(&rig) - before,
            1,
            "{kind:?}: not exactly one run"
        );
        assert!(!rig.marked(kind.which()), "{kind:?}: a mark is left behind");
    }
}

/// C6(d): commit while parked (after a certified checkpoint): the closure
/// sees Terminal and skips; nothing runs later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c6d_commit_while_parked_skips_for_good() {
    let _serial = file::saves_test_lock();
    for kind in Kind::BOTH {
        let rig = Rig::new();
        rig.set_replay_inputs(m2);
        let mut adapter = rig.adapter();
        pause(&mut adapter, &rig).await;
        assert_eq!(adapter.checkpoint(deadline()).await, Ok(()));
        let before = kind.effects(&rig);
        let mut parked = arm(Point::AdmissionMark, &kind.key(&rig), 1);
        let closure = start_parked(
            || kind.run_on_thread(&rig),
            &parked,
            &format!("the {kind:?} closure never reached its admission mark"),
        );
        adapter.commit();
        parked.release();
        closure.join().expect("the closure ends");
        adapter.resume();
        wait_until("the adapter never settled", || adapter.settled());
        assert_eq!(kind.effects(&rig), before, "{kind:?}: ran after commit");
    }
}

/// C6(e): two marks of one closure before one resume replay it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c6e_two_marks_replay_once() {
    let _serial = file::saves_test_lock();
    for kind in Kind::BOTH {
        let rig = Rig::new();
        rig.set_replay_inputs(m2);
        let mut adapter = rig.adapter();
        pause(&mut adapter, &rig).await;
        let before = kind.effects(&rig);
        kind.mark(&rig);
        kind.mark(&rig);
        assert!(
            rig.marked(kind.which()),
            "{kind:?}: did not mark while Paused"
        );
        assert_eq!(kind.effects(&rig), before, "{kind:?}: ran while Paused");
        adapter.resume();
        wait_until("the adapter never settled", || adapter.settled());
        assert_eq!(
            kind.effects(&rig) - before,
            1,
            "{kind:?}: two marks did not replay exactly once"
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Open,
    Paused,
    Certified,
    Released,
    Terminal,
}

#[derive(Clone, Copy, Debug)]
enum Call {
    Pause,
    Checkpoint,
    Resume,
    Release,
    Commit,
}

/// Build `state` with real calls.
async fn reach(state: State, adapter: &mut HealthFloor, rig: &Rig) {
    match state {
        State::Open => {}
        State::Paused => pause(adapter, rig).await,
        State::Certified | State::Terminal => {
            pause(adapter, rig).await;
            assert_eq!(
                adapter.checkpoint(deadline()).await,
                Ok(()),
                "premise: certified"
            );
            if state == State::Terminal {
                adapter.commit();
            }
        }
        State::Released => adapter.release_for_stop(),
    }
}

/// Apply `call`; the result for pause and checkpoint, None for the sync calls.
async fn apply(call: Call, adapter: &mut HealthFloor) -> Option<Result<(), FloorFault>> {
    match call {
        Call::Pause => Some(adapter.pause(deadline()).await),
        Call::Checkpoint => Some(adapter.checkpoint(deadline()).await),
        Call::Resume => {
            adapter.resume();
            None
        }
        Call::Release => {
            adapter.release_for_stop();
            None
        }
        Call::Commit => {
            adapter.commit();
            None
        }
    }
}

/// What each cell must end in: the gate, the call's result, certified, writes.
fn expected(state: State, call: Call) -> (GateState, Option<Result<(), FloorFault>>, bool, u64) {
    use GateState as G;
    let refused = Some(Err(FloorFault::Unavailable));
    match (state, call) {
        (State::Open, Call::Pause) => (G::Paused, Some(Ok(())), false, 0),
        (State::Open, Call::Checkpoint) => (G::Open, refused, false, 0),
        (State::Open, Call::Resume | Call::Commit) => (G::Open, None, false, 0),
        (State::Open | State::Paused | State::Certified, Call::Release) => {
            (G::Released, None, false, 0)
        }
        (State::Paused, Call::Pause) => (G::Paused, refused, false, 0),
        (State::Paused, Call::Checkpoint) => (G::Paused, Some(Ok(())), true, 1),
        (State::Paused | State::Certified, Call::Resume) => (G::Open, None, false, 0),
        (State::Paused, Call::Commit) => (G::Paused, None, false, 0),
        (State::Certified, Call::Pause) => (G::Paused, refused, true, 0),
        (State::Certified, Call::Checkpoint) => (G::Paused, Some(Ok(())), true, 1),
        (State::Certified, Call::Commit) => (G::Terminal, None, true, 0),
        (State::Released, Call::Pause | Call::Checkpoint) => (G::Released, refused, false, 0),
        (State::Released, _) => (G::Released, None, false, 0),
        (State::Terminal, Call::Pause | Call::Checkpoint) => (G::Terminal, refused, true, 0),
        (State::Terminal, _) => (G::Terminal, None, true, 0),
    }
}

/// C7: every state x call cell ends where the contract table and the design delta say.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c7_every_state_and_call_ends_where_the_contract_says() {
    let _serial = file::saves_test_lock();
    let states = [
        State::Open,
        State::Paused,
        State::Certified,
        State::Released,
        State::Terminal,
    ];
    let calls = [
        Call::Pause,
        Call::Checkpoint,
        Call::Resume,
        Call::Release,
        Call::Commit,
    ];
    for state in states {
        for call in calls {
            let rig = Rig::new();
            let mut adapter = rig.adapter();
            reach(state, &mut adapter, &rig).await;
            let before = rig.writes();
            let result = apply(call, &mut adapter).await;
            let (gate, want, certified, writes) = expected(state, call);
            let cell = format!("{state:?} x {call:?}");
            assert_eq!(rig.gate(), gate, "{cell}: gate");
            assert_eq!(result, want, "{cell}: result");
            assert_eq!(adapter.certified(), certified, "{cell}: certified");
            assert_eq!(rig.writes() - before, writes, "{cell}: writes");
            wait_until(&format!("{cell}: never settled"), || adapter.settled());
        }
    }
    for (path, end) in [
        (vec![Call::Release, Call::Commit], GateState::Released),
        (
            vec![Call::Resume, Call::Pause, Call::Commit],
            GateState::Paused,
        ),
        (vec![Call::Checkpoint, Call::Commit], GateState::Terminal),
    ] {
        let rig = Rig::new();
        let mut adapter = rig.adapter();
        reach(State::Certified, &mut adapter, &rig).await;
        for call in &path {
            let _ = apply(*call, &mut adapter).await;
        }
        assert_eq!(rig.gate(), end, "Certified then {path:?}");
        wait_until("never settled", || adapter.settled());
    }
}

/// C8: resume from Open (no pause ever started) replays nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c8_resume_from_open_replays_nothing() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    rig.set_replay_inputs(m2);
    let mut adapter = rig.adapter();
    let (writes, samples) = (rig.writes(), rig.health.history.sample_count());
    adapter.resume();
    assert!(adapter.settled(), "resume from Open started a replay");
    assert_eq!(rig.writes(), writes, "resume from Open saved");
    assert_eq!(
        rig.health.history.sample_count(),
        samples,
        "resume from Open sampled"
    );
    assert_eq!(rig.gate(), GateState::Open);
}

/// C9: a worker that panics is WorkerLost; nothing is written; the gate stays Paused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c9_a_worker_panic_is_worker_lost() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    adapter.panic_next_worker();
    let before = rig.writes();
    assert_eq!(
        adapter.checkpoint(deadline()).await,
        Err(FloorFault::WorkerLost)
    );
    assert_eq!(rig.writes(), before, "a lost worker wrote");
    assert_eq!(
        rig.gate(),
        GateState::Paused,
        "a lost worker resumed the gate"
    );
    wait_until("the adapter never settled", || adapter.settled());
    adapter.resume();
}

/// C13: a pause future dropped unpolled still leaves the gate Paused; resume reopens it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c13_an_unpolled_pause_still_pauses() {
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    drop(adapter.pause(deadline()));
    assert_eq!(
        rig.gate(),
        GateState::Paused,
        "the pause lived only in its future"
    );
    adapter.resume();
    assert_eq!(rig.gate(), GateState::Open);
}

/// C15: a checkpoint from Open is refused, with no worker and no write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c15_a_checkpoint_from_open_is_refused() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    let before = rig.writes();
    assert_eq!(
        adapter.checkpoint(deadline()).await,
        Err(FloorFault::Unavailable)
    );
    assert!(adapter.settled(), "a refused checkpoint started a worker");
    assert_eq!(rig.writes(), before, "a refused checkpoint wrote");
}

/// C16: a checkpoint future dropped unpolled still owns its worker's fate:
/// its drop guard stops the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c16_an_unpolled_checkpoint_dropped_writes_nothing() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    pause(&mut adapter, &rig).await;
    let before = rig.writes();
    let held = file::hold_saves();
    let waiting = arm(Point::WorkerWaiting, &rig.key(), 1);
    let checkpoint = adapter.checkpoint(deadline());
    waiting.reached("the checkpoint started no worker in its body");
    drop(waiting);
    drop(checkpoint);
    drop(held);
    wait_until("the worker never ended", || adapter.worker_finished());
    assert_eq!(
        rig.writes(),
        before,
        "an unpolled, dropped checkpoint wrote"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
}

/// C10: in one window, a new save that overtakes the replayed sample converges
/// to the same history and the same file as the replay-first order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c10_a_save_overtaking_the_replay_converges() {
    let _serial = file::saves_test_lock();
    let (a, b) = (Rig::new(), Rig::new());
    let (mut fa, mut fb) = (a.adapter(), b.adapter());
    for (rig, adapter) in [(&a, &mut fa), (&b, &mut fb)] {
        rig.set_replay_inputs(m2);
        pause(adapter, rig).await;
        (rig.sampler(m2))();
        assert!(
            rig.marked(Closure::Sample),
            "the sampler did not mark while Paused"
        );
    }
    fa.resume();
    wait_until("A never settled", || fa.settled());
    save_once(&a);
    let mut replay = arm(Point::ReplayBeforeSample, &b.hkey(), 1);
    fb.resume();
    replay.reached("resume did not replay the marked sample");
    save_once(&b);
    assert_eq!(
        max_of(&b.on_disk(), "memory_max"),
        None,
        "premise: the overtaking save has no replayed sample"
    );
    replay.release();
    wait_until("B never settled", || fb.settled());
    save_once(&b);
    assert_eq!(
        a.encoded(),
        b.encoded(),
        "the two orders left different histories"
    );
    assert_eq!(a.bytes(), b.bytes(), "the two orders left different files");
}

/// C12: the real coordinator, dropped mid-checkpoint, releases the gate for
/// the stop: the worker writes nothing, nothing is replayed, closures run again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c12_a_dropped_coordinator_releases_for_the_stop() {
    use crate::gateway::restart_floor::{FloorOwner, run_checkpoint};
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    rig.set_replay_inputs(m2);
    let (let_go, hold) = tokio::sync::oneshot::channel();
    let (entered_tx, entered) = std::sync::mpsc::channel();
    let mut adapters: Vec<Box<dyn FloorAdapter>> = vec![
        Box::new(rig.adapter()),
        Box::new(Fake {
            owner: FloorOwner::TaskStore,
            hold: Some(hold),
            entered: Some(entered_tx),
        }),
        Fake::ready(FloorOwner::Config),
    ];
    let waiting = arm(Point::WorkerWaiting, &rig.key(), 1);
    let (writes, samples);
    {
        // Boxed, so dropping `run` drops the run itself (a `tokio::pin!`
        // binding is only a reference to it).
        let mut run = Box::pin(run_checkpoint(&mut adapters, deadline()));
        assert!(
            futures::poll!(&mut run).is_pending(),
            "the run did not wait for the held pause"
        );
        assert!(
            entered.recv_timeout(GUARD).is_ok(),
            "the coordinator never reached the second pause"
        );
        assert_eq!(
            rig.gate(),
            GateState::Paused,
            "the coordinator did not pause the health gate"
        );
        mark_save(&rig);
        (rig.sampler(m2))();
        assert!(
            rig.marked(Closure::Sample),
            "the sampler did not mark while Paused"
        );
        (writes, samples) = (rig.writes(), rig.health.history.sample_count());
        let held = file::hold_saves();
        let _ = let_go.send(());
        assert!(
            futures::poll!(&mut run).is_pending(),
            "the checkpoint started no worker that waits on SAVES"
        );
        waiting.reached("the checkpoint started no worker that waits on SAVES");
        drop(waiting);
        drop(run);
        assert_eq!(
            rig.gate(),
            GateState::Released,
            "the dropped run did not release the gate"
        );
        drop(held);
    }
    wait_until("the health adapter never settled", || adapters[0].settled());
    assert_eq!(
        rig.writes(),
        writes,
        "the dropped attempt's worker wrote, or a save was replayed"
    );
    assert_eq!(
        rig.health.history.sample_count(),
        samples,
        "a sample was replayed after release_for_stop"
    );
    save_once(&rig);
}

/// C14: a replay that cannot start a thread is logged, leaves the adapter
/// settled, and the next periodic save and sample run as normal; a running
/// replay keeps settled() false.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c14_a_failed_replay_spawn_heals_on_the_next_tick() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    rig.set_replay_inputs(m2);
    let mut adapter = rig.adapter();
    pause_and_mark(&mut adapter, &rig).await;
    adapter.fail_next_replay_spawn();
    let writes = rig.writes();
    let ((), logs) = crate::test_log_capture::capture_warnings(|| adapter.resume());
    assert!(
        logs.contains("could not start"),
        "the failed replay was not logged: {logs}"
    );
    assert!(
        adapter.settled(),
        "a replay that never started keeps the adapter unsettled"
    );
    assert_eq!(rig.writes(), writes, "a replay that never started saved");
    (rig.sampler(m3))();
    save_once(&rig);
    assert_eq!(
        max_of(&rig.on_disk(), "memory_max"),
        Some(M3),
        "the next tick did not heal the history"
    );
    pause_and_mark(&mut adapter, &rig).await;
    let mut replay = arm(Point::ReplayBeforeSample, &rig.hkey(), 1);
    adapter.resume();
    replay.reached("resume did not replay the marked closures");
    assert!(!adapter.settled(), "settled() ignores a running replay");
    replay.release();
    wait_until("the adapter never settled", || adapter.settled());
}

/// C14b: a second resume never hides the first one's replay: settled() stays
/// false until the first replay ends, even after the second one finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c14b_a_second_replay_does_not_hide_the_first() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    rig.set_replay_inputs(m2);
    let mut adapter = rig.adapter();
    pause_and_mark(&mut adapter, &rig).await;
    let mut first = arm(Point::ReplayBeforeSample, &rig.hkey(), 1);
    adapter.resume();
    first.reached("resume did not replay the marked closures");
    pause(&mut adapter, &rig).await;
    mark_save(&rig);
    let writes = rig.writes();
    adapter.resume();
    wait_until("the second replay never saved", || rig.writes() > writes);
    assert!(!adapter.settled(), "the second resume hid the first replay");
    first.release();
    wait_until("the adapter never settled", || adapter.settled());
}

/// C17: an adapter built before the sampler starts replays with the inputs the
/// sampler sets later.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn c17_an_adapter_built_before_the_sampler_replays_its_inputs() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    let (stop, stopped) = tokio::sync::broadcast::channel(1);
    let sampler = rig.health.spawn_sampler(|| S2, stopped);
    pause(&mut adapter, &rig).await;
    (rig.sampler(m2))();
    assert!(
        rig.marked(Closure::Sample),
        "the sampler did not mark while Paused"
    );
    assert_eq!(
        max_of(&rig.encoded(), "sessions_max"),
        None,
        "premise: no sample yet"
    );
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
    assert_eq!(
        max_of(&rig.encoded(), "sessions_max"),
        Some(S2 as u64),
        "the replay did not read the sampler's inputs"
    );
    let _ = stop.send(());
    sampler.await.expect("the sampler ends");
}

/// C18: with no sampler started, the replayed sample does nothing and the
/// replayed save still writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c18_with_no_sampler_the_replay_still_saves() {
    let _serial = file::saves_test_lock();
    let rig = Rig::new();
    let mut adapter = rig.adapter();
    pause_and_mark(&mut adapter, &rig).await;
    let (writes, samples) = (rig.writes(), rig.health.history.sample_count());
    adapter.resume();
    wait_until("the adapter never settled", || adapter.settled());
    assert_eq!(
        rig.health.history.sample_count(),
        samples,
        "a replay sampled with no inputs"
    );
    assert_eq!(rig.writes() - writes, 1, "the replayed save did not write");
}
