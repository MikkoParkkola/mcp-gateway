// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Contract rows C7-C18 for the health floor adapter (restart slice 6b): the
//! state-by-call matrix, refusals, order independence, the coordinator drop path and replays.

use super::HealthFloor;
use super::tests::{
    Fake, GUARD, M3, Rig, S2, deadline, m2, m3, mark_save, max_of, pause, pause_and_mark,
    save_once, wait_until,
};
use crate::gateway::restart_floor::FloorAdapter;
use crate::gateway::restart_floor::FloorFault;
use crate::health_history::file;
use crate::health_history::gate::Closure;
use crate::health_history::gate::GateState;
use crate::health_history::pause_points::Point;
use crate::health_history::pause_points::arm;

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
