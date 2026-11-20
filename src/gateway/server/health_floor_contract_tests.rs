// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Contract rows C1-C6 for the health floor adapter (restart slice 6b): drops,
//! superseded workers, resume versus release, commit, `settled()` and the races.

use super::HealthFloor;
use super::tests::{
    M2, Rig, deadline, m2, mark_save, max_of, on_thread, pause, pause_and_mark, save_once,
    start_parked, wait_until,
};
use crate::gateway::restart_floor::FloorAdapter;
use crate::gateway::restart_floor::FloorFault;
use crate::health_history::file;
use crate::health_history::gate::Closure;
use crate::health_history::gate::GateState;
use crate::health_history::pause_points::Point;
use crate::health_history::pause_points::arm;

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
#[expect(
    clippy::await_holding_lock,
    reason = "holding SAVES while the dropped attempt's worker waits is the window under test; the serialisation lock keeps other rows out of it"
)]
async fn c1_a_dropped_checkpoint_then_resume_replays_once() {
    let _serial = file::saves_test_lock_async().await;
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
#[expect(
    clippy::await_holding_lock,
    reason = "holding SAVES while the dropped attempt's worker waits is the window under test; the serialisation lock keeps other rows out of it"
)]
async fn c1a_the_drop_guard_alone_stops_the_write() {
    let _serial = file::saves_test_lock_async().await;
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
    let _serial = file::saves_test_lock_async().await;
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
/// `release_for_stop` replays nothing and lets the closures run again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c3_resume_replays_and_release_for_stop_does_not() {
    let _serial = file::saves_test_lock_async().await;
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
    let _serial = file::saves_test_lock_async().await;
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
    b.health.shutdown_save().run_now();
    assert_ne!(
        b.on_disk()["clean_stop"],
        serde_json::Value::Null,
        "the shutdown save did not record the stop"
    );
    wait_until("A never settled", || fa.settled());
}

/// C5: `settled()` is false while a checkpoint worker runs and true otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::await_holding_lock,
    reason = "holding SAVES while the checkpoint worker waits is the window under test"
)]
async fn c5_settled_tracks_the_checkpoint_worker() {
    let _serial = file::saves_test_lock_async().await;
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
    let _serial = file::saves_test_lock_async().await;
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
    let _serial = file::saves_test_lock_async().await;
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

/// C6(c): `release_for_stop` while parked: the closure sees Released, claims
/// its own mark and runs once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c6c_release_while_parked_runs_it_once_itself() {
    let _serial = file::saves_test_lock_async().await;
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
    let _serial = file::saves_test_lock_async().await;
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
    let _serial = file::saves_test_lock_async().await;
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

/// C6(f): resume ran between the closure's first Paused read and its mark
/// store, so resume's claim found nothing and started no replay: the closure's
/// second read sees Open and it claims its own mark, exactly one run. No seam
/// sits before the mark store, so the row stages resume's effect at that point
/// (the gate Open, no replay) while the closure is parked after its mark.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c6f_resume_before_the_mark_leaves_the_run_to_the_closure() {
    let _serial = file::saves_test_lock_async().await;
    for kind in Kind::BOTH {
        let (rig, adapter, mut parked, closure, before) = parked_at_mark(kind).await;
        rig.health.gate.store(GateState::Open);
        parked.release();
        closure.join().expect("the closure ends");
        assert_eq!(
            kind.effects(&rig) - before,
            1,
            "{kind:?}: not exactly one run"
        );
        assert!(!rig.marked(kind.which()), "{kind:?}: a mark is left behind");
        assert!(adapter.settled(), "{kind:?}: a replay started");
    }
}
