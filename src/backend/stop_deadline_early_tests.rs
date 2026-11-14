// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart slice 2d: the HTTP stop hands every live stdio tree to
//! the reaper at the backend stage's entry, before any backend's stop waits
//! for its locks, so a held restart lock cannot eat the trees' graceful
//! phases, and each backend's plan is fitted to what is left of the stage.

use super::*;
use crate::transport::KILL_RESERVE_FOR_TEST;

/// [`PEER`], but SIGTERM leaves a `term` mark in its dir and is otherwise
/// ignored from its first line on: a row then sees that the reaper's plan
/// sent SIGTERM before its kill. Only the group SIGKILL ends it.
fn marking_peer() -> String {
    const IGNORE: &str = "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n";
    const MARK: &str =
        "signal.signal(signal.SIGTERM, lambda *_: open(\"term\", \"w\").write(\"term\"))\n";
    assert_eq!(
        PEER.matches(IGNORE).count(),
        1,
        "PEER ignores SIGTERM in one place"
    );
    let (first, rest) = PEER.split_once('\n').expect("PEER has lines");
    format!("{first}\n{MARK}{}", rest.replace(IGNORE, ""))
}

/// [`stays`], running [`marking_peer`].
fn marking(
    dir: &std::path::Path,
    name: &str,
    deadline: Arc<crate::transport::StopDeadline>,
) -> Arc<Backend> {
    let backend = stays(dir, name, deadline);
    std::fs::write(dir.join("peer.py"), marking_peer()).expect("write marking peer");
    backend
}

/// Waits (30 s watchdog) until the leader at `pid` has ended, then requires
/// the `term` mark: the graceful plan sends SIGTERM before its kill, while an
/// immediate kill (a stop's sweep, a retire) sends none.
async fn ended_after_term(dir: &std::path::Path, pid: Pid) {
    let by = std::time::Instant::now() + Duration::from_secs(30);
    while kernel_view(pid) == Some(false) {
        assert!(
            std::time::Instant::now() < by,
            "the handed tree was not ended within the watchdog"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        dir.join("term").exists(),
        "the tree ended without the SIGTERM its graceful plan sends first"
    );
}

/// A registry with one started [`marking`] backend in `dir`, the premise
/// checked: its tree is live and nothing is handed over yet.
async fn one_live(dir: &std::path::Path) -> (BackendRegistry, Arc<Backend>, EndOnDrop, Pid) {
    let registry = BackendRegistry::new();
    let backend = marking(dir, "held", registry.stop_deadline());
    let end = EndOnDrop(Arc::clone(&backend));
    assert!(registry.register(Arc::clone(&backend)), "registered");
    backend.ensure_started().await.expect("the backend starts");
    let pid = leader_pid(dir);
    assert_eq!(kernel_view(pid), Some(false), "premise: the tree is live");
    assert_eq!(
        registry.stop_deadline().handed_len(),
        0,
        "premise: nothing handed over yet"
    );
    (registry, backend, end, pid)
}

/// The stage's deadline for R1/R1c: the reserve plus one second of waits, so
/// the plan's kill is due about a second after entry, long before the
/// deadline itself (where the stop would give up and sweep).
fn stage_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + KILL_RESERVE_FOR_TEST + Duration::from_secs(1)
}

/// R1 (HANDOVER.1): with the backend's `stop_once` and `lifecycle` both held
/// (a stop and a restart in flight), the HTTP stop's first step still hands
/// its live tree to the reaper, and the reaper's plan ends it (EOF, SIGTERM,
/// then the kill) while the locks are still held.
#[tokio::test]
async fn the_early_stop_hands_a_lock_held_backends_tree_over_at_its_first_step() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (registry, backend, _end, pid) = one_live(dir.path()).await;
    let once = backend.stop_once.lock().await;
    let lifecycle = backend.lifecycle.write().await;
    let mut stop =
        std::pin::pin!(registry.stop_all_by(stage_deadline(), crate::backend::Handover::AtEntry));
    assert!(
        futures::poll!(stop.as_mut()).is_pending(),
        "premise: the held locks keep the stop waiting"
    );
    assert_eq!(
        registry.stop_deadline().handed_len(),
        1,
        "the stop's first step did not hand the lock-held backend's tree to the reaper"
    );
    // Locks still held and the stop not polled again: no sweep can run, so
    // only the reaper's plan can end the tree.
    ended_after_term(dir.path(), pid).await;
    drop((once, lifecycle));
    tokio::time::timeout(Duration::from_secs(30), stop)
        .await
        .expect("the stop completes once the locks are let go");
}

/// R1c (HANDOVER.1): the same stop dropped (cancelled) right after its first
/// step, the locks still held. Its sweep then finds the slot empty (the tree
/// is the reaper's), so the handed plan alone ends the tree, SIGTERM first.
#[tokio::test]
async fn an_early_stop_dropped_after_its_first_step_still_ends_its_trees() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (registry, backend, _end, pid) = one_live(dir.path()).await;
    let _once = backend.stop_once.lock().await;
    let _lifecycle = backend.lifecycle.write().await;
    {
        let mut stop = std::pin::pin!(
            registry.stop_all_by(stage_deadline(), crate::backend::Handover::AtEntry)
        );
        assert!(
            futures::poll!(stop.as_mut()).is_pending(),
            "premise: the held locks keep the stop waiting"
        );
    }
    ended_after_term(dir.path(), pid).await;
}

/// R2 (HANDOVER.2): the stop's first step latches every backend, so a start
/// after it spawns nothing, even for a backend whose own stop is still
/// waiting on its `stop_once` (only `stop` takes it, and its latch comes
/// after that wait).
#[tokio::test]
async fn a_start_after_the_early_stops_first_step_spawns_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (registry, backend, _end, _pid) = one_live(dir.path()).await;
    let second_dir = tempfile::tempdir().expect("temp dir");
    let second = stays(second_dir.path(), "second", registry.stop_deadline());
    let _second_end = EndOnDrop(Arc::clone(&second));
    assert!(registry.register(Arc::clone(&second)), "registered");
    let _once = backend.stop_once.lock().await;
    let _lifecycle = backend.lifecycle.write().await;
    let _second_once = second.stop_once.lock().await;
    let mut stop =
        std::pin::pin!(registry.stop_all_by(stage_deadline(), crate::backend::Handover::AtEntry));
    assert!(
        futures::poll!(stop.as_mut()).is_pending(),
        "premise: the held locks keep the stop waiting"
    );
    let started = second.ensure_started().await;
    let refusal = started.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        refusal.contains("is stopping"),
        "a start after the stop's first step was not refused as stopping: {refusal:?}"
    );
    assert!(
        !second_dir.path().join("leader.pid").exists(),
        "a start after the stop's first step spawned its backend"
    );
}

/// What a handover gave each stand-in tree: its budget and when it came.
type Seen = Arc<std::sync::Mutex<Vec<(Duration, std::time::Instant)>>>;

/// A stand-in live tree: records each handover, then holds the handing-over
/// thread for `hold` (the cost of a real tree's descendant scan).
struct Recorder {
    seen: Seen,
    hold: Duration,
}

impl crate::transport::LiveTree for Recorder {
    fn kill_now(&self) {}

    fn hand_over_gracefully(&self, budget: Duration) {
        self.seen
            .lock()
            .expect("lock")
            .push((budget, std::time::Instant::now()));
        std::thread::sleep(self.hold);
    }
}

/// An unstarted backend in `dir`, registered, whose live list holds a
/// [`Recorder`]; the returned tree keeps that list's weak entry alive.
fn recording(
    registry: &BackendRegistry,
    dir: &std::path::Path,
    name: &str,
    recorder: Recorder,
) -> (Arc<Backend>, Arc<dyn crate::transport::LiveTree>) {
    let backend = stays(dir, name, registry.stop_deadline());
    assert!(registry.register(Arc::clone(&backend)), "registered");
    let tree: Arc<dyn crate::transport::LiveTree> = Arc::new(recorder);
    backend
        .replaced_transport_cleanups
        .lock()
        .live
        .push(Arc::downgrade(&tree));
    (backend, tree)
}

/// R3 (HANDOVER.3): the early handover gets the whole backend stage, the
/// deadline less the entry instant, with no reserve taken off here (the only
/// one is graceful_ending's), and the stage's deadline is the registry's.
#[tokio::test(start_paused = true)]
async fn the_early_handover_gets_the_whole_backend_stage() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let seen = Seen::default();
    let recorder = Recorder {
        seen: Arc::clone(&seen),
        hold: Duration::ZERO,
    };
    let (backend, _tree) = recording(&registry, dir.path(), "recorded", recorder);
    let _once = backend.stop_once.lock().await;
    let stage = Duration::from_millis(6_400);
    let deadline = tokio::time::Instant::now() + stage;
    let mut stop =
        std::pin::pin!(registry.stop_all_by(deadline, crate::backend::Handover::AtEntry));
    assert!(
        futures::poll!(stop.as_mut()).is_pending(),
        "premise: the held stop_once keeps the stop waiting"
    );
    let budgets: Vec<Duration> = seen.lock().expect("lock").iter().map(|(b, _)| *b).collect();
    assert_eq!(
        budgets,
        vec![stage],
        "the early handover was not given the whole stage (its deadline less the entry)"
    );
    assert_eq!(
        registry.stop_deadline().get(),
        Some(deadline.into_std()),
        "the stage's deadline is not the registry's stop deadline"
    );
}

/// Two [`recording`] backends, each tree holding the handover thread for
/// `hold`, handed over by a stop of the stage ending at `deadline`, awaited
/// (30 s watchdog). Returns the handovers in the order they came.
async fn two_handed(
    hold: Duration,
    deadline: tokio::time::Instant,
) -> Vec<(Duration, std::time::Instant)> {
    let (one, two) = (
        tempfile::tempdir().expect("temp dir"),
        tempfile::tempdir().expect("temp dir"),
    );
    let registry = BackendRegistry::new();
    let seen = Seen::default();
    let recorder = |seen: &Seen| Recorder {
        seen: Arc::clone(seen),
        hold,
    };
    let _first = recording(&registry, one.path(), "first", recorder(&seen));
    let _second = recording(&registry, two.path(), "second", recorder(&seen));
    tokio::time::timeout(
        Duration::from_secs(30),
        registry.stop_all_by(deadline, crate::backend::Handover::AtEntry),
    )
    .await
    .expect("the stop returns within the watchdog");
    let mut seen = seen.lock().expect("lock").clone();
    seen.sort_by_key(|(_, at)| *at);
    seen
}

/// R3b (HANDOVER.3): each backend's budget is read at its own handover, so
/// a slow handover before it is not charged twice: the later budget is
/// shorter by at least the earlier tree's hold.
#[tokio::test]
async fn each_backend_reads_its_own_budget_at_its_handover() {
    let hold = Duration::from_millis(50);
    let seen = two_handed(
        hold,
        tokio::time::Instant::now() + Duration::from_millis(6_400),
    )
    .await;
    let [(earlier, _), (later, _)] = seen.as_slice() else {
        panic!("expected one handover per backend, got {seen:?}");
    };
    assert!(
        *later + hold <= *earlier,
        "the later backend's budget ({later:?}) was not read at its own handover (earlier {earlier:?})"
    );
}

/// R3c (HANDOVER.3): a stage deadline spent during the handover loop gives
/// the backends after it a zero budget (no panic), and the stop returns.
#[tokio::test]
async fn a_deadline_spent_mid_handover_gives_the_rest_a_zero_budget() {
    let hold = Duration::from_millis(50);
    let seen = two_handed(
        hold,
        tokio::time::Instant::now() + Duration::from_millis(30),
    )
    .await;
    let [_, (later, _)] = seen.as_slice() else {
        panic!("expected one handover per backend, got {seen:?}");
    };
    assert_eq!(
        *later,
        Duration::ZERO,
        "a spent deadline did not give a zero budget"
    );
}

/// R5 (HANDOVER.1 wiring): the HTTP stop's backend stage is the one
/// `stop_all_by` call in run.rs, and it hands over at entry. `run` is driven
/// by no row, so its source text is the evidence.
#[test]
fn the_http_backend_stage_hands_over_at_entry() {
    let code: String = crate::test_source_text::sanitize(
        &crate::test_source_text::production_text(include_str!("../gateway/server/run.rs")),
    )
    .split_whitespace()
    .collect();
    let calls: Vec<&str> = code.split("stop_all_by(").skip(1).collect();
    let [call] = calls.as_slice() else {
        panic!(
            "run.rs must hold exactly one stop_all_by call, found {}",
            calls.len()
        );
    };
    let args = call.split_once(')').map_or(*call, |(args, _)| args);
    assert!(
        args.ends_with(",crate::backend::Handover::AtEntry")
            || args.ends_with(",Handover::AtEntry"),
        "the HTTP stop's backend stage does not hand over at entry: stop_all_by({args})"
    );
}

/// P1 (from the GRACE review): a stdio backend leads its own process
/// group, apart from the gateway's, so an init that signals the gateway's
/// group (tini -g in the -full image) or systemd's KillMode=mixed never
/// signals a backend directly; the gateway's stop owns its ending.
#[tokio::test]
async fn a_stdio_backend_leads_its_own_process_group() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (_registry, _backend, _end, pid) = one_live(dir.path()).await;
    let group = rustix::process::getpgid(Some(pid)).expect("the leader's group");
    assert_eq!(
        group, pid,
        "the backend's leader does not lead its own group"
    );
    assert_ne!(
        group,
        rustix::process::getpgid(None).expect("the test's own group"),
        "the backend shares the gateway's process group"
    );
}
