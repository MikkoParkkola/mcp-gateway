// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart slice 2d: the HTTP stop hands every live stdio tree to
//! the reaper at the backend stage's entry, before any backend's stop waits
//! for its locks, so a held restart lock cannot eat the trees' graceful
//! phases, and each backend's plan is fitted to what is left of the stage.

use super::*;
use crate::transport::KILL_RESERVE_FOR_TEST;

/// [`PEER`], but SIGTERM leaves a `term` mark in its dir and is otherwise
/// ignored from its first line on, so only the group SIGKILL ends it. Rows
/// prove the plan's order from the reaper's record, not from this mark.
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
    assert!(
        first.starts_with("import ") && first.contains("signal"),
        "premise: PEER's first line imports signal, so the handler can follow it"
    );
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
/// the reaper's record (armed before the stop): the graceful plan sends SIGTERM
/// before its kill, while an immediate kill (a stop's sweep, a retire) sends
/// none. The record, not the peer's `term` mark: a loaded host may not run the
/// peer's handler inside the gap.
async fn ended_after_term(pid: Pid) {
    let by = std::time::Instant::now() + Duration::from_secs(30);
    while kernel_view(pid) == Some(false) {
        assert!(
            std::time::Instant::now() < by,
            "the handed tree was not ended within the watchdog"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    crate::transport::signal_log::assert_term_then_kill(pid, "the handed tree's graceful plan")
        .await;
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
    crate::transport::signal_log::arm(pid);
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
    ended_after_term(pid).await;
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
    crate::transport::signal_log::arm(pid);
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
    ended_after_term(pid).await;
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
    assert!(
        second.replaced_transport_cleanups.lock().stopping,
        "the stop's first step did not latch a backend whose own stop still waits"
    );
    // Refused by whichever check meets the latch first (the start's early-out
    // or its stdio publish), always before dispatch.
    let refusal = second.ensure_started().await.err();
    assert!(
        matches!(refusal, Some(crate::Error::BackendNotFound(_))),
        "a start after the stop's first step was not refused before dispatch: {refusal:?}"
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
/// one is `graceful_ending`'s), and the stage's deadline is the registry's.
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
/// `hold`, handed over by a stop of a `stage` long stage, its deadline set
/// right before the stop so fixture setup spends none of it, awaited (30 s
/// watchdog). Returns the handovers in the order they came.
async fn two_handed(hold: Duration, stage: Duration) -> Vec<(Duration, std::time::Instant)> {
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
    let deadline = tokio::time::Instant::now() + stage;
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
    let seen = two_handed(hold, Duration::from_millis(6_400)).await;
    let [(earlier, _), (later, _)] = seen.as_slice() else {
        panic!("expected one handover per backend, got {seen:?}");
    };
    assert!(
        *later + hold <= *earlier,
        "the later backend's budget ({later:?}) was not read at its own handover (earlier {earlier:?})"
    );
}

/// R3d (HANDOVER.3): inside one backend each tree's budget is read at its
/// own handover too: the later tree's budget is shorter by at least the
/// earlier tree's hold.
#[tokio::test]
async fn each_tree_of_a_backend_reads_its_own_budget_at_its_handover() {
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let seen = Seen::default();
    let hold = Duration::from_millis(50);
    let recorder = || Recorder {
        seen: Arc::clone(&seen),
        hold,
    };
    let (backend, _first) = recording(&registry, dir.path(), "two-trees", recorder());
    let second: Arc<dyn crate::transport::LiveTree> = Arc::new(recorder());
    backend
        .replaced_transport_cleanups
        .lock()
        .live
        .push(Arc::downgrade(&second));
    let deadline = tokio::time::Instant::now() + Duration::from_millis(6_400);
    tokio::time::timeout(
        Duration::from_secs(30),
        registry.stop_all_by(deadline, crate::backend::Handover::AtEntry),
    )
    .await
    .expect("the stop returns within the watchdog");
    let mut seen = seen.lock().expect("lock").clone();
    seen.sort_by_key(|(_, at)| *at);
    let [(earlier, _), (later, _)] = seen.as_slice() else {
        panic!("expected one handover per tree, got {seen:?}");
    };
    assert!(
        *later + hold <= *earlier,
        "the later tree's budget ({later:?}) was not read at its own handover (earlier {earlier:?})"
    );
}

/// R3c (HANDOVER.3): a stage deadline spent during the handover loop gives
/// the backends after it a zero budget (no panic), and the stop returns. The
/// first budget is positive, so the deadline passed inside the loop.
#[tokio::test]
async fn a_deadline_spent_mid_handover_gives_the_rest_a_zero_budget() {
    let hold = Duration::from_millis(50);
    let seen = two_handed(hold, Duration::from_millis(30)).await;
    let [(earlier, _), (later, _)] = seen.as_slice() else {
        panic!("expected one handover per backend, got {seen:?}");
    };
    assert!(
        *earlier > Duration::ZERO,
        "premise: the deadline was not already spent at the first handover"
    );
    assert_eq!(
        *later,
        Duration::ZERO,
        "a spent deadline did not give a zero budget"
    );
}

/// R5 (HANDOVER.1 wiring): the HTTP stop's backend stage is the one
/// `stop_all_by` call in `Gateway::run` and the blocks it moved into
/// `run_wiring.rs` (`stop_custody_and_backends`), and it hands over at entry.
/// `run` is driven by no row, so its source text is the evidence.
#[test]
fn the_http_backend_stage_hands_over_at_entry() {
    let code: String = [
        include_str!("../gateway/server/run.rs"),
        include_str!("../gateway/server/run_wiring.rs"),
    ]
    .iter()
    .map(|text| crate::test_source_text::sanitize(&crate::test_source_text::production_text(text)))
    .collect::<String>()
    .split_whitespace()
    .collect();
    let calls: Vec<&str> = code.split("stop_all_by(").skip(1).collect();
    let [call] = calls.as_slice() else {
        panic!(
            "run.rs and run_wiring.rs must hold exactly one stop_all_by call, found {}",
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

/// [`PEER`] as a nested gateway: it starts a leaf in its own session (beyond
/// the outer group's kill, as a nested gateway's leaf is), and its SIGTERM
/// handler waits `wait` (the inner's slowest hurried path) before it kills
/// and reaps the leaf through its own handle. The leaf ends by itself after
/// 120 s, so a red row leaks nothing and the row never signals a pid. Every
/// step writes a `CLOCK_MONOTONIC` mark file: `eof` in place of PEER's
/// post-EOF SIGTERM ignore, then `term` and `leaf_dead`.
#[cfg(target_os = "linux")]
fn nesting_peer(wait: Duration) -> String {
    const POST_EOF_IGNORE: &str = "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n";
    let preamble = format!(
        "import subprocess\n\
         def mark(name):\n\
         \x20   with open(name, \"w\") as out:\n\
         \x20       out.write(repr(time.clock_gettime(time.CLOCK_MONOTONIC)))\n\
         leaf = subprocess.Popen([sys.executable, \"-c\", \"import time\\ntime.sleep(120)\"], start_new_session=True)\n\
         open(\"leaf.pid\", \"w\").write(str(leaf.pid))\n\
         def hurried(*_):\n\
         \x20   mark(\"term\")\n\
         \x20   time.sleep({})\n\
         \x20   leaf.kill()\n\
         \x20   leaf.wait()\n\
         \x20   mark(\"leaf_dead\")\n\
         signal.signal(signal.SIGTERM, hurried)\n",
        wait.as_secs_f64()
    );
    let (first, rest) = PEER.split_once('\n').expect("PEER has lines");
    assert_eq!(
        rest.matches(POST_EOF_IGNORE).count(),
        1,
        "premise: PEER ignores SIGTERM once, after its EOF"
    );
    format!(
        "{first}\n{preamble}{}",
        rest.replace(POST_EOF_IGNORE, "mark(\"eof\")\n")
    )
}

/// Now on the clock the nesting peer marks with.
#[cfg(target_os = "linux")]
fn monotonic_now() -> Duration {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    Duration::new(
        u64::try_from(now.tv_sec).expect("a monotonic clock is not negative"),
        u32::try_from(now.tv_nsec).expect("nanoseconds fit"),
    )
}

/// The nesting peer's `name` mark, if it wrote one.
#[cfg(target_os = "linux")]
fn peer_mark(dir: &std::path::Path, name: &str) -> Option<Duration> {
    let text = std::fs::read_to_string(dir.join(name)).ok()?;
    text.trim().parse::<f64>().ok().map(Duration::from_secs_f64)
}

/// B.3 (BUDGET.4): with the backend's `stop_once` and `lifecycle` held, a
/// nested gateway's tree handed over at the stage's entry ends in its plan's
/// order before the stage deadline Db = entry + the backend reserve. CI
/// asserts: the peer saw EOF before the plan's SIGTERM instant (entry +
/// reserve - kill reserve - nested term need, on the peer's own clock); the
/// reaper's record holds its SIGTERM before its kill; the tree was reaped
/// before Db. The peer's `term` and `leaf_dead` marks are harness data: a
/// loaded host may not run its handler in the gap, so they are printed, not
/// asserted. A leaf the handler never ended is not signalled by the row: it
/// ends by itself after 120 s (see `nesting_peer`).
/// Linux only: the marks and the entry share `CLOCK_MONOTONIC`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_held_lock_and_a_nested_tree_end_in_order_before_the_stage_deadline() {
    use crate::gateway::BACKEND_RESERVE_FOR_TEST as BACKEND_RESERVE;
    use crate::transport::{
        NESTED_TERM_MARGIN_FOR_TEST as TERM_MARGIN, NESTED_TERM_NEED_FOR_TEST as TERM_NEED,
    };
    let dir = tempfile::tempdir().expect("temp dir");
    let registry = BackendRegistry::new();
    let backend = stays(dir.path(), "nested", registry.stop_deadline());
    let peer = nesting_peer(
        TERM_NEED
            .checked_sub(TERM_MARGIN)
            .expect("the margin is under the need"),
    );
    std::fs::write(dir.path().join("peer.py"), peer).expect("write the nesting peer");
    let _end = EndOnDrop(Arc::clone(&backend));
    assert!(registry.register(Arc::clone(&backend)), "registered");
    backend.ensure_started().await.expect("the backend starts");
    let pid = leader_pid(dir.path());
    assert_eq!(kernel_view(pid), Some(false), "premise: the tree is live");
    crate::transport::signal_log::arm(pid);
    let once = backend.stop_once.lock().await;
    let lifecycle = backend.lifecycle.write().await;
    let entry = monotonic_now();
    // On Linux std's Instant reads CLOCK_MONOTONIC too, so the reaper's
    // recorded kill instant maps onto the peer's marks through this pair.
    let entry_instant = std::time::Instant::now();
    let db = tokio::time::Instant::now() + BACKEND_RESERVE;
    let mut stop = std::pin::pin!(registry.stop_all_by(db, crate::backend::Handover::AtEntry));
    assert!(
        futures::poll!(stop.as_mut()).is_pending(),
        "premise: the held locks keep the stop waiting"
    );
    assert_eq!(
        registry.stop_deadline().handed_len(),
        1,
        "the stop's first step did not hand the nested tree to the reaper"
    );
    registry.stop_deadline().wait_handed(db).await;
    assert!(
        registry.stop_deadline().handed_all_reaped(),
        "the handed nested tree was not reaped before the stage deadline"
    );
    crate::transport::signal_log::assert_term_then_kill_strict(pid, "the nested tree's plan").await;
    let planned_term = entry
        + BACKEND_RESERVE
            .checked_sub(KILL_RESERVE_FOR_TEST + TERM_NEED)
            .expect("the backend reserve holds the kill reserve and the term need");
    let eof = peer_mark(dir.path(), "eof").expect("the nested peer never saw EOF");
    assert!(
        eof < planned_term,
        "the peer saw EOF {:?} after entry, not before the planned SIGTERM {:?} after it",
        eof.saturating_sub(entry),
        planned_term.saturating_sub(entry)
    );
    let since = |name: &str| peer_mark(dir.path(), name).map(|at| at.saturating_sub(entry));
    let leaf_dead = since("leaf_dead");
    // Harness data, one line per run: H = EOF after entry, J = the peer's
    // SIGTERM mark past the planned instant, slack = the kill actually sent
    // after the leaf's death (negative: the leaf outlived the kill).
    let kill = crate::transport::signal_log::kill_sent_at(pid)
        .map(|at| at.saturating_duration_since(entry_instant));
    let signed = |a: Option<Duration>, b: Option<Duration>| match (a, b) {
        (Some(a), Some(b)) => format!("{:.6}", a.as_secs_f64() - b.as_secs_f64()),
        _ => "none".to_owned(),
    };
    let planned = Some(planned_term.saturating_sub(entry));
    eprintln!(
        "B.3 RUN H={:.6} J={} slack={} term={:?} leaf_dead={:?} kill={:?}",
        eof.saturating_sub(entry).as_secs_f64(),
        signed(since("term"), planned),
        signed(kill, leaf_dead),
        since("term"),
        leaf_dead,
        kill
    );
    drop((once, lifecycle));
    tokio::time::timeout(Duration::from_secs(30), stop)
        .await
        .expect("the stop completes once the locks are let go");
}
