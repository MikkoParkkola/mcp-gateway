// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the task store's gate, written before the gate's behaviour:
//! against the red-first skeleton every row fails at its own assertion, and a
//! row that would otherwise wait forever fails by name under its own timeout.
//! Row names in comments (G2, G3, ...) follow the restart slice's test plan.

use std::future::Future;
use std::time::Duration;

use futures::FutureExt as _;
use tokio::time::Instant;

use super::StoreLimits;
use super::TaskStore;
use super::gate::seams::GateSeams;
use super::gate::{GateState, Kind, Refused, TaskGate};
use crate::gateway::task_service::record::PreparedTask;
use crate::protocol::tasks::{Task, TaskOptions};

const DEADLINE: Duration = Duration::from_secs(10);
const BUDGET: Duration = Duration::from_secs(30);
const OWNER: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// What one poll of an admission shows.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Admitted,
    Parked,
    Refused(Refused),
}

fn try_admit(gate: &TaskGate, kind: Kind) -> Outcome {
    match gate.admit(kind).now_or_never() {
        None => Outcome::Parked,
        Some(Ok(_admitted)) => Outcome::Admitted,
        Some(Err(refused)) => Outcome::Refused(refused),
    }
}

fn pause(gate: &TaskGate, attempt: u64) {
    let deadline = Instant::now() + DEADLINE;
    gate.pause(attempt, deadline, deadline + BUDGET);
}

fn paused() -> TaskGate {
    let gate = TaskGate::new();
    pause(&gate, 1);
    gate
}

fn certified() -> TaskGate {
    let gate = paused();
    gate.certify(1);
    gate
}

/// Run `future` to completion or fail the row by name: a missed wakeup or a
/// barrier the skeleton never reaches must not hang the suite.
async fn within<T>(row: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(Duration::from_secs(30), future).await {
        Ok(value) => value,
        Err(_) => panic!("{row}: did not finish in time"),
    }
}

// G2: every cell of the design's decision table for a fresh submitter (no
// ticket). The ticket subcells of Draining and Terminal are G7 and G11.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_gate_decides_every_state_and_kind_as_designed() {
    use Kind::{External, Internal, Sweep};
    use Outcome::{Admitted, Parked};
    let skipped = Outcome::Refused(Refused::Skipped);
    let restarting = Outcome::Refused(Refused::Restarting);

    let open = TaskGate::new();
    assert_eq!(open.state(), GateState::Open);
    for kind in [External, Internal, Sweep] {
        assert_eq!(try_admit(&open, kind), Admitted, "open admits {kind:?}");
    }

    for (name, gate) in [("paused", paused()), ("certified", certified())] {
        assert_eq!(try_admit(&gate, External), Parked, "{name} parks External");
        assert_eq!(try_admit(&gate, Internal), Parked, "{name} parks Internal");
        assert_eq!(try_admit(&gate, Sweep), skipped, "{name} skips a sweep");
    }

    let terminal = certified();
    terminal.commit();
    assert_eq!(terminal.state(), GateState::Terminal);
    assert_eq!(
        try_admit(&terminal, External),
        restarting,
        "terminal refuses a new External"
    );
    assert_eq!(
        try_admit(&terminal, Internal),
        Admitted,
        "terminal admits Internal"
    );
    assert_eq!(
        try_admit(&terminal, Sweep),
        skipped,
        "terminal skips a sweep"
    );

    let released = paused();
    released.release();
    assert_eq!(released.state(), GateState::Released);
    for kind in [External, Internal, Sweep] {
        assert_eq!(
            try_admit(&released, kind),
            Admitted,
            "released admits {kind:?}"
        );
    }
}

// G3: a submitter held between its Park decision and its wait still sees the
// gate open; no second change is needed to wake it.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_parked_submitter_cannot_miss_the_reopening() {
    let gate = paused();
    let hold = GateSeams::arm(&gate.seams().before_wait);
    let parked = tokio::spawn({
        let gate = gate.clone();
        async move { gate.admit(Kind::External).await.map(drop) }
    });
    within("G3 park", hold.reached()).await;
    gate.resume();
    hold.release();
    let admitted = within("G3 wake", parked).await.expect("the submitter task");
    assert_eq!(
        admitted,
        Ok(()),
        "admitted after the reopening it slept through"
    );
    assert_eq!(
        gate.state(),
        GateState::Open,
        "the drain of one opened the gate"
    );
}

// G4: checking the state and counting the admission are one step, so a
// checkpoint waiting for nothing in flight cannot slip between them.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn an_admission_is_counted_in_the_same_step_as_its_check() {
    let gate = TaskGate::new();
    let hold = GateSeams::arm(&gate.seams().at_decision);
    let (finish, finished) = tokio::sync::oneshot::channel::<()>();
    let submitter = tokio::spawn({
        let gate = gate.clone();
        async move {
            let admitted = gate.admit(Kind::Internal).await;
            let _ = finished.await;
            drop(admitted);
        }
    });
    within("G4 decision", hold.reached()).await;
    assert_eq!(
        gate.in_flight(),
        1,
        "counted at the decision, before anything else runs"
    );
    assert!(
        gate.idle().now_or_never().is_none(),
        "not idle while an admission is out"
    );
    hold.release();
    assert!(
        gate.idle().now_or_never().is_none(),
        "still out until its holder lets go"
    );
    let _ = finish.send(());
    within("G4 finish", submitter)
        .await
        .expect("the submitter task");
    within("G4 idle", gate.idle()).await;
    assert_eq!(gate.in_flight(), 0);
}

fn task() -> Task {
    let created = chrono::DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
        .expect("a fixed instant")
        .with_timezone(&chrono::Utc);
    Task::create_at(
        "private-tool",
        created,
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    )
}

async fn store() -> (tempfile::TempDir, TaskStore) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = TaskStore::open(&dir.path().join("tasks"), StoreLimits::default())
        .await
        .expect("a clean store opens");
    (dir, store)
}

// G5: the admission travels into the blocking work. A caller dropped after
// admission leaves its write counted until the write itself ends. Real clock:
// a paused clock would jump ahead while the blocking write runs.
#[tokio::test(flavor = "current_thread")]
async fn the_count_follows_the_write_not_its_caller() {
    let (_dir, store) = store().await;
    let gate = store.gate_for_test();
    // The write blocks inside its own first stage until the row lets it go.
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Mutex::new(released);
    let hook: super::CommitHook = std::sync::Arc::new({
        let entered = std::sync::Arc::clone(&entered);
        move |stage| {
            if matches!(stage, super::StoreWriteStage::Write) {
                entered.notify_one();
                let _ = released.lock().map(|rx| rx.recv());
            }
            Ok(())
        }
    });
    store.set_hook(Some(hook)).await;
    let caller = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create(PreparedTask::for_test(&task(), OWNER, 1))
                .await
                .map(drop)
        }
    });
    within("G5 entered", entered.notified()).await;
    caller.abort();
    let _ = caller.await;
    assert_eq!(
        gate.in_flight(),
        1,
        "the blocked write is still counted after its caller dropped"
    );
    let _ = release.send(());
    within("G5 drained", gate.idle()).await;
    assert_eq!(gate.in_flight(), 0);
}

// G8: a quiet store, no submitter ever holding a receiver: the gate's own
// changes are still made and seen.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_quiet_gate_still_changes_state() {
    let gate = paused();
    assert_eq!(gate.state(), GateState::Paused(1));
    gate.certify(1);
    assert_eq!(gate.state(), GateState::Certified(1));
    gate.resume();
    assert_eq!(
        gate.state(),
        GateState::Open,
        "nothing parked: resume opens at once"
    );
}

/// The name of the function whose body holds line `at`, found by walking back
/// to the nearest `fn name(` line.
fn enclosing_fn(lines: &[&str], at: usize) -> Option<String> {
    lines[..=at].iter().rev().find_map(|line| {
        let after = line.split("fn ").nth(1)?;
        let name: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty() && after[name.len()..].trim_start().starts_with(['(', '<']))
            .then_some(name)
    })
}

// G6 (pin once green): no mutation spawns blocking work without the gate. Every
// `spawn_blocking` in the store's own files sits in the admitting helper, or in
// `open` and `close`, which never run during a restart attempt.
#[test]
fn every_blocking_store_write_goes_through_the_gate() {
    const ALLOWED: [&str; 3] = ["admitted", "open", "close"];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/task_service");
    let mut strays = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the task_service directory") {
        let path = entry.expect("a directory entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if !name.starts_with("store") || !name.ends_with(".rs") || name.contains("_tests") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a store source file");
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") || !code.contains("spawn_blocking(") {
                continue;
            }
            let owner = enclosing_fn(&lines, at).unwrap_or_default();
            if !ALLOWED.contains(&owner.as_str()) {
                strays.push(format!("{name}:{} in fn {owner}", at + 1));
            }
        }
    }
    assert!(
        strays.is_empty(),
        "blocking store work outside the gate: {strays:#?}"
    );
}

// G9: a write admitted before the pause that fails during it is recorded in
// the gate before the count reaches zero, even with its caller gone, so the
// checkpoint waiting on the count sees the failure.
#[tokio::test(flavor = "current_thread")]
async fn a_failing_write_is_recorded_before_the_count_drains() {
    let (_dir, store) = store().await;
    let gate = store.gate_for_test();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Mutex::new(released);
    let hook: super::CommitHook = std::sync::Arc::new({
        let entered = std::sync::Arc::clone(&entered);
        move |stage| {
            if matches!(stage, super::StoreWriteStage::Write) {
                entered.notify_one();
                let _ = released.lock().map(|rx| rx.recv());
                return Err(std::io::Error::other("injected write failure"));
            }
            Ok(())
        }
    });
    store.set_hook(Some(hook)).await;
    let caller = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create(PreparedTask::for_test(&task(), OWNER, 1))
                .await
                .map(drop)
        }
    });
    within("G9 entered", entered.notified()).await;
    caller.abort();
    let _ = caller.await;
    pause(&gate, 1);
    assert!(!gate.failed(), "nothing has failed yet");
    let _ = release.send(());
    within("G9 drained", gate.idle()).await;
    assert!(
        gate.failed(),
        "the failure was recorded by the time the count reached zero"
    );
}

// G10: once the checkpoint has seen nothing in flight, no submitter of either
// class runs before the gate reopens.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn nothing_runs_between_quiescence_and_resume() {
    let gate = paused();
    within("G10 quiescent", gate.idle()).await;
    assert_eq!(
        try_admit(&gate, Kind::Internal),
        Outcome::Parked,
        "Internal parks after quiescence"
    );
    assert_eq!(
        try_admit(&gate, Kind::External),
        Outcome::Parked,
        "External parks after quiescence"
    );
    assert_eq!(gate.in_flight(), 0, "the checkpoint's view stays true");
}

/// Spawn a submitter that records its admission in `log`, signals `admitted`,
/// and keeps its admission (its "write") until `finish` fires.
fn held_submitter(
    gate: &TaskGate,
    kind: Kind,
    name: &'static str,
    log: &std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<tokio::sync::Notify>,
    tokio::sync::oneshot::Sender<()>,
) {
    let admitted = std::sync::Arc::new(tokio::sync::Notify::new());
    let (finish, finished) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn({
        let (gate, log, admitted) = (
            gate.clone(),
            std::sync::Arc::clone(log),
            std::sync::Arc::clone(&admitted),
        );
        async move {
            let admission = gate.admit(kind).await;
            if admission.is_ok() {
                log.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(name);
                admitted.notify_one();
                let _ = finished.await;
            }
            drop(admission);
        }
    });
    (task, admitted, finish)
}

/// Park a held submitter on `gate` and return once it is waiting.
async fn park_held(
    gate: &TaskGate,
    kind: Kind,
    name: &'static str,
    log: &std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
) -> (
    tokio::task::JoinHandle<()>,
    std::sync::Arc<tokio::sync::Notify>,
    tokio::sync::oneshot::Sender<()>,
) {
    let hold = GateSeams::arm(&gate.seams().before_wait);
    let parts = held_submitter(gate, kind, name, log);
    within(name, hold.reached()).await;
    hold.release();
    tokio::task::yield_now().await;
    parts
}

// G11: resume lands the parked cohort before anything newer. The gate stays
// Draining until the cohort's work has FINISHED, not merely been admitted, so a
// later write cannot take the store's lock first.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn resume_lands_the_parked_cohort_before_new_arrivals() {
    let gate = paused();
    let log = std::sync::Arc::default();
    let (p_task, p_admitted, p_finish) = park_held(&gate, Kind::External, "P", &log).await;
    assert_eq!(gate.parked(), 1, "P waits with a ticket");
    gate.resume();
    assert_eq!(gate.state(), GateState::Draining { left: 1 });
    within("G11 P admitted", p_admitted.notified()).await;
    assert_eq!(
        gate.state(),
        GateState::Draining { left: 1 },
        "admitted is not finished"
    );
    let (a_task, a_admitted, a_finish) = park_held(&gate, Kind::External, "A", &log).await;
    assert_eq!(
        gate.state(),
        GateState::Draining { left: 1 },
        "a new arrival is not counted"
    );
    assert_eq!(*log.lock().unwrap(), vec!["P"], "A waits behind the cohort");
    let _ = p_finish.send(());
    within("G11 P done", p_task).await.expect("P's task");
    within("G11 A admitted", a_admitted.notified()).await;
    assert_eq!(gate.state(), GateState::Open);
    assert_eq!(*log.lock().unwrap(), vec!["P", "A"]);
    let _ = a_finish.send(());
    within("G11 A done", a_task).await.expect("A's task");
}

// G11: a ticket taken while Draining is never part of the cohort: dropping it
// changes nothing, and the gate still opens when the cohort finishes.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_ticket_taken_while_draining_is_not_counted() {
    let gate = paused();
    let log = std::sync::Arc::default();
    let (p_task, p_admitted, p_finish) = park_held(&gate, Kind::Internal, "P", &log).await;
    gate.resume();
    within("G11b P admitted", p_admitted.notified()).await;
    let (a_task, _a_admitted, _a_finish) = park_held(&gate, Kind::Internal, "A", &log).await;
    a_task.abort();
    let _ = a_task.await;
    assert_eq!(
        gate.state(),
        GateState::Draining { left: 1 },
        "A's dropped ticket left the count alone"
    );
    let _ = p_finish.send(());
    within("G11b P done", p_task).await.expect("P's task");
    assert_eq!(gate.state(), GateState::Open);
}

// G11: a cohort member that goes away before it is admitted still lets the
// gate open; a resume with nothing parked opens at once; sweeps skip while
// draining.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_drain_survives_a_vanished_member_and_skips_sweeps() {
    let gate = paused();
    let log = std::sync::Arc::default();
    let (p_task, _p_admitted, _p_finish) = park_held(&gate, Kind::External, "P", &log).await;
    let (q_task, q_admitted, q_finish) = park_held(&gate, Kind::External, "Q", &log).await;
    gate.resume();
    assert_eq!(gate.state(), GateState::Draining { left: 2 });
    assert_eq!(
        try_admit(&gate, Kind::Sweep),
        Outcome::Refused(Refused::Skipped),
        "sweeps skip while draining"
    );
    p_task.abort();
    let _ = p_task.await;
    within("G11c Q admitted", q_admitted.notified()).await;
    let _ = q_finish.send(());
    within("G11c Q done", q_task).await.expect("Q's task");
    assert_eq!(
        gate.state(),
        GateState::Open,
        "the vanished member did not strand the drain"
    );

    let empty = paused();
    empty.resume();
    assert_eq!(
        empty.state(),
        GateState::Open,
        "nothing parked: open at once"
    );
}
