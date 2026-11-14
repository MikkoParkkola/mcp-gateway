// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the runtime ends once `dispatch` returned.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use crate::cli::Command;

use super::{RuntimeShutdown, SERVE_RUNTIME_SHUTDOWN_TIMEOUT, block_on, shut_down};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build a runtime")
}

/// A blocking-pool task that has started and stays stuck, as a read on a
/// stalled mount does, until the returned sender is dropped.
fn stuck_task(runtime: &tokio::runtime::Runtime) -> mpsc::Sender<()> {
    let (release, stuck) = mpsc::channel::<()>();
    let (started, running) = mpsc::channel();
    runtime.spawn_blocking(move || {
        started.send(()).expect("the test waits for the start");
        let _ = stuck.recv();
    });
    running
        .recv_timeout(Duration::from_secs(5))
        .expect("the stuck task starts");
    release
}

// The library's log capture is the one keeper `error_capture` shares.
use crate::test_log_capture as interest;
#[path = "../test_support/error_capture.rs"]
mod error_capture;
use error_capture::errors_logged;

/// MIK-7683 and `MIK-8084.SHUTDOWN.1`: every serve mode bounds the runtime's
/// shutdown, stdio and HTTP (with or without the subcommand) alike. Other
/// commands keep waiting for their blocking work.
#[test]
fn every_serve_mode_bounds_the_runtime_shutdown() {
    assert_eq!(
        RuntimeShutdown::of(Some(&Command::Serve { stdio: true })),
        RuntimeShutdown::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT)
    );
    assert_eq!(
        RuntimeShutdown::of(Some(&Command::Serve { stdio: false })),
        RuntimeShutdown::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
        "an HTTP gateway waits unbounded for blocking work"
    );
    assert_eq!(
        RuntimeShutdown::of(None),
        RuntimeShutdown::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
        "an HTTP gateway (no subcommand) waits unbounded for blocking work"
    );
}

/// MIK-8512: doctor's npm lookup resolves names on the blocking pool, where a
/// stalled DNS lookup outlives the check's own budget. Doctor's shutdown is
/// bounded at one second, so the process exits behind it; other one-shot
/// commands still wait for their writes.
#[test]
fn doctor_bounds_the_runtime_shutdown_at_one_second() {
    use clap::Parser as _;
    let doctor = crate::cli::Cli::try_parse_from(["mcp-gateway", "doctor"])
        .expect("doctor parses")
        .command;
    assert_eq!(
        RuntimeShutdown::of(doctor.as_ref()),
        RuntimeShutdown::Bounded(Duration::from_secs(1))
    );
    let init = crate::cli::Cli::try_parse_from(["mcp-gateway", "init"])
        .expect("init parses")
        .command;
    assert_eq!(
        RuntimeShutdown::of(init.as_ref()),
        RuntimeShutdown::WaitForBlockingWork
    );
}

/// Run `body` on its own thread and return its value, failing at this
/// assertion, not by hanging the suite, when it has not returned in 5 s.
fn within_watchdog<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    let (sent, result) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(body());
    });
    result
        .recv_timeout(Duration::from_secs(5))
        .expect("the shutdown did not return within 5 s")
}

/// `MIK-8084.SHUTDOWN.1` and `.3`: a blocking task stuck past the bound does
/// not hold the shutdown, which returns at the bound, reports that it left
/// work running and logs it at ERROR.
#[test]
fn a_stuck_blocking_task_is_left_behind_at_the_bound_and_logged() {
    let runtime = runtime();
    let release = stuck_task(&runtime);
    let (left_running, logged) = within_watchdog(move || {
        let mut left_running = false;
        let logged = errors_logged(|| {
            left_running = shut_down(
                runtime,
                RuntimeShutdown::Bounded(Duration::from_millis(200)),
                None,
            );
        });
        (left_running, logged)
    });
    drop(release);
    assert!(left_running, "the shutdown did not report the stuck task");
    assert!(
        logged.contains("ERROR") && logged.contains("blocking work"),
        "no ERROR line names the blocking work left running: {logged:?}"
    );
}

/// `MIK-8084.SHUTDOWN.1`: the runtime `main` runs on is shut down by its mode
/// when `block_on` returns, so a stuck blocking task does not hold the exit.
#[test]
fn block_on_returns_behind_a_stuck_blocking_task() {
    let (release, stuck) = mpsc::channel::<()>();
    within_watchdog(move || {
        block_on(
            RuntimeShutdown::Bounded(Duration::from_millis(200)),
            &crate::retire::RetireCell::default(),
            async move {
                let (started, running) = tokio::sync::oneshot::channel();
                tokio::task::spawn_blocking(move || {
                    let _ = started.send(());
                    let _ = stuck.recv();
                });
                running.await.expect("the stuck task starts");
            },
        );
    });
    drop(release);
}

/// `MIK-8084.SHUTDOWN.2`: blocking work already running that finishes inside
/// the bound (a flush) completes before the shutdown returns, which then
/// reports and logs nothing. The flush waits on a channel, not a timer: the
/// shutdown runs on its own thread and must NOT have returned while the flush
/// is held; only after the test releases it does the shutdown finish.
#[test]
fn a_flush_inside_the_bound_completes_and_logs_nothing() {
    let runtime = runtime();
    let flushed = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&flushed);
    let (started, running) = mpsc::channel();
    let (release, held) = mpsc::channel::<()>();
    runtime.spawn_blocking(move || {
        started.send(()).expect("the test waits for the start");
        held.recv().expect("the test releases the flush");
        done.store(true, Ordering::SeqCst);
    });
    running
        .recv_timeout(Duration::from_secs(5))
        .expect("the flush starts");
    let shutdown = std::thread::spawn(move || {
        let mut left_running = true;
        let logged = errors_logged(|| {
            left_running = shut_down(
                runtime,
                RuntimeShutdown::Bounded(Duration::from_secs(5)),
                None,
            );
        });
        (left_running, logged)
    });
    // A shutdown that waits for the flush cannot finish before the release, so
    // this poll never fails it; one that returns without waiting finishes
    // within a few yields. A count, not a timer.
    let returned_early = (0..100_000).any(|_| {
        std::thread::yield_now();
        shutdown.is_finished()
    });
    assert!(
        !returned_early,
        "the shutdown returned while the flush was still running"
    );
    release.send(()).expect("the flush is still waiting");
    let (left_running, logged) = shutdown.join().expect("the shutdown thread ends");
    assert!(flushed.load(Ordering::SeqCst), "the flush was cut");
    assert!(!left_running, "a finished flush reported as left running");
    assert!(logged.is_empty(), "a clean shutdown logged: {logged:?}");
}

/// A plain stop's plan whose runtime wait ends at `runtime_end`.
fn plan_with_runtime_end(runtime_end: tokio::time::Instant) -> crate::retire::RetirePlan {
    crate::retire::RetirePlan::new(
        runtime_end + Duration::from_secs(2),
        runtime_end,
        crate::retire::Exit::Plain,
    )
}

/// U1 (RETIRE.4): under a plan the runtime waits at most 250 ms when its
/// runtime deadline is further off, and only what is left to it when nearer;
/// without a plan, the mode's timeout as before.
#[test]
fn a_plan_bounds_the_runtime_wait_by_the_cap_and_its_deadline() {
    use super::wait_bound;
    let now = tokio::time::Instant::now();
    let ten = SERVE_RUNTIME_SHUTDOWN_TIMEOUT;
    assert_eq!(
        wait_bound(ten, None, now),
        ten,
        "no plan, the mode's timeout"
    );
    let far = plan_with_runtime_end(now + Duration::from_secs(60));
    assert_eq!(
        wait_bound(ten, Some(far), now),
        crate::retire::RUNTIME_WAIT_CAP,
        "a far runtime deadline did not cap the wait at 250 ms"
    );
    let near = plan_with_runtime_end(now + Duration::from_millis(100));
    assert_eq!(
        wait_bound(ten, Some(near), now),
        Duration::from_millis(100),
        "a near runtime deadline did not bound the wait"
    );
}

/// U1c (RETIRE.4): at or past the runtime deadline the wait is zero, with no
/// panic; the shutdown then reports work left running, which the tail maps to 75.
#[test]
fn a_spent_runtime_deadline_gives_a_zero_wait() {
    use super::wait_bound;
    let now = tokio::time::Instant::now();
    let spent = plan_with_runtime_end(
        now.checked_sub(Duration::from_secs(1))
            .expect("the clock is past its first second"),
    );
    assert_eq!(
        wait_bound(SERVE_RUNTIME_SHUTDOWN_TIMEOUT, Some(spent), now),
        Duration::ZERO,
        "a spent runtime deadline still allowed a wait"
    );
}

/// U1 (RETIRE.4): a blocking task that never ends no longer holds an HTTP
/// stop's runtime for the 10 s bound: the shutdown returns within the plan's
/// 250 ms cap (well under 2 s here) and reports the work left running.
#[test]
fn a_planned_shutdown_leaves_a_stuck_task_behind_within_the_cap() {
    let runtime = runtime();
    let release = stuck_task(&runtime);
    let plan = plan_with_runtime_end(tokio::time::Instant::now() + Duration::from_secs(60));
    let (sent, got) = mpsc::channel();
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let left_running = shut_down(
            runtime,
            RuntimeShutdown::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
            Some(plan),
        );
        let _ = sent.send((left_running, started.elapsed()));
    });
    let (left_running, took) = got
        .recv_timeout(Duration::from_secs(30))
        .expect("the shutdown returned within the watchdog");
    drop(release);
    assert!(left_running, "the shutdown did not report the stuck task");
    assert!(
        took < Duration::from_secs(2),
        "the planned shutdown waited {took:?} for a stuck task"
    );
}

/// U1d (RETIRE.4): `block_on` reads the plan its future stored in the cell, as
/// the HTTP stop stores it during the run, when it shuts the runtime down: a
/// stuck blocking task then holds the exit no longer than the cap, and the
/// shutdown reports it left running.
#[test]
fn block_on_bounds_its_shutdown_by_the_plan_stored_during_the_run() {
    let plan = crate::retire::RetireCell::default();
    let cell = Arc::clone(&plan);
    let (release, stuck) = mpsc::channel::<()>();
    let (sent, got) = mpsc::channel();
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let ((), left_running) = block_on(
            RuntimeShutdown::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
            &plan,
            async move {
                let far = tokio::time::Instant::now() + Duration::from_secs(60);
                let _ = cell.set(plan_with_runtime_end(far));
                let (started, running) = tokio::sync::oneshot::channel();
                tokio::task::spawn_blocking(move || {
                    let _ = started.send(());
                    let _ = stuck.recv();
                });
                running.await.expect("the stuck task starts");
            },
        );
        let _ = sent.send((left_running, started.elapsed()));
    });
    let (left_running, took) = got
        .recv_timeout(Duration::from_secs(30))
        .expect("block_on returned within the watchdog");
    drop(release);
    assert!(left_running, "the shutdown did not report the stuck task");
    assert!(
        took < Duration::from_secs(2),
        "block_on ignored the plan stored during the run and waited {took:?}"
    );
}
