// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the runtime ends once `dispatch` returned.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use crate::cli::Command;

use super::{CountedRuntime, RuntimeShutdown, SERVE_RUNTIME_SHUTDOWN_TIMEOUT, block_on, shut_down};

fn runtime() -> CountedRuntime {
    CountedRuntime::new()
}

/// A blocking-pool task that has started and stays stuck, as a read on a
/// stalled mount does, until the returned sender is dropped.
fn stuck_task(runtime: &CountedRuntime) -> mpsc::Sender<()> {
    let (release, stuck) = mpsc::channel::<()>();
    let (started, running) = mpsc::channel();
    runtime.tokio.spawn_blocking(move || {
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
    runtime.tokio.spawn_blocking(move || {
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

/// U1 (RETIRE.4): under a plan the runtime waits for blocking work
/// until the plan's runtime deadline, however far off, not a fixed cap; without
/// a plan, the mode's timeout as before.
#[test]
fn a_plan_bounds_the_runtime_wait_by_its_runtime_deadline() {
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
        Duration::from_secs(60),
        "a far runtime deadline was cut short by a fixed cap"
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

/// Blocking work that ends before the plan's runtime deadline is
/// waited for, not reported as left running. Under load such work outlived the
/// old 250 ms cap and the stop exited 75 with seconds of its budget left.
#[test]
fn blocking_work_that_ends_before_the_runtime_deadline_is_not_left_running() {
    let runtime = runtime();
    let (started, running) = mpsc::channel();
    let (go, hold) = mpsc::channel::<()>();
    runtime.tokio.spawn_blocking(move || {
        started.send(()).expect("the test waits for the start");
        // The hold starts when the shutdown is about to begin, not at spawn, so
        // setup delays under load cannot use it up before the old cap is tested.
        hold.recv().expect("the test starts the hold");
        // The work lasts at least 400 ms, past the old 250 ms cap; with the
        // deadline 30 s away, a late wake under load still ends long before it.
        // timing: lower-bound
        std::thread::sleep(Duration::from_millis(400));
    });
    running
        .recv_timeout(Duration::from_secs(30))
        .expect("the blocking task starts");
    let plan = plan_with_runtime_end(tokio::time::Instant::now() + Duration::from_secs(30));
    let (left_running, logged) = within_watchdog(move || {
        let mut left_running = true;
        let logged = errors_logged(|| {
            go.send(()).expect("the blocking task waits for its hold");
            left_running = shut_down(
                runtime,
                RuntimeShutdown::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
                Some(plan),
            );
        });
        (left_running, logged)
    });
    assert!(
        !left_running,
        "work that ended well before the runtime deadline was reported as left running"
    );
    assert!(
        logged.is_empty(),
        "a clean planned shutdown logged: {logged:?}"
    );
}

/// U1 (RETIRE.4): a blocking task that never ends no longer holds an
/// HTTP stop's runtime for the 10 s bound: the shutdown returns at the plan's
/// runtime deadline (500 ms away here) and reports the work left running.
#[test]
fn a_task_stuck_past_the_runtime_deadline_is_left_running() {
    let runtime = runtime();
    let release = stuck_task(&runtime);
    let plan = plan_with_runtime_end(tokio::time::Instant::now() + Duration::from_millis(500));
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
/// stuck blocking task then holds the exit no longer than the plan's runtime
/// deadline, and the shutdown reports it left running.
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
                let near = tokio::time::Instant::now() + Duration::from_millis(500);
                let _ = cell.set(plan_with_runtime_end(near));
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

/// RETIRE.4 log line: a task stuck past the plan's runtime deadline produces
/// exactly one ERROR line from the shutdown, naming how long it waited, the
/// runtime threads still alive (at least the stuck one) and the known
/// candidates for the stuck work.
#[test]
fn a_stuck_stop_logs_one_line_naming_what_was_still_running() {
    let runtime = runtime();
    let release = stuck_task(&runtime);
    let plan = plan_with_runtime_end(tokio::time::Instant::now() + Duration::from_millis(300));
    let logged = within_watchdog(move || {
        errors_logged(|| {
            shut_down(
                runtime,
                RuntimeShutdown::Bounded(SERVE_RUNTIME_SHUTDOWN_TIMEOUT),
                Some(plan),
            );
        })
    });
    drop(release);
    let lines: Vec<&str> = logged
        .lines()
        .filter(|line| line.contains("ERROR"))
        .collect();
    assert_eq!(lines.len(), 1, "not exactly one ERROR line: {logged:?}");
    let line = lines[0];
    let threads: usize = line
        .split("live_runtime_threads=")
        .nth(1)
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|digits| digits.parse().ok())
        .unwrap_or_else(|| panic!("the line names no live_runtime_threads count: {line:?}"));
    assert!(threads >= 1, "the stuck thread was not counted: {line:?}");
    assert!(
        line.contains("waited=") && line.contains("live_tasks="),
        "the line does not name the wait and the live tasks: {line:?}"
    );
    assert!(
        line.contains("disk or mount write") && line.contains("npm lookup"),
        "the line does not name the known candidates: {line:?}"
    );
}

/// The stdio stop has no budget plan, so this fixed cap is its whole runtime
/// wait. The stop-budget work leaves it alone: pinned by value, since every
/// other row names the constant and would follow a change to it.
#[test]
fn the_runtime_cap_without_a_plan_stays_ten_seconds() {
    assert_eq!(SERVE_RUNTIME_SHUTDOWN_TIMEOUT, Duration::from_secs(10));
}
