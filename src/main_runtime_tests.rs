// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the runtime ends once `run` returned (MIK-7683, MIK-8084).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use mcp_gateway::cli::Command;

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

#[path = "test_support/error_capture.rs"]
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
/// reports and logs nothing.
#[test]
fn a_flush_inside_the_bound_completes_and_logs_nothing() {
    let runtime = runtime();
    let flushed = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&flushed);
    let (started, running) = mpsc::channel();
    runtime.spawn_blocking(move || {
        started.send(()).expect("the test waits for the start");
        std::thread::sleep(Duration::from_millis(100));
        done.store(true, Ordering::SeqCst);
    });
    running
        .recv_timeout(Duration::from_secs(5))
        .expect("the flush starts");
    let mut left_running = true;
    let logged = errors_logged(|| {
        left_running = shut_down(runtime, RuntimeShutdown::Bounded(Duration::from_secs(5)));
    });
    assert!(flushed.load(Ordering::SeqCst), "the flush was cut");
    assert!(!left_running, "a finished flush reported as left running");
    assert!(logged.is_empty(), "a clean shutdown logged: {logged:?}");
}
