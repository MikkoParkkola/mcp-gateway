// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How the runtime ends once `run` returned (MIK-7683, MIK-8084).

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use mcp_gateway::cli::Command;

use super::{RuntimeShutdown, SERVE_RUNTIME_SHUTDOWN_TIMEOUT, shut_down};

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

/// Everything logged at ERROR while `body` runs on this thread.
fn errors_logged(body: impl FnOnce()) -> String {
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);
    impl Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the log buffer")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    let bytes = captured.0.lock().expect("the log buffer").clone();
    String::from_utf8(bytes).expect("utf-8 log lines")
}

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

/// `MIK-8084.SHUTDOWN.1` and `.3`: a blocking task stuck past the bound does
/// not hold the shutdown, which returns at the bound, reports that it left
/// work running and logs it at ERROR.
#[test]
fn a_stuck_blocking_task_is_left_behind_at_the_bound_and_logged() {
    let bound = Duration::from_millis(200);
    let runtime = runtime();
    let release = stuck_task(&runtime);
    let started = Instant::now();
    let mut left_running = false;
    let logged = errors_logged(|| {
        left_running = shut_down(runtime, RuntimeShutdown::Bounded(bound));
    });
    let took = started.elapsed();
    drop(release);
    assert!(took < Duration::from_secs(5), "shutdown took {took:?}");
    assert!(left_running, "the shutdown did not report the stuck task");
    assert!(
        logged.contains("ERROR") && logged.contains("blocking work"),
        "no ERROR line names the blocking work left running: {logged:?}"
    );
}

/// `MIK-8084.SHUTDOWN.2`: blocking work that finishes inside the bound (a
/// flush) completes before the shutdown returns, which then reports and
/// logs nothing.
#[test]
fn a_flush_inside_the_bound_completes_and_logs_nothing() {
    let runtime = runtime();
    let flushed = Arc::new(AtomicBool::new(false));
    let done = Arc::clone(&flushed);
    runtime.spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(100));
        done.store(true, Ordering::SeqCst);
    });
    let mut left_running = true;
    let logged = errors_logged(|| {
        left_running = shut_down(runtime, RuntimeShutdown::Bounded(Duration::from_secs(5)));
    });
    assert!(flushed.load(Ordering::SeqCst), "the flush was cut");
    assert!(!left_running, "a finished flush reported as left running");
    assert!(logged.is_empty(), "a clean shutdown logged: {logged:?}");
}
