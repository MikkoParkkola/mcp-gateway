// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F20: the bounded append. A test barrier holds one write inside `Inner`,
//! the way a write stuck in the kernel does.

use std::sync::Arc;
use std::time::Duration;

use super::rotation_tests::{append, cfg, log_path};
use super::*;
use crate::security::audit::AuditFailurePolicy;

const BOUND: Duration = Duration::from_millis(200);

fn logger(dir: &tempfile::TempDir, policy: AuditFailurePolicy) -> Arc<TransparencyLogger> {
    let l = TransparencyLogger::open(cfg(&log_path(dir), 12, false))
        .unwrap()
        .with_failure_policy(policy);
    *l.bound.limit.lock().unwrap() = BOUND;
    Arc::new(l)
}

/// Arm the next write to block until the returned barrier is released.
fn stall(l: &TransparencyLogger) -> Arc<super::rotation::StallGate> {
    let b = Arc::new(super::rotation::StallGate::default());
    *l.hooks.stall.lock().unwrap() = Some(Arc::clone(&b));
    b
}

fn invocation(l: &Arc<TransparencyLogger>) -> impl std::future::Future<Output = io::Result<()>> {
    l.append_bounded(|l| l.log_invocation("s", "c", "srv", "t", "a", "b"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_append_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    let start = std::time::Instant::now();
    let err = invocation(&l).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() < BOUND * 3, "bounded");
    assert!(l.is_stalled());
    release.release();
}

#[tokio::test(flavor = "current_thread")]
async fn stall_pins_no_runtime_worker() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    let call = tokio::spawn({
        let l = Arc::clone(&l);
        async move { invocation(&l).await }
    });
    // The single runtime thread is still free to run this timer.
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(call.await.unwrap().is_err());
    release.release();
}

/// T2: callers that arrive while a write is stuck wait for the one permit
/// and time out; none starts a second blocking closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stall_parks_one_blocking_thread() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    let first = tokio::spawn({
        let l = Arc::clone(&l);
        async move { invocation(&l).await }
    });
    while !l.write_in_flight_for_test() {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // Twenty callers queue while the first write is still in the kernel.
    let waiting: Vec<_> = (0..20)
        .map(|_| {
            let l = Arc::clone(&l);
            tokio::spawn(async move { invocation(&l).await })
        })
        .collect();
    for w in waiting {
        assert!(w.await.unwrap().is_err());
    }
    assert!(first.await.unwrap().is_err());
    assert_eq!(
        l.bound.closures_entered.load(Ordering::Acquire),
        1,
        "one blocking thread parked, not twenty-one"
    );
    release.release();
}

/// Once stalled, fail-closed appends refuse at once: no permit wait, no
/// closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fail_closed_calls_fail_fast_while_stalled() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    assert!(invocation(&l).await.is_err());
    assert!(l.is_stalled());
    let start = std::time::Instant::now();
    for _ in 0..10 {
        assert!(invocation(&l).await.is_err());
    }
    assert!(
        start.elapsed() < Duration::from_millis(50),
        "no permit wait"
    );
    assert_eq!(l.bound.closures_entered.load(Ordering::Acquire), 1);
    release.release();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admit_fails_fast_while_stalled_and_late_success_clears_it() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    assert!(invocation(&l).await.is_err());
    // Degrade it too, so a probe would run if the stall were ignored.
    l.set_append_failure_for_test(true);
    let probes = l.hooks.probes.load(std::sync::atomic::Ordering::Acquire);
    assert!(l.admit().await.is_err());
    assert_eq!(
        l.hooks.probes.load(std::sync::atomic::Ordering::Acquire),
        probes,
        "no probe while stalled"
    );
    l.set_append_failure_for_test(false);
    // The stuck write finishes: the stall clears and calls are admitted.
    release.release();
    for _ in 0..50 {
        if !l.is_stalled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!l.is_stalled());
    assert!(l.admit().await.is_ok());
    invocation(&l).await.unwrap();
    assert!(
        verify_log(&l.path()).unwrap().ok,
        "the late record landed in the chain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn best_effort_is_admitted_while_stalled() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::BestEffort);
    let release = stall(&l);
    assert!(invocation(&l).await.is_err());
    assert!(l.is_stalled());
    assert!(l.admit().await.is_ok(), "best effort keeps serving");
    release.release();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthy_append_is_unaffected() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    append(&l, 0);
    invocation(&l).await.unwrap();
    assert!(!l.is_stalled());
}

/// F20 r3: a write that finishes between the caller's timeout and its
/// stall-lock check must not leave `stalled` set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completion_at_timeout_boundary_does_not_stick() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    let probe = Arc::clone(&l);
    *l.bound.before_mark.lock().unwrap() = Some(Box::new(move || {
        release.release();
        // Wait for the late write to clear its generation.
        for _ in 0..500 {
            if !probe.write_in_flight_for_test() {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("the late write never finished");
    }));
    assert!(invocation(&l).await.is_err(), "the caller still timed out");
    assert!(!l.is_stalled(), "the finished write cleared the stall");
    assert!(l.admit().await.is_ok());
    invocation(&l).await.unwrap();
}

/// A stuck write that later fails leaves the log degraded with its real
/// cause, and clears the stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_failure_degrades_with_cause() {
    use super::rotation::WriteFault;
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    l.arm_write_fault(Some(WriteFault::FullForever));
    let release = stall(&l);
    assert!(invocation(&l).await.is_err());
    assert!(l.is_stalled());
    release.release();
    for _ in 0..100 {
        if !l.is_stalled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!l.is_stalled(), "the late result cleared the stall");
    assert_eq!(l.last_failure_cause(), Some("storage_full"));
    assert!(l.admit().await.is_err(), "degraded, not healthy");
    l.arm_write_fault(None);
}

/// The timeout is counted on the production metric operators alert on.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn append_timeout_is_counted() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                assert!(invocation(&l).await.is_err());
            });
        });
    });
    let rendered = handle.render();
    assert!(
        rendered
            .lines()
            .any(|line| line.starts_with("mcp_audit_append_timeouts_total") && line.ends_with(" 1")),
        "{rendered}"
    );
    release.release();
}
