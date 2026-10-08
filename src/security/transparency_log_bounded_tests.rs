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
    Arc::new(l)
}

/// Arm the next write to block until the returned barrier is released, and
/// shorten the bound to `BOUND` so that held write times out quickly.
fn stall(l: &TransparencyLogger) -> super::rotation::StallRelease {
    l.stall_next_write_for_test(BOUND)
}

fn invocation(l: &Arc<TransparencyLogger>) -> impl std::future::Future<Output = io::Result<()>> {
    l.append_bounded(|l| l.log_invocation("s", "c", "srv", "t", "a", "b"))
}

/// A healthy append after a stall, under the production bound: `BOUND` only
/// triggers the held write, and a healthy append asserts success, not
/// latency, so a runner slower than `BOUND` no longer fails it (#1779).
async fn healthy_invocation(l: &Arc<TransparencyLogger>) -> io::Result<()> {
    *l.bound.limit.lock().unwrap() = super::bounded::AUDIT_APPEND_TIMEOUT;
    invocation(l).await
}

/// The held write times out at exactly the configured bound. Tokio's clock
/// is paused and moved by hand, so this pins the deadline without depending
/// on runner speed: one tick before the bound the call is still waiting, at
/// the bound it returns `TimedOut` with the write still held.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stalled_append_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    let l2 = Arc::clone(&l);
    let call = tokio::spawn(async move { invocation(&l2).await });
    // Once the write is held, the call has registered its deadline. Real
    // time here is only a hang guard.
    let guard = std::time::Instant::now();
    while !release.is_entered() {
        assert!(
            guard.elapsed() < Duration::from_secs(60),
            "the write never started"
        );
        tokio::task::yield_now().await;
    }
    tokio::time::advance(BOUND.saturating_sub(Duration::from_millis(1))).await;
    tokio::task::yield_now().await;
    assert!(!call.is_finished(), "gave up before the bound");
    tokio::time::advance(Duration::from_millis(1)).await;
    let err = call.await.unwrap().unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
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
/// and time out; none starts a second blocking closure. All twenty-one are
/// released together by one barrier before any of them appends (MIK-7896).
/// Tokio's clock is paused and moved by hand, so every caller reaches the
/// permit before any deadline can pass, however slow the runner: the
/// contention does not depend on scheduling.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stall_parks_one_blocking_thread() {
    use std::sync::atomic::Ordering;
    const CALLERS: usize = 21;
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    let release = stall(&l);
    let start = Arc::new(tokio::sync::Barrier::new(CALLERS));
    let calls: Vec<_> = (0..CALLERS)
        .map(|_| {
            let l = Arc::clone(&l);
            let start = Arc::clone(&start);
            tokio::spawn(async move {
                start.wait().await;
                invocation(&l).await
            })
        })
        .collect();
    // Whichever caller took the permit holds the stalled write. Real time
    // here is only a hang guard; the paused clock has not moved.
    let guard = std::time::Instant::now();
    while !release.is_entered() {
        assert!(
            guard.elapsed() < Duration::from_secs(60),
            "no write reached the blocking pool"
        );
        tokio::task::yield_now().await;
    }
    // Every caller acknowledges reaching the permit wait (its deadline is
    // armed in the same poll) before the clock moves, rather than trusting a
    // count of yields to the scheduler.
    while l.permit_waits_for_test() < CALLERS {
        assert!(
            guard.elapsed() < Duration::from_secs(60),
            "callers never reached the permit wait"
        );
        tokio::task::yield_now().await;
    }
    assert!(
        calls.iter().all(|c| !c.is_finished()),
        "a caller returned before any deadline passed"
    );
    tokio::time::advance(BOUND).await;
    for call in calls {
        assert!(call.await.unwrap().is_err());
    }
    assert_eq!(
        l.bound.closures_entered.load(Ordering::Acquire),
        1,
        "one blocking thread parked, not twenty-one"
    );
    assert_eq!(
        l.refused_under_stall_for_test(),
        0,
        "callers were refused, not queued on the permit"
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
    assert!(release.wait_entered(), "the held write never started");
    // A refusal returns before its first await: Ready on the first poll. A
    // permit wait would be Pending.
    for _ in 0..10 {
        let mut call = std::pin::pin!(invocation(&l));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match call.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(r) => assert!(r.is_err()),
            std::task::Poll::Pending => panic!("waited instead of refusing"),
        }
    }
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
    // The late write finishes on another thread; a loaded runner can take
    // well over 500 ms to schedule it, so poll for up to 5 s.
    for _ in 0..500 {
        if !l.is_stalled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!l.is_stalled());
    assert!(l.admit().await.is_ok());
    healthy_invocation(&l).await.unwrap();
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
    healthy_invocation(&l).await.unwrap();
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

/// #2252. A degraded log whose probe write hangs must be marked stalled by
/// the probe's own timeout: the next admit then fails fast, without a second
/// probe, and the timeout is counted. Under the production append bound
/// (5 s) the 2 s probe bound is the one that expires.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn probe_timeout_marks_the_log_stalled() {
    let dir = tempfile::tempdir().unwrap();
    let l = logger(&dir, AuditFailurePolicy::FailClosed);
    // Degrade it with one failed append, then let appends succeed again.
    l.set_append_failure_for_test(true);
    assert!(invocation(&l).await.is_err());
    l.set_append_failure_for_test(false);
    assert!(l.is_degraded());
    let release = stall(&l);
    *l.bound.limit.lock().unwrap() = super::bounded::AUDIT_APPEND_TIMEOUT;

    let l2 = Arc::clone(&l);
    let first = tokio::spawn(async move { l2.admit().await });
    let guard = std::time::Instant::now();
    while !release.is_entered() {
        assert!(
            guard.elapsed() < Duration::from_secs(60),
            "the probe never started"
        );
        tokio::task::yield_now().await;
    }
    let probe_bound = super::degraded::AUDIT_PROBE_TIMEOUT;
    tokio::time::advance(probe_bound.saturating_sub(Duration::from_millis(1))).await;
    tokio::task::yield_now().await;
    assert!(!first.is_finished(), "gave up before the probe bound");
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(first.await.unwrap().is_err());
    assert!(l.is_stalled(), "the probe timeout did not mark the stall");

    let probes = l.hooks.probes.load(std::sync::atomic::Ordering::Acquire);
    // Under the paused clock a call that had to wait would hit this timeout.
    let next = tokio::time::timeout(Duration::from_millis(1), l.admit()).await;
    assert!(next.expect("the next admit waited").is_err());
    assert_eq!(
        l.hooks.probes.load(std::sync::atomic::Ordering::Acquire),
        probes,
        "no second probe while stalled"
    );
    release.release();
}
