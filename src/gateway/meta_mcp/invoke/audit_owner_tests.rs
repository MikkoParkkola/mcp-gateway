// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D2.5: graceful shutdown waits for the record writes handed off dropped
//! requests, within its bound, and reports one still open past it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::AuditJobs;

/// A handed-off job held at `gate`; it sets `landed` once let through.
fn held_job(jobs: &Arc<AuditJobs>) -> (Arc<Notify>, Arc<AtomicBool>) {
    let (gate, landed) = (Arc::new(Notify::new()), Arc::new(AtomicBool::new(false)));
    let (held, done) = (Arc::clone(&gate), Arc::clone(&landed));
    Arc::clone(jobs).spawn(async move {
        held.notified().await;
        done.store(true, Ordering::SeqCst);
    });
    (gate, landed)
}

/// A job still appending when the drain starts is waited for: the drain
/// ends only after it lands, and reports none open.
#[tokio::test]
async fn d2_5_shutdown_waits_for_a_handed_off_record_within_its_bound() {
    let jobs = Arc::new(AuditJobs::default());
    let (gate, landed) = held_job(&jobs);
    // Let go only once the drain has started with the job open.
    let draining = Arc::clone(&jobs);
    let release = tokio::spawn(async move {
        draining.seams.draining.notified().await;
        gate.notify_one();
    });
    let open = jobs.drain(Duration::from_secs(30)).await;
    assert_eq!(open, 0, "the drain ended with the job open");
    assert!(
        landed.load(Ordering::SeqCst),
        "the drain ended before the job landed"
    );
    release.await.expect("the release task joins");
}

/// A job past the bound is reported, not dropped silently: the drain waits
/// its whole bound, then names one job open.
#[tokio::test]
async fn d2_5_a_job_past_the_bound_is_reported() {
    let jobs = Arc::new(AuditJobs::default());
    let (_gate, landed) = held_job(&jobs);
    let bound = Duration::from_millis(100);
    let started = Instant::now();
    let open = jobs.drain(bound).await;
    assert!(
        started.elapsed() >= bound,
        "the drain gave up before its bound"
    );
    assert_eq!(open, 1, "the overdue job was not reported");
    assert!(
        !landed.load(Ordering::SeqCst),
        "premise: the job is still held"
    );
}

/// A job that panics still ends: the drain does not wait for it forever.
#[tokio::test]
async fn d2_5_a_panicking_job_still_ends() {
    let jobs = Arc::new(AuditJobs::default());
    Arc::clone(&jobs).spawn(async { panic!("the write failed hard") });
    assert_eq!(jobs.drain(Duration::from_secs(30)).await, 0);
}
