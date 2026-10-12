// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P4b, section D: the compile-red rows. They need what the fix
//! adds: the undated pending record (`PendingSend::next_after: Option<i64>`),
//! the held-past-ttl metric, and a one-pass expiry seam
//! (`TaskExecutor::expiry_pass_for_test`). The fixture is the runtime file's
//! [`dark_claim_then_restart`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use telemetry_metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};

use super::clock_tests::{Claimant, DAY, DAY_MS, HOUR, dark_claim_then_restart};
use crate::gateway::task_service::store::StoreError;
use crate::gateway::task_service::store::targets::UpstreamCancelState::{Done, Pending};

const HELD_METRIC: &str = "mcp_task_cancel_held_past_ttl_total";
const HELD_WARN: &str = "held past its ttl";

/// Counts increments of [`HELD_METRIC`] made on this thread.
#[derive(Default)]
struct HeldCounter(Arc<AtomicU64>);

struct Add(Arc<AtomicU64>);

impl CounterFn for Add {
    fn increment(&self, value: u64) {
        self.0.fetch_add(value, Ordering::SeqCst);
    }

    fn absolute(&self, value: u64) {
        self.0.store(value, Ordering::SeqCst);
    }
}

impl Recorder for HeldCounter {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}

    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        if key.name() == HELD_METRIC {
            Counter::from_arc(Arc::new(Add(Arc::clone(&self.0))))
        } else {
            Counter::noop()
        }
    }

    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }

    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

/// D-expiry (MIK-8202.AC.16, AC.2; plan r2, r3). r4 D.4: retention holds a
/// cancelled row whose pending cancel is unsent past its ttl, logs WARN once
/// per row and counts `mcp_task_cancel_held_past_ttl_total` once per row
/// (never once per pass); the readable sweep then sends once, and the next
/// pass removes the row by the normal rule.
/// The owner's cancel meets the dark clock; the ttl elapses while dark; the
/// reopened store reads past it. Two expiry passes run ALONE: the reopened
/// executor has no adapter yet, so a pass's own flush sends nothing.
/// A plain `#[test]` on its own current-thread runtime: the metric recorder
/// and the log capture are this thread's, so the WARN and the increment must
/// be made on the pass's own thread (the sweep or `expired_candidates`), not
/// inside a `spawn_blocking` closure.
/// Compile-red: `expiry_pass_for_test` (and the metric) do not exist on base.
/// Mutants: Dm2, the retention skip removed: killed at "the held row was
/// deleted" on the first pass (and the send count would be 0). Dm3, the
/// counter not incremented: killed at "held-past-ttl count" (0). WARN/metric
/// on every pass: killed at "held-past-ttl count" (2) and "held-past-ttl
/// WARNs" (2). WARN removed: killed at "held-past-ttl WARNs" (0).
#[test]
fn a_dark_cancel_past_its_ttl_is_held_counted_once_then_sent_once() {
    let recorder = HeldCounter::default();
    let counted = Arc::clone(&recorder.0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    telemetry_metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let (_capture, warns) = crate::test_log_capture::live_count(HELD_WARN);
            let r = dark_claim_then_restart(Claimant::Owner, Some(DAY_MS), DAY + HOUR).await;
            assert_eq!(r.claimed_dark, Some(Pending { attempts: 0 }), "premise");
            for _ in 0..2 {
                r.executor
                    .expiry_pass_for_test()
                    .await
                    .expect("an expiry pass");
                assert!(
                    r.service.store.get(&r.owner_digest, &r.id).is_ok(),
                    "the held row was deleted"
                );
            }
            assert_eq!(counted.load(Ordering::SeqCst), 1, "held-past-ttl count");
            assert_eq!(*warns.borrow(), 1, "held-past-ttl WARNs");
            let peer = r.peer();
            r.sweep_flush().await;
            assert_eq!(peer.count(), 1, "the held cancel is sent once");
            assert_eq!(r.state(), Some(Done));
            r.executor
                .expiry_pass_for_test()
                .await
                .expect("an expiry pass");
            assert!(
                matches!(
                    r.service.store.get(&r.owner_digest, &r.id),
                    Err(StoreError::NotFound)
                ),
                "a sent row past its ttl is removed by the normal rule"
            );
        });
    });
}

/// D-undated-due (MIK-8202.AC.16, AC.2). r4 D.1 and D.2: the record written
/// on a dark clock is undated (`next_after: None`, no age yet) and is due at
/// once on the first readable reading, never after a back-off; the sweep
/// sends it.
/// Compile-red: `PendingSend::next_after` is `i64` on base.
/// Mutants: Dm5, the undated record treated as not due: killed at "an undated
/// record is due at once" (and at the send count, 0). Dm1-variant, dated 0
/// or at a back-off instead of undated: killed at "the dark record is
/// undated".
#[tokio::test(flavor = "current_thread")]
async fn an_undated_pending_cancel_is_due_at_the_first_readable_reading() {
    let r = dark_claim_then_restart(Claimant::Owner, Some(DAY_MS), std::time::Duration::ZERO).await;
    let pending = r
        .service
        .store
        .pending_cancel(&r.owner_digest, &r.id)
        .expect("the dark claim wrote a pending record");
    assert_eq!(pending.next_after, None, "the dark record is undated");
    let now = r.service.store.now().expect("a readable clock").timestamp();
    assert!(
        r.service
            .store
            .pending_cancels(None, now)
            .contains(&(r.owner_digest.clone(), r.id.clone())),
        "an undated record is due at once"
    );
    let peer = r.peer();
    r.sweep_flush().await;
    assert_eq!(peer.count(), 1, "the undated record is sent by the sweep");
}
