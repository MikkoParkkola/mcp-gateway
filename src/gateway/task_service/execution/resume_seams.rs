// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 B5 test-only pause points in the resume worker. Thread-local: the
//! rows run on `#[tokio::test]`'s current-thread runtime, where the request,
//! the worker and the row all poll on the test's own thread.
use std::sync::Arc;

use tokio::sync::Notify;

use crate::test_pause::Slot;

/// Where the resume worker can be paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumePoint {
    /// The worker has been spawned; it has not yet committed the answers.
    Spawned,
    /// The answers are committed; the continuation is not yet redeemed.
    BeforeRedeem,
}

/// An armed pause: the `(reached, release)` pair from [`crate::test_pause::Slot::arm`].
/// Dropping it releases the worker, so a failing row cannot leave it parked.
pub(crate) struct PauseHandle {
    reached: Arc<Notify>,
    release: Arc<Notify>,
}

impl PauseHandle {
    /// Wait until the worker is parked. Await it once per handle: the slot
    /// signals `reached` with a single stored permit.
    pub(crate) async fn reached(&self) {
        self.reached.notified().await;
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}

impl Drop for PauseHandle {
    fn drop(&mut self) {
        self.release();
    }
}

thread_local! {
    // One-shot per point: the first arrival parks until released; later arrivals pass (test_pause::Slot).
    static SPAWNED: Arc<Slot> = Arc::new(Slot::default());
    static BEFORE_REDEEM: Arc<Slot> = Arc::new(Slot::default());
}

fn slot_for(point: ResumePoint) -> Arc<Slot> {
    match point {
        ResumePoint::Spawned => SPAWNED.with(Arc::clone),
        ResumePoint::BeforeRedeem => BEFORE_REDEEM.with(Arc::clone),
    }
}

/// Park the next resume worker that reaches `at`.
pub(crate) fn pause_at_for_test(at: ResumePoint) -> PauseHandle {
    let (reached, release) = slot_for(at).arm();
    PauseHandle { reached, release }
}

/// Called by the resume worker at `at`; parks it if a row armed that point.
pub(crate) async fn at(point: ResumePoint) {
    slot_for(point).pause().await;
}
