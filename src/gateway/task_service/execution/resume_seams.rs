// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 B5 test-only pause points in the resume worker. Thread-local: the
//! rows run on `#[tokio::test]`'s current-thread runtime, where the request,
//! the worker and the row all poll on the test's own thread.
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// Where the resume worker can be paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumePoint {
    /// The worker has been spawned; it has not yet committed the answers.
    Spawned,
    /// The answers are committed; the continuation is not yet redeemed.
    BeforeRedeem,
}

#[derive(Default)]
struct Pause {
    reached: AtomicBool,
    reached_notify: Notify,
    release: Notify,
}

/// An armed pause. Dropping it releases the worker, so a failing row cannot
/// leave it parked.
pub(crate) struct PauseHandle(Arc<Pause>);

impl PauseHandle {
    pub(crate) async fn reached(&self) {
        loop {
            let notified = self.0.reached_notify.notified();
            if self.0.reached.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self) {
        self.0.release.notify_one();
    }
}

impl Drop for PauseHandle {
    fn drop(&mut self) {
        self.release();
    }
}

thread_local! {
    static ARMED: RefCell<Option<(ResumePoint, Arc<Pause>)>> = const { RefCell::new(None) };
}

/// Park the next resume worker that reaches `at`.
pub(crate) fn pause_at_for_test(at: ResumePoint) -> PauseHandle {
    let pause = Arc::new(Pause::default());
    ARMED.with(|a| *a.borrow_mut() = Some((at, Arc::clone(&pause))));
    PauseHandle(pause)
}

/// Called by the resume worker at `at`; parks it if a row armed that point.
pub(crate) async fn at(point: ResumePoint) {
    let armed = ARMED.with(|a| {
        let mut slot = a.borrow_mut();
        match slot.as_ref() {
            Some((p, _)) if *p == point => slot.take().map(|(_, pause)| pause),
            _ => None,
        }
    });
    let Some(pause) = armed else {
        return;
    };
    pause.reached.store(true, Ordering::SeqCst);
    pause.reached_notify.notify_waiters();
    pause.release.notified().await;
}
