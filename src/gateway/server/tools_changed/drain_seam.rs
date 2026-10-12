// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test seams of the HTTP drain (`spawn_drain`, MIK-8350 rows): a completion
//! signal per nudge, and a barrier that parks the drain between its decision
//! and its announcement. Thread-local, so it serves the one-thread runtime a
//! `#[tokio::test]` runs on; production never compiles it.

use std::cell::RefCell;
use std::sync::Arc;

use tokio::sync::Notify;

use crate::backend::tools_nudge::ToolsNudge;

/// The marker a row sends to learn that everything queued before it is done.
pub(super) const SETTLE_PREFIX: &str = "__settle-";

thread_local! {
    static DONE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    static DONE_WAKE: Arc<Notify> = Arc::new(Notify::new());
    static HOLD: RefCell<Option<Arc<Hold>>> = const { RefCell::new(None) };
}

/// A catalogue nudge's name (the settle marker), else empty.
pub(super) fn label(nudge: &ToolsNudge) -> String {
    match nudge {
        ToolsNudge::Catalogue { name } => name.clone(),
        _ => String::new(),
    }
}

/// The drain finished one nudge: decided, and announced if it was.
pub(super) fn finished(label: String) {
    DONE.with(|d| d.borrow_mut().push(label));
    DONE_WAKE.with(|w| w.notify_waiters());
}

/// Wait until the drain has finished the nudge labelled `label`.
pub(super) async fn wait_finished(label: &str) {
    loop {
        let wake = DONE_WAKE.with(Arc::clone);
        let notified = wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if DONE.with(|d| d.borrow().iter().any(|l| l == label)) {
            return;
        }
        notified.await;
    }
}

/// A drain barrier: while armed, the drain parks after deciding to announce.
pub(super) struct Hold {
    reached: Notify,
    release: Notify,
}

impl Hold {
    /// Arm the barrier for this thread's drain.
    pub(super) fn arm() -> Arc<Self> {
        let hold = Arc::new(Self {
            reached: Notify::new(),
            release: Notify::new(),
        });
        HOLD.with(|h| *h.borrow_mut() = Some(Arc::clone(&hold)));
        hold
    }

    /// Wait until the drain is parked at the barrier.
    pub(super) async fn reached(&self) {
        self.reached.notified().await;
    }

    /// Let the parked drain go on, and disarm the barrier.
    pub(super) fn release(&self) {
        HOLD.with(|h| *h.borrow_mut() = None);
        self.release.notify_one();
    }
}

/// The drain's barrier point.
pub(super) async fn park() {
    let Some(hold) = HOLD.with(|h| h.borrow().clone()) else {
        return;
    };
    hold.reached.notify_one();
    hold.release.notified().await;
}
