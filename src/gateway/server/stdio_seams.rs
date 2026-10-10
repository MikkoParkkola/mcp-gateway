// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 C1-stdio test-only pause point: after an answer's delivery is
//! recorded and its execution settled (`judge_and_commit`), before it enters
//! the writer queue. Thread-local: the rows run on `#[tokio::test]`'s
//! current-thread runtime, where the serve loop's tasks poll on the test's
//! own thread.
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

#[derive(Default)]
struct Pause {
    reached: AtomicBool,
    reached_notify: Notify,
    release: Notify,
}

/// An armed pause. Dropping it releases the answer, so a failing row cannot
/// leave it parked.
pub(crate) struct PauseHandle(Arc<Pause>);

impl PauseHandle {
    pub(crate) async fn reached(&self) {
        Self::reached_on(&self.0).await;
    }

    async fn reached_on(pause: &Pause) {
        loop {
            let notified = pause.reached_notify.notified();
            if pause.reached.load(Ordering::SeqCst) {
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
    static ARMED: RefCell<Option<Arc<Pause>>> = const { RefCell::new(None) };
    static CANCEL: RefCell<Option<Arc<Pause>>> = const { RefCell::new(None) };
}

/// Watches for the serve loop to record the next `notifications/cancelled`.
pub(crate) struct CancelWatch(Arc<Pause>);

impl CancelWatch {
    pub(crate) async fn seen(&self) {
        PauseHandle::reached_on(&self.0).await;
    }
}

/// Arm a watch for the next cancel the serve loop records.
pub(crate) fn watch_cancel_for_test() -> CancelWatch {
    let watch = Arc::new(Pause::default());
    CANCEL.with(|c| *c.borrow_mut() = Some(Arc::clone(&watch)));
    CancelWatch(watch)
}

/// Called by the serve loop once a cancel is recorded.
pub(crate) fn cancel_recorded() {
    if let Some(watch) = CANCEL.with(|c| c.borrow_mut().take()) {
        watch.reached.store(true, Ordering::SeqCst);
        watch.reached_notify.notify_waiters();
    }
}

/// Park the next answer that has settled and is about to be queued.
pub(crate) fn pause_after_commit_for_test() -> PauseHandle {
    let pause = Arc::new(Pause::default());
    ARMED.with(|a| *a.borrow_mut() = Some(Arc::clone(&pause)));
    PauseHandle(pause)
}

/// Called by the serve loop between settlement and the enqueue.
pub(crate) async fn after_commit() {
    let Some(pause) = ARMED.with(|a| a.borrow_mut().take()) else {
        return;
    };
    pause.reached.store(true, Ordering::SeqCst);
    pause.reached_notify.notify_waiters();
    pause.release.notified().await;
}

thread_local! {
    static ANNOUNCER: RefCell<Option<std::sync::Weak<()>>> = const { RefCell::new(None) };
}

/// Called by the serve loop with its tools-changed drain's liveness token
/// (MIK-8278).
pub(crate) fn announcer_started(alive: std::sync::Weak<()>) {
    ANNOUNCER.with(|a| *a.borrow_mut() = Some(alive));
}

/// The liveness token of the last session started on this thread.
pub(crate) fn last_announcer() -> Option<std::sync::Weak<()>> {
    ANNOUNCER.with(|a| a.borrow_mut().take())
}

thread_local! {
    static DECISIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Called by a stdio session's drain for each change it decides to announce
/// (MIK-8278 T14).
pub(crate) fn decided() {
    DECISIONS.with(|d| d.set(d.get() + 1));
}

/// Changes decided to announce on this thread so far.
pub(crate) fn decisions() -> usize {
    DECISIONS.with(std::cell::Cell::get)
}

thread_local! {
    static QUEUE_FULL: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Called by a stdio session's sender when it wakes to a full writer queue
/// and must park on `reserve` (MIK-8278 T14 premise).
pub(crate) fn sender_found_queue_full() {
    QUEUE_FULL.with(|q| q.set(q.get() + 1));
}

/// Times a sender on this thread woke to a full writer queue.
pub(crate) fn queue_full_wakes() -> usize {
    QUEUE_FULL.with(std::cell::Cell::get)
}
