// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test seam for the watcher handover: it parks the first publish on a gate
//! and counts what each watcher did. Shared state in the hub, so it reaches
//! every worker thread (a thread-local would not).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::mpsc::Receiver;
use std::sync::{Mutex, PoisonError};

/// Counters and a one-shot gate for the publish step.
#[derive(Default)]
pub(crate) struct PublishProbe {
    gate: Mutex<Option<Receiver<()>>>,
    entered: AtomicBool,
    park_forever: AtomicBool,
    observe_calls: AtomicUsize,
    publishes: AtomicUsize,
    watchers_started: AtomicUsize,
    lock_waits: AtomicUsize,
}

impl PublishProbe {
    /// Park the next publish until something is sent on (or drops) the
    /// matching sender. The wait blocks its thread, as a stuck publish would.
    pub(crate) fn arm(&self, release: Receiver<()>) {
        *self.gate.lock().unwrap_or_else(PoisonError::into_inner) = Some(release);
    }

    /// Park the next watcher forever at an await point before it publishes,
    /// where an abort can still cancel it.
    pub(crate) fn arm_park_forever(&self) {
        self.park_forever.store(true, SeqCst);
    }

    /// Whether a publish is parked on the gate now or was.
    pub(crate) fn entered(&self) -> bool {
        self.entered.load(SeqCst)
    }

    /// Publish attempts begun, parked or not.
    pub(crate) fn observe_calls(&self) -> usize {
        self.observe_calls.load(SeqCst)
    }

    /// Publishes finished.
    pub(crate) fn publishes(&self) -> usize {
        self.publishes.load(SeqCst)
    }

    /// Watcher tasks started.
    pub(crate) fn watchers_started(&self) -> usize {
        self.watchers_started.load(SeqCst)
    }

    /// Watchers that found the publish lock held and queued behind it.
    pub(crate) fn lock_waits(&self) -> usize {
        self.lock_waits.load(SeqCst)
    }

    pub(super) fn lock_wait_begun(&self) {
        self.lock_waits.fetch_add(1, SeqCst);
    }

    pub(super) fn watcher_started(&self) {
        self.watchers_started.fetch_add(1, SeqCst);
    }

    pub(super) async fn park_point(&self) {
        if self.park_forever.swap(false, SeqCst) {
            self.entered.store(true, SeqCst);
            std::future::pending::<()>().await;
        }
    }

    pub(super) fn before_publish(&self) {
        self.observe_calls.fetch_add(1, SeqCst);
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(release) = gate {
            self.entered.store(true, SeqCst);
            let _ = release.recv();
        }
    }

    pub(super) fn after_publish(&self) {
        self.publishes.fetch_add(1, SeqCst);
    }
}
