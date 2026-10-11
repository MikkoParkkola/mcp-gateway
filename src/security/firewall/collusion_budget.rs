// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! `MIK-8066` 2b D8: `VIEW_BYTES`, the transient budget every answer view
//! reserves from while its answer is judged, and the view's caps. Every byte
//! of view storage is reserved BEFORE it is allocated and released when its
//! charge drops, so a dropped, cancelled or finished judgement always returns
//! what it took. Separate from the sketch store's `SKETCH_BYTES`: window-long
//! sketches never decide whether a millisecond judgement runs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use parking_lot::Mutex;

use super::big::{PLAN_ANSWER_FPS, VIEW_BYTES};

/// The most text, counting a segment's size per leaf as `of_parts` does, an
/// over-bound answer may hold and still be read as a view (D2): four times
/// the 1 MiB bound. Past it the answer is unread (D6).
pub(crate) const PLAN_ANSWER_TEXT: usize = 4 * 1024 * 1024;

/// The deepest an answer may nest and still be walked (D2): an explicit cap,
/// since a parsed JSON value's own 128 limit covers parsed JSON only.
pub(crate) const MAX_ANSWER_DEPTH: usize = 128;

/// `VIEW_BYTES` and its holders' accounting.
pub(crate) struct ViewBudget {
    cap: AtomicUsize,
    used: Mutex<usize>,
}

impl ViewBudget {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cap: AtomicUsize::new(VIEW_BYTES),
            used: Mutex::new(0),
        })
    }

    /// A charge of `bytes`, or `None` when the budget has no room for it.
    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<ViewCharge> {
        let mut charge = ViewCharge {
            budget: Arc::clone(self),
            bytes: 0,
        };
        charge.resize(bytes).then_some(charge)
    }

    /// Bytes held by live charges.
    pub(crate) fn used(&self) -> usize {
        *self.used.lock()
    }
}

/// Bytes held against `VIEW_BYTES`, released when dropped.
pub(crate) struct ViewCharge {
    budget: Arc<ViewBudget>,
    bytes: usize,
}

impl ViewCharge {
    /// Hold exactly `bytes` from now on: growing takes the difference from
    /// the budget first and fails, holding what it held, if there is no
    /// room; shrinking returns the difference.
    pub(crate) fn resize(&mut self, bytes: usize) -> bool {
        let mut used = self.budget.used.lock();
        if bytes > self.bytes {
            let more = bytes - self.bytes;
            if *used + more > self.budget.cap.load(Ordering::Relaxed) {
                return false;
            }
            *used += more;
        } else {
            *used -= self.bytes - bytes;
        }
        self.bytes = bytes;
        true
    }

    /// The bytes this charge holds.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for ViewCharge {
    fn drop(&mut self) {
        let _ = self.resize(0);
    }
}

/// A detector's view budget, caps, and counters (D2, D6, D8).
pub(crate) struct ViewLimits {
    pub(crate) budget: Arc<ViewBudget>,
    /// `PLAN_ANSWER_TEXT`, lowered only by tests.
    pub(crate) answer_text_cap: AtomicUsize,
    /// The view's entry cap A (`PLAN_ANSWER_FPS`), lowered only by tests.
    pub(crate) entry_cap: AtomicUsize,
    /// Plans whose answer could not be read (D6).
    pub(crate) unread_plans: AtomicU64,
    /// Views refused for lack of `VIEW_BYTES` (D6).
    pub(crate) budget_refusals: AtomicU64,
    /// Step selections refused for lack of `VIEW_BYTES` (D2): sketch
    /// abandoned, evidence kept.
    pub(crate) selection_refusals: AtomicU64,
    /// Step evidence bytes split off their sketch reservations and not yet
    /// released (D9): charged to the sketch store's total.
    pub(crate) evidence_bytes: AtomicUsize,
    /// Second records of one digest (A2): counted no-ops.
    pub(crate) double_records: AtomicU64,
}

impl ViewLimits {
    pub(crate) fn new() -> Self {
        Self {
            budget: ViewBudget::new(),
            answer_text_cap: AtomicUsize::new(PLAN_ANSWER_TEXT),
            entry_cap: AtomicUsize::new(PLAN_ANSWER_FPS),
            unread_plans: AtomicU64::new(0),
            budget_refusals: AtomicU64::new(0),
            selection_refusals: AtomicU64::new(0),
            evidence_bytes: AtomicUsize::new(0),
            double_records: AtomicU64::new(0),
        }
    }

    /// Set the budget's cap (tests only lower it).
    pub(crate) fn set_budget_cap(&self, bytes: usize) {
        self.budget.cap.store(bytes, Ordering::Relaxed);
    }
}
