// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test seam for design r9 R9.2 (row T2c): spend this worker's coop budget
//! inside the cancel arm, immediately before the rescue poll, and record that
//! it was spent there. Inert unless a test names the task.

use std::collections::HashSet;
use std::sync::LazyLock;

use parking_lot::Mutex;

static EXHAUST: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);
static EXHAUSTED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);

/// Spend the coop budget of `task_id`'s worker before its rescue poll.
pub(crate) fn exhaust_before_rescue(task_id: &str) {
    EXHAUST.lock().insert(task_id.to_owned());
}

/// Whether the budget was observed spent before the rescue poll.
pub(crate) fn was_exhausted(task_id: &str) -> bool {
    EXHAUSTED.lock().contains(task_id)
}

pub(super) async fn before_rescue_poll(task_id: &str) {
    if !EXHAUST.lock().contains(task_id) {
        return;
    }
    // Until the runtime says the budget is gone: `consume_budget` is
    // Pending exactly then.
    loop {
        let mut step = std::pin::pin!(tokio::task::consume_budget());
        if futures::poll!(step.as_mut()).is_pending() {
            break;
        }
    }
    EXHAUSTED.lock().insert(task_id.to_owned());
}
