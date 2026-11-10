// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The pieces of a grant decision's `invocation_recorded` marker: the delivery
//! scope, the set of trace ids whose invocation record landed, and the retry
//! cell a withheld call shares with its retry's dispatch.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};

tokio::task_local! {
    /// Set while a delivery is re-checked: its call already has the
    /// invocation record of the original request.
    static DELIVERY: ();
    /// Filled by a retry's dispatch with the trace id it opens; read by the
    /// withheld notes taken in the same scope.
    static RETRY_TRACE: RetryCell;
}

/// Whether a delivery re-check is running.
pub(super) fn delivery_scoped() -> bool {
    DELIVERY.try_with(|()| ()).is_ok()
}

/// For a writer of a route-stage refusal's invocation record: a hook to run,
/// on the blocking worker and only after the append returned `Ok`, that marks
/// the call's trace id as recorded in the open slot.
pub(crate) fn invocation_landing() -> Landing {
    Landing(super::open_slot_recorded())
}

/// The open slot's recorded set, held by a refusal writer until its append
/// returns; holding it allocates nothing.
pub(crate) struct Landing(Option<RecordedSet>);

impl Landing {
    /// Mark `trace_id` as recorded. Call only after the append returned `Ok`.
    pub(crate) fn land(self, trace_id: &str) {
        if let Some(recorded) = self.0 {
            recorded.add(trace_id);
        }
    }
}

/// The retry cell of the enclosing [`with_retry_trace`], if any.
pub(super) fn current_retry() -> Option<RetryCell> {
    RETRY_TRACE.try_with(Clone::clone).ok()
}

/// Run `check` as a delivery re-check: the call it is about already has its
/// invocation record, from the original request, so the decisions it notes
/// say so.
pub(in crate::gateway::meta_mcp) fn in_delivery_scope<T>(check: impl FnOnce() -> T) -> T {
    DELIVERY.sync_scope((), check)
}

/// The trace ids whose invocation record landed in the log, shared by the
/// notes of one slot. An invocation writer adds its id inside its own append
/// op, after the write returned `Ok`; appends are serialized, so a decision
/// appended later sees every earlier append's real outcome.
#[derive(Clone, Default)]
pub(in crate::gateway::meta_mcp) struct RecordedSet(Arc<Mutex<HashSet<String>>>);

impl RecordedSet {
    pub(in crate::gateway::meta_mcp) fn add(&self, trace_id: &str) {
        // invariant: nothing panics while holding the set lock, so it is never poisoned.
        self.0
            .lock()
            .expect("recorded set lock")
            .insert(trace_id.to_owned());
    }

    pub(super) fn contains(&self, trace_id: &str) -> bool {
        // invariant: nothing panics while holding the set lock, so it is never poisoned.
        self.0.lock().expect("recorded set lock").contains(trace_id)
    }
}

impl std::fmt::Debug for RecordedSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordedSet")
    }
}

impl PartialEq for RecordedSet {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for RecordedSet {}

/// The trace id of the retry a withheld call routes to, once its dispatch
/// has opened one. Shared by the notes taken in the same [`with_retry_trace`].
#[derive(Clone, Default)]
pub(in crate::gateway::meta_mcp) struct RetryCell(Arc<std::sync::OnceLock<String>>);

impl RetryCell {
    /// The retry's trace id, once its dispatch has opened one.
    pub(super) fn id(&self) -> Option<&str> {
        self.0.get().map(String::as_str)
    }
}

impl std::fmt::Debug for RetryCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RetryCell")
    }
}

impl PartialEq for RetryCell {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for RetryCell {}

/// Run `work`, a withheld call's note and its retry dispatch, so the retry's
/// trace id reaches the note: the note says the call has an invocation record
/// only when that retry's own record landed.
/// A plain function, not an `async fn`: an `async fn` would hold `work` twice
/// (the argument beside the task-local future that owns it).
pub(in crate::gateway::meta_mcp) fn with_retry_trace<F: Future>(
    work: F,
) -> impl Future<Output = F::Output> {
    RETRY_TRACE.scope(RetryCell::default(), work)
}

/// Called by the retry's dispatch with the trace id it opens.
pub(in crate::gateway::meta_mcp) fn note_retry_trace(trace_id: &str) {
    let _ = RETRY_TRACE.try_with(|cell| cell.0.set(trace_id.to_owned()));
}
