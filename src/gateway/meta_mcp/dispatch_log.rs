// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend calls one task worker's dispatch actually made (#2450).
//!
//! A playbook or code-mode program names its calls only as it runs them, and
//! the definition may change between publication and dispatch, so a stored
//! plan result is authorized against what executed, not what was published.
//! A task-local slot, for the reason `upstream::UPSTREAM_SUBMISSION` is one:
//! the log belongs to exactly the future the worker awaits, and threading it
//! would change every caller-context construction.

use std::future::Future;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

/// `(server, tool)` pairs in dispatch order, without duplicates.
#[derive(Default)]
pub(crate) struct DispatchLog {
    calls: Mutex<Vec<(String, String)>>,
    /// The worker-only clock channel (MIK-8202 AC12, AC13).
    worker: super::invoke::worker_clock::WorkerChannel,
}

impl DispatchLog {
    /// Everything logged so far. The log keeps its entries: a later round of
    /// the same task adds to it, and the store merges.
    pub(crate) fn snapshot(&self) -> Vec<(String, String)> {
        self.calls.lock().clone()
    }

    /// The clock channel the invoke funnel and this log's worker share.
    pub(crate) fn worker(&self) -> &super::invoke::worker_clock::WorkerChannel {
        &self.worker
    }

    fn note(&self, server: &str, tool: &str) {
        let mut entries = self.calls.lock();
        if !entries.iter().any(|(s, t)| s == server && t == tool) {
            entries.push((server.to_owned(), tool.to_owned()));
        }
    }
}

tokio::task_local! {
    /// The log of the dispatch currently being awaited by a task worker.
    static DISPATCH_LOG: Arc<DispatchLog>;
}

/// Run `future` with `log` collecting every step it completes.
pub(crate) async fn with_dispatch_log<F: Future>(log: Arc<DispatchLog>, future: F) -> F::Output {
    DISPATCH_LOG.scope(log, future).await
}

/// The worker channel of the dispatch being awaited, if a task worker awaits
/// it: the request thread has none, and so never waits or withholds.
pub(super) fn current_worker() -> Option<Arc<DispatchLog>> {
    DISPATCH_LOG.try_with(Arc::clone).ok()
}

/// Note the step `args` (a `{server, tool, ..}` envelope) completed. A no-op
/// outside a worker's scope.
pub(super) fn note_completed(args: &Value) {
    let (Some(server), Some(tool)) = (
        args.get("server").and_then(Value::as_str),
        args.get("tool").and_then(Value::as_str),
    ) else {
        return;
    };
    let _ = DISPATCH_LOG.try_with(|log| log.note(server, tool));
}
