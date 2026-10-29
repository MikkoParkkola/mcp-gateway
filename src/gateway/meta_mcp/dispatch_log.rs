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

/// Whether one invocation was refused before its backend: decided at the
/// invoke path's pre-send exits (`nonce_settle::settle_pre_send`) and cleared
/// by a send or a served answer, so it describes the last thing the
/// invocation did. A refused invocation is no call the task made.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum PreSend {
    /// Sent, served, or not proven refused: recorded as a call, as before.
    #[default]
    Clear,
    /// Refused before anything reached its backend.
    Refused,
}

/// `(server, tool)` pairs in dispatch order, without duplicates.
#[derive(Default)]
pub(crate) struct DispatchLog {
    calls: Mutex<Vec<(String, String)>>,
    /// The binding each call was dispatched under, once per distinct binding
    /// (MIK-8407).
    bindings: Mutex<Vec<crate::gateway::meta_mcp::admission::StepBinding>>,
    /// The worker-only clock channel (MIK-8202 AC12, AC13).
    worker: super::invoke::worker_clock::WorkerChannel,
    /// Whether the current round's last invocation was refused before its
    /// backend; reset when a round starts, so it never outlives one.
    round: Mutex<PreSend>,
}

impl DispatchLog {
    /// Everything logged so far. The log keeps its entries: a later round of
    /// the same task adds to it, and the store merges.
    pub(crate) fn snapshot(&self) -> Vec<(String, String)> {
        self.calls.lock().clone()
    }

    /// Every binding noted so far, as [`Self::snapshot`] keeps its calls.
    pub(crate) fn bindings(&self) -> Vec<crate::gateway::meta_mcp::admission::StepBinding> {
        self.bindings.lock().clone()
    }

    /// Whether the current round was refused before its backend.
    pub(crate) fn round(&self) -> PreSend {
        *self.round.lock()
    }

    /// Start a round: nothing refused yet.
    pub(crate) fn reset_round(&self) {
        *self.round.lock() = PreSend::Clear;
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

/// Note the binding `(server, tool)` is dispatched under (MIK-8407). A no-op
/// outside a worker's scope.
pub(crate) fn note_binding((server, tool): (&str, &str), binding: Option<&str>) {
    let _ = DISPATCH_LOG.try_with(|log| {
        crate::gateway::meta_mcp::admission::note_distinct(
            &mut log.bindings.lock(),
            (server, tool),
            binding,
        );
    });
}

/// Note what an invocation of this worker's round decided: each invocation
/// assigns it, so the round reads its last one. A no-op outside a worker.
pub(crate) fn note_round(pre_send: PreSend) {
    let _ = DISPATCH_LOG.try_with(|log| *log.round.lock() = pre_send);
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

#[cfg(test)]
mod round_tests {
    use std::sync::Arc;

    use super::{DispatchLog, PreSend, note_round, with_dispatch_log};

    /// A round reads its last invocation, starts clear, and is written only
    /// inside a worker's scope: a refusal never outlives its round, and a
    /// later invocation that was sent clears an earlier refusal.
    #[tokio::test]
    async fn a_round_reads_its_last_invocation_and_starts_clear() {
        let log = Arc::new(DispatchLog::default());
        with_dispatch_log(Arc::clone(&log), async { note_round(PreSend::Refused) }).await;
        assert_eq!(log.round(), PreSend::Refused, "refused, then read");
        log.reset_round();
        assert_eq!(log.round(), PreSend::Clear, "a new round starts clear");
        with_dispatch_log(Arc::clone(&log), async {
            note_round(PreSend::Refused);
            note_round(PreSend::Clear);
        })
        .await;
        assert_eq!(
            log.round(),
            PreSend::Clear,
            "a later sent invocation clears it"
        );
        note_round(PreSend::Refused);
        assert_eq!(
            log.round(),
            PreSend::Clear,
            "outside a worker nothing is noted"
        );
    }
}
