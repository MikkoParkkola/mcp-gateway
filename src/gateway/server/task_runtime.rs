// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Opening and shutting down a durable task runtime, shared by `Gateway::run`
//! and the stdio loop so the two transports cannot drift (MIK-7272.OWNER.2,
//! design D6 rev 5 item 6).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::config::Config;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::subscription_registry::SubscriptionRegistry;
use crate::gateway::task_service::execution::{CancelOutcome, ExpirySweep};
use crate::gateway::task_service::{ServiceError, StoreLimits, TaskExecutor, TaskService};

/// Open the store at `dir` with recovery, sharing meta-MCP's admission
/// authority: a task and a later synchronous call carrying the same owner and
/// key meet at ONE admission index. `managed` names the upstream adapters
/// whose interrupted rows are kept for an owner read; every other row is
/// settled on open.
pub(super) async fn open(
    config: &Config,
    dir: &Path,
    subscriptions: Arc<SubscriptionRegistry>,
    meta_mcp: &MetaMcp,
    managed: &[String],
) -> Result<(Arc<TaskService>, Arc<TaskExecutor>), ServiceError> {
    // A test must never open the operator's real store: it could take a live
    // gateway's lease or write into its records.
    #[cfg(test)]
    assert!(
        !is_real_store(dir),
        "a test opened the real task store at {}; give it a temp tasks.store_dir",
        dir.display()
    );
    crate::gateway::task_service::open_runtime_with_recovery(
        dir,
        config.tasks.max_workers,
        StoreLimits {
            records: config.tasks.max_records,
            per_principal: config.tasks.max_per_principal,
            record_bytes: config.tasks.max_record_bytes,
            logical_bytes: config.tasks.logical_budget_bytes,
        },
        subscriptions,
        Arc::clone(meta_mcp.execution_admission()),
        managed,
    )
    .await
}

/// How long the task half of shutdown may spend on each phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ShutdownBudget {
    /// Waiting for running workers to finish on their own.
    pub drain: Duration,
    /// After a drain that ran out: waiting for the cancelled workers to end.
    pub cancel: Duration,
    /// After the workers: joining the expiry sweep and closing the store,
    /// together. What a stalled delete or write cannot hold past.
    pub close: Duration,
}

impl ShutdownBudget {
    /// Carved out of the `remaining` shutdown window, which a drain as long as
    /// the window would otherwise use up and leave the cancellation never run.
    /// A fifth of the window is held back for cancelling and closing the
    /// store; cancelling gets half of that and the expiry join and store close the
    /// other half. HTTP passes `shutdown_timeout` as its window, so the three
    /// phases take at most one timeout between them; stdio passes what is left
    /// of its teardown deadline.
    pub(super) fn within(remaining: Duration, timeout: Duration) -> Self {
        let reserve = remaining / 5;
        Self {
            drain: timeout.min(remaining.saturating_sub(reserve)),
            cancel: reserve / 2,
            close: reserve - reserve / 2,
        }
    }
}

/// The task half of shutdown, in this order:
/// - workers drain within `budget.drain` (a worker's dispatch IS a backend
///   call, so this precedes any backend teardown);
/// - a drain that ran out cancels the workers still running and waits up to
///   `budget.cancel` for them to end, so none commits into a closed store or
///   outlives the backends. Their rows stay `working` and the next start
///   settles them through the interrupted-task table;
/// - the expiry sweep is joined while the store is still open, so a deletion
///   already in flight finishes and no new one starts. After the workers,
///   because its join has no bound of its own;
/// - the store closes, joining any writer still in flight and giving the
///   directory lease back.
///
/// Returns what a drain that ran out cancelled, or `None` after a clean drain.
pub(super) async fn shutdown(
    expiry: ExpirySweep,
    executor: &TaskExecutor,
    service: &TaskService,
    budget: ShutdownBudget,
) -> Option<CancelOutcome> {
    info!(timeout = ?budget.drain, "Draining in-flight tasks...");
    let drained = executor.drain(budget.drain).await;
    // Sealed either way: after a clean drain nothing runs, and nothing may
    // start, since a handler that begins a task now would run against a store
    // about to close. The bounded join also catches a task that slipped in
    // between the drain and the seal.
    let outcome = executor.cancel_remaining(budget.cancel).await;
    let cancelled = if drained.timed_out {
        warn!(
            cancelled = outcome.cancelled,
            all_stopped = outcome.stopped,
            "Task drain timeout reached; cancelled the remaining tasks"
        );
        Some(outcome)
    } else if outcome.cancelled > 0 || !outcome.stopped {
        warn!(
            cancelled = outcome.cancelled,
            all_stopped = outcome.stopped,
            "A task started after the drain; cancelled it"
        );
        Some(outcome)
    } else {
        info!("All in-flight tasks completed");
        None
    };
    settle_store(expiry, service, budget.close, cancelled.as_ref()).await;
    cancelled
}

/// The tail of shutdown: stop the expiry sweep, then close the store, both
/// inside `bound` so a stalled delete or write cannot hold backend teardown.
///
/// A cancel that did not complete leaves a worker that may still write, so the
/// store is retained, not closed under it; the next start settles its row
/// through recovery, as after a crash. A timeout abandons the join and the
/// close, and the process exit gives the directory lease back.
pub(super) async fn settle_store(
    expiry: ExpirySweep,
    service: &TaskService,
    bound: Duration,
    cancelled: Option<&CancelOutcome>,
) {
    let retain = cancelled.is_some_and(|outcome| !outcome.stopped);
    let tail = async {
        if let Err(error) = expiry.shutdown().await {
            warn!(%error, "Task expiry sweep did not stop cleanly");
        } else {
            info!("Task expiry sweep stopped");
        }
        if retain {
            warn!(
                "A cancelled task had not stopped; the task store is left open, not closed under it"
            );
        } else if let Err(error) = service.shutdown().await {
            warn!(%error, "Task store did not release its lease cleanly");
        }
    };
    if tokio::time::timeout(bound, tail).await.is_err() {
        warn!(
            ?bound,
            "Task expiry join or store close did not finish in time; going on to backend teardown"
        );
    }
}

/// Whether `dir` lies under the operator's real `~/.mcp-gateway`.
#[cfg(test)]
fn is_real_store(dir: &Path) -> bool {
    dir.starts_with(super::expand_home_path("~/.mcp-gateway"))
}

#[cfg(test)]
mod tests {
    use super::is_real_store;

    #[test]
    fn the_real_store_is_refused_and_a_temp_store_is_not() {
        let real = super::super::expand_home_path("~/.mcp-gateway/tasks/stdio");
        assert!(is_real_store(&real), "{}", real.display());
        let temp = tempfile::tempdir().expect("tempdir");
        assert!(!is_real_store(&temp.path().join("tasks")));
    }
}
