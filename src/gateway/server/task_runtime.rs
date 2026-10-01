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
use crate::gateway::task_service::execution::ExpirySweep;
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

/// The task half of shutdown, in this order:
/// - the expiry sweep is joined while the store is still open, so a deletion
///   already in flight finishes and no new one starts;
/// - workers drain within `timeout` (a worker's dispatch IS a backend call,
///   so this precedes any backend teardown);
/// - the store closes, joining any writer still in flight and giving the
///   directory lease back.
pub(super) async fn shutdown(
    expiry: ExpirySweep,
    executor: &TaskExecutor,
    service: &TaskService,
    timeout: Duration,
) {
    if let Err(error) = expiry.shutdown().await {
        warn!(%error, "Task expiry sweep did not stop cleanly");
    } else {
        info!("Task expiry sweep stopped");
    }
    info!(timeout = ?timeout, "Draining in-flight tasks...");
    let drained = executor.drain(timeout).await;
    if drained.timed_out {
        warn!(
            acquired_workers = drained.acquired,
            "Task drain timeout reached, proceeding with shutdown"
        );
    } else {
        info!("All in-flight tasks completed");
    }
    if let Err(error) = service.shutdown().await {
        warn!(%error, "Task store did not release its lease cleanly");
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
