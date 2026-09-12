// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable Task store and the executor that owns a committed record.
//!
//! The flat Tasks model lives at [`crate::protocol::tasks`]. This package owns
//! persistence, admission coupling, and the one publication seam.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::gateway::subscription_registry::SubscriptionRegistry;
use crate::idempotency::admission::ExecutionAdmission;

mod record;
mod store;

#[cfg(test)]
mod store_tests;

mod service;

#[cfg(test)]
mod service_tests;

pub(crate) mod execution;

#[cfg(test)]
mod runtime_tests;

/// Re-exported at crate-public visibility, not `pub(crate)`.
///
/// `AppState.task_executor` is a public field of a type the integration-test
/// facade hands out, so the executor's own name has to be reachable from
/// outside the crate or the facade re-export is a private type escaping through
/// a public one (E0365). The type is `pub` at its definition; this line is only
/// about which path names it.
pub use execution::TaskExecutor;
/// Re-exported at crate-public visibility for the same reason as
/// [`TaskExecutor`]: `MetaMcpCallerContext.task` is a public field carrying an
/// `Option<TaskIntent>`, so the intent's own name has to be reachable from
/// outside the crate or that field is a private type escaping through a public
/// one. The type is deliberately opaque — no public fields, no public
/// constructor — so the only thing an outside caller can write is `task: None`.
pub use execution::TaskIntent;
pub(crate) use execution::{
    OwnedAdmissionRequest, OwnedCallerContext, TaskCall, UpstreamAnswer, UpstreamHandle,
    UpstreamRecovery,
};
/// Re-exported at crate-public visibility for the same reason as
/// [`TaskExecutor`]: [`open_runtime`] is `pub` and returns this error, so its
/// name has to be reachable from outside the crate.
pub use service::ServiceError;
pub use service::TaskService;
pub use store::StoreLimits;

pub use crate::protocol::tasks::Task;
#[cfg(test)]
pub use crate::protocol::tasks::{TaskOptions, TaskStatus, TaskTransition};
#[cfg(test)]
pub(crate) use execution::{CommitObserver, CommitStage};
#[cfg(test)]
pub(crate) use service::CreateOutcome;

/// Open the durable store, import restored bindings, build the executor, and
/// settle whatever a previous process left mid-flight.
///
/// A failed open is returned, never swapped for a volatile store.
///
/// The directory is not created here. [`TaskStore`] already creates an absent
/// store path with owner-only permissions and refuses an existing one that any
/// other user can reach, so a `create_dir_all` ahead of it would hand the store
/// a directory made with the process umask — a directory the store is then right
/// to refuse. One creator, and it is the one that makes the directory private.
pub async fn open_runtime(
    store_dir: &Path,
    max_workers: usize,
    limits: StoreLimits,
    subscriptions: Arc<SubscriptionRegistry>,
) -> Result<(Arc<TaskService>, Arc<TaskExecutor>), ServiceError> {
    let admission = ExecutionAdmission::new(Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    }));
    open_runtime_with_admission(store_dir, max_workers, limits, subscriptions, admission).await
}

/// Same open, but over an admission authority the caller already owns.
///
/// The gateway's meta-MCP surface admits synchronous calls against one
/// [`ExecutionAdmission`]; handing that same `Arc` here is what makes a task and
/// a later sync call with the same owner and key one admission rather than two.
/// The provided authority is passed straight to [`TaskService::open`], which
/// imports restored bindings into it atomically, and the executor is built only
/// after that open succeeded — a failed open returns, and never leaves a
/// half-built runtime behind.
pub(crate) async fn open_runtime_with_admission(
    store_dir: &Path,
    max_workers: usize,
    limits: StoreLimits,
    subscriptions: Arc<SubscriptionRegistry>,
    admission: Arc<ExecutionAdmission>,
) -> Result<(Arc<TaskService>, Arc<TaskExecutor>), ServiceError> {
    open_runtime_with_recovery(
        store_dir,
        max_workers,
        limits,
        subscriptions,
        admission,
        &[],
    )
    .await
}

/// The same open, told which adapters may keep an interrupted row alive.
///
/// Additive rather than a signature change on [`open_runtime_with_admission`],
/// which twelve call sites reach directly: with an empty `managed` slice the
/// recovery below is byte-identical to the increment before this one, so the
/// no-adapter behaviour is unchanged by construction and not merely by test.
///
/// `managed` holds the names in `tasks.recovery_adapters` that are ALSO still
/// configured backends. The caller computes it because it is the only place
/// that can see both lists here: `AppState` does not exist yet, and a deferred
/// row is decided by configuration and the record alone — the weakest evaluable
/// test, which is right, because deferral is not a trust claim.
pub(crate) async fn open_runtime_with_recovery(
    store_dir: &Path,
    max_workers: usize,
    limits: StoreLimits,
    subscriptions: Arc<SubscriptionRegistry>,
    admission: Arc<ExecutionAdmission>,
    managed: &[String],
) -> Result<(Arc<TaskService>, Arc<TaskExecutor>), ServiceError> {
    let service = Arc::new(TaskService::open(store_dir, limits, admission).await?);
    let executor = TaskExecutor::new(Arc::clone(&service), subscriptions, max_workers);
    // Ready to serve means recovered. Rows a previous process left mid-flight are
    // settled here, after the admission import and before this returns; a store
    // that cannot take that write gives custody back instead of serving half of
    // it. Nothing is dispatched, resubmitted, or asked of a backend — including
    // for a deferred row, which is retained as a managed `working` record and
    // queried only when its owner next authenticates.
    if let Err(error) = executor.recover_interrupted_deferring(managed).await {
        let _ = service.shutdown().await;
        return Err(error);
    }
    Ok((service, executor))
}
