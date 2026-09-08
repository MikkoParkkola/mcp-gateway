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

pub(crate) use crate::protocol::tasks::TaskSnapshot;
pub use crate::protocol::tasks::{Task, TaskOptions, TaskStatus, TaskTransition};
/// Re-exported at crate-public visibility, not `pub(crate)`.
///
/// `AppState.task_executor` is a public field of a type the integration-test
/// facade hands out, so the executor's own name has to be reachable from
/// outside the crate or the facade re-export is a private type escaping through
/// a public one (E0365). The type is `pub` at its definition; this line is only
/// about which path names it.
pub use execution::TaskExecutor;
pub(crate) use execution::{
    BeginOutcome, CommitObserver, CommitStage, DrainOutcome, OwnedAdmissionRequest,
    OwnedCallerContext, TaskCall, TaskIntent, TaskWrite, UpstreamRecovery, WriteOutcome,
};
pub(crate) use record::CommittedTask;
pub use service::TaskService;
pub(crate) use service::{CreateOutcome, ServiceError};
pub use store::StoreLimits;
pub(crate) use store::{StoreError, TaskStore};

/// Open the durable store, import restored bindings, and build the executor.
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
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }));
    let service = Arc::new(TaskService::open(store_dir, limits, admission).await?);
    let executor = TaskExecutor::new(Arc::clone(&service), subscriptions, max_workers);
    Ok((service, executor))
}
