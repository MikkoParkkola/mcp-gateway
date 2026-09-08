// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-visible commit stages, drain result, and the I5 recovery seam.

use std::time::Duration;

use crate::protocol::JsonRpcError;
use serde_json::Value;

/// Durable-write stages the executor makes observable. Counts successful
/// writes, not attempts: a rejected CAS settle must not appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitStage {
    /// The create facade committed a new record.
    Published,
    /// `mark_dispatched` wrote the durable marker.
    Dispatched,
    /// A terminal transition was committed (settle/cancel/recover).
    Transitioned,
}

/// After a successful durable write at `stage`, before the worker proceeds.
///
/// Default methods match the interlock fixture: injections are off unless a
/// test forces them. No precommit hook exists; `fail_marker` is the store
/// failure the marker write itself reports.
#[async_trait::async_trait]
pub(crate) trait CommitObserver: Send + Sync {
    async fn reached(&self, stage: CommitStage, task_id: &str);
    fn fail_marker(&self, _task_id: &str) -> bool {
        false
    }
    fn fail_state_upgrade(&self, _task_id: &str) -> bool {
        false
    }
}

/// Result of acquiring every worker permit. Clean means every committed but
/// unsettled task had released its permit (or none existed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrainOutcome {
    pub timed_out: bool,
    pub acquired: usize,
}

impl DrainOutcome {
    pub(crate) fn is_clean(self) -> bool {
        !self.timed_out
    }
}

/// I5 seam. Consulted only during startup recovery (I3/I5), never permitted to
/// re-invoke the original operation. `None` on the executor keeps the
/// conservative branch. I1 does not run recovery rewrite.
pub(crate) struct RecoveryCheckpoint {
    pub handle: String,
}

pub(crate) struct RecoveryOutcome {
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
}

#[async_trait::async_trait]
pub(crate) trait UpstreamRecovery: Send + Sync {
    fn checkpoint(&self, task_id: &str, backend: &str) -> Option<RecoveryCheckpoint>;
    async fn query(
        &self,
        task_id: &str,
        checkpoint: &RecoveryCheckpoint,
    ) -> Option<RecoveryOutcome>;
}

/// Named remaining work. I1 writes and honours the dispatch marker but does
/// not rewrite restored `working` rows (I3) and does not sweep TTL (I4).
pub(crate) const REMAINING_STARTUP_RECOVERY: &str =
    "I3: split restored working rows on version>=2 && !dispatched vs dispatched-or-legacy";
pub(crate) const REMAINING_EXPIRY: &str =
    "I4: expiry sweep at tasks.expiry_interval over record-stamped ttl_ms";
pub(crate) const REMAINING_UPSTREAM_RECOVERY: &str =
    "I5: consult tasks.recovery_adapters; never resubmit the original operation";

pub(crate) fn remaining_implementation() -> [&'static str; 3] {
    [
        REMAINING_STARTUP_RECOVERY,
        REMAINING_EXPIRY,
        REMAINING_UPSTREAM_RECOVERY,
    ]
}

pub(crate) fn drain_timeout_default() -> Duration {
    Duration::from_secs(30)
}
