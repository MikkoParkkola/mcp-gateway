// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A replacement's new secret entries until they are settled, and how each
//! settlement runs: kept, abandoned, or discarded off the async worker.

use super::Settle;
use crate::gateway::restart_config_floor::AdmissionGuard;
#[cfg(test)]
use crate::gateway::restart_config_floor::seams::AdmittedPoint;
use crate::secret_store::PendingSecrets;

/// This replacement's new entries until they are settled. Dropped unsettled
/// (a panic, a write task that died) it discards them while the old file
/// stands and abandons them once `write_atomic` may have replaced it.
#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
pub(super) struct Entries {
    pub(super) pending: Option<PendingSecrets>,
    pub(super) renamed: bool,
    /// The write's one admission, moved from the task before any entry is
    /// staged: a detached discard holds the gate's in-flight count until the
    /// store calls are done, even when the write task died.
    pub(super) admitted: Option<AdmissionGuard>,
    /// What the write got to, shared with the task's caller.
    pub(super) trace: std::sync::Arc<super::WriteTrace>,
    #[cfg(test)]
    pub(super) gate: crate::gateway::restart_config_floor::ConfigGate,
}

#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
impl Entries {
    /// Keep and abandon touch no store, so they run here and now: a queued
    /// closure that a shutting-down runtime never runs would drop the
    /// entries undecided, which deletes them. Only a discard calls the
    /// store, off the async worker (a keychain call blocks for up to 2 s);
    /// if that closure never runs, the drop discards all the same.
    pub(super) async fn settle(mut self, how: Settle) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        match how {
            Settle::Keep | Settle::Abandon => settle_now(pending, how),
            Settle::Discard => {
                // The guard rides with the store calls: a write task that dies
                // during this await leaves the discard running, still counted.
                let admitted = self.admitted.take();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    settle_now(pending, how);
                    drop(admitted);
                })
                .await
                {
                    tracing::warn!(error = %e, "discarding a refused save's secret entries failed; they are listed as unused");
                }
            }
        }
    }
}

impl Drop for Entries {
    fn drop(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let how = if self.renamed {
            Settle::Abandon
        } else {
            Settle::Discard
        };
        match (how, tokio::runtime::Handle::try_current()) {
            (Settle::Discard, Ok(runtime)) => {
                let admitted = self.admitted.take();
                #[cfg(test)]
                let gate = self.gate.clone();
                drop(runtime.spawn_blocking(move || {
                    #[cfg(test)]
                    gate.call_admitted(AdmittedPoint::Cleanup);
                    settle_now(pending, how);
                    drop(admitted);
                }));
            }
            _ => settle_now(pending, how),
        }
    }
}

#[cfg_attr(
    not(any(test, feature = "webui")),
    expect(
        dead_code,
        reason = "first callers: the web UI settings save and discovery adopt"
    )
)]
fn settle_now(pending: PendingSecrets, how: Settle) {
    match how {
        Settle::Keep => pending.keep(),
        Settle::Abandon => pending.abandon(),
        Settle::Discard => {
            let left = pending.discard();
            if !left.is_empty() {
                tracing::warn!(
                    entries = left.len(),
                    "secret entries of a refused config save could not be removed; they are listed as unused"
                );
            }
        }
    }
}
