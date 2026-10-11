// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The durable state of a claimed upstream `tasks/cancel` while the peer has
//! not confirmed it (MIK-8347, design r3.5): the claim's shape, each
//! attempt's outcome, and the reads a retry or a flush makes.

use super::{Shared, StoreError, TaskStore, owned, record_name, serialize};
use crate::gateway::task_service::execution::CancelDelivery;
use crate::gateway::task_service::execution::pending_cancel::{
    MAX_CANCEL_ATTEMPTS, MAX_CANCEL_PENDING_AGE, NOT_READY_RETRY, backoff_after,
};
use crate::gateway::task_service::record::{
    PENDING_CANCEL_VERSION, PendingCancel, Record, UpstreamRecord,
};
use crate::protocol::tasks::Task;

/// Put `descriptor`'s cancel on `record` as pending, claimed at `now`.
///
/// The descriptor leaves the row; a legacy row keeps its call as a target
/// first, and the pending cancel names its backend through that target where
/// one does.
pub(super) fn record_pending_claim(
    task: &Task,
    record: &mut Record,
    descriptor: &UpstreamRecord,
    now: i64,
) {
    record.upstream = Some(descriptor.clone());
    let _ = super::targets::keep_provenance(task, record);
    record.upstream = None;
    let target = record
        .targets
        .iter()
        .position(|target| target.server == descriptor.backend)
        .and_then(|index| u8::try_from(index).ok());
    record.upstream_cancel_pending = Some(PendingCancel {
        handle: descriptor.handle.clone(),
        backend: target.is_none().then(|| descriptor.backend.clone()),
        target,
        attempts: 0,
        next_after: now,
        claimed_at: now,
    });
    record.version = record.version.max(PENDING_CANCEL_VERSION);
}

/// Why a pending cancel was given up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GiveUp {
    Attempts,
    Age,
    Unresolvable,
}

impl GiveUp {
    fn reason(self) -> &'static str {
        match self {
            Self::Attempts => "attempts",
            Self::Age => "age",
            Self::Unresolvable => "backend not resolvable",
        }
    }
}

/// A pending cancel as a sender reads it.
#[derive(Clone, Debug)]
pub(crate) struct PendingSend {
    /// `None` when the row names no resolvable backend: give it up.
    pub(crate) backend: Option<String>,
    pub(crate) handle: String,
    pub(crate) next_after: i64,
    pub(crate) claimed_at: i64,
}

impl PendingSend {
    /// Whether the age cap has passed at `now`.
    pub(crate) fn aged(&self, now: i64) -> bool {
        now.saturating_sub(self.claimed_at) >= age_secs()
    }
}

fn age_secs() -> i64 {
    i64::try_from(MAX_CANCEL_PENDING_AGE.as_secs()).unwrap_or(i64::MAX)
}

fn send_of(record: &Record) -> Option<PendingSend> {
    let pending = record.upstream_cancel_pending.as_ref()?;
    Some(PendingSend {
        backend: pending.backend_in(&record.targets).map(str::to_owned),
        handle: pending.handle.clone(),
        next_after: pending.next_after,
        claimed_at: pending.claimed_at,
    })
}

impl TaskStore {
    /// The row's pending cancel, if it has one.
    pub(crate) fn pending_cancel(&self, owner: &str, id: &str) -> Option<PendingSend> {
        let state = self.0.state();
        send_of(&owned(&state, owner, id).ok()?.record)
    }

    /// Rows with a pending cancel: `backend`'s rows whatever their back-off,
    /// or with `None`, every row due at `now` by back-off or by age.
    pub(crate) fn pending_cancels(&self, backend: Option<&str>, now: i64) -> Vec<(String, String)> {
        let state = self.0.state();
        state
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                let send = send_of(&entry.record)?;
                let wanted = match backend {
                    Some(backend) => send.backend.as_deref() == Some(backend),
                    None => send.next_after <= now || send.aged(now),
                };
                wanted.then(|| (entry.record.admission.principal_digest.clone(), id.clone()))
            })
            .collect()
    }

    /// Write what one attempt established, or with `None`, only the bounds.
    /// Confirmed, or a bound reached, clears the pending cancel and marks the
    /// row sent in ONE write, so no later flush can find it pending. Returns
    /// whether it is still pending.
    ///
    /// # Errors
    /// `NotFound` for a foreign or absent row; a storage failure as itself.
    pub(crate) async fn record_cancel_attempt(
        &self,
        owner: &str,
        id: &str,
        attempt: Option<CancelDelivery>,
    ) -> Result<bool, StoreError> {
        let shared = std::sync::Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || shared.record_cancel_attempt_blocking(&owner, &id, attempt))
            .await
            .map_err(|_| StoreError::Storage)?
    }
}

impl Shared {
    fn record_cancel_attempt_blocking(
        &self,
        owner: &str,
        id: &str,
        attempt: Option<CancelDelivery>,
    ) -> Result<bool, StoreError> {
        let _order = self.order();
        let now = self.now().map_err(|_| StoreError::Unavailable)?.timestamp();
        let (task, mut record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.record.upstream_cancel_pending.is_none() {
                return Ok(false);
            }
            (entry.task.clone(), entry.record.clone())
        };
        let Some(send) = send_of(&record) else {
            return Ok(false);
        };
        let Some(pending) = record.upstream_cancel_pending.as_mut() else {
            return Ok(false);
        };
        let mut outcome = match attempt {
            Some(CancelDelivery::Confirmed) => Some(None),
            Some(CancelDelivery::Failed) => {
                pending.attempts = pending.attempts.saturating_add(1);
                pending.next_after = now.saturating_add(backoff_after(pending.attempts));
                (pending.attempts >= MAX_CANCEL_ATTEMPTS).then_some(Some(GiveUp::Attempts))
            }
            Some(CancelDelivery::NotReady) => {
                pending.next_after = now.saturating_add(NOT_READY_RETRY);
                None
            }
            None => None,
        };
        if outcome.is_none() && send.backend.is_none() {
            outcome = Some(Some(GiveUp::Unresolvable));
        }
        if outcome.is_none() && send.aged(now) {
            outcome = Some(Some(GiveUp::Age));
        }
        if let Some(given_up) = outcome {
            record.upstream_cancel_pending = None;
            record.upstream_cancel_sent = true;
            if let Some(given_up) = given_up {
                let backend = send.backend.as_deref().unwrap_or("");
                let handle = send.handle.as_str();
                let reason = given_up.reason();
                tracing::error!(
                    task_id = %id,
                    backend,
                    handle,
                    reason,
                    "upstream tasks/cancel given up; the upstream job may still be running"
                );
            }
        }
        let still_pending = record.upstream_cancel_pending.is_some();
        let bytes = serialize(&record)?;
        self.commit(&record_name(task.id()), &bytes)?;
        self.publish(task, record, super::HoldUpdate::Carry);
        Ok(still_pending)
    }
}

/// Where a row's upstream cancel stands (MIK-8347).
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UpstreamCancelState {
    /// Claimed, not yet confirmed; `attempts` counts failed sends only.
    Pending { attempts: u8 },
    /// Confirmed, or given up: never sent again.
    Done,
}

#[cfg(test)]
impl TaskStore {
    /// The row's upstream cancel, if one was claimed.
    pub(crate) fn upstream_cancel_state(&self, owner: &str, id: &str) -> Option<UpstreamCancelState> {
        let state = self.0.state();
        let record = &owned(&state, owner, id).ok()?.record;
        match (&record.upstream_cancel_pending, record.upstream_cancel_sent) {
            (Some(pending), _) => Some(UpstreamCancelState::Pending {
                attempts: pending.attempts,
            }),
            (None, true) => Some(UpstreamCancelState::Done),
            (None, false) => None,
        }
    }
}
