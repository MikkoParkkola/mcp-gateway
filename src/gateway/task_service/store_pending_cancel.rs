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
    PENDING_CANCEL_VERSION, PendingCancel, Record, Target, UpstreamRecord,
};
use crate::protocol::tasks::Task;

/// Put `descriptor`'s cancel on `record` as pending, claimed at `now`.
///
/// The one shape both the claim and the dispatch preflight's reservation
/// use, so what is reserved is what is written. The descriptor leaves the
/// row; a legacy row keeps its call as a target first, and the pending
/// cancel names its backend through that target where one does. `None` is a
/// claim made on a dark clock: undated, due at once, with no age yet
/// (MIK-8202 P4b).
pub(super) fn record_pending_claim(
    task: &Task,
    record: &mut Record,
    descriptor: &UpstreamRecord,
    now: Option<i64>,
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

/// The widest encoding of [`record_pending_claim`]'s result: counters and
/// instants at their longest decimal spellings (`Some(i64::MIN)` still
/// spells longer than `None`).
pub(super) fn widest_pending_claim(task: &Task, record: &mut Record, descriptor: &UpstreamRecord) {
    record_pending_claim(task, record, descriptor, Some(i64::MIN));
    if let Some(pending) = record.upstream_cancel_pending.as_mut() {
        pending.attempts = u8::MAX;
    }
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
    /// `None` when the claim met a dark clock: due at once (MIK-8202 P4b).
    pub(crate) next_after: Option<i64>,
    /// `None` until the first readable reading dates it: no age yet
    /// (MIK-8202 P4b).
    pub(crate) claimed_at: Option<i64>,
}

impl PendingSend {
    /// Whether the age cap has passed at `now`. An undated record has no
    /// age yet, so it is never aged (MIK-8202 P4b).
    pub(crate) fn aged(&self, now: i64) -> bool {
        self.claimed_at
            .is_some_and(|claimed| now.saturating_sub(claimed) >= age_secs())
    }
}

fn age_secs() -> i64 {
    i64::try_from(MAX_CANCEL_PENDING_AGE.as_secs()).unwrap_or(i64::MAX)
}

fn send_of(record: &Record) -> Option<PendingSend> {
    let pending = record.upstream_cancel_pending.as_ref()?;
    Some(send_from(pending, &record.targets))
}

fn send_from(pending: &PendingCancel, targets: &[Target]) -> PendingSend {
    PendingSend {
        backend: pending.backend_in(targets).map(str::to_owned),
        handle: pending.handle.clone(),
        next_after: pending.next_after,
        claimed_at: pending.claimed_at,
    }
}

impl TaskStore {
    /// The row's pending cancel, if it has one.
    pub(crate) fn pending_cancel(&self, owner: &str, id: &str) -> Option<PendingSend> {
        let state = self.0.state();
        send_of(&owned(&state, owner, id).ok()?.record)
    }

    /// Rows with a pending cancel: `backend`'s rows whatever their back-off,
    /// or with `None`, every row due at `now` by back-off or by age. An
    /// undated record is due at once (MIK-8202 P4b).
    pub(crate) fn pending_cancels(&self, backend: Option<&str>, now: i64) -> Vec<(String, String)> {
        let state = self.0.state();
        state
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                let send = send_of(&entry.record)?;
                let wanted = match backend {
                    Some(backend) => send.backend.as_deref() == Some(backend),
                    None => send.next_after.is_none_or(|due| due <= now) || send.aged(now),
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
        tokio::task::spawn_blocking(move || {
            shared.record_cancel_attempt_blocking(&owner, &id, attempt)
        })
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
            (entry.task.clone(), entry.record.clone())
        };
        let Some(mut pending) = record.upstream_cancel_pending.take() else {
            return Ok(false);
        };
        // Read before the pending state leaves the row, for the give-up log.
        let send = send_from(&pending, &record.targets);
        let mut outcome = match attempt {
            Some(CancelDelivery::Confirmed) => Some(None),
            Some(CancelDelivery::Failed) => {
                pending.attempts = pending.attempts.saturating_add(1);
                pending.next_after = Some(now.saturating_add(backoff_after(pending.attempts)));
                // The first readable outcome dates an undated record, so the
                // age cap counts from here (MIK-8202 P4b).
                pending.claimed_at = pending.claimed_at.or(Some(now));
                (pending.attempts >= MAX_CANCEL_ATTEMPTS).then_some(Some(GiveUp::Attempts))
            }
            Some(CancelDelivery::NotReady) => {
                pending.next_after = Some(now.saturating_add(NOT_READY_RETRY));
                pending.claimed_at = pending.claimed_at.or(Some(now));
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
        if outcome.is_none() {
            record.upstream_cancel_pending = Some(pending);
        }
        // Logged once the ordering lock is released, whether or not the
        // commit below lands.
        let mut gave_up = None;
        if let Some(given_up) = outcome {
            record.upstream_cancel_sent = true;
            gave_up = given_up;
        }
        let still_pending = record.upstream_cancel_pending.is_some();
        let committed =
            serialize(&record).and_then(|bytes| self.commit(&record_name(task.id()), &bytes));
        if committed.is_ok() {
            self.publish(task, record, super::HoldUpdate::Carry);
        }
        drop(_order);
        if let Some(given_up) = gave_up {
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
        committed.map(|()| still_pending)
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
    pub(crate) fn upstream_cancel_state(
        &self,
        owner: &str,
        id: &str,
    ) -> Option<UpstreamCancelState> {
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
