// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one durable claim on a cancelled row's upstream `tasks/cancel`
//! (MIK-7642 PR.D, design r7 R7.3 / r8 R8.4).
//!
//! Every sender — the cancel transition, the worker's dispatch-phase cancel
//! arm, and the worker's offer after a refused capture — asks here, and sends only on
//! [`CancelClaim::Claimed`]. The claim is one compare on
//! `Record::upstream_cancel_sent` under the store's ordering lock, so exactly
//! one sender wins per row whatever order they arrive in.

use std::sync::Arc;

use super::{Shared, StoreError, TaskStore, owned, record_name, serialize};
use crate::gateway::task_service::record::{
    MAX_UPSTREAM_HANDLE_BYTES, UPSTREAM_CANCEL_VERSION, UpstreamRecord,
};
use crate::protocol::tasks::TaskStatus;

/// What one claim on a row's upstream cancel decided.
#[derive(Debug, PartialEq)]
pub(crate) enum CancelClaim {
    /// This caller won: send one `tasks/cancel` naming this descriptor's handle.
    Claimed(UpstreamRecord),
    /// Another sender already claimed it. Send nothing.
    AlreadyClaimed,
    /// Not a cancelled row, or no handle is known for it yet. Nothing is
    /// claimed, so a sender that learns the handle later can still win.
    NotOurs,
}

impl TaskStore {
    /// Claim the single upstream `tasks/cancel` of a cancelled row.
    ///
    /// `offered` is the descriptor a sender holds but the row may not: the
    /// worker that has a handle the capture never made durable. A descriptor
    /// already on the row wins over it (first handle wins), and an offered one
    /// must name the row's own admitted operation. The winning descriptor is
    /// returned to the sender and taken off the row. The revision is not
    /// bumped: like `mark_upstream`, no reader's compare-and-set depends on
    /// this field.
    ///
    /// # Errors
    /// `NotFound` for a foreign or absent row; `Capacity` when the descriptor
    /// would exceed the record budget; a storage failure as itself.
    pub(crate) async fn claim_upstream_cancel(
        &self,
        owner: &str,
        id: &str,
        offered: Option<UpstreamRecord>,
    ) -> Result<CancelClaim, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.claim_upstream_cancel_blocking(&owner, &id, offered)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }
}

impl Shared {
    fn claim_upstream_cancel_blocking(
        &self,
        owner: &str,
        id: &str,
        offered: Option<UpstreamRecord>,
    ) -> Result<CancelClaim, StoreError> {
        let _order = self.order();
        let (task, mut record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.task.status() != TaskStatus::Cancelled {
                return Ok(CancelClaim::NotOurs);
            }
            if entry.record.upstream_cancel_sent {
                return Ok(CancelClaim::AlreadyClaimed);
            }
            (entry.task.clone(), entry.record.clone())
        };
        let durable = record
            .upstream
            .clone()
            .filter(|upstream| upstream.consistent_with(&record.admission));
        let offered = offered.filter(|upstream| {
            upstream.handle.len() <= MAX_UPSTREAM_HANDLE_BYTES
                && upstream.consistent_with(&record.admission)
        });
        let Some(descriptor) = durable.or(offered) else {
            return Ok(CancelClaim::NotOurs);
        };
        // The descriptor leaves the row with the claim. A terminal row is never
        // queried again, and taking it off is what guarantees the marker fits:
        // the cancelled row already met its budget with the descriptor on it.
        // A legacy row named its call only through the descriptor: keep that
        // provenance as targets before the descriptor leaves (the row is raised
        // past the version that reads targets). The winning descriptor, offered
        // or durable, is the one read.
        record.upstream = Some(descriptor.clone());
        let _ = super::targets::keep_provenance(&task, &mut record);
        record.upstream = None;
        record.upstream_cancel_sent = true;
        record.version = record.version.max(UPSTREAM_CANCEL_VERSION);
        let bytes = serialize(&record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        self.publish(task, record);
        Ok(CancelClaim::Claimed(descriptor))
    }
}
