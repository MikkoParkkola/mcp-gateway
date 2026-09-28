// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Governance records for grant-file changes (MIK-7570.AUDIT.4).
//!
//! The CLI journals each change beside the grant file; this module turns the
//! journal and the file into governance audit records, exactly once, and
//! records direct edits as out-of-band. Every record has actor `unknown`.
//! Design: `docs/design/2026-09-28-grant-change-journal.md` sections 5-6.
//!
//! Two calls per reconciliation, because the plan must be durable before the
//! grant set is published and the records are appended after it:
//! [`GrantAuditor::prepare`] (steps 1-6 up to the plan write) and
//! [`GrantAuditor::record`] (appends and commit).

#![allow(dead_code, reason = "red-first stub")]
#![allow(
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_value,
    reason = "red-first stub"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::control_plane::ControlPlaneStore;
use crate::identity_grants::IdentityGrant;

/// The actor on every grant-file record: none was authenticated.
pub(crate) const UNKNOWN_ACTOR: &str = crate::identity_grants::journal::UNKNOWN_ACTOR;

/// What the journal read found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JournalRead {
    /// No journal file: no CLI change was ever journalled.
    Missing,
    /// The journal's bytes.
    Bytes(Vec<u8>),
    /// The journal exists but could not be read or failed its mode check.
    Unreadable(String),
}

/// One planned governance record, persisted before it is appended.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PlannedRecord {
    /// Deterministic event id (design 5.2 step 6).
    pub(crate) event_id: String,
    /// The audit event to append.
    pub(crate) event: crate::control_plane::ControlPlaneAuditEvent,
}

/// A reconciliation whose plan is durable and whose records are not yet all
/// appended. Hand it back to [`GrantAuditor::record`] after publishing.
#[derive(Debug)]
pub(crate) struct Prepared {
    pub(crate) records: Vec<PlannedRecord>,
}

/// Why a reconciliation refuses the change (design 5.2, paragraph after step 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal(pub(crate) String);

/// What [`GrantAuditor::record`] achieved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recorded {
    /// Every planned record is in the log and the plan is committed.
    All(usize),
    /// Some record is missing; the change stays applied (AUDIT4.6).
    Unrecorded(String),
}

/// Test-only crash points (design section 7).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantAuditFault {
    /// Return after the plan write, before any append (C4).
    AfterPlanWrite,
    /// Return after this many appends (C5).
    AfterAppend(usize),
    /// Return after the last append, before the commit write (C6).
    BeforeCommit,
    /// Every commit write fails while set.
    CommitWrite,
}

/// The state file name inside the governance store directory.
pub(crate) const STATE_FILE: &str = "grant-journal-state.json";

/// Turns grant-file changes into governance records.
pub struct GrantAuditor {
    store: Arc<dyn ControlPlaneStore>,
    state_path: PathBuf,
    grants_path: PathBuf,
    #[cfg(test)]
    pub(crate) fault: parking_lot::Mutex<Option<GrantAuditFault>>,
}

impl std::fmt::Debug for GrantAuditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantAuditor")
            .field("state_path", &self.state_path)
            .field("grants_path", &self.grants_path)
            .finish_non_exhaustive()
    }
}

impl GrantAuditor {
    /// An auditor over `store`, keeping its state in `store_dir`.
    #[must_use]
    pub fn new(store: Arc<dyn ControlPlaneStore>, store_dir: &Path, grants_path: &Path) -> Self {
        Self {
            store,
            state_path: store_dir.join(STATE_FILE),
            grants_path: grants_path.to_path_buf(),
            #[cfg(test)]
            fault: parking_lot::Mutex::new(None),
        }
    }

    /// Steps 1-6: finish any pending plan, compute this reconciliation's
    /// records, and persist them as the new plan.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the plan cannot be made durable, or an earlier plan
    /// cannot be finished: the caller must not publish.
    pub(crate) fn prepare(
        &self,
        rows: &[IdentityGrant],
        journal: &JournalRead,
    ) -> Result<Prepared, Refusal> {
        let _ = (&self.store, rows, journal);
        Ok(Prepared {
            records: Vec::new(),
        })
    }

    /// Step 7: append the prepared records in order and commit the plan.
    pub(crate) fn record(&self, prepared: Prepared) -> Recorded {
        Recorded::All(prepared.records.len())
    }

    /// Startup snapshot (design section 6 step 5): one `loaded` record per
    /// active grant, then `loaded_complete` with the count.
    ///
    /// # Errors
    ///
    /// The append that failed, or a plan still pending: the caller then
    /// serves no grants from this run.
    pub(crate) fn snapshot(
        &self,
        rows: &[IdentityGrant],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), String> {
        let _ = (rows, now);
        Ok(())
    }
}
