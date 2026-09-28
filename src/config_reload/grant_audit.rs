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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::error;

use super::grant_audit_plan::{Pending, State, plan, record as grant_record};
use crate::control_plane::store::AuditFilter;
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneStore, GrantChangeRecord, GrantChangeVerb,
};
use crate::identity_grants::IdentityGrant;
use crate::identity_grants::journal::grant_digest;

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
    /// The plan write fails (the state file itself stays readable).
    PlanWrite,
}

/// The state file name inside the governance store directory.
pub(crate) const STATE_FILE: &str = "grant-journal-state.json";

/// In-memory auditor state, behind one mutex: this serialises the gateway's
/// own reconciliations (design 5.3); the store lease excludes other gateways.
#[derive(Default)]
struct Inner {
    /// The state file as last read or written; `None` until first loaded.
    state: Option<State>,
    /// The pending plan's records are all in the log but its commit write
    /// failed: the plan stays a barrier and is never appended again.
    commit_owed: bool,
    /// Unreadable-journal causes already recorded by this process.
    reported: std::collections::BTreeSet<String>,
}

/// Turns grant-file changes into governance records.
pub struct GrantAuditor {
    store: Arc<dyn ControlPlaneStore>,
    state_path: PathBuf,
    grants_path: PathBuf,
    inner: parking_lot::Mutex<Inner>,
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

/// Records per page in the recovery scan; a plan larger than this pages.
const RECOVERY_PAGE: usize = 100;

const PLAN_REFUSED: &str = "grant change refused: the audit plan could not be written";

impl GrantAuditor {
    /// An auditor over `store`, keeping its state in `store_dir`.
    #[must_use]
    pub fn new(store: Arc<dyn ControlPlaneStore>, store_dir: &Path, grants_path: &Path) -> Self {
        Self {
            store,
            state_path: store_dir.join(STATE_FILE),
            grants_path: grants_path.to_path_buf(),
            inner: parking_lot::Mutex::new(Inner::default()),
            #[cfg(test)]
            fault: parking_lot::Mutex::new(None),
        }
    }

    /// Whether the test-only crash point `want` is armed.
    #[cfg(test)]
    fn fault_is(&self, want: GrantAuditFault) -> bool {
        *self.fault.lock() == Some(want)
    }

    /// A commit write: the state with nothing pending.
    fn commit_write(&self, state: &State) -> Result<(), String> {
        #[cfg(test)]
        if self.fault_is(GrantAuditFault::CommitWrite) {
            return Err("injected commit write failure".to_string());
        }
        state.save(&self.state_path)
    }

    /// Steps 1-6: finish any pending plan, compute this reconciliation's
    /// records, and persist them as the new plan.
    ///
    /// The caller serialises each `prepare` with its [`Self::record`] (the
    /// sink's grant lock on reload, the single startup call): the auditor's
    /// own mutex is released between the two, and an interleaved `prepare`
    /// would recover, and re-append, the plan still being recorded.
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
        let mut inner = self.inner.lock();
        let state = self.finish_pending(&mut inner)?;
        let state = state.for_path(&self.grants_path);
        let (records, next, reported) = plan(&state, rows, journal, &inner.reported);
        if records.is_empty() {
            // Nothing to record: commit the new baseline directly, and skip
            // the write when only the generation would change.
            let same = State {
                generation: state.generation,
                ..next.clone()
            } == state;
            if same {
                inner.state = Some(state);
            } else {
                next.save(&self.state_path)
                    .map_err(|e| Refusal(format!("{PLAN_REFUSED}: {e}")))?;
                inner.state = Some(next);
            }
            inner.reported = reported;
            return Ok(Prepared {
                records: Vec::new(),
            });
        }
        let mut planned = state;
        planned.pending = Some(Pending {
            records: records.clone(),
            next: Box::new(next),
        });
        #[cfg(test)]
        if self.fault_is(GrantAuditFault::PlanWrite) {
            return Err(Refusal(format!("{PLAN_REFUSED}: injected")));
        }
        planned
            .save(&self.state_path)
            .map_err(|e| Refusal(format!("{PLAN_REFUSED}: {e}")))?;
        inner.state = Some(planned);
        // Only a durable plan marks its unreadable-journal cause reported.
        inner.reported = reported;
        #[cfg(test)]
        if self.fault_is(GrantAuditFault::AfterPlanWrite) {
            return Err(Refusal("injected crash after the plan write".to_string()));
        }
        Ok(Prepared { records })
    }

    /// Step 1: load the state, then recover and commit a pending plan.
    /// Returns the committed state, with nothing pending.
    fn finish_pending(&self, inner: &mut Inner) -> Result<State, Refusal> {
        let state = match inner.state.take() {
            Some(state) => state,
            None => State::load(&self.state_path, &self.grants_path)
                .map_err(|e| Refusal(format!("{PLAN_REFUSED}: state file unreadable: {e}")))?,
        };
        let Some(pending) = state.pending.clone() else {
            return Ok(state);
        };
        if !inner.commit_owed
            && let Err(e) = self.append_missing(&pending.records)
        {
            let state = mark_gap(state);
            // Best effort: on a failed write the file keeps the plan, and the
            // next recovery retries it.
            let _ = state.save(&self.state_path);
            inner.state = Some(state);
            return Err(Refusal(format!(
                "grant change refused: an earlier grant change could not be recorded: {e}"
            )));
        }
        let next = *pending.next;
        if let Err(e) = self.commit_write(&next) {
            error!(error = %e, "grant audit plan commit failed; grant changes are refused until it succeeds");
            inner.commit_owed = true;
            inner.state = Some(state);
            return Err(Refusal(format!(
                "grant change refused: the audit plan could not be committed: {e}"
            )));
        }
        inner.commit_owed = false;
        Ok(next)
    }

    /// Append the plan records the log does not already hold, in plan order.
    /// Scans newest-first until it has examined as many grant records as the
    /// plan holds (design 5.3): by the invariant, no newer one can exist.
    fn append_missing(&self, records: &[PlannedRecord]) -> Result<(), String> {
        let mut filter = AuditFilter::new(records.len().clamp(1, RECOVERY_PAGE));
        filter.actor_id = Some(UNKNOWN_ACTOR.to_string());
        filter.action = Some(ControlPlaneAction::MutateGrant);
        let mut seen = std::collections::BTreeSet::new();
        let mut examined = 0;
        loop {
            let page = self.store.read_audit(&filter).map_err(|e| e.to_string())?;
            examined += page.events.len();
            seen.extend(page.events.into_iter().map(|e| e.event_id));
            match page.next_cursor {
                Some(cursor) if examined < records.len() => filter = filter.resume(cursor),
                _ => break,
            }
        }
        for planned in records.iter().filter(|r| !seen.contains(&r.event_id)) {
            self.store
                .append_audit(&planned.event)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

/// Mark the gap in the state and in the plan it will commit, so the commit
/// after recovery still owes the gap record.
fn mark_gap(mut state: State) -> State {
    state.gap = true;
    if let Some(pending) = state.pending.as_mut() {
        pending.next.gap = true;
    }
    state
}

impl GrantAuditor {
    /// Step 7: append the prepared records in order and commit the plan.
    ///
    /// A failed append never unpublishes (AUDIT4.6): it keeps the plan
    /// pending, marks the gap durably, and reports the change unrecorded.
    pub(crate) fn record(&self, prepared: Prepared) -> Recorded {
        let total = prepared.records.len();
        if total == 0 {
            return Recorded::All(0);
        }
        let mut inner = self.inner.lock();
        for (done, planned) in prepared.records.into_iter().enumerate() {
            #[cfg(test)]
            if self.fault_is(GrantAuditFault::AfterAppend(done)) {
                return Recorded::Unrecorded("injected crash after an append".to_string());
            }
            #[cfg(not(test))]
            let _ = done;
            if let Err(e) = self.store.append_audit(&planned.event) {
                if let Some(state) = inner.state.take() {
                    let state = mark_gap(state);
                    if let Err(write) = state.save(&self.state_path) {
                        error!(error = %write, "grant audit gap could not be written");
                    }
                    inner.state = Some(state);
                }
                error!(error = %e, "grant change applied but not recorded");
                return Recorded::Unrecorded(e.to_string());
            }
        }
        #[cfg(test)]
        if self.fault_is(GrantAuditFault::BeforeCommit) {
            return Recorded::Unrecorded("injected crash before the commit".to_string());
        }
        let Some(state) = inner.state.take() else {
            return Recorded::All(total);
        };
        let Some(next) = state.pending.as_ref().map(|p| (*p.next).clone()) else {
            inner.state = Some(state);
            return Recorded::All(total);
        };
        match self.commit_write(&next) {
            Ok(()) => {
                inner.state = Some(next);
                Recorded::All(total)
            }
            Err(e) => {
                error!(error = %e, "grant audit plan commit failed; grant changes are refused until it succeeds");
                inner.commit_owed = true;
                inner.state = Some(state);
                Recorded::Unrecorded(format!(
                    "{total} records written but the audit plan could not be committed: {e}"
                ))
            }
        }
    }

    /// A startup that could not read the grant file serves, and records, the
    /// empty set: make that the baseline when there is none yet, so a file
    /// later written directly reads as `out_of_band` rather than unseen.
    ///
    /// # Errors
    ///
    /// The state file cannot be read or written.
    pub(crate) fn seed_empty_baseline(&self) -> Result<(), String> {
        let mut inner = self.inner.lock();
        if inner.state.is_none() {
            inner.state = Some(State::load(&self.state_path, &self.grants_path)?);
        }
        let Some(state) = inner.state.take() else {
            return Ok(());
        };
        if state.pending.is_some() || inner.commit_owed {
            // A recovery barrier stays as it is; the next reload finishes it.
            inner.state = Some(state);
            return Ok(());
        }
        // State kept for another grant file is no baseline for this one.
        let mut state = state.for_path(&self.grants_path);
        if state.grants.is_none() {
            state.grants = Some(std::collections::BTreeMap::new());
            let saved = state.save(&self.state_path);
            inner.state = Some(state);
            return saved;
        }
        inner.state = Some(state);
        Ok(())
    }

    /// Startup snapshot (design section 6 step 5): one `loaded` record per
    /// active grant, then `loaded_complete` with the count, under a fresh
    /// run id.
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
        let mut inner = self.inner.lock();
        if inner.state.is_none() {
            inner.state = Some(State::load(&self.state_path, &self.grants_path)?);
        }
        if inner.commit_owed || inner.state.as_ref().is_some_and(|s| s.pending.is_some()) {
            return Err("a grant audit plan is still pending".to_string());
        }
        let run = uuid::Uuid::new_v4().to_string();
        let active = crate::identity_grants::journal::active_rows(rows, now);
        for row in &active {
            let mut change = GrantChangeRecord::new(GrantChangeVerb::Loaded);
            change.digest = Some(grant_digest(row));
            change.expires_at = row.expires_at;
            change.run_id = Some(run.clone());
            let loaded = grant_record(
                format!("grant-loaded:{run}:{}", row.grant_id),
                &row.grant_id,
                change,
                "startup snapshot: grant active and served",
            );
            self.store
                .append_audit(&loaded.event)
                .map_err(|e| e.to_string())?;
        }
        let mut change = GrantChangeRecord::new(GrantChangeVerb::LoadedComplete);
        change.run_id = Some(run.clone());
        change.count = Some(active.len() as u64);
        let closing = grant_record(
            format!("grant-loaded:{run}"),
            &run,
            change,
            "startup snapshot complete",
        );
        self.store
            .append_audit(&closing.event)
            .map_err(|e| e.to_string())
    }
}
