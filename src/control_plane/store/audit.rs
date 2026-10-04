// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Audit cursor, page and filter types, and the audit-event <-> log-entry mapping (split from `store.rs`).

use super::{AUDIT_KIND, MAX_AUDIT_LIMIT, MAX_AUDIT_SCAN_RECORDS, StoreError, StoreResult};
#[cfg(doc)]
use super::{ControlPlaneStore, MAX_AUDIT_SCAN_BYTES};
use crate::control_plane::{ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan};

/// Opaque continuation token for [`ControlPlaneStore::read_audit`].
///
/// A cursor names a position in one backend's log; passing it back resumes the
/// scan at records strictly older than that position. Its numeric meaning is
/// backend-private (a byte offset for the file backend, an index for the
/// in-memory one), so never construct or compare one against a hand-made value.
///
/// The file backend's cursor names a segment of the rotating governance log
/// and a byte offset inside it (D6 2.5), so a page walks back across a
/// rotation without skipping or re-reading. A cursor with no segment is the
/// pre-D6 shape: honoured only while the log has never rotated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCursor {
    pub(super) offset: u64,
    pub(super) segment: Option<u64>,
}

impl AuditCursor {
    pub(super) const fn at(offset: u64) -> Self {
        Self {
            offset,
            segment: None,
        }
    }
}

/// One bounded page of audit events, newest first.
#[derive(Debug, Clone)]
pub struct AuditPage {
    /// Matching events, newest first.
    pub events: Vec<ControlPlaneAuditEvent>,
    /// Set when older records remain unexamined: pass it back to continue.
    /// `None` means the scan reached the start of the log, so the page is final.
    pub next_cursor: Option<AuditCursor>,
    /// Audit records examined by this call; never exceeds `filter.scan_budget`.
    pub records_examined: usize,
    /// Bytes read from storage by this call; never exceeds
    /// [`MAX_AUDIT_SCAN_BYTES`]. The in-memory backend does no I/O and reports 0.
    pub bytes_examined: u64,
    /// The cursor passed in no longer named a position (a pre-D6 cursor after
    /// the log rotated), so this page restarts at the newest record. Records
    /// may be re-read; none are skipped.
    pub cursor_reset: bool,
}

/// Filter for [`ControlPlaneStore::read_audit`].
///
/// `limit` is required and must be in `1..=MAX_AUDIT_LIMIT`; a zero or oversized
/// limit is an invalid filter (it must error, never silently return all).
///
/// The read is newest-first and bounded: it examines at most `scan_budget`
/// records and returns [`AuditPage::next_cursor`] whenever it stops before the
/// start of the log, so a filter matching nothing is cheap per call and never
/// silently truncates — the caller pages until `next_cursor` is `None`.
#[derive(Debug, Clone)]
pub struct AuditFilter {
    /// Maximum number of events to return (`1..=10_000`).
    pub limit: usize,
    /// Maximum audit records to examine (`1..=MAX_AUDIT_SCAN_RECORDS`).
    pub scan_budget: usize,
    /// Resume point from a previous page; `None` starts at the newest record.
    pub cursor: Option<AuditCursor>,
    /// Restrict to a single actor id when set.
    pub actor_id: Option<String>,
    /// Restrict to a single action when set.
    pub action: Option<ControlPlaneAction>,
}

impl AuditFilter {
    /// A filter returning the newest `limit` events, with the default budget.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            scan_budget: MAX_AUDIT_SCAN_RECORDS,
            cursor: None,
            actor_id: None,
            action: None,
        }
    }

    /// The same filter resumed at `cursor`.
    #[must_use]
    pub fn resume(&self, cursor: AuditCursor) -> Self {
        Self {
            cursor: Some(cursor),
            ..self.clone()
        }
    }

    /// Validate the filter, returning [`StoreError::InvalidFilter`] when unusable.
    ///
    /// # Errors
    ///
    /// Errors when `limit` is `0` or greater than [`MAX_AUDIT_LIMIT`], or when
    /// `scan_budget` is `0` or greater than [`MAX_AUDIT_SCAN_RECORDS`].
    pub fn validate(&self) -> StoreResult<()> {
        if self.limit == 0 {
            return Err(StoreError::InvalidFilter("limit must be >= 1".to_string()));
        }
        if self.limit > MAX_AUDIT_LIMIT {
            return Err(StoreError::InvalidFilter(format!(
                "limit {} exceeds maximum {MAX_AUDIT_LIMIT}",
                self.limit
            )));
        }
        if self.scan_budget == 0 {
            return Err(StoreError::InvalidFilter(
                "scan_budget must be >= 1".to_string(),
            ));
        }
        if self.scan_budget > MAX_AUDIT_SCAN_RECORDS {
            return Err(StoreError::InvalidFilter(format!(
                "scan_budget {} exceeds maximum {MAX_AUDIT_SCAN_RECORDS}",
                self.scan_budget
            )));
        }
        Ok(())
    }

    /// True when `event` passes the actor/action predicates.
    pub(super) fn matches(&self, event: &ControlPlaneAuditEvent) -> bool {
        self.actor_id.as_ref().is_none_or(|a| a == &event.actor_id)
            && self.action.is_none_or(|a| a == event.action)
    }
}

/// Build the domain fields for an audit event (chain fields are added by the
/// logger). Kept as a free function so both backends serialise identically.
pub(super) fn audit_fields(
    event: &ControlPlaneAuditEvent,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("kind".into(), AUDIT_KIND.into());
    fields.insert("event_id".into(), event.event_id.clone().into());
    fields.insert("actor_id".into(), event.actor_id.clone().into());
    fields.insert(
        "action".into(),
        serde_json::to_value(event.action).unwrap_or(serde_json::Value::Null),
    );
    fields.insert("target_id".into(), event.target_id.clone().into());
    fields.insert("reason".into(), event.reason.clone().into());
    fields.insert(
        "rollback_summary".into(),
        event.rollback.summary.clone().into(),
    );
    fields.insert("rollback_step".into(), event.rollback.step.clone().into());
    if let Some(change) = &event.grant_change {
        fields.insert(
            "grant_change".into(),
            serde_json::to_value(change).unwrap_or(serde_json::Value::Null),
        );
    }
    fields
}

/// Reconstruct an audit event from a transparency-log entry, if it is one.
pub(super) fn audit_event_from_entry(entry: &serde_json::Value) -> Option<ControlPlaneAuditEvent> {
    let obj = entry.as_object()?;
    if obj.get("kind").and_then(serde_json::Value::as_str) != Some(AUDIT_KIND) {
        return None;
    }
    let string = |k: &str| {
        obj.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    Some(ControlPlaneAuditEvent {
        event_id: string("event_id")?,
        actor_id: string("actor_id")?,
        action: serde_json::from_value(obj.get("action")?.clone()).ok()?,
        target_id: string("target_id")?,
        reason: string("reason")?,
        rollback: ControlPlaneRollbackPlan {
            summary: string("rollback_summary")?,
            step: string("rollback_step")?,
        },
        grant_change: obj
            .get("grant_change")
            .and_then(|value| serde_json::from_value(value.clone()).ok()),
    })
}

/// Outcome of one bounded newest-first scan, before a backend turns the resume
/// position into an [`AuditCursor`].
pub(super) struct AuditScan {
    /// Matching events, newest first.
    pub(super) events: Vec<ControlPlaneAuditEvent>,
    /// Resume position when the scan stopped early; `None` when `records` ran
    /// out, in which case the backend supplies the position of what it left
    /// unread (the rest of the file below the window, or the start of the log).
    pub(super) stopped_at: Option<u64>,
    /// Records examined, capped by `filter.scan_budget`.
    pub(super) records_examined: usize,
}

/// Collect one bounded page from `records`, which must yield newest-first
/// `(resume_position, event)` pairs. `resume_position` is where a follow-up scan
/// must restart to cover everything strictly older than that record.
///
/// Stops at `filter.limit` matches or `filter.scan_budget` examined records,
/// whichever comes first, so an unmatched or rare filter does bounded work per
/// call instead of walking the log.
pub(super) fn scan_audit<I>(records: I, filter: &AuditFilter) -> StoreResult<AuditScan>
where
    I: Iterator<Item = StoreResult<(u64, ControlPlaneAuditEvent)>>,
{
    let mut scan = AuditScan {
        events: Vec::new(),
        stopped_at: None,
        records_examined: 0,
    };
    for record in records {
        let (resume_at, event) = record?;
        scan.records_examined += 1;
        if filter.matches(&event) {
            scan.events.push(event);
        }
        if scan.events.len() >= filter.limit || scan.records_examined >= filter.scan_budget {
            scan.stopped_at = Some(resume_at);
            break;
        }
    }
    Ok(scan)
}

/// A resume position becomes a cursor only when records remain below it.
pub(super) fn audit_cursor(resume_at: u64) -> Option<AuditCursor> {
    (resume_at > 0).then_some(AuditCursor::at(resume_at))
}
