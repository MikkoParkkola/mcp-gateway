// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Persistence for the enterprise control plane (MIK-6685).
//!
//! Grants and policies persist across restarts on a single node; the audit
//! view is fed by a governance-scoped [`TransparencyLogger`] (hash-chain,
//! append-only) rather than a new database (ADR-005).
//!
//! The [`ControlPlaneStore`] trait has two implementations: an in-memory one
//! for tests and an atomic-file one for durable single-node deployments. Both
//! pass the same conformance suite. A server-backed durable store is
//! demand-gated (MIK-6692).
//!
//! ## Crash- and concurrency-safety (file backend)
//!
//! - Each collection is written whole-file with a temp → `fsync` → `rename` →
//!   dir-`fsync` sequence, so a crash at any phase leaves either the complete
//!   old file or the complete new file, never a torn one.
//! - A CLI writer and the server writer are *separate processes*, so an
//!   in-process `Mutex` is insufficient. Each collection is guarded by an OS
//!   advisory lock (`flock`) held across the whole read-modify-write, plus a
//!   monotonic `generation` counter for compare-and-swap so a stale writer is
//!   rejected and must re-read.
//! - Malformed collection JSON fails closed: a load errors and a write never
//!   truncates the good file.
//!
//! ## Audit tamper-evidence scope
//!
//! The governance audit log reuses [`TransparencyLogger`]'s hash chain, which
//! `verify_log` checks for truncation, reordering, and un-rechained edits. Full
//! re-chain forgery by an attacker with write access AND the HMAC secret is not
//! caught by `verify_log` today (it does not verify the per-entry HMAC); that
//! external-anchor / signature-verification hardening is tracked separately and
//! is also mitigated by the SIEM export's trusted checkpoint anchor (MIK-6689).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Serialize, de::DeserializeOwned};

use crate::control_plane::{
    ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneGrant, ControlPlaneGrantStatus,
    ControlPlanePolicy, ControlPlaneRollbackPlan,
};
use crate::fs_lock::ExclusiveFileLock;
use crate::security::TransparencyLogger;

/// On-disk schema version for a persisted collection.
const COLLECTION_SCHEMA_VERSION: u32 = 1;

/// Marker written on every governance audit entry so the reader can tell
/// control-plane events apart from any other entries sharing the log.
const AUDIT_KIND: &str = "control_plane_audit";

/// Upper bound on a single [`AuditFilter`] page, so a caller cannot ask for an
/// unbounded read.
const MAX_AUDIT_LIMIT: usize = 10_000;

/// Upper bound on the audit records a single [`ControlPlaneStore::read_audit`]
/// call may examine, so a filter that matches nothing cannot walk the whole log.
const MAX_AUDIT_SCAN_RECORDS: usize = 50_000;

/// Hard ceiling on the bytes the file backend reads from the audit log per
/// [`ControlPlaneStore::read_audit`] call, regardless of the scan budget. The
/// scan is a reverse tail window, so this bounds the work of one page even when
/// the log is gigabytes long.
const MAX_AUDIT_SCAN_BYTES: u64 = 1 << 20;

/// Errors returned by a [`ControlPlaneStore`].
#[derive(Debug)]
pub enum StoreError {
    /// Underlying I/O failure.
    Io(std::io::Error),
    /// A collection file exists but could not be parsed. The store fails closed
    /// rather than treating the collection as empty and overwriting good data.
    Corrupt(String),
    /// A compare-and-swap write was rejected because the on-disk generation
    /// moved since the caller read it. The caller must re-read and retry.
    StaleGeneration {
        /// Generation the caller expected to write on top of.
        expected: u64,
        /// Generation currently on disk.
        actual: u64,
    },
    /// A read filter was invalid (e.g. a zero or too-large limit).
    InvalidFilter(String),
    /// Serialisation failed.
    Serialize(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "control-plane store I/O error: {e}"),
            Self::Corrupt(m) => write!(f, "control-plane store corrupt collection: {m}"),
            Self::StaleGeneration { expected, actual } => write!(
                f,
                "control-plane store stale write: expected generation {expected}, found {actual}"
            ),
            Self::InvalidFilter(m) => write!(f, "control-plane store invalid filter: {m}"),
            Self::Serialize(m) => write!(f, "control-plane store serialize error: {m}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Result alias for store operations.
pub type StoreResult<T> = Result<T, StoreError>;

/// Opaque continuation token for [`ControlPlaneStore::read_audit`].
///
/// A cursor names a position in one backend's log; passing it back resumes the
/// scan at records strictly older than that position. Its numeric meaning is
/// backend-private (a byte offset for the file backend, an index for the
/// in-memory one), so never construct or compare one against a hand-made value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditCursor(u64);

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
    fn matches(&self, event: &ControlPlaneAuditEvent) -> bool {
        self.actor_id.as_ref().is_none_or(|a| a == &event.actor_id)
            && self.action.is_none_or(|a| a == event.action)
    }
}

/// Persistence contract for control-plane grants, policies, and audit events.
pub trait ControlPlaneStore: Send + Sync {
    /// List all grants.
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>>;
    /// Get one grant by id.
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn get_grant(&self, grant_id: &str) -> StoreResult<Option<ControlPlaneGrant>>;
    /// Insert or replace a grant (keyed by `grant_id`).
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn put_grant(&self, grant: ControlPlaneGrant) -> StoreResult<()>;
    /// Delete a grant by id. Deleting a missing id is a no-op.
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn delete_grant(&self, grant_id: &str) -> StoreResult<()>;

    /// List all policies.
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>>;
    /// Get one policy by id.
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn get_policy(&self, policy_id: &str) -> StoreResult<Option<ControlPlanePolicy>>;
    /// Insert or replace a policy (keyed by `policy_id`).
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn put_policy(&self, policy: ControlPlanePolicy) -> StoreResult<()>;
    /// Delete a policy by id. Deleting a missing id is a no-op.
    ///
    /// # Errors
    /// Errors on I/O failure or a corrupt collection.
    fn delete_policy(&self, policy_id: &str) -> StoreResult<()>;

    /// Append a governance audit event to the tamper-evident log.
    ///
    /// # Errors
    /// Errors on I/O or serialisation failure.
    fn append_audit(&self, event: &ControlPlaneAuditEvent) -> StoreResult<()>;
    /// Read one bounded page of audit events, newest first.
    ///
    /// The page holds at most `filter.limit` matching events and the call
    /// examines at most `filter.scan_budget` records (and, on a file backend, at
    /// most [`MAX_AUDIT_SCAN_BYTES`] bytes). When the scan stops before the
    /// start of the log — because the page filled or the budget ran out — the
    /// returned [`AuditPage::next_cursor`] resumes it, so a filter matching
    /// nothing costs one bounded page per call and is never silently truncated.
    ///
    /// # Errors
    /// Errors on an invalid filter, an I/O failure, a corrupt log line.
    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<AuditPage>;

    /// Atomically append a write-ahead audit event, then upsert the grant, as a
    /// single serialized unit. Guarantees a committed grant is never unaudited
    /// and that audit order matches commit order. The default appends then
    /// commits; durable backends override to hold one lock across both.
    ///
    /// # Errors
    /// Errors on an I/O failure, a serialisation failure, a corrupt collection.
    fn commit_grant_audited(
        &self,
        grant: ControlPlaneGrant,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<()> {
        self.append_audit(event)?;
        self.put_grant(grant)
    }

    /// Policy counterpart of [`Self::commit_grant_audited`].
    ///
    /// # Errors
    /// Errors on an I/O failure, a serialisation failure, a corrupt collection.
    fn commit_policy_audited(
        &self,
        policy: ControlPlanePolicy,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<()> {
        self.append_audit(event)?;
        self.put_policy(policy)
    }

    /// Apply a status change to one grant as an audited unit WITHOUT overwriting
    /// its other fields. Returns `false` when no grant with `grant_id` exists
    /// (so callers can 404 without writing an audit record). Durable backends
    /// override to re-read the row under the lock, so a concurrent edit to other
    /// fields is not lost — unlike [`Self::commit_grant_audited`], which
    /// replaces the whole row with the caller's copy.
    ///
    /// # Errors
    /// Errors on an I/O failure, a serialisation failure, a corrupt collection.
    fn set_grant_status_audited(
        &self,
        grant_id: &str,
        status: ControlPlaneGrantStatus,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<bool> {
        let Some(mut grant) = self.get_grant(grant_id)? else {
            return Ok(false);
        };
        grant.status = status;
        self.commit_grant_audited(grant, event)?;
        Ok(true)
    }

    /// Policy counterpart of [`Self::set_grant_status_audited`] (sets `enforced`).
    ///
    /// # Errors
    /// Errors on an I/O failure, a serialisation failure, a corrupt collection.
    fn set_policy_enforced_audited(
        &self,
        policy_id: &str,
        enforced: bool,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<bool> {
        let Some(mut policy) = self.get_policy(policy_id)? else {
            return Ok(false);
        };
        policy.enforced = enforced;
        self.commit_policy_audited(policy, event)?;
        Ok(true)
    }
}

// ── Audit event <-> transparency-log entry mapping ─────────────────────────────

/// Build the domain fields for an audit event (chain fields are added by the
/// logger). Kept as a free function so both backends serialise identically.
fn audit_fields(event: &ControlPlaneAuditEvent) -> serde_json::Map<String, serde_json::Value> {
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
    fields
}

/// Reconstruct an audit event from a transparency-log entry, if it is one.
fn audit_event_from_entry(entry: &serde_json::Value) -> Option<ControlPlaneAuditEvent> {
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
    })
}

/// Outcome of one bounded newest-first scan, before a backend turns the resume
/// position into an [`AuditCursor`].
struct AuditScan {
    /// Matching events, newest first.
    events: Vec<ControlPlaneAuditEvent>,
    /// Resume position when the scan stopped early; `None` when `records` ran
    /// out, in which case the backend supplies the position of what it left
    /// unread (the rest of the file below the window, or the start of the log).
    stopped_at: Option<u64>,
    /// Records examined, capped by `filter.scan_budget`.
    records_examined: usize,
}

/// Collect one bounded page from `records`, which must yield newest-first
/// `(resume_position, event)` pairs. `resume_position` is where a follow-up scan
/// must restart to cover everything strictly older than that record.
///
/// Stops at `filter.limit` matches or `filter.scan_budget` examined records,
/// whichever comes first, so an unmatched or rare filter does bounded work per
/// call instead of walking the log.
fn scan_audit<I>(records: I, filter: &AuditFilter) -> StoreResult<AuditScan>
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
fn audit_cursor(resume_at: u64) -> Option<AuditCursor> {
    (resume_at > 0).then_some(AuditCursor(resume_at))
}

// ── In-memory backend ──────────────────────────────────────────────────────────

/// In-memory [`ControlPlaneStore`], used by tests and ephemeral deployments.
#[derive(Default)]
pub struct InMemoryControlPlaneStore {
    grants: Mutex<Vec<ControlPlaneGrant>>,
    policies: Mutex<Vec<ControlPlanePolicy>>,
    audit: Mutex<Vec<ControlPlaneAuditEvent>>,
}

impl InMemoryControlPlaneStore {
    /// Create an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock<T>(guard: &Mutex<T>) -> StoreResult<std::sync::MutexGuard<'_, T>> {
        guard
            .lock()
            .map_err(|_| StoreError::Serialize("in-memory store mutex poisoned".to_string()))
    }
}

impl ControlPlaneStore for InMemoryControlPlaneStore {
    fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>> {
        Ok(Self::lock(&self.grants)?.clone())
    }

    fn get_grant(&self, grant_id: &str) -> StoreResult<Option<ControlPlaneGrant>> {
        Ok(Self::lock(&self.grants)?
            .iter()
            .find(|g| g.grant_id == grant_id)
            .cloned())
    }

    fn put_grant(&self, grant: ControlPlaneGrant) -> StoreResult<()> {
        let mut grants = Self::lock(&self.grants)?;
        if let Some(existing) = grants.iter_mut().find(|g| g.grant_id == grant.grant_id) {
            *existing = grant;
        } else {
            grants.push(grant);
        }
        Ok(())
    }

    fn delete_grant(&self, grant_id: &str) -> StoreResult<()> {
        Self::lock(&self.grants)?.retain(|g| g.grant_id != grant_id);
        Ok(())
    }

    fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>> {
        Ok(Self::lock(&self.policies)?.clone())
    }

    fn get_policy(&self, policy_id: &str) -> StoreResult<Option<ControlPlanePolicy>> {
        Ok(Self::lock(&self.policies)?
            .iter()
            .find(|p| p.policy_id == policy_id)
            .cloned())
    }

    fn put_policy(&self, policy: ControlPlanePolicy) -> StoreResult<()> {
        let mut policies = Self::lock(&self.policies)?;
        if let Some(existing) = policies
            .iter_mut()
            .find(|p| p.policy_id == policy.policy_id)
        {
            *existing = policy;
        } else {
            policies.push(policy);
        }
        Ok(())
    }

    fn delete_policy(&self, policy_id: &str) -> StoreResult<()> {
        Self::lock(&self.policies)?.retain(|p| p.policy_id != policy_id);
        Ok(())
    }

    fn append_audit(&self, event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        Self::lock(&self.audit)?.push(event.clone());
        Ok(())
    }

    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<AuditPage> {
        filter.validate()?;
        let audit = Self::lock(&self.audit)?;
        // The cursor is an exclusive upper-bound index: scan backwards from it.
        let end = filter
            .cursor
            .map_or(audit.len(), |AuditCursor(i)| {
                usize::try_from(i).unwrap_or(usize::MAX)
            })
            .min(audit.len());
        let scan = scan_audit(
            audit[..end]
                .iter()
                .enumerate()
                .rev()
                .map(|(i, e)| Ok((u64::try_from(i).unwrap_or(u64::MAX), e.clone()))),
            filter,
        )?;
        Ok(AuditPage {
            events: scan.events,
            next_cursor: audit_cursor(scan.stopped_at.unwrap_or(0)),
            records_examined: scan.records_examined,
            bytes_examined: 0,
        })
    }
}

// ── Atomic-file backend ─────────────────────────────────────────────────────────

/// A collection serialised whole-file, with a generation for compare-and-swap.
#[derive(serde::Deserialize)]
struct VersionedCollection<T> {
    #[allow(dead_code)]
    schema_version: u32,
    generation: u64,
    items: Vec<T>,
}

/// Borrowing view used only for serialisation, so a compare-and-swap write need
/// not clone the items or bound `T: Clone`.
#[derive(Serialize)]
struct VersionedCollectionRef<'a, T> {
    schema_version: u32,
    generation: u64,
    items: &'a [T],
}

/// Point at which [`write_atomic`] simulates a crash, for the phase-fault test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    /// Complete the write normally.
    None,
    /// Crash after writing the temp file, before its `fsync`.
    AfterTempWrite,
    /// Crash after the temp file's `fsync`, before the `rename`.
    AfterTempFsync,
    /// Crash after the `rename`, before the directory `fsync`.
    AfterRename,
    /// Crash after the directory `fsync` (i.e. fully durable).
    AfterDirFsync,
}

/// Durable single-node [`ControlPlaneStore`] backed by one JSON file per
/// collection plus a governance-scoped [`TransparencyLogger`] for audit.
pub struct FileControlPlaneStore {
    dir: PathBuf,
    audit: Arc<TransparencyLogger>,
}

impl FileControlPlaneStore {
    /// Open a store rooted at `dir`, using `audit` as the governance log. The
    /// caller owns the logger's config (path, signing secret) and MUST keep it
    /// separate from the invocation log.
    ///
    /// # Errors
    ///
    /// Errors if `dir` cannot be created.
    pub fn open(dir: PathBuf, audit: Arc<TransparencyLogger>) -> StoreResult<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, audit })
    }

    fn grants_file(&self) -> PathBuf {
        self.dir.join("grants.json")
    }

    fn policies_file(&self) -> PathBuf {
        self.dir.join("policies.json")
    }

    /// Load a collection, treating a missing file as empty (generation 0) and a
    /// present-but-unparseable file as [`StoreError::Corrupt`] (fail closed).
    fn load<T: DeserializeOwned>(file: &Path) -> StoreResult<VersionedCollection<T>> {
        match std::fs::read(file) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| StoreError::Corrupt(format!("{}: {e}", file.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VersionedCollection {
                schema_version: COLLECTION_SCHEMA_VERSION,
                generation: 0,
                items: Vec::new(),
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Read only the on-disk generation of `file` (0 if missing). Fails closed
    /// on a corrupt file so a compare-and-swap never overwrites good data.
    fn disk_generation<T: DeserializeOwned>(file: &Path) -> StoreResult<u64> {
        Ok(Self::load::<T>(file)?.generation)
    }

    /// Compare-and-swap write of a collection under an exclusive OS file lock.
    ///
    /// The lock is held across read-generation → check → write so a concurrent
    /// process cannot interleave. If the on-disk generation no longer equals
    /// `expected_generation`, the write is rejected as stale.
    fn store_cas<T: Serialize + DeserializeOwned>(
        &self,
        file: &Path,
        items: &[T],
        expected_generation: u64,
        fault: FaultPoint,
    ) -> StoreResult<u64> {
        let _lock = ExclusiveFileLock::acquire(&self.lock_path(file))?;

        let current = Self::disk_generation::<T>(file)?;
        if current != expected_generation {
            return Err(StoreError::StaleGeneration {
                expected: expected_generation,
                actual: current,
            });
        }

        let next = current + 1;
        let payload = VersionedCollectionRef {
            schema_version: COLLECTION_SCHEMA_VERSION,
            generation: next,
            items,
        };
        let bytes = serde_json::to_vec_pretty(&payload)
            .map_err(|e| StoreError::Serialize(e.to_string()))?;
        write_atomic(file, &bytes, fault)?;
        Ok(next)
        // `_lock` drops here, releasing the advisory lock.
    }

    fn lock_path(&self, file: &Path) -> PathBuf {
        // A dedicated lock file that is never renamed, so the held fd's lock
        // survives the collection file's atomic rename.
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("cp");
        self.dir.join(format!(".{name}.lock"))
    }

    /// Optimistic read-modify-write against a collection: load, apply `mutate`,
    /// then compare-and-swap; retry from a fresh read if a stale write loses.
    fn mutate<T, F>(&self, file: &Path, mut mutate: F) -> StoreResult<()>
    where
        T: Serialize + DeserializeOwned,
        F: FnMut(&mut Vec<T>),
    {
        loop {
            let mut current = Self::load::<T>(file)?;
            mutate(&mut current.items);
            match self.store_cas(file, &current.items, current.generation, FaultPoint::None) {
                Ok(_) => return Ok(()),
                Err(StoreError::StaleGeneration { .. }) => {} // lost the race, re-read
                Err(e) => return Err(e),
            }
        }
    }

    /// Append one governance audit entry, assuming the caller already holds the
    /// audit lock. Re-syncs the chain tail from disk under the lock (so separate
    /// processes never write the same counter) and fsyncs for durability.
    fn append_audit_locked(&self, event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        self.audit
            .append_event_synced(audit_fields(event))
            .map(|_| ())
            .map_err(StoreError::from)
    }
}

impl ControlPlaneStore for FileControlPlaneStore {
    fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>> {
        Ok(Self::load::<ControlPlaneGrant>(&self.grants_file())?.items)
    }

    fn get_grant(&self, grant_id: &str) -> StoreResult<Option<ControlPlaneGrant>> {
        Ok(self
            .list_grants()?
            .into_iter()
            .find(|g| g.grant_id == grant_id))
    }

    fn put_grant(&self, grant: ControlPlaneGrant) -> StoreResult<()> {
        self.mutate::<ControlPlaneGrant, _>(&self.grants_file(), |items| {
            if let Some(existing) = items.iter_mut().find(|g| g.grant_id == grant.grant_id) {
                *existing = grant.clone();
            } else {
                items.push(grant.clone());
            }
        })
    }

    fn delete_grant(&self, grant_id: &str) -> StoreResult<()> {
        self.mutate::<ControlPlaneGrant, _>(&self.grants_file(), |items| {
            items.retain(|g| g.grant_id != grant_id);
        })
    }

    fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>> {
        Ok(Self::load::<ControlPlanePolicy>(&self.policies_file())?.items)
    }

    fn get_policy(&self, policy_id: &str) -> StoreResult<Option<ControlPlanePolicy>> {
        Ok(self
            .list_policies()?
            .into_iter()
            .find(|p| p.policy_id == policy_id))
    }

    fn put_policy(&self, policy: ControlPlanePolicy) -> StoreResult<()> {
        self.mutate::<ControlPlanePolicy, _>(&self.policies_file(), |items| {
            if let Some(existing) = items.iter_mut().find(|p| p.policy_id == policy.policy_id) {
                *existing = policy.clone();
            } else {
                items.push(policy.clone());
            }
        })
    }

    fn delete_policy(&self, policy_id: &str) -> StoreResult<()> {
        self.mutate::<ControlPlanePolicy, _>(&self.policies_file(), |items| {
            items.retain(|p| p.policy_id != policy_id);
        })
    }

    fn append_audit(&self, event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        let _lock = ExclusiveFileLock::acquire(&self.dir.join(".audit.lock"))?;
        self.append_audit_locked(event)
    }

    fn commit_grant_audited(
        &self,
        grant: ControlPlaneGrant,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<()> {
        // Hold the audit lock across BOTH the write-ahead audit and the commit
        // so the pair is one serialized, ordered unit: no interleaving can make
        // the audit order disagree with the committed order, and a committed
        // grant is never unaudited.
        let _lock = ExclusiveFileLock::acquire(&self.dir.join(".audit.lock"))?;
        self.append_audit_locked(event)?;
        self.mutate::<ControlPlaneGrant, _>(&self.grants_file(), |items| {
            if let Some(existing) = items.iter_mut().find(|g| g.grant_id == grant.grant_id) {
                *existing = grant.clone();
            } else {
                items.push(grant.clone());
            }
        })
    }

    fn commit_policy_audited(
        &self,
        policy: ControlPlanePolicy,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<()> {
        let _lock = ExclusiveFileLock::acquire(&self.dir.join(".audit.lock"))?;
        self.append_audit_locked(event)?;
        self.mutate::<ControlPlanePolicy, _>(&self.policies_file(), |items| {
            if let Some(existing) = items.iter_mut().find(|p| p.policy_id == policy.policy_id) {
                *existing = policy.clone();
            } else {
                items.push(policy.clone());
            }
        })
    }

    fn set_grant_status_audited(
        &self,
        grant_id: &str,
        status: ControlPlaneGrantStatus,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<bool> {
        let _lock = ExclusiveFileLock::acquire(&self.dir.join(".audit.lock"))?;
        // Existence check under the lock, so a missing target 404s without
        // writing a spurious audit record.
        if !Self::load::<ControlPlaneGrant>(&self.grants_file())?
            .items
            .iter()
            .any(|g| g.grant_id == grant_id)
        {
            return Ok(false);
        }
        self.append_audit_locked(event)?;
        // Re-read + mutate ONLY the status field on the current row, so a
        // concurrent edit to other fields is preserved (no stale-clone stomp).
        let mut applied = false;
        self.mutate::<ControlPlaneGrant, _>(&self.grants_file(), |items| {
            if let Some(g) = items.iter_mut().find(|g| g.grant_id == grant_id) {
                g.status = status;
                applied = true;
            }
        })?;
        Ok(applied)
    }

    fn set_policy_enforced_audited(
        &self,
        policy_id: &str,
        enforced: bool,
        event: &ControlPlaneAuditEvent,
    ) -> StoreResult<bool> {
        let _lock = ExclusiveFileLock::acquire(&self.dir.join(".audit.lock"))?;
        if !Self::load::<ControlPlanePolicy>(&self.policies_file())?
            .items
            .iter()
            .any(|p| p.policy_id == policy_id)
        {
            return Ok(false);
        }
        self.append_audit_locked(event)?;
        let mut applied = false;
        self.mutate::<ControlPlanePolicy, _>(&self.policies_file(), |items| {
            if let Some(p) = items.iter_mut().find(|p| p.policy_id == policy_id) {
                p.enforced = enforced;
                applied = true;
            }
        })?;
        Ok(applied)
    }

    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<AuditPage> {
        filter.validate()?;
        let path = self.audit.path();
        let file_len = match std::fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        // The cursor is an exclusive upper-bound byte offset: everything below it
        // is still unread. Read one tail window ending there, capped so a single
        // call never reads more than MAX_AUDIT_SCAN_BYTES no matter how long the
        // log is.
        let end = filter
            .cursor
            .map_or(file_len, |AuditCursor(b)| b)
            .min(file_len);
        let window_len = end.min(MAX_AUDIT_SCAN_BYTES);
        let window_start = end - window_len;
        let window = read_window(&path, window_start, window_len)?;

        // A window that starts mid-line drops that partial head; the line it
        // belongs to is read by the page that covers the bytes below.
        let (body_offset, body) = if window_start == 0 {
            (0, &window[..])
        } else {
            match window.iter().position(|b| *b == b'\n') {
                Some(nl) => (nl + 1, &window[nl + 1..]),
                None => (window.len(), &window[window.len()..]),
            }
        };
        // No complete line in a full window means one audit line is longer than
        // the whole scan window, so no page could ever read it. Fail closed
        // rather than hand back a cursor that never advances.
        if window_start > 0 && body.is_empty() {
            return Err(StoreError::Corrupt(format!(
                "audit line ending before byte {end} exceeds the {MAX_AUDIT_SCAN_BYTES}-byte scan window"
            )));
        }
        let body_start = window_start + u64::try_from(body_offset).unwrap_or(u64::MAX);

        let scan = scan_audit(reverse_audit_lines(body, body_start), filter)?;
        Ok(AuditPage {
            events: scan.events,
            // Exhausting the window still leaves every byte below it unread.
            next_cursor: audit_cursor(scan.stopped_at.unwrap_or(body_start)),
            records_examined: scan.records_examined,
            bytes_examined: window_len,
        })
    }
}

// ── Bounded reverse audit-log scan ──────────────────────────────────────────────

/// Read `len` bytes starting at `start`. A log file that was never created reads
/// as empty, matching an audit view with no events yet.
fn read_window(path: &Path, start: u64, len: u64) -> StoreResult<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    if len == 0 {
        return Ok(Vec::new());
    }
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    file.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Yield the control-plane audit records in `body` newest-first, each paired with
/// the absolute byte offset of its line. `body` must begin on a line boundary at
/// `body_start`.
///
/// A line tagged as a control-plane audit event MUST reconstruct; a malformed one
/// fails closed rather than silently vanishing from the view. Lines of any other
/// kind share the log but are not ours, and are skipped.
fn reverse_audit_lines(
    body: &[u8],
    body_start: u64,
) -> impl Iterator<Item = StoreResult<(u64, ControlPlaneAuditEvent)>> + '_ {
    let mut lines = Vec::new();
    let mut offset = 0usize;
    for line in body.split(|b| *b == b'\n') {
        lines.push((body_start + u64::try_from(offset).unwrap_or(u64::MAX), line));
        offset += line.len() + 1;
    }
    lines.into_iter().rev().filter_map(|(at, raw)| {
        let trimmed = raw.trim_ascii();
        if trimmed.is_empty() {
            return None;
        }
        let entry: serde_json::Value = match serde_json::from_slice(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return Some(Err(StoreError::Corrupt(format!(
                    "audit line at byte {at}: {e}"
                ))));
            }
        };
        if entry.get("kind").and_then(serde_json::Value::as_str) != Some(AUDIT_KIND) {
            return None;
        }
        Some(
            audit_event_from_entry(&entry)
                .map(|event| (at, event))
                .ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "audit line at byte {at}: malformed control-plane audit entry"
                    ))
                }),
        )
    })
}

// ── Atomic whole-file write ─────────────────────────────────────────────────────

/// Write `bytes` to `target` atomically: temp file in the same dir → `fsync` →
/// `rename` → dir `fsync`. A crash at any phase leaves either the complete old
/// file or the complete new file. `fault` injects an early return for the
/// phase-fault crash-safety test.
fn write_atomic(target: &Path, bytes: &[u8], fault: FaultPoint) -> std::io::Result<()> {
    use std::io::Write;

    let dir = target.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "target has no parent dir")
    })?;
    #[cfg(not(unix))]
    let _ = dir; // dir is only used for the unix directory fsync below
    // ponytail: fixed temp name per collection. A temp orphaned by a crash is
    // ignored by the loader (it reads only the real file) and overwritten by
    // the next write.
    let tmp = target.with_extension("json.tmp");

    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        set_owner_only(&mut opts);
        let mut f = opts.open(&tmp)?;
        // `mode` on OpenOptions only applies when creating; a stale temp keeps
        // its old mode and would survive the rename. Force 0600 explicitly so
        // the final collection is always owner-only.
        force_owner_only(&f)?;
        f.write_all(bytes)?;
        if fault == FaultPoint::AfterTempWrite {
            return Err(injected_fault());
        }
        f.sync_all()?;
        if fault == FaultPoint::AfterTempFsync {
            return Err(injected_fault());
        }
    }

    std::fs::rename(&tmp, target)?;
    if fault == FaultPoint::AfterRename {
        return Err(injected_fault());
    }

    // Directory fsync makes the rename durable across power loss. Unix only:
    // opening a directory as a file is not portable (Windows rejects it), and
    // the file backend's durability target is Linux. The rename itself is still
    // atomic elsewhere.
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    if fault == FaultPoint::AfterDirFsync {
        return Err(injected_fault());
    }

    Ok(())
}

fn injected_fault() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Interrupted,
        "injected write-phase fault",
    )
}

/// Restrict a new file to owner read/write (`0600`) on unix.
#[cfg(unix)]
fn set_owner_only(opts: &mut std::fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}

/// No-op on non-unix: file permissions are managed by the platform ACLs.
#[cfg(not(unix))]
fn set_owner_only(_opts: &mut std::fs::OpenOptions) {}

/// Force an already-open file to owner-only (`0600`) on unix, regardless of the
/// mode it was created with (handles a pre-existing temp file).
#[cfg(unix)]
fn force_owner_only(f: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
}

/// No-op on non-unix.
#[cfg(not(unix))]
fn force_owner_only(_f: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

// ── OS advisory file lock ────────────────────────────────────────────────────────
//
// `ExclusiveFileLock` moved to `crate::fs_lock` (2026-07-07, MIK-6750 r7) so the
// oauth client_id self-heal path can share the same flock primitive instead of
// duplicating it. See `crate::fs_lock` for the implementation.

// ── Tests ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::ControlPlaneGrantStatus;
    use crate::security::TransparencyLogConfig;

    fn grant(id: &str, status: ControlPlaneGrantStatus) -> ControlPlaneGrant {
        ControlPlaneGrant {
            grant_id: id.to_string(),
            subject_id: "user-1".to_string(),
            server_id: "srv-1".to_string(),
            tool_id: None,
            status,
        }
    }

    fn policy(id: &str, enforced: bool) -> ControlPlanePolicy {
        ControlPlanePolicy {
            policy_id: id.to_string(),
            name: format!("policy {id}"),
            enforced,
        }
    }

    fn audit_event(
        event_id: &str,
        actor: &str,
        action: ControlPlaneAction,
    ) -> ControlPlaneAuditEvent {
        ControlPlaneAuditEvent {
            event_id: event_id.to_string(),
            actor_id: actor.to_string(),
            action,
            target_id: "target-1".to_string(),
            reason: "ticket MIK-1".to_string(),
            rollback: ControlPlaneRollbackPlan {
                summary: "revert".to_string(),
                step: "helm rollback".to_string(),
            },
        }
    }

    fn governance_logger(dir: &Path) -> Arc<TransparencyLogger> {
        let cfg = Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir.join("audit.jsonl").to_string_lossy().to_string(),
            key_id: "gov".to_string(),
            shared_secret: "governance-secret-at-least-32-bytes-long!".to_string(),
        });
        Arc::new(TransparencyLogger::open(cfg).expect("open governance log"))
    }

    fn file_store(dir: &Path) -> FileControlPlaneStore {
        FileControlPlaneStore::open(dir.join("store"), governance_logger(dir)).expect("open store")
    }

    // MIK-6685.STORE.1 — shared conformance suite over both impls.
    fn conformance(store: &dyn ControlPlaneStore) {
        assert!(store.list_grants().unwrap().is_empty());
        store
            .put_grant(grant("g1", ControlPlaneGrantStatus::Requested))
            .unwrap();
        store
            .put_grant(grant("g2", ControlPlaneGrantStatus::Approved))
            .unwrap();
        assert_eq!(store.list_grants().unwrap().len(), 2);
        assert_eq!(
            store.get_grant("g1").unwrap().unwrap().status,
            ControlPlaneGrantStatus::Requested
        );
        // Upsert replaces, does not duplicate.
        store
            .put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
            .unwrap();
        assert_eq!(store.list_grants().unwrap().len(), 2);
        assert_eq!(
            store.get_grant("g1").unwrap().unwrap().status,
            ControlPlaneGrantStatus::Approved
        );
        store.delete_grant("g1").unwrap();
        assert!(store.get_grant("g1").unwrap().is_none());
        store.delete_grant("does-not-exist").unwrap(); // no-op

        store.put_policy(policy("p1", false)).unwrap();
        store.put_policy(policy("p1", true)).unwrap();
        assert_eq!(store.list_policies().unwrap().len(), 1);
        assert!(store.get_policy("p1").unwrap().unwrap().enforced);
        store.delete_policy("p1").unwrap();
        assert!(store.list_policies().unwrap().is_empty());

        store
            .append_audit(&audit_event("a1", "alice", ControlPlaneAction::MutateGrant))
            .unwrap();
        store
            .append_audit(&audit_event("a2", "bob", ControlPlaneAction::MutatePolicy))
            .unwrap();
        let all = store.read_audit(&AuditFilter::new(10)).unwrap();
        assert_eq!(
            all.events
                .iter()
                .map(|e| e.event_id.as_str())
                .collect::<Vec<_>>(),
            ["a2", "a1"],
            "audit reads newest first"
        );
        assert!(
            all.next_cursor.is_none(),
            "a scan that reached the start of the log is final"
        );
    }

    #[test]
    fn in_memory_passes_conformance() {
        conformance(&InMemoryControlPlaneStore::new());
    }

    #[test]
    fn file_backend_passes_conformance() {
        let dir = tempfile::tempdir().unwrap();
        conformance(&file_store(dir.path()));
    }

    // MIK-6685.STORE.1 — durability across "restart" (reopen the same dir).
    #[test]
    fn file_backend_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = file_store(dir.path());
            s.put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
                .unwrap();
        }
        let s2 = file_store(dir.path());
        assert_eq!(
            s2.get_grant("g1").unwrap().unwrap().status,
            ControlPlaneGrantStatus::Approved
        );
    }

    // MIK-6710.AUDIT.1 — a bounded newest-first read: paging with a cursor over a
    // log far larger than one page reproduces a full-scan oracle exactly, for
    // filters that match everything, some events and nothing; every call examines
    // at most the scan budget; and no filtered result is silently dropped.
    //
    // Both backends run this one suite, so the file and in-memory paths cannot
    // drift apart on order, filter semantics or cursor behaviour.
    fn bounded_audit_conformance(store: &dyn ControlPlaneStore) {
        // The oracle: what a full scan in chain order would have contained.
        let oracle: Vec<ControlPlaneAuditEvent> = (0..200)
            .map(|i| {
                let actor = match i {
                    137 => "rare",
                    _ if i % 2 == 0 => "alice",
                    _ => "bob",
                };
                let action = if i % 3 == 0 {
                    ControlPlaneAction::MutatePolicy
                } else {
                    ControlPlaneAction::MutateGrant
                };
                audit_event(&format!("a{i:04}"), actor, action)
            })
            .collect();
        for event in &oracle {
            store.append_audit(event).unwrap();
        }

        let cases: Vec<(Option<&str>, Option<ControlPlaneAction>)> = vec![
            (None, None),
            (Some("bob"), None),
            (None, Some(ControlPlaneAction::MutatePolicy)),
            (Some("bob"), Some(ControlPlaneAction::MutatePolicy)),
            (Some("rare"), None),
            (Some("nobody-did-this"), None),
        ];
        for (actor, action) in cases {
            let label = format!("actor={actor:?} action={action:?}");
            let base = AuditFilter {
                limit: 7,
                scan_budget: 13,
                cursor: None,
                actor_id: actor.map(str::to_string),
                action,
            };

            let mut seen: Vec<String> = Vec::new();
            let mut filter = base.clone();
            let mut calls = 0;
            loop {
                let page = store.read_audit(&filter).unwrap();
                calls += 1;
                assert!(calls < 1000, "{label}: pagination must terminate");
                assert!(
                    page.records_examined <= base.scan_budget,
                    "{label}: examined {} records, budget {}",
                    page.records_examined,
                    base.scan_budget
                );
                assert!(
                    page.bytes_examined <= MAX_AUDIT_SCAN_BYTES,
                    "{label}: read {} bytes, cap {MAX_AUDIT_SCAN_BYTES}",
                    page.bytes_examined
                );
                assert!(
                    page.events.len() <= base.limit,
                    "{label}: page overran limit"
                );
                seen.extend(page.events.iter().map(|e| e.event_id.clone()));
                match page.next_cursor {
                    // A bounded page that stops early MUST hand back a cursor, or
                    // the missing events are silently truncated.
                    Some(cursor) => filter = base.resume(cursor),
                    None => break,
                }
            }

            let expected: Vec<String> = oracle
                .iter()
                .filter(|e| {
                    actor.is_none_or(|a| a == e.actor_id) && action.is_none_or(|a| a == e.action)
                })
                .rev()
                .map(|e| e.event_id.clone())
                .collect();
            assert_eq!(seen, expected, "{label}: paged read must equal the oracle");
        }
    }

    // MIK-6710.AUDIT.1 — both backends satisfy the bounded-read contract.
    #[test]
    fn in_memory_audit_read_is_bounded_and_ordered() {
        bounded_audit_conformance(&InMemoryControlPlaneStore::new());
    }

    // MIK-6710.AUDIT.1 — both backends satisfy the bounded-read contract.
    #[test]
    fn file_audit_read_is_bounded_and_ordered() {
        let dir = tempfile::tempdir().unwrap();
        bounded_audit_conformance(&file_store(dir.path()));
    }

    // MIK-6710.AUDIT.1 — on a log larger than the scan window, one call reads a
    // bounded tail rather than the whole file, and still returns the newest
    // events. The positive control is the byte count: it must be below the file
    // size, which is what the previous whole-file read could never satisfy.
    #[test]
    fn file_audit_read_caps_bytes_on_a_log_larger_than_the_window() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let logger = governance_logger(dir.path());
        let store =
            FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
        store
            .append_audit(&audit_event(
                "seed",
                "alice",
                ControlPlaneAction::MutateGrant,
            ))
            .unwrap();

        // Grow the log past MAX_AUDIT_SCAN_BYTES by replaying the seed line with
        // fresh ids. Only parsing and ordering are under test here, so the
        // replayed lines need not extend the hash chain.
        let seed = std::fs::read_to_string(logger.path()).unwrap();
        let template = seed.lines().next_back().unwrap().to_string();
        let mut blob = String::new();
        let mut written = 0u64;
        let mut i = 0;
        while written <= MAX_AUDIT_SCAN_BYTES + (64 * 1024) {
            let line = template.replace("\"seed\"", &format!("\"bulk-{i:06}\""));
            written += u64::try_from(line.len()).unwrap_or(u64::MAX) + 1;
            blob.push_str(&line);
            blob.push('\n');
            i += 1;
        }
        let newest = format!("bulk-{:06}", i - 1);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(logger.path())
            .unwrap();
        f.write_all(blob.as_bytes()).unwrap();
        drop(f);

        let file_len = std::fs::metadata(logger.path()).unwrap().len();
        assert!(
            file_len > MAX_AUDIT_SCAN_BYTES,
            "log must exceed the window"
        );
        let page = store.read_audit(&AuditFilter::new(5)).unwrap();
        assert_eq!(page.events.len(), 5);
        assert_eq!(page.events[0].event_id, newest, "newest event comes first");
        assert!(
            page.bytes_examined <= MAX_AUDIT_SCAN_BYTES && page.bytes_examined < file_len,
            "one call read {} of {file_len} bytes",
            page.bytes_examined
        );
        assert!(
            page.next_cursor.is_some(),
            "unread bytes remain, so the page must be continuable"
        );

        // Page the whole log. The second window ends where the first one began,
        // so the line straddling that boundary is the one an off-by-one in the
        // cursor handoff would drop or return twice.
        let mut ids: Vec<String> = Vec::new();
        let mut cursor = None;
        let mut calls = 0;
        loop {
            let filter = match cursor {
                Some(at) => AuditFilter::new(10_000).resume(at),
                None => AuditFilter::new(10_000),
            };
            let page = store.read_audit(&filter).unwrap();
            assert!(
                page.bytes_examined <= MAX_AUDIT_SCAN_BYTES,
                "page {calls} read {} bytes",
                page.bytes_examined
            );
            ids.extend(page.events.iter().map(|event| event.event_id.clone()));
            calls += 1;
            assert!(calls < 100, "paging the log did not terminate");
            match page.next_cursor {
                Some(at) => cursor = Some(at),
                None => break,
            }
        }
        assert!(calls > 1, "the log must span more than one window");
        let expected: Vec<String> = (0..i)
            .rev()
            .map(|n| format!("bulk-{n:06}"))
            .chain(std::iter::once("seed".to_string()))
            .collect();
        assert_eq!(
            ids.len(),
            expected.len(),
            "every line must be returned exactly once across pages"
        );
        if let Some(pos) = ids
            .iter()
            .zip(&expected)
            .position(|(got, want)| got != want)
        {
            panic!(
                "page handoff diverged at index {pos}: got {}, want {}",
                ids[pos], expected[pos]
            );
        }
    }

    // MIK-6710.AUDIT.1 — a single line longer than the whole scan window can
    // never be read by any page, so it fails closed instead of returning a cursor
    // that never advances.
    #[test]
    fn file_audit_read_fails_closed_on_a_line_longer_than_the_window() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let logger = governance_logger(dir.path());
        let store =
            FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
        store
            .append_audit(&audit_event("ok", "alice", ControlPlaneAction::MutateGrant))
            .unwrap();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(logger.path())
            .unwrap();
        let giant = "x".repeat(usize::try_from(MAX_AUDIT_SCAN_BYTES).unwrap() + 4096);
        writeln!(f, "{giant}").unwrap();
        drop(f);

        assert!(matches!(
            store.read_audit(&AuditFilter::new(10)),
            Err(StoreError::Corrupt(_))
        ));
    }

    // MIK-6710.AUDIT.1 — an oversized or zero scan budget is an invalid filter,
    // so a caller cannot opt out of the work bound.
    #[test]
    fn invalid_scan_budget_errors() {
        let store = InMemoryControlPlaneStore::new();
        let bad = |budget| AuditFilter {
            scan_budget: budget,
            ..AuditFilter::new(10)
        };
        assert!(matches!(
            store.read_audit(&bad(0)),
            Err(StoreError::InvalidFilter(_))
        ));
        assert!(matches!(
            store.read_audit(&bad(MAX_AUDIT_SCAN_RECORDS + 1)),
            Err(StoreError::InvalidFilter(_))
        ));
    }

    // MIK-6685.STORE.6 — an invalid filter errors, never silently returns all.
    #[test]
    fn invalid_filter_errors() {
        let store = InMemoryControlPlaneStore::new();
        store
            .append_audit(&audit_event("a0", "alice", ControlPlaneAction::MutateGrant))
            .unwrap();
        assert!(matches!(
            store.read_audit(&AuditFilter::new(0)),
            Err(StoreError::InvalidFilter(_))
        ));
        assert!(matches!(
            store.read_audit(&AuditFilter::new(MAX_AUDIT_LIMIT + 1)),
            Err(StoreError::InvalidFilter(_))
        ));
    }

    // MIK-6685.STORE.4 — audit view fed by a governance TransparencyLogger that
    // passes verify_log.
    #[test]
    fn audit_backed_by_verifiable_transparency_log() {
        let dir = tempfile::tempdir().unwrap();
        let logger = governance_logger(dir.path());
        let store =
            FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
        store
            .append_audit(&audit_event(
                "gov1",
                "alice",
                ControlPlaneAction::MutateGrant,
            ))
            .unwrap();
        store
            .append_audit(&audit_event(
                "gov2",
                "bob",
                ControlPlaneAction::ApproveServer,
            ))
            .unwrap();

        let view = store.read_audit(&AuditFilter::new(10)).unwrap().events;
        assert_eq!(view.len(), 2);
        assert_eq!(view[0].event_id, "gov2", "newest first");
        assert_eq!(view[1].action, ControlPlaneAction::MutateGrant);

        let result = crate::security::transparency_log::verify_log(&logger.path()).unwrap();
        assert!(
            result.ok,
            "governance chain must verify: {:?}",
            result.error_message
        );
        assert_eq!(result.entries_checked, 2);
    }

    // MIK-6685.STORE.6 — collection files are 0600.
    #[cfg(unix)]
    #[test]
    fn collection_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        store
            .put_grant(grant("g1", ControlPlaneGrantStatus::Requested))
            .unwrap();
        let mode = std::fs::metadata(dir.path().join("store/grants.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "grants collection must be 0600");
    }

    // MIK-6685.STORE.5 — malformed collection JSON fails closed; a write never
    // truncates good data.
    #[test]
    fn corrupt_collection_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        store
            .put_grant(grant("g1", ControlPlaneGrantStatus::Approved))
            .unwrap();

        let grants_path = dir.path().join("store/grants.json");
        let good = std::fs::read(&grants_path).unwrap();
        std::fs::write(&grants_path, b"{ this is not valid json").unwrap();

        assert!(matches!(store.list_grants(), Err(StoreError::Corrupt(_))));
        // A write also fails closed and does NOT overwrite the corrupt-but-present collection.
        assert!(
            store
                .put_grant(grant("g2", ControlPlaneGrantStatus::Requested))
                .is_err()
        );

        std::fs::write(&grants_path, &good).unwrap();
        assert_eq!(
            store.get_grant("g1").unwrap().unwrap().status,
            ControlPlaneGrantStatus::Approved
        );
    }

    // MIK-6685.STORE.3 — cross-process (two handles) stale writer is rejected;
    // the optimistic put loop then does not lose updates.
    #[test]
    fn stale_generation_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let logger = governance_logger(dir.path());
        let store_dir = dir.path().join("store");
        let a = FileControlPlaneStore::open(store_dir.clone(), Arc::clone(&logger)).unwrap();
        let b = FileControlPlaneStore::open(store_dir.clone(), Arc::clone(&logger)).unwrap();
        let grants_path = a.grants_file();

        let gen_a = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path)
            .unwrap()
            .generation;
        let gen_b = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path)
            .unwrap()
            .generation;
        assert_eq!(gen_a, 0);
        assert_eq!(gen_b, 0);

        let items_a = vec![grant("ga", ControlPlaneGrantStatus::Approved)];
        assert_eq!(
            a.store_cas(&grants_path, &items_a, gen_a, FaultPoint::None)
                .unwrap(),
            1
        );

        let items_b = vec![grant("gb", ControlPlaneGrantStatus::Approved)];
        assert!(matches!(
            b.store_cas(&grants_path, &items_b, gen_b, FaultPoint::None),
            Err(StoreError::StaleGeneration {
                expected: 0,
                actual: 1
            })
        ));

        // The optimistic put loop re-reads and does not lose A's update.
        b.put_grant(grant("gb", ControlPlaneGrantStatus::Approved))
            .unwrap();
        let ids: Vec<_> = a
            .list_grants()
            .unwrap()
            .into_iter()
            .map(|g| g.grant_id)
            .collect();
        assert!(
            ids.contains(&"ga".to_string()) && ids.contains(&"gb".to_string()),
            "no lost update: {ids:?}"
        );
    }

    // MIK-6685.STORE.2 — phase-fault injection: a crash at any write phase leaves
    // either the complete old collection or the complete new one, never a torn one.
    #[test]
    fn write_phase_faults_never_tear_the_collection() {
        for fault in [
            FaultPoint::AfterTempWrite,
            FaultPoint::AfterTempFsync,
            FaultPoint::AfterRename,
            FaultPoint::AfterDirFsync,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let store = file_store(dir.path());
            let grants_path = store.grants_file();

            store
                .put_grant(grant("old", ControlPlaneGrantStatus::Approved))
                .unwrap();
            let old = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path).unwrap();
            assert_eq!(old.generation, 1);

            let new_items = vec![grant("new", ControlPlaneGrantStatus::Requested)];
            let _ = store.store_cas(&grants_path, &new_items, old.generation, fault);

            let recovered = FileControlPlaneStore::load::<ControlPlaneGrant>(&grants_path)
                .unwrap_or_else(|e| panic!("torn collection after {fault:?}: {e}"));
            let ids: Vec<_> = recovered
                .items
                .iter()
                .map(|g| g.grant_id.as_str())
                .collect();
            assert!(
                ids == ["old"] || ids == ["new"],
                "after {fault:?}: expected complete old or new, got {ids:?}"
            );
        }
    }

    // MIK-6685.STORE.4 — cross-process audit append stays verifiable. Two
    // loggers over the same log file (separate "processes") append via the
    // synced path; the chain must not fork and must pass verify_log.
    #[test]
    fn cross_process_audit_append_stays_verifiable() {
        let dir = tempfile::tempdir().unwrap();
        let logger_a = governance_logger(dir.path());
        let logger_b = governance_logger(dir.path()); // second handle, same file
        let store_dir = dir.path().join("store");
        let a = FileControlPlaneStore::open(store_dir.clone(), Arc::clone(&logger_a)).unwrap();
        let b = FileControlPlaneStore::open(store_dir, Arc::clone(&logger_b)).unwrap();

        // Interleave appends across the two handles.
        a.append_audit(&audit_event("e1", "alice", ControlPlaneAction::MutateGrant))
            .unwrap();
        b.append_audit(&audit_event("e2", "bob", ControlPlaneAction::MutatePolicy))
            .unwrap();
        a.append_audit(&audit_event(
            "e3",
            "carol",
            ControlPlaneAction::ApproveServer,
        ))
        .unwrap();

        let view = a.read_audit(&AuditFilter::new(10)).unwrap();
        assert_eq!(
            view.events
                .iter()
                .map(|e| e.event_id.as_str())
                .collect::<Vec<_>>(),
            ["e3", "e2", "e1"]
        );
        let result = crate::security::transparency_log::verify_log(&logger_a.path()).unwrap();
        assert!(
            result.ok,
            "chain must not fork across processes: {:?}",
            result.error_message
        );
        assert_eq!(result.entries_checked, 3);
    }

    // MIK-6685.STORE.6 — a malformed control-plane audit line fails closed
    // (errors) rather than silently vanishing from the view.
    #[test]
    fn malformed_audit_entry_fails_closed() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let logger = governance_logger(dir.path());
        let store =
            FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();
        store
            .append_audit(&audit_event(
                "ok1",
                "alice",
                ControlPlaneAction::MutateGrant,
            ))
            .unwrap();

        // Append a line tagged as a control-plane audit event but missing fields.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(logger.path())
            .unwrap();
        writeln!(f, r#"{{"kind":"control_plane_audit","event_id":"broken"}}"#).unwrap();
        drop(f);

        assert!(matches!(
            store.read_audit(&AuditFilter::new(10)),
            Err(StoreError::Corrupt(_))
        ));
    }

    // MIK-6686.CP.2 — the audited commit persists the grant AND appends a
    // verifiable audit entry as one unit, under a single lock.
    #[test]
    fn audited_commit_persists_grant_and_appends_verifiable_audit() {
        let dir = tempfile::tempdir().unwrap();
        let logger = governance_logger(dir.path());
        let store =
            FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();

        let g = grant("g1", ControlPlaneGrantStatus::Approved);
        let event = audit_event("e1", "alice", ControlPlaneAction::MutateGrant);
        store.commit_grant_audited(g, &event).unwrap();

        assert_eq!(store.list_grants().unwrap().len(), 1);
        let audit = store.read_audit(&AuditFilter::new(10)).unwrap();
        assert_eq!(audit.events.len(), 1);
        assert_eq!(audit.events[0].event_id, "e1");
        let result = crate::security::transparency_log::verify_log(&logger.path()).unwrap();
        assert!(
            result.ok,
            "audit chain must verify: {:?}",
            result.error_message
        );
    }

    // MIK-6687.CP.3 — set_grant_status_audited flips ONLY the status and
    // preserves other fields (no stale-clone lost update), audits the change,
    // and returns false (no audit) for a missing target.
    #[test]
    fn set_grant_status_audited_is_field_only_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let logger = governance_logger(dir.path());
        let store =
            FileControlPlaneStore::open(dir.path().join("store"), Arc::clone(&logger)).unwrap();

        // Seed g1, then a concurrent edit changes a NON-status field.
        store
            .put_grant(grant("g1", ControlPlaneGrantStatus::Requested))
            .unwrap();
        let mut edited = grant("g1", ControlPlaneGrantStatus::Requested);
        edited.subject_id = "user-CHANGED".to_string();
        store.put_grant(edited).unwrap();

        // A decision flips status; the concurrent field edit must survive.
        let ev = audit_event("d1", "alice", ControlPlaneAction::MutateGrant);
        assert!(
            store
                .set_grant_status_audited("g1", ControlPlaneGrantStatus::Approved, &ev)
                .unwrap()
        );
        let g = store.get_grant("g1").unwrap().unwrap();
        assert_eq!(g.status, ControlPlaneGrantStatus::Approved);
        assert_eq!(
            g.subject_id, "user-CHANGED",
            "non-status field must be preserved"
        );
        assert_eq!(
            store
                .read_audit(&AuditFilter::new(10))
                .unwrap()
                .events
                .len(),
            1
        );

        // Missing target -> false, and NO extra audit entry is written.
        assert!(
            !store
                .set_grant_status_audited("absent", ControlPlaneGrantStatus::Revoked, &ev)
                .unwrap()
        );
        assert_eq!(
            store
                .read_audit(&AuditFilter::new(10))
                .unwrap()
                .events
                .len(),
            1
        );
    }
}
