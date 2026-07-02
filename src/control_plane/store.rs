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
use crate::security::TransparencyLogger;

/// On-disk schema version for a persisted collection.
const COLLECTION_SCHEMA_VERSION: u32 = 1;

/// Marker written on every governance audit entry so the reader can tell
/// control-plane events apart from any other entries sharing the log.
const AUDIT_KIND: &str = "control_plane_audit";

/// Upper bound on a single [`AuditFilter`] page, so a caller cannot ask for an
/// unbounded read.
const MAX_AUDIT_LIMIT: usize = 10_000;

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

/// Filter for [`ControlPlaneStore::read_audit`].
///
/// `limit` is required and must be in `1..=MAX_AUDIT_LIMIT`; a zero or oversized
/// limit is an invalid filter (it must error, never silently return all).
#[derive(Debug, Clone)]
pub struct AuditFilter {
    /// Maximum number of events to return (`1..=10_000`).
    pub limit: usize,
    /// Number of leading (oldest, chain-order) events to skip.
    pub offset: usize,
    /// Restrict to a single actor id when set.
    pub actor_id: Option<String>,
    /// Restrict to a single action when set.
    pub action: Option<ControlPlaneAction>,
}

impl AuditFilter {
    /// A filter that returns the first `limit` events in chain order.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            offset: 0,
            actor_id: None,
            action: None,
        }
    }

    /// Validate the filter, returning [`StoreError::InvalidFilter`] when unusable.
    ///
    /// # Errors
    ///
    /// Errors when `limit` is `0` or greater than [`MAX_AUDIT_LIMIT`].
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
    /// Read audit events in chain order, honouring the filter's limit/offset.
    ///
    /// # Errors
    /// Errors on an invalid filter, an I/O failure, a corrupt log line.
    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<Vec<ControlPlaneAuditEvent>>;

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

/// Apply a filter's predicates then its offset/limit page to chain-ordered events.
fn page_audit(
    events: impl Iterator<Item = ControlPlaneAuditEvent>,
    filter: &AuditFilter,
) -> Vec<ControlPlaneAuditEvent> {
    events
        .filter(|e| filter.matches(e))
        .skip(filter.offset)
        .take(filter.limit)
        .collect()
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

    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<Vec<ControlPlaneAuditEvent>> {
        filter.validate()?;
        let audit = Self::lock(&self.audit)?;
        Ok(page_audit(audit.iter().cloned(), filter))
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

    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<Vec<ControlPlaneAuditEvent>> {
        filter.validate()?;
        let path = self.audit.path();
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e.into()),
        };
        let mut events = Vec::new();
        for (line_no, raw) in content.lines().enumerate() {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let entry: serde_json::Value = serde_json::from_str(trimmed)
                .map_err(|e| StoreError::Corrupt(format!("audit line {}: {e}", line_no + 1)))?;
            // A line tagged as a control-plane audit event MUST reconstruct; a
            // malformed one fails closed rather than silently vanishing from the
            // view. Lines of any other kind are not ours and are skipped.
            if entry.get("kind").and_then(serde_json::Value::as_str) == Some(AUDIT_KIND) {
                let event = audit_event_from_entry(&entry).ok_or_else(|| {
                    StoreError::Corrupt(format!(
                        "audit line {}: malformed control-plane audit entry",
                        line_no + 1
                    ))
                })?;
                events.push(event);
            }
        }
        Ok(page_audit(events.into_iter(), filter))
    }
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

/// An exclusive advisory lock on a dedicated lock file, released on drop.
///
/// On unix this is a real `flock`; the lock file's fd holds the lock across the
/// collection file's atomic rename. On non-unix it degrades to opening the file
/// with no advisory lock.
struct ExclusiveFileLock {
    _file: std::fs::File,
}

impl ExclusiveFileLock {
    fn acquire(lock_path: &Path) -> std::io::Result<Self> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).read(true);
        set_owner_only(&mut opts);
        let file = opts.open(lock_path)?;
        lock_exclusive(&file)?;
        Ok(Self { _file: file })
    }
}

/// Take an exclusive `flock` on unix. `rustix` is an already-present dependency
/// (promoted to direct with the `fs` feature); no new crate is compiled.
#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> std::io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
}

/// ponytail: cross-process advisory locking on non-unix is out of scope for the
/// single-node file backend. Atomic rename still prevents torn files, and the
/// generation compare-and-swap still rejects an in-process lost update. Upgrade
/// to `LockFileEx` if a Windows multi-process deployment ever needs it.
#[cfg(not(unix))]
fn lock_exclusive(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

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
            all.iter().map(|e| e.event_id.as_str()).collect::<Vec<_>>(),
            ["a1", "a2"]
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

    // MIK-6685.STORE.6 — read_audit chain order + limit/offset + filters.
    #[test]
    fn read_audit_honors_offset_limit_and_filters() {
        let store = InMemoryControlPlaneStore::new();
        for i in 0..5 {
            let actor = if i % 2 == 0 { "alice" } else { "bob" };
            store
                .append_audit(&audit_event(
                    &format!("a{i}"),
                    actor,
                    ControlPlaneAction::MutateGrant,
                ))
                .unwrap();
        }
        let page = store
            .read_audit(&AuditFilter {
                limit: 2,
                offset: 1,
                actor_id: None,
                action: None,
            })
            .unwrap();
        assert_eq!(
            page.iter().map(|e| e.event_id.as_str()).collect::<Vec<_>>(),
            ["a1", "a2"]
        );
        let f = AuditFilter {
            limit: 10,
            offset: 0,
            actor_id: Some("bob".to_string()),
            action: None,
        };
        let bobs = store.read_audit(&f).unwrap();
        assert_eq!(
            bobs.iter().map(|e| e.event_id.as_str()).collect::<Vec<_>>(),
            ["a1", "a3"]
        );
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

        let view = store.read_audit(&AuditFilter::new(10)).unwrap();
        assert_eq!(view.len(), 2);
        assert_eq!(view[0].event_id, "gov1");
        assert_eq!(view[1].action, ControlPlaneAction::ApproveServer);

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
            view.iter().map(|e| e.event_id.as_str()).collect::<Vec<_>>(),
            ["e1", "e2", "e3"]
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
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].event_id, "e1");
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
        assert_eq!(store.read_audit(&AuditFilter::new(10)).unwrap().len(), 1);

        // Missing target -> false, and NO extra audit entry is written.
        assert!(
            !store
                .set_grant_status_audited("absent", ControlPlaneGrantStatus::Revoked, &ev)
                .unwrap()
        );
        assert_eq!(store.read_audit(&AuditFilter::new(10)).unwrap().len(), 1);
    }
}
