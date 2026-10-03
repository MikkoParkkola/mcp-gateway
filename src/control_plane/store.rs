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

#[cfg(test)]
use crate::control_plane::{ControlPlaneAction, ControlPlaneRollbackPlan};
use crate::control_plane::{
    ControlPlaneAuditEvent, ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlanePolicy,
};
#[cfg(any(test, doc))]
use crate::security::TransparencyLogger;
#[cfg(test)]
use std::{path::Path, sync::Arc};

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
    /// A collection file exists but could not be parsed, or holds a schema
    /// version this build does not support. The store fails closed
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

// ── OS advisory file lock ────────────────────────────────────────────────────────
//
// `ExclusiveFileLock` moved to `crate::fs_lock` (2026-07-07, MIK-6750 r7) so the
// oauth client_id self-heal path can share the same flock primitive instead of
// duplicating it. See `crate::fs_lock` for the implementation.

mod audit;
mod file;
mod file_io;
mod memory;

pub use audit::{AuditCursor, AuditFilter, AuditPage};
use audit::{audit_cursor, audit_event_from_entry, audit_fields, scan_audit};
pub use file::FileControlPlaneStore;
use file_io::{FaultPoint, read_window, reverse_audit_lines, write_atomic};
pub use memory::InMemoryControlPlaneStore;

// ── Tests ────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "store_rotation_tests.rs"]
mod rotation_tests;
#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
