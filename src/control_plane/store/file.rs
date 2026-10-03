// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Atomic-file control-plane store (split from `store.rs`).

use super::{
    AuditCursor, AuditFilter, AuditPage, COLLECTION_SCHEMA_VERSION, ControlPlaneStore, FaultPoint,
    MAX_AUDIT_SCAN_BYTES, StoreError, StoreResult, audit_fields, read_window, reverse_audit_lines,
    scan_audit, write_atomic,
};
use crate::config::CheckedFile;
use crate::control_plane::{
    ControlPlaneAuditEvent, ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlanePolicy,
};
use crate::fs_lock::ExclusiveFileLock;
use crate::security::TransparencyLogger;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A collection serialised whole-file, with a generation for compare-and-swap.
/// Its `schema_version` is read first, by [`CollectionVersion`].
#[derive(serde::Deserialize)]
pub(super) struct VersionedCollection<T> {
    pub(super) generation: u64,
    pub(super) items: Vec<T>,
}

/// Only the format version of a collection file, read before its items: a
/// later format's items need not parse as this build's.
#[derive(serde::Deserialize)]
struct CollectionVersion {
    schema_version: u32,
}

/// Borrowing view used only for serialisation, so a compare-and-swap write need
/// not clone the items or bound `T: Clone`.
#[derive(Serialize)]
struct VersionedCollectionRef<'a, T> {
    schema_version: u32,
    generation: u64,
    items: &'a [T],
}

/// Durable single-node [`ControlPlaneStore`] backed by one JSON file per
/// collection plus a governance-scoped [`TransparencyLogger`] for audit.
pub struct FileControlPlaneStore {
    pub(super) dir: PathBuf,
    pub(super) audit: Arc<TransparencyLogger>,
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

    pub(super) fn grants_file(&self) -> PathBuf {
        self.dir.join("grants.json")
    }

    pub(super) fn policies_file(&self) -> PathBuf {
        self.dir.join("policies.json")
    }

    /// Load a collection, treating a missing file as empty (generation 0) and a
    /// present-but-unparseable file as [`StoreError::Corrupt`] (fail closed).
    pub(super) fn load<T: DeserializeOwned>(file: &Path) -> StoreResult<VersionedCollection<T>> {
        let what = CheckedFile::ControlPlaneCollection; // mode-checked on read (F18 I4)
        match crate::config::read_checked_file(file, what) {
            Ok(text) => {
                let corrupt =
                    |e: serde_json::Error| StoreError::Corrupt(format!("{}: {e}", file.display()));
                // An access-control store fails closed on a version it does not
                // know: read as this one, a newer file's grants and policies
                // would change meaning, and a write would drop fields (#2142).
                let CollectionVersion { schema_version } =
                    serde_json::from_str(&text).map_err(corrupt)?;
                if schema_version != COLLECTION_SCHEMA_VERSION {
                    return Err(StoreError::Corrupt(format!(
                        "{}: schema_version {schema_version} is not supported; this build \
                         supports {COLLECTION_SCHEMA_VERSION}",
                        file.display()
                    )));
                }
                serde_json::from_str(&text).map_err(corrupt)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(VersionedCollection {
                generation: 0,
                items: Vec::new(),
            }),
            Err(e) => Err(e.into()),
        }
    }

    /// Read only the on-disk generation of `file` (0 if missing). Fails closed
    /// on a corrupt file so a compare-and-swap never overwrites good data.
    pub(super) fn disk_generation<T: DeserializeOwned>(file: &Path) -> StoreResult<u64> {
        Ok(Self::load::<T>(file)?.generation)
    }

    /// Compare-and-swap write of a collection under an exclusive OS file lock.
    ///
    /// The lock is held across read-generation → check → write so a concurrent
    /// process cannot interleave. If the on-disk generation no longer equals
    /// `expected_generation`, the write is rejected as stale.
    pub(super) fn store_cas<T: Serialize + DeserializeOwned>(
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

    pub(super) fn lock_path(&self, file: &Path) -> PathBuf {
        // A dedicated lock file that is never renamed, so the held fd's lock
        // survives the collection file's atomic rename.
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("cp");
        self.dir.join(format!(".{name}.lock"))
    }

    /// Optimistic read-modify-write against a collection: load, apply `mutate`,
    /// then compare-and-swap; retry from a fresh read if a stale write loses.
    pub(super) fn mutate<T, F>(&self, file: &Path, mut mutate: F) -> StoreResult<()>
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
    pub(super) fn append_audit_locked(&self, event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        self.audit
            .append_event_synced(
                audit_fields(event),
                &crate::security::audit::AuditEnvelope::governance(&event.actor_id),
            )
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
        let (path, end, segment, cursor_reset) = self.audit_position(filter.cursor)?;
        // The cursor's offset is an exclusive upper bound: everything below it
        // is still unread. Read one tail window ending there, capped so a single
        // call never reads more than MAX_AUDIT_SCAN_BYTES no matter how long the
        // log is.
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
        // Exhausting the window still leaves every byte below it unread; at
        // the start of a segment, the next page is the older segment's end.
        let resume = scan.stopped_at.unwrap_or(body_start);
        let next_cursor = if resume > 0 {
            Some(AuditCursor {
                offset: resume,
                segment,
            })
        } else {
            self.older_segment(segment)?
        };
        Ok(AuditPage {
            events: scan.events,
            next_cursor,
            records_examined: scan.records_examined,
            bytes_examined: window_len,
            cursor_reset,
        })
    }
}

impl FileControlPlaneStore {
    /// Resolve a cursor to `(file, end offset, segment, cursor_reset)`. No
    /// cursor starts at the end of the active file; a segment cursor names
    /// its file by number (a rename never changes a segment's bytes); a
    /// pre-D6 offset-only cursor is honoured only while nothing is sealed.
    pub(super) fn audit_position(
        &self,
        cursor: Option<AuditCursor>,
    ) -> StoreResult<(PathBuf, u64, Option<u64>, bool)> {
        use crate::security::transparency_log::segments::{list_segments, sealed_path};
        let path = self.audit.path();
        let sealed = list_segments(&path)?;
        let active_seq = sealed.last().map_or(0, |s| s.seq + 1);
        let len_of = |p: &Path| match std::fs::metadata(p) {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(StoreError::from(e)),
        };
        let newest = || -> StoreResult<(PathBuf, u64, Option<u64>)> {
            Ok((path.clone(), len_of(&path)?, Some(active_seq)))
        };
        let (file, end, segment, reset) = match cursor {
            None => {
                let (f, e, s) = newest()?;
                (f, e, s, false)
            }
            Some(AuditCursor {
                offset,
                segment: None,
            }) if sealed.is_empty() => (path.clone(), offset.min(len_of(&path)?), Some(0), false),
            Some(AuditCursor { segment: None, .. }) => {
                tracing::warn!(
                    "pre-rotation audit cursor after a rotation: restarting at the newest record"
                );
                let (f, e, s) = newest()?;
                (f, e, s, true)
            }
            Some(AuditCursor {
                offset,
                segment: Some(seq),
            }) => {
                let file = if seq == active_seq {
                    path.clone()
                } else {
                    sealed_path(&path, seq)
                };
                (file.clone(), offset.min(len_of(&file)?), Some(seq), false)
            }
        };
        Ok((file, end, segment, reset))
    }

    /// The cursor for the end of the segment older than `segment`, if any
    /// survives retention.
    pub(super) fn older_segment(&self, segment: Option<u64>) -> StoreResult<Option<AuditCursor>> {
        use crate::security::transparency_log::segments::list_segments;
        let Some(seq) = segment else { return Ok(None) };
        let older = list_segments(&self.audit.path())?
            .into_iter()
            .rev()
            .find(|s| s.seq < seq);
        Ok(match older {
            Some(s) => Some(AuditCursor {
                offset: std::fs::metadata(&s.path)?.len(),
                segment: Some(s.seq),
            }),
            None => None,
        })
    }
}
