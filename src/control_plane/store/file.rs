// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Atomic-file control-plane store (split from `store.rs`).

use super::{
    AuditCursor, AuditFilter, AuditPage, COLLECTION_SCHEMA_VERSION, ControlPlaneStore, FaultPoint,
    MAX_AUDIT_SCAN_BYTES, StoreError, StoreResult, audit_fields, reverse_audit_lines, scan_audit,
    write_atomic,
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
        // Timed like every other record, so Activity can merge config changes
        // with calls; records written before this have no time.
        let mut fields = audit_fields(event);
        crate::clock::stamp_audit_row(&mut fields);
        self.audit
            .append_event_synced(
                fields,
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
        use crate::security::transparency_log::pager;
        filter.validate()?;
        let log = self.audit.path();
        let at = pager::position(&log, filter.cursor.map(|c| (c.offset, c.segment)))?;
        let segment = Some(at.segment);
        let Some(file) = pager::open_segment(&log, at.segment, || {})? else {
            // The segment is under neither name. If the log had files and the
            // page still names bytes in it, they went unread: refuse rather
            // than page past them. Otherwise there is nothing to read here.
            if at.lost_if_unopened() {
                return Err(StoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("audit segment {} vanished with bytes unread", at.segment),
                )));
            }
            return Ok(AuditPage {
                next_cursor: next_page(&log, 0, segment)?,
                ..AuditPage::empty(at.reset)
            });
        };
        // The page's end, from the file opened, once: a length read by name
        // could be a different file after a rotation.
        let end = pager::end_in(at.bound, &file)?;
        // The cursor's offset is an exclusive upper bound: everything below it
        // is still unread. Read one tail window ending there, assembling a
        // line up to the logger's record cap across windows (the shared pager,
        // as the Activity reader does), so one call reads at most
        // MAX_AUDIT_SCAN_BYTES plus one assembly window.
        let (tail, window_len) = pager::tail_window_assembled(&file, end, MAX_AUDIT_SCAN_BYTES)?;
        // A cursor this store hands out sits at a line start, at 0, or at a
        // file's end, so a page ending inside a line is one stepping through
        // an over-cap line already reported: the line is skipped, not re-read.
        let len = file.metadata()?.len();
        let continuation = continues_a_skipped_line(&file, end, len)?;
        let pager::Tail::Lines {
            start: body_start, ..
        } = tail
        else {
            // A line over the cap: report it once, at the bottom of the bytes
            // read, and page on below it.
            let below = end - end.min(pager::ASSEMBLY_WINDOW);
            let unreadable = (!continuation).then_some(AuditCursor {
                offset: below,
                segment,
            });
            if let Some(hole) = &unreadable {
                tracing::warn!(
                    offset = hole.offset,
                    segment = ?hole.segment,
                    "governance audit line over the record cap; skipped"
                );
            }
            return Ok(AuditPage {
                next_cursor: next_page(&log, below, segment)?,
                bytes_examined: window_len,
                unreadable,
                ..AuditPage::empty(at.reset)
            });
        };
        let body = if continuation {
            drop_trailing_fragment(tail.body())
        } else {
            tail.body()
        };
        let scan = scan_audit(reverse_audit_lines(body, body_start), filter)?;
        // Exhausting the window still leaves every byte below it unread; at
        // the start of a segment, the next page is the older segment's end.
        let resume = scan.stopped_at.unwrap_or(body_start);
        Ok(AuditPage {
            events: scan.events,
            next_cursor: next_page(&log, resume, segment)?,
            records_examined: scan.records_examined,
            bytes_examined: window_len,
            cursor_reset: at.reset,
            unreadable: None,
        })
    }
}

/// The page below `resume` in `segment`: the same file while bytes remain,
/// else the older segment's end, else none (the start of the log).
fn next_page(
    log: &std::path::Path,
    resume: u64,
    segment: Option<u64>,
) -> StoreResult<Option<AuditCursor>> {
    use crate::security::transparency_log::pager;
    if resume > 0 {
        return Ok(Some(AuditCursor {
            offset: resume,
            segment,
        }));
    }
    Ok(
        pager::older_segment(log, segment)?.map(|(offset, seq)| AuditCursor {
            offset,
            segment: Some(seq),
        }),
    )
}

/// Whether a page ending at `end` starts inside a line: below the file's end,
/// and the byte before `end` is not a newline.
fn continues_a_skipped_line(file: &std::fs::File, end: u64, len: u64) -> StoreResult<bool> {
    if end == 0 || end >= len {
        return Ok(false);
    }
    let last = crate::security::transparency_log::pager::read_window_in(file, end - 1, 1)?;
    Ok(last != *b"\n")
}

/// `body` without the bytes after its last newline: the head of a line the
/// page above has already dealt with.
fn drop_trailing_fragment(body: &[u8]) -> &[u8] {
    body.iter()
        .rposition(|b| *b == b'\n')
        .map_or(&body[..0], |nl| &body[..=nl])
}
