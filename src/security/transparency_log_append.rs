// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: the append path with rotation, retention and the disk-full emergency
//! path, all under the caller's `Inner` guard (no degraded window, 2.7).

use std::io::{self, Write};
use std::path::Path;

use serde_json::{Map, Value};

use super::rotation::{
    EV_EXPIRED, EV_SEALED, MAX_RECORD_BYTES, OversizedRecord, file_id, housekeeping, now_secs,
    open_after_seal, record_head, recover, seal_of,
};
use super::segments::{self, HighWater, Segment};
use super::{Inner, TransparencyLogger, chain_line, read_last_nonempty_line};
use crate::fs_lock::ExclusiveFileLock;
use crate::security::audit_rotation_config::OnDiskFull;

/// Acquire `<path>.lock` once per append, on first need; the one
/// acquisition point (F19).
fn guard<'a>(
    slot: &'a mut Option<ExclusiveFileLock>,
    path: &Path,
) -> io::Result<&'a ExclusiveFileLock> {
    if slot.is_none() {
        *slot = Some(ExclusiveFileLock::acquire(&segments::sibling(
            path, "lock",
        ))?);
    }
    Ok(slot.as_ref().expect("filled above"))
}

/// Truncate a torn tail back to `good` bytes. An append-only handle cannot
/// truncate on Windows (it lacks write-data access), so fall back to a write
/// handle on the path. The handle is opened first and checked against ours,
/// so a rotation between the check and the truncate cannot hit another file.
fn cut_back(file: &std::fs::File, path: &Path, good: u64) -> io::Result<()> {
    let Err(e) = file.set_len(good) else {
        return Ok(());
    };
    let writer = std::fs::OpenOptions::new().write(true).open(path)?;
    let (ours, theirs) = (file.metadata()?, writer.metadata()?);
    if file_id(&theirs) != file_id(&ours) || theirs.len() != ours.len() {
        return Err(e);
    }
    writer.set_len(good)
}

impl TransparencyLogger {
    #[cfg_attr(not(test), allow(clippy::unused_self))] // the clock offset is a test seam
    fn now(&self) -> u64 {
        #[cfg(test)]
        let offset = self
            .hooks
            .clock_offset
            .load(std::sync::atomic::Ordering::Acquire);
        #[cfg(not(test))]
        let offset = 0;
        now_secs(offset)
    }

    /// Chain and write one caller record, rotating first when due.
    pub(super) fn append_locked(
        &self,
        inner: &mut Inner,
        fields: Map<String, Value>,
        resync: bool,
    ) -> io::Result<String> {
        let path = self.path();
        let mut lock: Option<ExclusiveFileLock> = None;
        // Every append checks for a rotated or deleted path, on every
        // writer; a synced (governance) append always re-reads the tail.
        let moved = match std::fs::metadata(&path) {
            Ok(meta) => file_id(&meta) != inner.seg.id,
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(e),
        };
        if moved || resync {
            let g = guard(&mut lock, &path)?;
            self.rebuild(inner, &path, g)?;
        }
        let (line, _) = chain_line(
            &self.config,
            fields.clone(),
            inner.counter + 1,
            &inner.last_entry_hash,
        )?;
        if line.len() + 1 > MAX_RECORD_BYTES {
            return Err(io::Error::other(OversizedRecord(line.len() + 1)));
        }
        let active_bytes = std::fs::metadata(&path)?.len();
        let rot = &self.config.rotation;
        let now = self.now();
        let too_big = active_bytes + line.len() as u64 + 1 > rot.max_segment_bytes;
        let too_old = rot.max_segment_age_secs > 0
            && now >= inner.seg.opened_at.saturating_add(rot.max_segment_age_secs);
        // Retention also runs before the append, not only after a rotation:
        // a log opened over the limit (retain_segments lowered, or a crash
        // mid-retention) is trimmed on its first write. Its expiry records
        // are appends too, so a full disk here takes the path below.
        let mut staged = Ok(());
        if inner.seg.sealed > rot.retain_segments as usize {
            let g = guard(&mut lock, &path)?;
            staged = self.apply_retention(inner, &path, g);
        }
        let rotated = if staged.is_ok() && inner.seg.has_records && (too_big || too_old) {
            let g = guard(&mut lock, &path)?;
            self.rotate(inner, &path, g, now)
        } else {
            staged
        };
        // A failed rotation step is an append failure like any other; on
        // ENOSPC it takes the same rebuild-then-expire path (F23).
        let first = rotated.and_then(|()| self.write_record(inner, &path, fields.clone(), resync));
        match first {
            Err(e)
                if e.kind() == io::ErrorKind::StorageFull
                    && rot.on_disk_full == OnDiskFull::ExpireOldest =>
            {
                let g = guard(&mut lock, &path)?;
                self.free_space(inner, &path, g, e)?;
                let retried = self.write_record(inner, &path, fields, resync);
                if let Err(e) = segments::ensure_reserve(&path) {
                    tracing::warn!(error = %e, "audit log: disk-full reserve not recreated");
                    telemetry_metrics::gauge!("mcp_audit_reserve_present").set(0.0);
                } else {
                    telemetry_metrics::gauge!("mcp_audit_reserve_present").set(1.0);
                }
                retried
            }
            other => other,
        }
    }

    /// Re-run open-time recovery under the held guard: reopen after another
    /// writer rotated, finish a half-done rotation, or continue the counter
    /// past a deleted active file (2.8, 2.13).
    fn rebuild(&self, inner: &mut Inner, path: &Path, g: &ExclusiveFileLock) -> io::Result<()> {
        let r = recover(path, &self.config, g, self.now())?;
        inner.file = r.file;
        inner.counter = r.counter;
        inner.last_entry_hash = r.last_entry_hash;
        inner.seg = r.seg;
        Ok(())
    }

    /// Chain `fields` at the current tail, write it, advance, mark `.hwm`.
    fn write_record(
        &self,
        inner: &mut Inner,
        path: &Path,
        fields: Map<String, Value>,
        sync: bool,
    ) -> io::Result<String> {
        let counter = inner.counter + 1;
        let (line, hash) = chain_line(&self.config, fields, counter, &inner.last_entry_hash)?;
        self.write_line(inner, &line, sync)?;
        inner.counter = counter;
        inner.last_entry_hash.clone_from(&hash);
        inner.seg.has_records = true;
        self.mark_hwm(inner, path, sync);
        Ok(hash)
    }

    /// Write one whole line. A failed write is cut back to the last good
    /// length, so no later record is glued onto a torn line.
    fn write_line(&self, inner: &mut Inner, line: &str, sync: bool) -> io::Result<()> {
        let bytes = format!("{line}\n");
        let good = inner.file.metadata()?.len();
        let written = self
            .injected_write(inner, bytes.as_bytes())
            .unwrap_or_else(|| inner.file.write_all(bytes.as_bytes()))
            .and_then(|()| {
                if sync {
                    self.injected_sync(inner)
                } else {
                    Ok(())
                }
            });
        if written.is_err()
            && let Err(e) = cut_back(&inner.file, &self.path(), good)
        {
            tracing::warn!(error = %e, "audit log: torn tail not cut back");
        }
        written
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn injected_write(&self, _inner: &mut Inner, _bytes: &[u8]) -> Option<io::Result<()>> {
        None
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn injected_sync(&self, inner: &mut Inner) -> io::Result<()> {
        inner.file.sync_all()
    }

    /// The seam: a fault writes a partial prefix and returns ENOSPC.
    #[cfg(test)]
    fn injected_write(&self, inner: &mut Inner, bytes: &[u8]) -> Option<io::Result<()>> {
        use super::rotation::WriteFault;
        let fault = *self.hooks.fault.lock().unwrap();
        let full = match fault {
            Some(WriteFault::FullForever) => true,
            Some(WriteFault::FullUntilReserveFreed) => !self
                .hooks
                .reserve_released
                .load(std::sync::atomic::Ordering::Acquire),
            _ => false,
        };
        if !full {
            return None;
        }
        self.hooks
            .fault_fired
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let _ = inner.file.write_all(&bytes[..bytes.len() / 2]);
        Some(Err(io::Error::from(io::ErrorKind::StorageFull)))
    }

    #[cfg(test)]
    fn injected_sync(&self, inner: &mut Inner) -> io::Result<()> {
        use super::rotation::WriteFault;
        if *self.hooks.fault.lock().unwrap() == Some(WriteFault::ExpirySyncFails)
            && self
                .hooks
                .expiry_in_flight
                .load(std::sync::atomic::Ordering::Acquire)
        {
            self.hooks
                .fault_fired
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            return Err(io::Error::other("injected expiry sync failure"));
        }
        inner.file.sync_all()
    }

    fn mark_hwm(&self, inner: &Inner, path: &Path, sync: bool) {
        let mark = HighWater {
            counter: inner.counter,
            entry_hash: inner.last_entry_hash.clone(),
            segment_seq: inner.seg.seq,
        };
        let written = segments::encode_hwm(
            &mark,
            self.config.shared_secret.as_bytes(),
            &self.config.key_id,
        )
        .and_then(|bytes| segments::write_hwm(path, &bytes, sync));
        if let Err(e) = written {
            tracing::warn!(error = %e, "audit log: high-water mark not written");
        }
    }
}

// ── Rotation, retention, disk full ───────────────────────────────────────────

impl TransparencyLogger {
    /// Seal the active segment, rename it to `<path>.<seq>`, open the next
    /// one chained from the seal, then apply retention (2.6 steps 1-4).
    fn rotate(
        &self,
        inner: &mut Inner,
        path: &Path,
        g: &ExclusiveFileLock,
        now: u64,
    ) -> io::Result<()> {
        let seq = inner.seg.seq;
        let seal = housekeeping(
            EV_SEALED,
            &[
                ("segment_seq", seq.into()),
                ("next_segment_seq", (seq + 1).into()),
            ],
        );
        self.write_record(inner, path, seal, true)?;
        std::fs::rename(path, segments::sealed_path(path, seq))?;
        segments::sync_dir(path)?;
        #[cfg(test)]
        {
            if let Some(probe) = self.hooks.in_rotation.lock().unwrap().as_ref() {
                probe(self);
            }
            let mut fault = self.hooks.fault.lock().unwrap();
            if *fault == Some(super::rotation::WriteFault::FullAfterRename) {
                *fault = None;
                self.hooks
                    .fault_fired
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                return Err(io::Error::from(io::ErrorKind::StorageFull));
            }
        }
        let hw = HighWater {
            counter: inner.counter,
            entry_hash: inner.last_entry_hash.clone(),
            segment_seq: seq,
        };
        let r = open_after_seal(
            path,
            &self.config,
            &segments::list_segments(path)?,
            Some(&hw),
            now,
        )?;
        inner.file = r.file;
        inner.counter = r.counter;
        inner.last_entry_hash = r.last_entry_hash;
        inner.seg = r.seg;
        inner.seg.id = file_id(&inner.file.metadata()?);
        self.mark_hwm(inner, path, true);
        telemetry_metrics::counter!("mcp_audit_rotations_total").increment(1);
        if self.config.rotation.on_disk_full == OnDiskFull::ExpireOldest
            && let Err(e) = segments::ensure_reserve(path)
        {
            tracing::warn!(error = %e, "audit log: disk-full reserve could not be written");
        }
        self.apply_retention(inner, path, g)
    }

    /// Delete sealed segments beyond `retain_segments`, oldest first, each
    /// recorded before its unlink.
    fn apply_retention(
        &self,
        inner: &mut Inner,
        path: &Path,
        g: &ExclusiveFileLock,
    ) -> io::Result<()> {
        let sealed = segments::list_segments(path)?;
        let keep = self.config.rotation.retain_segments as usize;
        for seg in sealed.iter().take(sealed.len().saturating_sub(keep)) {
            self.expire(inner, path, seg, "retention", g)?;
        }
        let left = segments::list_segments(path)?.len();
        inner.seg.sealed = left;
        #[allow(clippy::cast_precision_loss)]
        telemetry_metrics::gauge!("mcp_audit_segments").set(left as f64 + 1.0);
        Ok(())
    }

    /// Record `seg`'s expiry (chained, fsync'd), then unlink it (2.4). A
    /// failed write or sync deletes nothing.
    fn expire(
        &self,
        inner: &mut Inner,
        path: &Path,
        seg: &Segment,
        reason: &'static str,
        _g: &ExclusiveFileLock,
    ) -> io::Result<()> {
        let first = segments::read_first_line(&seg.path)?.unwrap_or_default();
        let first_counter = record_head(&first).map_or(0, |h| h.0);
        let (last_counter, final_hash) = if let Some(seal) = seal_of(seg)? {
            seal
        } else {
            let tail = read_last_nonempty_line(&seg.path)?.unwrap_or_default();
            let (c, h, _, _) = record_head(&tail)?;
            (c, h)
        };
        let bytes = std::fs::metadata(&seg.path)?.len();
        let fields = housekeeping(
            EV_EXPIRED,
            &[
                ("segment_seq", seg.seq.into()),
                ("first_counter", first_counter.into()),
                ("last_counter", last_counter.into()),
                ("final_hash", final_hash.into()),
                ("bytes", bytes.into()),
                ("reason", reason.into()),
            ],
        );
        #[cfg(test)]
        self.hooks
            .expiry_in_flight
            .store(true, std::sync::atomic::Ordering::Release);
        let written = self.write_record(inner, path, fields, true);
        #[cfg(test)]
        self.hooks
            .expiry_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
        written?;
        std::fs::remove_file(&seg.path)?;
        inner.seg.sealed = inner.seg.sealed.saturating_sub(1);
        segments::sync_dir(path)?;
        telemetry_metrics::counter!("mcp_audit_segments_expired_total", "reason" => reason)
            .increment(1);
        Ok(())
    }

    /// `on_disk_full: expire_oldest` (2.7): cut back any torn prefix, free
    /// the reserve, rebuild a writer a failed rotation left on a sealed inode,
    /// then record and delete the oldest sealed segment. Never touches the
    /// active segment, never deletes without a record.
    fn free_space(
        &self,
        inner: &mut Inner,
        path: &Path,
        g: &ExclusiveFileLock,
        cause: io::Error,
    ) -> io::Result<()> {
        if segments::list_segments(path)?.is_empty() {
            return Err(cause);
        }
        #[cfg(test)]
        if *self.hooks.fault.lock().unwrap() == Some(super::rotation::WriteFault::FullForever) {
            return Err(cause);
        }
        if !segments::release_reserve(path)? {
            tracing::warn!("audit log: no disk-full reserve to release");
        }
        #[cfg(test)]
        self.hooks
            .reserve_released
            .store(true, std::sync::atomic::Ordering::Release);
        let on_active = std::fs::metadata(path).is_ok_and(|m| file_id(&m) == inner.seg.id);
        if !on_active {
            self.rebuild(inner, path, g)?;
        }
        let oldest = segments::list_segments(path)?;
        let Some(oldest) = oldest.first() else {
            return Err(cause);
        };
        tracing::warn!(
            segment = oldest.seq,
            "audit log: volume full, expiring the oldest segment"
        );
        self.expire(inner, path, oldest, "storage_full", g)
    }
}
