// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: the append path with rotation, retention and the disk-full emergency
//! path, all under the caller's `Inner` guard (no degraded window, 2.7).

use std::io::{self, Write};
use std::path::Path;

use serde_json::{Map, Value};

use super::identity::{self, LogId};
use super::rotation::{
    EV_EXPIRED, EV_SEALED, FileId, MAX_RECORD_BYTES, OversizedRecord, file_id, housekeeping,
    now_secs, open_after_seal, path_id, record_head, recover, seal_of, write_mark,
};
use super::segments::{self, HighWater, Segment};
use super::{Inner, TransparencyLogger, chain_line, read_last_nonempty_line};
use crate::fs_lock::ExclusiveFileLock;
use crate::security::audit_rotation_config::OnDiskFull;

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
    if file_id(&writer)? != file_id(file)? || theirs.len() != ours.len() {
        return Err(e);
    }
    writer.set_len(good)
}

/// A reader of appended records: the record's fields as the caller gave them
/// (its envelope included, the chain fields not), its `entry_hash`, and its
/// chain `counter`, which orders records across segments.
pub(crate) type Subscriber = std::sync::Arc<dyn Fn(&Map<String, Value>, &str, u64) + Send + Sync>;

/// A reader of every written record: the record as persisted (chain fields,
/// and `sig` and `key_id` when signed), its chain `counter`, and the logger's
/// rewrite generation. It runs under the log's lock like any reader below,
/// and must not panic: release builds abort on panic, so nothing contains it.
/// A reader subscribes before it reads the log's head, and takes generation
/// 0 as the one it has seen.
pub(crate) type AllReader = std::sync::Arc<dyn Fn(&Map<String, Value>, u64, u64) + Send + Sync>;

/// Readers told of each record of their `kind` once it is written. They run
/// under the log's lock, which every audit write takes, so they see records
/// in append order and never one whose write failed. A reader must only hand
/// the record off without waiting (a `try_send` into a bounded queue, or an
/// insert taking no other lock): one that blocks holds up every write. It
/// must not append to this log.
///
/// All-records readers ([`AllReader`]) follow the same rule, and are told of
/// every record written through `write_record`: caller
/// appends, the rotation's seal and retention's expiry record. The records
/// the rotation module writes itself (the next segment's open record,
/// recovery's own records) are not announced, so a reader sees a counter gap
/// after a rotation and must catch up from the file.
#[derive(Default)]
pub(crate) struct Subscribers {
    by_kind: std::sync::RwLock<Vec<(String, Subscriber)>>,
    all: std::sync::RwLock<Vec<AllReader>>,
    /// Raised when the log this writer extends is no longer the one it wrote:
    /// a rebuild found the counter moved back, or the active file was cut in
    /// place. A rotation does not raise it. In memory, from 0 at open.
    generation: std::sync::atomic::AtomicU64,
    /// The active file this writer last wrote, by identity, and its length
    /// after that write: the same file found shorter was cut in place.
    last_end: std::sync::Mutex<Option<(FileId, u64)>>,
    /// Every check that raised the generation, in order: rows tell an
    /// identity change from a moved tail.
    #[cfg(test)]
    raised: std::sync::Mutex<Vec<&'static str>>,
}

impl Subscribers {
    fn wants(&self, fields: &Map<String, Value>) -> bool {
        let Some(kind) = fields.get("kind").and_then(Value::as_str) else {
            return false;
        };
        self.by_kind
            .read()
            .is_ok_and(|readers| readers.iter().any(|(wanted, _)| wanted == kind))
    }

    fn publish(&self, fields: &Map<String, Value>, entry_hash: &str, counter: u64) {
        let kind = fields.get("kind").and_then(Value::as_str);
        let Ok(readers) = self.by_kind.read() else {
            return;
        };
        for (wanted, reader) in readers.iter() {
            if kind == Some(wanted.as_str()) {
                reader(fields, entry_hash, counter);
            }
        }
    }

    /// Tell every all-records reader of `line`, the record just written at
    /// `counter`. The written line is parsed back, so the record is exactly
    /// what was persisted; nothing is parsed while no reader listens.
    fn announce(&self, line: &str, counter: u64) {
        if !self.all.read().is_ok_and(|readers| !readers.is_empty()) {
            return;
        }
        // Parsed, and any failure logged, before the readers' lock is taken.
        let Ok(Value::Object(record)) = serde_json::from_str::<Value>(line) else {
            // Every reader of the file counts this line unreadable too; a
            // stream crosses it in catch-up like any unreadable line.
            tracing::warn!(
                counter,
                "audit log: a written record did not parse back; not announced"
            );
            return;
        };
        let generation = self.generation.load(std::sync::atomic::Ordering::Acquire);
        let Ok(readers) = self.all.read() else {
            return;
        };
        for reader in readers.iter() {
            reader(&record, counter, generation);
        }
    }

    /// Raise the generation for `check`; the new generation.
    fn bump(&self, check: &'static str) -> u64 {
        #[cfg(test)]
        if let Ok(mut raised) = self.raised.lock() {
            raised.push(check);
        }
        #[cfg(not(test))]
        let _ = check;
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1
    }

    /// A rebuild found another log, by id, where this writer's log was. Both
    /// ids are named: a silent identity change would hide a replaced log.
    fn raise_identity_change(&self, previous: &LogId, new: &LogId) {
        let now = self.bump("log_id");
        tracing::warn!(
            check = "log_id",
            generation = now,
            previous_log_id = %previous,
            log_id = %new,
            "audit log: the log this writer extends was replaced by another log"
        );
    }

    /// `check` names what found the rewrite, for the operator.
    fn raise_generation(&self, check: &'static str) {
        let now = self.bump(check);
        tracing::warn!(
            check,
            generation = now,
            "audit log: the log this writer extends was rewritten"
        );
    }

    /// The checks that raised the generation so far.
    #[cfg(test)]
    pub(super) fn raised(&self) -> Vec<&'static str> {
        self.raised.lock().map_or_default(|r| r.clone())
    }

    /// Take the active file's current end as this writer's baseline: when a
    /// reader subscribes, and after a rotation or a rebuild (whose own write
    /// may fail, so no write would record the new file's end). A cut found on the way is
    /// raised first, so a later baseline never hides an earlier cut.
    fn rebaseline(&self, inner: &Inner) {
        if let Ok(meta) = inner.file.metadata() {
            self.check_end(inner.seg.id, meta.len());
            self.record_end(inner.seg.id, meta.len());
        }
    }

    /// Before a write: the active file `id` holds `len` bytes. Shorter than
    /// this writer left the same file means it was cut in place.
    fn check_end(&self, id: FileId, len: u64) {
        let cut = self
            .last_end
            .lock()
            .is_ok_and(|end| end.is_some_and(|(at, end)| at == id && len < end));
        if cut {
            self.raise_generation("shrink");
        }
    }

    /// After a write: the active file `id` now ends at `end`.
    fn record_end(&self, id: FileId, end: u64) {
        if let Ok(mut last) = self.last_end.lock() {
            *last = Some((id, end));
        }
    }
}

/// The log under a bound append was replaced while space was being freed:
/// the append stopped before it wrote to, or expired anything in, the log
/// that took its place.
#[derive(Debug)]
pub(super) struct LogReplaced;

impl std::fmt::Display for LogReplaced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("transparency log: the bound log was replaced while freeing space")
    }
}

impl std::error::Error for LogReplaced {}

impl TransparencyLogger {
    /// Tell `reader` of every record of `kind` written from now on, at least
    /// once: a settle whose write was unconfirmed and then retried can land
    /// twice, and the reader is told of both. The two carry the same `role`
    /// (its `event`), `token` and caller payload, and differ only in the
    /// envelope and chain fields; a reader of a `settle.` kind dedupes by
    /// (token, role).
    #[cfg(feature = "webui")]
    pub(crate) fn subscribe(&self, kind: &str, reader: Subscriber) {
        if let Ok(mut readers) = self.subscribers.by_kind.write() {
            readers.push((kind.to_string(), reader));
        }
    }

    /// Tell `reader` of every record written from now on, whatever its kind.
    #[cfg(feature = "webui")]
    #[allow(
        dead_code,
        reason = "the live stream's activity and config sources read it when they land"
    )]
    pub(crate) fn subscribe_all(&self, reader: AllReader) {
        if let Ok(mut readers) = self.subscribers.all.write() {
            readers.push(reader);
        }
        // The shrink check's baseline from now: a file cut after this reader
        // subscribed is caught even before this writer's next record.
        if let Ok(inner) = self.inner.lock() {
            self.subscribers.rebaseline(&inner);
        }
    }
}

impl TransparencyLogger {
    #[cfg_attr(not(test), allow(clippy::unused_self))] // the clock offset is a test seam
    fn now(&self) -> Option<u64> {
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
        self.refresh(inner, resync)?;
        self.append_refreshed(inner, fields, resync, None)
    }

    /// Bring `inner` to the log on disk before an append: every append
    /// checks for a rotated or deleted path, on every writer, and a synced
    /// (governance) append always re-reads the tail. A rebuild here can
    /// adopt another log's id, so a check on the id belongs after this.
    pub(super) fn refresh(&self, inner: &mut Inner, resync: bool) -> io::Result<()> {
        let path = self.path();
        let moved = match path_id(&path) {
            Ok(id) => id != inner.seg.id,
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(e),
        };
        if moved || resync {
            self.rebuild(inner, &path, &self.lease)?;
        }
        Ok(())
    }

    /// [`Self::append_locked`] after its [`Self::refresh`]: rotate or trim
    /// when due, then write (synced when `sync`).
    pub(super) fn append_refreshed(
        &self,
        inner: &mut Inner,
        fields: Map<String, Value>,
        resync: bool,
        bound: Option<&LogId>,
    ) -> io::Result<String> {
        let published = self.subscribers.wants(&fields).then(|| fields.clone());
        let path = self.path();
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
        // Age rotation needs both a dated segment and a readable clock; size
        // rotation never depends on the clock (MIK-8202 P4a).
        let too_old = rot.max_segment_age_secs > 0
            && now
                .zip(inner.seg.opened_at)
                .is_some_and(|(now, at)| now >= at.saturating_add(rot.max_segment_age_secs));
        // Retention also runs before the append, not only after a rotation:
        // a log opened over the limit (retain_segments lowered, or a crash
        // mid-retention) is trimmed on its first write. Its expiry records
        // are appends too, so a full disk here takes the path below.
        let mut staged = Ok(());
        if inner.seg.sealed > rot.retain_segments as usize {
            staged = self.apply_retention(inner, &path, &self.lease);
        }
        let rotated = if staged.is_ok() && inner.seg.has_records && (too_big || too_old) {
            self.rotate(inner, &path, &self.lease, now)
        } else {
            staged
        };
        // A failed rotation step is an append failure like any other; on
        // ENOSPC it takes the same rebuild-then-expire path (F23).
        let first = rotated.and_then(|()| self.write_record(inner, &path, fields.clone(), resync));
        let written = match first {
            Err(e)
                if e.kind() == io::ErrorKind::StorageFull
                    && rot.on_disk_full == OnDiskFull::ExpireOldest =>
            {
                self.free_space(inner, &path, &self.lease, e, bound)?;
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
        };
        if let (Ok(entry_hash), Some(fields)) = (&written, published) {
            self.subscribers.publish(&fields, entry_hash, inner.counter);
        }
        written
    }

    /// Re-run open-time recovery under the held guard: reopen after another
    /// writer rotated, finish a half-done rotation, or continue the counter
    /// past a deleted active file (2.8, 2.13).
    fn rebuild(&self, inner: &mut Inner, path: &Path, g: &ExclusiveFileLock) -> io::Result<()> {
        let (r, log_id) = recover(path, &self.config, g, self.now(), Some(&inner.log_id))?;
        // A finding this writer already holds is never forgotten (#2294).
        let known = inner.seg.hwm_missing_at;
        // A tail that is not this writer's last record: the log it extends
        // was replaced, restored, forked or emptied, or recovery wrote its
        // own records over a cut. Positions in it no longer hold.
        // Another log in its place (another id) is raised as an identity
        // change, once, in place of the moved tail it also is.
        if log_id != inner.log_id {
            self.subscribers
                .raise_identity_change(&inner.log_id, &log_id);
        } else if r.counter != inner.counter || r.last_entry_hash != inner.last_entry_hash {
            self.subscribers.raise_generation("tail");
        }
        inner.log_id = log_id;
        inner.file = r.file;
        inner.counter = r.counter;
        inner.last_entry_hash = r.last_entry_hash;
        inner.seg = r.seg;
        self.subscribers.rebaseline(inner);
        if let Some(at) = known {
            inner.seg.hwm_missing_at = Some(inner.seg.hwm_missing_at.map_or(at, |e| e.min(at)));
        }
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
        self.subscribers.announce(&line, counter);
        Ok(hash)
    }

    /// Write one whole line. A failed write is cut back to the last good
    /// length, so no later record is glued onto a torn line.
    fn write_line(&self, inner: &mut Inner, line: &str, sync: bool) -> io::Result<()> {
        let bytes = format!("{line}\n");
        let path = self.path();
        let good = inner
            .file
            .metadata()
            .map_err(segments::ctx("stat", &path))?
            .len();
        self.subscribers.check_end(inner.seg.id, good);
        let written = self
            .injected_write(inner, bytes.as_bytes())
            .unwrap_or_else(|| inner.file.write_all(bytes.as_bytes()))
            .map_err(segments::ctx("write", &path))
            .and_then(|()| {
                if sync {
                    self.injected_sync(inner)
                        .map_err(segments::ctx("sync", &path))
                } else {
                    Ok(())
                }
            });
        if written.is_err()
            && let Err(e) = cut_back(&inner.file, &path, good)
        {
            tracing::warn!(error = %e, "audit log: torn tail not cut back");
        }
        if written.is_ok() {
            self.subscribers
                .record_end(inner.seg.id, good + bytes.len() as u64);
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
        Self::durable(&inner.file)
    }

    /// The one place an acknowledged append reaches the disk; the test build
    /// records each successful call per file so a path that skips it fails a row.
    #[cfg(not(test))]
    fn durable(file: &std::fs::File) -> io::Result<()> {
        file.sync_all()
    }

    #[cfg(test)]
    fn durable(file: &std::fs::File) -> io::Result<()> {
        file.sync_all()?;
        Self::note_synced(file);
        Ok(())
    }

    /// The seam: a fault writes a partial prefix and returns ENOSPC.
    #[cfg(test)]
    fn injected_write(&self, inner: &mut Inner, bytes: &[u8]) -> Option<io::Result<()>> {
        use super::rotation::WriteFault;
        use std::sync::atomic::Ordering;
        let stall = self.hooks.stall.lock().unwrap().take();
        if let Some(gate) = stall {
            gate.hold(); // held under `Inner`, like a write stuck in the kernel
        }
        let fault = *self.hooks.fault.lock().unwrap();
        if fault == Some(WriteFault::WriteError) {
            *self.hooks.fault.lock().unwrap() = None;
            self.hooks.fault_fired.fetch_add(1, Ordering::AcqRel);
            return Some(Err(io::Error::other("injected write failure")));
        }
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
        self.hooks.fault_fired.fetch_add(1, Ordering::AcqRel);
        self.note_partial_write_trace(bytes);
        let _ = inner.file.write_all(&bytes[..bytes.len() / 2]);
        let after_partial_write = self.hooks.after_partial_write.lock().unwrap().take();
        if let Some(callback) = after_partial_write {
            callback();
        }
        Some(Err(io::Error::from(io::ErrorKind::StorageFull)))
    }

    #[cfg(test)]
    fn injected_sync(&self, inner: &mut Inner) -> io::Result<()> {
        use super::rotation::WriteFault;
        {
            let mut fault = self.hooks.fault.lock().unwrap();
            if *fault == Some(WriteFault::SyncError) {
                *fault = None;
                self.hooks
                    .fault_fired
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                return Err(io::Error::other("injected sync failure"));
            }
        }
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
        Self::durable(&inner.file)
    }

    fn mark_hwm(&self, inner: &Inner, path: &Path, sync: bool) {
        #[cfg(test)]
        self.hooks
            .created_by
            .witness("audit log high-water mark", path);
        let written = write_mark(
            path,
            &self.config,
            inner.counter,
            &inner.last_entry_hash,
            inner.seg.seq,
            sync,
        );
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
        now: Option<u64>,
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
        let sealed = segments::sealed_path(path, seq);
        std::fs::rename(path, &sealed).map_err(segments::ctx("rename", &sealed))?;
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
            inner.seg.hwm_missing_at,
            &identity::open_fields(&inner.log_id, None),
        )?;
        inner.file = r.file;
        inner.counter = r.counter;
        inner.last_entry_hash = r.last_entry_hash;
        inner.seg = r.seg;
        inner.seg.id = file_id(&inner.file)?;
        self.subscribers.rebaseline(inner);
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
        std::fs::remove_file(&seg.path).map_err(segments::ctx("remove", &seg.path))?;
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
        bound: Option<&LogId>,
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
        let on_active = path_id(path).is_ok_and(|id| id == inner.seg.id);
        if !on_active {
            self.rebuild(inner, path, g)?;
            // A log put in place of the bound one: refuse before the expiry or
            // the retried write reaches it. The rebuild above has already run
            // its own recovery, as `refresh` does for any moved log.
            if bound.is_some_and(|bound| inner.log_id != *bound) {
                return Err(io::Error::other(LogReplaced));
            }
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

#[cfg(all(test, feature = "webui"))]
#[path = "transparency_log_announce_tests.rs"]
mod announce_tests;
#[cfg(all(test, feature = "webui"))]
#[path = "transparency_log_subscribe_tests.rs"]
mod subscribe_tests;
