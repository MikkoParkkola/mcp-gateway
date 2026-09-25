// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: size/age rotation, retention, the disk-full path and crash recovery.
//!
//! Every step runs inside `append_chained`'s `Inner` critical section, so no
//! caller sees a moment with no writable log. `<path>.lock` is acquired at one
//! point only ([`TransparencyLogger::append_locked`] or `open`), and every
//! helper that needs it takes `&ExclusiveFileLock` as proof: `flock` conflicts
//! between two descriptors even in one process, so a second acquire would
//! deadlock (F19).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use serde_json::{Map, Value};

#[cfg(test)]
use super::TransparencyLogger;
use super::segments::{self, HighWater, Segment};
use super::{
    MAX_TAIL_SCAN_BYTES, TransparencyLogConfig, chain_line, read_last_nonempty_line,
    recompute_entry_hash, verify_entry_sig,
};
use crate::fs_lock::ExclusiveFileLock;
use crate::security::audit::AuditEnvelope;
use crate::security::audit_rotation_config::OnDiskFull;

/// Every housekeeping `event` starts with this; callers may not use it.
pub(super) const SEGMENT_EVENT_PREFIX: &str = "audit_segment_";
/// Segment fields only the logger writes.
pub(super) const RESERVED_SEGMENT_FIELDS: [&str; 4] = [
    "segment_seq",
    "prev_segment_seq",
    "prev_segment_final_hash",
    "segment_opened_at",
];
pub(crate) const EV_SEALED: &str = "audit_segment_sealed";
pub(crate) const EV_OPENED: &str = "audit_segment_opened";
pub(crate) const EV_EXPIRED: &str = "audit_segment_expired";
pub(crate) const EV_TORN: &str = "audit_segment_torn_tail_dropped";

/// Largest record accepted: recovery reads tails through this window.
pub(super) const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// Marker for a record over [`MAX_RECORD_BYTES`]: refused for that call only,
/// never counted as a log failure. A distinct type, not an `ErrorKind`, so a
/// corrupt tail (`InvalidData`) still degrades.
#[derive(Debug)]
pub(super) struct OversizedRecord(pub(super) usize);

impl std::fmt::Display for OversizedRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "transparency log: record of {} bytes exceeds the {MAX_RECORD_BYTES}-byte cap",
            self.0
        )
    }
}

impl std::error::Error for OversizedRecord {}

/// Whether `e` is the oversized-record refusal.
pub(super) fn is_oversized(e: &io::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<OversizedRecord>())
        .is_some()
}

/// Which segment the writer holds, and the file it opened.
#[derive(Debug, Clone, Copy)]
pub(super) struct SegState {
    pub(super) seq: u64,
    pub(super) opened_at: u64,
    /// `(dev, ino)` from `fstat` at open; compared with `stat(path)` on
    /// every append to notice a rotation by another writer (2.8).
    pub(super) id: (u64, u64),
    /// Whether the active file holds more than its open record.
    pub(super) has_records: bool,
}

/// Unix seconds now, plus a test offset.
pub(super) fn now_secs(offset: i64) -> u64 {
    let now = chrono::Utc::now().timestamp().saturating_add(offset);
    u64::try_from(now).unwrap_or(0)
}

#[cfg(unix)]
pub(super) fn file_id(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
pub(super) fn file_id(meta: &std::fs::Metadata) -> (u64, u64) {
    // No inode off unix: creation time stands in, best effort.
    let t = meta
        .created()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    (0, t)
}

// ── Test seams ────────────────────────────────────────────────────────────────

/// A write fault the tests arm on one logger.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteFault {
    /// Write half the line, then ENOSPC on every write until `<path>.reserve`
    /// is unlinked.
    FullUntilReserveFreed,
    /// ENOSPC on every write, and the reserve cannot be unlinked either.
    FullForever,
    /// The expiry record writes, its `sync_all` fails.
    ExpirySyncFails,
    /// ENOSPC on the open-record write right after a rename, once.
    FullAfterRename,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    pub(crate) fault: std::sync::Mutex<Option<WriteFault>>,
    pub(crate) fault_fired: std::sync::atomic::AtomicUsize,
    pub(crate) clock_offset: std::sync::atomic::AtomicI64,
    /// Set once the disk-full path has unlinked the reserve.
    pub(crate) reserve_released: std::sync::atomic::AtomicBool,
    /// Set while an expiry record is being written.
    pub(crate) expiry_in_flight: std::sync::atomic::AtomicBool,
    /// Called between rename and the new open record, with the logger.
    #[allow(clippy::type_complexity)]
    pub(crate) in_rotation: std::sync::Mutex<Option<Box<dyn Fn(&TransparencyLogger) + Send>>>,
}

#[cfg(test)]
impl TransparencyLogger {
    pub(crate) fn arm_write_fault(&self, fault: Option<WriteFault>) {
        *self.hooks.fault.lock().unwrap() = fault;
    }
    pub(crate) fn write_faults_fired(&self) -> usize {
        self.hooks
            .fault_fired
            .load(std::sync::atomic::Ordering::Acquire)
    }
    pub(crate) fn set_clock_offset(&self, secs: i64) {
        self.hooks
            .clock_offset
            .store(secs, std::sync::atomic::Ordering::Release);
    }
    pub(crate) fn on_rotation_window(&self, f: Box<dyn Fn(&TransparencyLogger) + Send>) {
        *self.hooks.in_rotation.lock().unwrap() = Some(f);
    }
    /// Whether another thread could take `Inner` right now.
    pub(crate) fn inner_is_free(&self) -> bool {
        self.inner.try_lock().is_ok()
    }
}

// ── Record helpers ────────────────────────────────────────────────────────────

/// Domain fields of a housekeeping record, envelope included.
pub(super) fn housekeeping(event: &str, extra: &[(&str, Value)]) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("event".into(), event.into());
    fields.insert("timestamp".into(), chrono::Utc::now().to_rfc3339().into());
    for (k, v) in extra {
        fields.insert((*k).into(), v.clone());
    }
    AuditEnvelope::gateway().write_into(&mut fields);
    fields
}

/// Chain and write one housekeeping record straight to `file`, then
/// `sync_all`. For recovery, before any logger exists.
fn write_synced(
    file: &mut File,
    config: &TransparencyLogConfig,
    fields: Map<String, Value>,
    counter: u64,
    prev: &str,
) -> io::Result<String> {
    let (line, hash) = chain_line(config, fields, counter, prev)?;
    file.write_all(format!("{line}\n").as_bytes())?;
    file.sync_all()?;
    Ok(hash)
}

/// `(counter, entry_hash, event)` of a parsed record.
pub(super) fn record_head(line: &str) -> io::Result<(u64, String, Option<String>, Value)> {
    let v: Value =
        serde_json::from_str(line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let counter = v.get("counter").and_then(Value::as_u64).unwrap_or(0);
    let hash = v
        .get("entry_hash")
        .and_then(Value::as_str)
        .unwrap_or("genesis")
        .to_string();
    let event = v.get("event").and_then(Value::as_str).map(str::to_string);
    Ok((counter, hash, event, v))
}

/// The last record of a sealed segment, which must be its seal.
pub(super) fn seal_of(seg: &Segment) -> io::Result<Option<(u64, String)>> {
    let Some(line) = read_last_nonempty_line(&seg.path)? else {
        return Ok(None);
    };
    let (counter, hash, event, _) = record_head(&line)?;
    Ok((event.as_deref() == Some(EV_SEALED)).then_some((counter, hash)))
}

// ── Recovery (open, and a writer that finds its path rotated or gone) ────────

/// What recovery hands the writer.
pub(super) struct Recovered {
    pub(super) file: File,
    pub(super) counter: u64,
    pub(super) last_entry_hash: String,
    pub(super) seg: SegState,
}

/// Rebuild writer state under `<path>.lock` (D6 2.6). Finishes a half-done
/// rotation, repairs a torn tail, continues the counter past a lost active
/// segment, and finishes an interrupted retention unlink. Genesis is chosen
/// only when there is no active record and no sealed segment.
///
/// # Errors
///
/// An I/O error, a complete but unparseable final line (as before D6), or a
/// newest sealed segment with no seal while the active file is missing (F16).
pub(super) fn recover(
    path: &Path,
    config: &TransparencyLogConfig,
    _guard: &ExclusiveFileLock,
    now: u64,
) -> io::Result<Recovered> {
    let secret = config.shared_secret.as_bytes();
    let sealed = segments::list_segments(path)?;
    let hw = segments::read_hwm(path, secret, &config.key_id);
    if std::fs::metadata(path).is_ok_and(|m| m.len() > 0) {
        repair_torn_tail(path, config, sealed.last())?;
    }
    let mut state = match read_last_nonempty_line(path) {
        Ok(Some(line)) => {
            let (counter, hash, event, v) = record_head(&line)?;
            if false && event.as_deref() == Some(EV_SEALED) {
                // Crash after the seal, before the rename: finish it.
                let seq = v.get("segment_seq").and_then(Value::as_u64).unwrap_or(0);
                std::fs::rename(path, segments::sealed_path(path, seq))?;
                segments::sync_dir(path)?;
                open_after_seal(
                    path,
                    config,
                    &segments::list_segments(path)?,
                    hw.as_ref(),
                    now,
                )?
            } else {
                resume_active(path, counter, hash, &sealed, hw.as_ref(), now)?
            }
        }
        Ok(None) => open_after_seal(path, config, &sealed, hw.as_ref(), now)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            open_after_seal(path, config, &sealed, hw.as_ref(), now)?
        }
        Err(e) => return Err(e),
    };
    finish_pending_expiry(path)?;
    // The reserve only serves an expiry, which needs a sealed segment, so a
    // log that never rotated holds none (and leaves no 1 MiB file behind).
    if config.rotation.on_disk_full == OnDiskFull::ExpireOldest
        && !segments::list_segments(path)?.is_empty()
        && let Err(e) = segments::ensure_reserve(path)
    {
        tracing::warn!(error = %e, "audit log: disk-full reserve could not be written");
        telemetry_metrics::gauge!("mcp_audit_reserve_present").set(0.0);
    }
    if hw.is_none() && sealed.is_empty() && state.counter > 0 {
        // A pre-D6 log gets its high-water mark from the active tail.
        let mark = HighWater {
            counter: state.counter,
            entry_hash: state.last_entry_hash.clone(),
            segment_seq: state.seg.seq,
        };
        segments::write_hwm(
            path,
            &segments::encode_hwm(&mark, secret, &config.key_id),
            true,
        )?;
    }
    state.seg.id = file_id(&state.file.metadata()?);
    segments::sync_dir(path)?;
    Ok(state)
}

/// An active file whose last record is an ordinary record.
fn resume_active(
    path: &Path,
    counter: u64,
    hash: String,
    sealed: &[Segment],
    hw: Option<&HighWater>,
    now: u64,
) -> io::Result<Recovered> {
    let first = segments::read_first_line(path)?.unwrap_or_default();
    let (_, _, first_event, first_v) = record_head(&first)?;
    let (seq, opened_at) = if first_event.as_deref() == Some(EV_OPENED) {
        (
            first_v
                .get("segment_seq")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            first_v
                .get("segment_opened_at")
                .and_then(Value::as_u64)
                .unwrap_or(now),
        )
    } else {
        // A pre-D6 segment 0 has no open record; its age counts from now.
        (sealed.last().map_or(0, |s| s.seq + 1), now)
    };
    // The log committed to how far it got: a truncated tail must not let new
    // records reuse the lost counters, so verify reports the gap (2.13).
    let counter = hw
        .filter(|h| h.segment_seq == seq)
        .map_or(counter, |h| h.counter.max(counter));
    let file = OpenOptions::new().append(true).open(path)?;
    Ok(Recovered {
        seg: SegState {
            seq,
            opened_at,
            id: (0, 0),
            has_records: first != read_last_nonempty_line(path)?.unwrap_or_default(),
        },
        file,
        counter,
        last_entry_hash: hash,
    })
}

/// No active record: start the next segment chained from the newest seal,
/// or genesis when nothing was ever sealed.
pub(super) fn open_after_seal(
    path: &Path,
    config: &TransparencyLogConfig,
    sealed: &[Segment],
    hw: Option<&HighWater>,
    now: u64,
) -> io::Result<Recovered> {
    // Truncate, never `create_new`: an empty or torn-open active may exist.
    let fresh = || {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
    };
    let file_seg = |seq| SegState {
        seq,
        opened_at: now,
        id: (0, 0),
        has_records: false,
    };
    let Some(newest) = sealed.last() else {
        let hw_counter = hw.map_or(0, |h| h.counter);
        if hw_counter == 0 {
            drop(fresh()?);
            let file = OpenOptions::new().append(true).open(path)?;
            return Ok(Recovered {
                file,
                counter: 0,
                last_entry_hash: "genesis".into(),
                seg: file_seg(0),
            });
        }
        // An unrotated log whose active file was deleted: continue the
        // counter so verify names the missing records.
        let hw = hw.expect("hw_counter > 0");
        let fields = housekeeping(
            EV_OPENED,
            &[
                ("segment_seq", hw.segment_seq.into()),
                // Names the link, as every open record does, so the exporter
                // can resume here; verify still reports the missing counters.
                ("prev_segment_final_hash", hw.entry_hash.clone().into()),
                ("segment_opened_at", now.into()),
            ],
        );
        let hash = write_synced(
            &mut fresh()?,
            config,
            fields,
            hw.counter + 1,
            &hw.entry_hash,
        )?;
        return Ok(Recovered {
            file: OpenOptions::new().append(true).open(path)?,
            counter: hw.counter + 1,
            last_entry_hash: hash,
            seg: file_seg(hw.segment_seq),
        });
    };
    let Some((seal_counter, seal_hash)) = seal_of(newest)? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "audit log: segment {} is not sealed and the active log is missing; \
                 moved or truncated files are for the operator to resolve",
                newest.seq
            ),
        ));
    };
    let counter = seal_counter.max(hw.map_or(0, |h| h.counter)) + 1;
    let seq = newest.seq + 1;
    let fields = housekeeping(
        EV_OPENED,
        &[
            ("segment_seq", seq.into()),
            ("prev_segment_seq", newest.seq.into()),
            ("prev_segment_final_hash", seal_hash.clone().into()),
            ("segment_opened_at", now.into()),
        ],
    );
    let hash = write_synced(&mut fresh()?, config, fields, counter, &seal_hash)?;
    Ok(Recovered {
        file: OpenOptions::new().append(true).open(path)?,
        counter,
        last_entry_hash: hash,
        seg: file_seg(seq),
    })
}

/// A final line with no trailing newline (D6 2.6 note). Kept, with its
/// newline restored, when it verifies as the next record; otherwise it was
/// never a record: truncate to the last newline and, if the file still holds
/// a record, chain an `audit_segment_torn_tail_dropped` record naming the
/// dropped length. A complete unparseable line is left for the caller to
/// refuse, as before D6.
fn repair_torn_tail(
    path: &Path,
    config: &TransparencyLogConfig,
    newest_sealed: Option<&Segment>,
) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let len = file.metadata()?.len();
    let window = len.min(2 * MAX_TAIL_SCAN_BYTES);
    file.seek(SeekFrom::Start(len - window))?;
    let mut buf = Vec::new();
    (&mut file).take(window).read_to_end(&mut buf)?;
    if buf.last() == Some(&b'\n') {
        return Ok(());
    }
    let cut = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let keep_len = len - window + cut as u64;
    let torn = String::from_utf8_lossy(&buf[cut..]).into_owned();
    let before = String::from_utf8_lossy(&buf[..cut]).into_owned();
    let pred = match before.lines().rfind(|l| !l.trim().is_empty()) {
        Some(line) => Some(line.to_string()),
        None => match newest_sealed {
            Some(seg) => read_last_nonempty_line(&seg.path)?,
            None => None,
        },
    };
    let (pred_counter, pred_hash) = match &pred {
        Some(line) => {
            let (c, h, _, _) = record_head(line)?;
            (c, h)
        }
        None => (0, "genesis".to_string()),
    };
    if verifies_as_next(&torn, pred_counter, &pred_hash, config) {
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"\n")?;
        return file.sync_all();
    }
    file.set_len(keep_len)?;
    file.sync_all()?;
    let dropped = len - keep_len;
    tracing::warn!(bytes = dropped, "audit log: dropped a torn final line");
    if keep_len > 0 && !before.trim().is_empty() {
        let mut file = OpenOptions::new().append(true).open(path)?;
        let fields = housekeeping(EV_TORN, &[("bytes", dropped.into())]);
        write_synced(&mut file, config, fields, pred_counter + 1, &pred_hash)?;
    }
    Ok(())
}

/// Whether `line` is a durable record following `(counter, hash)`.
fn verifies_as_next(line: &str, counter: u64, hash: &str, config: &TransparencyLogConfig) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(line.trim()) else {
        return false;
    };
    let stored = v.get("entry_hash").and_then(Value::as_str).unwrap_or("");
    v.get("counter").and_then(Value::as_u64) == Some(counter + 1)
        && v.get("prev_entry_hash").and_then(Value::as_str) == Some(hash)
        && recompute_entry_hash(&v).is_ok_and(|h| h == stored)
        && (config.shared_secret.is_empty()
            || verify_entry_sig(&v, stored, config.shared_secret.as_bytes()).is_ok())
}

/// Crash between an expiry record and its unlink: unlink every segment an
/// expiry record in the active tail names that is still present.
fn finish_pending_expiry(path: &Path) -> io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(file) = File::open(path) else {
        return Ok(());
    };
    let len = file.metadata()?.len();
    let window = len.min(MAX_TAIL_SCAN_BYTES);
    let mut file = file;
    file.seek(SeekFrom::Start(len - window))?;
    let mut buf = Vec::new();
    file.take(window).read_to_end(&mut buf)?;
    for line in String::from_utf8_lossy(&buf).lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if v.get("event").and_then(Value::as_str) != Some(EV_EXPIRED) {
            continue;
        }
        if let Some(seq) = v.get("segment_seq").and_then(Value::as_u64) {
            let target = segments::sealed_path(path, seq);
            if target.exists() {
                std::fs::remove_file(&target)?;
                segments::sync_dir(path)?;
            }
        }
    }
    Ok(())
}
