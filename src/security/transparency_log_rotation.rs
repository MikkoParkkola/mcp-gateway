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

use super::hwm_scan::{contradicted, hwm_missing_in, newest_finding};
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
pub(super) const RESERVED_SEGMENT_FIELDS: [&str; 5] = [
    "segment_seq",
    "prev_segment_seq",
    "prev_segment_final_hash",
    "segment_opened_at",
    HWM_MISSING_AT,
];
pub(crate) const EV_SEALED: &str = "audit_segment_sealed";
pub(crate) const EV_OPENED: &str = "audit_segment_opened";
pub(crate) const EV_EXPIRED: &str = "audit_segment_expired";
pub(crate) const EV_TORN: &str = "audit_segment_torn_tail_dropped";
/// A restart found `.hwm` missing on a log that went through segment
/// handling: tail loss before this record cannot be ruled out (#2294).
pub(crate) const EV_HWM_MISSING: &str = "audit_segment_hwm_missing";
/// Set on an [`EV_TORN`] record whose dropped line the mark already counted:
/// a committed loss, read as a finding like [`EV_HWM_MISSING`] (MIK-7712).
pub(crate) const TORN_COMMITTED: &str = "committed";
/// Carries the earliest [`EV_HWM_MISSING`] counter on every later open
/// record, so the active segment always holds the finding and no expiry of
/// an older segment can erase it (#2294).
pub(crate) const HWM_MISSING_AT: &str = "hwm_missing_at";

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
    /// The open handle's `file_id` at open; compared with `path_id(path)` on
    /// every append to notice a rotation by another writer (2.8).
    pub(super) id: FileId,
    /// Whether the active file holds more than its open record.
    pub(super) has_records: bool,
    /// Sealed segments beside the active file, as last listed.
    pub(super) sealed: usize,
    /// Earliest counter at which a restart found `.hwm` missing; carried
    /// onto the next open record (#2294).
    pub(super) hwm_missing_at: Option<u64>,
}

/// Unix seconds now, plus a test offset.
pub(super) fn now_secs(offset: i64) -> u64 {
    let now = chrono::Utc::now().timestamp().saturating_add(offset);
    u64::try_from(now).unwrap_or(0)
}

/// A file's identity: (volume, file id). Unix: (`st_dev`, `st_ino`). Windows:
/// (volume serial, 128-bit id), the only pair `ReFS` keeps unique.
pub(super) type FileId = (u64, u128);

/// The identity of an open file, read from its handle.
#[cfg(unix)]
pub(super) fn file_id(file: &File) -> io::Result<FileId> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), u128::from(meta.ino())))
}

#[cfg(windows)]
pub(super) fn file_id(file: &File) -> io::Result<FileId> {
    crate::win_acl::file_identity(file)
}

/// The identity of whatever `path` names now. Windows has no id without a
/// handle, so the file is opened for attributes only, sharing everything so
/// a writer's rotate or delete is not blocked.
pub(super) fn path_id(path: &Path) -> io::Result<FileId> {
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x80;
        const SHARE_ALL: u32 = 0x7; // FILE_SHARE_READ | WRITE | DELETE
        OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(SHARE_ALL)
            .open(path)?
    };
    #[cfg(not(windows))]
    let file = File::open(path)?;
    file_id(&file)
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
    let dropped = if std::fs::metadata(path).is_ok_and(|m| m.len() > 0) {
        repair_torn_tail(path, config, sealed.last(), hw.as_ref())?
    } else {
        None
    };
    // `.hwm` is written after its record, so a torn line at or below the
    // mark was a committed record, not a crash mid-write: its loss is a
    // finding, whatever the line held (#2294).
    let committed_drop = dropped.is_some_and(|d| hw.as_ref().is_some_and(|h| h.counter >= d));
    // A tail that ends below the authenticated mark lost committed records
    // whether the cut was torn or fell on a newline (MIK-7712).
    let (mut state, below_mark) = reopen_tail(path, config, &sealed, hw.as_ref(), now)?;
    finish_pending_expiry(path)?;
    // The active file holds the finding from its open record or a marker,
    // and the newest sealed segment from its own; either can be edited, so
    // both are read.
    let in_active = hwm_missing_in(path, config)?;
    let in_sealed = newest_finding(&segments::list_segments(path)?, config)?;
    state.seg.hwm_missing_at = in_active.into_iter().chain(in_sealed).min();
    // The reserve only serves an expiry, which needs a sealed segment, so a
    // log that never rotated holds none (and leaves no 1 MiB file behind).
    if config.rotation.on_disk_full == OnDiskFull::ExpireOldest
        && !segments::list_segments(path)?.is_empty()
        && let Err(e) = segments::ensure_reserve(path)
    {
        tracing::warn!(error = %e, "audit log: disk-full reserve could not be written");
        telemetry_metrics::gauge!("mcp_audit_reserve_present").set(0.0);
    }
    if (hw.is_none() || committed_drop || below_mark) && state.counter > 0 {
        // Re-minting `.hwm` from a cut tail would launder the cut, so a log
        // that went through segment handling first records that the mark
        // was missing (#2294). A pre-D6 log (no open record) and a
        // genesis-only one (a crash before the first mark) are not marked.
        let opened = segments::read_first_line(path)?
            .and_then(|l| record_head(&l).ok())
            .is_some_and(|(_, _, e, _)| e.as_deref() == Some(EV_OPENED));
        let lost =
            committed_drop || below_mark || !sealed.is_empty() || (opened && state.counter > 1);
        // A crash between the marker and the mark left the marker last.
        let marked = read_last_nonempty_line(path)?
            .and_then(|l| record_head(&l).ok())
            .is_some_and(|(_, _, e, _)| e.as_deref() == Some(EV_HWM_MISSING));
        if lost && !marked {
            let fields = housekeeping(EV_HWM_MISSING, &[("last_counter", state.counter.into())]);
            state.last_entry_hash = write_synced(
                &mut state.file,
                config,
                fields,
                state.counter + 1,
                &state.last_entry_hash,
            )?;
            state.counter += 1;
            state.seg.has_records = true;
            state.seg.hwm_missing_at.get_or_insert(state.counter);
            tracing::warn!(
                counter = state.counter,
                "audit log: high-water mark missing at restart; recorded, verify will fail"
            );
            telemetry_metrics::counter!("mcp_audit_hwm_missing_total").increment(1);
        }
    }
    if hw.is_none() && state.counter > 0 {
        let mark = HighWater {
            counter: state.counter,
            entry_hash: state.last_entry_hash.clone(),
            segment_seq: state.seg.seq,
        };
        segments::write_hwm(
            path,
            &segments::encode_hwm(&mark, secret, &config.key_id)?,
            true,
        )?;
    }
    state.seg.id = file_id(&state.file)?;
    state.seg.sealed = segments::list_segments(path)?.len();
    segments::sync_dir(path)?;
    Ok(state)
}

/// Reopen the active segment from whatever its tail holds, and say whether
/// that tail ends below the authenticated mark `hw` (MIK-7712): the newest
/// surviving record is the active file's last, or the newest seal when the
/// active file holds none.
fn reopen_tail(
    path: &Path,
    config: &TransparencyLogConfig,
    sealed: &[Segment],
    hw: Option<&HighWater>,
    now: u64,
) -> io::Result<(Recovered, bool)> {
    match read_last_nonempty_line(path) {
        Ok(Some(line)) => {
            let (counter, hash, event, v) = record_head(&line)?;
            let seal = event.as_deref() == Some(EV_SEALED);
            let to = segments::sealed_path(path, v["segment_seq"].as_u64().unwrap_or(0));
            // Finish a crash between seal and rename; a seal of a sealed one is a copy (MIK-7949).
            if seal && !to.exists() {
                std::fs::rename(path, &to).map_err(segments::ctx("rename", &to))?;
                segments::sync_dir(path)?;
                let sealed = segments::list_segments(path)?;
                let behind = contradicted(path, &sealed, hw, counter, &hash, config)?;
                let carry = lost_from(newest_finding(&sealed, config)?, behind, counter);
                let state = open_after_seal(path, config, &sealed, hw, now, carry)?;
                Ok((state, behind))
            } else {
                let (resumed, misplaced) = resume_active(path, counter, hash, sealed, hw, now)?;
                let below_mark = (seal || misplaced)
                    || contradicted(path, sealed, hw, counter, &resumed.last_entry_hash, config)?;
                Ok((resumed, below_mark))
            }
        }
        Ok(None) => reopen_after_seal(path, config, sealed, hw, now),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            reopen_after_seal(path, config, sealed, hw, now)
        }
        Err(e) => Err(e),
    }
}

/// No active record: the newest seal (or nothing) is the tail.
fn reopen_after_seal(
    path: &Path,
    config: &TransparencyLogConfig,
    sealed: &[Segment],
    hw: Option<&HighWater>,
    now: u64,
) -> io::Result<(Recovered, bool)> {
    let (tail, tail_hash) = match sealed.last() {
        Some(segment) => seal_of(segment)?.unwrap_or_default(),
        None => (0, String::new()),
    };
    let below_mark = contradicted(path, sealed, hw, tail, &tail_hash, config)?;
    let carry = lost_from(newest_finding(sealed, config)?, below_mark, tail);
    let state = open_after_seal(path, config, sealed, hw, now, carry)?;
    Ok((state, below_mark))
}

/// The finding the replacement open record carries. A loss found below the
/// mark is carried from the first lost counter, so a crash after that record
/// is synced but before the marker cannot lose it (MIK-7712).
fn lost_from(carry: Option<u64>, below_mark: bool, tail: u64) -> Option<u64> {
    if below_mark {
        Some(carry.map_or(tail + 1, |at| at.min(tail + 1)))
    } else {
        carry
    }
}

/// An active file whose last record is an ordinary record; `true` if misplaced.
fn resume_active(
    path: &Path,
    counter: u64,
    hash: String,
    sealed: &[Segment],
    hw: Option<&HighWater>,
    now: u64,
) -> io::Result<(Recovered, bool)> {
    let first = segments::read_first_line(path)?.unwrap_or_default();
    let (_, _, first_event, first_v) = record_head(&first)?;
    let next = sealed.last().map_or(0, |s| s.seq.saturating_add(1));
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
        (next, now)
    };
    // The active segment follows every seal and the mark's, and holds the mark's record if it
    // ends on its counter. A rebuilt file breaks that (#2831): record it, never seal over one.
    let resumed = hw.map_or(seq, |h| seq.max(h.segment_seq)).max(next);
    let stray = resumed != seq || hw.is_some_and(|h| counter == h.counter && seq != h.segment_seq);
    // The log committed to how far it got: a truncated tail must not let new
    // records reuse the lost counters, so verify reports the gap (2.13).
    // Counters are global across segments, so the mark bounds them whatever
    // segment it names: a restored older file must not reuse them (MIK-7884).
    let counter = hw.map_or(counter, |h| h.counter.max(counter));
    let file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(segments::ctx("open", path))?;
    let recovered = Recovered {
        seg: SegState {
            seq: resumed,
            opened_at,
            id: (0, 0),
            has_records: first != read_last_nonempty_line(path)?.unwrap_or_default(),
            sealed: sealed.len(),
            hwm_missing_at: None,
        },
        file,
        counter,
        last_entry_hash: hash,
    };
    Ok((recovered, stray))
}

/// No active record: start the next segment chained from the newest seal,
/// or genesis when nothing was ever sealed.
pub(super) fn open_after_seal(
    path: &Path,
    config: &TransparencyLogConfig,
    sealed: &[Segment],
    hw: Option<&HighWater>,
    now: u64,
    carry: Option<u64>,
) -> io::Result<Recovered> {
    // Truncate, never `create_new`: an empty or torn-open active may exist.
    let fresh = || {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(segments::ctx("create", path))?;
        Ok::<_, io::Error>(file)
    };
    let file_seg = |seq| SegState {
        seq,
        opened_at: now,
        id: (0, 0),
        has_records: false,
        sealed: sealed.len(),
        hwm_missing_at: carry,
    };
    let Some(newest) = sealed.last() else {
        let hw_counter = hw.map_or(0, |h| h.counter);
        if hw_counter == 0 {
            // Segment 0 opens with a record too, so verify can tell a
            // never-rotated log from a pre-D6 one and require `.hwm` (#2275).
            let fields = housekeeping(
                EV_OPENED,
                &[("segment_seq", 0.into()), ("segment_opened_at", now.into())],
            );
            let hash = write_synced(&mut fresh()?, config, fields, 1, "genesis")?;
            return Ok(Recovered {
                file: OpenOptions::new()
                    .append(true)
                    .open(path)
                    .map_err(segments::ctx("open", path))?,
                counter: 1,
                last_entry_hash: hash,
                seg: file_seg(0),
            });
        }
        // An unrotated log whose active file was deleted: continue the
        // counter so verify names the missing records.
        let hw = hw.expect("hw_counter > 0");
        let mut extra: Vec<(&str, Value)> = vec![
            ("segment_seq", hw.segment_seq.into()),
            // Names the link, as every open record does, so the exporter
            // can resume here; verify still reports the missing counters.
            ("prev_segment_final_hash", hw.entry_hash.clone().into()),
            ("segment_opened_at", now.into()),
        ];
        if let Some(at) = carry {
            extra.push((HWM_MISSING_AT, at.into()));
        }
        let fields = housekeeping(EV_OPENED, &extra);
        let hash = write_synced(
            &mut fresh()?,
            config,
            fields,
            hw.counter + 1,
            &hw.entry_hash,
        )?;
        return Ok(Recovered {
            file: OpenOptions::new()
                .append(true)
                .open(path)
                .map_err(segments::ctx("open", path))?,
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
    let mut extra: Vec<(&str, Value)> = vec![
        ("segment_seq", seq.into()),
        ("prev_segment_seq", newest.seq.into()),
        ("prev_segment_final_hash", seal_hash.clone().into()),
        ("segment_opened_at", now.into()),
    ];
    if let Some(at) = carry {
        extra.push((HWM_MISSING_AT, at.into()));
    }
    let fields = housekeeping(EV_OPENED, &extra);
    let hash = write_synced(&mut fresh()?, config, fields, counter, &seal_hash)?;
    Ok(Recovered {
        file: OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(segments::ctx("open", path))?,
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
/// refuse, as before D6. Returns the counter the dropped line would have
/// held, if a line was dropped. When `hw` already counts that line, it was a
/// committed record: the repair record says so itself (`committed: true`), so
/// a crash before the missing-mark marker cannot lose the finding (MIK-7712).
fn repair_torn_tail(
    path: &Path,
    config: &TransparencyLogConfig,
    newest_sealed: Option<&Segment>,
    hw: Option<&HighWater>,
) -> io::Result<Option<u64>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(segments::ctx("open", path))?;
    let len = file.metadata()?.len();
    let window = len.min(2 * MAX_TAIL_SCAN_BYTES);
    file.seek(SeekFrom::Start(len - window))?;
    let mut buf = Vec::new();
    (&mut file).take(window).read_to_end(&mut buf)?;
    if buf.last() == Some(&b'\n') {
        return Ok(None);
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
        file.sync_all()?;
        return Ok(None);
    }
    file.set_len(keep_len)?;
    file.sync_all()?;
    let dropped = len - keep_len;
    tracing::warn!(bytes = dropped, "audit log: dropped a torn final line");
    if keep_len > 0 && !before.trim().is_empty() {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(segments::ctx("open", path))?;
        let committed = hw.is_some_and(|h| h.counter > pred_counter);
        let mut extra = vec![("bytes", dropped.into())];
        if committed {
            extra.push((TORN_COMMITTED, true.into()));
        }
        let fields = housekeeping(EV_TORN, &extra);
        // Above the mark when it is further ahead than the one line dropped,
        // so a restored older file's repair record reuses no committed counter.
        let at = hw
            .filter(|h| h.counter > pred_counter + 1)
            .map_or(pred_counter + 1, |h| h.counter + 1);
        write_synced(&mut file, config, fields, at, &pred_hash)?;
    }
    Ok(Some(pred_counter + 1))
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
    /// A plain I/O error (not ENOSPC) on the next line write, once.
    WriteError,
    /// A plain I/O error on the next synced append's `sync_all`, once.
    SyncError,
}

/// F20: holds one write "in the kernel" until the test opens it. Every test
/// opens it explicitly (the guard from `stall_next_write_for_test` also
/// opens it on drop); the 60 s deadline is only a hang guard, turning an
/// unbounded append (a mutant) into a failed assertion, never a timing bound.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct StallGate {
    state: std::sync::Mutex<GateState>,
    cv: std::sync::Condvar,
}

#[cfg(test)]
impl StallGate {
    pub(crate) const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

    /// Record entry, then block the writer until opened or the deadline.
    pub(crate) fn hold(&self) {
        let mut s = self.state.lock().expect("gate lock");
        s.entered = true;
        self.cv.notify_all();
        let _ = self
            .cv
            .wait_timeout_while(s, Self::DEADLINE, |s| !s.open)
            .expect("gate lock");
    }

    /// Wait until a write has entered `hold` (up to the deadline); whether
    /// it did.
    pub(crate) fn wait_entered(&self) -> bool {
        let s = self.state.lock().expect("gate lock");
        self.cv
            .wait_timeout_while(s, Self::DEADLINE, |s| !s.entered)
            .expect("gate lock")
            .0
            .entered
    }

    /// Whether a write has reached `hold` (no wait).
    pub(crate) fn is_entered(&self) -> bool {
        self.state.lock().expect("gate lock").entered
    }

    /// Let the held write finish.
    pub(crate) fn release(&self) {
        self.state.lock().expect("gate lock").open = true;
        self.cv.notify_all();
    }
}

#[cfg(test)]
#[derive(Default)]
struct GateState {
    /// A write has reached `hold`.
    entered: bool,
    /// The test let the write go.
    open: bool,
}

/// Opens its gate on drop, so a failed assertion never leaves a write held.
#[cfg(test)]
#[must_use = "dropping the guard releases the stalled write at once"]
pub(crate) struct StallRelease(pub(crate) std::sync::Arc<StallGate>);

#[cfg(test)]
impl std::ops::Deref for StallRelease {
    type Target = StallGate;
    fn deref(&self) -> &StallGate {
        &self.0
    }
}

#[cfg(test)]
impl Drop for StallRelease {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    pub(crate) fault: std::sync::Mutex<Option<WriteFault>>,
    pub(crate) fault_fired: std::sync::atomic::AtomicUsize,
    pub(crate) clock_offset: std::sync::atomic::AtomicI64,
    /// F20: the next write blocks on this gate (a stalled filesystem).
    pub(crate) stall: std::sync::Mutex<Option<std::sync::Arc<StallGate>>>,
    /// F20: probe appends started.
    pub(crate) probes: std::sync::atomic::AtomicUsize,
    /// Set once the disk-full path has unlinked the reserve.
    pub(crate) reserve_released: std::sync::atomic::AtomicBool,
    /// Set while an expiry record is being written.
    pub(crate) expiry_in_flight: std::sync::atomic::AtomicBool,
    /// Called between rename and the new open record, with the logger.
    #[allow(clippy::type_complexity)]
    pub(crate) in_rotation:
        std::sync::Mutex<Option<Box<dyn Fn(&super::TransparencyLogger) + Send>>>,
}

#[cfg(test)]
impl super::TransparencyLogger {
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
    pub(crate) fn on_rotation_window(&self, f: Box<dyn Fn(&super::TransparencyLogger) + Send>) {
        *self.hooks.in_rotation.lock().unwrap() = Some(f);
    }
    /// Whether another thread could take `Inner` right now.
    pub(crate) fn inner_is_free(&self) -> bool {
        self.inner.try_lock().is_ok()
    }
}
