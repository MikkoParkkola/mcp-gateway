// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The audit log's stable identity: one `log_id`, minted once, carried by
//! every segment open record, so a record kept elsewhere can name the log it
//! was meant for. Records hold the id only: no paths, values or secrets.

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use serde_json::Value;

use super::rotation::{EV_OPENED, MAX_RECORD_BYTES};
use super::segments::{self, HighWater, Segment};

/// Names a log that has no segment open record to carry its id (a log
/// written before the id existed), and records the mint of one.
pub(crate) const EV_IDENTIFIED: &str = "audit_log_identified";

/// Precedes the identified record of a new genesis whose predecessor is gone
/// (written first, so a crash before the identified record keeps it and the
/// unfinished-genesis repair adds that record),
/// naming what evidence of it survived: `previous_log_id` when a live logger
/// held the old id, `previous_high_water` (`counter`, `entry_hash`) when the
/// old `.hwm` survived. It does not cover a deletion that also removed `.hwm`
/// with no live logger: nothing then names the old log, and no marker is
/// written without evidence.
pub(crate) const EV_PREDECESSOR_MISSING: &str = "audit_log_predecessor_missing";

/// Events only the logger writes; a caller naming one is refused.
pub(crate) const RESERVED_EVENTS: [&str; 2] = [EV_IDENTIFIED, EV_PREDECESSOR_MISSING];

/// How many records from the start of the oldest file can hold the marker:
/// open, mark-missing, then the marker.
const MARKER_HEAD: usize = 3;

/// An audit log's identity. Opaque: compare, display, never parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogId(String);

impl LogId {
    /// A fresh random id.
    pub(super) fn mint() -> Self {
        Self(uuid::Uuid::new_v4().simple().to_string())
    }

    /// The id as written to a record.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The id of the log at `path`: the one on its newest open record, else the
/// newest identified record. `None` only for a log that has neither, which
/// then mints.
///
/// # Errors
///
/// A segment that cannot be read.
pub(super) fn resolve(path: &Path, sealed: &[Segment]) -> io::Result<Option<LogId>> {
    let files: Vec<&Path> = std::iter::once(path)
        .chain(sealed.iter().rev().map(|s| s.path.as_path()))
        .collect();
    for file in &files {
        match segments::read_first_line(file) {
            Ok(Some(line)) => {
                let head = serde_json::from_str::<Value>(&line).ok();
                if let Some(id) = head
                    .filter(|v| is_event(v, EV_OPENED))
                    .and_then(|v| id_of(&v))
                {
                    return Ok(Some(id));
                }
                break; // only the newest segment's open record counts
            }
            Ok(None) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    for file in files {
        if let Some(id) = newest_identified(file)? {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// Whether the active file is a genesis left unfinished: the log's first
/// segment (nothing sealed), whose open record carries an id that no record
/// in it names. A crash between the genesis open record (and its first mark)
/// and the identified record leaves this, and so does a torn identified
/// record, whose drop recovery records in its place: so the whole file is
/// searched, not the second line, and the search stops at the first
/// identified record (normally line 2). With nothing sealed the active file
/// is the whole log, so retention cannot have expired the record. A beta
/// log's open record has no id (it mints instead), and a log whose identified
/// record retention expired has sealed segments, so neither is repaired.
///
/// # Errors
///
/// The active file cannot be read.
pub(super) fn unfinished_genesis(path: &Path, sealed: &[Segment]) -> io::Result<bool> {
    if !sealed.is_empty() {
        return Ok(false);
    }
    // The first record, parsed or not, then whether any later one names the id.
    let (mut first, mut named): (Option<Option<Value>>, bool) = (None, false);
    each_line(path, |line| {
        let line = line.trim();
        if line.is_empty() {
            return true;
        }
        let v = serde_json::from_str::<Value>(line).ok();
        if first.is_none() {
            first = Some(v);
            return true;
        }
        named = v.is_some_and(|v| is_event(&v, EV_IDENTIFIED));
        !named
    })?;
    let genesis_with_id = first.flatten().is_some_and(|v| {
        is_event(&v, EV_OPENED)
            && v.get("segment_seq").and_then(Value::as_u64) == Some(0)
            && id_of(&v).is_some()
    });
    Ok(genesis_with_id && !named)
}

/// The marker's fields, or `None` when nothing of the old log survived.
pub(super) fn predecessor_fields(
    held: Option<&LogId>,
    mark: Option<&HighWater>,
) -> Option<serde_json::Map<String, Value>> {
    let mut extra: Vec<(&str, Value)> = Vec::new();
    if let Some(id) = held {
        extra.push(("previous_log_id", id.as_str().into()));
    }
    if let Some(h) = mark {
        let hw = serde_json::json!({ "counter": h.counter, "entry_hash": h.entry_hash });
        extra.push(("previous_high_water", hw));
    }
    (!extra.is_empty()).then(|| super::rotation::housekeeping(EV_PREDECESSOR_MISSING, &extra))
}

/// Verify's warning for a log whose oldest file starts with the marker. Read
/// apart from the chain checks, so a log that also fails them (its mark
/// survived and names the lost records) still reports it.
///
/// # Errors
///
/// The file cannot be read.
pub(super) fn predecessor_warning(path: &Path) -> io::Result<Option<String>> {
    let (mut seen, mut found) = (0, None);
    each_line(path, |line| {
        if line.trim().is_empty() {
            return true;
        }
        seen += 1;
        let v = serde_json::from_str::<Value>(line.trim()).ok();
        found = v.filter(|v| is_event(v, EV_PREDECESSOR_MISSING));
        found.is_none() && seen < MARKER_HEAD
    })?;
    Ok(found.map(|v| {
        let mut named = Vec::new();
        if let Some(id) = v.get("previous_log_id").and_then(Value::as_str) {
            named.push(format!("previous log_id {id}"));
        }
        if let Some(hw) = v.get("previous_high_water") {
            let counter = hw.get("counter").and_then(Value::as_u64).unwrap_or(0);
            let hash = hw.get("entry_hash").and_then(Value::as_str).unwrap_or("");
            named.push(format!(
                "previous high-water mark at counter {counter} ({hash})"
            ));
        }
        format!(
            "{} starts a new log after its predecessor went missing: {}",
            path.display(),
            named.join(", ")
        )
    }))
}

/// The fields of the record that names a fresh id.
pub(super) fn identified_fields(id: &LogId) -> serde_json::Map<String, Value> {
    super::rotation::housekeeping(EV_IDENTIFIED, &[("log_id", id.as_str().into())])
}

fn is_event(v: &Value, event: &str) -> bool {
    v.get("event").and_then(Value::as_str) == Some(event)
}

fn id_of(v: &Value) -> Option<LogId> {
    let id = v.get("log_id")?.as_str()?;
    Some(LogId(id.to_string()))
}

/// Visit each line of `path` as lossy text, oldest first, until `visit`
/// returns false. A line over the record cap is skipped unread, as
/// `hwm_missing_in` does, so no line allocates without bound. A missing file
/// has no lines.
fn each_line(path: &Path, mut visit: impl FnMut(&str) -> bool) -> io::Result<()> {
    let mut reader = match File::open(path) {
        Ok(f) => BufReader::new(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let cap = MAX_RECORD_BYTES as u64 + 1;
        if (&mut reader).take(cap).read_until(b'\n', &mut buf)? == 0 {
            return Ok(());
        }
        if buf.last() != Some(&b'\n') && buf.len() > MAX_RECORD_BYTES {
            reader.skip_until(b'\n')?;
            continue;
        }
        if !visit(&String::from_utf8_lossy(&buf)) {
            return Ok(());
        }
    }
}

/// The last identified record in one file. Reads every line, as lossy text
/// like the other recovery readers, so an odd byte never hides the record.
/// ponytail: a full scan, reached only while the newest open record has no
/// id: from the upgrade of a beta log until its first rotation. In that
/// window it runs on every recovery (each synced append's rebuild included)
/// and can cover the active file and every retained segment; index the id in
/// the open record's successor if it shows in a profile.
fn newest_identified(path: &Path) -> io::Result<Option<LogId>> {
    let mut found = None;
    each_line(path, |line| {
        if line.contains(EV_IDENTIFIED)
            && let Some(id) = serde_json::from_str::<Value>(line)
                .ok()
                .filter(|v| is_event(v, EV_IDENTIFIED))
                .and_then(|v| id_of(&v))
        {
            found = Some(id);
        }
        true
    })?;
    Ok(found)
}
