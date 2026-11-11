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

/// The open-record field of a new genesis whose predecessor is gone, naming
/// what evidence of it survived: `previous_log_id` when a live logger held
/// the old id, `previous_high_water` (`counter`, `entry_hash`) when the old
/// `.hwm` survived. Written in the open record that sets the new id, so no
/// crash can keep the one without the other. Absent without evidence: an
/// offline deletion of the active file and `.hwm` with nothing sealed leaves
/// no identity or anchor to name (the lease and filesystem metadata are not
/// identity evidence), so it reads as a first start; an operator-kept anchor
/// (a pinned high-water mark) detects it.
pub(crate) const PREDECESSOR_MISSING: &str = "predecessor_missing";

/// Retired: once a separate record carrying a lost predecessor's evidence,
/// which now lives in the open record's `predecessor_missing` field. The
/// name stays reserved so no caller can forge a record that once meant
/// tamper evidence.
const EV_PREDECESSOR_RETIRED: &str = "audit_log_predecessor_missing";

/// Events only the logger writes (or, once retired, no one); a caller naming
/// one is refused. Open records, and so their `predecessor_missing` field,
/// are reserved with every `audit_segment_*` event.
pub(crate) const RESERVED_EVENTS: [&str; 2] = [EV_IDENTIFIED, EV_PREDECESSOR_RETIRED];

/// An audit log's identity. Opaque: compare, display, never parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogId(String);

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidLogId;

impl LogId {
    #[cfg(test)]
    pub(crate) fn from_journal(text: String) -> Result<Self, InvalidLogId> {
        if text.is_empty() || text.len() > 1024 {
            return Err(InvalidLogId);
        }
        Ok(Self(text))
    }
}

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

/// Whether the active file is a genesis left unfinished: nothing is sealed,
/// line 1 is an open record carrying an id and linking to no sealed segment
/// (a genesis, at segment 0 or continuing a surviving `.hwm`'s segment), and
/// no identified record in the file names that id. A crash between the
/// genesis open record and the identified record leaves this, and so does a
/// torn identified record, whose drop recovery records in its place: so the
/// whole file is searched. A beta log's open record has no id (it mints
/// instead). A rotation's open record links to the segment it follows, so a
/// log whose identified record expired with its segment is never repaired,
/// even once the disk-full path has expired every sealed segment.
///
/// Accepted exception: an upgraded beta log whose active file was lost mints
/// its id onto the open record that continues its (id-less) sealed segments,
/// which links to them; killed before its identified record, it keeps that id
/// on every reopen and never gains the record.
///
/// # Errors
///
/// The active file cannot be read.
pub(super) fn unfinished_genesis(path: &Path, sealed: &[Segment]) -> io::Result<bool> {
    if !sealed.is_empty() {
        return Ok(false);
    }
    // The genesis's id once line 1 shows one, then whether a record names it.
    let (mut first, mut genesis, mut named) = (true, None::<LogId>, false);
    each_line(path, |line| {
        let line = line.trim();
        if line.is_empty() {
            return true;
        }
        let v = serde_json::from_str::<Value>(line).ok();
        if std::mem::take(&mut first) {
            genesis = v
                .filter(|v| is_event(v, EV_OPENED) && v.get("prev_segment_seq").is_none())
                .and_then(|v| id_of(&v));
            return genesis.is_some();
        }
        named = v.is_some_and(|v| is_event(&v, EV_IDENTIFIED) && id_of(&v) == genesis);
        !named
    })?;
    Ok(genesis.is_some() && !named)
}

/// The identity fields of an open record: its `log_id`, and the evidence of
/// a lost predecessor when there is any.
pub(super) fn open_fields(id: &LogId, predecessor: Option<Value>) -> Vec<(&'static str, Value)> {
    let mut fields = vec![("log_id", id.as_str().into())];
    fields.extend(predecessor.map(|p| (PREDECESSOR_MISSING, p)));
    fields
}

/// What survived of a lost predecessor, or `None` when nothing did. Only
/// evidence held is named; an absent part is never invented.
pub(super) fn predecessor_evidence(
    held: Option<&LogId>,
    mark: Option<&HighWater>,
) -> Option<Value> {
    let mut evidence = serde_json::Map::new();
    if let Some(id) = held {
        evidence.insert("previous_log_id".into(), id.as_str().into());
    }
    if let Some(h) = mark {
        let hw = serde_json::json!({ "counter": h.counter, "entry_hash": h.entry_hash });
        evidence.insert("previous_high_water".into(), hw);
    }
    (!evidence.is_empty()).then_some(Value::Object(evidence))
}

/// Verify's warning for a log whose oldest file opens with a record naming a
/// lost predecessor. `checked` is that first record as the chain checks
/// parsed and authenticated it: the warning is built from it alone, verified,
/// so nothing read later can change what it says. When the checks did not
/// reach or pass that record (a log that fails them still reports its
/// predecessor), the file's first line is read here and the warning is
/// always labelled "unverified".
///
/// # Errors
///
/// The file cannot be read.
pub(super) fn predecessor_warning(
    path: &Path,
    checked: Option<&Value>,
) -> io::Result<Option<String>> {
    if let Some(head) = checked {
        return Ok(warning_for(path, head, true));
    }
    let head = match segments::read_first_line(path) {
        Ok(line) => line.and_then(|l| serde_json::from_str::<Value>(&l).ok()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };
    Ok(head.and_then(|v| warning_for(path, &v, false)))
}

/// The warning for `head`, if it is an open record naming a predecessor.
fn warning_for(path: &Path, head: &Value, verified: bool) -> Option<String> {
    let evidence = Some(head)
        .filter(|v| is_event(v, EV_OPENED))?
        .get(PREDECESSOR_MISSING)?;
    let how = if verified {
        ""
    } else {
        " (unverified: the chain check did not authenticate this record)"
    };
    Some(format!(
        "{} starts a new log after its predecessor went missing{how}: {}",
        path.display(),
        evidence_text(evidence)
    ))
}

/// The evidence a `predecessor_missing` field names, as text; an object
/// naming neither part reads as "no evidence fields".
fn evidence_text(evidence: &Value) -> String {
    let mut named = Vec::new();
    if let Some(id) = evidence.get("previous_log_id").and_then(Value::as_str) {
        named.push(format!("previous log_id {id}"));
    }
    if let Some(hw) = evidence.get("previous_high_water") {
        let counter = hw.get("counter").and_then(Value::as_u64).unwrap_or(0);
        let hash = hw.get("entry_hash").and_then(Value::as_str).unwrap_or("");
        named.push(format!(
            "previous high-water mark at counter {counter} ({hash})"
        ));
    }
    if named.is_empty() {
        return "no evidence fields".to_string();
    }
    named.join(", ")
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
