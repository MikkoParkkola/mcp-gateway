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
use super::segments::{self, Segment};

/// Names a log that has no segment open record to carry its id (a log
/// written before the id existed), and records the mint of one.
pub(crate) const EV_IDENTIFIED: &str = "audit_log_identified";

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
/// segment (nothing sealed), whose open record carries an id that the next
/// record does not name. A crash between the genesis open record (and its
/// first mark) and the identified record leaves exactly this, because the
/// fresh-log path writes the identified record second; so the first two
/// lines decide it, cheaply, on every recovery. A beta log's open record has
/// no id (it mints instead), and a log whose identified record retention
/// expired has sealed segments, so neither is repaired.
///
/// # Errors
///
/// The active file cannot be read.
pub(super) fn unfinished_genesis(path: &Path, sealed: &[Segment]) -> io::Result<bool> {
    if !sealed.is_empty() {
        return Ok(false);
    }
    let mut head: Vec<Option<Value>> = Vec::with_capacity(2);
    each_line(path, |line| {
        if !line.trim().is_empty() {
            head.push(serde_json::from_str(line.trim()).ok());
        }
        head.len() < 2
    })?;
    let parsed = |i: usize| head.get(i).and_then(Option::as_ref);
    let genesis_with_id = parsed(0).is_some_and(|v| {
        is_event(v, EV_OPENED)
            && v.get("segment_seq").and_then(Value::as_u64) == Some(0)
            && id_of(v).is_some()
    });
    Ok(genesis_with_id && !parsed(1).is_some_and(|v| is_event(v, EV_IDENTIFIED)))
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
/// ponytail: a full scan per open, and only a log whose open record has no
/// id reaches it; index the id in the open record's successor if it shows.
fn newest_identified(path: &Path) -> io::Result<Option<LogId>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let (mut reader, mut buf, mut found) = (BufReader::new(file), Vec::new(), None);
    while reader.read_until(b'\n', &mut buf)? > 0 {
        let line = String::from_utf8_lossy(&buf);
        if line.contains(EV_IDENTIFIED)
            && let Some(id) = serde_json::from_str::<Value>(&line)
                .ok()
                .filter(|v| is_event(v, EV_IDENTIFIED))
                .and_then(|v| id_of(&v))
        {
            found = Some(id);
        }
        buf.clear();
    }
    Ok(found)
}
