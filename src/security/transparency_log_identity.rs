// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The audit log's stable identity: one `log_id`, minted once, carried by
//! every segment open record, so a record kept elsewhere can name the log it
//! was meant for. Records hold the id only: no paths, values or secrets.

use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use serde_json::Value;

use super::rotation::EV_OPENED;
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
