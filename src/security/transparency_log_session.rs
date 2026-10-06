// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The session reader: every entry of one session across the sealed
//! segments and the active file.

use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tracing::warn;

#[cfg(test)]
use super::{AFTER_STREAM, BEFORE_STREAM, LISTED, PASSES, fire};
use super::{changed_under_reader, existing_log_files, log_files, seqs};
use crate::security::transparency_log::{MAX_AUDIT_READ_BYTES, bounded_read_to_string};

/// Every entry whose `session_id` is `session` or, since F9, its
/// fingerprint, oldest first, across the sealed segments and the active file.
///
/// # Errors
///
/// `NotFound` when neither the log nor any sealed segment exists, or a
/// segment cannot be read.
pub fn show_session_entries(path: &Path, session: &str) -> io::Result<Vec<Value>> {
    let fp = crate::gateway::session_id::session_fp(session);
    let mut attempt = 0;
    loop {
        #[cfg(test)]
        {
            PASSES.with(|c| c.set(c.get() + 1));
            fire(&BEFORE_STREAM);
        }
        let files = existing_log_files(path)?;
        #[cfg(test)]
        fire(&LISTED);
        let read = matching_entries(&files, session, &fp);
        #[cfg(test)]
        fire(&AFTER_STREAM);
        // Growth leaves the file list as it was; only a rotation changes it.
        let stable = seqs(&files) == seqs(&log_files(path)?);
        match read {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
            Ok(found) if stable => return Ok(found),
            Ok(_) => {}
        }
        if attempt == 1 {
            return Err(changed_under_reader("reading"));
        }
        attempt += 1;
    }
}

/// One pass of [`show_session_entries`] over `files`.
fn matching_entries(
    files: &[(Option<u64>, PathBuf)],
    session: &str,
    fp: &str,
) -> io::Result<Vec<Value>> {
    let mut results = Vec::new();
    for (_, file) in files {
        let content = bounded_read_to_string(file, MAX_AUDIT_READ_BYTES)?;
        for raw in content.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str::<Value>(raw.trim()) {
                Ok(entry)
                    if entry
                        .get("session_id")
                        .and_then(Value::as_str)
                        .is_some_and(|s| s == session || s == fp) =>
                {
                    results.push(entry);
                }
                Ok(_) => {}
                Err(e) => warn!("transparency log: skipping malformed line: {e}"),
            }
        }
    }
    Ok(results)
}
