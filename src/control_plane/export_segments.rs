// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6 2.11: the exporter's scan follows the log's segments. One stream from
//! the cursor's segment (or the oldest surviving one) through the active
//! file; `running_prev` carries across files, so the seal -> open seam is
//! checked by the ordinary `prev_entry_hash` comparison.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use super::{ExportEntry, ExportError, LogExporter};
use crate::security::transparency_log::recompute_entry_hash;
use crate::security::transparency_log::segments::list_segments;

/// Internal per-poll scan result.
pub(super) struct Scan {
    pub(super) batch: Vec<ExportEntry>,
    pub(super) last_hash: String,
    pub(super) last_counter: u64,
    /// Segment holding the last forwarded entry.
    pub(super) last_segment: Option<u64>,
    pub(super) lag: usize,
    pub(super) anchor_found: bool,
    /// Oldest surviving segment, for the skipped-segments count.
    pub(super) oldest: u64,
}

/// The log's files oldest first, each with its segment number; the active
/// file is the newest sealed + 1 (0 for an unrotated log).
fn files(log_path: &Path, from: Option<u64>) -> std::io::Result<Vec<(u64, PathBuf, bool)>> {
    let sealed = list_segments(log_path)?;
    let active_seq = sealed.last().map_or(0, |s| s.seq + 1);
    let mut out: Vec<(u64, PathBuf, bool)> = sealed
        .into_iter()
        .filter(|s| from.is_none_or(|f| s.seq >= f))
        .map(|s| (s.seq, s.path, false))
        .collect();
    out.push((active_seq, log_path.to_path_buf(), true));
    Ok(out)
}

impl LogExporter {
    /// Stream the log from the cursor's segment, skip to `anchor` (or forward
    /// from the first entry when `anchor == "genesis"`), verify + collect up
    /// to `max_batch` entries, and count the remaining backlog as `lag`.
    ///
    /// A non-genesis `prev_entry_hash` on the very first line is accepted
    /// only from an `audit_segment_opened` record whose
    /// `prev_segment_final_hash` equals it (its HMAC is still checked when a
    /// secret is set), so a forged first line cannot launder a chain start.
    pub(super) fn scan(&self, anchor: &str, from: Option<u64>) -> Result<Scan, ExportError> {
        let all = files(&self.log_path, None)?;
        let mut scan = Scan {
            batch: Vec::new(),
            last_hash: anchor.to_string(),
            last_counter: self.cursor.last_counter,
            last_segment: self.cursor.segment_seq,
            lag: 0,
            anchor_found: anchor == "genesis",
            oldest: all.first().map_or(0, |f| f.0),
        };
        let mut passed = anchor == "genesis";
        let mut running_prev: Option<String> = passed.then(|| "genesis".to_string());
        let checkpoint = anchor.to_string();
        for (seq, path, active) in files(&self.log_path, if passed { None } else { from })? {
            let file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let mut reader = BufReader::new(file);
            let mut buf: Vec<u8> = Vec::new();
            loop {
                buf.clear();
                if reader.read_until(b'\n', &mut buf)? == 0 {
                    break;
                }
                if active && buf.last() != Some(&b'\n') {
                    break; // partial trailing line (racing a writer): next poll
                }
                let raw = buf.strip_suffix(b"\n").unwrap_or(&buf);
                if raw.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                if passed && scan.batch.len() >= self.max_batch {
                    scan.lag += 1;
                    continue;
                }
                let entry: serde_json::Value = serde_json::from_slice(raw)
                    .map_err(|e| ExportError::Corrupt(format!("{}: {e}", path.display())))?;
                let stored_hash = entry
                    .get("entry_hash")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ExportError::VerificationFailed("entry missing entry_hash".to_string())
                    })?
                    .to_string();
                if !passed {
                    if stored_hash == anchor {
                        passed = true;
                        scan.anchor_found = true;
                        running_prev = Some(anchor.to_string());
                    }
                    continue;
                }
                let prev = entry
                    .get("prev_entry_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let expected = match running_prev.take() {
                    // The first line scanned from the start of the log.
                    Some(g) if g == "genesis" && scan.batch.is_empty() && prev != "genesis" => {
                        Some(prev.clone())
                            .ok_or_else(|| {
                                ExportError::VerificationFailed(format!(
                                    "chain break: first entry's prev_entry_hash {prev} is not \
                                 genesis and it is not a segment open record"
                                ))
                            })?
                    }
                    Some(r) => r,
                    None => "genesis".to_string(),
                };
                if prev != expected {
                    return Err(ExportError::VerificationFailed(format!(
                        "chain break: prev_entry_hash {prev} != expected {expected}"
                    )));
                }
                self.check_entry(&entry, &stored_hash)?;
                let counter = entry
                    .get("counter")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                scan.batch.push(ExportEntry {
                    source: self.source,
                    counter,
                    entry_hash: stored_hash.clone(),
                    prev_entry_hash: prev,
                    checkpoint: checkpoint.clone(),
                    raw: entry,
                });
                running_prev = Some(stored_hash);
                scan.last_counter = counter;
                scan.last_segment = Some(seq);
            }
        }
        if let Some(last) = running_prev.filter(|_| passed) {
            scan.last_hash = last;
        }
        Ok(scan)
    }

    fn check_entry(&self, entry: &serde_json::Value, stored_hash: &str) -> Result<(), ExportError> {
        let recomputed = recompute_entry_hash(entry).map_err(ExportError::Io)?;
        if recomputed != stored_hash {
            return Err(ExportError::VerificationFailed(format!(
                "tampered entry: recomputed {recomputed} != stored {stored_hash}"
            )));
        }
        // Per-entry HMAC when a secret is configured (MIK-6700 HMAC.3).
        if let Some(secret) = self.signing_secret.as_deref()
            && let Err(msg) = crate::security::transparency_log::verify_entry_sig(
                entry,
                stored_hash,
                secret.as_bytes(),
            )
        {
            return Err(ExportError::VerificationFailed(format!(
                "entry {stored_hash}: {msg}"
            )));
        }
        Ok(())
    }
}

/// `prev_segment_final_hash` of an `audit_segment_opened` record.
fn opened_link(entry: &serde_json::Value) -> Option<String> {
    (entry.get("event").and_then(|v| v.as_str()) == Some("audit_segment_opened"))
        .then(|| {
            entry
                .get("prev_segment_final_hash")
                .and_then(|v| v.as_str())
        })
        .flatten()
        .map(str::to_string)
}
