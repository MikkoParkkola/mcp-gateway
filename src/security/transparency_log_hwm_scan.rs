// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a restart finds a missing high-water mark recorded (#2294): the
//! scan recovery trusts only over records that verify.

use std::fs::File;
use std::io;
use std::path::Path;

use serde_json::Value;

use super::rotation::{EV_HWM_MISSING, EV_OPENED, HWM_MISSING_AT, MAX_RECORD_BYTES};
use super::segments::{self, Segment};
use super::{TransparencyLogConfig, recompute_entry_hash, verify_entry_sig};

/// The earliest missing-mark counter `file` records: an [`EV_HWM_MISSING`]
/// record, or an open record carrying [`HWM_MISSING_AT`] (#2294).
///
/// Absence is accepted only from a file that checks out: every line is
/// parsed (a raw-text match is defeated by a JSON escape), its hash
/// recomputed, its signature checked when a secret is set (as verify does),
/// and each record
/// linked to the one before. A line that fails any of these, or is over
/// [`MAX_RECORD_BYTES`], counts as a finding at that point: an edit that
/// hides the marker must not also erase it. A blank line is skipped, as
/// verify skips it. A missing file holds no finding.
pub(super) fn hwm_missing_in(
    file: &Path,
    config: &TransparencyLogConfig,
) -> io::Result<Option<u64>> {
    use std::io::{BufRead, Read};
    let mut reader = match File::open(file) {
        Ok(f) => io::BufReader::new(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(segments::ctx("read", file)(e)),
    };
    let read_err = |e| segments::ctx("read", file)(e);
    let secret = config.shared_secret.as_bytes();
    let mut earliest: Option<u64> = None;
    let mut note = |at: u64| earliest = Some(earliest.map_or(at, |e: u64| e.min(at)));
    // Counter and hash of the previous record; the first has no link here.
    let mut prev: Option<(u64, String)> = None;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = (&mut reader)
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(read_err)?;
        if n == 0 {
            break;
        }
        let next = prev.as_ref().map_or(0, |p| p.0 + 1);
        if buf.last() != Some(&b'\n') && buf.len() > MAX_RECORD_BYTES {
            reader.skip_until(b'\n').map_err(read_err)?;
            note(next);
            continue;
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            note(next);
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(v) = serde_json::from_str::<Value>(line).ok() else {
            note(next);
            continue;
        };
        let counter = v.get("counter").and_then(Value::as_u64).unwrap_or(next);
        let stored = v.get("entry_hash").and_then(Value::as_str).unwrap_or("");
        // The first record opens the segment, or is a pre-D6 genesis record;
        // anything else means the head was cut.
        let linked = match prev.as_ref() {
            Some((c, h)) => {
                counter == c + 1 && v.get("prev_entry_hash").and_then(Value::as_str) == Some(h)
            }
            None => {
                v.get("event").and_then(Value::as_str) == Some(EV_OPENED)
                    || (counter == 1
                        && v.get("prev_entry_hash").and_then(Value::as_str) == Some("genesis"))
            }
        };
        let intact = linked
            && recompute_entry_hash(&v).is_ok_and(|h| h == stored)
            && (secret.is_empty() || verify_entry_sig(&v, stored, secret).is_ok());
        if !intact {
            note(counter);
        }
        match v.get("event").and_then(Value::as_str) {
            Some(EV_HWM_MISSING) => note(counter),
            Some(EV_OPENED) => {
                if let Some(at) = v.get(HWM_MISSING_AT).and_then(Value::as_u64) {
                    note(at);
                }
            }
            _ => {}
        }
        prev = Some((counter, stored.to_string()));
    }
    Ok(earliest)
}

/// The finding the newest sealed segment holds, for the open record that
/// follows it.
pub(super) fn newest_finding(
    sealed: &[Segment],
    config: &TransparencyLogConfig,
) -> io::Result<Option<u64>> {
    sealed
        .last()
        .map_or(Ok(None), |s| hwm_missing_in(&s.path, config))
}
