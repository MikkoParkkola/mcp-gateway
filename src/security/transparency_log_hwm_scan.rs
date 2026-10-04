// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a restart finds a missing high-water mark recorded (#2294): the
//! scan recovery trusts only over records that verify.

use std::fs::File;
use std::io;
use std::path::Path;

use serde_json::Value;

use super::rotation::{
    EV_HWM_MISSING, EV_OPENED, EV_TORN, HWM_MISSING_AT, MAX_RECORD_BYTES, TORN_COMMITTED,
    record_head,
};
use super::segments::{self, HighWater, Segment};
use super::{TransparencyLogConfig, recompute_entry_hash, verify_entry_sig};

/// The earliest missing-mark counter `file` records: an [`EV_HWM_MISSING`]
/// record, a committed [`EV_TORN`] record (MIK-7712), or an open record
/// carrying [`HWM_MISSING_AT`] (#2294).
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
            Some(EV_TORN) if v.get(TORN_COMMITTED).and_then(Value::as_bool) == Some(true) => {
                note(counter);
            }
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

/// Whether the newest surviving record `(counter, hash)` contradicts the
/// authenticated mark `hw` (MIK-7884). Counters are global and monotone across
/// segments and `.hwm` is written after its record, so an honest tail is never
/// below the mark, in any segment, and at the mark's counter it is the mark's
/// record. A tail behind the mark lost committed records (or is an older file
/// restored); one at the mark with another hash was replaced. Either way
/// re-minting `.hwm` from it would launder the change, signed log or not.
pub(super) fn contradicts(hw: Option<&HighWater>, counter: u64, hash: &str) -> bool {
    hw.is_some_and(|h| counter < h.counter || (counter == h.counter && hash != h.entry_hash))
}

/// [`contradicts`], and, when the tail is ahead of the mark, whether the
/// record the mark names is still there as the mark recorded it (MIK-7884).
/// A restart that repaired a torn suffix, or a mark that lags its record by a
/// crash, leaves the tail ahead of a record that may have been replaced; the
/// next append would carry the replacement forward unnoticed.
pub(super) fn contradicted(
    path: &Path,
    sealed: &[Segment],
    hw: Option<&HighWater>,
    counter: u64,
    hash: &str,
    config: &TransparencyLogConfig,
) -> io::Result<bool> {
    let Some(h) = hw else {
        return Ok(false);
    };
    if contradicts(hw, counter, hash) {
        return Ok(true);
    }
    if counter == h.counter {
        return Ok(false);
    }
    // The mark's record is the newest one when the mark was written: in the
    // active file, or at the end of the sealed segment the mark names.
    let named = sealed.iter().find(|s| s.seq == h.segment_seq);
    for file in std::iter::once(path).chain(named.map(|s| s.path.as_path())) {
        if let Some(contradicts) = record_at_mark(file, h, config)? {
            return Ok(contradicts);
        }
    }
    // Neither file holds the record the mark names.
    Ok(true)
}

/// Whether the record at `h.counter` in `file` contradicts the mark, or `None`
/// when `file` is missing or holds no record at that counter.
///
/// Read with the scan's line bound: a line over [`MAX_RECORD_BYTES`] is a
/// finding, as [`hwm_missing_in`] counts it, and is never held whole. The
/// record is judged on its content: its stored `entry_hash` must equal the
/// mark's, recompute from the record, and carry a valid signature when a
/// secret is set. An edit that keeps the stored hash is otherwise accepted
/// here, and retention later expires the edited record with nothing recorded.
fn record_at_mark(
    file: &Path,
    h: &HighWater,
    config: &TransparencyLogConfig,
) -> io::Result<Option<bool>> {
    use std::io::{BufRead, Read};
    let mut reader = match File::open(file) {
        Ok(f) => io::BufReader::new(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(segments::ctx("read", file)(e)),
    };
    let secret = config.shared_secret.as_bytes();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = (&mut reader)
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(segments::ctx("read", file))?;
        if n == 0 {
            return Ok(None);
        }
        if buf.last() != Some(&b'\n') && buf.len() > MAX_RECORD_BYTES {
            return Ok(Some(true));
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            continue;
        };
        let Ok((counter, stored, _, v)) = record_head(line.trim()) else {
            continue;
        };
        if counter == h.counter {
            let intact = recompute_entry_hash(&v).is_ok_and(|x| x == stored)
                && (secret.is_empty() || verify_entry_sig(&v, &stored, secret).is_ok());
            return Ok(Some(stored != h.entry_hash || !intact));
        }
    }
}
