// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Find one record by its counter without scanning. Counters only grow, so
//! the segment is the last one whose first record is at or below the counter,
//! and inside it the record is found by halving the file by byte offset and
//! resynchronising to the next line: O(log n) reads whatever the record's age.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use serde_json::Value;

use crate::security::transparency_log::pager::{ASSEMBLY_WINDOW, open_segment};
use crate::security::transparency_log::segments::listing;

/// How much one forward read takes while looking for a line's end.
const CHUNK: u64 = 64 * 1024;

/// A record found by [`seek`]: its entry, and where it sits.
#[derive(Debug)]
pub(super) struct Found {
    pub(super) entry: Value,
    pub(super) segment: u64,
}

/// Reads made, for the O(log n) test.
#[derive(Debug, Default)]
pub(super) struct Reads(pub(super) usize);

/// The line starting at `start`: its bytes and the offset after its newline.
/// `None` at the end of the file, or for a line with no newline within the
/// record cap (a torn or over-cap line), which is never served.
fn line_at(file: &mut File, start: u64, reads: &mut Reads) -> io::Result<Option<(Vec<u8>, u64)>> {
    let mut line = Vec::new();
    let mut at = start;
    file.seek(SeekFrom::Start(start))?;
    while u64::try_from(line.len()).unwrap_or(u64::MAX) < ASSEMBLY_WINDOW {
        let mut chunk = vec![0u8; usize::try_from(CHUNK).unwrap_or(usize::MAX)];
        let n = file.read(&mut chunk)?;
        reads.0 += 1;
        if n == 0 {
            return Ok(None);
        }
        chunk.truncate(n);
        if let Some(nl) = chunk.iter().position(|b| *b == b'\n') {
            line.extend_from_slice(&chunk[..nl]);
            at += u64::try_from(nl).unwrap_or(u64::MAX) + 1;
            return Ok(Some((line, at)));
        }
        line.extend_from_slice(&chunk);
        at += u64::try_from(n).unwrap_or(u64::MAX);
    }
    Ok(None)
}

/// The offset after the next newline at or after `from`, however far it is:
/// a line over the record cap is stepped over, never held whole.
fn after_next_newline(file: &mut File, from: u64, reads: &mut Reads) -> io::Result<Option<u64>> {
    file.seek(SeekFrom::Start(from))?;
    let mut at = from;
    let mut chunk = vec![0u8; usize::try_from(CHUNK).unwrap_or(usize::MAX)];
    loop {
        let n = file.read(&mut chunk)?;
        reads.0 += 1;
        if n == 0 {
            return Ok(None);
        }
        if let Some(nl) = chunk[..n].iter().position(|b| *b == b'\n') {
            return Ok(Some(at + u64::try_from(nl).unwrap_or(u64::MAX) + 1));
        }
        at += u64::try_from(n).unwrap_or(u64::MAX);
    }
}

/// The first line start at or after `from`.
fn next_line_start(file: &mut File, from: u64, reads: &mut Reads) -> io::Result<Option<u64>> {
    if from == 0 {
        return Ok(Some(0));
    }
    // The byte before `from` decides: a newline there makes `from` a start.
    after_next_newline(file, from - 1, reads)
}

/// The first readable line at or after `start` and below `hi`, with its
/// counter and the offset after it. Unreadable lines in between (torn,
/// hand-edited, over the cap) are stepped over, so a bad line never hides
/// the records after it.
fn first_readable(
    file: &mut File,
    start: u64,
    hi: u64,
    reads: &mut Reads,
) -> io::Result<Option<(u64, Vec<u8>, u64)>> {
    let mut at = start;
    while at < hi {
        match line_at(file, at, reads)? {
            Some((bytes, end)) => match counter_of(&bytes) {
                Some(c) => return Ok(Some((c, bytes, end))),
                None => at = end,
            },
            None => match after_next_newline(file, at, reads)? {
                Some(end) => at = end,
                None => return Ok(None),
            },
        }
    }
    Ok(None)
}

fn counter_of(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Value>(bytes)
        .ok()?
        .get("counter")?
        .as_u64()
}

/// The log's segments, oldest first, the active file's included when it
/// exists.
fn segments(log: &Path) -> io::Result<Vec<u64>> {
    let files = listing(log)?;
    let mut segments: Vec<u64> = files.sealed.iter().map(|s| s.seq).collect();
    segments.extend(files.active);
    Ok(segments)
}

/// The counter of the oldest record the kept log holds.
pub(super) fn oldest_counter(log: &Path, reads: &mut Reads) -> io::Result<Option<u64>> {
    for segment in segments(log)? {
        let Some(mut file) = open_segment(log, segment, || {})? else {
            continue;
        };
        let len = file.metadata()?.len();
        if let Some((c, _, _)) = first_readable(&mut file, 0, len, reads)? {
            return Ok(Some(c));
        }
    }
    Ok(None)
}

/// The record numbered `counter` in `log`, if the kept log holds it.
pub(super) fn seek(log: &Path, counter: u64, reads: &mut Reads) -> io::Result<Option<Found>> {
    let mut chosen = None;
    for segment in segments(log)? {
        let Some(mut file) = open_segment(log, segment, || {})? else {
            continue;
        };
        match line_at(&mut file, 0, reads)?.and_then(|(l, _)| counter_of(&l)) {
            Some(first) if first <= counter => chosen = Some((segment, file)),
            Some(_) => break,
            None => {}
        }
    }
    let Some((segment, mut file)) = chosen else {
        return Ok(None);
    };
    let (mut lo, mut hi) = (0_u64, file.metadata()?.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let Some(start) = next_line_start(&mut file, mid, reads)? else {
            hi = mid;
            continue;
        };
        if start >= hi {
            hi = mid;
            continue;
        }
        match first_readable(&mut file, start, hi, reads)? {
            Some((c, bytes, _)) if c == counter => {
                let entry = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                return Ok(Some(Found { entry, segment }));
            }
            Some((c, _, end)) if c < counter => lo = end,
            // Above the target, or nothing readable up to `hi`: the target,
            // if kept, starts below `start`.
            _ => hi = start,
        }
    }
    Ok(None)
}

#[cfg(test)]
#[path = "seek_tests.rs"]
mod tests;
