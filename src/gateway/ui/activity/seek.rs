// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Find one record by its counter without scanning. Counters only grow, so
//! the segment is the last one whose first record is at or below the counter,
//! and inside it the record is found by halving the file by byte offset and
//! resynchronising to the next line: O(log n) reads whatever the record's age.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::security::transparency_log::pager::ASSEMBLY_WINDOW;
use crate::security::transparency_log::segments::{list_segments, sealed_path};

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

/// The first line start at or after `from`.
fn next_line_start(file: &mut File, from: u64, reads: &mut Reads) -> io::Result<Option<u64>> {
    if from == 0 {
        return Ok(Some(0));
    }
    // The byte before `from` decides: a newline there makes `from` a start.
    Ok(line_at(file, from - 1, reads)?.map(|(_, end)| end))
}

fn counter_of(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<Value>(bytes)
        .ok()?
        .get("counter")?
        .as_u64()
}

/// The log's files, oldest first: `(segment, path)`.
fn files(log: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let sealed = list_segments(log)?;
    let active = sealed.last().map_or(0, |s| s.seq + 1);
    let mut files: Vec<(u64, PathBuf)> = sealed
        .iter()
        .map(|s| (s.seq, sealed_path(log, s.seq)))
        .collect();
    files.push((active, log.to_path_buf()));
    Ok(files)
}

/// The record numbered `counter` in `log`, if the kept log holds it.
pub(super) fn seek(log: &Path, counter: u64, reads: &mut Reads) -> io::Result<Option<Found>> {
    let mut chosen = None;
    for (segment, path) in files(log)? {
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
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
        let Some((bytes, end)) = line_at(&mut file, start, reads)? else {
            hi = mid;
            continue;
        };
        match counter_of(&bytes) {
            Some(c) if c == counter => {
                let entry = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
                return Ok(Some(Found { entry, segment }));
            }
            Some(c) if c < counter => lo = end,
            Some(_) => hi = start,
            // An unreadable line: look on both sides of it in turn.
            None => {
                if start > lo {
                    hi = start;
                } else {
                    lo = end;
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
#[path = "seek_tests.rs"]
mod tests;
