// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Paging a transparency log backward, newest first: where a cursor points
//! across rotated segments, one bounded tail window, and its lines. The one
//! paging engine every reader of the log shares; a reader adds only what it
//! does with a line.

use std::io;
use std::path::{Path, PathBuf};

use super::rotation::MAX_RECORD_BYTES;
use super::segments::{active_segment_seq, list_segments, sealed_path, segment_seq_in};

/// Where a page starts reading: bytes below `end` in `file` are unread.
pub(crate) struct Position {
    pub(crate) file: PathBuf,
    pub(crate) end: u64,
    /// The segment `file` is, the active file included; `None` never occurs
    /// for a resolved position but stays in the cursor shape callers keep.
    pub(crate) segment: Option<u64>,
    /// The cursor no longer named a position, so reading restarts at the
    /// newest record.
    pub(crate) reset: bool,
}

/// Resolve a cursor `(offset, segment)` on `log`. No cursor starts at the end
/// of the active file; a segment cursor names its file by number (a rename
/// never changes a segment's bytes); an offset-only cursor from before
/// rotation is honoured only while nothing is sealed.
pub(crate) fn position(log: &Path, cursor: Option<(u64, Option<u64>)>) -> io::Result<Position> {
    let sealed = list_segments(log)?;
    // The active file's own open record names its number: retention or the
    // disk-full path can leave no sealed sibling to count from.
    let active_seq = active_segment_seq(log, sealed.last().map_or(0, |s| s.seq + 1));
    let len_of = |p: &Path| match std::fs::metadata(p) {
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    };
    let newest = |reset| -> io::Result<Position> {
        Ok(Position {
            file: log.to_path_buf(),
            end: len_of(log)?,
            segment: Some(active_seq),
            reset,
        })
    };
    match cursor {
        None => newest(false),
        Some((offset, None)) if sealed.is_empty() => Ok(Position {
            file: log.to_path_buf(),
            end: offset.min(len_of(log)?),
            segment: Some(0),
            reset: false,
        }),
        Some((_, None)) => {
            tracing::warn!(
                "pre-rotation audit cursor after a rotation: restarting at the newest record"
            );
            newest(true)
        }
        Some((offset, Some(seq))) => {
            let file = if seq == active_seq {
                log.to_path_buf()
            } else {
                sealed_path(log, seq)
            };
            let end = offset.min(len_of(&file)?);
            Ok(Position {
                file,
                end,
                segment: Some(seq),
                reset: false,
            })
        }
    }
}

/// The `(end offset, segment)` of the segment older than `segment`, if any
/// survives retention.
pub(crate) fn older_segment(log: &Path, segment: Option<u64>) -> io::Result<Option<(u64, u64)>> {
    let Some(seq) = segment else { return Ok(None) };
    let older = list_segments(log)?.into_iter().rev().find(|s| s.seq < seq);
    Ok(match older {
        Some(s) => Some((std::fs::metadata(&s.path)?.len(), s.seq)),
        None => None,
    })
}

/// Read `len` bytes starting at `start`. A log file that was never created
/// reads as empty, matching a view with no events yet.
pub(crate) fn read_window(path: &Path, start: u64, len: u64) -> io::Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    match std::fs::File::open(path) {
        Ok(file) => read_window_in(&file, start, len),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Open segment `seq` of `log` for reading. The active file is opened by name
/// and then checked: if rotation sealed it meanwhile, the sealed file holds
/// its bytes, so that is the one read; in the gap where rotation has renamed
/// the active file but not yet created the next, its bytes are under the
/// sealed name too. `None` when neither exists. `before_open` runs just
/// before the open: a test's seam to rotate in that window.
pub(crate) fn open_segment(
    log: &Path,
    seq: u64,
    before_open: impl FnOnce(),
) -> io::Result<Option<std::fs::File>> {
    let sealed_now =
        || -> io::Result<bool> { Ok(list_segments(log)?.iter().any(|s| s.seq == seq)) };
    let path = if sealed_now()? {
        sealed_path(log, seq)
    } else {
        log.to_path_buf()
    };
    before_open();
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return if path == log && sealed_now()? {
                std::fs::File::open(sealed_path(log, seq)).map(Some)
            } else {
                Ok(None)
            };
        }
        Err(e) => return Err(e),
    };
    if path == log && sealed_now()? {
        return std::fs::File::open(sealed_path(log, seq)).map(Some);
    }
    // Opened by the active name: it must hold `seq`. Retention can delete a
    // sealed segment after a cursor into it was resolved, and the active file
    // then holds a later segment, whose bytes are not the ones asked for.
    if path == log && active_seq_of(&file, log)? != seq {
        return Ok(None);
    }
    Ok(Some(file))
}

/// The segment the open active file holds, read from that descriptor by the
/// same rule as [`active_segment_seq`]: its open record, or for a log written
/// before open records, the newest sealed segment plus one.
fn active_seq_of(file: &std::fs::File, log: &Path) -> io::Result<u64> {
    let after = list_segments(log)?.last().map_or(0, |s| s.seq + 1);
    segment_seq_in(file, after)
}

/// [`read_window`] on a file already open. A reader that holds the handle
/// keeps reading the same bytes when rotation renames the file under it.
pub(crate) fn read_window_in(file: &std::fs::File, start: u64, len: u64) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = file;
    file.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// One tail window of at most `max` bytes ending at `end`, trimmed to whole
/// lines.
pub(crate) enum Tail {
    /// The window's complete lines, starting at byte `start` of the file.
    Lines {
        start: u64,
        window: Vec<u8>,
        from: usize,
    },
    /// A full window held no line start: one line is longer than `max`.
    LineTooLong,
}

impl Tail {
    /// The complete lines of a [`Tail::Lines`], or nothing.
    pub(crate) fn body(&self) -> &[u8] {
        match self {
            Self::Lines { window, from, .. } => &window[*from..],
            Self::LineTooLong => &[],
        }
    }
}

/// Read the tail window below `end` in `file`. A window that starts mid-line
/// drops that partial head; the line it belongs to is read by the page that
/// covers the bytes below. Returns the window and the bytes it spans.
pub(crate) fn tail_window(file: &Path, end: u64, max: u64) -> io::Result<(Tail, u64)> {
    let window_len = end.min(max);
    let window = read_window(file, end - window_len, window_len)?;
    Ok(split_tail(window, end))
}

/// The longest window line assembly reads: the newline ending the line
/// before, and one record at the logger's cap. The cap counts the record's own
/// newline (the logger refuses `line.len() + 1 > MAX_RECORD_BYTES`), so one
/// byte more than the cap holds both.
pub(crate) const ASSEMBLY_WINDOW: u64 = MAX_RECORD_BYTES as u64 + 1;

/// [`tail_window`] on an open file, with line assembly: when no line starts
/// inside `max`, the window is read again at [`ASSEMBLY_WINDOW`], so a line
/// up to the record cap is returned whole. [`Tail::LineTooLong`] then means a
/// line over the cap, which the logger never writes, wherever it sits: a
/// window that starts at byte 0 has no newline before its first line, so that
/// line's length is checked against the cap too. The bytes returned count
/// both reads.
pub(crate) fn tail_window_assembled(
    file: &std::fs::File,
    end: u64,
    max: u64,
) -> io::Result<(Tail, u64)> {
    let read = |len: u64| -> io::Result<(Tail, u64)> {
        let len = end.min(len);
        Ok(split_tail(read_window_in(file, end - len, len)?, end))
    };
    match read(max)? {
        (Tail::LineTooLong, first) if max < ASSEMBLY_WINDOW => {
            let (tail, second) = read(ASSEMBLY_WINDOW)?;
            Ok((over_cap_at_start(tail), first + second))
        }
        done => Ok(done),
    }
}

/// A window starting at byte 0 counts as starting on a line, so its first line
/// is never `LineTooLong` by position; one longer than the record cap is.
fn over_cap_at_start(tail: Tail) -> Tail {
    match &tail {
        Tail::Lines {
            start: 0, window, ..
        } => {
            let first = window
                .iter()
                .position(|b| *b == b'\n')
                .map_or(window.len(), |nl| nl + 1);
            if first > MAX_RECORD_BYTES {
                Tail::LineTooLong
            } else {
                tail
            }
        }
        _ => tail,
    }
}

/// Trim `window`, the bytes ending at `end`, to whole lines.
fn split_tail(window: Vec<u8>, end: u64) -> (Tail, u64) {
    let window_len = u64::try_from(window.len()).unwrap_or(u64::MAX);
    let window_start = end - window_len;
    let from = if window_start == 0 {
        0
    } else {
        match window.iter().position(|b| *b == b'\n') {
            Some(nl) => nl + 1,
            None => window.len(),
        }
    };
    if window_start > 0 && from == window.len() {
        return (Tail::LineTooLong, window_len);
    }
    let start = window_start + u64::try_from(from).unwrap_or(u64::MAX);
    (
        Tail::Lines {
            start,
            window,
            from,
        },
        window_len,
    )
}

/// The lines of `body`, which starts on a line boundary at byte `body_start`,
/// newest first, each with its absolute byte offset.
pub(crate) fn lines_newest_first(body: &[u8], body_start: u64) -> Vec<(u64, &[u8])> {
    let mut lines = Vec::new();
    let mut offset = 0usize;
    for line in body.split(|b| *b == b'\n') {
        lines.push((body_start + u64::try_from(offset).unwrap_or(u64::MAX), line));
        offset += line.len() + 1;
    }
    lines.reverse();
    lines
}

#[cfg(test)]
mod tests {
    use super::{open_segment, position, sealed_path};

    /// Every sealed segment expired (retention or the disk-full path): the
    /// active file is numbered by its open record, not by counting siblings.
    #[test]
    fn the_active_segment_is_numbered_by_its_open_record() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let opened = serde_json::json!({"event": "audit_segment_opened", "segment_seq": 7});
        std::fs::write(&log, format!("{opened}\n")).unwrap();
        assert_eq!(position(&log, None).unwrap().segment, Some(7));
        // A cursor into that segment resolves to the active file.
        let at = position(&log, Some((3, Some(7)))).unwrap();
        assert_eq!(at.file, log);
        assert!(!at.reset);
    }

    /// Retention deletes a sealed segment after `position` resolved a cursor
    /// into it. Opening that segment then finds it under neither name, and
    /// must not hand back the active file, which is a different segment.
    #[test]
    fn a_segment_removed_after_resolving_is_not_replaced_by_the_active_file() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        let sealed = sealed_path(&log, 3);
        let opened =
            |seq: u64| serde_json::json!({"event": "audit_segment_opened", "segment_seq": seq});
        std::fs::write(&sealed, format!("{}\n{{\"a\":1}}\n", opened(3))).unwrap();
        std::fs::write(&log, format!("{}\n", opened(4))).unwrap();
        let at = position(&log, Some((10, Some(3)))).unwrap();
        assert_eq!(at.segment, Some(3));
        assert!(!at.reset);
        // Retention, between resolving the cursor and opening its file.
        std::fs::remove_file(&sealed).unwrap();
        let file = open_segment(&log, 3, || {}).unwrap();
        assert!(
            file.is_none(),
            "segment 3 is gone; the active file is segment 4"
        );
    }
}
