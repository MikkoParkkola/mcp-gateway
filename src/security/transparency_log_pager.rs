// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Paging a transparency log backward, newest first: where a cursor points
//! across rotated segments, one bounded tail window, and its lines. The one
//! paging engine every reader of the log shares; a reader adds only what it
//! does with a line.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "webui")]
use super::rotation::MAX_RECORD_BYTES;
use super::segments::{active_segment_seq, list_segments, sealed_path};

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

/// The longest window line assembly reads: one record at the logger's cap,
/// its newline, and the newline ending the line before it.
#[cfg(feature = "webui")]
pub(crate) const ASSEMBLY_WINDOW: u64 = MAX_RECORD_BYTES as u64 + 2;

/// [`tail_window`] on an open file, with line assembly: when no line starts
/// inside `max`, the window is read again at [`ASSEMBLY_WINDOW`], so a line
/// up to the record cap is returned whole. [`Tail::LineTooLong`] then means a
/// line over the cap, which the logger never writes. The bytes returned count
/// both reads.
#[cfg(feature = "webui")]
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
            Ok((tail, first + second))
        }
        done => Ok(done),
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
    use super::position;

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
}
