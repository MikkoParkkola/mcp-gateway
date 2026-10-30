// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Paging a transparency log backward, newest first: where a cursor points
//! across rotated segments, one bounded tail window, and its lines. The one
//! paging engine every reader of the log shares; a reader adds only what it
//! does with a line.

use std::io;
use std::path::Path;

use super::rotation::MAX_RECORD_BYTES;
use super::segments::{list_segments, listing, sealed_path, segment_seq_in};

/// Where a page starts reading. Its segment's file is opened with
/// [`open_segment`], and the page's end is read from that file once, with
/// [`end_in`]: never from a length read by name before the open, which a
/// rotation in between would take from another file.
pub(crate) struct Position {
    /// The cursor's bound, unclamped; `None` reads to the end of the file.
    pub(crate) bound: Option<u64>,
    /// The segment, the active file included.
    pub(crate) segment: u64,
    /// The cursor no longer named a position: reading restarts at the newest
    /// record. Records between the old position and the newest may have
    /// expired, so the pages before and after are not one unbroken history.
    pub(crate) reset: bool,
    /// The log had a file when this was resolved.
    seen: bool,
}

impl Position {
    /// Whether finding no file for this position means bytes were lost: the
    /// log had files when resolved and the page still names bytes in its
    /// segment. A log never written, or a page at offset 0, has none to lose.
    pub(crate) fn lost_if_unopened(&self) -> bool {
        self.seen && self.bound != Some(0)
    }
}

/// The end of a page in `file`, opened for its position: the bound, or the
/// file's end, never past the file. Read once per page, right after the open.
pub(crate) fn end_in(bound: Option<u64>, file: &std::fs::File) -> io::Result<u64> {
    let len = file.metadata()?.len();
    Ok(bound.map_or(len, |b| b.min(len)))
}

/// Resolve a cursor `(offset, segment)` on `log`, reading no file's length.
/// No cursor reads the newest segment from its end; a segment cursor names
/// its file by number (a rename never changes a segment's bytes) and holds
/// while that segment is kept; an offset-only cursor from before rotation
/// holds while the log is still in segment 0. Any other cursor restarts at
/// the newest record, with `reset`.
pub(crate) fn position(log: &Path, cursor: Option<(u64, Option<u64>)>) -> io::Result<Position> {
    let files = listing(log)?;
    #[cfg(test)]
    seam::fire();
    let seen = files.seen();
    let at = |bound, segment, reset| Position {
        bound,
        segment,
        reset,
        seen,
    };
    // The newest page reads the active file from its end. With no active file
    // (all sealed, or never written) it names the number the next file takes,
    // at offset 0: nothing there to lose, and the page steps to the sealed ones.
    let newest_bound = files.active.map_or(Some(0), |_| None);
    let newest = |why: &str| {
        tracing::warn!("audit cursor {why}: restarting at the newest record");
        at(newest_bound, files.newest(), true)
    };
    Ok(match cursor {
        None => at(newest_bound, files.newest(), false),
        // Bytes named in a log with no file left: they cannot be read, and an
        // empty page would pass them as the end of the log.
        Some((offset, _)) if !seen && offset > 0 => newest("into a log with no files"),
        Some((offset, None)) if files.newest() == 0 => at(Some(offset), 0, false),
        Some((_, None)) => newest("from before rotation, after a rotation"),
        Some((offset, Some(seq))) if files.kept(seq) => at(Some(offset), seq, false),
        Some((_, Some(_))) => newest("into a segment no longer kept"),
    })
}

/// The `(length, segment)` of the segment just older than `segment`. `None`
/// at the start of the log, including when retention removes the oldest
/// segment meanwhile. A kept older segment below `segment - 1` means one in
/// between is gone (retention only removes the oldest): an error, never a
/// page that steps over it.
pub(crate) fn older_segment(log: &Path, segment: Option<u64>) -> io::Result<Option<(u64, u64)>> {
    let Some(seq) = segment else { return Ok(None) };
    let listed = list_segments(log)?;
    let Some(older) = listed.iter().rev().find(|s| s.seq < seq).cloned() else {
        return Ok(None);
    };
    // Decided from this listing, not a later one: retention racing a later
    // listing could make a hole look like the start of the log.
    let older_kept = listed.iter().any(|s| s.seq < older.seq);
    if older.seq + 1 != seq {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "log segment {} is missing between kept segments {} and {seq}",
                seq - 1,
                older.seq
            ),
        ));
    }
    #[cfg(test)]
    seam::fire_older_listed();
    match std::fs::metadata(&older.path) {
        Ok(meta) => Ok(Some((meta.len(), older.seq))),
        // Gone since listed. Retention removes the oldest first: with nothing
        // older kept, the log ends here; otherwise it is a hole.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if older_kept {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("log segment {} vanished below kept segments", older.seq),
                ))
            } else {
                Ok(None)
            }
        }
        Err(e) => Err(e),
    }
}

/// Open segment `seq` of `log` for reading, positioned at its first byte; the
/// one place a reader opens a segment. A file opened by the active name is
/// kept only if its open record names `seq`; otherwise rotation sealed `seq`
/// meanwhile (or is between renaming it and creating the next file), and its
/// bytes are under the sealed name. `None` when `seq` is under neither name:
/// retention removed it, and the active file is a later segment.
/// `before_open` runs just before the open: a test's seam for that window.
pub(crate) fn open_segment(
    log: &Path,
    seq: u64,
    before_open: impl FnOnce(),
) -> io::Result<Option<std::fs::File>> {
    use std::io::{Seek, SeekFrom};

    let open = |path: &Path| match std::fs::File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let sealed_now =
        || -> io::Result<bool> { Ok(list_segments(log)?.iter().any(|s| s.seq == seq)) };
    let by_sealed_name = sealed_now()?;
    before_open();
    let file = if by_sealed_name {
        open(&sealed_path(log, seq))?
    } else {
        match open(log)? {
            Some(file) if active_seq_of(&file, log)? == seq => Some(file),
            _ if sealed_now()? => open(&sealed_path(log, seq))?,
            _ => None,
        }
    };
    // The identity check read the first line through this handle.
    if let Some(mut file) = file.as_ref() {
        file.seek(SeekFrom::Start(0))?;
    }
    Ok(file)
}

/// The segment the open active file holds, read from that descriptor by the
/// same rule as [`active_segment_seq`]: its open record, or for a log written
/// before open records, the newest sealed segment plus one.
fn active_seq_of(file: &std::fs::File, log: &Path) -> io::Result<u64> {
    let after = list_segments(log)?.last().map_or(0, |s| s.seq + 1);
    segment_seq_in(file, after)
}

/// Read `len` bytes starting at `start` of a file already open. A reader
/// that holds the handle keeps reading the same bytes when rotation renames
/// the file under it.
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

/// Read the tail window below `end` in an open file, without line assembly:
/// the Overview's recent-actions view. A window that starts mid-line drops
/// that partial head; the line it belongs to is read by the page that covers
/// the bytes below. Returns the window and the bytes it spans.
#[cfg(feature = "webui")]
pub(crate) fn tail_window_in(file: &std::fs::File, end: u64, max: u64) -> io::Result<(Tail, u64)> {
    let window_len = end.min(max);
    let window = read_window_in(file, end - window_len, window_len)?;
    #[cfg(test)]
    seam::fire_after_window();
    Ok(split_tail(window, end))
}

/// The longest window line assembly reads: the newline ending the line
/// before, and one record at the logger's cap. The cap counts the record's own
/// newline (the logger refuses `line.len() + 1 > MAX_RECORD_BYTES`), so one
/// byte more than the cap holds both.
pub(crate) const ASSEMBLY_WINDOW: u64 = MAX_RECORD_BYTES as u64 + 1;

/// The tail window of at most `max` bytes below `end` in an open file, with
/// line assembly. A window that starts mid-line drops that partial head; the
/// line it belongs to is read by the page that covers the bytes below. When
/// no line starts
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

/// A test's seam inside [`position`], once the active segment's number is
/// read: rotation there is the window between naming a segment and reading
/// anything of it.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::RefCell;

    thread_local! {
        static AFTER_ACTIVE_SEQ: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    #[cfg(feature = "webui")]
    thread_local! {
        static AFTER_WINDOW: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Run `hook` once, after this thread's next [`super::tail_window_in`]
    /// read: rotation between two windows of one Overview read.
    #[cfg(feature = "webui")]
    pub(crate) fn after_window(hook: impl FnOnce() + 'static) {
        AFTER_WINDOW.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    #[cfg(feature = "webui")]
    pub(super) fn fire_after_window() {
        if let Some(hook) = AFTER_WINDOW.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, the next time this thread's [`super::position`] has
    /// read the active segment's number.
    pub(crate) fn after_active_seq(hook: impl FnOnce() + 'static) {
        AFTER_ACTIVE_SEQ.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn fire() {
        if let Some(hook) = AFTER_ACTIVE_SEQ.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    thread_local! {
        static AFTER_SEALED_LISTED: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
        static AFTER_OLDER_LISTED: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    /// Run `hook` once, inside the next listing, between listing the sealed
    /// segments and reading the live file.
    pub(crate) fn after_sealed_listed(hook: impl FnOnce() + 'static) {
        AFTER_SEALED_LISTED.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(crate) fn fire_sealed_listed() {
        if let Some(hook) = AFTER_SEALED_LISTED.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    /// Run `hook` once, inside the next [`super::older_segment`], between
    /// finding the older segment and reading its length.
    pub(crate) fn after_older_listed(hook: impl FnOnce() + 'static) {
        AFTER_OLDER_LISTED.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    pub(super) fn fire_older_listed() {
        if let Some(hook) = AFTER_OLDER_LISTED.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }
}

#[cfg(test)]
#[path = "transparency_log_pager_tests.rs"]
mod tests;
