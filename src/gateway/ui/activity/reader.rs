// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Activity reader: the invocation log and the governance log, each read
//! backward through its segments in windows, merged newest first, within a
//! byte budget. Built on the shared pager; this module adds only the merge,
//! the per-log position and the budget.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::answer::LOOK_ABOVE;
use super::seek::segments;
use super::strict_scan::{Forward, Next};
use crate::security::transparency_log::pager::{
    self, ASSEMBLY_WINDOW, Tail, lines_newest_first, older_segment, tail_window_assembled,
    tail_window_in,
};

/// The window each read takes.
pub(super) const WINDOW: u64 = 1 << 20;

/// Which log a line came from: the SIEM export's name for the same two logs.
pub(super) use crate::control_plane::export::ExportSource as Which;

/// Where a log is read from next: everything below `offset` in segment
/// `segment` is unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct LogPos {
    pub(super) segment: u64,
    pub(super) offset: u64,
}

/// Both logs' positions. `None` is a log read to its oldest kept line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Cursor {
    pub(super) inv: Option<LogPos>,
    pub(super) gov: Option<LogPos>,
    /// The time of the oldest timed governance record already read: an
    /// untimed one below it (written before governance records were timed,
    /// so always older) sorts just below this time.
    #[serde(default)]
    pub(super) gov_bound: Option<String>,
}

/// One line the reader returns.
#[derive(Debug, Clone)]
pub(super) struct Line {
    pub(super) log: Which,
    pub(super) entry: Value,
    pub(super) segment: u64,
    /// The line's start and length in its segment, newline excluded; `None`
    /// for a record the writer just announced, which follows every anchor.
    pub(super) span: Option<(u64, u64)>,
}

/// A line that is not a JSON entry: a hand-edited log, or one over the record
/// cap. Reported, never served and never read forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(super) struct Unreadable {
    pub(super) log: Which,
    pub(super) segment: u64,
    pub(super) offset: u64,
}

/// One page.
#[derive(Debug)]
pub(super) struct Page {
    pub(super) lines: Vec<Line>,
    pub(super) unreadable: Vec<Unreadable>,
    /// `None` when both logs are read to their oldest kept line.
    pub(super) next: Option<Cursor>,
    /// The budget, not the logs' start, ended the page.
    pub(super) scan_exhausted: bool,
    pub(super) bytes_examined: u64,
    /// The cursor named a segment no longer kept; reading restarted newest.
    pub(super) cursor_reset: bool,
    /// Where the invocation log's bytes above stood when the page ended, for
    /// the next pass of an export.
    pub(super) above_end: Seen,
}

/// What bounds one page.
#[derive(Debug, Clone, Copy)]
pub(in crate::gateway::ui) struct Limits {
    pub(in crate::gateway::ui) matches: usize,
    pub(in crate::gateway::ui) bytes: u64,
}

enum Item {
    /// A line and its bytes, newline included.
    Entry(Line, u64),
    Unreadable(Unreadable),
}

/// One log read backward. Holds the open file, so a rotation that renames the
/// active file mid-read leaves this reader on the same bytes.
struct LogTail {
    which: Which,
    log: PathBuf,
    file: Option<File>,
    segment: u64,
    end: u64,
    /// Lines of the last window not yet returned, oldest first:
    /// `(offset, bytes, boundary above the line)`.
    pending: Vec<(u64, Vec<u8>, u64)>,
    /// The next line read is the head of a line already reported, or a
    /// partial append at the end of the active file: drop it silently.
    skip_head: bool,
    done: bool,
    /// This page has taken an item from this log: the strict budget applies.
    advanced: bool,
}

impl LogTail {
    /// Open `log` at `pos`, or at its newest line. A position the log no
    /// longer holds answers `Ok(None)`, so the caller restarts both logs.
    fn open(which: Which, log: &Path, pos: Option<LogPos>) -> io::Result<Option<Self>> {
        let at = pager::position(log, pos.map(|p| (p.offset, Some(p.segment))))?;
        if at.reset {
            return Ok(None);
        }
        #[cfg(test)]
        tests::after_resolve();
        let mut tail = Self {
            which,
            log: log.to_path_buf(),
            file: None,
            segment: at.segment,
            end: 0,
            pending: Vec::new(),
            skip_head: pos.is_none(),
            done: false,
            advanced: false,
        };
        tail.file = tail.open_segment(at.lost_if_unopened())?;
        if let Some(f) = &tail.file {
            tail.end = pager::end_in(at.bound, f)?;
        }
        Ok(Some(tail))
    }

    /// Open the current segment's file through the pager's one opener.
    /// `lost_if_unopened`: finding no file means bytes the page names went
    /// unread, so the page fails rather than pass them.
    fn open_segment(&self, lost_if_unopened: bool) -> io::Result<Option<File>> {
        let file = pager::open_segment(&self.log, self.segment, || {
            #[cfg(test)]
            tests::before_open();
        })?;
        if file.is_none() && lost_if_unopened {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("log segment {} vanished with bytes unread", self.segment),
            ));
        }
        Ok(file)
    }

    /// The position a later page resumes from.
    fn pos(&self) -> Option<LogPos> {
        (!self.done).then_some(LogPos {
            segment: self.segment,
            offset: self.end,
        })
    }

    /// One complete line at `offset` (`above` is the end it was read below):
    /// a JSON object is an entry, anything else is unreadable.
    fn item_of(&self, bytes: &[u8], offset: u64, above: u64) -> Item {
        match serde_json::from_slice::<Value>(bytes) {
            Ok(entry) if entry.is_object() => Item::Entry(
                Line {
                    log: self.which,
                    entry,
                    segment: self.segment,
                    span: Some((offset, bytes.len() as u64)),
                },
                above - offset,
            ),
            _ => Item::Unreadable(Unreadable {
                log: self.which,
                segment: self.segment,
                offset,
            }),
        }
    }

    /// The next line, newest first. `Ok(None)` is the log's oldest kept line
    /// passed (`done`) or the budget spent (not `done`).
    fn next(&mut self, spent: &mut u64, budget: u64) -> io::Result<Option<(Item, u64)>> {
        loop {
            if let Some((offset, bytes, above)) = self.pending.pop() {
                self.end = offset;
                // Consuming any bytes is progress, a skipped partial head
                // included: from here the log keeps the strict budget, so it
                // never assembles twice in one page.
                self.advanced = true;
                if bytes.is_empty() {
                    // A window ending on a newline: the head is empty.
                    self.skip_head = false;
                    continue;
                }
                if std::mem::take(&mut self.skip_head) {
                    continue;
                }
                let item = self.item_of(&bytes, offset, above);
                return Ok(Some((item, above)));
            }
            if self.done {
                return Ok(None);
            }
            if self.end == 0 {
                match older_segment(&self.log, Some(self.segment))? {
                    Some((len, seq)) => {
                        self.segment = seq;
                        self.skip_head = false;
                        self.file = self.open_segment(false)?;
                        match &self.file {
                            Some(f) => self.end = pager::end_in(Some(len), f)?,
                            // Gone since it was listed. Retention removes the
                            // oldest first: with nothing older kept, the log
                            // ends here; with an older one kept, a segment in
                            // between was removed, which a page never steps over.
                            None if older_segment(&self.log, Some(seq))?.is_some() => {
                                return Err(io::Error::new(
                                    io::ErrorKind::NotFound,
                                    format!("log segment {seq} vanished below kept segments"),
                                ));
                            }
                            None => self.done = true,
                        }
                    }
                    None => self.done = true,
                }
                continue;
            }
            if *spent >= budget && self.advanced {
                return Ok(None);
            }
            let Some(file) = &self.file else {
                self.end = 0;
                continue;
            };
            // One page budget. The window and the pager's re-read for a line
            // longer than the window are charged together, so assembly runs
            // up front only when both fit what is left. A log this page has
            // taken nothing from reads the window within what is left and,
            // when that holds no line start, assembles the one record anyway:
            // paging always advances. The peak is the window within the
            // budget left plus one ASSEMBLY_WINDOW (the record cap plus a
            // newline): at most that past the budget, per log. A log that has
            // advanced keeps the strict budget and the page ends resumable.
            let remaining = budget.saturating_sub(*spent);
            let assemble = remaining >= WINDOW + ASSEMBLY_WINDOW;
            let (mut tail, mut read) = match (assemble, remaining) {
                (true, _) => tail_window_assembled(file, self.end, WINDOW)?,
                (false, 0) => (Tail::LineTooLong, 0),
                (false, left) => tail_window_in(file, self.end, WINDOW.min(left))?,
            };
            if !assemble && !self.advanced && matches!(tail, Tail::LineTooLong) {
                let (whole, more) = tail_window_assembled(file, self.end, ASSEMBLY_WINDOW)?;
                (tail, read) = (whole, read + more);
            }
            *spent += read;
            if self.advanced && !assemble && matches!(tail, Tail::LineTooLong) {
                return Ok(None);
            }
            match tail {
                Tail::LineTooLong => {
                    // Over the record cap: report it once, step below the
                    // bytes read, and drop the rest of that line when reached.
                    let above = self.end;
                    self.end -= self.end.min(ASSEMBLY_WINDOW);
                    self.skip_head = true;
                    let item = Item::Unreadable(Unreadable {
                        log: self.which,
                        segment: self.segment,
                        offset: self.end,
                    });
                    self.advanced = true;
                    return Ok(Some((item, above)));
                }
                Tail::Lines { start, .. } => {
                    let mut above = self.end;
                    let mut lines: Vec<(u64, Vec<u8>, u64)> = Vec::new();
                    for (offset, bytes) in lines_newest_first(tail.body(), start) {
                        lines.push((offset, bytes.to_vec(), above));
                        above = offset;
                    }
                    lines.reverse();
                    self.pending = lines;
                    if self.pending.is_empty() {
                        self.end = start;
                    }
                }
            }
        }
    }
}

/// Both logs' readers; `None` is a log not read (done, or not configured).
type Tails = (Option<LogTail>, Option<LogTail>);

/// Open both logs at `cursor`, or at their newest lines. `Ok(None)` when the
/// cursor names a segment no longer kept, so the caller restarts.
fn open_tails(
    inv: &Path,
    gov: Option<&Path>,
    cursor: Option<&Cursor>,
) -> io::Result<Option<Tails>> {
    let inv_pos = cursor.map(|c| c.inv);
    let gov_pos = cursor.map(|c| c.gov);
    let inv_tail = match inv_pos {
        Some(None) => None,
        pos => match LogTail::open(Which::Invocation, inv, pos.flatten())? {
            Some(t) => Some(t),
            None => return Ok(None),
        },
    };
    let gov_tail = match (gov, gov_pos) {
        (None, _) | (_, Some(None)) => None,
        (Some(path), pos) => match LogTail::open(Which::Governance, path, pos.flatten())? {
            Some(t) => Some(t),
            None => return Ok(None),
        },
    };
    Ok(Some((inv_tail, gov_tail)))
}

fn timestamp(entry: &Value) -> Option<DateTime<FixedOffset>> {
    entry
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
}

/// Read one page. `keep` decides which entries count as matches; the others
/// are examined and skipped. Across the logs, the later timestamp comes
/// first; a tie or a missing invocation time takes the invocation log first,
/// and each log keeps its own recorded order. An untimed governance record
/// sorts just below the oldest timed governance record already read (it was
/// written before governance records were timed); with none read, the
/// invocation log goes first.
pub(super) fn read_page(
    inv: &Path,
    gov: Option<&Path>,
    cursor: Option<&Cursor>,
    limits: Limits,
    mut keep: impl FnMut(&Line) -> bool,
) -> io::Result<Page> {
    let carried = Look::Carried(Seen {
        above: 0,
        head_covered: true,
    });
    read_page_joined(inv, gov, cursor, limits, carried, |line, _| keep(line))
}

/// Where the invocation log's bytes above a line stand, handed to `keep`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Seen {
    /// Bytes read above the line in this read: look-above plus every line
    /// consumed since the page top (and, in an export, earlier passes).
    pub(super) above: u64,
    /// Everything above the line, up to the log head, has been read.
    pub(super) head_covered: bool,
}

/// How a page learns what lies above its cursor.
pub(super) enum Look<'a> {
    /// Read forward from the cursor and give each line to the callback.
    Fold(&'a mut dyn FnMut(&Line)),
    /// Nothing is read: this is where an earlier pass of the same read stopped.
    Carried(Seen),
}

/// [`read_page`] with the invocation log's look-above, and `keep` told how
/// many bytes lie above each line.
pub(super) fn read_page_joined(
    inv: &Path,
    gov: Option<&Path>,
    cursor: Option<&Cursor>,
    limits: Limits,
    look: Look<'_>,
    mut keep: impl FnMut(&Line, Seen) -> bool,
) -> io::Result<Page> {
    let mut cursor_reset = false;
    let mut gov_bound = cursor
        .and_then(|c| c.gov_bound.as_deref())
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok());
    let (mut inv_tail, mut gov_tail) = if let Some(tails) = open_tails(inv, gov, cursor)? {
        tails
    } else {
        cursor_reset = true;
        gov_bound = None;
        open_tails(inv, gov, None)?.unwrap_or((None, None))
    };

    let mut spent = 0_u64;
    let Seen {
        above: mut inv_above,
        head_covered,
    } = match look {
        Look::Carried(seen) => seen,
        Look::Fold(fold) => {
            let valid = cursor.filter(|_| !cursor_reset);
            look_above(inv, valid, fold, &mut spent, LOOK_ABOVE.min(limits.bytes))?
        }
    };
    let mut lines = Vec::new();
    let mut unreadable = Vec::new();
    // The head of each log, read but not yet taken: `(item, boundary above)`.
    let mut heads: [Option<(Item, u64)>; 2] = [None, None];
    let mut stalled = false;
    while lines.len() < limits.matches {
        for (slot, tail) in heads.iter_mut().zip([&mut inv_tail, &mut gov_tail]) {
            if slot.is_none()
                && let Some(t) = tail.as_mut()
            {
                *slot = t.next(&mut spent, limits.bytes)?;
                if slot.is_none() && !t.done {
                    stalled = true;
                }
            }
        }
        if stalled {
            break;
        }
        let pick = match (&heads[0], &heads[1]) {
            (None, None) => break,
            (Some(_), None) => 0,
            (None, Some(_)) => 1,
            (Some((a, _)), Some((b, _))) => match (item_time(a), item_time(b), gov_bound) {
                (Some(a), Some(b), _) if b > a => 1,
                (Some(a), None, Some(bound)) if a < bound => 1,
                _ => 0,
            },
        };
        let Some((item, _)) = heads[pick].take() else {
            break;
        };
        if pick == 1
            && let Some(t) = item_time(&item)
        {
            gov_bound = Some(t);
        }
        match item {
            Item::Entry(line, len) => {
                let seen = Seen {
                    above: inv_above,
                    head_covered,
                };
                if line.log == Which::Invocation {
                    inv_above += len;
                }
                if keep(&line, seen) {
                    lines.push(line);
                }
            }
            Item::Unreadable(u) => unreadable.push(u),
        }
    }

    let inv_pos = resume_pos(inv_tail.as_ref(), heads[0].as_ref());
    let gov_pos = resume_pos(gov_tail.as_ref(), heads[1].as_ref());
    let next = (inv_pos.is_some() || gov_pos.is_some()).then(|| Cursor {
        inv: inv_pos,
        gov: gov_pos,
        gov_bound: gov_bound.map(|t| t.to_rfc3339()),
    });
    Ok(Page {
        lines,
        unreadable,
        next,
        scan_exhausted: stalled,
        bytes_examined: spent,
        cursor_reset,
        above_end: Seen {
            above: inv_above,
            head_covered,
        },
    })
}

/// Read forward from the invocation cursor over at most `budget` bytes,
/// crossing newer retained segments, giving each line to `fold`. Charged to
/// `spent`. A gap in the segment numbers, a vanished file or the byte limit
/// leaves `head_covered` false; only reaching the active file's end sets it.
fn look_above(
    inv: &Path,
    cursor: Option<&Cursor>,
    fold: &mut dyn FnMut(&Line),
    spent: &mut u64,
    budget: u64,
) -> io::Result<Seen> {
    let Some(pos) = cursor.and_then(|c| c.inv) else {
        // No cursor, or this log already read to its oldest line: nothing
        // lies above that a page has not seen.
        return Ok(Seen {
            above: 0,
            head_covered: true,
        });
    };
    let mut above = 0_u64;
    let mut previous: Option<u64> = None;
    for seq in segments(inv)? {
        if seq < pos.segment {
            continue;
        }
        let contiguous = previous.is_none_or(|p| seq == p + 1);
        let file = pager::open_segment(inv, seq, || {})?;
        let (true, Some(file)) = (contiguous, file) else {
            break;
        };
        previous = Some(seq);
        let offset = if seq == pos.segment { pos.offset } else { 0 };
        let mut forward = Forward::open(file, offset, budget - above)?;
        let mut at = offset;
        let ended = loop {
            match forward.next_line()? {
                Next::Line(bytes) => {
                    fold_line(&bytes, seq, at, fold);
                    at += bytes.len() as u64 + 1;
                }
                other => break other,
            }
        };
        above += forward.pulled();
        if ended == Next::Budget {
            break;
        }
        if previous == seg_last(inv)? {
            *spent += above;
            return Ok(Seen {
                above,
                head_covered: true,
            });
        }
    }
    *spent += above;
    Ok(Seen {
        above,
        head_covered: false,
    })
}

/// The newest segment's number, the active file's included.
fn seg_last(inv: &Path) -> io::Result<Option<u64>> {
    Ok(segments(inv)?.last().copied())
}

fn fold_line(bytes: &[u8], segment: u64, offset: u64, fold: &mut dyn FnMut(&Line)) {
    if let Ok(entry @ Value::Object(_)) = serde_json::from_slice::<Value>(bytes) {
        fold(&Line {
            log: Which::Invocation,
            entry,
            segment,
            span: Some((offset, bytes.len() as u64)),
        });
    }
}

/// Where a later page resumes in `tail`: a head read but not taken is unread,
/// so resume above it.
fn resume_pos(tail: Option<&LogTail>, head: Option<&(Item, u64)>) -> Option<LogPos> {
    let t = tail?;
    match head {
        Some((item, above)) => Some(LogPos {
            segment: item_segment(item),
            offset: *above,
        }),
        None => t.pos(),
    }
}

fn item_time(item: &Item) -> Option<DateTime<FixedOffset>> {
    match item {
        Item::Entry(line, _) => timestamp(&line.entry),
        Item::Unreadable(_) => None,
    }
}

fn item_segment(item: &Item) -> u64 {
    match item {
        Item::Entry(line, _) => line.segment,
        Item::Unreadable(u) => u.segment,
    }
}

#[cfg(test)]
#[path = "reader_tests.rs"]
mod tests;
