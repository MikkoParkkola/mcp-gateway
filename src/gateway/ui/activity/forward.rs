// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live stream's read of one log: oldest first, from a delivered row up to
//! a captured head, with the list's keep.
//!
//! A call is bounded by a byte budget, and so is finding the delivered row:
//! an invalid or far-off cursor costs at most one budget per call. Where a call
//! stops is kept in the connection's [`Search`], never sent to the client. A
//! later call resumes from it only after proving the bytes are the same ones:
//! the segment's file identity read from the opened handle, the log's rewrite
//! generation, the file's length, and the hash of the last whole record before
//! the offset.
//!
//! The bound on one call's reads: its byte budget, plus at most one record
//! within the log's cap (a record is never split across calls), plus the
//! anchor's re-read, plus the shared segment opener's identity check of the
//! active file, which reads that file's first line (at most one capped line)
//! each time the active file is opened. Opening a sealed segment reads nothing.
//!
//! Opens of the active file, each reading at most its first line (one capped
//! line, `RECORD_CAP`). Every listing of the segments opens it once, three
//! times when a rotation races it three times, and a call lists at most
//! `3 + X` times: a resume, a fresh start, the end of the log, and one per
//! segment crossed (`X`). Every attempt to open a segment opens it at most
//! once, directly or by the opener's fallback when a listed sealed segment
//! has vanished, and a call makes at most `2S + X` attempts: the resume and
//! the start each walk the listing, and each crossing opens one. `S` is the
//! most segments any of the call's listings shows, and `X <= S`, so one call
//! opens the active file at most `9 + 6S` times. `S` is the kept sealed
//! segments plus the active file, and a rotation seals the old active file
//! before its retention pass unlinks the oldest segment, so `S` is at most
//! `retain_segments + 2`: 93 opens at the invocation log's default of 12 and
//! 45 for the governance log's fixed 4. Retention runs on the next append, so
//! after `retain_segments` is lowered `S` is, until then, at most the largest
//! value the log has run under, plus 2.

use std::fs::File;
use std::io;
use std::path::Path;

use serde_json::Value;

use super::access::Access;
use super::answer::{Joined, Searched};
pub(in crate::gateway::ui) use super::reader::Limits;
use super::reader::{Line, WINDOW, Which, read_page};
use super::rows::{Check, Kind, kind_of, row};

/// After this many restarts in one catch-up, the page ends in `reset`, so a
/// log replaced on every call cannot hold a stream in catch-up.
pub(in crate::gateway::ui) const MAX_RESTARTS: u8 = 3;

/// A row's place in its log: its counter and the first 16 hex digits of its
/// entry hash, as the stream's id carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::gateway::ui) struct Mark {
    pub(in crate::gateway::ui) counter: u64,
    pub(in crate::gateway::ui) hash16: String,
}

/// The stream kind a source serves. Each reads one log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::gateway::ui) enum StreamKind {
    /// Calls and admin actions, from the invocation log.
    Activity,
    /// Config changes, from the governance log.
    Config,
}

impl StreamKind {
    /// The log this kind reads.
    pub(in crate::gateway::ui) fn log(self) -> Which {
        match self {
            Self::Activity => Which::Invocation,
            Self::Config => Which::Governance,
        }
    }

    /// Whether a row of `kind` belongs on this stream.
    fn keeps(self, kind: Kind) -> bool {
        match self {
            Self::Activity => matches!(kind, Kind::Call | Kind::Refusal | Kind::AdminAction),
            Self::Config => kind == Kind::Config,
        }
    }
}

/// One log as a source reads it.
#[derive(Clone, Copy)]
pub(in crate::gateway::ui) struct Log<'a> {
    pub(in crate::gateway::ui) path: &'a Path,
    pub(in crate::gateway::ui) kind: StreamKind,
    /// The logger's rewrite generation now.
    pub(in crate::gateway::ui) generation: u64,
    pub(in crate::gateway::ui) secret: Option<&'a [u8]>,
}

/// One connection's place in one log. Held by the connection for one
/// catch-up and dropped with it.
#[derive(Debug, Default)]
pub(in crate::gateway::ui) struct Search {
    /// Where the last call stopped, when it stopped short.
    at: Option<place::Place>,
    /// Restarts in this catch-up. Kept apart from the suspended position,
    /// which a restart discards.
    restarts: u8,
}

/// A row served, with its place.
#[derive(Clone, Debug, PartialEq)]
pub(in crate::gateway::ui) struct Served {
    pub(in crate::gateway::ui) mark: Mark,
    pub(in crate::gateway::ui) row: Value,
}

/// One call's result.
#[derive(Clone, Debug, Default)]
pub(in crate::gateway::ui) struct ForwardPage {
    pub(in crate::gateway::ui) rows: Vec<Served>,
    /// The last record passed, visible or not: where the next call starts.
    /// The cursor itself while the search for it is unfinished.
    pub(in crate::gateway::ui) next: Option<Mark>,
    /// A budget, not the stop, ended the call.
    pub(in crate::gateway::ui) more: bool,
    /// The cursor's row is gone, or its hash differs.
    pub(in crate::gateway::ui) reset: bool,
    /// The cursor is not yet found: this log is not at its head.
    pub(in crate::gateway::ui) searching: bool,
    /// What this call read and from where: the bounds and the resume proof
    /// are judged on these.
    pub(in crate::gateway::ui) diag: Diagnostics,
}

/// One call's reads.
#[derive(Clone, Debug, Default)]
pub(in crate::gateway::ui) struct Diagnostics {
    /// Whether this call discarded a suspended position and searched again.
    pub(in crate::gateway::ui) restarted: bool,
    /// Bytes this call read, the anchor's re-read included.
    pub(in crate::gateway::ui) bytes_read: u64,
    /// Of those, the anchor's re-read.
    pub(in crate::gateway::ui) anchor_bytes: u64,
    /// The offset in its segment where this call's first read began.
    pub(in crate::gateway::ui) first_read: Option<u64>,
    /// The offset in its segment just past this call's last read: where a
    /// resume continues.
    pub(in crate::gateway::ui) read_end: Option<u64>,
}

/// Rows after `cursor` up to and including `stop`, oldest first. `None` for
/// `cursor` starts at the log's oldest kept record.
pub(in crate::gateway::ui) fn rows_after(
    log: &Log<'_>,
    cursor: Option<&Mark>,
    stop: Option<&Mark>,
    access: &Access,
    budget: Limits,
    search: &mut Search,
) -> io::Result<ForwardPage> {
    let mut page = ForwardPage::default();
    let Some(stop) = stop else {
        // An empty log: nothing to read up to.
        search.at = None;
        return Ok(page);
    };
    let Some((file, mut at)) = begin(log, cursor, search, &mut page)? else {
        return Ok(page);
    };
    let check = Check::one(log.secret, log.kind.log(), log.path);
    let mut scan = scan::Scan::new(file, at.offset, at.mode, budget.bytes)?;
    // Where the scan itself starts, not where the place says it should.
    page.diag.first_read = Some(scan.offset);
    let mut spent = 0;
    let outcome = loop {
        let item = scan.next()?;
        let anchor = match &item {
            scan::Step::Record { anchor, .. } => Some(*anchor),
            _ => None,
        };
        match item {
            scan::Step::Record { entry, .. } => {
                at.anchor = anchor;
                let Some(mark) = mark_of(&entry) else {
                    continue;
                };
                if !at.found {
                    // `start` guarantees a cursor here.
                    let Some(c) = cursor else {
                        break Outcome::Reset;
                    };
                    match mark.counter.cmp(&c.counter) {
                        std::cmp::Ordering::Less => continue,
                        std::cmp::Ordering::Equal if mark.hash16 == c.hash16 => {
                            at.found = true;
                            // A cursor at the stop is caught up: what follows
                            // the stop, a gap included, is a later call's.
                            let caught_up = mark == *stop;
                            at.last = Some(mark);
                            if caught_up {
                                break Outcome::Done;
                            }
                            continue;
                        }
                        _ => break Outcome::Reset,
                    }
                }
                // Counters run without gaps within a log, and retention removes
                // only the oldest: a jump means rows between were lost. Checked
                // before the stop, since the stop itself may be among them.
                if at
                    .last
                    .as_ref()
                    .is_some_and(|l| mark.counter != l.counter + 1)
                {
                    break Outcome::Reset;
                }
                if mark.counter > stop.counter {
                    break Outcome::Done;
                }
                let line = Line {
                    log: log.kind.log(),
                    entry,
                    segment: at.seq,
                    // The anchor's length includes the newline.
                    span: at.anchor.map(|a| (a.start, a.len.saturating_sub(1))),
                };
                if let Some(row) = served(log, access, &line, &check) {
                    page.rows.push(row);
                }
                at.last = Some(mark.clone());
                if mark == *stop {
                    break Outcome::Done;
                }
                if page.rows.len() >= budget.matches {
                    break Outcome::More;
                }
            }
            scan::Step::Unreadable => {}
            scan::Step::Budget => break Outcome::More,
            scan::Step::End => {
                let (next, seq, id) = match place::next_segment(log.path, at.seq)? {
                    place::Next::Opened(file, seq, id) => (file, seq, id),
                    // The log ends here: a cursor not yet found is ahead of it.
                    place::Next::End if at.found => break Outcome::Done,
                    // Or the next segment is gone or unreadable: rows past this
                    // point cannot be proven, so the client reloads.
                    place::Next::End | place::Next::Missing => break Outcome::Reset,
                };
                spent += scan.read;
                at = at.at_start(seq, id);
                let left = budget.bytes.saturating_sub(spent);
                scan = scan::Scan::new(next, 0, scan::Mode::Boundary, left)?;
            }
        }
    };
    at.offset = scan.offset;
    at.mode = scan.mode;
    page.diag.read_end = Some(scan.offset);
    page.diag.bytes_read += spent + scan.read + page.diag.anchor_bytes;
    settle(&mut page, search, at, outcome, cursor);
    Ok(page)
}

/// Where this call starts: its suspended place when that still holds, else a
/// fresh search from the oldest segment. `None` when the page is a reset: too
/// many restarts, or no place to start from.
fn begin(
    log: &Log<'_>,
    cursor: Option<&Mark>,
    search: &mut Search,
    page: &mut ForwardPage,
) -> io::Result<Option<(File, place::Place)>> {
    let saved = search.at.take().filter(|p| p.continues(cursor));
    let resumed = match &saved {
        Some(p) => place::resume(log, p, &mut page.diag.anchor_bytes)?,
        None => None,
    };
    if saved.is_some() && resumed.is_none() {
        search.restarts += 1;
        if search.restarts > MAX_RESTARTS {
            page.reset = true;
            page.diag.bytes_read = page.diag.anchor_bytes;
            return Ok(None);
        }
        page.diag.restarted = true;
    }
    let started = match resumed {
        Some(r) => Some(r),
        None => place::start(log, cursor)?,
    };
    if started.is_none() {
        page.reset = true;
        page.diag.bytes_read += page.diag.anchor_bytes;
    }
    Ok(started)
}

/// Record how a call ended, and keep its place only when it stopped short.
fn settle(
    page: &mut ForwardPage,
    search: &mut Search,
    at: place::Place,
    outcome: Outcome,
    cursor: Option<&Mark>,
) {
    match outcome {
        Outcome::Reset => {
            page.reset = true;
            search.at = None;
        }
        Outcome::Done => {
            page.next.clone_from(&at.last);
            search.at = None;
        }
        Outcome::More => {
            page.more = true;
            page.searching = !at.found;
            page.next = if at.found {
                at.last.clone()
            } else {
                cursor.cloned()
            };
            search.at = Some(at);
        }
    }
}

/// How a call ended.
#[derive(Clone, Copy)]
enum Outcome {
    /// The stop was reached, or the log ended.
    Done,
    /// A budget ended it; the place is saved.
    More,
    /// The cursor's row is gone, or its hash differs.
    Reset,
}

/// A record's place, from its own counter and entry hash.
pub(in crate::gateway::ui) fn mark_of(entry: &Value) -> Option<Mark> {
    let counter = entry.get("counter")?.as_u64()?;
    let hash = entry.get("entry_hash")?.as_str()?.strip_prefix("sha256:")?;
    Some(Mark {
        counter,
        hash16: hash.get(..16)?.to_owned(),
    })
}

/// The newest kept record's place, visible to the caller or not.
pub(in crate::gateway::ui) fn head(log: &Log<'_>) -> io::Result<Option<Mark>> {
    let one = Limits {
        matches: 1,
        bytes: 2 * WINDOW,
    };
    // Either log reads as the reader's first: only the counter and hash of
    // its newest line are used here, never its log label. One bounded read
    // from the end: a budget spent on unreadable bytes is not an empty log,
    // and reading on from the page's continuation could take the head of an
    // over-cap line for a record, so it is an error instead.
    let page = read_page(log.path, None, None, one, |line| {
        mark_of(&line.entry).is_some()
    })?;
    match page.lines.first().and_then(|l| mark_of(&l.entry)) {
        Some(mark) => Ok(Some(mark)),
        None if page.scan_exhausted => Err(io::Error::other(
            "no record within one read of the log's end",
        )),
        None => Ok(None),
    }
}

/// The row for an announced record, as a read back gives it, or `None` when
/// this caller or this stream kind does not get it.
pub(in crate::gateway::ui) fn frame(
    log: &Log<'_>,
    access: &Access,
    entry: &Value,
) -> Option<Served> {
    let line = Line {
        log: log.kind.log(),
        entry: entry.clone(),
        segment: 0,
        span: None,
    };
    // A signed record that verifies never loads the anchor (`Check::one` is
    // lazy); only an unsigned one, which with signing on is an edit, reads
    // the sidecar.
    served(
        log,
        access,
        &line,
        &Check::one(log.secret, log.kind.log(), log.path),
    )
}

/// The row for `line` when this stream kind keeps it and `access` may see it.
fn served(log: &Log<'_>, access: &Access, line: &Line, check: &Check<'_>) -> Option<Served> {
    let kind = kind_of(line).filter(|k| log.kind.keeps(*k))?;
    if !access.admits(line, kind) {
        return None;
    }
    Some(Served {
        mark: mark_of(&line.entry)?,
        row: row(line, check, &Joined::NoRecord(Searched::AppendTime))?,
    })
}

#[path = "forward_place.rs"]
mod place;
#[path = "forward_scan.rs"]
mod scan;

#[cfg(test)]
#[path = "forward_tests.rs"]
mod tests;
