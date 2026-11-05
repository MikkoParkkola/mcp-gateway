// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a connection's read of one log stands between calls, how a fresh
//! read finds its start, and how a saved place is proven before it is reused.

use std::fs::File;
use std::io;
use std::path::Path;

use super::scan::{Anchor, Mode};
use super::{Log, Mark};
use crate::security::transparency_log::pager::open_segment;
use crate::security::transparency_log::rotation::{FileId, file_id};

/// A saved place in one segment.
#[derive(Clone, Debug)]
pub(super) struct Place {
    /// The cursor the call that saved it was given.
    pub(super) cursor: Option<Mark>,
    /// The cursor's own record was found and its hash matched.
    pub(super) found: bool,
    /// The last record passed, visible or not.
    pub(super) last: Option<Mark>,
    pub(super) generation: u64,
    pub(super) file: FileId,
    pub(super) seq: u64,
    pub(super) offset: u64,
    pub(super) mode: Mode,
    /// The last whole record before `offset` in this segment.
    pub(super) anchor: Option<Anchor>,
}

impl Place {
    /// Whether a call with `cursor` continues from this place.
    pub(super) fn continues(&self, cursor: Option<&Mark>) -> bool {
        if self.found {
            self.last.as_ref() == cursor
        } else {
            self.cursor.as_ref() == cursor
        }
    }

    /// The same place at the start of segment `seq`.
    pub(super) fn at_start(&self, seq: u64, file: FileId) -> Self {
        Self {
            seq,
            file,
            offset: 0,
            mode: Mode::Boundary,
            anchor: None,
            ..self.clone()
        }
    }
}

/// What follows segment `seq`.
pub(super) enum Next {
    /// The next segment, opened with its identity.
    Opened(File, u64, FileId),
    /// No later segment: the log ends at `seq`.
    End,
    /// A later segment exists but the next number is missing, or it would
    /// not open or name itself: rows may lie in it, so the read cannot just end.
    Missing,
}

/// The log's segments. Every listing opens the active file to read the
/// segment number on its first line, once, or up to three times when a
/// rotation races it; the forward read's module doc counts these opens.
fn listed(path: &Path) -> io::Result<Vec<u64>> {
    #[cfg(test)]
    super::tests::listed();
    super::super::seek::segments(path)
}

/// The segment after `seq`. Segments are numbered without gaps, so a later
/// one that is not `seq + 1` means one vanished.
pub(super) fn next_segment(path: &Path, seq: u64) -> io::Result<Next> {
    let Some(next) = listed(path)?.into_iter().find(|s| *s > seq) else {
        return Ok(Next::End);
    };
    if next != seq + 1 {
        return Ok(Next::Missing);
    }
    Ok(match open(path, next)? {
        Segment::Opened(file, id) => Next::Opened(file, next, id),
        Segment::Gone | Segment::Unreadable => Next::Missing,
    })
}

/// A segment opened with its identity. `None` when it is gone, or when its
/// identity cannot be read: an unreadable identity is never trusted.
pub(super) fn open(path: &Path, seq: u64) -> io::Result<Segment> {
    let Some(file) = open_segment(path, seq, || {})? else {
        return Ok(Segment::Gone);
    };
    #[cfg(test)]
    if super::tests::identity_fails(seq) {
        return Ok(Segment::Unreadable);
    }
    Ok(match file_id(&file) {
        Ok(id) => Segment::Opened(file, id),
        Err(_) => Segment::Unreadable,
    })
}

/// A listed segment, opened.
pub(super) enum Segment {
    Opened(File, FileId),
    /// Removed since it was listed: retention, or a rotation in between.
    Gone,
    /// It exists but its identity cannot be read: it cannot be proven.
    Unreadable,
}

/// Where a fresh read starts: the oldest kept segment, at its first byte. A
/// cursor is then searched for by the budgeted scan itself, so finding it
/// costs no more per call than reading rows does. `None` for a log with no
/// segment that opens.
pub(super) fn start(log: &Log<'_>, cursor: Option<&Mark>) -> io::Result<Option<(File, Place)>> {
    for seq in listed(log.path)? {
        let (file, id) = match open(log.path, seq)? {
            Segment::Opened(file, id) => (file, id),
            // Removed since it was listed: the next one is now the oldest.
            Segment::Gone => continue,
            // Rows may lie in it; starting past it would skip them.
            Segment::Unreadable => return Ok(None),
        };
        let place = Place {
            cursor: cursor.cloned(),
            found: cursor.is_none(),
            last: None,
            generation: log.generation,
            file: id,
            seq,
            offset: 0,
            mode: Mode::Boundary,
            anchor: None,
        };
        return Ok(Some((file, place)));
    }
    Ok(None)
}

/// Reopen a saved place, proven on the handle it will read: the same file
/// identity, the same rewrite generation, long enough, and the anchor's bytes
/// unchanged. `None` restarts. Adds the anchor's re-read to `anchor_bytes`.
pub(super) fn resume(
    log: &Log<'_>,
    place: &Place,
    anchor_bytes: &mut u64,
) -> io::Result<Option<(File, Place)>> {
    if place.generation != log.generation {
        return Ok(None);
    }
    let mut found = None;
    for seq in listed(log.path)? {
        if let Segment::Opened(file, id) = open(log.path, seq)?
            && id == place.file
        {
            found = Some((file, seq));
            break;
        }
    }
    let Some((file, seq)) = found else {
        return Ok(None);
    };
    #[cfg(test)]
    super::tests::after_identity();
    // Any element that cannot be read restarts the search, as a mismatch does.
    if !file.metadata().is_ok_and(|m| m.len() >= place.offset) {
        return Ok(None);
    }
    if let Some(anchor) = &place.anchor {
        let Ok((same, n)) = anchor.holds(&file) else {
            return Ok(None);
        };
        *anchor_bytes += n;
        if !same {
            return Ok(None);
        }
    }
    Ok(Some((
        file,
        Place {
            seq,
            ..place.clone()
        },
    )))
}
