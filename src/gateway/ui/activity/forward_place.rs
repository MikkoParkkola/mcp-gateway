// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Where a connection's read of one log stands between calls, how a fresh
//! read finds its start, and how a saved place is proven before it is reused.

use std::fs::File;
use std::io;
use std::path::Path;

use super::scan::{Anchor, Mode, Scan, Step};
use super::{Log, Mark, mark_of};
use crate::security::transparency_log::pager::{ASSEMBLY_WINDOW, open_segment};
use crate::security::transparency_log::rotation::{FileId, file_id};
use crate::security::transparency_log::segments::listing;

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

/// The log's segments, oldest first, the active file's included.
pub(super) fn segments(path: &Path) -> io::Result<Vec<u64>> {
    let files = listing(path)?;
    let mut seqs: Vec<u64> = files.sealed.iter().map(|s| s.seq).collect();
    seqs.extend(files.active);
    Ok(seqs)
}

/// The next kept segment after `seq`, opened with its identity; `None` when
/// the log ends there.
pub(super) fn next_segment(path: &Path, seq: u64) -> io::Result<Option<(File, u64, FileId)>> {
    let Some(next) = segments(path)?.into_iter().find(|s| *s > seq) else {
        return Ok(None);
    };
    Ok(open(path, next)?.map(|(f, id)| (f, next, id)))
}

/// A segment opened with its identity. `None` when it is gone, or when its
/// identity cannot be read: an unreadable identity is never trusted.
pub(super) fn open(path: &Path, seq: u64) -> io::Result<Option<(File, FileId)>> {
    let Some(file) = open_segment(path, seq, || {})? else {
        return Ok(None);
    };
    #[cfg(test)]
    if super::tests::identity_fails() {
        return Ok(None);
    }
    Ok(file_id(&file).ok().map(|id| (file, id)))
}

/// The counter of a segment's first record, when one starts within the cap.
/// Returns the bytes read too.
fn first_counter(file: &File) -> io::Result<(Option<u64>, u64)> {
    let mut scan = Scan::new(file.try_clone()?, 0, Mode::Boundary, ASSEMBLY_WINDOW);
    // Unreadable lines before the first record are stepped over, within one
    // capped read, so a torn or hand-edited head does not hide the segment.
    let counter = loop {
        match scan.next()? {
            Step::Record { entry, .. } => break mark_of(&entry).map(|m| m.counter),
            Step::Unreadable => {}
            Step::Budget | Step::End => break None,
        }
    };
    Ok((counter, scan.read))
}

/// Where a fresh read for `cursor` starts: the oldest segment for none, else
/// the last segment whose first record is at or below the cursor's counter.
/// `None` when no kept segment can hold it: the cursor's row is gone.
/// Adds the bytes it read to `read`.
pub(super) fn start(
    log: &Log<'_>,
    cursor: Option<&Mark>,
    read: &mut u64,
) -> io::Result<Option<(File, Place)>> {
    let mut chosen = None;
    for seq in segments(log.path)? {
        let Some((file, id)) = open(log.path, seq)? else {
            continue;
        };
        let fits = match cursor {
            None => true,
            Some(c) => {
                let (first, n) = first_counter(&file)?;
                *read += n;
                match first {
                    Some(first) if first > c.counter => break,
                    Some(_) => true,
                    None => false,
                }
            }
        };
        if fits {
            chosen = Some((file, seq, id));
            if cursor.is_none() {
                break;
            }
        }
    }
    Ok(chosen.map(|(file, seq, id)| {
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
        (file, place)
    }))
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
    for seq in segments(log.path)? {
        if let Some((file, id)) = open(log.path, seq)?
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
    if file.metadata()?.len() < place.offset {
        return Ok(None);
    }
    if let Some(anchor) = &place.anchor {
        let (same, n) = anchor.holds(&file)?;
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
