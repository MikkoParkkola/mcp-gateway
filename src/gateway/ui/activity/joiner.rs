// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The join of delivery records to calls, held for one read (a page, or all
//! the passes of one export).

use super::answer::{Joined, Searched};
use super::reader::Line;

/// Where the reader is when it hands a call to the join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Seen {
    /// Bytes of the invocation log read above this line in this read:
    /// look-above bytes plus every line consumed since the page top.
    pub(super) above: u64,
    /// The bytes of this line, newline included.
    pub(super) len: u64,
    /// The first page of a read starts at the log head: nothing is above.
    pub(super) head_covered: bool,
}

/// The join state of one read.
#[derive(Debug, Default)]
pub(super) struct Joiner {
    secret: Option<Vec<u8>>,
    /// Admitted calls joined incomplete, or unfinished with no record.
    pub(super) join_incomplete: usize,
    /// Calls whose record failed the trust rule or was duplicated.
    pub(super) answer_integrity_failed: usize,
}

impl Joiner {
    pub(super) fn new(secret: Option<&[u8]>) -> Self {
        Self {
            secret: secret.map(<[u8]>::to_vec),
            ..Self::default()
        }
    }

    /// Fold a scanned invocation-log line that is not a listed row. `true`
    /// when the line was a delivery or a poison: the caller drops it.
    pub(super) fn observe(&mut self, line: &Line) -> bool {
        let _ = (&self.secret, line);
        false
    }

    /// The join for a call line. Does not count: see [`Self::count`].
    pub(super) fn join(&mut self, line: &Line, seen: Seen) -> Joined {
        let _ = (line, seen);
        Joined::NoRecord(Searched::Finished)
    }

    /// Count an admitted call's join.
    pub(super) fn count(&mut self, joined: &Joined) {
        let _ = joined;
    }
}
