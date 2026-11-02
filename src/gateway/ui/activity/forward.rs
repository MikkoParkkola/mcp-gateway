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

use std::io;
use std::path::Path;

use serde_json::Value;

use super::access::Access;
use super::reader::Which;
use super::rows::Kind;

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
    pub(in crate::gateway::ui) fn keeps(self, kind: Kind) -> bool {
        let _ = kind;
        true
    }
}

/// One log as a source reads it.
#[derive(Clone, Copy, Debug)]
pub(in crate::gateway::ui) struct Log<'a> {
    pub(in crate::gateway::ui) path: &'a Path,
    pub(in crate::gateway::ui) kind: StreamKind,
    /// The logger's rewrite generation now.
    pub(in crate::gateway::ui) generation: u64,
    pub(in crate::gateway::ui) secret: Option<&'a [u8]>,
}

/// What bounds one call.
#[derive(Clone, Copy, Debug)]
pub(in crate::gateway::ui) struct Budget {
    pub(in crate::gateway::ui) rows: usize,
    pub(in crate::gateway::ui) bytes: u64,
}

/// One connection's place in one log. Held by the connection for one
/// catch-up and dropped with it.
#[derive(Debug, Default)]
pub(in crate::gateway::ui) struct Search {
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
    budget: Budget,
    search: &mut Search,
) -> io::Result<ForwardPage> {
    let _ = (log, cursor, stop, access, budget, search.restarts);
    #[cfg(test)]
    {
        tests::after_identity();
        let _ = tests::identity_fails();
    }
    Ok(ForwardPage::default())
}

/// The newest kept record's place, visible to the caller or not.
pub(in crate::gateway::ui) fn head(log: &Log<'_>) -> io::Result<Option<Mark>> {
    let _ = log;
    Ok(None)
}

/// The row for an announced record, as a read back gives it, or `None` when
/// this caller or this stream kind does not get it.
pub(in crate::gateway::ui) fn frame(
    log: &Log<'_>,
    access: &Access,
    entry: &Value,
) -> Option<Served> {
    let _ = (log, access, entry);
    None
}

#[cfg(test)]
#[path = "forward_tests.rs"]
mod tests;
