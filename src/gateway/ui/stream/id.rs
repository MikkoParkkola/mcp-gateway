// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The composite event id: `b<boot>.s<gen>.r<gen>.q<gen>.i<N>-<hash>.g<M>-<hash>`.
//!
//! Every part is optional and printed in that fixed order. An id names what one
//! connection has delivered, so a frame changes only its own part.

/// One log's position: the counter and the 16-hex hash of its last row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LogPart {
    pub(super) n: u64,
    pub(super) hash: String,
}

/// Which log a row belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LogName {
    Invocation,
    Governance,
}

/// A position in both logs. Either half may be absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct LogCursor {
    pub(super) inv: Option<LogPart>,
    pub(super) gov: Option<LogPart>,
}

/// The id could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IdError;

/// What a connection has delivered, as one id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct StreamId {
    pub(super) boot: Option<u64>,
    pub(super) status: Option<u64>,
    pub(super) reload: Option<u64>,
    pub(super) queue: Option<u64>,
    pub(super) cursor: LogCursor,
}

impl StreamId {
    /// Read an id; any malformed or out-of-order part is an error.
    pub(super) fn parse(_text: &str) -> Result<Self, IdError> {
        Err(IdError)
    }

    /// Print the id; `parse(render(x)) == x`.
    pub(super) fn render(&self) -> String {
        String::new()
    }
}
