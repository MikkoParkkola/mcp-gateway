// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The restart status record: one board per boot, holding the latest restart
//! attempt's phase, deadline, remaining calls and cancel reason for the admin
//! status view. The board's lock is a leaf: no other lock, no await and no
//! I/O while it is held; every method is infallible and returns at once.
#![allow(
    dead_code,
    clippy::unused_self,
    reason = "red stubs; the restart coordinator, a later slice, drives the transitions"
)]

use serde_json::Value;

use super::restart_floor::Cancelled;

/// Where an attempt is. Ranked Accepted < Checkpoint < Restarting < Saving <
/// Draining; Cancelled is terminal for its attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestartPhase {
    Accepted,
    Checkpoint,
    Restarting,
    Saving,
    Draining,
    Cancelled,
}

/// Why an attempt was cancelled before its commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestartCancel {
    /// A floor owner's checkpoint failed.
    Floor(Cancelled),
    /// A stop signal won the checkpoint.
    StopSignal,
    /// The recheck before the commit failed.
    Recheck,
    /// The acceptance audit was unavailable; the client got 503.
    AuditRefused,
}

/// The latest attempt's record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RestartStatus {
    id: u64,
    phase: RestartPhase,
    deadline_unix_ms: u64,
    remaining_calls: u64,
    cancel: Option<RestartCancel>,
}

impl RestartStatus {
    /// The status edge's form: `{id, phase, deadline, remaining_calls,
    /// reason}`, the phase lowercase, the deadline in unix ms, the reason
    /// rendered from the cancel (null without one).
    pub(crate) fn wire(&self) -> Value {
        Value::Null
    }
}

#[derive(Default)]
struct Board {
    last_id: u64,
    record: Option<RestartStatus>,
    committed: bool,
}

/// The one restart status board of this boot.
#[derive(Default)]
pub(crate) struct RestartBoard {
    board: parking_lot::Mutex<Board>,
}

impl RestartBoard {
    /// Start a new attempt and return its id (a per-boot sequence from 1).
    pub(crate) fn accept(&self, _checkpoint_deadline_unix_ms: u64) -> u64 {
        0
    }

    /// Accepted to Checkpoint.
    pub(crate) fn checkpoint(&self) {}

    /// Cancel the attempt before its commit.
    pub(crate) fn cancel(&self, _reason: RestartCancel) {}

    /// The commit edge: the deadline becomes the stop's own.
    pub(crate) fn commit(&self, _stop_deadline_unix_ms: u64) {}

    /// Checkpoint to Restarting, only after the commit; otherwise ignored and
    /// logged.
    pub(crate) fn restarting(&self) {}

    /// Forward to Saving after the commit; otherwise silent.
    pub(crate) fn saving(&self) {}

    /// Forward to Draining after the commit; otherwise silent.
    pub(crate) fn draining(&self) {}

    /// The calls still running, after the commit; otherwise silent.
    pub(crate) fn set_remaining_calls(&self, _n: u64) {}

    /// The latest record, `None` before any accept.
    pub(crate) fn status(&self) -> Option<RestartStatus> {
        None
    }
}

#[cfg(test)]
#[path = "restart_status_tests.rs"]
mod tests;
