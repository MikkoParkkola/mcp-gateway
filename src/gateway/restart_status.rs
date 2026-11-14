// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The restart status record: one board per boot, holding the latest restart
//! attempt's phase, deadline, remaining calls and cancel reason for the admin
//! status view. The board's lock is a leaf: no other lock, no await and no
//! I/O while it is held; every method is infallible and returns at once.
#![allow(
    dead_code,
    reason = "the restart coordinator, a later slice, drives the transitions"
)]

use serde_json::{Value, json};

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

impl RestartPhase {
    /// The order phases move in; Cancelled is outside it.
    const fn rank(self) -> u8 {
        match self {
            Self::Cancelled => 0,
            Self::Accepted => 1,
            Self::Checkpoint => 2,
            Self::Restarting => 3,
            Self::Saving => 4,
            Self::Draining => 5,
        }
    }

    const fn word(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Checkpoint => "checkpoint",
            Self::Restarting => "restarting",
            Self::Saving => "saving",
            Self::Draining => "draining",
            Self::Cancelled => "cancelled",
        }
    }
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

impl RestartCancel {
    /// The status edge's text: a floor cancel names its owner, stage and
    /// reason in the audit's own words.
    fn text(self) -> String {
        match self {
            Self::Floor(cancelled) => {
                let detail = cancelled.audit_detail();
                let word = |key: &str| {
                    detail
                        .get(key)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                format!(
                    "floor:{}:{}:{}",
                    word("owner"),
                    word("stage"),
                    word("reason")
                )
            }
            Self::StopSignal => "stop_signal".to_owned(),
            Self::Recheck => "recheck_failed".to_owned(),
            Self::AuditRefused => "audit_unavailable".to_owned(),
        }
    }
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
        json!({
            "id": self.id,
            "phase": self.phase.word(),
            "deadline": self.deadline_unix_ms,
            "remaining_calls": self.remaining_calls,
            "reason": self.cancel.map(RestartCancel::text),
        })
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
    pub(crate) fn accept(&self, checkpoint_deadline_unix_ms: u64) -> u64 {
        let mut board = self.board.lock();
        board.last_id += 1;
        board.committed = false;
        board.record = Some(RestartStatus {
            id: board.last_id,
            phase: RestartPhase::Accepted,
            deadline_unix_ms: checkpoint_deadline_unix_ms,
            remaining_calls: 0,
            cancel: None,
        });
        board.last_id
    }

    /// Accepted to Checkpoint.
    pub(crate) fn checkpoint(&self) {
        self.edit(|record, _| {
            if record.phase == RestartPhase::Accepted {
                record.phase = RestartPhase::Checkpoint;
            }
        });
    }

    /// Cancel the attempt before its commit.
    pub(crate) fn cancel(&self, reason: RestartCancel) {
        self.edit(|record, committed| {
            if !*committed && record.phase != RestartPhase::Cancelled {
                record.phase = RestartPhase::Cancelled;
                record.cancel = Some(reason);
            }
        });
    }

    /// The commit edge: the deadline becomes the stop's own.
    pub(crate) fn commit(&self, stop_deadline_unix_ms: u64) {
        self.edit(|record, committed| {
            if !*committed && record.phase == RestartPhase::Checkpoint {
                *committed = true;
                record.deadline_unix_ms = stop_deadline_unix_ms;
            }
        });
    }

    /// Checkpoint to Restarting, only after the commit; before it the call is
    /// ignored and logged.
    pub(crate) fn restarting(&self) {
        let mut early = None;
        self.edit(|record, committed| {
            if *committed {
                forward(record, RestartPhase::Restarting);
            } else {
                early = Some(record.id);
            }
        });
        // Logged after the board's lock is released: the lock is a leaf.
        if let Some(id) = early {
            tracing::warn!(
                attempt = id,
                "restart status: restarting before commit, ignored"
            );
        }
    }

    /// Forward to Saving after the commit; otherwise silent.
    pub(crate) fn saving(&self) {
        self.edit(|record, committed| {
            if *committed {
                forward(record, RestartPhase::Saving);
            }
        });
    }

    /// Forward to Draining after the commit; otherwise silent.
    pub(crate) fn draining(&self) {
        self.edit(|record, committed| {
            if *committed {
                forward(record, RestartPhase::Draining);
            }
        });
    }

    /// The calls still running, after the commit; otherwise silent.
    pub(crate) fn set_remaining_calls(&self, n: u64) {
        self.edit(|record, committed| {
            if *committed {
                record.remaining_calls = n;
            }
        });
    }

    /// The latest record, `None` before any accept.
    pub(crate) fn status(&self) -> Option<RestartStatus> {
        self.board.lock().record
    }

    /// Apply `change` to the latest record and its commit flag; nothing
    /// before any accept.
    fn edit(&self, change: impl FnOnce(&mut RestartStatus, &mut bool)) {
        let mut board = self.board.lock();
        let Board {
            record, committed, ..
        } = &mut *board;
        if let Some(record) = record.as_mut() {
            change(record, committed);
        }
    }
}

/// Move `record` to `to` only when that is forward by rank. A committed
/// record is never Cancelled (cancel is refused after the commit).
fn forward(record: &mut RestartStatus, to: RestartPhase) {
    if to.rank() > record.phase.rank() {
        record.phase = to;
    }
}

#[cfg(test)]
#[path = "restart_status_tests.rs"]
mod tests;
