// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The graceful-ending planner: how a stop's budget splits into the wait
//! after EOF, the SIGTERM phase and the kill's reserve.

use std::time::Duration;

use super::super::child_tree::{Ending, NESTED_TERM_NEED};
use super::{KILL_RESERVE, MIN_PHASE, StopDeadline, stop_deadline};

/// A close with no stop deadline from its caller gets this budget.
pub(super) const DEFAULT_STOP_BUDGET: Duration = Duration::from_secs(10);

/// The graceful ending that fits `budget`: [`KILL_RESERVE`] is kept for the
/// kill, a third of the rest goes to the wait after SIGTERM and the remainder
/// to the wait after EOF. Stdin that could not be closed (a writer holds it)
/// gets no EOF wait, since the child never saw EOF. Windows has no SIGTERM.
/// A hurried deadline keeps at least `MIN_PHASE` for SIGTERM when it fits. An
/// unhurried stop keeps at least `NESTED_TERM_NEED` for it (capped so EOF keeps
/// `MIN_PHASE`): a nested gateway only learns to hurry at the SIGTERM.
pub(in super::super) fn graceful_ending(
    budget: Duration,
    stdin_closed: bool,
    deadline: Option<&StopDeadline>,
) -> Ending {
    let waits = budget.saturating_sub(KILL_RESERVE);
    let (eof, term) = match (cfg!(unix), stdin_closed) {
        (true, true) => {
            let term = deadline.map_or(waits / 3, |deadline| deadline.term_phase(waits));
            // An unhurried stop keeps a SIGTERM phase a nested gateway can hurry
            // inside, leaving the EOF wait at least the minimum phase.
            let term = if deadline.is_some_and(StopDeadline::is_hurried) {
                term
            } else {
                term.max(NESTED_TERM_NEED.min(waits.saturating_sub(MIN_PHASE)))
            };
            (waits.saturating_sub(term), term)
        }
        (true, false) => (Duration::ZERO, waits),
        (false, true) => (waits, Duration::ZERO),
        (false, false) => (Duration::ZERO, Duration::ZERO),
    };
    let kept = |wait: Duration| {
        if wait < MIN_PHASE {
            Duration::ZERO
        } else {
            wait
        }
    };
    match (kept(eof), kept(term)) {
        (Duration::ZERO, Duration::ZERO) => Ending::Now,
        (eof, term) => Ending::Graceful { eof, term },
    }
}

/// The graceful ending for a handover whose `budget` was fixed before its
/// stop snapshot ran: the time the snapshot took comes off first, so the
/// waits fit what is left and the stop still ends inside the stage's budget.
pub(super) fn ending_after_snapshot(
    budget: Duration,
    snapshot_took: Duration,
    stdin_closed: bool,
    deadline: Option<&StopDeadline>,
) -> Ending {
    graceful_ending(budget.saturating_sub(snapshot_took), stdin_closed, deadline)
}

/// Every graceful stop's one route (code review r3, T2): `budget` is fixed
/// once, before `snapshot` runs with it as its limit; the snapshot is timed
/// and its time comes off before the plan. A budget read again after the
/// snapshot would not count it when the stop has no caller deadline
/// ([`DEFAULT_STOP_BUDGET`] both times).
pub(super) fn ending_around_snapshot(
    budget: Duration,
    snapshot: impl FnOnce(Duration),
    close_stdin: impl FnOnce() -> bool,
    deadline: Option<&StopDeadline>,
) -> Ending {
    ending_around_snapshot_by(
        std::time::Instant::now,
        budget,
        snapshot,
        close_stdin,
        deadline,
    )
}

/// [`ending_around_snapshot`] on the clock `now` (rows supply the readings).
pub(super) fn ending_around_snapshot_by(
    mut now: impl FnMut() -> std::time::Instant,
    budget: Duration,
    snapshot: impl FnOnce(Duration),
    close_stdin: impl FnOnce() -> bool,
    deadline: Option<&StopDeadline>,
) -> Ending {
    let began = now();
    snapshot(budget);
    let took = now().saturating_duration_since(began);
    ending_after_snapshot(budget, took, close_stdin(), deadline)
}

/// The budget left for a stop started now: the caller's deadline, else
/// [`DEFAULT_STOP_BUDGET`].
pub(super) fn stop_budget() -> Duration {
    stop_deadline().map_or(DEFAULT_STOP_BUDGET, |deadline| {
        deadline.saturating_duration_since(tokio::time::Instant::now())
    })
}
