// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One stop budget for an HTTP gateway stop: `server.shutdown_timeout` is the
//! total from the trigger, split into absolute deadlines that every stage of
//! the stop is handed, so no stage starts a fresh timeout of its own.

use std::time::Duration;

use tokio::time::Instant;

/// Listener grace the budget always keeps for open requests.
const LISTENER_MIN: Duration = Duration::from_millis(100);
/// Reserved for the post-listener, pre-backend work: saves, window close, drains.
const POST_RESERVE: Duration = Duration::from_millis(250);
/// Reserved for the backend stage: the stdio reaper's kill reserve (6 s) plus
/// a first-step allowance and a scheduling allowance for each of its phases.
const BACKEND_RESERVE: Duration = Duration::from_millis(6_400);
/// Reserved for retirement: runtime and main-stack coordination, then the logger.
const TERMINAL_RESERVE: Duration = Duration::from_millis(2_250);
/// The logger's share of the terminal reserve: the runtime wait ends this long
/// before the total does.
const LOGGER_TAIL: Duration = Duration::from_secs(2);

/// The smallest total an HTTP stop accepts: every reserve plus the minimum
/// listener grace.
pub(crate) const HTTP_MIN_TOTAL: Duration = LISTENER_MIN
    .saturating_add(POST_RESERVE)
    .saturating_add(BACKEND_RESERVE)
    .saturating_add(TERMINAL_RESERVE);

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BelowMinimum {
    pub(crate) configured: Duration,
    pub(crate) minimum: Duration,
}

impl std::fmt::Display for BelowMinimum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "server.shutdown_timeout is {:?}, below the {:?} an HTTP stop needs for the listener \
             grace, the saves, the backend stop and the logger flush; set it to at least {:?}",
            self.configured, self.minimum, self.minimum
        )
    }
}

/// The absolute deadlines of one HTTP stop, fixed at the trigger.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StopBudget {
    t0: Instant,
    total: Duration,
}

impl StopBudget {
    /// The budget of an HTTP stop triggered at `t0` with `total` as
    /// `server.shutdown_timeout`; refuses a total that cannot hold every stage.
    pub(crate) fn http(t0: Instant, total: Duration) -> Result<Self, BelowMinimum> {
        if total < HTTP_MIN_TOTAL {
            return Err(BelowMinimum {
                configured: total,
                minimum: HTTP_MIN_TOTAL,
            });
        }
        Ok(Self { t0, total })
    }

    /// D: the end of the whole stop.
    pub(crate) fn end(&self) -> Instant {
        self.t0 + self.total
    }

    /// Db: the end of the backend stage. The backend reserve is time kept for
    /// it, never taken off this deadline.
    pub(crate) fn backend_end(&self) -> Instant {
        self.end() - TERMINAL_RESERVE
    }

    /// Dp: one deadline for everything between the listener and the backends.
    pub(crate) fn post_listener_end(&self) -> Instant {
        self.backend_end() - BACKEND_RESERVE
    }

    /// Dl: where the listener grace ends, leaving the post-listener reserve.
    pub(crate) fn listener_end(&self) -> Instant {
        self.post_listener_end() - POST_RESERVE
    }

    /// Dr: where the runtime wait ends, before the logger's share.
    pub(crate) fn runtime_end(&self) -> Instant {
        self.end() - LOGGER_TAIL
    }

    /// The listener's grace from the trigger.
    pub(crate) fn listener_grace(&self) -> Duration {
        self.listener_end().saturating_duration_since(self.t0)
    }

    /// What a post-listener stage may wait from `now`: its own `cap`, or what is
    /// left to Dp if that is less. Never renewed: after Dp it is zero.
    pub(crate) fn stage_window(&self, now: Instant, cap: Duration) -> Duration {
        self.post_listener_end()
            .saturating_duration_since(now)
            .min(cap)
    }
}

#[cfg(test)]
#[path = "stop_budget_tests.rs"]
mod tests;
