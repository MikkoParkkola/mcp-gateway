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
/// Reserved for the backend stage: the stdio reaper's kill reserve (6 s), the
/// graceful window a stopping nested gateway needs before it (3 s: a hurried
/// nested gateway took 2.3 s to take its own leaf down in the nested stop rows),
/// and 0.4 s of first-step and scheduling allowances for the reaper's phases.
/// With less, a parent that reaches its backend stage after the listener has
/// used its grace group-kills a busy nested gateway first, and the leaf, which
/// has its own process group, is orphaned.
const BACKEND_RESERVE: Duration = Duration::from_millis(9_400);
/// Reserved for retirement: runtime and main-stack coordination, then the logger.
const TERMINAL_RESERVE: Duration = Duration::from_millis(2_250);
/// The logger's share of the terminal reserve: the runtime wait ends this long
/// before the total does. Test-only with `runtime_end`.
#[cfg(test)]
const LOGGER_TAIL: Duration = Duration::from_secs(2);

/// The most an in-flight, override or task drain waits, whatever is left to Dp.
pub(crate) const DRAIN_CAP: Duration = Duration::from_secs(10);

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
        Ok(Self::fixed_at(t0, total))
    }

    /// The budget of a stop whose listener has returned: the total was accepted
    /// when the gateway started, so this never refuses, and every deadline
    /// saturates at the trigger instead of failing. A second refusal here would
    /// skip the whole stop, backends included.
    pub(crate) fn fixed_at(t0: Instant, total: Duration) -> Self {
        Self { t0, total }
    }

    /// D: the end of the whole stop. Test-only: the stages are given Db, Dp and
    /// Dl, and nothing in production waits on D itself until retirement does.
    #[cfg(test)]
    pub(crate) fn end(&self) -> Instant {
        self.t0 + self.total
    }

    /// Db: the end of the backend stage. The backend reserve is time kept for
    /// it, never taken off this deadline.
    pub(crate) fn backend_end(&self) -> Instant {
        self.t0 + self.total.saturating_sub(TERMINAL_RESERVE)
    }

    /// Dp: one deadline for everything between the listener and the backends.
    pub(crate) fn post_listener_end(&self) -> Instant {
        self.t0
            + self
                .total
                .saturating_sub(BACKEND_RESERVE + TERMINAL_RESERVE)
    }

    /// Dl: where the listener grace ends, leaving the post-listener reserve.
    /// Test-only: production asks `listener_grace_for`, before any trigger.
    #[cfg(test)]
    pub(crate) fn listener_end(&self) -> Instant {
        self.t0
            + self
                .total
                .saturating_sub(POST_RESERVE + BACKEND_RESERVE + TERMINAL_RESERVE)
    }

    /// Dr: where the runtime wait ends, before the logger's share. Test-only
    /// until the retirement slice waits on it.
    #[cfg(test)]
    pub(crate) fn runtime_end(&self) -> Instant {
        self.end() - LOGGER_TAIL
    }

    /// The listener's grace for a stop whose total is `total`, known before any
    /// trigger exists: the listener is started first.
    pub(crate) fn listener_grace_for(total: Duration) -> Duration {
        total.saturating_sub(POST_RESERVE + BACKEND_RESERVE + TERMINAL_RESERVE)
    }

    /// How long after the trigger Dp falls, for a window saver started before
    /// any trigger exists.
    pub(crate) fn post_listener_offset(total: Duration) -> Duration {
        total.saturating_sub(BACKEND_RESERVE + TERMINAL_RESERVE)
    }

    /// The listener's grace from the trigger; production asks
    /// [`Self::listener_grace_for`], before any trigger exists. Test-only: a row
    /// holds the two together.
    #[cfg(test)]
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

    /// Run one post-listener stage under its own `cap` or what is left to Dp,
    /// whichever is less; `None` when it ran out (logged by `what`) so the stop
    /// goes on to the next stage. Never renewed: a stage that starts at or after
    /// Dp gets no time at all, and its work is not polled even once.
    pub(crate) async fn stage<F: std::future::Future>(
        &self,
        what: &'static str,
        cap: Duration,
        work: F,
    ) -> Option<F::Output> {
        within(what, self.stage_window(Instant::now(), cap), work).await
    }

    /// Run a step that must finish before the backends are listed, so it may use
    /// every moment left to Db, the end of the backend stage, even after Dp. The
    /// same rule otherwise: no time left means the work is not polled.
    pub(crate) async fn stage_until_backend_end<F: std::future::Future>(
        &self,
        what: &'static str,
        work: F,
    ) -> Option<F::Output> {
        let window = self.backend_end().saturating_duration_since(Instant::now());
        within(what, window, work).await
    }
}

/// `work` under `window`; with none left it is not polled, because a first poll
/// can do synchronous work that no timeout can cut.
async fn within<F: std::future::Future>(
    what: &'static str,
    window: Duration,
    work: F,
) -> Option<F::Output> {
    if window.is_zero() {
        tracing::warn!(
            stage = what,
            "stop stage had no time left; the stop goes on"
        );
        return None;
    }
    if let Ok(done) = tokio::time::timeout(window, work).await {
        Some(done)
    } else {
        tracing::warn!(
            stage = what,
            "stop stage ran out of its window; the stop goes on"
        );
        None
    }
}

#[cfg(test)]
#[path = "stop_budget_tests.rs"]
mod tests;
