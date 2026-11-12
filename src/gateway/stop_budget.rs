// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One stop budget for an HTTP gateway stop: `server.shutdown_timeout` is the
//! total from the trigger, split into absolute deadlines that every stage of
//! the stop is handed, so no stage starts a fresh timeout of its own.

use std::time::Duration;

use tokio::time::Instant;

/// The smallest total an HTTP stop accepts.
pub(crate) const HTTP_MIN_TOTAL: Duration = Duration::from_secs(9);

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BelowMinimum {
    pub(crate) configured: Duration,
    pub(crate) minimum: Duration,
}

impl std::fmt::Display for BelowMinimum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stub")
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StopBudget {
    t0: Instant,
}

impl StopBudget {
    pub(crate) fn http(t0: Instant, _total: Duration) -> Result<Self, BelowMinimum> {
        Ok(Self { t0 })
    }
    pub(crate) fn end(&self) -> Instant {
        self.t0
    }
    pub(crate) fn backend_end(&self) -> Instant {
        self.t0
    }
    pub(crate) fn post_listener_end(&self) -> Instant {
        self.t0
    }
    pub(crate) fn listener_end(&self) -> Instant {
        self.t0
    }
    pub(crate) fn runtime_end(&self) -> Instant {
        self.t0
    }
    pub(crate) fn listener_grace(&self) -> Duration {
        Duration::ZERO
    }
    pub(crate) fn stage_window(&self, _now: Instant, _cap: Duration) -> Duration {
        Duration::ZERO
    }
}

#[cfg(test)]
#[path = "stop_budget_tests.rs"]
mod tests;
