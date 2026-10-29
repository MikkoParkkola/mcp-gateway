// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! How many reloads this process attempted and how each ended: the read model
//! behind the `reloads` block of `GET /ui/api/gateway`.
//!
//! One tally per gateway, held by [`super::refusals::ReloadReporting`], so the
//! file watcher, the admin writes, the meta-tool and lock recovery all report
//! into the same counts. The outcome is recorded where it is decided (the
//! applied branch, the refused branch, the lock skip), never read back out of
//! an error string, so every attempt has exactly one outcome.
//!
//! Process lifetime only: a restart begins again at zero. Applied reloads that
//! earlier runs made are on `/ui/api/markers`; refusals are in the ledger.

use serde::Serialize;

/// How one reload attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadResult {
    /// The new configuration was published.
    Applied,
    /// The file or a check refused it; the previous configuration still runs.
    Refused,
    /// The config lock could not be taken, so nothing was read.
    Skipped,
}

/// The last attempt: when, and how it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LastReload {
    /// RFC 3339, display only; `None` when the clock could not be read.
    pub at: Option<chrono::DateTime<chrono::Utc>>,
    /// How it ended.
    pub outcome: ReloadResult,
}

/// The tally as served.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ReloadCounts {
    /// Attempts since this process started.
    pub attempts: u64,
    /// Of those, the ones that were applied.
    pub applied: u64,
    /// The latest attempt; `None` before the first.
    pub last: Option<LastReload>,
}

/// The counts, behind one lock so a reader never sees `attempts` ahead of
/// `last`.
#[derive(Debug, Default)]
pub struct ReloadTally {
    counts: parking_lot::Mutex<ReloadCounts>,
}

impl ReloadTally {
    /// An attempt that published a new configuration.
    pub(crate) fn applied(&self) {
        self.record(ReloadResult::Applied);
    }

    /// An attempt that was refused.
    pub(crate) fn refused(&self) {
        self.record(ReloadResult::Refused);
    }

    /// An attempt that could not take the config lock.
    pub(crate) fn skipped(&self) {
        self.record(ReloadResult::Skipped);
    }

    /// A copy of the counts, taken under the lock.
    #[cfg(any(test, feature = "webui"))]
    pub(crate) fn snapshot(&self) -> ReloadCounts {
        *self.counts.lock()
    }

    fn record(&self, outcome: ReloadResult) {
        let mut counts = self.counts.lock();
        // Read under the lock, so `last.at` is never older than an attempt
        // another thread recorded before this one.
        let at = super::refusals::rfc3339(crate::clock::system_time_or_before_epoch());
        counts.attempts = counts.attempts.saturating_add(1);
        if outcome == ReloadResult::Applied {
            counts.applied = counts.applied.saturating_add(1);
        }
        counts.last = Some(LastReload { at, outcome });
    }
}
