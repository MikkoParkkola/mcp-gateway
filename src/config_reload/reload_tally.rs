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

/// Counts plus the time the configuration still running was applied, behind
/// one lock so a reader never sees `attempts` ahead of `last`, nor a refusal
/// ahead of the apply that moved `last_applied_at`.
#[derive(Debug, Default)]
struct TallyInner {
    counts: ReloadCounts,
    /// Startup load, then each applied reload. A refusal does not move it:
    /// the version still running is the one this names.
    last_applied_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The counts, behind one lock so a reader never sees `attempts` ahead of
/// `last`.
#[derive(Debug, Default)]
pub struct ReloadTally {
    inner: parking_lot::Mutex<TallyInner>,
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
        self.inner.lock().counts
    }

    /// The configuration now running was loaded. The first call records it;
    /// an applied reload replaces it, and a later call leaves that time.
    /// A clock that cannot be read records nothing, so the next call tries
    /// again.
    pub(crate) fn note_loaded(&self) {
        let mut inner = self.inner.lock();
        if inner.last_applied_at.is_some() {
            return;
        }
        // Under the lock, as an attempt's stamp is, so an apply on another
        // thread cannot leave this older than that apply.
        inner.last_applied_at =
            super::refusals::rfc3339(crate::clock::system_time_or_before_epoch());
    }

    /// When the configuration still running was applied. `None` before the
    /// startup load is recorded, and when that clock could not be read.
    pub(crate) fn last_applied_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.inner.lock().last_applied_at
    }

    fn record(&self, outcome: ReloadResult) {
        let mut inner = self.inner.lock();
        // Read under the lock, so `last.at` is never older than an attempt
        // another thread recorded before this one.
        let at = super::refusals::rfc3339(crate::clock::system_time_or_before_epoch());
        inner.counts.attempts = inner.counts.attempts.saturating_add(1);
        if outcome == ReloadResult::Applied {
            inner.counts.applied = inner.counts.applied.saturating_add(1);
            // A refusal does not reach this arm, so it cannot move the time.
            inner.last_applied_at = at;
        }
        inner.counts.last = Some(LastReload { at, outcome });
    }
}
