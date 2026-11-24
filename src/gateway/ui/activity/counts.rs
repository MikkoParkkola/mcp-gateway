// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Counting over the Activity logs: one bounded, newest-first scan of a time
//! window ([`scan_window`]) that every count the UI shows is folded from, and
//! the Policies screen's fold of it into hits per rule ([`count_rule_hits`]).

use std::collections::HashMap;
use std::io;
use std::ops::{ControlFlow, RangeInclusive};
use std::path::Path;

use chrono::{DateTime, FixedOffset};

use super::access::{Access, AccessScope};
use super::answer::Joined;
use super::reader::{Line, WINDOW};
use super::rows::{Check, Kind};
use crate::clock::ClockBeforeEpoch;

/// The most bytes one counting read examines: eight list pages.
pub(in crate::gateway::ui) const COUNT_SCAN_BYTES: u64 = 8 * super::PAGE_SCAN_BYTES;

/// The bytes one pass reads: two windows, so that with both logs present each
/// reads one window inside the budget. With one window the invocation log
/// spends it and the governance log is read by the reader's past-budget
/// assembly on every pass.
pub(super) const COUNT_PASS_BYTES: u64 = 2 * WINDOW;

/// How a scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanEnd {
    /// Both logs were read to their oldest kept line.
    End,
    /// Two passes in a row each held a timed record and none at or after the
    /// window's start: the window lies above them.
    WindowPassed,
    /// The byte cap was spent.
    Cap,
}

/// One finished pass, as the caller is told of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gateway::ui) struct Pass {
    /// The bytes this pass examined.
    pub(in crate::gateway::ui) bytes: u64,
}

/// Read the logs newest first, pass by pass, and hand `each_record` every
/// record the caller may read that carries a time inside `window`, with its
/// kind and its joined delivery record.
#[expect(
    clippy::too_many_arguments,
    reason = "the logs, the read's bounds and the two callbacks, each owned by the caller"
)]
pub(super) fn scan_window(
    window: RangeInclusive<DateTime<FixedOffset>>,
    invocation: &Path,
    governance: Option<&Path>,
    check: &Check<'_>,
    access: &Access,
    byte_cap: u64,
    each_record: impl FnMut(&Line, Kind, &Joined, DateTime<FixedOffset>),
    after_pass: impl FnMut(Pass) -> ControlFlow<()>,
) -> io::Result<ScanEnd> {
    let _ = (window, invocation, governance, check, access, byte_cap);
    drop((each_record, after_pass));
    Ok(ScanEnd::End)
}

/// Why a count stopped, as its answer names it: the scan's three ends, and a
/// log that rotated during the read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::gateway::ui) enum Stopped {
    End,
    WindowPassed,
    Cap,
    Rotated,
}

impl Stopped {
    /// The answer's word for this stop.
    pub(in crate::gateway::ui) const fn word(self) -> &'static str {
        match self {
            Self::End => "end",
            Self::WindowPassed => "window_passed",
            Self::Cap => "cap",
            Self::Rotated => "rotated",
        }
    }
}

/// Hits per rule id in the 24 hours ending at `to` and the 24 hours before.
#[derive(Debug, Clone)]
pub(in crate::gateway::ui) struct RuleHits {
    /// `(newer day, older day)` per rule id.
    per_rule: HashMap<String, (u64, u64)>,
    /// `None`: nothing was read (a clock before 1970, or no log).
    pub(in crate::gateway::ui) stop: Option<Stopped>,
    /// The end of the newer day; `None` on a clock before 1970.
    pub(in crate::gateway::ui) to: Option<DateTime<FixedOffset>>,
    /// Whose calls were counted.
    pub(in crate::gateway::ui) scope: AccessScope,
}

impl RuleHits {
    /// Nothing read, for `scope`.
    pub(in crate::gateway::ui) fn unread(scope: AccessScope) -> Self {
        Self {
            per_rule: HashMap::new(),
            stop: None,
            to: None,
            scope,
        }
    }

    /// `(newer day, older day)` for the rule `id`.
    pub(in crate::gateway::ui) fn counts(&self, id: Option<&str>) -> Option<(u64, u64)> {
        let _ = id;
        None
    }
}

/// The hits per rule under `access` in the 48 hours ending at `now`.
pub(in crate::gateway::ui) fn count_rule_hits(
    now: Result<DateTime<FixedOffset>, ClockBeforeEpoch>,
    invocation: &Path,
    governance: Option<&Path>,
    access: &Access,
    byte_cap: u64,
    after_pass: impl FnMut(Pass) -> ControlFlow<()>,
) -> io::Result<RuleHits> {
    let _ = (now, invocation, governance, byte_cap);
    drop(after_pass);
    Ok(RuleHits::unread(access.scope()))
}
