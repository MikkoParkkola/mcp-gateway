// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Counting over the Activity logs: one bounded, newest-first scan of a time
//! window ([`scan_window`]) that every count the UI shows is folded from, and
//! the Policies screen's fold of it into hits per rule ([`count_rule_hits`]).

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::ops::{ControlFlow, RangeInclusive};
use std::path::Path;

use chrono::{DateTime, FixedOffset, TimeDelta};

use super::access::{Access, AccessScope};
use super::answer::Joined;
use super::joiner::Joiner;
use super::reader::{
    Cursor, Limits, Line, Look, Seen, WINDOW, read_page_joined, restarted_mid_read, timestamp,
};
use super::rows::{Check, Kind, row_id};
use crate::clock::ClockBeforeEpoch;
use crate::security::decision_record::read::decision_evidence;

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
/// record the caller may read, that the list would show as a row, and that
/// carries a time inside `window`, with its kind and its joined delivery
/// record. Every line goes through the list's
/// own steps ([`Joiner::admit`]), and one join is held across the passes,
/// so a delivery read in one pass reaches its call in the next.
///
/// Each pass reads [`COUNT_PASS_BYTES`]; `after_pass` is told what it read
/// and may stop the scan (`Err(ConnectionAborted)`). The scan ends at the
/// logs' oldest line ([`ScanEnd::End`]), after two passes in a row that each
/// held a timed line and none at or after the window's start
/// ([`ScanEnd::WindowPassed`]; a log keeps its recorded order, not time
/// order, so one old stamp proves nothing), or once `byte_cap` is spent
/// ([`ScanEnd::Cap`]). The window rule reads every timed line, whoever may
/// read it: it asks where the log's time stands, not what this caller sees.
///
/// A pass after the first that finds its segment gone (retention removed
/// it) ends the scan with `Err(Interrupted)`. That pass has already handed
/// records to `each_record`, so a caller drops whatever it folded.
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
    mut each_record: impl FnMut(&Line, Kind, &Joined, DateTime<FixedOffset>),
    mut after_pass: impl FnMut(Pass) -> ControlFlow<()>,
) -> io::Result<ScanEnd> {
    let joiner = RefCell::new(Joiner::new(check));
    // This pass held a timed line; one of them at or after the start.
    let (timed, fresh) = (Cell::new(false), Cell::new(false));
    let mut keep = |line: &Line, seen: Seen| {
        let admitted = joiner.borrow_mut().admit(line, seen, access);
        let Some(at) = timestamp(&line.entry) else {
            return false;
        };
        timed.set(true);
        if at >= *window.start() {
            fresh.set(true);
        }
        // Only a record the list can show as a row counts (it needs its
        // counter and entry hash), so a count never exceeds what Activity
        // lists for the same window.
        if let Some((kind, joined)) = admitted
            && window.contains(&at)
            && row_id(line).is_some()
        {
            each_record(line, kind, &joined, at);
        }
        // Nothing is held: the caller folds as the records go by.
        false
    };
    let mut cursor: Option<Cursor> = None;
    let mut carried = Seen {
        above: 0,
        head_covered: true,
    };
    let (mut scanned, mut old_passes) = (0_u64, 0_u8);
    loop {
        timed.set(false);
        fresh.set(false);
        let limits = Limits {
            matches: usize::MAX,
            bytes: COUNT_PASS_BYTES.min(byte_cap.saturating_sub(scanned)),
        };
        // One read across every pass: what lies above a pass's top was read
        // by the pass before, so the position carries, as in the export.
        let look = Look::Carried(carried);
        let page = read_page_joined(
            invocation,
            governance,
            cursor.as_ref(),
            limits,
            look,
            &mut keep,
        )?;
        restarted_mid_read(cursor.as_ref(), &page)?;
        carried = page.above_end;
        scanned += page.bytes_examined;
        let pass = Pass {
            bytes: page.bytes_examined,
        };
        if after_pass(pass).is_break() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the caller stopped the scan",
            ));
        }
        let Some(next) = page.next else {
            return Ok(ScanEnd::End);
        };
        old_passes = if timed.get() && !fresh.get() {
            old_passes + 1
        } else {
            0
        };
        if old_passes == 2 {
            return Ok(ScanEnd::WindowPassed);
        }
        if scanned >= byte_cap {
            return Ok(ScanEnd::Cap);
        }
        cursor = Some(next);
    }
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
    /// Nothing read, for a caller with `access`.
    pub(in crate::gateway::ui) fn unread(access: &Access) -> Self {
        Self {
            per_rule: HashMap::new(),
            stop: None,
            to: None,
            scope: access.scope(),
        }
    }

    /// `(newer day, older day)` for the rule `id`: `None` when nothing was
    /// counted (no read, or a rotation), `(0, 0)` for a rule with no id or no
    /// record. Counts from a stop other than the end are what was read: the
    /// answer's `complete` says so.
    pub(in crate::gateway::ui) fn counts(&self, id: Option<&str>) -> Option<(u64, u64)> {
        match self.stop {
            None | Some(Stopped::Rotated) => None,
            Some(_) => Some(
                id.and_then(|id| self.per_rule.get(id))
                    .copied()
                    .unwrap_or_default(),
            ),
        }
    }

    /// The two days' bounds, when the clock could be read.
    pub(in crate::gateway::ui) fn days(&self) -> Option<Days> {
        self.to.map(Days::ending)
    }
}

/// The two days counted: the newer `[split, to]`, the older `[from, split)`,
/// stated as `[from, older_to]`. Stamps carry fractions of a second, so
/// `older_to` is one nanosecond before `split`: the Activity filter, which
/// compares parsed times inclusively, then lists exactly the older day.
#[derive(Debug, Clone, Copy)]
pub(in crate::gateway::ui) struct Days {
    pub(in crate::gateway::ui) from: DateTime<FixedOffset>,
    pub(in crate::gateway::ui) older_to: DateTime<FixedOffset>,
    pub(in crate::gateway::ui) split: DateTime<FixedOffset>,
    pub(in crate::gateway::ui) to: DateTime<FixedOffset>,
}

impl Days {
    fn ending(to: DateTime<FixedOffset>) -> Self {
        let day = crate::duration_bound::delta!(hours, 24);
        let split = to - day;
        Self {
            from: split - day,
            older_to: split - TimeDelta::nanoseconds(1),
            split,
            to,
        }
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
    let Ok(to) = now else {
        return Ok(RuleHits::unread(access));
    };
    let days = Days::ending(to);
    // No secret: a count reads no signature, and the join only decides what
    // an answer row would say.
    let check = Check::new(None, invocation, governance);
    let mut per_rule: HashMap<String, (u64, u64)> = HashMap::new();
    let end = scan_window(
        days.from..=days.to,
        invocation,
        governance,
        &check,
        access,
        byte_cap,
        |line, _, _, at| {
            // The rule the Activity filter matches (`read::matches_rule`).
            let Some(rule) = decision_evidence(&line.entry).and_then(|d| d.rule_id) else {
                return;
            };
            let slot = per_rule.entry(rule).or_default();
            if at >= days.split {
                slot.0 += 1;
            } else {
                slot.1 += 1;
            }
        },
        after_pass,
    );
    let stop = match end {
        Ok(ScanEnd::End) => Stopped::End,
        Ok(ScanEnd::WindowPassed) => Stopped::WindowPassed,
        Ok(ScanEnd::Cap) => Stopped::Cap,
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
            // Records may have been read twice: none of it is a count.
            per_rule.clear();
            Stopped::Rotated
        }
        Err(e) => return Err(e),
    };
    Ok(RuleHits {
        per_rule,
        stop: Some(stop),
        to: Some(to),
        scope: access.scope(),
    })
}
