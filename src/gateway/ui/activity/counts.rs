// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Counting over the Activity logs: one bounded, newest-first scan of a time
//! window ([`scan_window`]) that every count the UI shows is folded from, and
//! the Policies screen's fold of it into hits per rule ([`count_rule_hits`]).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::ops::{ControlFlow, RangeInclusive};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, FixedOffset, TimeDelta};
use serde::Deserialize;
use serde_json::json;

use super::access::{Access, AccessScope};
use super::answer::Joined;
use super::joiner::Joiner;
use super::reader::{
    Cursor, Limits, Line, Look, Seen, WINDOW, read_page_joined, restarted_mid_read, timestamp,
};
use super::rows::{Check, FeedOutcome, Filter, Kind, row_id};
use super::{Admitted, AppState, Early, ListQuery, Logs, bad_request, blocking, flat_error, parse};
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

/// The Outcome group's counts query: the list's filters and its window. The
/// list's own `outcome`, `cursor` and `limit` are named so a malformed one
/// fails as the list's does, before access is decided; any other parameter
/// lands in `other`. All of those are refused by name.
#[derive(Debug, Default, Deserialize)]
pub(super) struct CountsQuery {
    pub(super) outcome: Option<String>,
    pub(super) cursor: Option<String>,
    pub(super) limit: Option<String>,
    pub(super) effect: Option<String>,
    pub(super) server: Option<String>,
    pub(super) caller: Option<String>,
    pub(super) rule: Option<String>,
    pub(super) q: Option<String>,
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    #[serde(flatten)]
    pub(super) other: BTreeMap<String, String>,
}

/// The counts query as the list parses its filters, with its window, or the
/// 400 that refuses it: a parameter the route does not take, a missing bound,
/// or a window that does not end after it starts.
fn checked(query: &CountsQuery) -> Result<(Filter, RangeInclusive<DateTime<FixedOffset>>), Early> {
    let refuse = |error: String| Box::new(bad_request(json!({ "error": error })));
    let listed = [
        ("outcome", &query.outcome),
        ("cursor", &query.cursor),
        ("limit", &query.limit),
    ];
    let named = listed
        .iter()
        .find(|(_, sent)| sent.is_some())
        .map(|(name, _)| *name);
    if let Some(name) = named.or_else(|| query.other.keys().next().map(String::as_str)) {
        return Err(refuse(format!("`{name}` is not a counts parameter")));
    }
    let as_listed = ListQuery {
        effect: query.effect.clone(),
        server: query.server.clone(),
        caller: query.caller.clone(),
        rule: query.rule.clone(),
        q: query.q.clone(),
        from: query.from.clone(),
        to: query.to.clone(),
        ..ListQuery::default()
    };
    let filter = parse(&as_listed)?.filter;
    let (Some(from), Some(to)) = (filter.from, filter.to) else {
        return Err(refuse("`from` and `to` are both required".to_owned()));
    };
    if to <= from {
        return Err(refuse("`to` must be after `from`".to_owned()));
    }
    Ok((filter, from..=to))
}

/// The count of each Outcome value for `query` under `access`: for each, the
/// number of rows the list shows for that value over the same window. Blocking:
/// it reads the log files, in one scan of at most `byte_cap` bytes.
pub(super) fn count_page(
    logs: &Logs,
    access: &Access,
    query: &CountsQuery,
    byte_cap: u64,
    after_pass: impl FnMut(Pass) -> ControlFlow<()>,
) -> Response {
    let (filter, window) = match checked(query) {
        Ok(parsed) => parsed,
        Err(refusal) => return *refusal,
    };
    // The list's filter with only the outcome changed, once per value.
    let values = [
        Filter {
            outcome: Some(FeedOutcome::Ok),
            ..filter.clone()
        },
        Filter {
            outcome: Some(FeedOutcome::Failed),
            ..filter.clone()
        },
        Filter {
            outcome: Some(FeedOutcome::Blocked),
            ..filter.clone()
        },
        Filter {
            cleaned: true,
            ..filter.clone()
        },
    ];
    // All, then each value in the order above.
    let mut tally = [0_u64; 5];
    let check = logs.check();
    let end = scan_window(
        window,
        &logs.invocation,
        logs.governance.as_deref(),
        &check,
        access,
        byte_cap,
        |line, kind, joined, _| {
            if !filter.matches(line, kind, joined) {
                return;
            }
            tally[0] += 1;
            for (count, value) in tally[1..].iter_mut().zip(&values) {
                if value.matches(line, kind, joined) {
                    *count += 1;
                }
            }
        },
        after_pass,
    );
    let stop = match Stopped::of(end) {
        Ok(Stopped::Rotated) => {
            return flat_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "the log rotated while it was being counted: try again",
            )
            .into_response();
        }
        Ok(stop) => stop,
        Err(error) => {
            // A caller that went away stopped its own read: nothing to report.
            if error.kind() != io::ErrorKind::ConnectionAborted {
                tracing::warn!(%error, "activity counts read failed");
            }
            return flat_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the activity log could not be read",
            )
            .into_response();
        }
    };
    let [all, ok, failed, blocked, cleaned] = tally;
    Json(json!({
        "access": access.scope(),
        "counts": {"all": all, "ok": ok, "failed": failed, "blocked": blocked, "cleaned": cleaned},
        "complete": stop == Stopped::End,
        "stopped": stop.word(),
    }))
    .into_response()
}

/// Set once the request it belongs to is dropped (its caller went away). The
/// read checks it between passes, so an abandoned count stops within a pass.
#[derive(Default)]
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// `GET /ui/api/activity/counts`. Its bounds are checked before anything is
/// held; then it takes one of the counts permits, and only then a read slot,
/// so counts never hold more than two of the four.
pub(super) async fn counts_route(
    State(state): State<Arc<AppState>>,
    read: Admitted<Query<CountsQuery>>,
) -> Response {
    let Admitted {
        access,
        logs,
        input: Query(query),
    } = read;
    if let Err(refusal) = checked(&query) {
        return *refusal;
    }
    let dropped = DropFlag::default();
    let Ok(permit) = Arc::clone(state.process.counts_reads())
        .acquire_owned()
        .await
    else {
        let failed = "the activity read failed";
        return flat_error(StatusCode::INTERNAL_SERVER_ERROR, failed).into_response();
    };
    let flag = Arc::clone(&dropped.0);
    let hook = state.process.counts_hook().cloned();
    blocking(state.process.activity_reads(), move || {
        let _held = permit;
        let cap = COUNT_SCAN_BYTES;
        count_page(&logs, &access, &query, cap, |pass| {
            if let Some(hook) = &hook {
                (hook.0)(cap, pass.bytes, &|| flag.load(Ordering::SeqCst));
            }
            if flag.load(Ordering::SeqCst) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
    })
    .await
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

    /// How a scan ended, a rotation during the read being its own stop. Any
    /// other error stays an error.
    fn of(scan: io::Result<ScanEnd>) -> io::Result<Self> {
        match scan {
            Ok(ScanEnd::End) => Ok(Self::End),
            Ok(ScanEnd::WindowPassed) => Ok(Self::WindowPassed),
            Ok(ScanEnd::Cap) => Ok(Self::Cap),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(Self::Rotated),
            Err(e) => Err(e),
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
    let stop = Stopped::of(end)?;
    if stop == Stopped::Rotated {
        // Records may have been read twice: none of it is a count.
        per_rule.clear();
    }
    Ok(RuleHits {
        per_rule,
        stop: Some(stop),
        to: Some(to),
        scope: access.scope(),
    })
}
