// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/overview`: the web UI's first screen in one admin read.
//!
//! A section whose source is not available is left out, never sent as a zero
//! or an empty list, so a client can tell "nothing to show" from "cannot
//! know". A configured source whose read fails is left out too, and its name
//! goes into `degraded`. Every list is capped and reports what it folded, so
//! the body does not grow with the number of servers.
//!
//! Counter fields (the 24-hour totals, each server's calls, the top flows, the
//! chart markers and `checklist.tool_tried`) come from the counter store, all
//! read at one instant. With no store they are absent. With a store but an
//! unreadable clock they are absent and named in `degraded`.
//!
//! Not available in this version, and so absent:
//! - `checklist.client_connected`: a caller label exists only once it has
//!   made a call, so it would repeat `tool_tried` as a second fact;
//! - the needs-you sign-in row: nothing yet lets the operator sign a server
//!   back in, so the row would lead nowhere;
//! - the pending-decisions count: its only source runs a discovery scan per
//!   request.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Extension, State};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::guard::Guard;
use crate::backend::Backend;
use crate::config_reload::refusals::{Refusal, RefusalCode, RefusalKind, startup_refusal};
use crate::counters::{CounterStore, Filter, Metric, Query, Window};
use crate::gateway::router::AppState;
use crate::security::transparency_log::pager::{
    Tail, lines_newest_first, open_segment, tail_window_in,
};
use crate::security::transparency_log::segments::listing;

/// Server rows shown; the rest fold into `servers.more`.
const SERVER_ROWS: usize = 24;
/// Needs-you rows shown; the rest fold into `needs_you.more`.
const NEEDS_YOU_ROWS: usize = 20;
/// Caller x server flows shown; the rest fold into `edges.more`.
const EDGE_ROWS: usize = 48;
/// Chart markers shown, newest first; the rest fold into `markers.more`.
const MARKER_ROWS: usize = 50;
/// Seconds in the 24-hour window the counter fields cover.
const DAY_SECS: u64 = 86_400;
/// Every counter field, as `degraded` names it when the clock cannot be read.
const COUNTER_FIELDS: [&str; 8] = [
    "kpi.calls_24h",
    "kpi.blocks_24h",
    "kpi.errors_24h",
    "servers.calls_24h",
    "edges",
    "markers",
    "checklist.tool_tried",
    "latency",
];
/// Admin actions shown.
const ACTION_ROWS: usize = 5;
/// Bytes of the transparency log scanned for those actions, newest first.
const ACTION_SCAN_BYTES: u64 = 4 << 20;
/// One read window of that scan.
const ACTION_WINDOW_BYTES: u64 = 256 << 10;
/// Longest text a field carries: names, subjects and audit fields are cut
/// here, so the body is bounded in bytes as well as rows.
const TEXT_BYTES: usize = 256;

/// `text` cut to at most [`TEXT_BYTES`] bytes on a character boundary.
fn clip(text: &str) -> String {
    use crate::truncate::{Budget, Suffix, truncate};
    truncate(text, Budget::Bytes(TEXT_BYTES), "", Suffix::Within)
}

/// An audit record's string field, clipped; JSON null when it is not a string.
fn clip_field(value: &Value) -> Value {
    value.as_str().map_or(Value::Null, |text| clip(text).into())
}

/// `GET /ui/api/overview`. Admin only: an authenticated non-admin gets 403
/// here, and an unauthenticated caller never reaches it (401 upstream).
pub(super) async fn overview(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let mut body = Map::new();
    let mut degraded = Vec::new();
    if let Ok(now) = crate::clock::utc_now() {
        body.insert("generated_at".into(), now.to_rfc3339().into());
    }
    // One instant for the counter reads and the server states alike.
    let at = crate::clock::system_time_or_before_epoch();
    let source = Source::open(&state, at);
    let (mut kpi, servers, denied) = kpi_and_servers(&state, &source, at);
    source.add_totals(&mut kpi);
    body.insert("kpi".into(), kpi.into());
    body.insert("servers".into(), servers);
    body.insert("needs_you".into(), needs_you(&state, &denied));
    source.add_flows(&mut body);
    if let Some(log) = &state.transparency_log {
        match last_actions(&log.path()) {
            Ok(actions) => {
                body.insert("last_actions".into(), actions);
            }
            Err(error) => {
                tracing::warn!(%error, "overview: the admin actions could not be read");
                degraded.push("last_actions");
            }
        }
    }
    let mut checklist = Map::new();
    checklist.insert(
        "has_key".into(),
        (!generation.auth().api_keys().is_empty()).into(),
    );
    source.add_tool_tried(&mut checklist);
    body.insert("checklist".into(), checklist.into());
    degraded.extend_from_slice(source.degraded());
    if !degraded.is_empty() {
        body.insert("degraded".into(), json!(degraded));
    }
    Json(Value::Object(body)).into_response()
}

/// All backends, in name order. Sort on the full name; clipping first could
/// tie or reorder names that differ only past the cut, and keep the wrong
/// rows.
fn backends_by_name(state: &AppState) -> Vec<Arc<Backend>> {
    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator overview behind admin auth; not a tenant read"
    )]
    let mut backends = state.backends.all();
    backends.sort_by(|a, b| a.name.cmp(&b.name));
    backends
}

/// The KPI strip, the server list and the startup refusals, from one pass
/// over the backends. A server is up when it is running. Rows are best first
/// by calls (by name when calls are not counted); the rest fold into `more`
/// with their up and down counts.
fn kpi_and_servers(
    state: &AppState,
    source: &Source,
    at: SystemTime,
) -> (Map<String, Value>, Value, Vec<Refusal>) {
    let backends = backends_by_name(state);
    // Not `status()`: it also sorts latency samples this view never shows.
    let up: HashMap<&str, bool> = backends
        .iter()
        .map(|backend| (backend.name.as_str(), backend.is_running()))
        .collect();
    let tools: usize = backends.iter().map(|b| b.cached_tools_count()).sum();
    let denied = backends
        .iter()
        .filter_map(|b| Some(startup_refusal(&b.name, b.startup_denial()?)))
        .collect();
    let mut kpi = Map::new();
    kpi.insert("servers_total".into(), backends.len().into());
    kpi.insert(
        "servers_up".into(),
        up.values().filter(|up| **up).count().into(),
    );
    kpi.insert("tools_total".into(), tools.into());
    kpi.insert("uptime_secs".into(), state.process.uptime_secs().into());
    kpi.insert("version".into(), env!("CARGO_PKG_VERSION").into());
    (kpi, server_list(source, &backends, &up, at), denied)
}

/// The server rows and what folded. Servers are ranked first; only the rows
/// shown have their state worked out, because that reads health metrics.
fn server_list(
    source: &Source,
    backends: &[Arc<Backend>],
    up: &HashMap<&str, bool>,
    at: SystemTime,
) -> Value {
    let counts = source.server_calls(backends);
    let names = backends.iter().map(|b| b.name.clone());
    let mut ranked: Vec<(String, Option<u64>)> = match &counts {
        Some(counts) => rank_servers(names.zip(counts.iter().copied()).collect()),
        None => names.map(|name| (name, None)).collect(),
    };
    let folded = ranked.split_off(ranked.len().min(SERVER_ROWS));
    let folded_up = folded.iter().filter(|(name, _)| up[name.as_str()]).count();
    let by_name: HashMap<&str, &Arc<Backend>> =
        backends.iter().map(|b| (b.name.as_str(), b)).collect();
    let rows: Vec<Value> = ranked
        .into_iter()
        .map(|(name, calls)| {
            let mut row = server_row(by_name[name.as_str()], up[name.as_str()], at);
            if counts.is_some() {
                row["calls_24h"] = calls.into();
            }
            row
        })
        .collect();
    json!({
        "rows": rows,
        "more": {
            "count": folded.len(),
            "up": folded_up,
            "down": folded.len() - folded_up,
        },
    })
}

/// One server row: its name, whether it is up, its tools, and the operator's
/// state with the reason.
fn server_row(backend: &Backend, up: bool, at: SystemTime) -> Value {
    let view = backend.server_state(at);
    json!({
        "name": clip(&backend.name),
        "up": up,
        "tools": backend.cached_tools_count(),
        "state": view.state,
        "reason": clip(&view.reason),
    })
}

/// Servers with their calls in the last 24 hours (`None` when the count may
/// be low), best first: positive counts by calls descending, then `None`,
/// then zeros; ties by name.
fn rank_servers(mut rows: Vec<(String, Option<u64>)>) -> Vec<(String, Option<u64>)> {
    let class = |calls: Option<u64>| match calls {
        Some(0) => 2,
        None => 1,
        Some(_) => 0,
    };
    rows.sort_by(|a, b| {
        class(a.1)
            .cmp(&class(b.1))
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    rows
}

/// Where the counter fields come from, fixed once per request so every read
/// uses one store and one instant.
enum Source {
    /// No store is configured: the counter fields are absent, not degraded.
    Off,
    /// A store, but the clock cannot be read: absent, and named in `degraded`.
    Unreadable,
    /// The store and unix seconds now.
    On(Arc<CounterStore>, u64),
}

impl Source {
    fn open(state: &AppState, at: SystemTime) -> Self {
        let Some(store) = state.meta_mcp.counters() else {
            return Self::Off;
        };
        at.duration_since(UNIX_EPOCH)
            .map_or(Self::Unreadable, |since| {
                Self::On(Arc::clone(store), since.as_secs())
            })
    }

    /// The counter fields that could not be read.
    fn degraded(&self) -> &'static [&'static str] {
        if matches!(self, Self::Unreadable) {
            &COUNTER_FIELDS
        } else {
            &[]
        }
    }

    /// Each backend's calls in the last 24 hours, in the order given; `None`
    /// inside when the count may be low. The whole outer value is `None`
    /// without a readable store.
    ///
    /// ponytail: this takes the store lock once and does one map lookup per
    /// server, so it is linear in the server count under the lock, capped by
    /// the 512-label Server dimension. Declined for now: a current-window-only
    /// sum, and ranking from the Server dimension with names resolved outside
    /// the lock. Either is an upgrade if the 140-server read shows lock
    /// contention.
    fn server_calls(&self, backends: &[Arc<Backend>]) -> Option<Vec<Option<u64>>> {
        let Self::On(store, now) = self else {
            return None;
        };
        let filters: Vec<Filter<'_>> = backends.iter().map(|b| Filter::Server(&b.name)).collect();
        let sums = store.window_sums(&filters, *now, &crate::local_day::host_zone());
        Some(sums.counts.into_iter().map(|(day, _)| day).collect())
    }

    /// One metric's 24-hour total, the previous 24 hours' total when the
    /// store covers all of it, and when counting began.
    fn day_total(&self, metric: Metric) -> Option<(u64, Option<u64>, u64)> {
        let Self::On(store, now) = self else {
            return None;
        };
        let query = Query {
            metric,
            window: Window::Day,
            filter: Filter::All,
            compare: true,
        };
        let view = store.series(&query, *now, &crate::local_day::host_zone());
        let previous = view
            .previous
            .filter(|_| view.previous_complete)
            .map(|points| points.iter().map(|p| p.v).sum());
        Some((view.points.iter().map(|p| p.v).sum(), previous, view.since))
    }

    /// The 24-hour totals, each with the previous 24 hours when the store
    /// covers all of it, and when counting began.
    fn add_totals(&self, kpi: &mut Map<String, Value>) {
        for (metric, name) in [
            (Metric::Calls, "calls"),
            (Metric::Blocks, "blocks"),
            (Metric::Errors, "errors"),
        ] {
            let Some((total, previous, since)) = self.day_total(metric) else {
                return;
            };
            kpi.insert(format!("{name}_24h"), total.into());
            if let Some(previous) = previous {
                kpi.insert(format!("{name}_prev_24h"), previous.into());
            }
            kpi.insert("counting_since".into(), since.into());
        }
    }

    /// The top flows and the chart markers.
    fn add_flows(&self, body: &mut Map<String, Value>) {
        let Self::On(store, now) = self else {
            return;
        };
        let pairs = store.top_pairs(*now, &crate::local_day::host_zone(), EDGE_ROWS);
        let edges: Vec<Value> = pairs
            .rows
            .iter()
            .map(|row| {
                let (caller, server) = (clip(&row.caller), clip(&row.server));
                json!({ "caller": caller, "server": server, "calls": row.calls, "blocks": row.blocks })
            })
            .collect();
        body.insert(
            "edges".into(),
            json!({
                "rows": edges,
                "more": {
                    "count": pairs.more_count,
                    "calls": pairs.more_calls,
                    "overflow_calls": pairs.overflow_calls,
                },
            }),
        );
        body.insert("markers".into(), marker_rows(store, *now));
        body.insert("latency".into(), latency(store, *now));
    }

    /// Whether any call was counted in the last 30 local days.
    fn add_tool_tried(&self, checklist: &mut Map<String, Value>) {
        let Self::On(store, now) = self else {
            return;
        };
        let query = Query {
            metric: Metric::Calls,
            window: Window::Month,
            filter: Filter::All,
            compare: false,
        };
        let view = store.series(&query, *now, &crate::local_day::host_zone());
        checklist.insert(
            "tool_tried".into(),
            view.points.iter().any(|p| p.v > 0).into(),
        );
    }
}

/// The last hour's backend latency per server (the current and the previous
/// half-hour slot), slowest first, and the slowest server with enough calls
/// to name; found before the rows are capped.
fn latency(store: &CounterStore, now: u64) -> Value {
    let hour = store.latency_hour(now);
    let row = |s: &crate::counters::ServerLatency| json!({ "name": clip(&s.name), "p95_ms": s.p95_ms, "calls": s.calls });
    let rows: Vec<Value> = hour.servers.iter().take(SERVER_ROWS).map(row).collect();
    json!({
        "from": hour.from,
        "to": hour.to,
        "servers": rows,
        "more": { "count": hour.servers.len().saturating_sub(SERVER_ROWS) },
        "slowest": hour.slowest.as_ref().map(row),
    })
}

/// The newest [`MARKER_ROWS`] markers of the last 24 hours, newest first.
fn marker_rows(store: &CounterStore, now: u64) -> Value {
    let (markers, total) = store.newest_markers(now.saturating_sub(DAY_SECS), MARKER_ROWS);
    let rows: Vec<Value> = markers
        .iter()
        .map(|m| json!({ "t": m.at, "kind": m.kind, "subject": m.subject.as_deref().map(clip) }))
        .collect();
    json!({ "rows": rows, "more": { "count": total - markers.len() } })
}

/// What needs the operator, highest priority first, capped with `more`: the
/// newest invalid config, then every refusal, then budgets near their limit.
fn needs_you(state: &AppState, startup: &[Refusal]) -> Value {
    let (invalid, mut rows) = ledger_rows(state);
    // A denied server has no ledger entry and never ages out, so it leads.
    let denied = startup
        .iter()
        .map(|refusal| refused_row(refusal, &refusal_detail(refusal)));
    rows.splice(0..0, denied);
    rows.splice(0..0, invalid);
    rows.extend(limit_rows(state));
    let folded = rows.split_off(rows.len().min(NEEDS_YOU_ROWS)).len();
    json!({ "rows": rows, "more": { "count": folded } })
}

/// The newest active invalid-config reload refusal as its own row (never
/// folded: it is first), and the other active ledger refusals, newest first.
/// An older invalid-config refusal is the same problem and is left out.
fn ledger_rows(state: &AppState) -> (Option<Value>, Vec<Value>) {
    let Some(context) = state.meta_mcp.reload_context() else {
        return (None, Vec::new());
    };
    let is_invalid =
        |r: &Refusal| r.kind == RefusalKind::Reload && r.code == RefusalCode::InvalidConfig;
    let active: Vec<Refusal> = context
        .refusals()
        .list()
        .into_iter()
        .filter(|r| r.active)
        .collect();
    let invalid = active.iter().find(|r| is_invalid(r)).map(|r| {
        let mut detail = refusal_detail(r);
        detail.remove("code");
        detail.insert("repeats".into(), r.repeats.into());
        json!({ "kind": "invalid_config", "subject": "config", "detail": detail })
    });
    let refused = active
        .iter()
        .filter(|r| !is_invalid(r))
        .map(|r| refused_row(r, &refusal_detail(r)))
        .collect();
    (invalid, refused)
}

/// A refusal's code, cause, fix and time. The cause and fix are fixed text
/// the ledger rebuilds, never a configured value; they are clipped anyway.
fn refusal_detail(refusal: &Refusal) -> Map<String, Value> {
    let mut detail = Map::new();
    detail.insert("code".into(), json!(refusal.code));
    detail.insert("cause".into(), clip(&refusal.cause).into());
    detail.insert("fix".into(), clip(refusal.fix).into());
    detail.insert("at".into(), json!(refusal.at));
    detail
}

/// A `refused` needs-you row for `refusal`, about its server or the config.
fn refused_row(refusal: &Refusal, detail: &Map<String, Value>) -> Value {
    let subject = refusal.backend.as_deref().unwrap_or("config");
    json!({ "kind": "refused", "subject": clip(subject), "detail": detail })
}

/// One row per daily budget whose spend has reached the configured Notify
/// alert's percent (inclusive, as the enforcer's own alerts compare), highest
/// percent first. None when cost governance is off: there is no limit to near.
#[cfg(feature = "cost-governance")]
fn limit_rows(state: &AppState) -> Vec<Value> {
    use crate::cost_accounting::config::AlertAction;
    let Some(enforcer) = &state.meta_mcp.budget_enforcer else {
        return Vec::new();
    };
    let threshold = enforcer
        .config
        .alerts
        .iter()
        .filter(|rule| rule.action == AlertAction::Notify)
        .map(|rule| f64::from(rule.at_percent))
        .reduce(f64::min)
        .unwrap_or(80.0);
    let snapshot = enforcer.snapshot();
    let mut found: Vec<(f64, Value)> = Vec::new();
    let mut check = |scope: &str, name: Option<&str>, spent: f64, limit: f64| {
        if limit <= 0.0 {
            return;
        }
        let percent = spent / limit * 100.0;
        if percent >= threshold {
            found.push((
                percent,
                json!({
                    "kind": "limit_80",
                    "subject": clip(&name.map_or_else(|| scope.to_owned(), |n| format!("{scope}:{n}"))),
                    "detail": {
                        "scope": scope,
                        "name": name.map(clip),
                        "spent_usd": spent,
                        "limit_usd": limit,
                        "percent": percent,
                    },
                }),
            ));
        }
    };
    if let Some(limit) = snapshot.global_daily_limit {
        check("global", None, snapshot.global_daily_usd, limit);
    }
    for (tool, limit) in &snapshot.tool_limits {
        let spent = snapshot.tool_daily.get(tool).copied().unwrap_or(0.0);
        check("tool", Some(tool), spent, *limit);
    }
    for (key, limit) in &snapshot.key_limits {
        let spent = snapshot.key_daily.get(key).copied().unwrap_or(0.0);
        check("key", Some(key), spent, *limit);
    }
    found.sort_by(|a, b| {
        b.0.total_cmp(&a.0)
            .then_with(|| a.1["subject"].as_str().cmp(&b.1["subject"].as_str()))
    });
    found.into_iter().map(|(_, row)| row).collect()
}

#[cfg(not(feature = "cost-governance"))]
fn limit_rows(_state: &AppState) -> Vec<Value> {
    Vec::new()
}

/// The newest admin actions in the transparency log's live segment, read
/// newest window first until [`ACTION_ROWS`] are found or
/// [`ACTION_SCAN_BYTES`] are read. `complete` is true only when the rows are
/// the newest [`ACTION_ROWS`] there are: no line was skipped as too long to
/// read, and either all five were found or the whole log was read with no
/// rotated-out segment behind it. Otherwise an action may exist that was not
/// read.
fn last_actions(path: &std::path::Path) -> io::Result<Value> {
    // The live segment, opened once: every window is read from this handle,
    // so a rotation mid-read cannot hand later windows another file's bytes.
    let files = listing(path)?;
    let file = match files.active {
        Some(seq) => open_segment(path, seq, || {})?,
        None => None,
    };
    let mut end = match &file {
        Some(file) => {
            let meta = file.metadata()?;
            // A directory reports length 0 on Windows and would read as an
            // empty log; anything but a regular file cannot be read.
            if !meta.is_file() {
                return Err(io::Error::other("transparency log is not a file"));
            }
            meta.len()
        }
        // A log never written, or its live segment gone since it was listed:
        // no rows from it, and not complete if anything is sealed behind it.
        None => 0,
    };
    let mut scanned = 0u64;
    let mut skipped = false;
    let mut rows = Vec::new();
    while let Some(file) = file
        .as_ref()
        .filter(|_| end > 0 && rows.len() < ACTION_ROWS && scanned < ACTION_SCAN_BYTES)
    {
        let (tail, window_len) = tail_window_in(file, end, ACTION_WINDOW_BYTES)?;
        scanned += window_len;
        let Tail::Lines { start, .. } = &tail else {
            // One line longer than a window: skip past it rather than loop.
            skipped = true;
            end -= window_len;
            continue;
        };
        for (_, line) in lines_newest_first(tail.body(), *start) {
            if rows.len() == ACTION_ROWS {
                break;
            }
            let Ok(entry) = serde_json::from_slice::<Value>(line) else {
                // An unreadable record may have been an action too.
                skipped |= !line.is_empty();
                continue;
            };
            if entry["event"] == "admin_action" {
                let who = &entry["who"];
                rows.push(json!({
                    "at": clip_field(&entry["timestamp"]),
                    "route": clip_field(&entry["route"]),
                    "method": clip_field(&entry["method"]),
                    "outcome": clip_field(&entry["outcome"]),
                    "who": {
                        "authority": clip_field(&who["authority"]),
                        "subject": clip_field(&who["subject"]),
                        "account": clip_field(&who["account"]),
                    },
                }));
            }
        }
        end = *start;
    }
    let rotated = !files.sealed.is_empty();
    // A skipped line may have been a newer action than any row found, so any
    // skip makes the list incomplete, even with all five rows.
    let complete = !skipped && (rows.len() == ACTION_ROWS || (end == 0 && !rotated));
    Ok(json!({ "rows": rows, "complete": complete }))
}

#[cfg(test)]
mod rank_tests {
    use super::rank_servers;

    /// S2b: a count that may be low ranks after every positive count and
    /// before a zero; ties go by name.
    #[test]
    fn s2b_a_count_that_may_be_low_ranks_between_positive_and_zero() {
        let rows = ["a", "b", "c", "d", "e"]
            .into_iter()
            .zip([Some(5), None, Some(9), Some(5), Some(0)])
            .map(|(name, calls)| (name.to_owned(), calls))
            .collect();
        let names: Vec<String> = rank_servers(rows).into_iter().map(|row| row.0).collect();
        assert_eq!(names, ["c", "a", "d", "b", "e"]);
    }
}
