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
//! Not available in this version, and so absent: the needs-you sign-in row
//! (it waits on per-server OAuth state) and the pending-decisions count (its
//! only source runs a discovery scan per request).

use std::io;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, State};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use super::{admin_auth_required, is_admin, uptime_secs};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::security::transparency_log::pager::{Tail, lines_newest_first, tail_window};

/// Server rows shown; the rest fold into `servers.more`.
const SERVER_ROWS: usize = 24;
/// Needs-you rows shown; the rest fold into `needs_you.more`.
const NEEDS_YOU_ROWS: usize = 20;
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
    let mut end = text.len().min(TEXT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// An audit record's string field, clipped; JSON null when it is not a string.
fn clip_field(value: &Value) -> Value {
    value.as_str().map_or(Value::Null, |text| clip(text).into())
}

/// `GET /ui/api/overview`. Admin only: an authenticated non-admin gets 403
/// here, and an unauthenticated caller never reaches it (401 upstream).
pub(super) async fn overview(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> Response {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return admin_auth_required().into_response();
    }
    let mut body = Map::new();
    let mut degraded = Vec::new();
    if let Ok(now) = crate::clock::utc_now() {
        body.insert("generated_at".into(), now.to_rfc3339().into());
    }
    let (kpi, servers) = kpi_and_servers(&state);
    body.insert("kpi".into(), kpi);
    body.insert("servers".into(), servers);
    body.insert("needs_you".into(), needs_you(&state));
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
    body.insert(
        "checklist".into(),
        json!({ "has_key": !state.auth_config.api_keys.is_empty() }),
    );
    if !degraded.is_empty() {
        body.insert("degraded".into(), json!(degraded));
    }
    Json(Value::Object(body)).into_response()
}

/// The KPI strip and the server list, from one pass over the backends. A
/// server is up when it is running. Rows are in name order; the rest fold
/// into `more` with their up and down counts.
fn kpi_and_servers(state: &AppState) -> (Value, Value) {
    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator overview behind admin auth; not a tenant read"
    )]
    let backends = state.backends.all();
    let mut rows: Vec<(String, bool, usize)> = backends
        .iter()
        .map(|backend| {
            let status = backend.status();
            (clip(&status.name), status.running, status.tools_cached)
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let up = rows.iter().filter(|row| row.1).count();
    let tools: usize = rows.iter().map(|row| row.2).sum();
    let kpi = json!({
        "servers_total": rows.len(),
        "servers_up": up,
        "tools_total": tools,
        "uptime_secs": uptime_secs(),
        "version": env!("CARGO_PKG_VERSION"),
    });
    let folded = rows.split_off(rows.len().min(SERVER_ROWS));
    let folded_up = folded.iter().filter(|row| row.1).count();
    let servers = json!({
        "rows": rows
            .into_iter()
            .map(|(name, up, tools)| json!({ "name": name, "up": up, "tools": tools }))
            .collect::<Vec<_>>(),
        "more": {
            "count": folded.len(),
            "up": folded_up,
            "down": folded.len() - folded_up,
        },
    });
    (kpi, servers)
}

/// What needs the operator, highest priority first, capped with `more`.
fn needs_you(state: &AppState) -> Value {
    let mut rows = limit_rows(state);
    let folded = rows.split_off(rows.len().min(NEEDS_YOU_ROWS)).len();
    json!({ "rows": rows, "more": { "count": folded } })
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
/// the newest [`ACTION_ROWS`] there are: all five found, or the whole log
/// read with no rotated-out segment behind it and no line skipped as too long
/// to read. Otherwise older actions may exist that were not read.
fn last_actions(path: &std::path::Path) -> io::Result<Value> {
    let mut end = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error),
    };
    let mut scanned = 0u64;
    let mut skipped = false;
    let mut rows = Vec::new();
    while end > 0 && rows.len() < ACTION_ROWS && scanned < ACTION_SCAN_BYTES {
        let (tail, spanned) = tail_window(path, end, ACTION_WINDOW_BYTES)?;
        scanned += spanned;
        let Tail::Lines { start, .. } = &tail else {
            // One line longer than a window: skip past it rather than loop.
            skipped = true;
            end -= spanned;
            continue;
        };
        for (_, line) in lines_newest_first(tail.body(), *start) {
            if rows.len() == ACTION_ROWS {
                break;
            }
            let Ok(entry) = serde_json::from_slice::<Value>(line) else {
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
    let rotated = !crate::security::transparency_log::segments::list_segments(path)
        .is_ok_and(|sealed| sealed.is_empty());
    let complete = rows.len() == ACTION_ROWS || (end == 0 && !skipped && !rotated);
    Ok(json!({ "rows": rows, "complete": complete }))
}
