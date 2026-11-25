// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/gateway/health`: the gateway's own health over time, for the
//! Gateway Status page's tiles, sparklines and 7-day uptime strip.
//!
//! Admin only, as `GET /ui/api/gateway` is. It reads the history this process
//! records and saves (`crate::health_history`) from one copy taken under one
//! lock, so every number in an answer is of one instant. The answer holds
//! numbers, booleans, nulls and the two downtime words only: no session,
//! client name, path or other text. A span or half-hour the history did not
//! observe is null, never 0.
//!
//! Two readings are only as fine as the store keeps them. The memory and
//! session tiles are the highest sample in the half-hour in progress, not the
//! latest one. Uptime counts every six-hour block the strip serves: each block
//! that overlaps the last 7 days, so up to 7 days and 6 hours. Its percent is
//! running over covered seconds of those same blocks, so it never passes 100.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::AppState;
use super::guard::Guard;
use crate::health_history::{BLOCK, DowntimeSource, HALF, HealthHistory, P95};

/// The 503 answer's sentence when this process keeps no health history.
pub(super) const NO_HISTORY: &str = "the health history is not running";
/// The 503 answer's sentence when the clock cannot date the answer.
pub(super) const CLOCK_BEFORE_1970: &str = "the system clock reads before 1970";

/// A rate tile's span: one complete hour.
const HOUR: u64 = 2 * HALF;
/// The sparklines' points: the 16 complete half-hours of the last 8 hours.
const POINTS: u64 = 16;
/// The uptime strip's window.
const WEEK: u64 = 7 * 86_400;

/// The route: admit an admin, then answer from the history this gateway's
/// meta-MCP handler holds (set by the server at start).
pub(super) async fn gateway_health(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    respond(
        state.meta_mcp.health_history().cloned(),
        crate::clock::unix_secs(),
    )
}

/// The answer for `history` at `now`, or 503 when either is missing.
pub(super) fn respond<E>(history: Option<Arc<HealthHistory>>, now: Result<u64, E>) -> Response {
    let Some(history) = history else {
        return unavailable(NO_HISTORY);
    };
    let now = match now {
        Ok(now) => now,
        Err(_before_1970) => return unavailable(CLOCK_BEFORE_1970),
    };
    Json(health_body(&history.frozen(), now)).into_response()
}

fn unavailable(why: &str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": why}))).into_response()
}

/// The whole answer for `history` at unix second `now`.
pub(super) fn health_body(history: &HealthHistory, now: u64) -> Value {
    // The half-hour in progress starts at `h`; it is in no rate tile and is
    // not a sparkline point, so both tile spans were observed for as long.
    let h = now - now % HALF;
    let week_from = now.saturating_sub(WEEK);
    let points: Vec<Value> = (1..=POINTS)
        .rev()
        .map(|back| half_point(history, h.saturating_sub(back * HALF)))
        .collect();
    let (restarts, restarts_dropped) = history.restarts(week_from, now);
    let restarts: Vec<Value> = restarts
        .into_iter()
        .map(|r| {
            json!({
                "stopped_at": r.stopped_at,
                "started_at": r.started_at,
                "downtime": downtime_word(r.downtime_source),
            })
        })
        .collect();
    json!({
        "generated_at": now,
        "observed_since": history.observed_since(),
        "incomplete": history.incomplete(),
        "tiles": tiles(history, h),
        "halves": points,
        "uptime": uptime(history, week_from, now),
        "blocks": blocks(history, week_from, now),
        "restarts": restarts,
        "restarts_dropped": restarts_dropped,
    })
}

/// The two rate tiles over the last complete hour against the hour before,
/// and the two gauges as the highest samples in the half-hour in progress.
fn tiles(history: &HealthHistory, h: u64) -> Value {
    let (last_from, before_from) = (h.saturating_sub(HOUR), h.saturating_sub(2 * HOUR));
    let current = history.half(h);
    json!({
        "added_p95": {
            "now": p95(history.p95(last_from, h)),
            "before": p95(history.p95(before_from, last_from)),
        },
        "gateway_errors": {
            "now": history.errors(last_from, h),
            "before": history.errors(before_from, last_from),
        },
        "memory_bytes": current.as_ref().and_then(|half| half.memory_max),
        "sessions": current.as_ref().and_then(|half| half.sessions_max),
    })
}

/// One sparkline point; every value but `t` is null when `t` was not observed.
fn half_point(history: &HealthHistory, t: u64) -> Value {
    let half = history.half(t);
    json!({
        "t": t,
        "added_p95": p95(history.p95(t, t + HALF)),
        "gateway_errors": history.errors(t, t + HALF),
        "memory_max": half.as_ref().and_then(|half| half.memory_max),
        "sessions_max": half.as_ref().and_then(|half| half.sessions_max),
    })
}

/// Seconds of every block overlapping `[from, now)`, which may begin up to six
/// hours before `from`; the percent divides running by covered seconds of the
/// same blocks.
fn uptime(history: &HealthHistory, from: u64, now: u64) -> Value {
    let uptime = history.uptime(from, now);
    json!({
        "percent": uptime.percent,
        "running_seconds": uptime.running_seconds,
        "down_seconds": uptime.down_seconds,
        "covered_seconds": uptime.covered_seconds,
        "coverage_complete": uptime.coverage_complete,
    })
}

/// Every block whose six hours overlap `[from, now]`, oldest first, each with
/// its own start so the page can clip the first.
fn blocks(history: &HealthHistory, from: u64, now: u64) -> Vec<Value> {
    history
        .blocks()
        .into_iter()
        .filter(|block| block.start + BLOCK > from && block.start <= now)
        .map(|block| {
            json!({
                "t": block.start,
                "running_seconds": block.running_seconds,
                "down_seconds": block.down_seconds,
                "restarts": block.restarts,
                "estimated": block.estimated,
            })
        })
        .collect()
}

fn p95(value: P95) -> Value {
    match value {
        P95::Ms(ms) => json!({"ms": ms}),
        P95::AboveMs(ms) => json!({"above_ms": ms}),
        P95::NoData => Value::Null,
    }
}

fn downtime_word(source: DowntimeSource) -> &'static str {
    match source {
        DowntimeSource::Measured => "measured",
        DowntimeSource::Estimated => "estimated",
    }
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "gateway_health_tests.rs"]
mod tests;
