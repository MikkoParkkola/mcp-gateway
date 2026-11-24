// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/gateway/health`: the gateway's own health over time, for the
//! Gateway Status page's tiles, sparklines and 7-day uptime strip.

use std::sync::Arc;

use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::health_history::HealthHistory;

/// The 503 answer's sentence when this process keeps no health history.
pub(super) const NO_HISTORY: &str = "the health history is not running";
/// The 503 answer's sentence when the clock cannot date the answer.
pub(super) const CLOCK_BEFORE_1970: &str = "the system clock reads before 1970";

/// The answer for `history` at `now`, or 503 when either is missing.
pub(super) fn respond<E>(history: Option<Arc<HealthHistory>>, now: Result<u64, E>) -> Response {
    let _ = (history, now);
    Json(json!({})).into_response()
}

/// The whole answer for `history` at unix second `now`.
pub(super) fn health_body(history: &HealthHistory, now: u64) -> Value {
    let _ = (history, now);
    json!({})
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "gateway_health_tests.rs"]
mod tests;
