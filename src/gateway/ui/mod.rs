// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Embedded web UI for the MCP Gateway.
//!
//! Serves a single-page HTML dashboard from the same axum server,
//! with JSON API endpoints for live status, tools, and configuration.
//! Also exposes `GET /dashboard` — a self-contained operator dashboard
//! rendered as inline HTML with automatic 5-second refresh.
//!
//! All UI code is gated behind the `webui` feature flag.

mod access_report;
mod access_table;
#[cfg(test)]
pub(in crate::gateway) use self::access_table::plain_rows;
mod activity;
pub mod admin_audit;
pub mod backend_ops;
pub mod backends;
pub mod capabilities;
pub mod control_plane;
mod dashboard;
pub(in crate::gateway) mod decisions;
mod discovery;
mod errors;
mod events;
mod gateway_status;
mod gateway_upgrade;
mod guard;
mod history;
pub mod import;
mod overview;
mod preview;
mod preview_identity;
mod refusals;
pub(crate) mod session;
mod shell;
mod status;
pub(crate) mod stream;
mod tool_call;
#[cfg(test)]
pub(crate) use tool_call::DEADLINE_FOR_TEST;

use crate::gateway::routes;
use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use self::errors::flat_error;
use self::guard::Guard;
use super::auth::AuthenticatedClient;
use super::router::AppState;
use crate::stats::{StatsSnapshot, TopTool};

use self::dashboard::dashboard_handler;

/// Embedded HTML — compiled into the binary, zero filesystem dependency.
const INDEX_HTML: &str = include_str!("index.html");

/// Returns `true` when the caller has admin-level access.
///
/// Admin access follows a credential: the bearer, an API key with `admin: true`,
/// or an SSO identity while a `role: admin` mapping rule matches it (E1). The
/// identity used when authentication is disabled is NOT admin, because an
/// unauthenticated gateway cannot tell its operator from any other caller that
/// reaches the port.
fn is_admin(client: Option<&AuthenticatedClient>) -> bool {
    client.is_some_and(|c| c.admin)
}

/// Build the authenticated `/ui/api/*` and `/dashboard` sub-router.
pub fn api_router() -> Router<Arc<AppState>> {
    let router = Router::new()
        .route(routes::UI_STATUS, get(status::status))
        .route(routes::UI_OVERVIEW, get(overview::overview))
        .route(routes::UI_TOOLS, get(tools))
        .route(routes::UI_TOOLS_CALL, post(tool_call::call))
        .route(routes::UI_REFUSALS, get(refusals::refusals))
        .route(routes::UI_GATEWAY, get(gateway_status::gateway_status))
        .route(routes::UI_CONFIG, get(config))
        .route(routes::UI_RELOAD, post(reload))
        .route(routes::UI_DASHBOARD_LINK, post(session::dashboard_link))
        .route(routes::DASHBOARD, get(dashboard_handler))
        .route(routes::UI_PREVIEWS, post(preview::preview_backend))
        .merge(activity::activity_router())
        .merge(capabilities::capabilities_router())
        .merge(control_plane::control_plane_router())
        .merge(backends::backends_router())
        .merge(events::events_router())
        .merge(import::import_router())
        .merge(discovery::discovery_router())
        .merge(decisions::decisions_router())
        .merge(history::history_router())
        .merge(stream::stream_router());

    #[cfg(feature = "cost-governance")]
    let router = router.route(routes::UI_COSTS, get(costs));
    // Test builds: a guarded handler that answers without admitting its
    // caller fails the test that sent the request.
    #[cfg(test)]
    let router = router.route_layer(axum::middleware::from_fn(guard::probe::layer));
    router
}

/// Build the unauthenticated `/ui` route (serves static HTML, no data).
pub fn html_router() -> Router {
    Router::new()
        .route(routes::UI, get(index))
        .route(routes::UI_CLASSIC, get(index))
        .route(routes::UI_ASSET, get(shell::asset))
        .route(
            routes::UI_SHELL,
            get(shell::document).fallback(shell::not_found),
        )
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /ui` and `GET /ui/classic` — serve the single-page HTML dashboard
/// (`/ui/classic` keeps it reachable once `/ui` serves the new UI, MIK-8870).
///
/// Returns `Cache-Control: no-cache` so browsers always fetch fresh HTML
/// after gateway restarts (the HTML is embedded via `include_str!`).
async fn index() -> impl IntoResponse {
    (
        [(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")],
        Html(INDEX_HTML),
    )
}

// ── Dashboard domain types ───────────────────────────────────────────

/// Overall health status of a backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum HealthStatus {
    /// Backend is reachable and healthy.
    Healthy,
    /// Backend is reachable but showing elevated errors.
    Degraded,
    /// Backend is unreachable or not running.
    Down,
}

impl HealthStatus {
    /// CSS class suffix used by the dashboard renderer.
    fn css_class(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Down => "down",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Degraded => "Degraded",
            Self::Down => "Down",
        }
    }
}

/// Health data for a single backend.
#[derive(Debug, Clone, Serialize)]
pub struct BackendHealth {
    /// Backend name.
    pub name: String,
    /// Current health status.
    pub status: HealthStatus,
    /// P50 latency in milliseconds (None if no data yet).
    pub latency_ms: Option<u64>,
    /// Error rate as a fraction 0.0–1.0.
    pub error_rate: f64,
    /// Number of tools cached from this backend.
    pub tool_count: usize,
}

/// Aggregate session / call metrics.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    /// Number of active streaming sessions.
    pub active_sessions: usize,
    /// Cumulative tool invocations across all backends.
    pub total_calls: u64,
    /// Average P50 latency in milliseconds across all backends.
    pub avg_latency_ms: Option<u64>,
}

/// Full aggregated state used to render the operator dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardState<'a> {
    /// Per-backend health matrix.
    pub backends: Vec<BackendHealth>,
    /// Session / call summary.
    pub session_summary: SessionSummary,
    /// Calls per tool since start, most-called first (`UsageStats::snapshot`
    /// keeps the top 10). The stats count attempts and carry no outcome,
    /// timestamp or latency, so neither does a row (MIK-8370).
    pub tool_counts: Vec<TopTool>,
    /// Cache statistics.
    pub cache_stats: CacheStats,
    /// Gateway uptime in seconds.
    pub uptime_secs: u64,
    /// Gateway version string.
    pub version: &'a str,
}

/// Cache hit/miss statistics.
#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    /// Hit rate as fraction 0.0–1.0.
    pub hit_rate: f64,
    /// Total cache hits.
    pub total_hits: u64,
    /// Total cache misses.
    pub total_misses: u64,
}

// ── Dashboard renderer ───────────────────────────────────────────────

/// Renders [`DashboardState`] as a self-contained HTML page.
///
/// No external dependencies — all CSS is inlined.
pub struct DashboardRenderer;

impl DashboardRenderer {
    /// Render the full HTML page for the operator dashboard.
    #[must_use]
    pub fn render(ds: &DashboardState<'_>) -> String {
        let backend_rows = Self::render_backend_rows(&ds.backends);
        let tool_rows = Self::render_tool_rows(&ds.tool_counts);
        let hit_pct = format!("{:.1}", ds.cache_stats.hit_rate * 100.0);
        let uptime = format_uptime(ds.uptime_secs);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5;url=/dashboard?poll=1">
<title>MCP Gateway — Operator Dashboard</title>
<style>
:root{{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--fg:#e6edf3;--fg2:#8b949e;
  --accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;
  --border:#30363d;--r:6px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;}}
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{background:var(--bg);color:var(--fg);min-height:100vh;padding:1.5rem 2rem;}}
h1{{font-size:1.4rem;font-weight:700;margin-bottom:0.25rem;}}
.sub{{font-size:0.8rem;color:var(--fg2);margin-bottom:1.5rem;}}
h2{{font-size:1rem;font-weight:600;color:var(--fg2);margin:1.5rem 0 0.75rem;}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1rem;}}
.card{{background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);padding:1rem 1.25rem;}}
.card .lbl{{font-size:0.75rem;color:var(--fg2);text-transform:uppercase;letter-spacing:.05em;}}
.card .val{{font-size:1.6rem;font-weight:700;margin-top:.2rem;}}
table{{width:100%;border-collapse:collapse;background:var(--bg2);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;}}
th{{text-align:left;padding:.55rem .75rem;background:var(--bg3);font-size:.75rem;color:var(--fg2);text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border);}}
td{{padding:.55rem .75rem;border-bottom:1px solid var(--border);font-size:.85rem;}}
tr:last-child td{{border-bottom:none;}}
tr:hover td{{background:var(--bg3);}}
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:10px;font-size:.7rem;font-weight:600;text-transform:uppercase;}}
.healthy{{background:rgba(63,185,80,.15);color:var(--green);}}
.degraded{{background:rgba(210,153,34,.15);color:var(--yellow);}}
.down{{background:rgba(248,81,73,.15);color:var(--red);}}
.hit-bar{{background:var(--bg3);border-radius:var(--r);height:8px;overflow:hidden;margin-top:.5rem;}}
.hit-fill{{height:100%;background:var(--green);border-radius:var(--r);}}
.meta{{font-size:.75rem;color:var(--fg2);margin-top:1.5rem;}}
</style>
</head>
<body>
<h1>MCP Gateway — Operator Dashboard</h1>
<div class="sub">v{version} &nbsp;|&nbsp; uptime: {uptime} &nbsp;|&nbsp; auto-refresh every 5 s &nbsp;|&nbsp; <form method="post" action="/dashboard/logout" style="display:inline"><button type="submit">Log out</button></form></div>

<div class="cards">
  <div class="card"><div class="lbl">Backends</div><div class="val">{backend_count}</div></div>
  <div class="card"><div class="lbl">Active Sessions</div><div class="val">{active_sessions}</div></div>
  <div class="card"><div class="lbl">Total Calls</div><div class="val">{total_calls}</div></div>
  <div class="card"><div class="lbl">Avg Latency</div><div class="val">{avg_latency}</div></div>
  <div class="card"><div class="lbl">Cache Hits</div><div class="val">{cache_hits}</div></div>
  <div class="card"><div class="lbl">Cache Misses</div><div class="val">{cache_misses}</div></div>
</div>

<h2>Cache Hit Rate</h2>
<div class="card" style="max-width:320px">
  <div class="lbl">Hit Rate</div>
  <div class="val">{hit_pct}%</div>
  <div class="hit-bar"><div class="hit-fill" style="width:{hit_pct}%"></div></div>
</div>

<h2>Backend Health</h2>
<table>
  <thead><tr><th>Name</th><th>Status</th><th>P50 Latency</th><th>Error Rate</th><th>Tools</th></tr></thead>
  <tbody>{backend_rows}</tbody>
</table>

<h2>Calls per tool (cumulative since start, top 10)</h2>
<table>
  <thead><tr><th>Tool</th><th>Server</th><th>Calls</th></tr></thead>
  <tbody>{tool_rows}</tbody>
</table>

<div class="meta">Page generated server-side &mdash; refreshes automatically every 5 seconds.</div>
</body>
</html>"#,
            version = esc(ds.version),
            uptime = uptime,
            backend_count = ds.backends.len(),
            active_sessions = ds.session_summary.active_sessions,
            total_calls = ds.session_summary.total_calls,
            avg_latency = ds
                .session_summary
                .avg_latency_ms
                .map_or_else(|| "-".to_string(), |ms| format!("{ms} ms")),
            cache_hits = ds.cache_stats.total_hits,
            cache_misses = ds.cache_stats.total_misses,
            hit_pct = hit_pct,
            backend_rows = backend_rows,
            tool_rows = tool_rows,
        )
    }

    #[allow(clippy::format_collect)] // format! inside collect is intentional for HTML row building
    fn render_backend_rows(backends: &[BackendHealth]) -> String {
        if backends.is_empty() {
            return r#"<tr><td colspan="5" style="color:var(--fg2)">No backends registered</td></tr>"#
                .to_string();
        }
        backends
            .iter()
            .map(|b| {
                let latency = b
                    .latency_ms
                    .map_or_else(|| "-".to_string(), |ms| format!("{ms} ms"));
                let error_pct = format!("{:.1}%", b.error_rate * 100.0);
                format!(
                    "<tr><td><strong>{name}</strong></td>\
                     <td><span class=\"badge {css}\">{label}</span></td>\
                     <td>{latency}</td><td>{error_pct}</td><td>{tools}</td></tr>",
                    name = esc(&b.name),
                    css = b.status.css_class(),
                    label = b.status.label(),
                    latency = latency,
                    error_pct = error_pct,
                    tools = b.tool_count,
                )
            })
            .collect::<String>()
    }

    #[allow(clippy::format_collect)] // format! inside collect is intentional for HTML row building
    fn render_tool_rows(counts: &[TopTool]) -> String {
        if counts.is_empty() {
            return r#"<tr><td colspan="3" style="color:var(--fg2)">No tool calls recorded yet</td></tr>"#
                .to_string();
        }
        counts
            .iter()
            .map(|c| {
                format!(
                    "<tr><td>{tool}</td><td>{server}</td><td>{count}</td></tr>",
                    tool = esc(&c.tool),
                    server = esc(&c.server),
                    count = c.count,
                )
            })
            .collect::<String>()
    }
}

// ── Existing handlers (tools / config / reload) ─────────────────────

/// MIK-8786: the auth facts the page decides from, stated in both views of
/// `GET /ui/api/status`: whether authentication is on, and whether this caller
/// is signed in and is an admin. Three booleans about the caller, none about
/// backends; an anonymous caller already learns on/off from 401 versus 200.
fn auth_facts(state: &AppState, client: Option<&AuthenticatedClient>) -> Value {
    json!({
        "enabled": state.live_config.generation().auth().enabled,
        "signed_in": client.is_some_and(|c| c.authenticated),
        "admin": is_admin(client),
    })
}

/// `GET /ui/api/tools` — flat list of all cached tools across servers.
async fn tools(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    Query(params): Query<ToolsQuery>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator dashboard behind admin auth; not a tenant read"
    )]
    let backends = state.backends.all();
    let mut entries: Vec<Value> = Vec::new();
    let query_lower = params.q.as_deref().unwrap_or("").to_lowercase();
    let server_filter = params.server.as_deref().unwrap_or("");

    for backend in &backends {
        let name = &backend.name;

        // Server filter
        if !server_filter.is_empty() && name.as_str() != server_filter {
            continue;
        }

        // get_tools() returns from cache if populated (no network I/O).
        // If cache is empty, it will connect + fetch — acceptable for the tools tab.
        if let Ok((tools, declared)) = backend.shared_tools_with_declared_hints().await {
            for tool in tools.iter() {
                // Search filter
                if !query_lower.is_empty() {
                    let name_match = tool.name.to_lowercase().contains(&query_lower);
                    let desc_match = tool
                        .description
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&query_lower);
                    if !name_match && !desc_match {
                        continue;
                    }
                }

                let (class, class_source) =
                    preview::tool_class(tool, declared.contains(&tool.name));
                entries.push(json!({
                    "name": tool.name,
                    "server": name,
                    "description": tool.description,
                    "schema": tool.input_schema,
                    "class": class,
                    "class_source": class_source,
                    // The admin view lists every cached tool, so one left out
                    // of `allowed_tools` can be ticked again.
                    "selected": !backend.is_unselected(&tool.name),
                }));
            }
        }
    }

    // The names, copied out so the entries can take their counts in place.
    let names: Vec<(String, String)> = entries
        .iter()
        .map(|e| {
            let text = |key: &str| e[key].as_str().unwrap_or_default().to_owned();
            (text("server"), text("name"))
        })
        .collect();
    let labels: Vec<crate::counters::Filter<'_>> = names
        .iter()
        .map(|(server, tool)| crate::counters::Filter::Tool(server, tool))
        .collect();
    let (windows, counts_since) = call_windows(&state, &labels);
    for (entry, (day, prev)) in entries.iter_mut().zip(windows) {
        entry["calls_24h"] = json!(day);
        entry["calls_prev_24h"] = json!(prev);
    }

    Json(json!({
        "tools": entries,
        "total": entries.len(),
        "counts_since": counts_since,
    }))
    .into_response()
}

/// `GET /ui/api/config` — sanitized configuration (secrets masked). One
/// generation per response: the one pinned on this request (ADR-023).
async fn config(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    // Build a sanitized config snapshot from AppState
    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator dashboard behind admin auth; not a tenant read"
    )]
    let backends = state.backends.all();
    let servers: Vec<Value> = backends
        .iter()
        .map(|b| {
            let s = b.status();
            json!({
                "name": s.name,
                "transport": s.transport,
                "running": s.running,
                // As written, so a pattern that matches no current tool shows.
                "allowed_tools": b.allowed_tools(),
            })
        })
        .collect();

    // Each backend secret slot that holds a reference, as written, read from
    // the literal file: never a resolved value (ADR-028).
    let secret_references = match state.config_path.clone() {
        Some(path) => tokio::task::spawn_blocking(move || {
            crate::config::Config::load_literal(Some(&path)).map_or_else(
                |e| {
                    tracing::warn!(error = %e, "secret references hidden: config did not load");
                    std::collections::BTreeMap::new()
                },
                |literal| crate::config::display::backend_secret_references(&literal),
            )
        })
        .await
        .unwrap_or_default(),
        None => std::collections::BTreeMap::new(),
    };

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "meta_mcp_enabled": state.meta_mcp_enabled,
        "streaming_enabled": state.streaming_config.enabled,
        "sanitize_input": generation.sanitize_input(),
        "ssrf_protection": generation.ssrf_protection(),
        "environment": generation.environment(),
        "servers": servers,
        "secret_references": secret_references,
    }))
    .into_response()
}

/// `POST /ui/api/reload` — trigger an immediate config reload (admin only).
async fn reload(State(state): State<Arc<AppState>>, guard: Guard) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    let Some(reload_context) = state.meta_mcp.reload_context() else {
        return flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Config reload is not enabled on this gateway",
        )
        .into_response();
    };

    match reload_context.reload_outcome().await {
        Ok(outcome) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "changes": outcome.changes,
                "restart_required": outcome.restart_required,
                "restart_reason": outcome.restart_reason,
            })),
        )
            .into_response(),
        Err(error) => {
            // Whose fault, not just that it failed (MIK-8058): a file the
            // network posture refuses is the operator's config, a shutdown is
            // the gateway unavailable.
            use crate::config_reload::{ReloadFailure, reload_failure};
            let status = match reload_failure(&error) {
                ReloadFailure::PostureRefused => StatusCode::CONFLICT,
                ReloadFailure::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
                ReloadFailure::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            };
            flat_error(status, error).into_response()
        }
    }
}

/// `GET /ui/api/costs` — aggregate cost data for the web UI (admin only).
///
/// Returns aggregate totals, per-API-key breakdown, and per-session breakdown.
/// Requires admin access (returns 401 for unauthenticated public requests).
#[cfg(feature = "cost-governance")]
async fn costs(State(state): State<Arc<AppState>>, guard: Guard) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let tracker = state.meta_mcp.cost_tracker();
    Json(serde_json::json!({
        "aggregate": serde_json::to_value(tracker.aggregate()).unwrap_or(serde_json::Value::Null),
        "by_key":     serde_json::to_value(tracker.all_keys()).unwrap_or(serde_json::json!([])),
        "by_session": serde_json::to_value(tracker.all_sessions_fingerprinted()).unwrap_or_default(),
        // The zone daily budgets count days in (ADR-026).
        "day_zone": state.meta_mcp.day_zone(),
    }))
    .into_response()
}

// ── Private helpers ──────────────────────────────────────────────────

/// HTML-escape a string to prevent XSS in server-rendered output.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Compute error rate as a fraction (0.0–1.0).
fn compute_error_rate(success: u64, failure: u64) -> f64 {
    let total = success + failure;
    if total == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let rate = failure as f64 / total as f64;
    rate
}

/// Compute average P50 latency across all backends that have data.
fn avg_latency_from_backends(backends: &[Arc<crate::backend::Backend>]) -> Option<u64> {
    let latencies: Vec<u64> = backends
        .iter()
        .filter_map(|b| b.health_metrics().latency_p50_ms)
        .collect();
    if latencies.is_empty() {
        return None;
    }
    let sum: u64 = latencies.iter().sum();
    #[allow(clippy::cast_possible_truncation)]
    Some(sum / latencies.len() as u64)
}

/// Format uptime seconds into a human-readable string.
fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m {s}s")
    }
}

// ── Existing internal types ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ToolsQuery {
    q: Option<String>,
    server: Option<String>,
}

/// Each label's calls in the last 24 hours (the 48 half-hour buckets ending
/// with the current, partial one) and in the same local wall-clock hours of
/// the day before (on a DST date that span is one hour shorter or longer),
/// read in one store read, plus when counting began. A count is `None` when
/// it could be low (calls folded into an overflow, or no longer held); every
/// count and the start are `None` when the counter store is not running or
/// the clock cannot be read: the caller still answers, with nulls.
fn call_windows(
    state: &AppState,
    labels: &[crate::counters::Filter<'_>],
) -> (Vec<crate::counters::CallWindows>, Option<u64>) {
    let unknown = || vec![(None, None); labels.len()];
    let (Some(store), Ok(now)) = (state.meta_mcp.counters(), crate::clock::unix_secs()) else {
        return (unknown(), None);
    };
    let sums = store.window_sums(labels, now, &crate::local_day::host_zone());
    (sums.counts, Some(sums.since))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
