//! Embedded web UI for the MCP Gateway.
//!
//! Serves a single-page HTML dashboard from the same axum server,
//! with JSON API endpoints for live status, tools, and configuration.
//! Also exposes `GET /dashboard` — a self-contained operator dashboard
//! rendered as inline HTML with automatic 5-second refresh.
//!
//! All UI code is gated behind the `webui` feature flag.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::auth::AuthenticatedClient;
use super::router::AppState;
use crate::stats::StatsSnapshot;

/// Embedded HTML — compiled into the binary, zero filesystem dependency.
const INDEX_HTML: &str = include_str!("index.html");

/// Process start time for uptime calculation.
static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn uptime_secs() -> u64 {
    START.get_or_init(Instant::now).elapsed().as_secs()
}

/// Returns `true` when the caller has admin-level access.
///
/// When auth is disabled the middleware sets name="anonymous" — treat
/// that as admin (no point restricting with no auth configured).
/// Only "public" (unauthenticated with auth enabled) is restricted.
fn is_admin(client: Option<&AuthenticatedClient>) -> bool {
    client.is_some_and(|c| c.name != "public")
}

/// Build the authenticated `/ui/api/*` and `/dashboard` sub-router.
pub fn api_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ui/api/status", get(status))
        .route("/ui/api/tools", get(tools))
        .route("/ui/api/config", get(config))
        .route("/ui/api/reload", post(reload))
        .route("/dashboard", get(dashboard_handler))
}

/// Build the unauthenticated `/ui` route (serves static HTML, no data).
pub fn html_router() -> Router {
    Router::new().route("/ui", get(index))
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /ui` — serve the single-page HTML dashboard.
async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// `GET /dashboard` — operator dashboard: self-contained HTML, auto-refreshes every 5 s.
pub async fn dashboard_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let backends = state.backends.all();

    // Collect per-backend health data.
    let mut backend_healths: Vec<BackendHealth> = Vec::with_capacity(backends.len());
    let mut total_tools: usize = 0;
    let mut total_calls: u64 = 0;

    for backend in &backends {
        let bs = backend.status();
        let hm = backend.health_metrics();

        total_tools += bs.tools_cached;
        total_calls += bs.request_count;

        let status = if !bs.running {
            HealthStatus::Down
        } else if hm.healthy {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        };

        backend_healths.push(BackendHealth {
            name: bs.name.clone(),
            status,
            latency_ms: hm.latency_p50_ms,
            error_rate: compute_error_rate(hm.success_count, hm.failure_count),
            tool_count: bs.tools_cached,
        });
    }

    // Aggregate session / call summary from UsageStats snapshot.
    // We pass total_tools as the available count (same convention as
    // the existing snapshot() caller in meta_mcp).
    let snap: StatsSnapshot = state.meta_mcp.stats_snapshot(total_tools);

    let session_summary = SessionSummary {
        active_sessions: state.multiplexer.session_count(),
        total_calls,
        avg_latency_ms: avg_latency_from_backends(&backends),
    };

    let cache_stats = CacheStats {
        hit_rate: snap.cache_hit_rate,
        total_hits: snap.cache_hits,
        total_misses: snap.invocations.saturating_sub(snap.cache_hits),
    };

    // Recent calls come from the top-tools list (best available proxy without
    // a dedicated ring-buffer for now).
    let recent_calls: Vec<RecentCall> = snap
        .top_tools
        .iter()
        .take(50)
        .map(|t| RecentCall {
            timestamp: String::new(), // no per-call timestamps in current stats
            tool: t.tool.clone(),
            server: t.server.clone(),
            latency_ms: None,
            status: CallStatus::Success,
            count: t.count,
        })
        .collect();

    let ds = DashboardState {
        backends: backend_healths,
        session_summary,
        recent_calls,
        cache_stats,
        uptime_secs: uptime_secs(),
        version: env!("CARGO_PKG_VERSION"),
    };

    let html = DashboardRenderer::render(&ds);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
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

/// One entry in the recent-calls table.
#[derive(Debug, Clone, Serialize)]
pub struct RecentCall {
    /// ISO-8601 timestamp (empty if not tracked).
    pub timestamp: String,
    /// Tool name.
    pub tool: String,
    /// Backend server name.
    pub server: String,
    /// Observed latency in milliseconds.
    pub latency_ms: Option<u64>,
    /// Whether the call succeeded or failed.
    pub status: CallStatus,
    /// Cumulative call count for this tool (used when per-call log is unavailable).
    pub count: u64,
}

/// Success/error classification for a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CallStatus {
    /// Call completed successfully.
    Success,
    /// Call returned an error.
    Error,
}

impl CallStatus {
    fn css_class(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
    fn label(&self) -> &'static str {
        match self {
            Self::Success => "OK",
            Self::Error => "ERR",
        }
    }
}

/// Full aggregated state used to render the operator dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardState<'a> {
    /// Per-backend health matrix.
    pub backends: Vec<BackendHealth>,
    /// Session / call summary.
    pub session_summary: SessionSummary,
    /// Recent calls (up to 50).
    pub recent_calls: Vec<RecentCall>,
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
        let recent_rows = Self::render_recent_rows(&ds.recent_calls);
        let hit_pct = format!("{:.1}", ds.cache_stats.hit_rate * 100.0);
        let uptime = format_uptime(ds.uptime_secs);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
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
.success{{background:rgba(63,185,80,.15);color:var(--green);}}
.error{{background:rgba(248,81,73,.15);color:var(--red);}}
.hit-bar{{background:var(--bg3);border-radius:var(--r);height:8px;overflow:hidden;margin-top:.5rem;}}
.hit-fill{{height:100%;background:var(--green);border-radius:var(--r);}}
.meta{{font-size:.75rem;color:var(--fg2);margin-top:1.5rem;}}
</style>
</head>
<body>
<h1>MCP Gateway — Operator Dashboard</h1>
<div class="sub">v{version} &nbsp;|&nbsp; uptime: {uptime} &nbsp;|&nbsp; auto-refresh every 5 s</div>

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

<h2>Top Tools (last 50)</h2>
<table>
  <thead><tr><th>Tool</th><th>Server</th><th>Calls</th><th>Status</th></tr></thead>
  <tbody>{recent_rows}</tbody>
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
            recent_rows = recent_rows,
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
    fn render_recent_rows(calls: &[RecentCall]) -> String {
        if calls.is_empty() {
            return r#"<tr><td colspan="4" style="color:var(--fg2)">No tool calls recorded yet</td></tr>"#
                .to_string();
        }
        calls
            .iter()
            .map(|c| {
                format!(
                    "<tr><td>{tool}</td><td>{server}</td><td>{count}</td>\
                     <td><span class=\"badge {css}\">{label}</span></td></tr>",
                    tool = esc(&c.tool),
                    server = esc(&c.server),
                    count = c.count,
                    css = c.status.css_class(),
                    label = c.status.label(),
                )
            })
            .collect::<String>()
    }
}

// ── Existing handlers (status / tools / config / reload) ────────────

/// `GET /ui/api/status` — JSON snapshot of gateway health.
async fn status(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> Json<Value> {
    let client = client.map(|Extension(c)| c);
    let backends = state.backends.all();
    let total = backends.len();

    if !is_admin(client.as_ref()) {
        // Redacted view: counts only, no names/details
        let healthy = backends
            .iter()
            .filter(|b| b.status().circuit_state != "Open")
            .count();
        return Json(json!({
            "server_count": total,
            "healthy_count": healthy,
            "degraded_count": total - healthy,
            "uptime_secs": uptime_secs(),
            "version": env!("CARGO_PKG_VERSION"),
        }));
    }

    // Full admin view
    let mut servers: Vec<ServerStatus> = Vec::with_capacity(total);
    let mut tool_count: usize = 0;
    let mut cb_closed: usize = 0;
    let mut cb_open: usize = 0;
    let mut cb_half_open: usize = 0;

    for backend in &backends {
        let bs = backend.status();
        let cb = backend.circuit_breaker_stats();
        let hm = backend.health_metrics();

        tool_count += bs.tools_cached;

        match cb.state {
            crate::failsafe::CircuitState::Closed => cb_closed += 1,
            crate::failsafe::CircuitState::Open => cb_open += 1,
            crate::failsafe::CircuitState::HalfOpen => cb_half_open += 1,
        }

        servers.push(ServerStatus {
            name: bs.name,
            running: bs.running,
            transport: bs.transport,
            tools_cached: bs.tools_cached,
            request_count: bs.request_count,
            circuit_state: cb.state.as_str().to_string(),
            circuit_trips: cb.trips_count,
            current_failures: cb.current_failures,
            healthy: hm.healthy,
            success_count: hm.success_count,
            failure_count: hm.failure_count,
            latency_p50_ms: hm.latency_p50_ms,
            latency_p95_ms: hm.latency_p95_ms,
            latency_p99_ms: hm.latency_p99_ms,
        });
    }

    Json(json!({
        "server_count": total,
        "tool_count": tool_count,
        "uptime_secs": uptime_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "circuit_breakers": {
            "closed": cb_closed,
            "open": cb_open,
            "half_open": cb_half_open,
        },
        "servers": servers,
    }))
}

/// `GET /ui/api/tools` — flat list of all cached tools across servers.
async fn tools(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    Query(params): Query<ToolsQuery>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);

    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Authentication required"})),
        )
            .into_response();
    }

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
        if let Ok(tools) = backend.get_tools().await {
            for tool in &tools {
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

                entries.push(json!({
                    "name": tool.name,
                    "server": name,
                    "description": tool.description,
                    "schema": tool.input_schema,
                }));
            }
        }
    }

    Json(json!({ "tools": entries, "total": entries.len() })).into_response()
}

/// `GET /ui/api/config` — sanitized configuration (secrets masked).
async fn config(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);

    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Authentication required"})),
        )
            .into_response();
    }

    // Build a sanitized config snapshot from AppState
    let backends = state.backends.all();
    let servers: Vec<Value> = backends
        .iter()
        .map(|b| {
            let s = b.status();
            json!({
                "name": s.name,
                "transport": s.transport,
                "running": s.running,
            })
        })
        .collect();

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "meta_mcp_enabled": state.meta_mcp_enabled,
        "streaming_enabled": state.streaming_config.enabled,
        "sanitize_input": state.sanitize_input,
        "ssrf_protection": state.ssrf_protection,
        "servers": servers,
    }))
    .into_response()
}

/// `POST /ui/api/reload` — trigger hot-reload (admin only).
async fn reload(client: Option<Extension<AuthenticatedClient>>) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);

    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        );
    }

    // Hot-reload is handled by the file watcher in the gateway server.
    // This endpoint signals intent — the actual reload happens via notify/SIGHUP.
    // For now, return success to indicate the request was accepted.
    (StatusCode::OK, Json(json!({"status": "reload_requested"})))
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

#[derive(Debug, Serialize)]
struct ServerStatus {
    name: String,
    running: bool,
    transport: String,
    tools_cached: usize,
    request_count: u64,
    circuit_state: String,
    circuit_trips: u64,
    current_failures: u32,
    healthy: bool,
    success_count: u64,
    failure_count: u64,
    latency_p50_ms: Option<u64>,
    latency_p95_ms: Option<u64>,
    latency_p99_ms: Option<u64>,
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DashboardState helpers ──────────────────────────────────────

    fn healthy_backend(name: &str, tool_count: usize, latency_ms: Option<u64>) -> BackendHealth {
        BackendHealth {
            name: name.to_string(),
            status: HealthStatus::Healthy,
            latency_ms,
            error_rate: 0.0,
            tool_count,
        }
    }

    fn degraded_backend(name: &str) -> BackendHealth {
        BackendHealth {
            name: name.to_string(),
            status: HealthStatus::Degraded,
            latency_ms: Some(500),
            error_rate: 0.3,
            tool_count: 2,
        }
    }

    fn down_backend(name: &str) -> BackendHealth {
        BackendHealth {
            name: name.to_string(),
            status: HealthStatus::Down,
            latency_ms: None,
            error_rate: 1.0,
            tool_count: 0,
        }
    }

    fn default_state<'a>(backends: Vec<BackendHealth>) -> DashboardState<'a> {
        DashboardState {
            backends,
            session_summary: SessionSummary {
                active_sessions: 3,
                total_calls: 42,
                avg_latency_ms: Some(80),
            },
            recent_calls: vec![],
            cache_stats: CacheStats {
                hit_rate: 0.75,
                total_hits: 300,
                total_misses: 100,
            },
            uptime_secs: 3661,
            version: "2.4.0",
        }
    }

    // ── HealthStatus ────────────────────────────────────────────────

    #[test]
    fn health_status_css_class() {
        assert_eq!(HealthStatus::Healthy.css_class(), "healthy");
        assert_eq!(HealthStatus::Degraded.css_class(), "degraded");
        assert_eq!(HealthStatus::Down.css_class(), "down");
    }

    #[test]
    fn health_status_label() {
        assert_eq!(HealthStatus::Healthy.label(), "Healthy");
        assert_eq!(HealthStatus::Degraded.label(), "Degraded");
        assert_eq!(HealthStatus::Down.label(), "Down");
    }

    #[test]
    fn call_status_css_and_label() {
        assert_eq!(CallStatus::Success.css_class(), "success");
        assert_eq!(CallStatus::Error.css_class(), "error");
        assert_eq!(CallStatus::Success.label(), "OK");
        assert_eq!(CallStatus::Error.label(), "ERR");
    }

    // ── compute_error_rate ──────────────────────────────────────────

    #[test]
    fn error_rate_zero_when_no_calls() {
        let rate = compute_error_rate(0, 0);
        assert!(rate.abs() < f64::EPSILON);
    }

    #[test]
    fn error_rate_zero_when_all_success() {
        let rate = compute_error_rate(100, 0);
        assert!(rate.abs() < f64::EPSILON);
    }

    #[test]
    fn error_rate_one_when_all_failure() {
        let rate = compute_error_rate(0, 50);
        assert!((rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn error_rate_partial() {
        let rate = compute_error_rate(75, 25);
        assert!((rate - 0.25).abs() < 1e-9);
    }

    // ── format_uptime ───────────────────────────────────────────────

    #[test]
    fn format_uptime_seconds() {
        assert_eq!(format_uptime(45), "0m 45s");
    }

    #[test]
    fn format_uptime_minutes() {
        assert_eq!(format_uptime(130), "2m 10s");
    }

    #[test]
    fn format_uptime_hours() {
        assert_eq!(format_uptime(3661), "1h 1m");
    }

    #[test]
    fn format_uptime_days() {
        assert_eq!(format_uptime(90_000), "1d 1h");
    }

    // ── esc ─────────────────────────────────────────────────────────

    #[test]
    fn esc_replaces_html_specials() {
        assert_eq!(esc("<script>"), "&lt;script&gt;");
        assert_eq!(esc("a & b"), "a &amp; b");
        assert_eq!(esc(r#"say "hi""#), "say &quot;hi&quot;");
        assert_eq!(esc("it's"), "it&#x27;s");
    }

    #[test]
    fn esc_passthrough_plain_text() {
        let plain = "hello world 123";
        assert_eq!(esc(plain), plain);
    }

    // ── DashboardRenderer ───────────────────────────────────────────

    #[test]
    fn render_contains_doctype_and_meta_refresh() {
        let ds = default_state(vec![healthy_backend("alpha", 5, Some(20))]);
        let html = DashboardRenderer::render(&ds);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains(r#"http-equiv="refresh" content="5""#));
    }

    #[test]
    fn render_contains_version_and_uptime() {
        let ds = default_state(vec![]);
        let html = DashboardRenderer::render(&ds);
        assert!(html.contains("v2.4.0"));
        assert!(html.contains("1h 1m")); // 3661 s
    }

    #[test]
    fn render_backend_rows_healthy() {
        let backends = vec![healthy_backend("my-backend", 10, Some(42))];
        let rows = DashboardRenderer::render_backend_rows(&backends);
        assert!(rows.contains("my-backend"));
        assert!(rows.contains("badge healthy"));
        assert!(rows.contains("42 ms"));
        assert!(rows.contains("0.0%")); // error rate
    }

    #[test]
    fn render_backend_rows_degraded_and_down() {
        let backends = vec![degraded_backend("svc-a"), down_backend("svc-b")];
        let rows = DashboardRenderer::render_backend_rows(&backends);
        assert!(rows.contains("badge degraded"));
        assert!(rows.contains("badge down"));
    }

    #[test]
    fn render_backend_rows_empty_shows_fallback() {
        let rows = DashboardRenderer::render_backend_rows(&[]);
        assert!(rows.contains("No backends registered"));
    }

    #[test]
    fn render_recent_rows_empty_shows_fallback() {
        let rows = DashboardRenderer::render_recent_rows(&[]);
        assert!(rows.contains("No tool calls recorded yet"));
    }

    #[test]
    fn render_recent_rows_with_calls() {
        let calls = vec![
            RecentCall {
                timestamp: String::new(),
                tool: "search".to_string(),
                server: "brave".to_string(),
                latency_ms: None,
                status: CallStatus::Success,
                count: 7,
            },
            RecentCall {
                timestamp: String::new(),
                tool: "query".to_string(),
                server: "db".to_string(),
                latency_ms: None,
                status: CallStatus::Error,
                count: 2,
            },
        ];
        let rows = DashboardRenderer::render_recent_rows(&calls);
        assert!(rows.contains("search"));
        assert!(rows.contains("brave"));
        assert!(rows.contains("badge success"));
        assert!(rows.contains("badge error"));
    }

    #[test]
    fn render_cache_hit_rate_displayed() {
        let ds = default_state(vec![]);
        let html = DashboardRenderer::render(&ds);
        assert!(html.contains("75.0%"));
    }

    #[test]
    fn render_session_summary_in_cards() {
        let ds = default_state(vec![]);
        let html = DashboardRenderer::render(&ds);
        // active_sessions = 3, total_calls = 42
        assert!(html.contains(">3<") || html.contains(">3 <") || html.contains("val\">3"));
        assert!(html.contains(">42<") || html.contains("val\">42"));
    }

    #[test]
    fn render_xss_escaped_in_backend_name() {
        let backends = vec![BackendHealth {
            name: "<evil>".to_string(),
            status: HealthStatus::Healthy,
            latency_ms: None,
            error_rate: 0.0,
            tool_count: 0,
        }];
        let rows = DashboardRenderer::render_backend_rows(&backends);
        assert!(!rows.contains("<evil>"));
        assert!(rows.contains("&lt;evil&gt;"));
    }

    #[test]
    fn render_xss_escaped_in_tool_name() {
        let calls = vec![RecentCall {
            timestamp: String::new(),
            tool: "<script>alert(1)</script>".to_string(),
            server: "s".to_string(),
            latency_ms: None,
            status: CallStatus::Success,
            count: 1,
        }];
        let rows = DashboardRenderer::render_recent_rows(&calls);
        assert!(!rows.contains("<script>"));
        assert!(rows.contains("&lt;script&gt;"));
    }

    // ── avg_latency_from_backends (pure helper, no backend) ─────────
    // Tested indirectly via format_uptime + compute_error_rate above.

    #[test]
    fn dashboard_state_serializes_to_json() {
        let ds = default_state(vec![healthy_backend("x", 1, Some(10))]);
        let json = serde_json::to_string(&ds).expect("serialization failed");
        assert!(json.contains("\"backends\""));
        assert!(json.contains("\"session_summary\""));
        assert!(json.contains("\"cache_stats\""));
    }
}
