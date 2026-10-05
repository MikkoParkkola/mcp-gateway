// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::{
    AppState, Arc, AuthenticatedClient, BackendHealth, CacheStats, CallStatus, DashboardRenderer,
    DashboardState, Extension, HealthStatus, IntoResponse, RecentCall, SessionSummary, State,
    StatsSnapshot, StatusCode, avg_latency_from_backends, compute_error_rate, is_admin,
    uptime_secs,
};

/// Served in place of the dashboard when the caller holds no admin credential.
const DASHBOARD_ADMIN_REQUIRED_HTML: &str = "<!doctype html><meta charset=utf-8>\
<title>Admin required</title>\
<body style=\"font:16px/1.5 system-ui;margin:4rem auto;max-width:34rem\">\
<h1>Admin required</h1>\
<p>This dashboard shows backend names, tool names and call counts, so it needs \
an admin credential.</p>\
<p>On a config <code>mcp-gateway init</code> wrote, the credential already \
exists and <code>serve</code> prints a single-use link to open this page with. \
Look for DASHBOARD in its startup output.</p>\
<p>That link is printed only when the gateway binds loopback. A gateway on a \
network address prints none, so there is nothing to redeem and a port-forward \
does not produce one: manage it through <a href=\"/ui\">/ui</a>, which can \
present the bearer token, or through the meta-tools with that same \
credential.</p>\
<p>On a config without authentication, set <code>auth.enabled = true</code> \
with a bearer token, keeping <code>/health</code> and <code>/mcp</code> in \
<code>auth.public_paths</code> so tool calls keep working.</p>";

/// `GET /dashboard` — operator dashboard: self-contained HTML, auto-refreshes every 5 s.
///
/// Admin only. The page renders backend names, tool names and call counts,
/// which is the same inventory `/ui/api/status` redacts for a non-admin caller,
/// so it follows the same rule rather than serving as a way around it.
pub async fn dashboard_handler(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        // HTML, not JSON. A browser navigating here cannot attach an
        // Authorization header, so a bare 403 would leave an operator staring at
        // a JSON-RPC error with no way forward. The page says what is missing
        // and points at `/ui`, which is a script that can send the header.
        return (
            StatusCode::FORBIDDEN,
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            DASHBOARD_ADMIN_REQUIRED_HTML,
        )
            .into_response();
    }

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
        .into_response()
}
