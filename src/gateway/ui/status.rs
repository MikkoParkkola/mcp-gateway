// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/status`, shaped by who is asking, with the caller's `access`
//! report; its payload is the one the live stream sends: one builder, so the
//! two cannot drift.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, State};
use serde::Serialize;
use serde_json::{Value, json};

use super::guard::Guard;
use super::{AppState, access_report, auth_facts, call_windows};
use crate::gateway::auth::is_gateway_admin;
use crate::gateway::authz::BackendGrant;
use crate::gateway::restart_status::RestartStatus;
use crate::oauth::client::sign_in::SignIn;

/// `GET /ui/api/status` — JSON snapshot of gateway health.
pub(super) async fn status(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<crate::config_reload::Generation>>,
    guard: Guard,
) -> Json<Value> {
    // Open to every caller that reaches it; the answer is shaped by caller.
    let _ = guard.admit();
    let access = access_report::report(&generation, guard.client.as_ref(), guard.identity.as_ref());
    let client = guard.client;
    // A caller with no credential (a public status path) has no scope to
    // narrow by. A scoped admin gets the counts, within its scope: the full
    // view lists every backend.
    let (view, scope) = StatusView::for_client(client.as_ref());
    let mut body = status_body(&state, view, scope);
    body["auth"] = auth_facts(&state, client.as_ref());
    // An auth-on caller with no credential gets no `access` member at all.
    if let Some(access) = access {
        body["access"] = access;
    }
    Json(body)
}

/// Which of the two views a caller gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StatusView {
    /// Every server row: unscoped admin callers.
    Full,
    /// Counts only, of the backends the caller's scope reaches: every other
    /// caller.
    CountsOnly,
}

impl StatusView {
    /// The view `client` gets and the backend scope its counts read within:
    /// the full view only for an unscoped gateway admin. The one place that
    /// decides it, for the status route and the restart GET alike.
    pub(super) fn for_client(
        client: Option<&crate::gateway::auth::AuthenticatedClient>,
    ) -> (Self, BackendGrant<'_>) {
        let scope = BackendGrant::for_ui(client);
        let view = if is_gateway_admin(client) && scope == BackendGrant::Unscoped {
            Self::Full
        } else {
            Self::CountsOnly
        };
        (view, scope)
    }
}

/// The status body without the caller's `auth` member, which the caller adds.
/// `CountsOnly` counts only the backends `scope` admits.
pub(super) fn status_body(state: &AppState, view: StatusView, scope: BackendGrant<'_>) -> Value {
    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator dashboard behind admin auth; not a tenant read"
    )]
    let backends = state.backends.all();
    let total = backends.len();

    if view == StatusView::CountsOnly {
        // Redacted view: counts only, no names/details
        let counted: Vec<_> = backends.iter().filter(|b| scope.admits(&b.name)).collect();
        let total = counted.len();
        let healthy = counted
            .iter()
            .filter(|b| b.status().circuit_state != crate::failsafe::CircuitState::Open)
            .count();
        let mut body = json!({
            "server_count": total,
            "healthy_count": healthy,
            "degraded_count": total - healthy,
            "uptime_secs": state.process.uptime_secs(),
            "version": env!("CARGO_PKG_VERSION"),
        });
        add_restart(&mut body, view, state.meta_mcp.restart_board().status());
        return body;
    }

    // Full admin view
    let mut servers: Vec<ServerStatus> = Vec::with_capacity(total);
    let mut tool_count: usize = 0;
    let mut cb_closed: usize = 0;
    let mut cb_open: usize = 0;
    let mut cb_half_open: usize = 0;

    let now = crate::clock::system_time_or_before_epoch();
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

        let view = backend.server_state(now);
        servers.push(ServerStatus {
            state: view.state,
            reason: view.reason,
            next_retry_at: view
                .next_retry_at
                .and_then(crate::config_reload::refusals::rfc3339),
            cleartext_credentials_accepted: backend.cleartext_override_in_effect(),
            needs_sign_in: backend.needs_sign_in(),
            sign_in: Some(backend.sign_in()).filter(|sign_in| *sign_in != SignIn::NotOAuth),
            // A sign-in in flight: only its phase and end, never a secret.
            sign_in_flow: backend.sign_in_flow_view().map(|(phase, until)| {
                super::backends::with_time(json!({ "phase": phase.word() }), "until", until)
            }),
            calls_24h: None,
            calls_prev_24h: None,
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

    let labels: Vec<crate::counters::Filter<'_>> = servers
        .iter()
        .map(|s| crate::counters::Filter::Server(&s.name))
        .collect();
    let (windows, counts_since, _) = call_windows(state, &labels);
    for (server, w) in servers.iter_mut().zip(windows) {
        server.calls_24h = w.day;
        server.calls_prev_24h = w.prev_day;
    }

    let mut body = json!({
        "server_count": total,
        "tool_count": tool_count,
        "uptime_secs": state.process.uptime_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "circuit_breakers": {
            "closed": cb_closed,
            "open": cb_open,
            "half_open": cb_half_open,
        },
        "servers": servers,
        "counts_since": counts_since,
    });
    add_restart(&mut body, view, state.meta_mcp.restart_board().status());
    body
}

/// Add the restart member to a status body: the latest attempt's wire form,
/// or null before any accept, in the full view only. The counts-only view
/// (which scoped callers get too) never carries it, so a change of the record
/// raises the stream's status generation and never its counts generation.
pub(super) fn add_restart(body: &mut Value, view: StatusView, record: Option<RestartStatus>) {
    if view == StatusView::Full
        && let Some(members) = body.as_object_mut()
    {
        members.insert(
            "restart".to_owned(),
            record.as_ref().map_or(Value::Null, RestartStatus::wire),
        );
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent fact on the wire; no two encode a state"
)]
#[derive(Debug, Serialize)]
struct ServerStatus {
    name: String,
    running: bool,
    transport: String,
    tools_cached: usize,
    /// Requests since this process started; resets on restart.
    request_count: u64,
    /// Calls in the last 24 hours, persisted across restarts; `null` when
    /// the count could be low (see [`call_windows`]).
    calls_24h: Option<u64>,
    /// Calls in the same hours of the day before; `null` likewise.
    calls_prev_24h: Option<u64>,
    circuit_state: String,
    circuit_trips: u64,
    current_failures: u32,
    healthy: bool,
    success_count: u64,
    failure_count: u64,
    latency_p50_ms: Option<u64>,
    latency_p95_ms: Option<u64>,
    latency_p99_ms: Option<u64>,
    /// The operator's one-word state, with why and when it retries.
    state: crate::backend::server_state::ServerState,
    reason: String,
    next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Loads only because `allow_cleartext_credentials` accepts sending its
    /// credentials in cleartext.
    cleartext_credentials_accepted: bool,
    /// Whether a person must sign in: the one predicate
    /// (`Backend::needs_sign_in`), shown beside `state` so display keys on it.
    needs_sign_in: bool,
    /// Its sign-in, for a backend that has an `oauth` block or waits on a
    /// sign-in made elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    sign_in: Option<SignIn>,
    /// A sign-in in flight: only `phase` and `until`, never a secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    sign_in_flow: Option<Value>,
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
