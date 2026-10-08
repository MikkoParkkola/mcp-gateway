// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /health`.

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::json;

use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;

/// Decide overall gateway health from per-backend status.
///
/// Overall health must reflect more than the circuit breaker. A backend that is
/// timing out under load records consecutive failures and the health tracker
/// flips it unhealthy *before* the breaker trips Open; deriving health from
/// circuit state alone reports "healthy" while backends are silently failing
/// (MIK-5080). A backend is considered healthy only when its breaker is not
/// Open AND the health tracker still considers it live.
pub(super) fn backends_overall_healthy(
    statuses: &std::collections::HashMap<String, crate::backend::BackendStatus>,
) -> bool {
    statuses
        .values()
        .all(|s| s.circuit_state != crate::failsafe::CircuitState::Open && s.healthy)
}

/// Health check handler
///
/// For unauthenticated (public) clients, backend details are redacted
/// to avoid leaking internal topology. Only authenticated admin clients
/// see full backend names and circuit breaker state.
pub(in crate::gateway::router) async fn health_handler(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    let statuses = state.backends.statuses();
    // The in-process capability backend is not in the registry: its health (MIK-5080) and its
    // startup scan (MIK-7268) count here. None configured is healthy (`all` of nothing).
    let capability_status = state.meta_mcp.get_capabilities().map(|c| c.status());
    let capability_healthy = capability_status.iter().all(|s| s.healthy && s.loaded);
    // MIK-8052: a sealed task row degrades health; probes read `/livez`.
    let sealed_rows = state.tasks.skipped_records().sealed;
    let healthy = backends_overall_healthy(&statuses) && capability_healthy && sealed_rows == 0;

    // Admin is a grant, not a name. Comparing against "public"/"anonymous"
    // gave full backend detail to every authenticated non-admin key the moment
    // an operator removed /health from `auth.public_paths`.
    let is_admin = request
        .extensions()
        .get::<AuthenticatedClient>()
        .is_some_and(|c| c.admin);

    let status = if healthy { "healthy" } else { "degraded" };
    // A non-admin gets `status` and `version` only: a backend count is
    // inventory, and readiness probes read `status` or `/livez`/`/readyz` (A3).
    let response = if is_admin {
        json!({
            "status": status,
            "version": env!("CARGO_PKG_VERSION"),
            "backends": serde_json::to_value(&statuses).unwrap_or(json!({})),
            // Capability-backend health as a sibling field, so the existing
            // `backends` shape stays backward-compatible.
            "capability_backend": capability_status
                .as_ref()
                .map(|s| serde_json::to_value(s).unwrap_or(json!({}))),
            "task_store": state.tasks.health_view(),
        })
    } else {
        json!({ "status": status, "version": env!("CARGO_PKG_VERSION") })
    };

    let code = [StatusCode::SERVICE_UNAVAILABLE, StatusCode::OK][usize::from(healthy)];
    (code, Json(response))
}
