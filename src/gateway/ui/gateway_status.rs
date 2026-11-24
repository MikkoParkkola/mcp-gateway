// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/gateway`: the facts the web UI's Gateway page shows, in one
//! admin read.
//!
//! Admin only. Every value is either held by the process (its start, the
//! version change it recorded, what it refused while starting, the reload
//! tally) or read from the state on request (the environment, the TLS state,
//! the connected clients). Clients appear by the name each reported in
//! `initialize` and nothing else: no session id, no fingerprint, no owner.
//! The reported name is display text a peer chose, so it is cleaned when it is
//! kept and served as an ordinary JSON string; it is never an identity.
//! Cleaning removes control and format characters and caps the length; it does
//! NOT make the text HTML-safe (`<script>` comes back unchanged), so a consumer
//! must render `reported_name` as text, never as markup.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use super::AppState;
use super::gateway_upgrade::upgrade_block;
use super::guard::Guard;
use crate::cli_support::display_text;

/// Characters kept of an environment name or host name.
const ENVIRONMENT_CAP: usize = 128;

/// Where the environment name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvironmentSource {
    /// `environment:` in the configuration.
    Config,
    /// The host's name.
    Hostname,
    /// Neither was set or readable.
    Default,
}

impl EnvironmentSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Hostname => "hostname",
            Self::Default => "default",
        }
    }
}

/// The name shown when neither the configuration nor the host supplies one.
const DEFAULT_ENVIRONMENT: &str = "default";

/// The environment name and where it came from: the configured name, else the
/// host's, else [`DEFAULT_ENVIRONMENT`]. Each candidate is cleaned as display
/// text first, so one that cleans to nothing falls through to the next.
fn environment(configured: Option<&str>, host: Option<&str>) -> (String, EnvironmentSource) {
    let clean = |raw: Option<&str>| {
        raw.and_then(|raw| display_text(raw, ENVIRONMENT_CAP))
            .map(|(text, _cut)| text)
    };
    if let Some(name) = clean(configured) {
        return (name, EnvironmentSource::Config);
    }
    if let Some(name) = clean(host) {
        return (name, EnvironmentSource::Hostname);
    }
    (DEFAULT_ENVIRONMENT.to_owned(), EnvironmentSource::Default)
}

/// The `environment` block.
fn environment_block(state: &AppState) -> Value {
    let config = state.live_config.get();
    let (name, source) = environment(config.environment.as_deref(), state.process.host_name());
    json!({ "name": name, "source": source.as_str() })
}

/// The `tls` block: what the listener bound from at start. `running()` is the
/// configuration this process started with and a reload never replaces it, so
/// a staged change to `mtls` cannot make the page claim a state the listener
/// does not have.
fn tls_block(state: &AppState) -> Value {
    let mtls = &state.live_config.running().mtls;
    json!({
        "enabled": mtls.enabled,
        "client_certificates_required": mtls.enabled && mtls.require_client_cert,
    })
}

/// What only a restart would apply: null while nothing waits, else the field
/// ids in stored order. A changed startup value shows as one "environment"
/// id; no variable is named.
fn pending_restart_block(state: &AppState) -> Value {
    let (fields, wait) = state.live_config.restart_view();
    if fields.is_empty() {
        return Value::Null;
    }
    let mut block = serde_json::Map::new();
    block.insert("fields".into(), json!(fields));
    // Keys waiting in gateway.yaml freeze it: name them, and add what the
    // shared wrapper says for the file's own start verdict (guidance plus
    // start command if a start would succeed, else only its refusal).
    if let Some(wait) = wait {
        block.insert("frozen".into(), true.into());
        block.insert("waiting_keys".into(), json!(wait.keys));
        let restart = super::restart_confirm::restart_advice(
            true,
            wait.start_refusal.as_deref(),
            state.config_path.as_deref(),
        );
        block.extend(restart.unwrap_or_default());
    }
    Value::Object(block)
}

/// The handler.
pub(super) async fn gateway_status(
    State(state): State<Arc<AppState>>,
    guard: Guard,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let reloads = state
        .meta_mcp
        .reload_context()
        .map(|context| context.reload_tally().snapshot())
        .unwrap_or_default();
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": state.process.started_at(),
        "uptime_secs": state.process.uptime_secs(),
        "environment": environment_block(&state),
        "reloads": reloads,
        "tls": tls_block(&state),
        "upgrade": upgrade_block(state.process.upgrade()),
        "clients": state.multiplexer.client_roster(),
        "refused_at_start": state.process.refused_at_start(),
        "pending_restart": pending_restart_block(&state),
    }))
    .into_response()
}

#[cfg(tp3)]
#[cfg(test)]
#[path = "gateway_status_tests.rs"]
mod tests;
