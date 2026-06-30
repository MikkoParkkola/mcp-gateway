//! Privacy-preserving active-user telemetry (MIK-6573).
//!
//! Sends a daily heartbeat to the MIK-6565 collector so adoption and aggregate
//! geography can be tracked without betraying open-source trust. The client
//! sends a minimal payload, never an IP, honours every common opt-out, and is
//! failure-open and dependency-free (uses only existing crate dependencies).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::warn;

/// Default collector URL for the MIK-6565 shared public collector.
/// Overridable via the `MCP_GATEWAY_TELEMETRY_URL` environment variable.
pub const DEFAULT_TELEMETRY_URL: &str =
    "https://telemetry.mik.services/collect/mcp-gateway";

/// Environment variable that overrides the default collector URL.
pub const TELEMETRY_URL_ENV: &str = "MCP_GATEWAY_TELEMETRY_URL";

/// Maximum timeout for the heartbeat HTTP request (seconds).
const REQUEST_TIMEOUT_SECS: u64 = 3;

// ── State-directory helpers ────────────────────────────────────────────────────

/// Returns the telemetry state directory: `~/.mcp-gateway/telemetry/`
/// (or `$MCP_GATEWAY_CONFIG_DIR/telemetry/` when set).
fn telemetry_state_dir() -> PathBuf {
    let base = std::env::var("MCP_GATEWAY_CONFIG_DIR").map_or_else(
        |_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".mcp-gateway")
        },
        PathBuf::from,
    );
    base.join("telemetry")
}

/// Loads the persisted `install_id` (uuid v4) or generates and persists a new one.
/// Returns `None` only on unrecoverable I/O errors.
fn load_or_create_install_id(state_dir: &Path) -> Option<String> {
    let id_path = state_dir.join("install_id");
    if let Ok(id) = std::fs::read_to_string(&id_path) {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    if std::fs::create_dir_all(state_dir).is_ok() {
        let _ = std::fs::write(&id_path, &id);
    }
    Some(id)
}

/// Reads the stored `last_heartbeat` date (`YYYY-MM-DD`). Returns `None` if missing.
fn read_last_heartbeat(state_dir: &Path) -> Option<String> {
    std::fs::read_to_string(state_dir.join("last_heartbeat"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Persists today's UTC date as the `last_heartbeat` marker.
fn write_last_heartbeat(state_dir: &Path) {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    if std::fs::create_dir_all(state_dir).is_ok() {
        let _ = std::fs::write(state_dir.join("last_heartbeat"), today);
    }
}

/// Returns `true` when the stored date equals today (UTC) — heartbeat already sent.
fn already_sent_today(state_dir: &Path) -> bool {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    read_last_heartbeat(state_dir).as_deref() == Some(today.as_str())
}

// ── Opt-out logic ──────────────────────────────────────────────────────────────

/// Returns `true` when telemetry should be suppressed.
///
/// Suppression triggers (any one is sufficient):
/// - Environment variables: `NO_TELEMETRY`, `DO_NOT_TRACK`, `MCP_GATEWAY_NO_TELEMETRY`
/// - CI environment: `CI`, `GITHUB_ACTIONS`
/// - Config: `telemetry.enabled = false`
/// - Debug/test builds: `cfg!(debug_assertions)`
fn is_opted_out(config: &crate::config::Config, skip_ci_checks: bool) -> bool {
    if cfg!(debug_assertions) {
        return true;
    }
    if !config.telemetry.enabled {
        return true;
    }
    for var in ["NO_TELEMETRY", "DO_NOT_TRACK", "MCP_GATEWAY_NO_TELEMETRY"] {
        if std::env::var(var).is_ok() {
            return true;
        }
    }
    if !skip_ci_checks {
        for var in ["CI", "GITHUB_ACTIONS"] {
            if std::env::var(var).is_ok() {
                return true;
            }
        }
    }
    false
}

// ── Payload ────────────────────────────────────────────────────────────────────

/// Heartbeat payload sent to the MIK-6565 collector.
/// Keys are strictly limited to: project, event, version, runtime, install_id.
/// No IP, host, path, or any other identifying field is ever included.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct HeartbeatPayload {
    project: String,
    event: String,
    version: String,
    runtime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    install_id: Option<String>,
}

/// Builds the heartbeat payload.
fn build_payload(install_id: Option<String>) -> HeartbeatPayload {
    HeartbeatPayload {
        project: "mcp-gateway".to_string(),
        event: "heartbeat".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        runtime: "rust".to_string(),
        install_id,
    }
}

// ── Public entry-point (fire-and-forget) ───────────────────────────────────────

/// Fire-and-forget heartbeat. Performs all opt-out and date-guard checks
/// synchronously, then spawns a background tokio task for the HTTP send.
/// Never blocks the caller and never panics.
///
/// Returns `true` when a send was initiated, `false` when skipped.
pub fn maybe_send_heartbeat(config: &crate::config::Config) -> bool {
    if is_opted_out(config, false) {
        return false;
    }

    let state_dir = telemetry_state_dir();
    if already_sent_today(&state_dir) {
        return false;
    }

    let url = std::env::var(TELEMETRY_URL_ENV)
        .unwrap_or_else(|_| DEFAULT_TELEMETRY_URL.to_string());

    let install_id = load_or_create_install_id(&state_dir);
    let payload = build_payload(install_id);

    tokio::spawn(async move {
        let _ = send_http(&url, &payload).await;
        write_last_heartbeat(&state_dir);
    });

    true
}

// ── Test-only entry-point ──────────────────────────────────────────────────────

/// Internal heartbeat implementation used by integration tests.
/// Allows overriding the collector URL, state directory, and bypassing
/// the debug-build and CI opt-out guards so tests can exercise the
/// full send path.
///
/// Returns `true` when the HTTP send completed, `false` when skipped.
#[doc(hidden)]
pub async fn send_heartbeat_internal(
    url_override: &str,
    state_dir: &Path,
    config: &crate::config::Config,
    skip_opt_out: bool,
    skip_ci_checks: bool,
) -> bool {
    if !skip_opt_out && is_opted_out(config, skip_ci_checks) {
        return false;
    }

    if already_sent_today(state_dir) {
        return false;
    }

    let install_id = load_or_create_install_id(state_dir);
    let payload = build_payload(install_id);

    match send_http(url_override, &payload).await {
        Ok(()) => {
            write_last_heartbeat(state_dir);
            true
        }
        Err(e) => {
            warn!(error = %e, "telemetry heartbeat failed (failure-open)");
            false
        }
    }
}

// ── HTTP send ──────────────────────────────────────────────────────────────────

async fn send_http(url: &str, payload: &HeartbeatPayload) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("build client: {e}"))?;

    let resp = client
        .post(url)
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("send: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    Ok(())
}
