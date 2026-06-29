//! Privacy-preserving active-user telemetry.
//!
//! Sends a minimal heartbeat payload to the MIK-6565 shared collector for
//! adoption and aggregate geography tracking. The client never collects or
//! transmits a raw IP address — geography is derived server-side in aggregate.
//!
//! Every common opt-out mechanism is honoured, the send is failure-open
//! (errors are swallowed), and the change adds zero new crate dependencies.

use serde::Serialize;
use std::path::PathBuf;
use tracing::warn;

// ── Default collector URL (MIK-6565 shared collector, project `mcp-gateway`) ──

/// Default collector endpoint, overridable via `MCP_GATEWAY_TELEMETRY_URL`.
pub const DEFAULT_TELEMETRY_URL: &str = "https://telemetry.mcp-gateway.com/api/v1/collect";

/// Environment variable that overrides the collector URL.
pub const TELEMETRY_URL_ENV: &str = "MCP_GATEWAY_TELEMETRY_URL";

// ── Heartbeat payload ─────────────────────────────────────────────────────────

/// Minimal heartbeat payload (≤ 2 KB).
///
/// Contains only `project`, `event`, `version`, `runtime`, and optional
/// `install_id`. Never includes an IP address, hostname, path, or internal
/// field.
#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatPayload {
    /// Project identifier — always `"mcp-gateway"`.
    pub project: String,
    /// Event type — always `"heartbeat"`.
    pub event: String,
    /// Crate version from `CARGO_PKG_VERSION`.
    pub version: String,
    /// Runtime identifier — always `"rust"`.
    pub runtime: String,
    /// Per-install random UUID v4. Omitted when the install-id file cannot be
    /// read or created (failure-open).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_id: Option<String>,
}

// ── File paths ────────────────────────────────────────────────────────────────

/// Return the gateway data directory (`~/.mcp-gateway/` or
/// `$MCP_GATEWAY_CONFIG_DIR`).
fn gateway_data_dir() -> PathBuf {
    std::env::var("MCP_GATEWAY_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".mcp-gateway")
        })
}

/// Telemetry state directory: `~/.mcp-gateway/telemetry/`.
fn telemetry_dir() -> PathBuf {
    gateway_data_dir().join("telemetry")
}

/// Path to the per-install random UUID file.
fn install_id_path() -> PathBuf {
    telemetry_dir().join("install_id")
}

/// Path to the last-heartbeat date file (stores `YYYY-MM-DD`).
fn last_heartbeat_path() -> PathBuf {
    telemetry_dir().join("last_heartbeat")
}

// ── Install ID ────────────────────────────────────────────────────────────────

/// Read or create the per-install random UUID v4.
///
/// Returns `None` when the directory cannot be created or the file cannot be
/// read/written — the heartbeat is still sent without an `install_id`.
fn get_or_create_install_id() -> Option<String> {
    let dir = telemetry_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(%e, "telemetry: cannot create telemetry dir");
        return None;
    }

    let path = install_id_path();
    match std::fs::read_to_string(&path) {
        Ok(id) => {
            let trimmed = id.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = uuid::Uuid::new_v4().to_string();
            if let Err(e) = std::fs::write(&path, &id) {
                warn!(%e, "telemetry: cannot write install_id");
                return None;
            }
            Some(id)
        }
        Err(e) => {
            warn!(%e, "telemetry: cannot read install_id");
            None
        }
    }
}

// ── Environment snapshot (for testability) ────────────────────────────────────

/// Snapshot of relevant environment variables.
///
/// Production code reads real env vars via `EnvSnapshot::from_env()`.
/// Tests inject overrides via `EnvSnapshot` fields.
#[derive(Debug, Clone, Default)]
pub struct EnvSnapshot {
    /// `NO_TELEMETRY` is set (any value).
    pub no_telemetry: bool,
    /// `DO_NOT_TRACK` is set (any value).
    pub do_not_track: bool,
    /// `MCP_GATEWAY_NO_TELEMETRY` is set (any value).
    pub mcp_gateway_no_telemetry: bool,
    /// `CI` is set (any value).
    pub ci: bool,
    /// `GITHUB_ACTIONS` is set (any value).
    pub github_actions: bool,
}

impl EnvSnapshot {
    /// Read the real process environment.
    pub fn from_env() -> Self {
        Self {
            no_telemetry: std::env::var("NO_TELEMETRY").is_ok(),
            do_not_track: std::env::var("DO_NOT_TRACK").is_ok(),
            mcp_gateway_no_telemetry: std::env::var("MCP_GATEWAY_NO_TELEMETRY").is_ok(),
            ci: std::env::var("CI").is_ok(),
            github_actions: std::env::var("GITHUB_ACTIONS").is_ok(),
        }
    }
}

// ── Opt-out checks ────────────────────────────────────────────────────────────

/// Return `true` when the heartbeat should be suppressed.
///
/// Checks (in order):
/// 1. Debug / test builds.
/// 2. `NO_TELEMETRY` or `DO_NOT_TRACK` or `MCP_GATEWAY_NO_TELEMETRY` env var.
/// 3. `CI` or `GITHUB_ACTIONS` env var (CI environments).
/// 4. `telemetry.enabled = false` config flag.
/// 5. Once-per-day guard: skip when `last_heartbeat` date equals today.
fn should_suppress(
    telemetry_enabled: bool,
    is_debug: bool,
    is_test: bool,
    env: &EnvSnapshot,
) -> bool {
    // 1. Debug / test builds never send telemetry.
    if is_debug || is_test {
        return true;
    }

    // 2. Universal and project-native opt-out env vars.
    if env.no_telemetry || env.do_not_track || env.mcp_gateway_no_telemetry {
        return true;
    }

    // 3. CI environments.
    if env.ci || env.github_actions {
        return true;
    }

    // 4. Config flag.
    if !telemetry_enabled {
        return true;
    }

    // 5. Once-per-day guard.
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    if let Ok(stored) = std::fs::read_to_string(last_heartbeat_path()) {
        if stored.trim() == today {
            return true;
        }
    }

    false
}

// ── Heartbeat recording ───────────────────────────────────────────────────────

/// Write today's date to `last_heartbeat` so we don't send again today.
///
/// Called **before** the HTTP request so the guard takes effect even when the
/// request times out or the collector is unreachable (privacy-preserving:
/// at-most-once-per-day under all conditions).
fn record_heartbeat_attempt() {
    let dir = telemetry_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(%e, "telemetry: cannot create telemetry dir for heartbeat stamp");
        return;
    }
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    if let Err(e) = std::fs::write(last_heartbeat_path(), &today) {
        warn!(%e, "telemetry: cannot write last_heartbeat");
    }
}

// ── HTTP send ─────────────────────────────────────────────────────────────────

/// Build the collector URL, respecting the env-var override.
fn collector_url() -> String {
    std::env::var(TELEMETRY_URL_ENV)
        .unwrap_or_else(|_| DEFAULT_TELEMETRY_URL.to_string())
}

/// Send one heartbeat POST. Failure-open: errors are swallowed.
async fn send_heartbeat(payload: &HeartbeatPayload) {
    let url = collector_url();

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(%e, "telemetry: cannot build reqwest client");
            return;
        }
    };

    match client.post(&url).json(payload).send().await {
        Ok(_resp) => {
            // Any HTTP response (including 4xx/5xx) is fine.
            // We already recorded the attempt before sending.
        }
        Err(e) => {
            // Timeout, connection error, DNS failure — all swallowed.
            warn!(%e, "telemetry: heartbeat send failed (failure-open)");
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Public entry point called from `run_server()` in `src/main.rs`.
///
/// This is the **only** call site in production. The function reads
/// `cfg!(debug_assertions)` and `cfg!(test)` at compile time; library
/// consumers that do not go through `run_server` never trigger a heartbeat.
pub async fn maybe_send_heartbeat(telemetry_enabled: bool) {
    let env = EnvSnapshot::from_env();
    maybe_send_heartbeat_inner(telemetry_enabled, cfg!(debug_assertions), cfg!(test), &env).await;
}

/// Inner implementation with explicit opt-out flags for testability.
///
/// Integration tests call this directly with `is_debug: false, is_test: false`
/// and an injected `EnvSnapshot` so `cfg!(test)` does not suppress the
/// heartbeat under test.
#[doc(hidden)]
pub async fn maybe_send_heartbeat_inner(
    telemetry_enabled: bool,
    is_debug: bool,
    is_test: bool,
    env: &EnvSnapshot,
) {
    if should_suppress(telemetry_enabled, is_debug, is_test, env) {
        return;
    }

    let payload = HeartbeatPayload {
        project: "mcp-gateway".to_string(),
        event: "heartbeat".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        runtime: "rust".to_string(),
        install_id: get_or_create_install_id(),
    };

    // Record the attempt BEFORE sending so the once-per-day guard works even
    // when the collector is unreachable.
    record_heartbeat_attempt();

    send_heartbeat(&payload).await;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_serializes_with_only_allowed_keys() {
        let payload = HeartbeatPayload {
            project: "mcp-gateway".to_string(),
            event: "heartbeat".to_string(),
            version: "2.19.0".to_string(),
            runtime: "rust".to_string(),
            install_id: Some("test-uuid".to_string()),
        };

        let json = serde_json::to_value(&payload).unwrap();
        let obj = json.as_object().unwrap();

        // Allowed keys only.
        let allowed: std::collections::HashSet<&str> = [
            "project", "event", "version", "runtime", "install_id",
        ]
        .iter()
        .copied()
        .collect();

        for key in obj.keys() {
            assert!(
                allowed.contains(key.as_str()),
                "disallowed key in payload: {key}"
            );
        }

        // "ip" must not be present.
        assert!(!obj.contains_key("ip"), "payload must not contain 'ip'");

        // install_id is optional — omit it.
        let payload_no_id = HeartbeatPayload {
            project: "mcp-gateway".to_string(),
            event: "heartbeat".to_string(),
            version: "2.19.0".to_string(),
            runtime: "rust".to_string(),
            install_id: None,
        };
        let json_no_id = serde_json::to_value(&payload_no_id).unwrap();
        let obj_no_id = json_no_id.as_object().unwrap();
        assert!(!obj_no_id.contains_key("install_id"));
    }

    #[test]
    fn payload_under_2kb() {
        let payload = HeartbeatPayload {
            project: "mcp-gateway".to_string(),
            event: "heartbeat".to_string(),
            version: "2.19.0".to_string(),
            runtime: "rust".to_string(),
            install_id: Some(uuid::Uuid::new_v4().to_string()),
        };

        let bytes = serde_json::to_vec(&payload).unwrap();
        assert!(
            bytes.len() <= 2048,
            "payload is {} bytes, must be <= 2048",
            bytes.len()
        );
    }

    fn env_snapshot(values: &[(&str, bool)]) -> EnvSnapshot {
        let mut snap = EnvSnapshot::default();
        for (key, val) in values {
            match *key {
                "NO_TELEMETRY" => snap.no_telemetry = *val,
                "DO_NOT_TRACK" => snap.do_not_track = *val,
                "MCP_GATEWAY_NO_TELEMETRY" => snap.mcp_gateway_no_telemetry = *val,
                "CI" => snap.ci = *val,
                "GITHUB_ACTIONS" => snap.github_actions = *val,
                _ => {}
            }
        }
        snap
    }

    #[test]
    fn suppress_on_no_telemetry_env() {
        let env = env_snapshot(&[("NO_TELEMETRY", true)]);
        assert!(should_suppress(true, false, false, &env));
    }

    #[test]
    fn suppress_on_do_not_track_env() {
        let env = env_snapshot(&[("DO_NOT_TRACK", true)]);
        assert!(should_suppress(true, false, false, &env));
    }

    #[test]
    fn suppress_on_project_native_env() {
        let env = env_snapshot(&[("MCP_GATEWAY_NO_TELEMETRY", true)]);
        assert!(should_suppress(true, false, false, &env));
    }

    #[test]
    fn suppress_when_telemetry_config_disabled() {
        let env = EnvSnapshot::default();
        assert!(should_suppress(false, false, false, &env));
    }

    #[test]
    fn suppress_in_ci() {
        let env = env_snapshot(&[("CI", true)]);
        assert!(should_suppress(true, false, false, &env));
    }

    #[test]
    fn suppress_in_github_actions() {
        let env = env_snapshot(&[("GITHUB_ACTIONS", true)]);
        assert!(should_suppress(true, false, false, &env));
    }

    #[test]
    fn suppress_in_debug_build() {
        let env = EnvSnapshot::default();
        assert!(should_suppress(true, true, false, &env));
    }

    #[test]
    fn suppress_in_test_build() {
        let env = EnvSnapshot::default();
        assert!(should_suppress(true, false, true, &env));
    }

    #[test]
    #[allow(unsafe_code)]
    fn not_suppressed_in_release_without_opt_outs() {
        // Use a temp dir so a real ~/.mcp-gateway/telemetry/last_heartbeat
        // doesn't interfere with this test.
        let dir = tempfile::TempDir::new().unwrap();
        // SAFETY: single-threaded test context
        unsafe { std::env::set_var("MCP_GATEWAY_CONFIG_DIR", dir.path()); }
        let env = EnvSnapshot::default();
        assert!(!should_suppress(true, false, false, &env));
    }
}
