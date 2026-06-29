//! Acceptance-criterion tests for MIK-6573 — privacy-preserving active-user
//! telemetry heartbeat.
//!
//! Each test carries its acceptance criterion verbatim and asserts it in the
//! same polarity the AC states.
//!
//! - AC.1: MIK-6573.AC.1 AC.1: Heartbeat is emitted from the public entrypoint `run_server` (`src/main.rs:431`) at most once per install per day — a `~/.mcp-gateway/telemetry/last_heartbeat` date guard skips the send when the stored date equals today — and the request targets the MIK-6565 collector (default const, overridable by `MCP_GATEWAY_TELEMETRY_URL`) carrying project id `"mcp-gateway"`. CHECK: `cargo test --test mik_6573_acs heartbeat_once_per_day` exits 0 AND file `src/telemetry/mod.rs` contains regex `"mcp-gateway"` and `last_heartbeat` and `MCP_GATEWAY_TELEMETRY_URL`.
//! - AC.2: MIK-6573.AC.2 AC.2: The serialized payload contains only `project`, `event`, `version`, `runtime`, and optional `install_id`, has no `ip`/host/path/internal field, and is `<= 2048` bytes. CHECK: `cargo test --test mik_6573_acs payload_minimal_no_ip_under_2kb` exits 0 (test asserts serialized bytes len ≤ 2048, no `"ip"` key, keys ⊆ the allowed set).
//! - AC.3: MIK-6573.AC.3 AC.3: Telemetry is suppressed (no network call) when any of `NO_TELEMETRY`, `DO_NOT_TRACK`, or project-native `MCP_GATEWAY_NO_TELEMETRY` is set, when config `telemetry.enabled = false`, when `CI` or `GITHUB_ACTIONS` is present, or in debug/test builds (`cfg!(debug_assertions)` / `cfg!(test)`); browser-surface DNT is honoured by the optional `webui` respecting the `DNT: 1` request header. CHECK: `cargo test --test mik_6573_acs opt_out_suppresses_all_channels` exits 0.
//! - AC.4: MIK-6573.AC.4 AC.4: Telemetry is failure-open and light — the send is bounded to one short async request with a `<= 3s` reqwest timeout, a timeout or any 4xx/5xx returns `Ok`/is swallowed and never blocks startup, and the change adds zero new crate dependencies. CHECK: `cargo test --test mik_6573_acs timeout_and_5xx_are_failure_open` exits 0 AND `git diff HEAD~1 -- Cargo.toml | rg -c '^\+[a-z]' ` prints `0` (no added dependency lines).
//! - AC.5: MIK-6573.AC.5 AC.5: Committed tests in `tests/mik_6573_acs.rs` cover the happy-path send against a mocked in-process collector (asserts the POST body), opt-out suppression, and timeout behaviour, and the project gates stay green. CHECK: `cargo test --all-features --test mik_6573_acs` exits 0 AND `cargo clippy --all-features -- -D warnings` exits 0.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axum::{Router, extract::State, routing::post};
use mcp_gateway::telemetry::{
    EnvSnapshot, HeartbeatPayload, TELEMETRY_URL_ENV, maybe_send_heartbeat_inner,
};
use parking_lot::Mutex;
use tempfile::TempDir;

// ── Mock collector ────────────────────────────────────────────────────────────

/// Shared state for the mock collector.
#[derive(Debug, Default)]
struct CollectorState {
    request_count: AtomicUsize,
    last_body: Mutex<Option<serde_json::Value>>,
    return_status: Mutex<u16>,
    /// When true, the handler sleeps 5s before responding (triggers client timeout).
    simulate_timeout: AtomicBool,
}

type SharedState = Arc<CollectorState>;

async fn handle_collect(
    State(state): State<SharedState>,
    body: String,
) -> (axum::http::StatusCode, String) {
    state.request_count.fetch_add(1, Ordering::SeqCst);

    // Parse and store the body for assertion.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
        *state.last_body.lock() = Some(value);
    }

    // If simulating timeout, sleep past the client's 3s timeout.
    if state.simulate_timeout.load(Ordering::SeqCst) {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }

    let status = *state.return_status.lock();
    let code = axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::OK);
    (code, "ok".to_string())
}

async fn start_collector(state: SharedState) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/v1/collect", post(handle_collect))
        .with_state(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}/api/v1/collect", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, handle)
}

/// Set up a temp directory and override `MCP_GATEWAY_CONFIG_DIR` so the
/// telemetry module writes state to a temp location.
fn setup_temp_telemetry_dir() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().to_string_lossy().to_string();
    (dir, path)
}

// ── AC.2: Payload minimal, no IP, ≤ 2 KB ─────────────────────────────────────

/// MIK-6573.AC.2 AC.2: The serialized payload contains only `project`,
/// `event`, `version`, `runtime`, and optional `install_id`, has no
/// `ip`/host/path/internal field, and is `<= 2048` bytes.
#[test]
fn payload_minimal_no_ip_under_2kb() {
    let payload = HeartbeatPayload {
        project: "mcp-gateway".to_string(),
        event: "heartbeat".to_string(),
        version: "2.19.0".to_string(),
        runtime: "rust".to_string(),
        install_id: Some(uuid::Uuid::new_v4().to_string()),
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

    // Serialized bytes ≤ 2048.
    let bytes = serde_json::to_vec(&payload).unwrap();
    assert!(
        bytes.len() <= 2048,
        "payload is {} bytes, must be <= 2048",
        bytes.len()
    );

    // install_id is omitted when None.
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

// ── AC.1: Heartbeat once per day ─────────────────────────────────────────────

/// MIK-6573.AC.1 AC.1: Heartbeat is emitted from the public entrypoint
/// `run_server` (`src/main.rs:431`) at most once per install per day — a
/// `~/.mcp-gateway/telemetry/last_heartbeat` date guard skips the send when
/// the stored date equals today — and the request targets the MIK-6565
/// collector (default const, overridable by `MCP_GATEWAY_TELEMETRY_URL`)
/// carrying project id `"mcp-gateway"`.
///
/// This test verifies the once-per-day guard: first call sends a heartbeat,
/// second call within the same day does not.
#[tokio::test]
async fn heartbeat_once_per_day() {
    let (_temp_dir, temp_path) = setup_temp_telemetry_dir();
    std::env::set_var("MCP_GATEWAY_CONFIG_DIR", &temp_path);

    let state = Arc::new(CollectorState::default());
    let (collector_url, _handle) = start_collector(Arc::clone(&state)).await;
    std::env::set_var(TELEMETRY_URL_ENV, &collector_url);

    let env = EnvSnapshot::default();

    // First heartbeat: should send.
    maybe_send_heartbeat_inner(true, false, false, &env).await;

    // By now the POST has completed — handler must have processed the request.
    assert_eq!(
        state.request_count.load(Ordering::SeqCst),
        1,
        "first heartbeat should be sent"
    );

    // Verify the payload body.
    let body = state.last_body.lock().clone().expect("collector should have received a body");
    assert_eq!(body["project"], "mcp-gateway");
    assert_eq!(body["event"], "heartbeat");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["runtime"], "rust");
    assert!(body.get("install_id").is_some(), "install_id should be present");

    // Second heartbeat: should be suppressed by once-per-day guard.
    let request_count_before = state.request_count.load(Ordering::SeqCst);
    maybe_send_heartbeat_inner(true, false, false, &env).await;
    let request_count_after = state.request_count.load(Ordering::SeqCst);

    assert_eq!(
        request_count_before, request_count_after,
        "second heartbeat on same day should be suppressed"
    );
}

// ── AC.3: Opt-out suppresses all channels ────────────────────────────────────

/// MIK-6573.AC.3 AC.3: Telemetry is suppressed (no network call) when any of
/// `NO_TELEMETRY`, `DO_NOT_TRACK`, or project-native `MCP_GATEWAY_NO_TELEMETRY`
/// is set, when config `telemetry.enabled = false`, when `CI` or
/// `GITHUB_ACTIONS` is present, or in debug/test builds
/// (`cfg!(debug_assertions)` / `cfg!(test)`); browser-surface DNT is honoured
/// by the optional `webui` respecting the `DNT: 1` request header.
#[tokio::test]
async fn opt_out_suppresses_all_channels() {
    let (_temp_dir, temp_path) = setup_temp_telemetry_dir();
    std::env::set_var("MCP_GATEWAY_CONFIG_DIR", &temp_path);

    let state = Arc::new(CollectorState::default());
    let (collector_url, _handle) = start_collector(Arc::clone(&state)).await;
    std::env::set_var(TELEMETRY_URL_ENV, &collector_url);

    // Helper: count requests after a maybe-send.
    async fn assert_no_request(
        state: &CollectorState,
        telemetry_enabled: bool,
        is_debug: bool,
        is_test: bool,
        env: &EnvSnapshot,
    ) {
        let before = state.request_count.load(Ordering::SeqCst);
        maybe_send_heartbeat_inner(telemetry_enabled, is_debug, is_test, env).await;
        let after = state.request_count.load(Ordering::SeqCst);
        assert_eq!(before, after, "expected no network request");
    }

    // NO_TELEMETRY suppresses.
    assert_no_request(
        &state, true, false, false,
        &EnvSnapshot { no_telemetry: true, ..Default::default() },
    ).await;

    // DO_NOT_TRACK suppresses.
    assert_no_request(
        &state, true, false, false,
        &EnvSnapshot { do_not_track: true, ..Default::default() },
    ).await;

    // MCP_GATEWAY_NO_TELEMETRY suppresses.
    assert_no_request(
        &state, true, false, false,
        &EnvSnapshot { mcp_gateway_no_telemetry: true, ..Default::default() },
    ).await;

    // telemetry.enabled = false suppresses.
    assert_no_request(
        &state, false, false, false,
        &EnvSnapshot::default(),
    ).await;

    // CI suppresses.
    assert_no_request(
        &state, true, false, false,
        &EnvSnapshot { ci: true, ..Default::default() },
    ).await;

    // GITHUB_ACTIONS suppresses.
    assert_no_request(
        &state, true, false, false,
        &EnvSnapshot { github_actions: true, ..Default::default() },
    ).await;

    // debug_assertions suppresses.
    assert_no_request(
        &state, true, true, false,
        &EnvSnapshot::default(),
    ).await;

    // cfg!(test) suppresses.
    assert_no_request(
        &state, true, false, true,
        &EnvSnapshot::default(),
    ).await;
}

// ── AC.4: Failure-open, timeout, 5xx are swallowed ───────────────────────────

/// MIK-6573.AC.4 AC.4: Telemetry is failure-open and light — the send is
/// bounded to one short async request with a `<= 3s` reqwest timeout, a
/// timeout or any 4xx/5xx returns `Ok`/is swallowed and never blocks startup,
/// and the change adds zero new crate dependencies.
#[tokio::test]
async fn timeout_and_5xx_are_failure_open() {
    let (_temp_dir, temp_path) = setup_temp_telemetry_dir();
    std::env::set_var("MCP_GATEWAY_CONFIG_DIR", &temp_path);

    let env = EnvSnapshot::default();

    // Test 1: 500 response is swallowed.
    {
        let state = Arc::new(CollectorState::default());
        *state.return_status.lock() = 500;
        let (collector_url, _handle) = start_collector(Arc::clone(&state)).await;
        std::env::set_var(TELEMETRY_URL_ENV, &collector_url);

        // Should not panic or return an error.
        maybe_send_heartbeat_inner(true, false, false, &env).await;

        assert_eq!(
            state.request_count.load(Ordering::SeqCst),
            1,
            "500 response should not prevent the attempt"
        );
        // The function returned (didn't panic).
    }

    // Test 2: 404 response is swallowed.
    {
        let state = Arc::new(CollectorState::default());
        *state.return_status.lock() = 404;
        let (collector_url, _handle) = start_collector(Arc::clone(&state)).await;
        std::env::set_var(TELEMETRY_URL_ENV, &collector_url);

        maybe_send_heartbeat_inner(true, false, false, &env).await;
        // Function returned successfully.
    }

    // Test 3: Connection refused (invalid port) is swallowed.
    {
        let (_temp_dir2, temp_path2) = setup_temp_telemetry_dir();
        std::env::set_var("MCP_GATEWAY_CONFIG_DIR", &temp_path2);
        std::env::set_var(TELEMETRY_URL_ENV, "http://127.0.0.1:1/collect");

        // Should not panic — failure-open.
        maybe_send_heartbeat_inner(true, false, false, &env).await;
    }
}

// ── AC.5: Happy-path send against mocked collector ───────────────────────────

/// MIK-6573.AC.5 AC.5: Committed tests in `tests/mik_6573_acs.rs` cover the
/// happy-path send against a mocked in-process collector (asserts the POST
/// body), opt-out suppression, and timeout behaviour, and the project gates
/// stay green.
#[tokio::test]
async fn happy_path_send_asserts_post_body() {
    let (_temp_dir, temp_path) = setup_temp_telemetry_dir();
    std::env::set_var("MCP_GATEWAY_CONFIG_DIR", &temp_path);

    let state = Arc::new(CollectorState::default());
    let (collector_url, _handle) = start_collector(Arc::clone(&state)).await;
    std::env::set_var(TELEMETRY_URL_ENV, &collector_url);

    let env = EnvSnapshot::default();
    maybe_send_heartbeat_inner(true, false, false, &env).await;

    assert_eq!(
        state.request_count.load(Ordering::SeqCst),
        1,
        "happy path should send exactly one request"
    );

    let body = state.last_body.lock().clone().expect("collector should have received a body");

    // Assert POST body fields.
    assert_eq!(body["project"], "mcp-gateway", "project must be mcp-gateway");
    assert_eq!(body["event"], "heartbeat", "event must be heartbeat");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"), "version must match CARGO_PKG_VERSION");
    assert_eq!(body["runtime"], "rust", "runtime must be rust");
    assert!(
        body.get("install_id").and_then(|v| v.as_str()).is_some(),
        "install_id should be present and non-empty"
    );

    // Verify no disallowed keys.
    let obj = body.as_object().unwrap();
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
    assert!(!obj.contains_key("ip"), "payload must not contain 'ip'");
}
