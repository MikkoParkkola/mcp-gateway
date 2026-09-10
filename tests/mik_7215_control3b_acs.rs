// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7215.CONTROL.3b — a real client's `params._meta` must reach the
//! correlation key, through the router, not through a hand-composed call.
//!
//! The unit cases at `src/gateway/router/tests.rs` drive
//! `extract_tools_call_params` and `merge_client_meta` in the handler's own
//! order, and `src/gateway/meta_mcp/trace_correlation_tests.rs` drives
//! `invoke_tool` with an already-merged `_meta`. Neither carries a client's
//! `params._meta` through `handle_request`, so both stayed green while the
//! wiring that joins them was absent: `extract_tools_call_params`
//! (`src/gateway/router/helpers.rs:206`) returns the arguments object alone
//! and drops `params._meta`, and the merge that puts it back is a separate
//! call at `src/gateway/router/handlers.rs:1185`.
//!
//! These cases start at the wire — one `POST /mcp` carrying
//! `params._meta.traceparent` exactly as a client sends it — and end at the
//! transparency log's `correlation_source`, which is the field the criterion
//! is about. Nothing between the two is constructed by the test.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, Config, FailsafeConfig, TransportConfig};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{
    ToolPolicy, ToolPolicyConfig, TransparencyLogConfig, TransparencyLogger,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The backend and tool every case here invokes.
const BACKEND: &str = "backend";
const TOOL: &str = "tool";

/// A syntactically valid W3C `traceparent` — `version-traceid-spanid-flags`,
/// all lower-hex, trace id not all-zero, which is what
/// `TraceContext::from_meta` (`src/protocol/trace.rs:131`) requires.
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

/// One gateway process with a real, file-backed transparency log.
///
/// The logger hangs off `MetaMcp` because that is where the invoke path reads
/// it (`src/gateway/meta_mcp/invoke.rs`); `AppState.transparency_log` serves
/// the direct-backend route, which is not this criterion's path.
fn app_state_with_log() -> (Arc<AppState>, std::path::PathBuf) {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    // Kept alive for the whole test; reclaimed at process exit.
    std::mem::forget(file);
    let logger = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().to_string(),
            key_id: "test".to_string(),
            shared_secret: String::new(),
        }))
        .expect("the transparency logger must open"),
    );

    let mut meta = MetaMcp::new(Arc::clone(&backends));
    meta.enable_transparency_log(logger);
    let meta_mcp = Arc::new(meta);
    let continuation = meta_mcp.continuation();

    let state = Arc::new(AppState {
        session_lifecycle: None,
        env: None,
        meta_mcp,
        backends,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
        key_server: None,
        tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(100)),
        agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks: Arc::new(mcp_gateway::protocol::task_store::TaskStore::new()),
        subscriptions: Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
        continuation,
    });
    (state, path)
}

/// A loopback MCP server: enough protocol surface to be dispatched to.
async fn spawn_fixture_backend() -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(request): axum::Json<Value>| async move {
            axum::Json(fixture_answer(&request))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture backend must bind a loopback port");
    let address = listener.local_addr().expect("the bound port must be known");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/")
}

fn fixture_answer(request: &Value) -> Value {
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fixture", "version": "0" }
        }),
        Some("tools/list") => json!({
            "tools": [ { "name": TOOL, "description": "d", "inputSchema": { "type": "object" } } ]
        }),
        Some("tools/call") => json!({ "content": [ { "type": "text", "text": "ok" } ] }),
        _ => json!({}),
    };
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": result
    })
}

fn register_fixture_backend(state: &Arc<AppState>, url: &str) {
    let config = BackendConfig {
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let backend = Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    assert!(
        state.backends.register(Arc::new(backend)),
        "the fixture backend must register under a name nothing else holds"
    );
}

/// A client's own `tools/call` frame: `_meta` sits beside `name` and
/// `arguments` in `params`, which is where the specification puts it and the
/// only place a client can put it.
fn call_body(meta: Value) -> Value {
    // The envelope keys every modern frame carries, merged under whatever the
    // case adds. Without them `classify_and_observe` refuses the request as
    // `Malformed` (`src/gateway/router/handlers.rs:809`) and the control this
    // criterion names never runs — a frame carrying ONE namespaced key and not
    // the rest is the malformed shape, not a minimal one. Omitting them
    // entirely is worse than failing: the frame classifies legacy, so the test
    // passes while exercising the path the criterion is not about.
    let mut meta = meta;
    meta["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
    meta["io.modelcontextprotocol/clientCapabilities"] = json!({});
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "_meta": meta,
            "arguments": { "server": BACKEND, "tool": TOOL, "arguments": {} }
        }
    })
}

async fn post(state: &Arc<AppState>, body: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        // A modern frame mirrors its declaration into the headers an upstream
        // routes on. Omitting them is refused (-32020) before the control under
        // test runs, so these are part of the frame, not decoration.
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(Body::from(serde_json::to_vec(body).expect("body")))
        .expect("request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The invocation entries the log holds for the fixture backend.
///
/// Parsed, never substring-matched: a trace id that appears anywhere in the
/// line (in `request_hash`, say) would satisfy a `contains` check without
/// being the correlation key, which is the only thing this criterion is about.
fn invocation_entries(path: &std::path::Path) -> Vec<Value> {
    let raw = std::fs::read_to_string(path).expect("read log");
    raw.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry.get("server").and_then(Value::as_str) == Some(BACKEND))
        .collect()
}

/// `MIK-7215.CONTROL.3b` — GIVEN a client that sends `traceparent` in the
/// `params._meta` of its `tools/call`, WHEN the request goes through the
/// router's own request path, THEN the transparency log's correlation key is
/// that trace id and the entry names `otel_trace_id` as its source.
#[tokio::test]
async fn ac_control_3b_client_params_meta_trace_id_is_the_correlation_key() {
    let (state, log_path) = app_state_with_log();
    let url = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (status, response) = post(&state, &call_body(json!({ "traceparent": TRACEPARENT }))).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the call must be answered: {response}"
    );
    assert!(
        response.get("error").is_none(),
        "the invocation must succeed — a refused call writes no log entry at all, \
         so an assertion about the key would pass on an empty log: {response}"
    );

    let entries = invocation_entries(&log_path);
    assert_eq!(
        entries.len(),
        1,
        "exactly one invocation of the fixture backend must be logged: {entries:?}"
    );
    let entry = &entries[0];
    assert_eq!(
        entry.get("correlation_source").and_then(Value::as_str),
        Some("otel_trace_id"),
        "the client's own `params._meta` trace id must be the key's source: {entry}"
    );
    assert_eq!(
        entry.get("session_id").and_then(Value::as_str),
        Some(TRACE_ID),
        "the correlation key must be the trace id the client sent: {entry}"
    );
}

/// Control, not a criterion: the same wire path with a `params._meta` that
/// carries no `traceparent` must NOT report an `OTel` key.
///
/// Without it, an implementation that stamped `otel_trace_id` unconditionally —
/// or one that read a trace id from anywhere but the client's `_meta` — would
/// pass the case above.
#[tokio::test]
async fn control_params_meta_without_traceparent_yields_no_otel_key() {
    let (state, log_path) = app_state_with_log();
    let url = spawn_fixture_backend().await;
    register_fixture_backend(&state, &url);

    let (status, response) = post(
        &state,
        &call_body(
            json!({ "io.modelcontextprotocol/clientInfo": { "name": "c", "version": "0" } }),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the call must be answered: {response}"
    );
    assert!(
        response.get("error").is_none(),
        "the invocation must succeed: {response}"
    );

    let entries = invocation_entries(&log_path);
    assert_eq!(
        entries.len(),
        1,
        "one invocation must be logged: {entries:?}"
    );
    let entry = &entries[0];
    assert_ne!(
        entry.get("correlation_source").and_then(Value::as_str),
        Some("otel_trace_id"),
        "no trace id was sent, so nothing may claim an OTel key: {entry}"
    );
    assert_ne!(
        entry.get("session_id").and_then(Value::as_str),
        Some(TRACE_ID),
        "the trace id from the other case must not leak into this one: {entry}"
    );
}
