// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! NFR.OBS.5 — modern-protocol serving sits behind a flag, defaults off, and
//! reverting it costs a legacy peer nothing.
//!
//! Every assertion here goes through the router. Reading
//! `config.server.modern_protocol` back would prove the field exists, not that
//! anything serves differently because of it, so each case asserts the wire
//! difference instead: the status and the `supportedVersions` payload the
//! refusal carries. That payload is the fingerprint — `unsupported_version_error`
//! (`src/gateway/router/handlers.rs:172-188`) emits an EMPTY list exactly when
//! the flag is off, so a refusal from some earlier gate cannot be mistaken for
//! this one.
//!
//! Revert is modelled as a restart, not a live mutation, because the gateway
//! has no runtime mutator for the flag the handlers read: `LiveConfig::set`
//! (`src/config_reload/mod.rs:296`) writes the `inner` field, while
//! `LiveConfig::running` (`:268`) returns the separate `running` field seeded
//! once at `new` and documented as "what the running process actually applied,
//! fixed at startup" (`:243-253`). Every handler reads
//! `live_config.running().server.modern_protocol`, so `set` cannot move it. The
//! gateway says so itself: `pending_restart_fields` (`:545-557`) declares the
//! whole `server` section — `modern_protocol` included — restart-required.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// The revision this criterion is about.
const MODERN: &str = "2026-07-28";
/// The revision a legacy peer speaks, and must keep speaking across the flip.
const LEGACY: &str = "2025-06-18";
/// `src/protocol/era.rs:34`.
const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;

/// A modern request frame: the revision removed the handshake, so the frame
/// carries its own `_meta`.
fn modern_frame(method: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": method,
        "params": { "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
        }}
    })
}

/// A gateway built from `base`, differing from any other state here only in the
/// flag under test. Passing the whole `Config` is what makes the revert case a
/// revert: both sides come from one configuration.
fn state(base: &Config, modern_protocol: bool) -> Arc<AppState> {
    let mut config = base.clone();
    config.server.modern_protocol = modern_protocol;
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        env: None,
        meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
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
        subscriptions: Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

async fn send(
    state: &Arc<AppState>,
    headers: &[(&str, &str)],
    body: &Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
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

/// POST as a conforming modern caller: `_meta` mirrored into the headers the
/// revision requires, so no mirrored-header check refuses ahead of the flag.
async fn post_modern(state: &Arc<AppState>, body: &Value) -> (StatusCode, Value) {
    let method = body["method"].as_str().expect("method");
    send(
        state,
        &[("mcp-protocol-version", MODERN), ("mcp-method", method)],
        body,
    )
    .await
}

/// POST as a 2025 caller: the old header, no `_meta`, no mirrored headers.
/// Sending the modern header instead would classify this frame `Malformed`
/// rather than `Legacy` and test nothing about a legacy peer.
async fn post_legacy(state: &Arc<AppState>, body: &Value) -> (StatusCode, Value) {
    send(state, &[("mcp-protocol-version", LEGACY)], body).await
}

fn legacy_initialize() -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": { "name": "LegacyClient", "version": "1.0.0" }
        }
    })
}

fn legacy_discover() -> Value {
    json!({ "jsonrpc": "2.0", "id": 2, "method": "server/discover" })
}

// ============================================================================
// 1 — DEFAULT OFF. A gateway configured with nothing but `Config::default()`
//     does not serve the modern protocol.
// ============================================================================
#[tokio::test]
async fn a_default_gateway_does_not_serve_a_modern_frame() {
    // GIVEN: a gateway whose config was never touched. `state` is handed the
    // default's own flag value, so this case reads the shipped default rather
    // than a `false` the fixture chose.
    let default_config = Config::default();
    let app = state(&default_config, default_config.server.modern_protocol);

    // WHEN: a conforming modern caller sends a frame.
    let (status, body) = post_modern(&app, &modern_frame("tools/list")).await;

    // THEN: it is refused as an unsupported version, and the refusal advertises
    // NOTHING — the empty list is what distinguishes this gate from every other
    // refusal on the path.
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["error"]["code"], UNSUPPORTED_PROTOCOL_VERSION,
        "body: {body}"
    );
    assert_eq!(
        body["error"]["data"]["supportedVersions"],
        json!([]),
        "a gateway that does not serve the modern revision must not advertise \
         it; body: {body}"
    );
}

// ============================================================================
// 2 — FLAG ON SERVES. The same frame, the same code, one field different.
// ============================================================================
#[tokio::test]
async fn the_same_modern_frame_is_served_when_the_flag_is_on() {
    // GIVEN: the same default configuration with the flag turned on.
    let app = state(&Config::default(), true);

    // WHEN: the identical frame from case 1 arrives.
    let (status, body) = post_modern(&app, &modern_frame("tools/list")).await;

    // THEN: it is served, not refused.
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(
        body.get("result").is_some(),
        "a served modern frame answers with a result; body: {body}"
    );
}

// ============================================================================
// 3 — REVERTIBLE WITHOUT A DOWNGRADE.
//
// One configuration, the flag flipped back off, and the gateway restarted onto
// it — which is what "revertible" can mean here, because the flag the handlers
// read is fixed at startup (see the module comment). No binary is rolled back,
// no version is renegotiated: that is the "without a downgrade" the criterion
// names.
// ============================================================================
#[tokio::test]
async fn reverting_the_flag_stops_modern_serving_and_costs_the_legacy_caller_nothing() {
    // GIVEN: one configuration, served with the flag on, then with it off.
    let base = Config::default();
    let before = state(&base, true);
    let after = state(&base, false);

    // AND: a legacy peer that handshook before the flip.
    let (legacy_status_before, legacy_before) = post_legacy(&before, &legacy_initialize()).await;
    assert_eq!(legacy_status_before, StatusCode::OK, "{legacy_before}");
    assert_eq!(
        legacy_before["result"]["protocolVersion"], LEGACY,
        "precondition: the legacy peer negotiated its own revision; \
         body: {legacy_before}"
    );

    // AND: modern serving was genuinely on beforehand, or "it stopped" is empty.
    let (modern_before, modern_before_body) =
        post_modern(&before, &modern_frame("tools/list")).await;
    assert_eq!(
        modern_before,
        StatusCode::OK,
        "precondition: the modern frame was served before the flip; body: {modern_before_body}"
    );

    // WHEN/THEN (a): after the revert the same frame stops being served modern,
    // with the flag's own fingerprint on the refusal.
    let (modern_after, modern_after_body) = post_modern(&after, &modern_frame("tools/list")).await;
    assert_eq!(
        modern_after,
        StatusCode::BAD_REQUEST,
        "body: {modern_after_body}"
    );
    assert_eq!(
        modern_after_body["error"]["data"]["supportedVersions"],
        json!([]),
        "body: {modern_after_body}"
    );

    // AND: the revert is visible on a path a LEGACY caller can reach, so the
    // flip is not merely the modern branch refusing itself. Discovery advertises
    // the modern revision while it is served and stops once it is not. This is
    // the flag working, not a downgrade: the legacy peer's own revision stays on
    // the list throughout.
    let (_, discover_before) = post_legacy(&before, &legacy_discover()).await;
    let (_, discover_after) = post_legacy(&after, &legacy_discover()).await;
    let advertised = |doc: &Value| -> Vec<String> {
        doc["result"]["supportedVersions"]
            .as_array()
            .expect("supportedVersions")
            .iter()
            .map(|v| v.as_str().expect("version").to_string())
            .collect()
    };
    let (listed_before, listed_after) = (advertised(&discover_before), advertised(&discover_after));
    assert!(
        listed_before.iter().any(|v| v == MODERN),
        "precondition: discovery advertised the modern revision while it was \
         served; got {listed_before:?}"
    );
    assert!(
        !listed_after.iter().any(|v| v == MODERN),
        "after the revert discovery must stop advertising a revision the \
         gateway no longer serves; got {listed_after:?}"
    );
    assert!(
        listed_after.iter().any(|v| v == LEGACY),
        "the legacy revision must survive the revert; got {listed_after:?}"
    );

    // WHEN/THEN (b): the legacy caller is served exactly as before. Not "still
    // works" — byte-identical, so no renegotiation and no changed capability
    // could hide inside a looser check.
    let (legacy_status_after, legacy_after) = post_legacy(&after, &legacy_initialize()).await;
    assert_eq!(legacy_status_after, legacy_status_before);
    assert_eq!(
        legacy_after["result"], legacy_before["result"],
        "reverting the flag must cost the legacy caller nothing; \
         before: {legacy_before} after: {legacy_after}"
    );
}
