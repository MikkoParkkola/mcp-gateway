// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! NFR.OBS.5 — the modern surface sits behind a flag (a), reverting it costs a
//! legacy peer nothing (b), it is served BY DEFAULT (c), and the gateway
//! negotiates down to the highest revision a client supports (d).
//!
//! THREE CASES IN THIS FILE FAIL TODAY, DELIBERATELY. Clause (c) needs a code
//! change this file does not contain and is not authorised to make:
//!
//!   1. `src/config/mod.rs:1229` — the struct default `modern_protocol: false`.
//!   2. `src/config/mod.rs:1181` — the FIELD-level `#[serde(default)]`, which
//!      must be DELETED. The struct already carries a container-level
//!      `#[serde(default)]` (`:1166`); the field-level one shadows it and
//!      resolves to `bool::default()` — `false` — so a config file with a
//!      `server:` section that omits the flag deserializes to `false` whatever
//!      the struct default says. That is every real deployment. Change 1 alone
//!      would turn case 1 green while an operator still got the old behaviour:
//!      a passing test over a broken criterion.
//!
//! Both are sequenced behind cluster A wiring the continuation path — default-on
//! turns every gap there into a first-run defect
//! (`docs/requirements/RELEASE-4.0.0-blocking-rollup.md:30`, operator ruling
//! 2026-09-02). Until then clause (c) is legitimately unmet and cases 1, 2 and 7
//! fail for the right reason. Red here means "not built yet", not "broken".
//!
//! | case | clause | today |
//! |---|---|---|
//! | 1 default gateway serves a modern frame | c | FAILS |
//! | 2 default gateway advertises the revision | c | FAILS |
//! | 3 flag off refuses the revision | a | passes |
//! | 4 revert stops serving, legacy unchanged | b | passes |
//! | 5 negotiation down to each supported revision | d | passes |
//! | 7 a config file omitting the flag still serves modern | c | FAILS |
//!
//! Every assertion goes through the router. Reading
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
use mcp_gateway::config::{Config, ServerConfig};
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
    post_at_version(state, LEGACY, body).await
}

/// POST as a pre-2026 caller declaring `version`. Clause (d) is about more than
/// one revision, so the revision is a parameter and not a constant.
async fn post_at_version(
    state: &Arc<AppState>,
    version: &str,
    body: &Value,
) -> (StatusCode, Value) {
    send(state, &[("mcp-protocol-version", version)], body).await
}

fn legacy_initialize() -> Value {
    initialize_at(LEGACY)
}

/// A pre-2026 handshake offering exactly `version`.
fn initialize_at(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "LegacyClient", "version": "1.0.0" }
        }
    })
}

fn legacy_discover() -> Value {
    json!({ "jsonrpc": "2.0", "id": 2, "method": "server/discover" })
}

/// The revision list `server/discover` answers with.
fn advertised(doc: &Value) -> Vec<String> {
    doc["result"]["supportedVersions"]
        .as_array()
        .expect("supportedVersions")
        .iter()
        .map(|v| v.as_str().expect("version").to_string())
        .collect()
}

// ============================================================================
// 1 — DEFAULT ON (clause c). A gateway configured with nothing but
//     `Config::default()` serves the modern revision.
//
//     `tools/list`, not `initialize`: the 2026 revision REMOVED the handshake,
//     so asserting on initialize would validate a retired path instead of the
//     live one.
//
//     FAILS until both halves of the default flip land — see the module comment.
// ============================================================================
#[tokio::test]
async fn a_default_gateway_serves_a_modern_frame() {
    // GIVEN: a gateway whose config was never touched. `state` is handed the
    // default's own flag value, so this reads the SHIPPED default rather than a
    // `true` the fixture chose.
    let default_config = Config::default();
    let app = state(&default_config, default_config.server.modern_protocol);

    // WHEN: a conforming modern caller sends a frame.
    let (status, body) = post_modern(&app, &modern_frame("tools/list")).await;

    // THEN: it is served, not refused.
    assert_eq!(
        status,
        StatusCode::OK,
        "a default gateway must serve the latest revision; body: {body}"
    );
    assert!(
        body.get("result").is_some(),
        "a served modern frame answers with a result; body: {body}"
    );
}

// ============================================================================
// 2 — DEFAULT ADVERTISES IT (clause c).
//
//     Asked over the LEGACY path on purpose: `discover_document`
//     (`src/gateway/meta_mcp/mod.rs:1108-1140`) can only append the revision
//     when the flag is on, and a legacy caller reaching that answer means the
//     modern branch is not vouching for itself.
//
//     FAILS until the default flip lands.
// ============================================================================
#[tokio::test]
async fn a_default_gateway_advertises_the_modern_revision() {
    let default_config = Config::default();
    let app = state(&default_config, default_config.server.modern_protocol);

    let (status, body) = post_legacy(&app, &legacy_discover()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let listed = advertised(&body);
    assert!(
        listed.iter().any(|v| v == MODERN),
        "a default gateway must advertise the revision it serves; got {listed:?}"
    );
}

// ============================================================================
// 3 — THE FLAG GATES SERVING (clause a). Explicit `modern_protocol: false`
//     refuses the modern revision, with the flag's own fingerprint on the
//     refusal.
// ============================================================================
#[tokio::test]
async fn turning_the_flag_off_refuses_the_modern_revision() {
    // GIVEN: the default configuration with the flag explicitly off.
    let app = state(&Config::default(), false);

    // WHEN: the frame case 1 sends arrives.
    let (status, body) = post_modern(&app, &modern_frame("tools/list")).await;

    // THEN: refused as an unsupported version, advertising NOTHING — the empty
    // list is what distinguishes this gate from every other refusal on the path.
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
// 4 — REVERTIBLE WITHOUT A DOWNGRADE (clause b), and the legacy caller is
//     served byte-identically across the revert (the case-6 guard).
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

// ============================================================================
// 5 — NEGOTIATES DOWN (clause d). A modern-serving gateway answers a client
//     offering an older SUPPORTED revision AT that revision.
//
//     Three revisions, not one: "negotiates down to the highest revision the
//     client supports" is a claim about a range, and a single value cannot tell
//     negotiation apart from a constant. Flag-independent by construction —
//     `negotiate_version` (`src/protocol/mod.rs:52-62`) exact-matches over
//     `SUPPORTED_VERSIONS` — so this passes today and must KEEP passing after
//     the flip. That is the point of asserting it here: turning the modern
//     revision on by default must cost a 2025 client nothing.
//
//     Out of scope: a revision NOT in `SUPPORTED_VERSIONS`, where the function
//     falls back to `PROTOCOL_VERSION` rather than refusing. Not asserted here
//     either way.
// ============================================================================
#[tokio::test]
async fn a_default_gateway_negotiates_down_to_each_supported_revision() {
    let default_config = Config::default();
    let app = state(&default_config, default_config.server.modern_protocol);

    for offered in ["2025-06-18", "2025-03-26", "2024-11-05"] {
        let (status, body) = post_at_version(&app, offered, &initialize_at(offered)).await;
        assert_eq!(status, StatusCode::OK, "offered {offered}; body: {body}");
        assert_eq!(
            body["result"]["protocolVersion"], offered,
            "a client offering {offered} must be answered at {offered}, neither \
             silently upgraded nor dropped to a floor; body: {body}"
        );
    }
}

// ============================================================================
// 7 — THE OPERATOR-FACING DEFAULT (clause c). A `server:` section that OMITS
//     the flag must deserialize to ON.
//
//     Case 1 exercises `Config::default()`. This exercises what an operator
//     with a config file actually gets, and TODAY THE TWO ANSWER DIFFERENTLY:
//     the FIELD-level `#[serde(default)]` (`src/config/mod.rs:1181`) shadows the
//     container-level one (`:1166`) and resolves to `bool::default()` — false.
//     Flipping only the struct default would turn case 1 green and leave this
//     red, which is precisely why this case exists.
//
//     The mapping carries `port` deliberately: an absent or empty `server:` key
//     routes through `ServerConfig::default()` and would pass for the wrong
//     reason, proving nothing about the field attribute under test.
//
//     FAILS until that field-level attribute is deleted.
// ============================================================================
#[test]
fn a_config_file_that_omits_the_flag_still_serves_modern() {
    let parsed: ServerConfig =
        serde_yaml::from_str("port: 9999\n").expect("a partial server section must parse");

    assert_eq!(
        parsed.port, 9999,
        "precondition: the mapping really was parsed, so the assertion below is \
         about an OMITTED field rather than an unread document"
    );
    assert!(
        parsed.modern_protocol,
        "an operator whose config file never mentions the flag must still get \
         the latest revision"
    );
}
