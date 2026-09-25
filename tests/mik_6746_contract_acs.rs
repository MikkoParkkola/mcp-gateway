// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-6746.CONTRACT.1 — the inbound audience contract, proved from OUTSIDE
//! the crate and at the ROUTE, not only in `--lib` unit rows.
//!
//! Two things only an integration binary can establish for this row.
//!
//! 1. MIGRATION. The existing coverage builds a `Config` struct and clears
//!    `audience` by field assignment (`src/config/tests.rs:1191`). An operator
//!    does not hold a struct; they hold a pre-4.0.0 YAML file in which the key
//!    is simply ABSENT. A `#[serde(default)]` that quietly supplies a value, or
//!    a `load` path that never reaches `validate`, both pass the struct row and
//!    still ship a forgeable gateway. These rows load real files.
//!
//! 2. ROUTE-LEVEL REFUSAL AND ROUTE PARITY. `65057b0a` proved the verifier
//!    refuses; it did not prove the refusal is reached through the middleware a
//!    client actually meets, on both the meta route `/mcp` and the direct
//!    backend route `/mcp/{name}`. The direct route is where the sibling
//!    agent-identity defect lived (`d7a59a95`), so parity is asserted, never
//!    assumed.
//!
//! Every refusal row carries a positive control, because "refused" is also what
//! a gateway that refuses EVERYTHING returns.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{
    AgentAuthState, AgentDefinition, AgentRegistry, GatewayKeyPair, JwtError, validate_agent_token,
};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, create_router, open_runtime,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The identifier this gateway is known by.
const OURS: &str = "https://gateway.internal/mcp";
/// A different relying party that shares the signing key — the substitution the
/// audience check exists to refuse.
const THEIRS: &str = "https://billing.internal/api";
const CLIENT_ID: &str = "svc";
/// 32 bytes: the shortest HS256 secret config validation accepts.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

// ── Configuration-file migration (an operator's pre-4.0.0 YAML) ─────────────

/// A gateway config with agent auth ON and one HS256 agent, rendering
/// `audience` exactly as the argument says: `None` writes no key at all, which
/// is the pre-4.0.0 document shape.
fn config_yaml(audience: Option<&str>) -> String {
    let line = audience.map_or_else(String::new, |a| format!("      audience: \"{a}\"\n"));
    format!(
        "server:\n  port: 39471\nbackends: {{}}\nagent_auth:\n  enabled: true\n  agents:\n    \
         - client_id: {CLIENT_ID}\n      name: Legacy Agent\n      hs256_secret: \"{SECRET}\"\n\
         {line}"
    )
}

/// Load `body` as a gateway configuration file through the real load path.
fn load(body: &str) -> mcp_gateway::Result<Config> {
    let dir = tempfile::tempdir().expect("a private config directory");
    let path = dir.path().join("gateway.yaml");
    std::fs::write(&path, body).expect("the fixture config must be writable");
    Config::load(Some(&path))
}

#[test]
fn a_pre_4_0_0_config_file_that_omits_audience_is_refused_at_load() {
    // GIVEN a config file written before 4.0.0, where `audience` is absent.
    let yaml = config_yaml(None);

    // WHEN the gateway loads it.
    let err = load(&yaml).expect_err("an audience-less enabled agent must not load");

    // THEN the refusal names the agent and the missing key, so an operator can
    // act on it without reading the source.
    let err = err.to_string();
    assert!(
        err.contains(CLIENT_ID) && err.contains("audience"),
        "the migration refusal must name the agent and the missing audience: {err}"
    );
}

#[test]
fn the_same_file_loads_once_the_operator_supplies_an_audience() {
    // GIVEN the identical file with the one documented migration step applied.
    let yaml = config_yaml(Some(OURS));

    // WHEN it is loaded, THEN it is accepted — the refusal above is about the
    // missing audience, not about agent auth being enabled at all.
    let config = load(&yaml).expect("the documented migration step must make the config loadable");
    assert_eq!(
        config.agent_auth.agents[0].audience.as_deref(),
        Some(OURS),
        "the loaded audience must be the operator's value"
    );
}

#[test]
fn an_empty_audience_in_a_config_file_is_refused_like_an_absent_one() {
    // GIVEN an operator who satisfies the key without naming a relying party.
    // WHEN the gateway loads it, THEN it is refused: "" distinguishes nobody,
    // so accepting it would reopen the hole the key closes.
    let err = load(&config_yaml(Some("   "))).expect_err("a blank audience must not load");
    assert!(
        err.to_string().contains("audience"),
        "a blank audience must be refused on audience grounds: {err}"
    );
}

// ── The verifier itself, through the public API ─────────────────────────────

/// A registered agent, with whatever audience the case needs.
fn agent(audience: Option<&str>) -> AgentDefinition {
    AgentDefinition {
        client_id: CLIENT_ID.to_string(),
        name: "svc".to_string(),
        hs256_secret: Some(SECRET.to_string()),
        rs256_public_key: None,
        scopes: vec!["tools:*:*".to_string()],
        issuer: None,
        audience: audience.map(str::to_string),
    }
}

/// A registry holding exactly that agent.
fn registry(audience: Option<&str>) -> Arc<AgentRegistry> {
    let reg = AgentRegistry::new();
    reg.register(agent(audience));
    Arc::new(reg)
}

/// A correctly-signed HS256 token for [`CLIENT_ID`], claiming `aud`.
///
/// Correctly signed is the whole point: a token refused for a bad signature
/// would prove nothing about the audience check.
fn token(aud: &str) -> String {
    sign(&json!({ "sub": CLIENT_ID, "aud": aud, "exp": in_seconds(3600) }))
}

/// A unix timestamp `offset` seconds from now (negative for the past).
fn in_seconds(offset: i64) -> i64 {
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_secs(),
    )
    .expect("a unix timestamp fits in i64");
    now + offset
}

/// Sign `claims` with the agent's HS256 secret.
fn sign(claims: &Value) -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        claims,
        &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .expect("the fixture token must sign")
}

#[test]
fn a_registered_agent_with_no_audience_refuses_a_correctly_signed_token() {
    // GIVEN an agent registered through the PUBLIC registry, which validates
    // nothing — the path that makes `None` reachable even after config
    // validation refuses it at load.
    let reg = registry(None);

    // WHEN a correctly-signed token for that agent is validated.
    let err = validate_agent_token(&token(OURS), &reg)
        .expect_err("a definition with no audience must not validate a token");

    // THEN it is refused, so the invariant belongs to the verifier rather than
    // to one caller's configuration.
    assert!(
        matches!(err, JwtError::JwtVerification(_)),
        "the refusal must be a verification failure, not an unrelated error: {err}"
    );
    // AND the same token is accepted once the agent names this gateway —
    // the control proving the refusal is about the audience, not the token.
    validate_agent_token(&token(OURS), &registry(Some(OURS)))
        .expect("a correctly-signed token for the configured audience must validate");
}

// ── The routes a client actually meets ──────────────────────────────────────

/// Gateway state with agent auth ON and exactly one agent registered, whose
/// expected audience is [`OURS`].
///
/// No backend is registered on purpose: agent auth runs as middleware, ahead of
/// any dispatch, so a row that reached a backend would be testing the wrong
/// layer. The `TempDir` is returned because the task store holds it for the
/// life of the state.
async fn state() -> (Arc<AppState>, tempfile::TempDir) {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let subscriptions = Arc::new(SubscriptionRegistry::new(64));
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let (tasks, task_executor) = open_runtime(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("the fixture task store opens");
    let app = Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        session_lifecycle: None,
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
        agent_auth: AgentAuthState::new(true, registry(Some(OURS))),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        control_plane_base: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
    });
    (app, store_dir)
}

/// POST a `tools/list` frame to `uri`, bearing `bearer`.
///
/// The method is deliberately the cheapest one a client can send: agent auth is
/// a middleware, so if it only refused `tools/call` the row would pass for the
/// wrong reason.
async fn post(state: &Arc<AppState>, uri: &str, bearer: Option<&str>) -> StatusCode {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let request = builder
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router must answer")
        .status()
}

/// Both public POST routes: the meta surface and the direct per-backend route.
///
/// Named together because parity is the claim — `d7a59a95` closed an
/// agent-identity guard that `/mcp` had and `/mcp/{name}` did not, and the
/// audience check must not repeat that asymmetry.
const ROUTES: [&str; 2] = ["/mcp", "/mcp/anything"];

#[tokio::test]
async fn a_token_minted_for_another_relying_party_is_refused_on_every_route() {
    // GIVEN a gateway whose one agent expects THIS gateway's audience.
    let (app, _store_dir) = state().await;

    // WHEN a correctly-signed token for a DIFFERENT relying party arrives on
    // each route a client can POST to.
    for route in ROUTES {
        let status = post(&app, route, Some(&token(THEIRS))).await;

        // THEN every route refuses it with 401, not just the meta surface.
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{route} admitted a token minted for {THEIRS}"
        );
    }
}

#[tokio::test]
async fn a_token_for_this_gateways_audience_clears_agent_auth_on_every_route() {
    // GIVEN the same gateway. This is the positive control for the row above:
    // without it, a gateway that refused every request would pass.
    let (app, _store_dir) = state().await;

    // WHEN the only difference is the `aud` claim.
    for route in ROUTES {
        let status = post(&app, route, Some(&token(OURS))).await;

        // THEN agent auth admits it. What happens afterwards is another
        // layer's business — no backend is registered here — so the assertion
        // is precisely "not refused by agent auth".
        assert_ne!(
            status,
            StatusCode::UNAUTHORIZED,
            "{route} refused a token for its own audience ({status})"
        );
    }
}

// ── The remaining cells of `scope-tests.md:46` ──────────────────────────────

/// A second identity provider: the same key, a different `iss`.
const OTHER_IDP: &str = "https://idp.other.invalid";

#[test]
fn an_agent_pinned_to_one_issuer_refuses_a_token_from_another() {
    // GIVEN an agent pinned to one issuer and holding the right audience, so
    // the audience check cannot be the one that answers.
    let reg = AgentRegistry::new();
    let mut pinned = agent(Some(OURS));
    pinned.issuer = Some("https://idp.ours.invalid".to_string());
    reg.register(pinned);
    let reg = Arc::new(reg);

    // WHEN a correctly-signed token arrives claiming the OTHER issuer.
    let swapped = sign(&json!({
        "sub": CLIENT_ID, "aud": OURS, "iss": OTHER_IDP, "exp": in_seconds(3600)
    }));

    // THEN it is refused — a shared key does not make one provider the other.
    assert!(
        validate_agent_token(&swapped, &reg).is_err(),
        "a token from {OTHER_IDP} must not satisfy an agent pinned elsewhere"
    );
    // AND the positive control: the pinned issuer is accepted, so the row is
    // about the swap and not about issuer pinning refusing everything.
    let matching = sign(&json!({
        "sub": CLIENT_ID, "aud": OURS, "iss": "https://idp.ours.invalid", "exp": in_seconds(3600)
    }));
    assert!(
        validate_agent_token(&matching, &reg).is_ok(),
        "the pinned issuer must still be accepted"
    );
}

#[test]
fn an_expired_token_is_refused_even_with_the_right_audience() {
    // GIVEN the right agent, the right audience and a valid signature.
    let reg = registry(Some(OURS));

    // WHEN the token expired an hour ago — well outside the 30-second clock
    // leeway (`src/gateway/oauth/jwt.rs:148`), so skew cannot explain it.
    let expired = sign(&json!({ "sub": CLIENT_ID, "aud": OURS, "exp": in_seconds(-3600) }));

    // THEN it is refused: audience is a necessary condition, never a
    // sufficient one.
    assert!(
        validate_agent_token(&expired, &reg).is_err(),
        "an expired token must be refused whatever its audience"
    );
}

#[tokio::test]
async fn a_request_with_no_credential_at_all_is_refused_on_every_route() {
    // GIVEN the same gateway with agent auth enabled.
    let (app, _store_dir) = state().await;

    // WHEN a request carries no Authorization header.
    for route in ROUTES {
        let status = post(&app, route, None).await;

        // THEN both routes refuse it. Absent identity must not fall through to
        // the primary auth config, which this fixture leaves disabled.
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{route} admitted a request with no credential"
        );
    }
}
