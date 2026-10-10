// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7927: the in-band confirmation gate's refusal arms, driven over the
//! modern HTTP path (`src/gateway/meta_mcp/confirmation.rs`, `InBand`).
//!
//! Each refusal is checked two ways: the answer is `-32001`, and the
//! destructive tool did not run. `gateway_kill_server` marks the server in the
//! gateway's kill switch, so `killed_servers()` counts its executions. Each
//! test also runs the rightful call on the same state and sees the kill land,
//! so an empty kill switch means "refused", not "this fixture never runs it".
//!
//! Two arms have no test here:
//! - no principal (`confirmation.rs:271-272`) is unreachable over HTTP: the
//!   gate sits behind the admin check, and every admin client carries a name,
//!   which `confirmation_principal` always turns into a principal;
//! - signing refused (`:319-321`) fires only on a random-source failure or an
//!   exhausted per-key budget of 2^32 envelopes (the gate fixes the payload's
//!   size and lifetime). A test can induce neither: `Keyring::with_mint_budget`
//!   can lower the budget, but `ContinuationState::new` is the only
//!   constructor and builds its keyring at the full budget.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, auth_state, create_router, open_runtime,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

const CONFIRM_KEY: &str = "io.mcp-gateway.destructive-confirmation.v1";
const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

/// Two admin keys, so one admin can present the other's envelope.
fn two_admins() -> mcp_gateway::config::AuthConfig {
    let key = |secret: &[u8], name: &str| {
        serde_json::from_value(json!({
            "key_sha256": mcp_gateway::config::api_key_digest_spec(secret),
            "name": name, "backends": ["*"], "admin": true
        }))
        .expect("api key fixture")
    };
    mcp_gateway::config::AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![key(b"admin-a", "admin-a"), key(b"admin-b", "admin-b")],
        public_paths: Vec::new(),
        ..mcp_gateway::config::AuthConfig::default()
    }
}

async fn state() -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = Config::default();
    config.server.modern_protocol = true;
    config.auth = two_admins();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let subscriptions = Arc::new(SubscriptionRegistry::new(64, auth_state(&config.auth)));
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let (tasks, task_executor) = open_runtime(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("the fixture task store opens");
    let state = Arc::new(AppState {
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
        agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
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
    (state, store_dir)
}

/// A modern `gateway_kill_server` call; `retry` adds the echoed envelope and
/// a `true` answer. A retry reuses its ask's `id`, so the request id and the
/// idempotency key never differ between the two calls. A retry under a new
/// id is refused even when it comes from the right caller, which would hide
/// the variable each test changes.
fn kill(id: i64, server: &str, retry: Option<&str>) -> Value {
    let mut params = json!({
        "name": "gateway_kill_server",
        "arguments": { "server": server },
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            IDEMPOTENCY_KEY_META: format!("mik7927-{id}"),
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
        }
    });
    if let Some(envelope) = retry {
        params["requestState"] = json!(envelope);
        params["inputResponses"] = json!({ CONFIRM_KEY: true });
    }
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params })
}

async fn post(state: &Arc<AppState>, body: Value, bearer: &str) -> Value {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_kill_server")
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "JSON-RPC errors ride a 200"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    serde_json::from_slice(&bytes).unwrap_or_else(|error| {
        panic!(
            "the answer must be JSON ({error}): {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

/// Ask, and return the envelope the gateway answered with.
async fn ask(state: &Arc<AppState>, id: i64, server: &str, bearer: &str) -> String {
    let body = post(state, kill(id, server, None), bearer).await;
    assert_eq!(
        body.pointer("/result/resultType").and_then(Value::as_str),
        Some("input_required"),
        "the first call must be asked, not run or refused: {body}"
    );
    assert_eq!(
        body.pointer(&format!("/result/inputRequests/{CONFIRM_KEY}/type"))
            .and_then(Value::as_str),
        Some("boolean"),
        "the ask is a yes/no confirmation: {body}"
    );
    body.pointer("/result/requestState")
        .and_then(Value::as_str)
        .expect("the ask carries an envelope")
        .to_owned()
}

fn killed(state: &Arc<AppState>) -> Vec<String> {
    state.meta_mcp.kill_switch().killed_servers()
}

fn assert_refused(body: &Value) {
    assert_eq!(
        body.pointer("/error/code").and_then(Value::as_i64),
        Some(-32001),
        "the gate must refuse: {body}"
    );
    assert!(
        body.get("result").is_none(),
        "a refusal returns no result: {body}"
    );
    // The gate could not obtain a confirmation; an operator's "no" is another
    // arm with its own message and must not satisfy these tests.
    assert!(
        body.pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("requires confirmation and none could be obtained")),
        "the refusal is the cannot-obtain one: {body}"
    );
}

/// The rightful call ran and answered with a JSON-RPC result.
fn assert_ran(body: &Value) {
    assert!(
        body.get("error").is_none() && body.get("result").is_some(),
        "the rightful call must succeed: {body}"
    );
}

/// TEST.2, unredeemable answer: another admin presents an envelope minted
/// for admin-a. The control is admin-a redeeming the same envelope, which
/// must run the kill: the refusal did not spend it and the fixture can run.
#[tokio::test]
async fn an_envelope_from_another_principal_is_refused_and_not_run() {
    let (state, _dir) = state().await;
    let envelope = ask(&state, 1, "mik7927-p", "admin-a").await;

    let body = post(&state, kill(1, "mik7927-p", Some(&envelope)), "admin-b").await;
    assert_refused(&body);
    assert!(killed(&state).is_empty(), "the tool ran: {body}");

    let body = post(&state, kill(1, "mik7927-p", Some(&envelope)), "admin-a").await;
    assert_eq!(
        killed(&state),
        vec!["mik7927-p".to_owned()],
        "the rightful retry must run the kill: {body}"
    );
    assert_ran(&body);
}

/// TEST.2, unredeemable answer: the envelope's own caller presents it for
/// different arguments. Control as above.
#[tokio::test]
async fn an_envelope_for_other_arguments_is_refused_and_not_run() {
    let (state, _dir) = state().await;
    let envelope = ask(&state, 1, "mik7927-asked", "admin-a").await;

    let body = post(&state, kill(1, "mik7927-other", Some(&envelope)), "admin-a").await;
    assert_refused(&body);
    assert!(killed(&state).is_empty(), "the tool ran: {body}");

    let body = post(&state, kill(1, "mik7927-asked", Some(&envelope)), "admin-a").await;
    assert_eq!(
        killed(&state),
        vec!["mik7927-asked".to_owned()],
        "the rightful retry must run the kill: {body}"
    );
    assert_ran(&body);
}

/// TEST.3, no free slot: with every in-flight slot held, the gate cannot
/// hold a question open and must refuse rather than run. The control is an
/// envelope asked before the table filled: redeeming it needs no new slot, so
/// it must still run the kill on the full table.
#[tokio::test]
async fn a_full_exchange_table_is_refused_and_not_run() {
    let (state, _dir) = state().await;
    let envelope = ask(&state, 1, "mik7927-full", "admin-a").await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs();
    let in_flight = state.continuation.in_flight();
    let mut held = 0;
    while in_flight
        .hold(
            "mik7927-filler",
            // A caller per hold: the table fills, not one caller's share.
            &mcp_gateway::protocol::continuation::QuotaKey::new(
                mcp_gateway::protocol::continuation::QuotaSource::KeyName(&format!(
                    "filler-{held}"
                )),
            ),
            now + 600,
            now,
        )
        .await
        .is_some()
    {
        held += 1;
        assert!(held <= 100_000, "the exchange table never filled");
    }

    let body = post(&state, kill(2, "mik7927-full", None), "admin-a").await;
    assert_refused(&body);
    assert!(killed(&state).is_empty(), "the tool ran: {body}");

    let body = post(&state, kill(1, "mik7927-full", Some(&envelope)), "admin-a").await;
    assert_eq!(
        killed(&state),
        vec!["mik7927-full".to_owned()],
        "the earlier envelope must still run the kill: {body}"
    );
    assert_ran(&body);
}
