// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7312 — continuation state has one owner, and it is the production one.
//!
//! The gap these cover: `Keyring`, `ConsumedLedger` and `InFlight` had no
//! constructor outside tests, so every property already proven about them was
//! proven about objects a test built. These build the state the way the running
//! gateway does — through `AppState` — and assert the two properties MRTR.5
//! rests on: the owner is reachable there at all, and a second process cannot
//! open the first one's envelope.

use std::sync::Arc;

use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::continuation::{ContinuationError, ContinuationState, Payload};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};

/// One gateway process, built the way the server builds it.
///
/// The `continuation` field is what this test file exists for: it is filled
/// from `ContinuationState::new()`, the same call `serve` makes, rather than
/// from key bytes a test chose.
fn app_state() -> Arc<AppState> {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let agent_registry = Arc::new(AgentRegistry::new());
    Arc::new(AppState {
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
        agent_auth: AgentAuthState::new(false, agent_registry),
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
        continuation: Arc::new(ContinuationState::new()),
    })
}

fn payload(jti: &str, origin: &str, expires_at: u64) -> Payload {
    Payload {
        backend_id: "backend".to_string(),
        backend_request_state: "backend-state".to_string(),
        principal_fingerprint: "principal".to_string(),
        original_request_digest: "digest".to_string(),
        origin_replica: origin.to_string(),
        issued_at: 1_000,
        expires_at,
        jti: jti.to_string(),
    }
}

/// The owner is reachable through the state the gateway actually runs on.
///
/// Mint and open both go through `AppState`, and the ledger refuses the second
/// spend — the single-use half of MRTR.5, asserted against the production
/// owner rather than a loose `ConsumedLedger` a test constructed.
#[tokio::test]
async fn continuation_state_is_reachable_from_the_production_app_state() {
    let state = app_state();
    let minted = payload("jti-reachable", "replica-a", 2_000);

    let token = state
        .continuation
        .keyring()
        .mint(&minted)
        .expect("mint through AppState");
    let opened = state
        .continuation
        .keyring()
        .open(&token, 1_500)
        .expect("open through AppState");
    assert_eq!(opened.jti, "jti-reachable");

    assert!(
        state
            .continuation
            .ledger()
            .consume(&opened.jti, opened.expires_at, 1_500)
            .await,
        "first spend wins"
    );
    assert!(
        !state
            .continuation
            .ledger()
            .consume(&opened.jti, opened.expires_at, 1_500)
            .await,
        "a spent continuation is refused, so it is single-use"
    );
}

/// MRTR.5 across replicas: a second process cannot evaluate the first's token.
///
/// Two `AppState`s stand in for two gateway processes. Both generate their own
/// key material at construction, so the envelope sealed by one does not
/// authenticate under the other's key — the refusal is cryptographic, and no
/// shared store decides it.
#[tokio::test]
async fn a_token_minted_by_one_app_state_is_refused_by_another() {
    let a = app_state();
    let b = app_state();

    let token = a
        .continuation
        .keyring()
        .mint(&payload("jti-cross-replica", "replica-a", 2_000))
        .expect("mint on A");

    assert!(
        matches!(
            b.continuation.keyring().open(&token, 1_500),
            Err(ContinuationError::NotAuthentic)
        ),
        "B holds different key material, so A's envelope does not authenticate there"
    );
}
