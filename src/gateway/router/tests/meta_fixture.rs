// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The authenticated router fixture, with the Meta-MCP configured by the
//! caller before it is shared: a `&mut self` setting such as the
//! transparency log cannot be applied once `AppState` holds it in an `Arc`.

use super::*;

/// [`test_router_app_state_with_auth_and_key_server`], with `configure`
/// applied to the fixture's `MetaMcp` before it is wrapped.
pub(in crate::gateway::router) async fn test_router_app_state_with_meta(
    auth: &AuthConfig,
    key_server: Option<Arc<crate::key_server::KeyServer>>,
    configure: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fixture {
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    fixture_with(auth, key_server, agent_auth, configure).await
}

/// [`test_router_app_state_with_meta`], with `firewall` as the router's own
/// engine (the response pass), as startup wires it beside the Meta-MCP's.
#[cfg(feature = "firewall")]
pub(in crate::gateway::router) async fn test_router_app_state_with_meta_and_firewall(
    auth: &AuthConfig,
    key_server: Option<Arc<crate::key_server::KeyServer>>,
    firewall: Option<Arc<crate::security::firewall::Firewall>>,
    configure: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fixture {
    let (mut state, store) = test_router_app_state_with_meta(auth, key_server, configure).await;
    // The router's engine exempts the keyring the gateway mints with, as
    // startup pairs them (#2210, MIK-8276).
    assert!(
        firewall.as_ref().is_none_or(|fw| fw
            .continuations_for_test()
            .is_some_and(|keys| Arc::ptr_eq(&keys, &state.meta_mcp.continuation()))),
        "the router's firewall must exempt the gateway's keyring"
    );
    Arc::get_mut(&mut state)
        .expect("the fixture state is not shared yet")
        .firewall = firewall;
    (state, store)
}

/// [`test_router_app_state_with_auth`] with `agent_auth` in place from the
/// start, so the listener registry re-validates against the same agents the
/// request middleware admits.
pub(in crate::gateway::router) async fn test_router_app_state_with_agent_auth(
    auth: &AuthConfig,
    agent_auth: AgentAuthState,
) -> Fixture {
    fixture_with(auth, None, agent_auth, |meta| meta).await
}

async fn fixture_with(
    auth: &AuthConfig,
    key_server: Option<Arc<crate::key_server::KeyServer>>,
    agent_auth: AgentAuthState,
    configure: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fixture {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(configure(MetaMcp::new(Arc::clone(&backends))));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(auth));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, key_server.clone(), &agent_auth);
    let (task_service, task_executor, store_dir) =
        test_task_runtime(&subscriptions, &meta_mcp).await;

    let state = Arc::new(AppState {
        session_lifecycle: None,
        continuation: Arc::new(crate::protocol::continuation::ContinuationState::new()),
        env: None,
        backends,
        meta_mcp,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config,
        auth_config,
        key_server,
        tool_policy: Arc::new(crate::security::ToolPolicy::default()),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(8)),
        agent_auth,
        gateway_key_pair,
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: crate::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        control_plane_base: None,
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tasks: task_service,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}
