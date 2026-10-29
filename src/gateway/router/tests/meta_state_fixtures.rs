// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Meta-MCP `AppState` test fixtures.

use super::{
    AgentAuthState, AgentRegistry, AppState, Arc, AuthConfig, Backend, BackendRegistry,
    GatewayKeyPair, MetaMcp, MtlsConfig, MtlsPolicy, NotificationMultiplexer, ProxyManager,
    ResolvedAuthConfig, StreamingConfig, test_subscriptions, test_task_runtime,
};

/// `AppState` whose shared Meta-MCP has provenance stamping enabled, for
/// exercising the direct `/mcp/{name}` route's rung-3 stamping (MIK-6905).
/// An `AppState` whose Meta-MCP `configure` sets up first (e.g. a receipt signer
/// on the production-derived subkey, MIK-6909).
pub(super) async fn test_router_app_state_with_meta(
    backend: Arc<Backend>,
    configure: impl FnOnce(&mut MetaMcp),
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let backends = Arc::new(BackendRegistry::new());
    let _ = backends.register(backend);
    let mut meta = MetaMcp::new(Arc::clone(&backends));
    configure(&mut meta);
    let meta_mcp = Arc::new(meta);
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(
        &AuthConfig::default(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    ));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None, &agent_auth);
    let (task_service, task_executor, store_dir) =
        test_task_runtime(&subscriptions, &meta_mcp).await;

    let state = Arc::new(AppState {
        process: std::sync::Arc::default(),
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
        key_server: None,
        tool_policy: Arc::new(crate::security::ToolPolicy::default()),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
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
            crate::config_reload::flags_off(crate::config::Config::default()),
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

/// `AppState` whose Meta-MCP has an identity-propagation strategy wired (so a
/// `required` backend actually MINTS a per-user credential) AND a transparency
/// log on the Meta-MCP side (so the shared mint chokepoint's own audit
/// succeeds) — but with `state.transparency_log = None`. This split-config
/// exercises the direct route's OWN mint-audit fail-closed guard (MIK-6740):
/// the Meta-MCP mint + audit succeed, then the direct route finds no
/// `state.transparency_log` and must fail closed (500) rather than ship the
/// per-user credential without recording it on this route.
pub(super) async fn test_router_app_state_minting_without_route_audit(
    backend: Arc<Backend>,
) -> (
    crate::security::transparency_log::temp::TempLog,
    Arc<AppState>,
    crate::gateway::router::tests::FixtureDir,
) {
    use crate::identity_propagation::SignedAssertionStrategy;
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let backends = Arc::new(BackendRegistry::new());
    let _ = backends.register(backend);
    let mut meta = MetaMcp::new(Arc::clone(&backends));
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    meta.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));
    // Meta-MCP side gets an audit sink, returned first so the caller drops it
    // last; the DIRECT route deliberately does NOT (`transparency_log: None`).
    let log = crate::security::transparency_log::temp::TempLog::new();
    let path = log.path().to_string_lossy().to_string();
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path,
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    meta.enable_transparency_log(Arc::new(
        TransparencyLogger::open(cfg).expect("logger opens"),
    ));
    let meta_mcp = Arc::new(meta);

    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(
        &AuthConfig::default(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    ));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None, &agent_auth);
    let (task_service, task_executor, store_dir) =
        test_task_runtime(&subscriptions, &meta_mcp).await;

    let state = Arc::new(AppState {
        process: std::sync::Arc::default(),
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
        key_server: None,
        tool_policy: Arc::new(crate::security::ToolPolicy::default()),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
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
            crate::config_reload::flags_off(crate::config::Config::default()),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tasks: task_service,
        task_executor,
        subscriptions,
    });
    (log, state, store_dir)
}
