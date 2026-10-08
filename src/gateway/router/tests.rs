// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::helpers::{
    attach_session_header, build_accepted_response, build_error_response,
    build_http_error_response, build_json_response, extract_request_id, extract_tools_call_params,
    is_notification_method, merge_client_meta, parse_elicitation_params, parse_request,
};
use super::{AppState, create_router, create_router_with};
use super::{authorization, handlers, helpers};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{
    ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig, StreamingConfig, SurfacedToolConfig,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::test_helpers::MetaMcp;
use crate::gateway::{
    AgentAuthState, AgentIdentity as OAuthAgentIdentity, AgentRegistry, GatewayKeyPair,
    NotificationMultiplexer, ProxyManager, ResolvedAuthConfig,
};
use crate::mtls::{MtlsConfig, MtlsPolicy};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;
use async_trait::async_trait;
use axum::{
    body::to_bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use pretty_assertions::assert_eq;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

use super::authorization::{ToolTarget, authorize_tool_target, backend_tool_targets_for_call};

/// MIK-7570.ATTEST.1: enforce on the direct route and on surfaced tools.
mod attestation_routes;
mod chain_direct;
/// MIK-7962.COLD.1: admission reads the tool cache only.
mod cold_admission;
mod descriptor_withholding;
mod f24_resource_subscribe;
/// MIK-7215.CONTROL.5 G4: arm and hints key on the caller.
mod g4_caller_keyed;
/// The Meta-MCP route's own response-firewall verdict obligation (RED).
#[cfg(feature = "firewall")]
mod meta_firewall_verdict;
mod meta_fixture;
mod order2_fsm;
mod task_execution_adapter;

mod issue_555_listing_scope;
/// C7: `/metrics` behind a dedicated scrape token (MIK 7570 METRICS.1).
#[cfg(feature = "metrics")]
mod metrics_scrape;

mod authz_and_sse;
mod code_mode_param;
mod direct_route_identity;
mod origin_gate;
mod playbook_authz;
/// MIK-8158: no authorization server, no protected-resource metadata.
mod prm_without_issuer;
mod request_parsing;
mod responses;
mod session_hold_direct;
mod session_routing;

/// The durable task runtime every fixture in this file is built on.
///
/// A fresh `TempDir` per fixture, handed back to the caller and bound for the
/// lifetime of the test. Both halves of that are load-bearing: the store takes
/// an exclusive lease on its directory, so a shared path would make one test's
/// open refuse another's, and a `TempDir` dropped at the end of the fixture
/// would delete the records out from under a service that is still serving.
///
/// Real, not a stand-in. `open_runtime` is the production entry point, and the
/// admission index it imports into is the one the route reads ownership from —
/// a substitute store would leave every ownership assertion below testing the
/// substitute. Nothing here names a fixed path or reads a process-wide
/// variable, so tests stay independent of each other and of the environment.
/// The admission authority is the fixture's OWN Meta-MCP, not a second one: a
/// task admitted through the route and a synchronous call carrying the same
/// owner and idempotency key have to meet at one index, which is exactly what
/// the deployed gateway wires.
async fn test_task_runtime(
    subscriptions: &Arc<crate::gateway::subscription_registry::SubscriptionRegistry>,
    meta_mcp: &Arc<MetaMcp>,
) -> (
    Arc<crate::gateway::task_service::TaskService>,
    Arc<crate::gateway::task_service::TaskExecutor>,
    tempfile::TempDir,
) {
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let (service, executor) = crate::gateway::task_service::open_runtime_with_admission(
        &store_dir.path().join("tasks"),
        crate::config::TasksConfig::default().max_workers,
        crate::gateway::task_service::StoreLimits::default(),
        Arc::clone(subscriptions),
        Arc::clone(meta_mcp.execution_admission()),
    )
    .await
    .expect("the fixture task store opens");
    (service, executor, store_dir)
}

/// The subscription registry a fixture shares between `AppState` and the
/// executor's publication seam. Two registries would publish a task's
/// notifications to a listener set no client is on. Re-validates against the
/// fixture's own credentials, so it agrees with the request middleware.
fn test_subscriptions(
    auth_config: &Arc<ResolvedAuthConfig>,
    key_server: Option<Arc<crate::key_server::KeyServer>>,
) -> Arc<crate::gateway::subscription_registry::SubscriptionRegistry> {
    let authorizer = crate::gateway::auth::AuthState {
        auth_config: Arc::clone(auth_config),
        key_server,
        dashboard_bootstrap: Arc::default(),
        tls_enabled: false,
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
    };
    Arc::new(crate::gateway::subscription_registry::SubscriptionRegistry::new(64, authorizer))
}

type Fixture = (Arc<AppState>, tempfile::TempDir);

pub(super) async fn test_router_app_state_with_streaming(
    streaming_config: StreamingConfig,
) -> Fixture {
    test_router_app_state_with(streaming_config, crate::config::Config::default()).await
}

/// The fixture, with the configuration left to the caller.
///
/// Split out because the protocol era is a config field: a test that wants the
/// modern path has to be able to turn it on, and one that reaches it through
/// the default config is not testing the modern path at all — it is reading an
/// `unsupported protocol version` refusal and finding it agreeable.
async fn test_router_app_state_with(
    streaming_config: StreamingConfig,
    config: crate::config::Config,
) -> (Arc<AppState>, tempfile::TempDir) {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None);
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
        key_server: None,
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(config)),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tasks: task_service,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

pub(super) async fn test_router_app_state() -> (Arc<AppState>, tempfile::TempDir) {
    test_router_app_state_with_streaming(StreamingConfig::default()).await
}

async fn test_router_app_state_with_agent_auth_enabled() -> (Arc<AppState>, tempfile::TempDir) {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(true, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None);
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
        key_server: None,
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

pub(super) async fn test_router_app_state_with_backend(
    backend: Arc<Backend>,
) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store_dir) = test_router_app_state().await;
    let _ = state.backends.register(backend);
    (state, store_dir)
}

/// `AppState` whose shared Meta-MCP has provenance stamping enabled, for
/// exercising the direct `/mcp/{name}` route's rung-3 stamping (MIK-6905).
/// An `AppState` whose Meta-MCP `configure` sets up first (e.g. a receipt signer
/// on the production-derived subkey, MIK-6909).
async fn test_router_app_state_with_meta(
    backend: Arc<Backend>,
    configure: impl FnOnce(&mut MetaMcp),
) -> (Arc<AppState>, tempfile::TempDir) {
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
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None);
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
        key_server: None,
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

/// `AppState` whose Meta-MCP has an identity-propagation strategy wired (so a
/// `required` backend actually MINTS a per-user credential) AND a transparency
/// log on the Meta-MCP side (so the shared mint chokepoint's own audit
/// succeeds) — but with `state.transparency_log = None`. This split-config
/// exercises the direct route's OWN mint-audit fail-closed guard (MIK-6740):
/// the Meta-MCP mint + audit succeed, then the direct route finds no
/// `state.transparency_log` and must fail closed (500) rather than ship the
/// per-user credential without recording it on this route.
async fn test_router_app_state_minting_without_route_audit(
    backend: Arc<Backend>,
) -> (Arc<AppState>, tempfile::TempDir) {
    use crate::identity_propagation::SignedAssertionStrategy;
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    let backends = Arc::new(BackendRegistry::new());
    let _ = backends.register(backend);
    let mut meta = MetaMcp::new(Arc::clone(&backends));
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    meta.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));
    // Meta-MCP side gets an audit sink (leaked tempfile — reclaimed at process
    // exit); the DIRECT route deliberately does NOT (`transparency_log: None`).
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_string_lossy().to_string();
    std::mem::forget(file);
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
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None);
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
        key_server: None,
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

pub(super) fn http_backend_at(name: &str, http_url: &str) -> Arc<Backend> {
    Arc::new(Backend::new(
        name,
        BackendConfig {
            transport: crate::config::TransportConfig::Http {
                http_url: http_url.to_string(),
                streamable_http: Some(false),
                protocol_version: None,
            },
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

pub(super) async fn test_router_app_state_with_auth(auth: &AuthConfig) -> Fixture {
    test_router_app_state_with_auth_and_key_server(auth, None).await
}

/// [`test_router_app_state_with_auth`], with a key server whose temporary
/// tokens both the middleware and listener re-validation accept.
pub(super) async fn test_router_app_state_with_auth_and_key_server(
    auth: &AuthConfig,
    key_server: Option<Arc<crate::key_server::KeyServer>>,
) -> Fixture {
    meta_fixture::test_router_app_state_with_meta(auth, key_server, |meta| meta).await
}

/// Authenticated fixture whose executor capacity comes from the supplied config.
pub(super) async fn test_router_app_state_with_auth_and_config(
    auth: &AuthConfig,
    config: crate::config::Config,
) -> (Arc<AppState>, tempfile::TempDir) {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(auth));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None);
    let store_dir = tempfile::tempdir().expect("a private configured task-store directory");
    let (task_service, task_executor) = crate::gateway::task_service::open_runtime_with_admission(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        crate::gateway::task_service::StoreLimits::default(),
        Arc::clone(&subscriptions),
        Arc::clone(meta_mcp.execution_admission()),
    )
    .await
    .expect("the configured fixture task store opens");

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
        key_server: None,
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(config)),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tasks: task_service,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

pub(super) fn scoped_auth_config(admin: bool) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec("scoped-key".as_bytes())),
            expires_at: None,
            name: "scoped-client".to_string(),
            rate_limit: 0,
            backends: vec!["demo".to_string()],
            allowed_tools: Some(vec!["allowed_tool".to_string()]),
            denied_tools: None,
            admin,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    }
}

struct RouterNotificationTestTransport {
    request_methods: Mutex<Vec<String>>,
    notify_methods: Mutex<Vec<String>>,
    notify_error: Option<String>,
}

impl RouterNotificationTestTransport {
    fn success() -> Self {
        Self {
            request_methods: Mutex::new(Vec::new()),
            notify_methods: Mutex::new(Vec::new()),
            notify_error: None,
        }
    }

    fn fail(message: &str) -> Self {
        Self {
            request_methods: Mutex::new(Vec::new()),
            notify_methods: Mutex::new(Vec::new()),
            notify_error: Some(message.to_string()),
        }
    }
}

#[async_trait]
impl Transport for RouterNotificationTestTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.request_methods
            .lock()
            .unwrap()
            .push(method.to_string());
        Ok(JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"ok": true}),
        ))
    }

    async fn notify(&self, method: &str, _params: Option<Value>) -> crate::Result<()> {
        self.notify_methods.lock().unwrap().push(method.to_string());
        if let Some(message) = &self.notify_error {
            return Err(crate::Error::Transport(message.clone()));
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The deployment guide names exactly the tools the admin set contains.
///
/// A prose file cannot be derived from a constant, so it is compared to one.
/// The guide, the startup banner, the changelog and the predicate were four
/// hand-maintained copies of one roster, and they disagreed the moment the
/// roster changed. Three now read the constant; this makes the fourth fail
/// loudly instead of quietly misleading an operator about what they can run.
#[test]
fn deployment_guide_matches_the_admin_tool_set() {
    let guide = include_str!("../../../docs/DEPLOYMENT.md");

    for tool in super::authorization::ADMIN_META_TOOLS {
        assert!(
            guide.contains(tool),
            "DEPLOYMENT.md must name {tool} among the tools needing a credential"
        );
    }

    for session_local in ["gateway_set_profile", "gateway_set_state"] {
        assert!(
            !guide.contains(session_local),
            "DEPLOYMENT.md still lists {session_local} as needing a credential, \
             which it no longer does"
        );
    }
}

/// A client restricted to one backend, with optional tool scoping.
fn scoped_client(
    name: &str,
    backends: Vec<String>,
    allowed_tools: Option<Vec<String>>,
) -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: None,
        name: name.to_string(),
        rate_limit: 0,
        backends,
        allowed_tools,
        denied_tools: None,
        admin: false,
        principal: format!("principal-{name}"),
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

/// A refusal must be attributed to whichever identity authenticated the caller.
///
/// The audit line exists so an incident responder can say who was refused.
/// Reporting only the API-key name labels an agent-authenticated or
/// certificate-authenticated caller as unauthenticated — precisely the
/// refusals most worth attributing. Unwired from any assertion until now.
#[test]
fn authz_refusal_principal_names_the_authenticated_identity() {
    use crate::gateway::oauth::AgentIdentity;
    use crate::mtls::CertIdentity;

    let api_key = scoped_client("keyed", vec!["*".into()], None);
    assert_eq!(
        super::authorization::refusal_principal(Some(&api_key), None, None).as_deref(),
        Some("keyed"),
        "an API-key caller is named by its client name"
    );

    let agent = AgentIdentity {
        quota_principal: None,
        client_id: "cid".to_string(),
        agent_name: "runner".to_string(),
        scopes: Vec::new(),
        raw_scopes: Vec::new(),
    };
    assert_eq!(
        super::authorization::refusal_principal(None, Some(&agent), None).as_deref(),
        Some("agent:runner"),
        "an agent caller must not be reported as unauthenticated"
    );

    let cert = CertIdentity {
        display_name: "machine-7".to_string(),
        ..CertIdentity::default()
    };
    assert_eq!(
        super::authorization::refusal_principal(None, None, Some(&cert)).as_deref(),
        Some("cert:machine-7"),
        "a certificate caller must not be reported as unauthenticated"
    );

    let anonymous = AuthenticatedClient {
        quota_principal: None,
        authenticated: false,
        credential_kind: crate::security::audit::CredentialKind::None,
        ..scoped_client("public", vec!["*".into()], None)
    };
    assert_eq!(
        super::authorization::refusal_principal(Some(&anonymous), None, None),
        None,
        "an identity that presented no credential is genuinely unattributed, \
         and must not borrow the name of a configured client"
    );
}

/// The fixture with the 2026 era switched on.
///
/// Without it every modern request stops at `unsupported protocol version`,
/// and a test asserting an absence — no session header, no profile switch —
/// passes on the refusal rather than on the behaviour it names.
async fn modern_router_app_state() -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = crate::config::Config::default();
    config.server.modern_protocol = true;
    test_router_app_state_with(StreamingConfig::default(), config).await
}

mod openwebui_adapter;

/// C5 route parity (MIK-6746): agent-identity enforcement must not depend on
/// which URL the caller picks. `require_id` and the `known_agents` allowlist
/// are checked in `meta_mcp_dispatch` for `/mcp`; the direct `/mcp/{name}`
/// route reaches the same backends, so a guard missing there is an allowlist
/// a client bypasses by changing the path.
pub(crate) async fn direct_route_state_with_identity(
    config: crate::config::AgentIdentityConfig,
) -> (Arc<AppState>, tempfile::TempDir) {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::new(RouterNotificationTestTransport::success());
    backend.set_transport_for_test(transport);

    let (mut state, store_dir) = test_router_app_state().await;
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .agent_identity_config = config;
    let _ = state.backends.register(backend);
    (state, store_dir)
}

pub(super) fn direct_route_call(agent_id: Option<&str>) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json");
    if let Some(id) = agent_id {
        builder = builder.header("x-agent-id", id);
    }
    builder
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": { "name": "search", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap()
}
