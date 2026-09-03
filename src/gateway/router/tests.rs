// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::helpers::{
    attach_session_header, build_accepted_response, build_error_response,
    build_http_error_response, build_json_response, extract_request_id, extract_tools_call_params,
    is_notification_method, parse_elicitation_params, parse_request,
};
use super::{AppState, create_router, create_router_with};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{
    ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig, StreamingConfig, SurfacedToolConfig,
};
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

fn test_router_app_state_with_streaming(streaming_config: StreamingConfig) -> Arc<AppState> {
    test_router_app_state_with(streaming_config, crate::config::Config::default())
}

/// The fixture, with the configuration left to the caller.
///
/// Split out because the protocol era is a config field: a test that wants the
/// modern path has to be able to turn it on, and one that reaches it through
/// the default config is not testing the modern path at all — it is reading an
/// `unsupported protocol version` refusal and finding it agreeable.
fn test_router_app_state_with(
    streaming_config: StreamingConfig,
    config: crate::config::Config,
) -> Arc<AppState> {
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

    Arc::new(AppState {
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(config)),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

fn test_router_app_state() -> Arc<AppState> {
    test_router_app_state_with_streaming(StreamingConfig::default())
}

fn test_router_app_state_with_agent_auth_enabled() -> Arc<AppState> {
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

    Arc::new(AppState {
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

fn test_router_app_state_with_code_mode(enabled: bool) -> Arc<AppState> {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)).with_code_mode(enabled));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    Arc::new(AppState {
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

fn test_router_app_state_with_backend(backend: Arc<Backend>) -> Arc<AppState> {
    let state = test_router_app_state();
    let _ = state.backends.register(backend);
    state
}

/// `AppState` whose shared Meta-MCP has provenance stamping enabled, for
/// exercising the direct `/mcp/{name}` route's rung-3 stamping (MIK-6905).
/// Uses a fixed signer key so a twin validator can verify the receipt.
fn test_router_app_state_with_provenance_backend(backend: Arc<Backend>) -> Arc<AppState> {
    let backends = Arc::new(BackendRegistry::new());
    let _ = backends.register(backend);
    let mut meta = MetaMcp::new(Arc::clone(&backends));
    // Derive the receipt-domain subkey before stamping, mirroring the
    // production `resolve_provenance_signer` wiring in `gateway::server`
    // (MIK-6909): the validator below derives the same subkey internally, so
    // the stamping side must derive it too or signatures won't cross-verify.
    meta.enable_provenance_stamping(
        crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .derive_domain(crate::attestation::RESULT_PROVENANCE_DOMAIN_INFO),
    );
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

    Arc::new(AppState {
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

/// `AppState` whose Meta-MCP has an identity-propagation strategy wired (so a
/// `required` backend actually MINTS a per-user credential) AND a transparency
/// log on the Meta-MCP side (so the shared mint chokepoint's own audit
/// succeeds) — but with `state.transparency_log = None`. This split-config
/// exercises the direct route's OWN mint-audit fail-closed guard (MIK-6740):
/// the Meta-MCP mint + audit succeed, then the direct route finds no
/// `state.transparency_log` and must fail closed (500) rather than ship the
/// per-user credential without recording it on this route.
fn test_router_app_state_minting_without_route_audit(backend: Arc<Backend>) -> Arc<AppState> {
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
        shared_secret: String::new(),
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

    Arc::new(AppState {
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

fn test_router_app_state_with_ssrf(
    ssrf_protection: bool,
    trust_configured_backends: bool,
) -> Arc<AppState> {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    Arc::new(AppState {
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
        ssrf_protection,
        trust_configured_backends,
        inflight: Arc::new(tokio::sync::Semaphore::new(8)),
        agent_auth,
        gateway_key_pair,
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: crate::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

fn http_backend_at(name: &str, http_url: &str) -> Arc<Backend> {
    Arc::new(Backend::new(
        name,
        BackendConfig {
            transport: crate::config::TransportConfig::Http {
                http_url: http_url.to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn test_router_app_state_with_auth(auth: &AuthConfig) -> Arc<AppState> {
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

    Arc::new(AppState {
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
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            crate::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

fn scoped_auth_config(admin: bool) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: "scoped-key".to_string(),
            name: "scoped-client".to_string(),
            rate_limit: 0,
            backends: vec!["demo".to_string()],
            allowed_tools: Some(vec!["allowed_tool".to_string()]),
            denied_tools: None,
            admin,
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
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

// =====================================================================
// extract_request_id
// =====================================================================

#[test]
fn extract_request_id_string_value() {
    let val = json!("abc-123");
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::String("abc-123".to_string()));
}

#[test]
fn extract_request_id_positive_integer() {
    let val = json!(42);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(42));
}

#[test]
fn extract_request_id_negative_integer() {
    let val = json!(-1);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(-1));
}

#[test]
fn extract_request_id_zero() {
    let val = json!(0);
    let id = extract_request_id(&val).unwrap();
    assert_eq!(id, RequestId::Number(0));
}

#[test]
fn extract_request_id_null_returns_none() {
    let val = json!(null);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_bool_returns_none() {
    let val = json!(true);
    assert!(extract_request_id(&val).is_none());
}

#[test]
#[allow(clippy::approx_constant)] // 3.14 tests float input, not π
fn extract_request_id_float_returns_none() {
    let val = json!(3.14);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_array_returns_none() {
    let val = json!([1, 2]);
    assert!(extract_request_id(&val).is_none());
}

#[test]
fn extract_request_id_object_returns_none() {
    let val = json!({"id": 1});
    assert!(extract_request_id(&val).is_none());
}

// =====================================================================
// is_notification_method
// =====================================================================

#[test]
fn notification_method_recognized() {
    assert!(is_notification_method("notifications/initialized"));
    assert!(is_notification_method("notifications/cancelled"));
    assert!(is_notification_method("notifications/"));
}

#[test]
fn regular_method_not_notification() {
    assert!(!is_notification_method("initialize"));
    assert!(!is_notification_method("tools/list"));
    assert!(!is_notification_method("tools/call"));
    assert!(!is_notification_method("ping"));
    assert!(!is_notification_method(""));
}

// =====================================================================
// extract_tools_call_params
// =====================================================================

#[test]
fn extract_tools_call_params_full() {
    let params = json!({"name": "my_tool", "arguments": {"key": "value"}});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "my_tool");
    assert_eq!(args, json!({"key": "value"}));
}

#[test]
fn extract_tools_call_params_missing_name() {
    let params = json!({"arguments": {"key": "value"}});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "");
    assert_eq!(args, json!({"key": "value"}));
}

#[test]
fn extract_tools_call_params_missing_arguments() {
    let params = json!({"name": "my_tool"});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "my_tool");
    assert_eq!(args, json!({}));
}

#[test]
fn extract_tools_call_params_none_input() {
    let (name, args) = extract_tools_call_params(None);
    assert_eq!(name, "");
    assert_eq!(args, json!({}));
}

#[test]
fn extract_tools_call_params_empty_object() {
    let params = json!({});
    let (name, args) = extract_tools_call_params(Some(&params));
    assert_eq!(name, "");
    assert_eq!(args, json!({}));
}

// =====================================================================
// parse_request - valid requests
// =====================================================================

#[test]
fn parse_request_valid_with_string_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/list"
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::String("req-1".to_string())));
    assert_eq!(method, "tools/list");
    assert!(params.is_none());
}

#[test]
fn parse_request_valid_with_numeric_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "ping"
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(42)));
    assert_eq!(method, "ping");
    assert!(params.is_none());
}

#[test]
fn parse_request_valid_with_params() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "my_tool", "arguments": {"q": "test"}}
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(1)));
    assert_eq!(method, "tools/call");
    assert!(params.is_some());
    let p = params.unwrap();
    assert_eq!(p["name"], "my_tool");
}

#[test]
fn parse_request_notification_without_id() {
    let req = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let (id, method, _params) = parse_request(&req).unwrap();
    assert!(id.is_none());
    assert_eq!(method, "notifications/initialized");
}

#[test]
fn parse_request_notification_with_id_accepted() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "notifications/cancelled"
    });
    let (id, method, _params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::Number(99)));
    assert_eq!(method, "notifications/cancelled");
}

// =====================================================================
// parse_request - error cases
// =====================================================================

#[test]
fn parse_request_missing_jsonrpc_field() {
    let req = json!({"id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert!(err.error.is_some());
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(
        err.error
            .as_ref()
            .unwrap()
            .message
            .contains("JSON-RPC version")
    );
}

#[test]
fn parse_request_wrong_jsonrpc_version() {
    let req = json!({"jsonrpc": "1.0", "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_missing_method() {
    let req = json!({"jsonrpc": "2.0", "id": 1});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(err.error.as_ref().unwrap().message.contains("method"));
}

#[test]
fn parse_request_non_notification_without_id() {
    let req = json!({"jsonrpc": "2.0", "method": "tools/list"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
    assert!(err.error.as_ref().unwrap().message.contains("id"));
}

#[test]
fn parse_request_null_jsonrpc() {
    let req = json!({"jsonrpc": null, "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_numeric_jsonrpc() {
    let req = json!({"jsonrpc": 2, "id": 1, "method": "ping"});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_method_is_not_string() {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": 123});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_empty_object() {
    let req = json!({});
    let err = parse_request(&req).unwrap_err();
    assert_eq!(err.error.as_ref().unwrap().code, -32600);
}

#[test]
fn parse_request_initialize_method() {
    let req = json!({
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    });
    let (id, method, params) = parse_request(&req).unwrap();
    assert_eq!(id, Some(RequestId::String("init-1".to_string())));
    assert_eq!(method, "initialize");
    assert!(params.is_some());
}

// =====================================================================
// response helpers
// =====================================================================

#[tokio::test]
async fn build_error_response_sets_status_session_header_and_rpc_body() {
    let response = build_error_response(
        Some(RequestId::Number(7)),
        -32602,
        "Missing parameter",
        "sess-123",
        StatusCode::BAD_REQUEST,
    );

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-123");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32602);
    assert_eq!(json["error"]["message"], "Missing parameter");
    assert_eq!(json["id"], json!(7));
}

#[tokio::test]
async fn build_accepted_response_sets_status_session_header_and_empty_body() {
    let response = build_accepted_response("sess-accepted");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()["mcp-session-id"], "sess-accepted");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, json!({}));
}

#[tokio::test]
async fn build_json_response_skips_invalid_session_header_without_panicking() {
    let response = build_json_response(json!({"ok": true}), "sess\n123", StatusCode::OK);

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("mcp-session-id").is_none());

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, json!({"ok": true}));
}

#[test]
fn attach_session_header_skips_invalid_session_header_without_panicking() {
    let mut headers = HeaderMap::new();

    attach_session_header(&mut headers, "sess\n123");

    assert!(headers.get("mcp-session-id").is_none());
}

#[tokio::test]
async fn build_http_error_response_sets_status_and_jsonrpc_body() {
    let (status, body) = build_http_error_response(
        Some(RequestId::String("req-403".to_string())),
        -32003,
        "Forbidden",
        StatusCode::FORBIDDEN,
    );
    let response = (status, body).into_response();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get("mcp-session-id").is_none());

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32003);
    assert_eq!(json["error"]["message"], "Forbidden");
    assert_eq!(json["id"], json!("req-403"));
}

#[tokio::test]
async fn build_http_error_response_without_request_id_includes_null_id_field() {
    let (status, body) =
        build_http_error_response(None, -32700, "Parse error", StatusCode::BAD_REQUEST);
    let response = (status, body).into_response();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let object = json.as_object().unwrap();
    assert!(object.contains_key("id"));
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32700);
    assert_eq!(json["error"]["message"], "Parse error");
}

#[tokio::test]
async fn parse_elicitation_params_missing_returns_bad_request_with_session_header() {
    let response = parse_elicitation_params(RequestId::Number(9), None, "sess-elicit").unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-elicit");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32602);
    assert_eq!(json["error"]["message"], "Missing elicitation params");
    assert_eq!(json["id"], json!(9));
}

#[tokio::test]
async fn parse_elicitation_params_invalid_returns_bad_request_with_context() {
    let response = parse_elicitation_params(
        RequestId::String("req-1".to_string()),
        Some(json!({"message": 42})),
        "sess-elicit",
    )
    .unwrap_err();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["mcp-session-id"], "sess-elicit");

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32602);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid elicitation params:")
    );
    assert_eq!(json["id"], json!("req-1"));
}

#[tokio::test]
async fn backend_handler_invalid_json_returns_jsonrpc_parse_error() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{not json"))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32700);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("Invalid JSON:")
    );
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn backend_handler_missing_backend_returns_jsonrpc_not_found() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/missing-backend")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32001);
    assert_eq!(
        json["error"]["message"],
        "Backend not found: missing-backend"
    );
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn backend_handler_preserves_callers_jsonrpc_id_on_success() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::new(RouterNotificationTestTransport::success());
    backend.set_transport_for_test(transport);

    let router = create_router(test_router_app_state_with_backend(backend));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "caller-initialize-41",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test-client", "version": "1.0" }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], "caller-initialize-41");
    assert_eq!(json["result"], json!({"ok": true}));
}

#[tokio::test]
async fn backend_handler_discovery_method_fails_closed_for_required_propagation() {
    // ADR-007 IDP.2/IDP.3 regression guard: a discovery method (resources/list)
    // on a propagation-`required` backend must fail closed (403) when the
    // request carries no verified identity — never downgrade to the shared
    // static credential. Guards the fix that extends the per-user credential
    // gate beyond `tools/call` to every backend-reaching method (MIK-6728).
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };

    let config = BackendConfig {
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://mem.internal/mcp".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "demo",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));

    let router = create_router(test_router_app_state_with_backend(backend));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resources/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32003);
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("required"),
        "fail-closed error message: {}",
        json["error"]["message"]
    );
}

#[tokio::test]
async fn backend_handler_required_mint_without_route_audit_fails_closed_generically() {
    // MIK-6740 operator-misconfig fail-OPEN guard on the DIRECT route: a
    // `required` backend whose per-user credential mints successfully but whose
    // route-side transparency log is UNCONFIGURED must fail closed (500) — never
    // ship the credential without a durable audit record. CWE-209: the 500 body
    // must be a GENERIC client message, never the transparency-log path / IO
    // error.
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
    };
    use crate::key_server::oidc::VerifiedIdentity;

    let config = BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "https://mem.internal/mcp".to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        identity_propagation: Some(IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://mem.internal/mcp".to_string(),
            required: true,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }),
        enabled: true,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "demo",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let router = create_router(test_router_app_state_minting_without_route_audit(backend));

    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "read", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();
    // Inject a verified end-user identity so the required backend actually MINTS
    // a per-user credential. Auth is disabled in this test state, so the
    // middleware does not overwrite the extension.
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@corp".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp".to_string(),
    });

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let msg = json["error"]["message"].as_str().unwrap();
    // Generic client-facing message — the whole point of the CWE-209 fix.
    assert_eq!(msg, "identity-propagation audit unavailable");
    // Defense-in-depth: no filesystem path or IO detail leaks to the client.
    assert!(!msg.contains('/'), "must not leak a filesystem path: {msg}");
    assert!(
        !msg.to_lowercase().contains("write failed"),
        "must not leak audit IO detail: {msg}"
    );
}

#[tokio::test]
async fn backend_handler_notification_uses_notify_and_returns_accepted() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::new(RouterNotificationTestTransport::success());
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let router = create_router(test_router_app_state_with_backend(backend));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": { "progress": 50 }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json, json!({}));
    assert!(transport.request_methods.lock().unwrap().is_empty());
    assert_eq!(
        transport.notify_methods.lock().unwrap().as_slice(),
        ["notifications/initialized"]
    );
}

#[tokio::test]
async fn backend_handler_notification_failure_surfaces_error() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::new(RouterNotificationTestTransport::fail("notify failed"));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let router = create_router(test_router_app_state_with_backend(backend));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": { "progress": 50 }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32000);
    assert_eq!(json["error"]["message"], "Transport error: notify failed");
    assert_eq!(json["id"], Value::Null);
    assert!(transport.request_methods.lock().unwrap().is_empty());
    assert_eq!(
        transport.notify_methods.lock().unwrap().as_slice(),
        ["notifications/initialized"]
    );
}

#[tokio::test]
async fn backend_handler_tools_call_enforces_api_key_tool_scope() {
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport = Arc::new(RouterNotificationTestTransport::success());
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let state = test_router_app_state_with_auth(&scoped_auth_config(false));
    let _ = state.backends.register(backend);
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "blocked_tool",
                    "arguments": {}
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32600);
    assert!(
        json["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("allowlist"))
    );
    assert!(transport.request_methods.lock().unwrap().is_empty());
}

#[tokio::test]
async fn backend_handler_direct_route_stamps_bypass_provenance() {
    // Rung 3: the direct /mcp/{name} passthrough must also carry a signed
    // provenance receipt, tagged cache=Bypass (it never consults the meta
    // cache). Without this a client routes around provenance by URL choice.
    use crate::trust::{CacheOutcome, SignedResultProvenance};

    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::new(RouterNotificationTestTransport::success());
    backend.set_transport_for_test(transport);

    let state = test_router_app_state_with_provenance_backend(backend);
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": { "name": "search", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let provenance = json
        .pointer("/result/_meta/provenance")
        .expect("direct route must stamp _meta.provenance on tools/call");
    let signed: SignedResultProvenance =
        serde_json::from_value(provenance.clone()).expect("provenance must deserialize");

    assert_eq!(
        signed.receipt.cache,
        CacheOutcome::Bypass,
        "direct route bypasses the meta cache → cache=Bypass"
    );
    assert_eq!(signed.receipt.backend_id, "demo");
    assert_eq!(signed.receipt.tool, "search");

    let validator = crate::attestation::AttestationValidator::new(
        crate::attestation::BnautAttestationSigner::new(b"prov-key".to_vec(), "unit"),
    );
    assert!(
        validator.verify_result_provenance(&signed),
        "direct-route receipt must verify under a twin validator"
    );
}

#[tokio::test]
async fn backend_handler_direct_route_no_provenance_when_disabled() {
    // Flag off (default MetaMcp, no signer): the direct route stays
    // byte-identical — no _meta.provenance appears.
    let backend = Arc::new(Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let transport: Arc<dyn Transport> = Arc::new(RouterNotificationTestTransport::success());
    backend.set_transport_for_test(transport);

    let router = create_router(test_router_app_state_with_backend(backend));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": { "name": "search", "arguments": {} }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], 8);
    assert!(
        json.pointer("/result/_meta/provenance").is_none(),
        "flag off must not stamp provenance, got: {json}"
    );
}

#[tokio::test]
async fn meta_mcp_gateway_execute_enforces_api_key_tool_scope() {
    let router = create_router(test_router_app_state_with_auth(&scoped_auth_config(false)));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "gateway_execute",
                    "arguments": {
                        "tool": "demo:blocked_tool",
                        "arguments": {}
                    }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32600);
    assert!(
        json["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("allowlist"))
    );
}

#[tokio::test]
async fn meta_mcp_management_tool_requires_admin_client() {
    let router = create_router(test_router_app_state_with_auth(&scoped_auth_config(false)));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "gateway_reload_config",
                    "arguments": {}
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("admin access"))
    );
}

#[test]
fn authorize_tool_target_enforces_agent_scope() {
    let state = test_router_app_state();
    let identity = OAuthAgentIdentity {
        client_id: "agent-a".to_string(),
        agent_name: "Agent A".to_string(),
        scopes: vec![
            crate::gateway::oauth::Scope::parse("tools:demo:allowed_tool:execute").unwrap(),
        ],
        raw_scopes: vec!["tools:demo:allowed_tool:execute".to_string()],
    };
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        Some(&identity),
        None,
        ToolTarget {
            server: "demo",
            tool: "blocked_tool",
            arguments: &args,
        },
    );

    assert!(
        result.is_ok(),
        "agent auth disabled should not enforce scopes"
    );

    let enabled_state = test_router_app_state_with_agent_auth_enabled();
    let result = authorize_tool_target(
        enabled_state.as_ref(),
        None,
        Some(&identity),
        None,
        ToolTarget {
            server: "demo",
            tool: "blocked_tool",
            arguments: &args,
        },
    );

    assert!(result.is_err());
}

#[test]
fn surfaced_tool_calls_resolve_to_backend_authorization_target() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(vec![
        SurfacedToolConfig {
            server: "demo".to_string(),
            tool: "pinned_tool".to_string(),
        },
    ]);

    let targets = backend_tool_targets_for_call(&meta, "pinned_tool", &json!({"x": 1}));

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].server, "demo");
    assert_eq!(targets[0].tool, "pinned_tool");
}

#[test]
fn authorize_tool_target_blocks_ssrf_when_protection_enabled() {
    let state = test_router_app_state_with_ssrf(true, false);
    let _ = state
        .backends
        .register(http_backend_at("loopback", "http://127.0.0.1:9000/mcp"));
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        None,
        None,
        ToolTarget {
            server: "loopback",
            tool: "echo",
            arguments: &args,
        },
    );

    let err = result.expect_err("loopback backend must be blocked when SSRF protection is on");
    assert!(
        err.message.contains("SSRF blocked"),
        "error should reference SSRF, got: {}",
        err.message
    );
}

#[test]
fn authorize_tool_target_allows_public_host_when_ssrf_protection_enabled() {
    let state = test_router_app_state_with_ssrf(true, false);
    let _ = state
        .backends
        .register(http_backend_at("public", "https://gateway-public.test/mcp"));
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        None,
        None,
        ToolTarget {
            server: "public",
            tool: "echo",
            arguments: &args,
        },
    );

    assert!(
        result.is_ok(),
        "public hostname must pass SSRF gate, got: {}",
        result.err().map(|e| e.message).unwrap_or_default()
    );
}

#[test]
fn authorize_tool_target_skips_ssrf_when_trust_configured_backends_enabled() {
    let state = test_router_app_state_with_ssrf(true, true);
    let _ = state
        .backends
        .register(http_backend_at("loopback", "http://127.0.0.1:9000/mcp"));
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        None,
        None,
        ToolTarget {
            server: "loopback",
            tool: "echo",
            arguments: &args,
        },
    );

    assert!(
        result.is_ok(),
        "trust_configured_backends must bypass SSRF re-check at proxy time, got: {}",
        result.err().map(|e| e.message).unwrap_or_default()
    );
}

#[tokio::test]
async fn sse_handler_rejects_non_sse_accept_with_jsonrpc_error_shape() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "application/json")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(
        json["error"]["message"],
        "Must accept text/event-stream for SSE notifications"
    );
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn sse_handler_streaming_disabled_returns_jsonrpc_internal_shape() {
    let streaming_config = StreamingConfig {
        enabled: false,
        ..StreamingConfig::default()
    };

    let router = create_router(test_router_app_state_with_streaming(streaming_config));
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let object = json.as_object().unwrap();
    assert!(object.contains_key("id"));
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(
        json["error"]["message"],
        "Streaming not enabled. Use POST to send JSON-RPC requests to /mcp"
    );
}

#[tokio::test]
async fn sse_deprecated_endpoint_returns_jsonrpc_error_with_migration_data() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/sse")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::GONE);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let object = json.as_object().unwrap();
    assert!(object.contains_key("id"));
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(
        json["error"]["message"],
        "SSE transport is deprecated. Use Streamable HTTP (POST /mcp) instead."
    );
    assert_eq!(
        json["error"]["data"]["migration"],
        "In settings.json, change: \"type\": \"sse\" -> \"type\": \"http\" and \"url\": \"http://localhost:39400/sse\" -> \"url\": \"http://localhost:39400/mcp\""
    );
    assert_eq!(
        json["error"]["data"]["spec"],
        "https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http"
    );
}

// =====================================================================
// /metrics endpoint
// =====================================================================

#[cfg(feature = "metrics")]
#[tokio::test]
async fn metrics_endpoint_returns_200() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    // Endpoint must always return 200 (body may be empty when recorder is not
    // installed in tests, but the route must be reachable).
    assert_eq!(response.status(), StatusCode::OK);
}

#[cfg(feature = "metrics")]
#[tokio::test]
async fn metrics_endpoint_includes_jsonrpc_request_counter() {
    crate::metrics::install();

    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "metrics-jsonrpc-counter",
                "method": "metrics/test-counter",
                "params": {}
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let scrape = axum::http::Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();
    let metrics_response = router.oneshot(scrape).await.unwrap();
    assert_eq!(metrics_response.status(), StatusCode::OK);

    let body = to_bytes(metrics_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("mcp_jsonrpc_requests_total"));
    assert!(text.contains("method=\"metrics/test-counter\""));
    assert!(text.contains("status=\"error\""));
}

// =====================================================================
// ?codemode=search_and_execute per-connection URL override (issue #146)
// =====================================================================

#[tokio::test]
async fn tools_list_without_codemode_param_returns_standard_meta_tools() {
    // GIVEN: Code Mode disabled in config, no URL param
    let router = create_router(test_router_app_state_with_code_mode(false));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    // Standard mode must NOT include gateway_search / gateway_execute as the
    // only tools; it includes the full meta-tool set.
    assert!(
        !names.contains(&"gateway_search") || tools.len() > 2,
        "Standard mode should not return exactly the two code-mode tools; got: {names:?}"
    );
    assert!(
        !names.contains(&"gateway_execute") || tools.len() > 2,
        "Standard mode should not return exactly the two code-mode tools; got: {names:?}"
    );
}

#[tokio::test]
async fn tools_list_with_codemode_param_activates_code_mode_per_connection() {
    // GIVEN: Code Mode disabled in config, but ?codemode=search_and_execute in URL
    let router = create_router(test_router_app_state_with_code_mode(false));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp?codemode=search_and_execute")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    // Code Mode always returns exactly two tools: gateway_search and gateway_execute
    assert_eq!(
        tools.len(),
        2,
        "Code Mode must return exactly 2 tools; got: {}",
        tools.len()
    );
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(
        names.contains(&"gateway_search"),
        "gateway_search must be present"
    );
    assert!(
        names.contains(&"gateway_execute"),
        "gateway_execute must be present"
    );
}

#[tokio::test]
async fn tools_list_with_wrong_codemode_value_ignores_param() {
    // GIVEN: Code Mode disabled, URL has ?codemode=wrong_value
    let router = create_router(test_router_app_state_with_code_mode(false));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp?codemode=wrong_value")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    // Should NOT be Code Mode — wrong value is ignored, standard tools returned
    assert!(
        tools.len() != 2
            || !tools.iter().all(|t| matches!(
                t["name"].as_str().unwrap_or(""),
                "gateway_search" | "gateway_execute"
            )),
        "Wrong codemode value should not activate Code Mode"
    );
}

#[tokio::test]
async fn tools_list_static_code_mode_unaffected_by_absent_param() {
    // GIVEN: Code Mode enabled in static config, no URL param
    let router = create_router(test_router_app_state_with_code_mode(true));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    assert_eq!(
        tools.len(),
        2,
        "Static Code Mode must always return exactly 2 tools"
    );
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"gateway_search"));
    assert!(names.contains(&"gateway_execute"));
}

// ── Origin / Host validation (CWE-346) ────────────────────────────────────────
//
// The gateway binds loopback and, with auth off, treats every caller as an
// anonymous identity. A web page can therefore reach `/mcp` either by rebinding
// a hostname to 127.0.0.1 or, because the handler never checks Content-Type, by
// a preflight-free cross-origin POST. A browser always sends `Origin`; a CLI MCP
// client never does. That asymmetry is the gate.

fn mcp_request_with(header: Option<(&str, &str)>) -> axum::http::Request<axum::body::Body> {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");
    if let Some((name, value)) = header {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn mcp_rejects_foreign_origin() {
    let router = create_router(test_router_app_state());
    let response = router
        .oneshot(mcp_request_with(Some((
            "origin",
            "http://attacker.example",
        ))))
        .await
        .unwrap();
    // Must fail on the gate, not on a parse error: the body above is valid.
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_allows_absent_origin() {
    let router = create_router(test_router_app_state());
    let response = router.oneshot(mcp_request_with(None)).await.unwrap();
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a CLI MCP client sends no Origin and must keep working"
    );
}

#[tokio::test]
async fn mcp_allows_bind_origin() {
    let router = create_router(test_router_app_state());
    let response = router
        .oneshot(mcp_request_with(Some(("origin", "http://127.0.0.1:39400"))))
        .await
        .unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_rejects_foreign_host() {
    let router = create_router(test_router_app_state());
    // No Origin at all: this is the rebinding shape, where the browser's own
    // Origin may be suppressed but Host carries the attacker's name.
    let response = router
        .oneshot(mcp_request_with(Some(("host", "attacker.example"))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn health_is_reachable_by_a_probe_and_refused_cross_site() {
    // No exemption. A monitoring probe sends no Origin and passes on the
    // general rules; a web page sends one and is refused like anywhere else,
    // so the boundary is the whole port with no special cases to audit.
    let router = create_router(test_router_app_state());

    let probe = axum::http::Request::builder()
        .method("GET")
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(probe).await.unwrap().status(),
        StatusCode::OK
    );

    let page = axum::http::Request::builder()
        .method("GET")
        .uri("/health")
        .header("origin", "http://attacker.example")
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        router.oneshot(page).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn anonymous_denied_admin_meta_tools() {
    use super::authorization::{ADMIN_META_TOOLS, require_admin_tool_access};
    let anon = crate::gateway::auth::anonymous_client();

    // Iterates the one list rather than a copy of it. The copy had drifted:
    // it still named two tools removed from the admin set, and the assertion
    // did not notice because `require_admin_tool_access` never reads the tool
    // name — it answers from the client's admin bit alone, so the loop asserted
    // the same thing once per entry whatever the entries were.
    for tool in ADMIN_META_TOOLS {
        assert!(
            super::authorization::is_admin_meta_tool(tool),
            "{tool} is in the admin list, so the predicate must say so"
        );
        assert!(
            require_admin_tool_access(Some(&anon), tool).is_err(),
            "anonymous must not reach {tool}"
        );
    }

    for session_local in ["gateway_set_profile", "gateway_set_state"] {
        assert!(
            !super::authorization::is_admin_meta_tool(session_local),
            "{session_local} writes only the caller's own session and must stay \
             out of the admin list"
        );
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

#[tokio::test]
async fn mcp_rejects_no_cors_get_from_a_page() {
    // The Fetch standard omits `Origin` from a no-CORS GET, so the
    // absent-Origin allowance would admit it. Fetch Metadata is what catches it.
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("sec-fetch-site", "cross-site")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_rejects_opaque_origin() {
    // A sandboxed iframe and a cross-site redirect both send `Origin: null`.
    let router = create_router(test_router_app_state());
    let response = router
        .oneshot(mcp_request_with(Some(("origin", "null"))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_allows_same_origin_browser_request() {
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:39400")
        .header("sec-fetch-site", "same-origin")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_rejects_foreign_authority_without_host_header() {
    // HTTP/2 carries the target in the `:authority` pseudo-header, not `Host`,
    // so a gate that reads only `Host` is inert over HTTP/2 and the rebinding
    // refusal disappears on exactly the protocol browsers prefer.
    let router = create_router(test_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("http://attacker.example/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    assert!(
        request.headers().get(axum::http::header::HOST).is_none(),
        "the case is only meaningful with no Host header present"
    );
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Build router state whose live config binds a wildcard address.
fn wildcard_bind_app_state() -> Arc<AppState> {
    let state = test_router_app_state();
    let mut config = crate::config::Config::default();
    config.server.host = "0.0.0.0".to_string();
    state.live_config.set(config);
    state
}

#[tokio::test]
async fn wildcard_bind_refuses_a_rebound_name_through_the_middleware() {
    // The policy unit tests assert the rule; this asserts the middleware
    // actually applies it on the real route, so the wildcard allowance cannot
    // widen back into a rebinding path during a refactor.
    let router = create_router(wildcard_bind_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "attacker.example")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wildcard_bind_admits_a_numeric_host_through_the_middleware() {
    let router = create_router(wildcard_bind_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "192.168.1.5:39400")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn merged_routes_are_behind_the_origin_gate() {
    // Routes merged after the layer stack would skip the gate entirely. That
    // set includes the key server's token exchange and revocation endpoints,
    // JWKS, the protected-resource metadata, /metrics and the UI HTML.
    let router = create_router(test_router_app_state());
    for uri in [
        "/.well-known/jwks.json",
        "/.well-known/oauth-protected-resource",
        "/metrics",
    ] {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .header("origin", "http://attacker.example")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} must be refused for a cross-site Origin"
        );
    }
}

#[tokio::test]
async fn a_route_merged_after_create_router_is_still_gated() {
    // Round 4 fixed merges INSIDE create_router; a merge OUTSIDE it reopened
    // the same hole for the webhook routes. The guard is therefore applied to
    // extra routes handed in, not to whatever happened to be merged by then.
    let extra = axum::Router::new().route(
        "/webhooks/test",
        axum::routing::post(|| async { axum::http::StatusCode::OK }),
    );
    let router = create_router_with(test_router_app_state(), Some(extra));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/webhooks/test")
        .header("origin", "http://attacker.example")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_numeric_origin_must_match_the_request_authority() {
    // Round 6 admitted ANY numeric Origin on a non-loopback bind, reasoning
    // that a browser sets Origin from where the page came so an attacker
    // cannot claim one. An attacker can: host the page on a public IP and the
    // browser sends that address as the Origin. It is only safe when it names
    // the gateway the request is actually addressed to.
    let router = create_router(wildcard_bind_app_state());

    let attacker = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "192.168.1.5:39400")
        .header("origin", "http://203.0.113.5")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(attacker).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a numeric Origin naming another host must be refused"
    );

    let own_page = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("host", "192.168.1.5:39400")
        .header("origin", "http://192.168.1.5:39400")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string(),
        ))
        .unwrap();
    assert_ne!(
        router.oneshot(own_page).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "the gateway's own page must still work"
    );
}

// ===========================================================================
// MIK-7252 — a playbook step faces the invoking caller's real scope.
//
// The meta-layer cases in `meta_mcp::authz_tests` prove the chokepoint is
// reached, using a test authorizer. These prove the thing that actually
// matters: the REAL policy — `RouterAuthorizer` over an `AuthenticatedClient`
// — refuses a playbook step, which no test double can demonstrate.
// ===========================================================================

use crate::gateway::auth::AuthenticatedClient;

/// A client restricted to one backend, with optional tool scoping.
fn scoped_client(
    name: &str,
    backends: Vec<String>,
    allowed_tools: Option<Vec<String>>,
) -> AuthenticatedClient {
    AuthenticatedClient {
        name: name.to_string(),
        rate_limit: 0,
        backends,
        allowed_tools,
        denied_tools: None,
        admin: false,
        principal: format!("principal-{name}"),
        authenticated: true,
    }
}

/// As [`run_step_as`], but carrying a certificate or agent identity.
///
/// Separate rather than a fourth parameter on `run_step_as`, so the many cases
/// that have no such identity are not obliged to say `None, None` and mean it.
async fn run_step_with_identity(
    state: &Arc<AppState>,
    client: &AuthenticatedClient,
    cert_identity: Option<&crate::mtls::CertIdentity>,
    oauth_agent_identity: Option<&crate::gateway::oauth::AgentIdentity>,
    server: &str,
    tool: &str,
) -> JsonRpcResponse {
    let yaml = format!(
        "name: scoped\ndescription: one step\non_error: abort\nsteps:\n  - name: step\n    server: {server}\n    tool: {tool}\n"
    );
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(&yaml).expect("playbook fixture must parse");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    state.meta_mcp.set_playbook_engine(engine);

    let authorizer = super::authorization::RouterAuthorizer {
        state: state.as_ref(),
        client: Some(client),
        oauth_agent_identity,
        cert_identity,
        principal: super::authorization::refusal_principal(
            Some(client),
            oauth_agent_identity,
            cert_identity,
        ),
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authorizer: &authorizer,
        api_key_name: Some(client.name.as_str()),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: client.admin,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    };
    state
        .meta_mcp
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_run_playbook",
            serde_json::json!({ "name": "scoped", "arguments": {} }),
            None,
            caller,
        )
        .await
}

/// Run a one-step playbook through the production path, with the real router
/// authorizer built exactly as `handlers.rs` builds it.
///
/// Most cases carry no certificate or agent identity, so [`run_step_as`] wraps
/// this and passes `None` for both rather than making every call site say so.
async fn run_step_as(
    state: &Arc<AppState>,
    client: &AuthenticatedClient,
    server: &str,
    tool: &str,
) -> JsonRpcResponse {
    run_step_with_identity(state, client, None, None, server, tool).await
}

/// The text a dispatch came back with, whether it succeeded or failed.
///
/// A refusal surfaces as a JSON-RPC error; a network failure surfaces inside a
/// successful envelope. Both are strings to assert against — every case below
/// asserts what the response WAS, not merely that it failed.
fn response_text(response: &JsonRpcResponse) -> String {
    response.error.as_ref().map_or_else(
        || {
            response
                .result
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        },
        |e| e.message.clone(),
    )
}

#[tokio::test]
async fn authz_1_playbook_step_outside_client_backend_scope_is_refused() {
    let state = test_router_app_state_with_backend(http_backend_at("beta", "http://127.0.0.1:1/"));
    let client = scoped_client("scoped", vec!["alpha".to_string()], None);

    let response = run_step_as(&state, &client, "beta", "read").await;

    let msg = response_text(&response);
    assert!(
        response.error.is_some(),
        "a step outside the client's backend scope must be refused: {msg}"
    );
    assert!(
        msg.contains("beta"),
        "the refusal must name the backend it refused: {msg}"
    );
    assert!(
        msg.contains("scoped"),
        "and the client it refused for: {msg}"
    );
}

#[tokio::test]
async fn authz_1a_playbook_step_inside_client_backend_scope_is_not_refused() {
    let state = test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    let client = scoped_client("scoped", vec!["alpha".to_string()], None);

    let response = run_step_as(&state, &client, "alpha", "read").await;

    // The backend is unreachable, so this fails at the network — deliberately.
    // What must NOT appear is an authorization refusal: the point is that the
    // scope check passed and the call proceeded to dispatch.
    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "a permitted backend must reach dispatch rather than be refused: {}",
        response_text(&response)
    );
}

#[tokio::test]
async fn authz_2_playbook_step_outside_client_tool_scope_is_refused() {
    let state = test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    let client = scoped_client(
        "scoped",
        vec!["alpha".to_string()],
        Some(vec!["safe_*".to_string()]),
    );

    let response = run_step_as(&state, &client, "alpha", "danger_tool").await;

    let msg = response_text(&response);
    assert!(
        response.error.is_some(),
        "a step outside the client's tool allowlist must be refused: {msg}"
    );
    assert!(
        msg.contains("danger_tool"),
        "the refusal must name the tool: {msg}"
    );
}

#[tokio::test]
async fn authz_2a_playbook_step_inside_client_tool_scope_is_not_refused() {
    let state = test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    let client = scoped_client(
        "scoped",
        vec!["alpha".to_string()],
        Some(vec!["safe_*".to_string()]),
    );

    let response = run_step_as(&state, &client, "alpha", "safe_read").await;

    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "a permitted tool must reach dispatch rather than be refused: {}",
        response_text(&response)
    );
}

/// A refusal only the chokepoint can see maps to 403.
///
/// The router gate answers 403 for the shapes it inspects. A playbook step is
/// not one of them — its targets never appear in the request — so before the
/// status travelled on the refusal, a denied playbook came back HTTP 200 with
/// the refusal buried in the body, telling every caller and intermediary that
/// the call had succeeded.
///
/// NOT end to end, and the name no longer claims it is. This drives the meta
/// dispatch and asserts the mapping `refusal_status` performs; it does not
/// drive the axum handler, so it would stay green if the handler stopped
/// calling that mapping. The handler's use of it is one line
/// (`let status = refusal_status(&response).unwrap_or(StatusCode::OK)`), and
/// its control is code review, which is stated here rather than implied by a
/// test name.
#[tokio::test]
async fn authz_playbook_denial_maps_to_forbidden() {
    let state = test_router_app_state_with_backend(http_backend_at("beta", "http://127.0.0.1:1/"));
    let client = scoped_client("scoped", vec!["alpha".to_string()], None);

    let response = run_step_as(&state, &client, "beta", "read").await;
    assert!(
        response.error.is_some(),
        "the step must be refused: {}",
        response_text(&response)
    );
    // Asserted through the mapping the handler applies, which reads the status
    // the dispatch layer stamped onto the error. Handing a status to
    // `build_response` instead would prove only that it uses its argument.
    assert_eq!(
        super::handlers::refusal_status(&response),
        Some(StatusCode::FORBIDDEN),
        "a refused dispatch must not answer 200"
    );

    let http = super::helpers::build_response(response, "sess-authz", StatusCode::FORBIDDEN);
    assert_eq!(http.status(), StatusCode::FORBIDDEN);
}

/// The mapping must not reclassify an error that is not a refusal.
///
/// Choosing the control took two attempts, and both failures are worth
/// recording. An unreachable backend does not work: dispatch returns a
/// SUCCESSFUL envelope carrying `isError`, so no JSON-RPC error exists and the
/// row could not fail whatever the mapping did. An invalid tool name does not
/// work either, for a more interesting reason — `authorize_tool_target`
/// validates the name first and returns a refusal, so a malformed name IS a
/// refusal in this codebase's model and the router gate has always answered it
/// 403. That is pre-existing behaviour and out of scope here; it is recorded
/// because it looks like a bug in the mapping and is not.
///
/// An unknown playbook name is the control: a genuine JSON-RPC error, raised
/// before any authorizer sees anything, so this row fails if the stamp were
/// ever applied to every error rather than to refusals alone.
#[tokio::test]
async fn authz_ordinary_error_is_not_reclassified_as_forbidden() {
    let state = test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    let client = scoped_client("scoped", vec![], None);

    let authorizer = super::authorization::RouterAuthorizer {
        state: state.as_ref(),
        client: Some(&client),
        oauth_agent_identity: None,
        cert_identity: None,
        principal: super::authorization::refusal_principal(Some(&client), None, None),
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authorizer: &authorizer,
        api_key_name: Some(client.name.as_str()),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    };
    let response = state
        .meta_mcp
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_run_playbook",
            serde_json::json!({ "name": "no_such_playbook", "arguments": {} }),
            None,
            caller,
        )
        .await;

    assert!(
        response.error.is_some(),
        "the control must actually produce a JSON-RPC error, or it cannot \
         fail: {}",
        response_text(&response)
    );
    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "only an authorization refusal may be mapped to 403: {}",
        response_text(&response)
    );
}

/// Four refusal branches carry the stamp: backend scope, tool scope, global
/// policy and invalid tool name.
///
/// The claim "a refusal answers 403" is only as good as the narrowest branch
/// that carries it, and each of these is minted in a different place. The
/// certificate and agent-scope branches are pinned by `authz_10` and
/// `authz_11`, which assert `refusal_status` directly; the SSRF branch has no
/// case, and the name says four rather than "every" so that gap is visible.
#[tokio::test]
async fn authz_four_refusal_branches_carry_the_status() {
    let scoped_state =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));

    let tool_scoped = scoped_client(
        "scoped",
        vec!["alpha".to_string()],
        Some(vec!["safe_*".to_string()]),
    );
    let tool_refusal = run_step_as(&scoped_state, &tool_scoped, "alpha", "danger_tool").await;
    assert_eq!(
        super::handlers::refusal_status(&tool_refusal),
        Some(StatusCode::FORBIDDEN),
        "a tool-allowlist refusal must answer 403: {}",
        response_text(&tool_refusal)
    );

    let backend_scoped = scoped_client("scoped", vec!["alpha".to_string()], None);
    let backend_state =
        test_router_app_state_with_backend(http_backend_at("beta", "http://127.0.0.1:1/"));
    let backend_refusal = run_step_as(&backend_state, &backend_scoped, "beta", "read").await;
    assert_eq!(
        super::handlers::refusal_status(&backend_refusal),
        Some(StatusCode::FORBIDDEN),
        "a backend-scope refusal must answer 403: {}",
        response_text(&backend_refusal)
    );

    // Global policy is minted in a third place, and an invalid tool name in a
    // fourth. The test's name claims EVERY branch, so it has to mean it.
    let mut policy_state =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    {
        let state_mut = Arc::get_mut(&mut policy_state).expect("sole owner during setup");
        state_mut.tool_policy = Arc::new(crate::security::ToolPolicy::from_config(
            &crate::security::ToolPolicyConfig {
                enabled: true,
                deny: vec!["globally_blocked".to_string()],
                ..crate::security::ToolPolicyConfig::default()
            },
        ));
    }
    let unrestricted = scoped_client("scoped", vec![], None);
    let policy_refusal =
        run_step_as(&policy_state, &unrestricted, "alpha", "globally_blocked").await;
    assert_eq!(
        super::handlers::refusal_status(&policy_refusal),
        Some(StatusCode::FORBIDDEN),
        "a global-policy refusal must answer 403: {}",
        response_text(&policy_refusal)
    );

    let name_refusal = run_step_as(&policy_state, &unrestricted, "alpha", "bad/name").await;
    assert_eq!(
        super::handlers::refusal_status(&name_refusal),
        Some(StatusCode::FORBIDDEN),
        "an invalid tool name is refused by the authorizer, so it answers 403 \
         like any other refusal: {}",
        response_text(&name_refusal)
    );
}

/// AUTHZ.3 — a playbook step hitting a tool denied by GLOBAL policy is
/// refused.
///
/// Distinct from AUTHZ.1 and AUTHZ.2 on purpose: the policy lives on
/// `AppState`, not on the client, so a fix that threaded only the caller's
/// identity into the chokepoint passes those two and fails this one.
#[tokio::test]
async fn authz_3_playbook_step_denied_by_global_tool_policy_is_refused() {
    let mut state =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        state_mut.tool_policy = Arc::new(crate::security::ToolPolicy::from_config(
            &crate::security::ToolPolicyConfig {
                enabled: true,
                deny: vec!["globally_blocked".to_string()],
                ..crate::security::ToolPolicyConfig::default()
            },
        ));
    }
    let client = scoped_client("scoped", vec![], None);

    let response = run_step_as(&state, &client, "alpha", "globally_blocked").await;

    let msg = response_text(&response);
    assert!(
        response.error.is_some(),
        "a globally denied tool must be refused even for an unrestricted client: {msg}"
    );
    assert!(
        msg.contains("globally_blocked"),
        "the refusal must name the tool: {msg}"
    );
}

/// AUTHZ.3a — the same policy must not refuse a permitted tool.
#[tokio::test]
async fn authz_3a_global_policy_does_not_refuse_a_permitted_tool() {
    let mut state =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        state_mut.tool_policy = Arc::new(crate::security::ToolPolicy::from_config(
            &crate::security::ToolPolicyConfig {
                enabled: true,
                deny: vec!["globally_blocked".to_string()],
                ..crate::security::ToolPolicyConfig::default()
            },
        ));
    }
    let client = scoped_client("scoped", vec![], None);

    let response = run_step_as(&state, &client, "alpha", "permitted").await;

    assert_eq!(
        super::handlers::refusal_status(&response),
        None,
        "a permitted tool must reach dispatch rather than be refused: {}",
        response_text(&response)
    );
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

    let api_key = scoped_client("keyed", vec![], None);
    assert_eq!(
        super::authorization::refusal_principal(Some(&api_key), None, None).as_deref(),
        Some("keyed"),
        "an API-key caller is named by its client name"
    );

    let agent = AgentIdentity {
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
        authenticated: false,
        ..scoped_client("public", vec![], None)
    };
    assert_eq!(
        super::authorization::refusal_principal(Some(&anonymous), None, None),
        None,
        "an identity that presented no credential is genuinely unattributed, \
         and must not borrow the name of a configured client"
    );
}

/// AUTHZ.10 / 10a — certificate policy reaches a playbook step.
///
/// The allow row is not decoration. `MtlsPolicy::evaluate` returns `Deny` for a
/// `None` identity once the policy is enabled, so the refusal row stays green
/// even if the certificate identity were dropped on the way to the chokepoint
/// and never consulted. Only a certificate the policy PERMITS proves the
/// identity actually arrived.
#[tokio::test]
async fn authz_10_certificate_policy_refuses_and_permits_a_playbook_step() {
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
    use crate::mtls::{CertIdentity, MtlsPolicy};

    let policy = Arc::new(MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        policies: vec![PolicyRuleConfig {
            match_criteria: CertMatchConfig {
                cn: Some("trusted-machine".to_string()),
                ..CertMatchConfig::default()
            },
            allow: ToolScopeConfig {
                backends: vec!["alpha".to_string()],
                tools: vec!["permitted".to_string()],
            },
            deny: ToolScopeConfig::default(),
        }],
        ..MtlsConfig::default()
    }));

    let mut state =
        test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        state_mut.mtls_policy = Arc::clone(&policy);
    }
    let client = scoped_client("scoped", vec![], None);
    let cert = CertIdentity {
        common_name: Some("trusted-machine".to_string()),
        display_name: "trusted-machine".to_string(),
        ..CertIdentity::default()
    };

    let refused =
        run_step_with_identity(&state, &client, Some(&cert), None, "alpha", "blocked").await;
    assert_eq!(
        super::handlers::refusal_status(&refused),
        Some(StatusCode::FORBIDDEN),
        "a tool outside the certificate's allowed scope must be refused: {}",
        response_text(&refused)
    );

    let permitted =
        run_step_with_identity(&state, &client, Some(&cert), None, "alpha", "permitted").await;
    assert_eq!(
        super::handlers::refusal_status(&permitted),
        None,
        "a tool the certificate permits must reach dispatch — without this the \
         refusal above passes with the identity dropped entirely: {}",
        response_text(&permitted)
    );
}

/// AUTHZ.11 / 11a — agent scope reaches a playbook step.
///
/// Same fail-closed trap as the certificate case, and worse: with agent auth
/// enabled, a MISSING identity is refused outright, so the deny row alone stays
/// green even if the identity never reaches the chokepoint. The allow row is
/// what proves it arrives.
#[tokio::test]
async fn authz_11_agent_scope_refuses_and_permits_a_playbook_step() {
    use crate::gateway::oauth::{AgentIdentity, Scope};

    let mut state = test_router_app_state_with_agent_auth_enabled();
    {
        let state_mut = Arc::get_mut(&mut state).expect("sole owner during setup");
        let _ = state_mut
            .backends
            .register(http_backend_at("alpha", "http://127.0.0.1:1/"));
    }
    let client = scoped_client("scoped", vec![], None);

    // Scoped to one tool on one backend.
    let agent = AgentIdentity {
        client_id: "agent-1".to_string(),
        agent_name: "runner".to_string(),
        scopes: vec![Scope::parse("tools:alpha:permitted:*").expect("scope must parse")],
        raw_scopes: vec!["tools:alpha:permitted:*".to_string()],
    };

    let refused =
        run_step_with_identity(&state, &client, None, Some(&agent), "alpha", "blocked").await;
    assert_eq!(
        super::handlers::refusal_status(&refused),
        Some(StatusCode::FORBIDDEN),
        "a tool outside the agent's scope must be refused: {}",
        response_text(&refused)
    );

    let permitted =
        run_step_with_identity(&state, &client, None, Some(&agent), "alpha", "permitted").await;
    assert_eq!(
        super::handlers::refusal_status(&permitted),
        None,
        "a tool the agent's scope permits must reach dispatch — without this \
         the refusal above passes with the identity dropped entirely: {}",
        response_text(&permitted)
    );

    // And with NO agent identity at all, agent auth being enabled must refuse:
    // the check is fail-closed, and this pins that it still is.
    let anonymous = run_step_with_identity(&state, &client, None, None, "alpha", "permitted").await;
    assert_eq!(
        super::handlers::refusal_status(&anonymous),
        Some(StatusCode::FORBIDDEN),
        "agent auth enabled with no agent identity must refuse: {}",
        response_text(&anonymous)
    );
}

/// An ordinary error must not carry the HTTP-status stamp.
///
/// The stamp is a plain JSON key on the error's `data`. Today nothing but the
/// gateway writes that field — `JsonRpcResponse::error` starts it at `None` —
/// but a future path forwarding a backend's error data would otherwise let a
/// backend choose the gateway's HTTP status. The response builder assigns both
/// arms, and this pins that: a non-refusal comes back with no `data` at all.
#[tokio::test]
async fn authz_ordinary_error_carries_no_status_stamp() {
    let state = test_router_app_state_with_backend(http_backend_at("alpha", "http://127.0.0.1:1/"));
    let client = scoped_client("scoped", vec![], None);

    let authorizer = super::authorization::RouterAuthorizer {
        state: state.as_ref(),
        client: Some(&client),
        oauth_agent_identity: None,
        cert_identity: None,
        principal: super::authorization::refusal_principal(Some(&client), None, None),
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        authorizer: &authorizer,
        api_key_name: Some(client.name.as_str()),
        agent_id: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
    };
    let response = state
        .meta_mcp
        .handle_tools_call(
            RequestId::Number(1),
            "gateway_run_playbook",
            serde_json::json!({ "name": "no_such_playbook", "arguments": {} }),
            None,
            caller,
        )
        .await;

    let error = response.error.as_ref().expect("the control must error");
    assert!(
        error.data.is_none(),
        "an ordinary error must carry no data, so nothing can be mistaken for \
         a status stamp: {:?}",
        error.data
    );
}
/// The admin gate covers the tools with global effect, and only those.
///
/// Both halves matter. Gating too little leaves a shared control open to any
/// caller; gating too much breaks a legitimate workflow while stopping nothing,
/// which is what happened to `gateway_set_profile`: it was announced as
/// admin-only in the changelog, was never tested, and was bypassable anyway
/// because `handle_initialize` binds a caller-supplied profile through the
/// identical call with no credential.
#[test]
fn admin_gate_covers_global_tools_and_not_session_local_ones() {
    for global in [
        "gateway_kill_server",
        "gateway_revive_server",
        "gateway_reload_config",
        "gateway_reload_capabilities",
    ] {
        assert!(
            super::authorization::is_admin_meta_tool(global),
            "{global} changes the gateway for every session and must need a credential"
        );
    }

    for session_local in ["gateway_set_profile", "gateway_set_state"] {
        assert!(
            !super::authorization::is_admin_meta_tool(session_local),
            "{session_local} writes only the caller's own session and cannot widen \
             what that caller reaches, so gating it blocks the documented path \
             while leaving the equivalent one at initialize open"
        );
    }
}

/// A non-admin caller can switch its own routing profile.
///
/// The regression guard for the half above that is easy to re-break: someone
/// reading `set_profile` as "administrative" and adding it back to the gate.
#[tokio::test]
async fn non_admin_may_set_its_own_routing_profile() {
    let router = create_router(test_router_app_state_with_auth(&scoped_auth_config(false)));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .header("mcp-session-id", "sess-profile")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "gateway_set_profile",
                    "arguments": { "profile": "does-not-exist" }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    // The profile name is deliberately unknown: the assertion is about the
    // GATE, not about profile resolution. A refusal for lacking admin is what
    // must not happen; being told the profile is unknown means the call got
    // past the gate and reached the tool.
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a non-admin must not be refused its own session's routing profile"
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let message = json["error"]["message"].as_str().unwrap_or_default();
    assert!(
        !message.contains("admin access"),
        "and must not be told it needs admin: {message}"
    );
}

// ── Session-targeted prompts reach the session that asked ─────────────

#[tokio::test]
async fn sampling_prompt_is_delivered_to_the_requesting_session() {
    // GIVEN: a live session listening on its own notification stream
    let state = test_router_app_state();
    let (session_id, mut rx) = state
        .multiplexer
        .get_or_create_session_for(Some("gw-caller"), "unauthenticated:anonymous");
    let router = create_router(Arc::clone(&state));

    // WHEN: that session asks the gateway for a sampling round trip
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-session-id", session_id.as_str())
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "sample-1",
                "method": "sampling/createMessage",
                "params": {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
                    "maxTokens": 16
                }
            })
            .to_string(),
        ))
        .unwrap();
    let call = tokio::spawn(async move { router.oneshot(request).await.unwrap() });

    // THEN: the prompt arrives on that session's stream
    let delivered = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the prompt must reach the requesting session, not a literal \"broadcast\" id")
        .expect("the notification stream must stay open");
    assert_eq!(delivered.data["method"], "sampling/createMessage");

    call.abort();
}

#[tokio::test]
async fn sampling_without_a_live_stream_fails_instead_of_hanging() {
    // GIVEN: a caller that only POSTs — it never opened a notification stream
    let state = test_router_app_state();
    let router = create_router(Arc::clone(&state));

    // WHEN: it asks the gateway for a sampling round trip
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "sample-nostream",
                "method": "sampling/createMessage",
                "params": {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
                    "maxTokens": 16
                }
            })
            .to_string(),
        ))
        .unwrap();

    // THEN: it is told there is nobody to ask, rather than waiting out the
    // 120-second response timeout on a prompt only the handler could hear.
    let response = tokio::time::timeout(Duration::from_secs(5), router.oneshot(request))
        .await
        .expect("an undeliverable prompt must fail fast, not hang until the timeout")
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], -32002, "body: {body}");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("No sampling-capable client connected"),
        "body: {body}"
    );
}

/// The fixture with the 2026 era switched on.
///
/// Without it every modern request stops at `unsupported protocol version`,
/// and a test asserting an absence — no session header, no profile switch —
/// passes on the refusal rather than on the behaviour it names.
fn modern_router_app_state() -> Arc<AppState> {
    let mut config = crate::config::Config::default();
    config.server.modern_protocol = true;
    test_router_app_state_with(StreamingConfig::default(), config)
}

/// A modern request gets no session, even when it offers one.
///
/// The pin under `meta_mcp::session_key`, which reads an empty session id as
/// "no session" and refuses the routing-profile meta-tools on that basis. That
/// reading is only sound while this branch holds: mint a session here and the
/// profile becomes per-connection state again, silently reopening ORDER.2
/// (`docs/requirements/RELEASE-4.0.0-requirements.md`). The response header is
/// the observable side of it — `attach_session_header` emits nothing for an
/// empty id, so a minted session would show up here as a header.
#[tokio::test]
async fn ac_order_2_a_modern_request_is_given_no_session_even_when_it_offers_one() {
    let router = create_router(modern_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        // The modern path requires the method in a header as well as the body.
        .header("mcp-method", "tools/list")
        // Offered deliberately: the modern path must decline it, not adopt it.
        .header("mcp-session-id", "sess-offered-by-client")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let session_header = response.headers().get("mcp-session-id").cloned();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // The request must actually REACH modern dispatch. An earlier draft of this
    // test omitted the mcp-method header and params._meta; the router rejected
    // it before dispatch, and a rejection carries no session header either — so
    // the assertion below passed while proving nothing. Pin the success first.
    assert!(
        json["result"]["tools"].is_array(),
        "the request must reach modern dispatch and list tools, or the header \
         assertion below is satisfied by a rejection instead of by the \
         behaviour under test: {json}"
    );
    assert!(
        session_header.is_none(),
        "a 2026-07-28 caller has no session; answering with one would give it \
         per-connection state its own revision removed"
    );
}

/// A modern caller cannot switch the routing profile, through the real stack.
///
/// The unit tests for this live in `meta_mcp::tests` and call the meta-tool
/// directly; this one goes in at the wire, so the refusal is known to survive
/// dispatch rather than only being reachable from inside. Which outcome is
/// asserted matters: "the tool set did not change" is satisfied both by a
/// closed path and by a write that silently landed somewhere useless, and only
/// the refusal tells the two apart.
#[tokio::test]
async fn ac_order_2_a_modern_caller_is_refused_gateway_set_profile() {
    let router = create_router(modern_router_app_state());
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        // The modern path requires the method in a header as well as the body.
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_set_profile")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "gateway_set_profile",
                    "arguments": { "profile": "research" },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // The refusal must arrive as a JSON-RPC error, not as a successful result
    // that happens to mention a session: the design decision is that the call
    // BREAKS for a modern client, and the shape is what the client sees.
    let message = json["error"]["message"].as_str().unwrap_or_else(|| {
        panic!("gateway_set_profile must be refused with a JSON-RPC error: {json}")
    });
    assert!(
        message.contains("no session"),
        "the refusal must say why, and the reason must be the true one — the \
         old text told the caller to send a session header, which on this path \
         cannot help: {message}"
    );
}
