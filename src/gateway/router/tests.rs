// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::helpers::{
    attach_session_header, build_accepted_response, build_error_response,
    build_http_error_response, build_json_response, extract_request_id, extract_tools_call_params,
    is_notification_method, parse_elicitation_params, parse_request,
};
use super::{AppState, create_router};
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
    })
}

fn test_router_app_state_with_backend(backend: Arc<Backend>) -> Arc<AppState> {
    let state = test_router_app_state();
    state.backends.register(backend);
    state
}

/// `AppState` whose shared Meta-MCP has provenance stamping enabled, for
/// exercising the direct `/mcp/{name}` route's rung-3 stamping (MIK-6905).
/// Uses a fixed signer key so a twin validator can verify the receipt.
fn test_router_app_state_with_provenance_backend(backend: Arc<Backend>) -> Arc<AppState> {
    let backends = Arc::new(BackendRegistry::new());
    backends.register(backend);
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
    backends.register(backend);
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

#[cfg(unix)]
const STRICT_SLOW_STDIO_FIXTURE: &str = r#"#!/bin/sh
events=$1
initialized=0
while IFS= read -r request; do
    case "$request" in
        *'"method":"initialize"'*)
            printf '%s\n' initialize >> "$events"
            if [ "$initialized" -eq 0 ]; then
                initialized=1
                sleep 0.20
                printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"strict-slow-screenpipe-fake","version":"9.9.9"},"instructions":"cached-handshake-sentinel"}}'
            else
                printf '%s\n' '{"jsonrpc":"2.0","id":2,"error":{"code":-32600,"message":"initialize called more than once"}}'
                exit 0
            fi
            ;;
        *'"method":"notifications/initialized"'*)
            printf '%s\n' notifications/initialized >> "$events"
            ;;
        *'"method":"tools/list"'*)
            printf '%s\n' tools/list >> "$events"
            printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"screenpipe_status","description":"deterministic fake","inputSchema":{"type":"object"}}]}}'
            exit 0
            ;;
    esac
done
"#;

#[cfg(unix)]
const SINGLETON_SLOW_STDIO_FIXTURE: &str = r#"#!/bin/sh
events=$1
singleton=$2
printf '%s\n' spawn >> "$events"
if ! mkdir "$singleton" 2>/dev/null; then
    printf '%s\n' duplicate-spawn >> "$events"
    exit 70
fi
trap 'rmdir "$singleton" 2>/dev/null || true' EXIT HUP INT TERM
while IFS= read -r request; do
    case "$request" in
        *'"method":"initialize"'*)
            printf '%s\n' initialize >> "$events"
            sleep 0.20
            printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"singleton-slow-screenpipe-fake","version":"1.0"}}}'
            ;;
        *'"method":"notifications/initialized"'*)
            printf '%s\n' notifications/initialized >> "$events"
            ;;
    esac
done
"#;

#[cfg(unix)]
fn write_stdio_fixture(
    workspace: &tempfile::TempDir,
    name: &str,
    source: &str,
) -> std::path::PathBuf {
    let path = workspace.path().join(name);
    std::fs::write(&path, source).expect("write fake stdio MCP server");
    path
}

#[cfg(unix)]
fn quote_stdio_fixture_path(path: &std::path::Path) -> String {
    let rendered = path.to_string_lossy();
    assert!(
        !rendered.contains('\''),
        "temporary fixture paths must be safely single-quotable"
    );
    format!("'{rendered}'")
}

#[cfg(unix)]
fn stdio_fixture_backend(
    name: &str,
    server: &std::path::Path,
    arguments: &[&std::path::Path],
    timeout: Duration,
) -> Arc<Backend> {
    let command_args = std::iter::once(server)
        .chain(arguments.iter().copied())
        .map(quote_stdio_fixture_path)
        .collect::<Vec<_>>()
        .join(" ");
    Arc::new(Backend::new(
        name,
        BackendConfig {
            transport: crate::config::TransportConfig::Stdio {
                command: format!("/bin/sh {command_args}"),
                cwd: None,
                protocol_version: None,
            },
            timeout,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

#[cfg(unix)]
fn direct_route_request(backend: &str, message: &Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(message.to_string()))
        .expect("build direct-route request")
}

#[cfg(unix)]
async fn direct_route_response_json(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read direct-route response");
    let json = serde_json::from_slice(&body).expect("parse direct-route response");
    (status, json)
}

#[cfg(unix)]
#[tokio::test]
async fn backend_handler_reuses_slow_stdio_handshake_for_direct_client() {
    // A strict stdio MCP server owns one protocol session. The gateway warms
    // that session itself, so a client reaching the direct route must receive
    // the original negotiated handshake without sending a second initialize
    // to the same child. The delay models slow-starting local servers such as
    // Screenpipe and must remain inside the backend's configured timeout.
    let workspace = tempfile::tempdir().expect("create fake stdio workspace");
    let events = workspace.path().join("events.log");
    let server = write_stdio_fixture(&workspace, "strict-slow-mcp.sh", STRICT_SLOW_STDIO_FIXTURE);
    let configured_timeout = Duration::from_secs(1);
    let backend = stdio_fixture_backend(
        "strict-slow",
        &server,
        &[events.as_path()],
        configured_timeout,
    );
    let router = create_router(test_router_app_state_with_backend(Arc::clone(&backend)));

    let client_init = direct_route_request(
        "strict-slow",
        &json!({
            "jsonrpc": "2.0",
            "id": "direct-client-init",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "direct-test-client", "version": "1.0" }
            }
        }),
    );
    let client_init_response =
        tokio::time::timeout(configured_timeout, router.clone().oneshot(client_init))
            .await
            .expect("slow backend must become ready inside its configured timeout")
            .expect("route initialize response");
    let (client_init_status, client_init_json) =
        direct_route_response_json(client_init_response).await;
    assert_eq!(client_init_status, StatusCode::OK);
    assert_eq!(client_init_json["id"], "direct-client-init");
    assert_eq!(
        client_init_json["result"]["protocolVersion"], "2025-11-25",
        "initialize response: {client_init_json}"
    );
    assert_eq!(
        client_init_json["result"]["serverInfo"]["name"],
        "strict-slow-screenpipe-fake"
    );
    assert_eq!(
        client_init_json["result"]["instructions"],
        "cached-handshake-sentinel"
    );
    assert!(
        client_init_json.get("error").is_none(),
        "direct client initialize must not expose a duplicate-handshake error: {client_init_json}"
    );

    let ready_notice = direct_route_request(
        "strict-slow",
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    let ready_notice_response = router
        .clone()
        .oneshot(ready_notice)
        .await
        .expect("route initialized notification");
    assert_eq!(ready_notice_response.status(), StatusCode::ACCEPTED);

    let tool_list = direct_route_request(
        "strict-slow",
        &json!({"jsonrpc": "2.0", "id": "direct-client-tools", "method": "tools/list"}),
    );
    let tool_list_response = router
        .oneshot(tool_list)
        .await
        .expect("route tools/list request");
    let (tool_list_status, tool_list_json) = direct_route_response_json(tool_list_response).await;
    assert_eq!(tool_list_status, StatusCode::OK);
    assert_eq!(tool_list_json["id"], "direct-client-tools");
    assert_eq!(
        tool_list_json["result"]["tools"][0]["name"],
        "screenpipe_status"
    );

    let observed = std::fs::read_to_string(&events).expect("read fake backend event log");
    assert_eq!(
        observed.lines().collect::<Vec<_>>(),
        ["initialize", "notifications/initialized", "tools/list"],
        "the direct client must reuse the gateway-owned stdio handshake"
    );

    backend.stop().await.expect("stop fake stdio backend");
}

#[cfg(unix)]
#[tokio::test]
async fn backend_handler_waits_for_inflight_slow_stdio_warm_start() {
    // Background warm-start and route-triggered startup must share the same
    // single-flight lock. This fixture models a slow singleton backend: a
    // second process cannot acquire its runtime directory and exits, which
    // would make the route falsely report failure while the first process is
    // still becoming ready inside the configured timeout.
    let workspace = tempfile::tempdir().expect("create singleton fake workspace");
    let events = workspace.path().join("events.log");
    let singleton = workspace.path().join("singleton.lock");
    let server = write_stdio_fixture(
        &workspace,
        "singleton-slow-mcp.sh",
        SINGLETON_SLOW_STDIO_FIXTURE,
    );
    let configured_timeout = Duration::from_secs(1);
    let backend = stdio_fixture_backend(
        "singleton-slow",
        &server,
        &[events.as_path(), singleton.as_path()],
        configured_timeout,
    );
    let router = create_router(test_router_app_state_with_backend(Arc::clone(&backend)));

    let warm_backend = Arc::clone(&backend);
    let warm_start = tokio::spawn(async move { warm_backend.start().await });

    tokio::time::timeout(configured_timeout, async {
        loop {
            let observed = std::fs::read_to_string(&events).unwrap_or_default();
            if observed.lines().any(|line| line == "initialize") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background warm-start must reach its deterministic delay");

    let warm_overlap_request = direct_route_request(
        "singleton-slow",
        &json!({
            "jsonrpc": "2.0",
            "id": "client-during-warm-start",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "readiness-test", "version": "1.0" }
            }
        }),
    );

    let route_outcome = match tokio::time::timeout(
        configured_timeout,
        router.oneshot(warm_overlap_request),
    )
    .await
    {
        Ok(Ok(response)) => Ok(direct_route_response_json(response).await),
        Ok(Err(error)) => Err(format!("route service failed: {error:?}")),
        Err(_) => Err("route did not become ready inside configured timeout".to_string()),
    };

    let warm_result = warm_start
        .await
        .map_err(|error| format!("warm-start task failed: {error}"))
        .and_then(|result| result.map_err(|error| format!("warm-start failed: {error}")));
    let stop_result = backend.stop().await;
    let observed = std::fs::read_to_string(&events).expect("read singleton event log");

    assert!(warm_result.is_ok(), "{warm_result:?}");
    assert!(stop_result.is_ok(), "failed to stop fake singleton backend");
    let (status, warm_route_json) = route_outcome.expect("direct route must wait for warm-start");
    assert_eq!(
        status,
        StatusCode::OK,
        "route response during warm-start: {warm_route_json}"
    );
    assert_eq!(warm_route_json["id"], "client-during-warm-start");
    assert_eq!(
        warm_route_json["result"]["serverInfo"]["name"],
        "singleton-slow-screenpipe-fake"
    );
    assert_eq!(
        observed.lines().collect::<Vec<_>>(),
        ["spawn", "initialize", "notifications/initialized"],
        "warm-start and route traffic must share one stdio process"
    );
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
    state.backends.register(backend);
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
    state
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
    state
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
    state
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
