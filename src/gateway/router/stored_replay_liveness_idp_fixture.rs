// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R6m support: a token-exchange backend whose `IdP` is the key-server `IdP`
//! pattern from `token_exchange_live_tests`, with `kill()` and `restart()`.

use std::sync::Arc;

use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt;

use axum::{Router, routing::get};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::config::{
    KeyServerConfig, KeyServerPolicyConfig, KeyServerProviderConfig, PolicyMatchConfig,
    PolicyScopesConfig,
};
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::key_server::policy::PolicyEngine;
use crate::key_server::{InMemoryTokenStore, KeyServer, OidcVerifier, handler::key_server_routes};

const GATEWAY_ASSERTION_ISSUER: &str = "mcp-gateway";

/// The in-process key-server `IdP`: `/auth/token` plus `/.well-known/jwks.json`.
pub(super) struct LiveIdp {
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    exchanges: Arc<AtomicUsize>,
}

impl LiveIdp {
    pub(super) async fn start(key: &Arc<GatewayKeyPair>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an ephemeral port");
        Self::serve(key, listener)
    }

    /// A fresh `IdP` on a killed one's address, so the gateway's
    /// configured endpoint reaches it again (the old listener is freed
    /// once its aborted task is dropped).
    pub(super) async fn restart(key: &Arc<GatewayKeyPair>, addr: std::net::SocketAddr) -> Self {
        for _ in 0..200 {
            if let Ok(listener) = TcpListener::bind(addr).await {
                return Self::serve(key, listener);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("rebind the IdP address {addr}");
    }

    fn serve(key: &Arc<GatewayKeyPair>, listener: TcpListener) -> Self {
        let config = KeyServerConfig {
            enabled: true,
            oidc: vec![KeyServerProviderConfig {
                issuer: GATEWAY_ASSERTION_ISSUER.to_string(),
                jwks_uri: Some(String::new()),
                discovery_url: None,
                auto_discover: false,
                audiences: Vec::new(),
                allowed_domains: Vec::new(),
            }],
            policies: vec![KeyServerPolicyConfig {
                match_criteria: PolicyMatchConfig {
                    domain: None,
                    issuer: GATEWAY_ASSERTION_ISSUER.to_string(),
                    email: None,
                    group: None,
                },
                scopes: PolicyScopesConfig {
                    backends: vec!["*".to_string()],
                    tools: vec!["*".to_string()],
                    rate_limit: 42,
                },
            }],
            ..KeyServerConfig::default()
        };
        let addr = listener.local_addr().expect("a local address");
        let mut config = config;
        config.oidc[0].jwks_uri = Some(format!("http://{addr}/.well-known/jwks.json"));
        let key_server = Arc::new(KeyServer {
            store: Arc::new(InMemoryTokenStore::new()),
            oidc: Arc::new(OidcVerifier::with_http_client(
                config.oidc.clone(),
                reqwest::Client::new(),
            )),
            policy: Arc::new(PolicyEngine::new(config.policies.clone())),
            config,
        });
        let jwks_router = Router::new()
            .route("/.well-known/jwks.json", get(jwks_handler))
            .with_state(Arc::clone(key));
        let exchanges = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&exchanges);
        let app =
            key_server_routes(key_server)
                .merge(jwks_router)
                .layer(axum::middleware::from_fn(
                    move |request: axum::extract::Request, next: axum::middleware::Next| {
                        if request.uri().path() == "/auth/token" {
                            seen.fetch_add(1, Ordering::SeqCst);
                        }
                        next.run(request)
                    },
                ));
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("the in-process IdP serves");
        });
        Self {
            addr,
            server,
            exchanges,
        }
    }

    pub(super) fn addr(&self) -> std::net::SocketAddr {
        self.addr
    }

    /// The token-exchange requests this `IdP` has received; the counter
    /// outlives [`Self::kill`].
    pub(super) fn exchanges(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.exchanges)
    }

    pub(super) fn endpoint(&self) -> String {
        format!("http://{}/auth/token", self.addr)
    }

    /// Kill the `IdP` outright: any later mint must fail without it.
    pub(super) fn kill(self) {
        self.server.abort();
    }
}

/// A counting backend transport: `tools/call` answers the marker;
/// listings answer the one tool without counting.
/// The token-exchange backend R6m calls: per-caller propagation, no
/// `account:`.
pub(super) const TX: &str = "tx";

/// The verified caller the `IdP` mints for.
pub(super) fn alice() -> crate::key_server::oidc::VerifiedIdentity {
    crate::key_server::oidc::VerifiedIdentity {
        subject: "alice-subject".to_string(),
        email: "alice@corp.example".to_string(),
        name: None,
        groups: vec!["eng".to_string()],
        issuer: "https://corp-idp.example".to_string(),
    }
}

/// The router over [`TX`]. Its counting transport serves `alice`'s
/// per-user slot (the binding token exchange mints under), so a mint that
/// succeeds reaches it. Returns the send counter and the directories to
/// keep alive.
pub(super) async fn gateway(
    key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
    endpoint: String,
    alice: &crate::key_server::oidc::VerifiedIdentity,
) -> (
    axum::Router,
    Arc<AtomicUsize>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    gateway_armed(key, endpoint, alice, |meta| meta).await
}

/// [`gateway`], with `arm` applied to the `MetaMcp` before it serves.
pub(super) async fn gateway_armed(
    key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
    endpoint: String,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    arm: impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
) -> (
    axum::Router,
    Arc<AtomicUsize>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    gateway_with(key, endpoint, alice, Requirement::Required, arm).await
}

/// Whether [`TX`]'s identity propagation is `required`.
#[derive(Clone, Copy)]
pub(super) enum Requirement {
    Required,
    /// A failed mint falls back to static credentials (IDP.5).
    Optional,
}

/// [`gateway_armed`] with the propagation requirement chosen.
pub(super) async fn gateway_with(
    key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
    endpoint: String,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    requirement: Requirement,
    arm: impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
) -> (
    axum::Router,
    Arc<AtomicUsize>,
    (tempfile::TempDir, tempfile::TempDir),
) {
    let (router, sends, dirs, _) = build(key, endpoint, alice, requirement, arm).await;
    (router, sends, dirs)
}

/// [`gateway`], also handing back the served `MetaMcp`, so a row can read
/// its plan executor entries (MIK-8406).
pub(super) async fn gateway_with_meta(
    key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
    endpoint: String,
    alice: &crate::key_server::oidc::VerifiedIdentity,
) -> (
    axum::Router,
    Arc<AtomicUsize>,
    (tempfile::TempDir, tempfile::TempDir),
    Arc<crate::gateway::meta_mcp::MetaMcp>,
) {
    build(key, endpoint, alice, Requirement::Required, |meta| meta).await
}

async fn build(
    key: &Arc<crate::gateway::oauth::GatewayKeyPair>,
    endpoint: String,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    requirement: Requirement,
    arm: impl FnOnce(crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp,
) -> (
    axum::Router,
    Arc<AtomicUsize>,
    (tempfile::TempDir, tempfile::TempDir),
    Arc<crate::gateway::meta_mcp::MetaMcp>,
) {
    use crate::config::{BackendConfig, TransportConfig};
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode, TokenExchangeStrategy,
    };
    const AUDIENCE: &str = "https://tx.internal";
    const SCOPE: &str = "backends:tx tools:read";
    let sends = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(crate::backend::Backend::new(
        TX,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: "https://tx.internal/mcp".to_string(),
                streamable_http: Some(true),
                protocol_version: None,
            },
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::TokenExchange,
                audience: AUDIENCE.to_string(),
                required: matches!(requirement, Requirement::Required),
                session_mode: SessionMode::Stateless,
                token_exchange_endpoint: Some(endpoint.clone()),
                token_exchange_scope: Some(SCOPE.to_string()),
            }),
            ..BackendConfig::r2_off()
        },
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let counting: Arc<dyn crate::transport::Transport> = Arc::new(Counting {
        sends: Arc::clone(&sends),
    });
    backend.set_transport_for_test(Arc::clone(&counting));
    // The per-user slot token exchange dispatches on, keyed as its
    // `exchange_cache_key` builds it: `cache_binding(subject, audience)`
    // widened by the length-prefixed endpoint and scope.
    let subject = alice.stable_actor_id();
    let binding = format!(
        "idp:{}:{}:{}:{}:{}:{}:{}:{}",
        subject.len(),
        subject,
        AUDIENCE.len(),
        AUDIENCE,
        endpoint.len(),
        endpoint,
        SCOPE.len(),
        SCOPE,
    );
    backend.set_pooled_transport_for_test(&crate::backend::PoolKey::PerUser { binding }, counting);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": super::TOOL,
        "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    backend.store_shared_tools_for_test(vec![tool]);
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(backend), "the fixture backend registers");

    let mut meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
    meta.set_identity_propagation(Arc::new(TokenExchangeStrategy::with_http_client(
        Arc::clone(key),
        300,
        reqwest::Client::new(),
    )));
    let log_dir = tempfile::tempdir().expect("a log directory");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(
            crate::security::transparency_log::TransparencyLogConfig {
                enabled: true,
                path: log_dir
                    .path()
                    .join("audit.jsonl")
                    .to_string_lossy()
                    .into_owned(),
                key_id: "r6m".to_string(),
                ..crate::security::transparency_log::TransparencyLogConfig::default()
            },
        ))
        .expect("the transparency log opens"),
    );
    meta.enable_transparency_log(Arc::clone(&log));
    let auth = crate::config::AuthConfig::default();
    let (mut state, store) =
        crate::gateway::router::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = registry;
    let meta = Arc::new(arm(meta));
    state_mut.meta_mcp = Arc::clone(&meta);
    state_mut.transparency_log = Some(log);
    (
        crate::gateway::router::create_router(state),
        sends,
        (log_dir, store),
        meta,
    )
}

/// A `tools/call` as `alice`, whose verified identity rides the request.
pub(super) async fn send_as(
    router: &axum::Router,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    params: Value,
) -> Value {
    send_method_as(router, alice, ("tools/call", "gateway_invoke"), params).await
}

/// [`send_as`] for any `(method, name)`.
pub(super) async fn send_method_as(
    router: &axum::Router,
    alice: &crate::key_server::oidc::VerifiedIdentity,
    (method, name): (&str, &str),
    params: Value,
) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(alice.clone());
    let response = router.clone().oneshot(request).await.expect("an answer");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

pub(super) struct Counting {
    pub(super) sends: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Counting {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        use crate::protocol::{JsonRpcResponse, RequestId};
        if method == "tools/call" {
            self.sends.fetch_add(1, Ordering::SeqCst);
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({"content": [{"type": "text", "text": super::MARKER}]}),
            ));
        }
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(
                RequestId::Number(1),
                json!({"tools": [{"name": super::TOOL, "inputSchema": {"type": "object"}}]}),
            ));
        }
        Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
    }

    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.request(method, params).await
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}
