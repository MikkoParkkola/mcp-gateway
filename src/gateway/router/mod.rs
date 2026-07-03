//! HTTP router and handlers

use std::sync::Arc;

use axum::{
    Router, middleware,
    routing::{get, post},
};
use tower_http::{catch_panic::CatchPanicLayer, compression::CompressionLayer, trace::TraceLayer};

use super::auth::{AuthState, ResolvedAuthConfig, auth_middleware};
use super::meta_mcp::MetaMcp;
use super::oauth::{AgentAuthState, GatewayKeyPair, agent_auth_middleware, jwks_handler};
use super::proxy::ProxyManager;
use super::streaming::NotificationMultiplexer;
use crate::backend::BackendRegistry;
use crate::config::{AgentIdentityConfig, StreamingConfig};
use crate::control_plane::ControlPlaneStore;
use crate::key_server::{KeyServer, handler::key_server_routes};
use crate::mtls::MtlsPolicy;
use crate::security::ToolPolicy;
#[cfg(feature = "firewall")]
use crate::security::firewall::Firewall;

mod authorization;
mod backend_handlers;
mod handlers;
pub(crate) mod helpers;
mod well_known;

#[cfg(test)]
mod tests;

/// Shared application state
#[allow(clippy::struct_excessive_bools)] // Independent feature flags; grouping into a substruct
// would force churn across every call site for no gain.
pub struct AppState {
    /// Backend registry
    pub backends: Arc<BackendRegistry>,
    /// Meta-MCP handler
    pub meta_mcp: Arc<MetaMcp>,
    /// Whether Meta-MCP is enabled
    pub meta_mcp_enabled: bool,
    /// Notification multiplexer for streaming
    pub multiplexer: Arc<NotificationMultiplexer>,
    /// Proxy manager for server-to-client capability forwarding
    pub proxy_manager: Arc<ProxyManager>,
    /// Streaming configuration
    pub streaming_config: StreamingConfig,
    /// Authentication configuration (static keys)
    pub auth_config: Arc<ResolvedAuthConfig>,
    /// Key server for OIDC-issued temporary tokens (optional)
    pub key_server: Option<Arc<KeyServer>>,
    /// Tool access policy
    pub tool_policy: Arc<ToolPolicy>,
    /// Certificate-based mTLS tool access policy
    pub mtls_policy: Arc<MtlsPolicy>,
    /// Whether input sanitization is enabled
    pub sanitize_input: bool,
    /// Whether SSRF protection is enabled for outbound URLs
    pub ssrf_protection: bool,
    /// Whether URLs declared in `backends:` config are pre-authorised
    /// (skip runtime SSRF check at proxy time). MIK-3529.
    pub trust_configured_backends: bool,
    /// In-flight request tracker for graceful drain.
    /// Each in-flight request holds a permit; shutdown waits for all permits
    /// to be returned.
    pub inflight: Arc<tokio::sync::Semaphore>,
    /// Agent auth state (issue #80 — agent-scoped JWT permissions).
    pub agent_auth: AgentAuthState,
    /// Gateway RSA key pair for JWKS endpoint.
    pub gateway_key_pair: Arc<GatewayKeyPair>,
    /// Configured capability directories (for Web UI capability management).
    /// Empty when the capability system is disabled.
    pub capability_dirs: Vec<String>,
    /// Path to the gateway config file on disk (enables API-driven config writes).
    /// `None` when the gateway was started without a config file path.
    pub config_path: Option<std::path::PathBuf>,
    /// Security firewall — bidirectional request/response scanning (RFC-0071).
    #[cfg(feature = "firewall")]
    pub firewall: Option<Arc<Firewall>>,
    /// Per-agent identity configuration (OWASP ASI03).
    pub agent_identity_config: AgentIdentityConfig,
    /// Durable control-plane store (grants/policies + governance audit log).
    /// `None` when the control-plane data directory could not be opened, in
    /// which case governance mutation routes return 503 (MIK-6686).
    pub control_plane_store: Option<Arc<dyn ControlPlaneStore>>,
    /// Live gateway configuration (hot-reloadable). The control-plane RBAC role
    /// mapping is read through this so a `/reload` that changes
    /// `control_plane.role_mapping` takes effect without a restart — e.g. a
    /// removed admin rule stops granting Admin (MIK-6702 CP.RELOAD.1). The
    /// config-reload loop swaps the inner `Arc<Config>` on every applied reload.
    pub live_config: Arc<crate::config_reload::LiveConfig>,
    /// SIEM export status, present when the export background task is running
    /// (MIK-6703). Drives the `EvidenceExport` entitlement + export-status route.
    pub export_status: Option<Arc<crate::control_plane::ExportStatus>>,
}

/// Create the router.
#[allow(clippy::needless_pass_by_value)] // Arc<T> is idiomatically passed by value
pub fn create_router(state: Arc<AppState>) -> Router {
    let auth_state = AuthState {
        auth_config: Arc::clone(&state.auth_config),
        key_server: state.key_server.clone(),
    };

    // Agent auth middleware state (cloned to avoid Arc wrapping AgentAuthState).
    let agent_auth_state = state.agent_auth.clone();

    // Key server routes run outside the standard auth middleware (they ARE the auth step).
    let maybe_ks_routes: Option<Router> = state
        .key_server
        .as_ref()
        .map(|ks| key_server_routes(Arc::clone(ks)));

    // JWKS endpoint — unauthenticated, no agent auth required.
    let jwks_route = Router::new()
        .route("/.well-known/jwks.json", get(jwks_handler))
        .with_state(Arc::clone(&state.gateway_key_pair));

    // RFC 9728 protected-resource metadata — unauthenticated (clients fetch it
    // before holding a token). Populated from config, not the request Host.
    let protected_resource_route = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(well_known::oauth_protected_resource_handler),
        )
        .with_state(Arc::clone(&state));

    #[allow(unused_mut)]
    let mut routes = Router::new()
        .route("/health", get(handlers::health_handler))
        .route("/api/costs", get(backend_handlers::costs_handler))
        .route(
            "/mcp",
            post(handlers::meta_mcp_handler)
                .get(handlers::mcp_sse_handler)
                .delete(handlers::mcp_delete_handler),
        )
        .route("/mcp/{name}", post(backend_handlers::backend_handler))
        .route(
            "/mcp/{name}/{*path}",
            post(backend_handlers::backend_handler),
        )
        // Helpful error for deprecated SSE endpoint (common misconfiguration)
        .route(
            "/sse",
            get(handlers::sse_deprecated_handler).post(handlers::sse_deprecated_handler),
        );

    // Merge web UI API routes (auth-aware: admin gets full data, public gets redacted)
    #[cfg(feature = "webui")]
    {
        routes = routes.merge(super::ui::api_router());
    }

    let mut app = routes
        // Agent JWT scope middleware runs inside the standard auth layer.
        .layer(middleware::from_fn_with_state(
            agent_auth_state,
            agent_auth_middleware,
        ))
        // Authentication middleware (applied before other layers)
        .layer(middleware::from_fn_with_state(auth_state, auth_middleware))
        .layer(CatchPanicLayer::new())
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(Arc::clone(&state));

    // Merge key server routes (unauthenticated) if enabled
    if let Some(ks_routes) = maybe_ks_routes {
        app = app.merge(ks_routes);
    }

    // Merge JWKS route (unauthenticated)
    app = app.merge(jwks_route);

    // Merge RFC 9728 protected-resource metadata route (unauthenticated)
    app = app.merge(protected_resource_route);

    // Merge /metrics scrape endpoint (unauthenticated — Prometheus scrapers do not send auth headers)
    #[cfg(feature = "metrics")]
    {
        app = app.merge(Router::new().route("/metrics", get(handlers::metrics_handler)));
    }

    // Merge web UI HTML route (unauthenticated — static HTML, no data)
    #[cfg(feature = "webui")]
    {
        app = app.merge(super::ui::html_router());
    }

    app
}
