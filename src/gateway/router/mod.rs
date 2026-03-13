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
use crate::config::StreamingConfig;
use crate::key_server::{KeyServer, handler::key_server_routes};
use crate::mtls::MtlsPolicy;
use crate::security::ToolPolicy;

mod backend_handlers;
mod handlers;
mod helpers;

#[cfg(test)]
mod tests;

/// Shared application state
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

    // Merge web UI HTML route (unauthenticated — static HTML, no data)
    #[cfg(feature = "webui")]
    {
        app = app.merge(super::ui::html_router());
    }

    app
}
