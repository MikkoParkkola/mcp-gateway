// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! HTTP router and handlers

use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
};
use tower_http::{catch_panic::CatchPanicLayer, compression::CompressionLayer, trace::TraceLayer};

use super::auth::{AuthState, ResolvedAuthConfig, auth_middleware};
use super::meta_mcp::MetaMcp;
use super::oauth::{AgentAuthState, GatewayKeyPair, agent_auth_middleware, jwks_handler};
use super::openwebui_adapter::{OpenWebUiAdapterState, openwebui_adapter_middleware};
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

mod accounts;
use crate::personal_accounts::AccountHandles;
pub(crate) use accounts::{ConnectOffers, account_handles_of};
mod authorization;
pub use authorization::CallerStanding;
pub(crate) use authorization::{
    ADMIN_META_TOOLS, OwnedRouterAuthorizer, RouterAuthorizer, backend_tool_targets_for_call,
};
mod backend_handlers;
mod handlers;
mod identity;
// Re-exported rather than widening `mod handlers` itself, so exactly one item
// becomes crate-visible. The `MIK-7334.CATALOGUE.1` C10a/C10b cells drive the
// production constructor instead of reimplementing it; see its doc comment.
#[cfg(test)]
pub(crate) use identity::grant_subject_from_verified_identity;
pub(crate) mod helpers;
mod origin_guard;
#[cfg(feature = "firewall")]
mod response_pass;

/// `true` when `host` names the loopback interface.
///
/// Re-exported so startup can warn about a bind that puts the unauthenticated
/// surface on the network, using the same classifier the Origin gate uses.
#[must_use]
pub fn is_loopback_bind(host: &str) -> bool {
    well_known::is_loopback_host(host)
}
mod well_known;

#[cfg(test)]
mod audit_degraded_tests;
#[cfg(test)]
mod body_limit_tests;
#[cfg(test)]
mod direct_list_scope_tests;
#[cfg(test)]
mod identity_parity_tests;
#[cfg(test)]
mod log_level_admin_tests;
#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod r2_identity_keys_tests;
#[cfg(test)]
mod r2_input_keys_tests;
#[cfg(test)]
mod resource_prompt_scope_tests;
/// E1: SSO admins through the role mapping (MIK-7570.ADMINSSO.1).
#[cfg(test)]
mod sso_admin_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod webhook_scope_tests;

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
    /// Single-use value that opens the dashboard from the link `serve` prints.
    pub dashboard_bootstrap: Arc<crate::gateway::auth::DashboardBootstrap>,
    /// Listeners on open `subscriptions/listen` streams.
    ///
    /// Separate from `multiplexer`, which is keyed by session id: this revision
    /// deleted sessions, so there is nothing to key on. Kept beside it rather
    /// than inside it so the two lifetimes stay distinguishable.
    pub subscriptions: Arc<crate::gateway::subscription_registry::SubscriptionRegistry>,
    /// Durable tasks, scoped to the principal that created them.
    pub tasks: Arc<crate::gateway::task_service::TaskService>,
    /// Worker pool and publication seam for in-flight tasks.
    pub task_executor: Arc<crate::gateway::task_service::TaskExecutor>,
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
    /// Continuation keys, spent-ledger and held legacy exchanges — one owner,
    /// one lifetime, generated per process at startup.
    ///
    /// Not three fields: a keyring outliving its ledger is a replay window. The
    /// keys are never shared with another process, which is what makes a
    /// continuation single-use across replicas without a shared store. See
    /// [`crate::protocol::continuation::ContinuationState`].
    pub continuation: Arc<crate::protocol::continuation::ContinuationState>,
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
    /// Where the control-plane store lives and which setting chose it,
    /// resolved once at startup (MIK-7570 F6). The admin API reports it and
    /// names it in a 503 when the store could not be opened there. `None`
    /// only for a state built without a startup (embedders, tests).
    pub control_plane_base: Option<crate::control_plane::role_mapping::ControlPlaneBaseInfo>,
    /// Live gateway configuration (hot-reloadable). The control-plane RBAC role
    /// mapping is read through this so a `/reload` that changes
    /// `control_plane.role_mapping` takes effect without a restart — e.g. a
    /// removed admin rule stops granting Admin (MIK-6702 CP.RELOAD.1). The
    /// config-reload loop swaps the inner `Arc<Config>` on every applied reload.
    pub live_config: Arc<crate::config_reload::LiveConfig>,
    /// SIEM export status, present when the export background task is running
    /// (MIK-6703). Drives the `EvidenceExport` entitlement + export-status route.
    pub export_status: Option<Arc<crate::control_plane::ExportStatus>>,
    /// The environment the gateway resolves against, so a route reading an
    /// operator-supplied variable sees what a reload published rather than what
    /// the process was started with. `None` in tests that construct the state
    /// directly, which then read the process environment as before.
    pub env: Option<Arc<crate::config::LiveEnv>>,
    /// Tamper-evident transparency log (issue #133, D3), shared with `MetaMcp`.
    /// Lets the direct backend route (`backend_handlers::backend_handler`),
    /// which bypasses `MetaMcp`, write identity-propagation audit events
    /// (`idp_mint` / `idp_refuse`) into the same hash chain (MIK-6740). `None`
    /// when the transparency log is disabled — audit writes are then a no-op.
    pub transparency_log: Option<Arc<crate::security::TransparencyLogger>>,
    /// Lifecycle registry for TTL-reaped per-identity state
    /// (`MIK-7215.CONTROL.4`). `None` when the gateway was constructed
    /// without lifecycle wiring — tests and any embedder that does not run
    /// the reaper — in which case tracking and sweeping are both no-ops.
    pub session_lifecycle: Option<Arc<crate::gateway::session_lifecycle::SessionLifecycle>>,
}

/// Create the router.
#[allow(clippy::needless_pass_by_value)] // Arc<T> is idiomatically passed by value
pub fn create_router(state: Arc<AppState>) -> Router {
    create_router_with(state, None)
}

/// Create the router, folding in routes a caller assembles separately.
///
/// Extra routes are merged **here**, before the origin gate is applied, rather
/// than by the caller afterwards. A layer only covers what is already merged,
/// so a route merged onto the finished router silently skips the gate. That has
/// happened twice: first for the routes merged below, then for the webhook
/// routes merged at the call site. Taking them as a parameter removes the
/// ordering discipline that failed both times.
#[allow(clippy::needless_pass_by_value)] // Arc<T> is idiomatically passed by value
impl AppState {
    /// Announce that the set of available tools has changed.
    ///
    /// Two audiences, one event: sessions attached to the pre-2026 GET stream,
    /// and listeners on `subscriptions/listen`. Kept in one function because
    /// telling only one of them is the failure mode — the capability is
    /// advertised as `listChanged: true` to both.
    ///
    /// Both audiences are scoped to callers who may access `backend` now.
    pub async fn announce_tools_changed(&self, backend: &str) {
        self.proxy_manager
            .broadcast_tools_list_changed(backend)
            .await;
        self.subscriptions.publish_for_backend(
            crate::gateway::subscription_registry::tools_list_changed(),
            backend,
        );
    }
}

/// `/livez`; the invariant is stated at the route table.
async fn probe_ok() -> &'static str {
    "ok"
}

/// `/readyz`: `/livez` plus the audit log (D1-f). While the log is degraded
/// the probe itself attempts one bounded append, so a pod the Service has
/// drained still recovers without call traffic (Revision 3). `/livez` stays
/// constant, so the kubelet unreadies the pod but never restarts it.
async fn readyz(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> (axum::http::StatusCode, String) {
    match &state.transparency_log {
        // The cause is a fixed label such as `storage_full`, never a path.
        Some(log) if log.admit().await.is_err() => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "audit log unavailable: {}",
                log.last_failure_cause().unwrap_or("io_error")
            ),
        ),
        _ => (axum::http::StatusCode::OK, "ok".to_string()),
    }
}

/// The `AuthState` needed by [`auth_middleware`], split out of
/// [`create_router_with`] purely to keep that function under the line
/// budget — logic and ordering are unchanged.
fn build_auth_state(state: &Arc<AppState>) -> AuthState {
    AuthState {
        auth_config: Arc::clone(&state.auth_config),
        key_server: state.key_server.clone(),
        live_config: Arc::clone(&state.live_config),
        dashboard_bootstrap: Arc::clone(&state.dashboard_bootstrap),
        tls_enabled: {
            let c = state.live_config.get();
            // Also when a proxy terminates TLS in front: the browser speaks
            // HTTPS even though this listener does not, and without `Secure` a
            // downgrade puts the operator's session on the wire.
            c.mtls.enabled
                || c.server
                    .public_url
                    .as_deref()
                    .is_some_and(|u| u.starts_with("https://"))
        },
    }
}

pub fn create_router_with(state: Arc<AppState>, extra: Option<Router>) -> Router {
    create_router_with_accounts(state, extra, None)
}

/// Agent auth, then the Open `WebUI` adapter, then authentication. Layers wrap
/// outward, so a layer added LATER runs EARLIER: authentication runs first and
/// the adapter reads an assertion only once the presenter is identified, which
/// it then requires to be a named API key. Reversing the adapter and auth
/// lines would let an unauthenticated request assert an identity. One helper
/// for both the main chain and the accounts owner routes, so the order is
/// written once. `None` adapter installs no layer: the no-adapter deployment
/// keeps its exact previous behaviour.
fn authenticate(
    routes: Router<Arc<AppState>>,
    agent_auth: AgentAuthState,
    adapter: Option<OpenWebUiAdapterState>,
    auth: AuthState,
) -> Router<Arc<AppState>> {
    let mut routes = routes.layer(middleware::from_fn_with_state(
        agent_auth,
        agent_auth_middleware,
    ));
    if let Some(adapter) = adapter {
        routes = routes.layer(middleware::from_fn_with_state(
            adapter,
            openwebui_adapter_middleware,
        ));
    }
    routes.layer(middleware::from_fn_with_state(auth, auth_middleware))
}

/// `/metrics`, carrying the scrape token resolved once at router build.
#[cfg(feature = "metrics")]
fn metrics_route(config: &crate::config::Config) -> Router {
    let token = config
        .server
        .resolve_metrics_token(&config.env_overlay())
        .map(Arc::<str>::from);
    Router::new()
        .route("/metrics", get(handlers::metrics_handler))
        .with_state(token)
}

/// [`create_router_with`] plus the managed-account handles, which only a
/// gateway that brought custody up has.
pub(crate) fn create_router_with_accounts(
    state: Arc<AppState>,
    extra: Option<Router>,
    accounts: Option<AccountHandles>,
) -> Router {
    let auth_state = build_auth_state(&state);
    // Webhook delivery re-validates each session against the same authorizer
    // the middleware uses, so the two cannot disagree about who may see what.
    state.multiplexer.set_authorizer(auth_state.clone());

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
    // The bind fallback origin is snapshotted from the *startup* config here:
    // `server.host`/`port` are restart-required, so the advertised origin must
    // not follow a hot host/port edit that has not moved the listener.
    // `public_url` is still read live inside the handler.
    let startup_config = state.live_config.get();
    let bind_origin =
        well_known::bind_fallback_origin(&startup_config.server.host, startup_config.server.port);
    let origin_policy = Arc::new(origin_guard::OriginPolicy::from_live(&state.live_config));
    let protected_resource_route =
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get({
                    let bind_origin = bind_origin.clone();
                    move |axum::extract::State(state): axum::extract::State<Arc<AppState>>| {
                        let bind_origin = bind_origin.clone();
                        async move {
                            well_known::oauth_protected_resource_handler(state, bind_origin).await
                        }
                    }
                }),
            )
            .with_state(Arc::clone(&state));

    #[allow(unused_mut)]
    let mut routes = Router::new()
        .route("/health", get(handlers::health_handler))
        // Orchestrator probes answer from the process alone. `/health` fails
        // when any backend is down, and probing it restarted every replica for
        // one flapping upstream. Reaching this handler means the config loaded
        // and the listener is up; readiness adds only the audit log (D1-f).
        // Graceful shutdown closes the listener, which is how both turn red.
        .route("/livez", get(probe_ok))
        .route("/readyz", get(readyz))
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

    // Open WebUI assertion adapter; `None` when none is configured, and then
    // no environment lookup happens.
    let openwebui_adapter =
        OpenWebUiAdapterState::from_config(&startup_config, &startup_config.env_overlay());
    // The dispatch sites offer from the same custody the owner routes use.
    if let Some(handles) = &accounts {
        let live = Arc::clone(&state.live_config);
        let offers = ConnectOffers::new(Arc::clone(&handles.journeys), live);
        state.meta_mcp.install_connect_offers(offers);
    }
    // Merged outside the main `TraceLayer` below: its span records the full
    // URI, and the callback's query carries the code and state (§4.3).
    let accounts_router = accounts::router(accounts, &startup_config, |owner| {
        authenticate(
            owner,
            agent_auth_state.clone(),
            openwebui_adapter.clone(),
            auth_state.clone(),
        )
    })
    .map(|router| router.with_state(Arc::clone(&state)));

    let mut app = authenticate(routes, agent_auth_state, openwebui_adapter, auth_state)
        .layer(CatchPanicLayer::new())
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Merge key server routes (unauthenticated) if enabled
    if let Some(ks_routes) = maybe_ks_routes {
        app = app.merge(ks_routes);
    }

    // Merge JWKS route (unauthenticated)
    app = app.merge(jwks_route);

    // Merge RFC 9728 protected-resource metadata route (unauthenticated)
    app = app.merge(protected_resource_route);

    // Merge /metrics outside auth: it checks its own scrape token, not the bearer
    #[cfg(feature = "metrics")]
    {
        app = app.merge(metrics_route(&startup_config));
    }

    // Merge web UI HTML route (unauthenticated — static HTML, no data)
    #[cfg(feature = "webui")]
    {
        app = app.merge(super::ui::html_router());
    }

    if let Some(extra) = extra {
        app = app.merge(extra);
    }

    if let Some(accounts_router) = accounts_router {
        app = app.merge(accounts_router);
    }

    // `server.max_body_size` caps every body read, the /mcp handlers included
    // (they buffer through `helpers::read_body`). Like the origin gate it must
    // wrap the FULLY MERGED router: a layer covers only the routes merged
    // before it, and the key server, webhooks and accounts are merged above.
    app = app.layer(DefaultBodyLimit::max(startup_config.server.max_body_size));

    // Origin/Host validation wraps the FULLY MERGED router, and does so last so
    // it runs first. Two properties depend on that placement:
    //
    // - it is outside authentication, so a cross-site request is refused before
    //   any identity, the anonymous one included, is assigned;
    // - it covers the routes merged above, which sit outside the auth layer and
    //   would otherwise skip the gate entirely. That set includes the key
    //   server's token exchange and revocation endpoints.
    //
    // Non-browser callers are unaffected: they send no `Origin`, and Prometheus
    // and health probes reach `/metrics` and `/health` as before.
    app.layer(middleware::from_fn_with_state(
        origin_policy,
        origin_guard::origin_guard_middleware,
    ))
}
