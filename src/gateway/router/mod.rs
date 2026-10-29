// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! HTTP router and handlers

use crate::gateway::routes;
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
mod app_state_announce;
use crate::personal_accounts::AccountHandles;
pub(crate) use accounts::{ConnectOffers, account_handles_of};
pub(crate) use handlers::shape_modern_response;
mod authorization;
pub use authorization::CallerStanding;
pub(crate) use authorization::{
    ADMIN_META_TOOLS, OwnedRouterAuthorizer, RouterAuthorizer, backend_tool_targets_for_call,
    sanitize_exempt,
};
mod backend_handlers;
mod handlers;
// The web UI's Try-a-tool route runs this one MCP path in process (U12).
#[cfg(feature = "webui")]
pub(in crate::gateway) use handlers::meta_mcp_handler;
mod hardened_elicitation;
mod hardened_identity;
mod identity;
pub(crate) mod inflight_calls;
mod meta_refusal_audit;
// Re-exported rather than widening `mod handlers` itself, so exactly one item
// becomes crate-visible. The `MIK-7334.CATALOGUE.1` C10a/C10b cells drive the
// production constructor instead of reimplementing it; see its doc comment.
#[cfg(test)]
pub(crate) use identity::grant_subject_from_verified_identity;
pub(crate) mod helpers;
mod origin_guard;
mod process_facts;
pub use process_facts::{ProcessFacts, ProcessStart};
mod view_judge;
mod watch_poll;
pub(crate) use watch_poll::GatewayWatchHost;

/// `true` when `host` names the loopback interface.
///
/// Re-exported so startup can warn about a bind that puts the unauthenticated
/// surface on the network, using the same classifier the Origin gate uses.
#[must_use]
pub fn is_loopback_bind(host: &str) -> bool {
    well_known::is_loopback_host(host)
}
mod well_known;
// Direct-route guard chain (design doc 2026-09-27-direct-route-guards.md §2.2).
mod direct_guards;

#[cfg(test)]
mod adapter_get_rollback_tests;
#[cfg(test)]
mod audit_degraded_tests;
/// MIK-8392.STORED.1 T10: a revoked account's stored task read.
mod backend_choke;
#[cfg(test)]
mod body_limit_tests;
#[cfg(test)]
mod callback_admin_denial_tests;
#[cfg(test)]
mod chokepoint_direct_tests;
#[cfg(test)]
mod chokepoint_tests;
/// MIK-8202 P2: task creation on a clock before 1970.
#[cfg(test)]
mod clock_p2_tests;
#[cfg(all(test, feature = "firewall"))]
mod collusion_direct_tests;
#[cfg(test)]
mod continuation_instance_tests;
/// MIK-8202 P2: the control-plane grant display on a clock before 1970.
#[cfg(all(test, feature = "webui"))]
mod control_plane_grant_clock_tests;
#[cfg(test)]
mod cost_key_tests;
#[cfg(test)]
mod direct_anonymous_continuation_tests;
#[cfg(test)]
mod direct_audit_tests;
#[cfg(test)]
mod direct_cache_guard_tests;
#[cfg(test)]
mod direct_capability_tests;
#[cfg(test)]
mod direct_continuation_gate_tests;
#[cfg(test)]
mod direct_continuation_tests;
#[cfg(test)]
mod direct_explicit_cancel_tests;
#[cfg(test)]
mod direct_guards_effect_tests;
#[cfg(test)]
mod direct_guards_fixture;
#[cfg(all(test, feature = "a2a", feature = "firewall"))]
mod direct_guards_fixture_a2a;
#[cfg(test)]
mod direct_guards_tests;
#[cfg(test)]
mod direct_list_scope_tests;
#[cfg(test)]
mod direct_log_escape_tests;
#[cfg(test)]
mod direct_modern_shape_tests;
#[cfg(test)]
mod direct_nonce_witness_tests;
#[cfg(test)]
mod direct_notification_credential_tests;
#[cfg(test)]
mod direct_notification_refusal_tests;
#[cfg(test)]
mod direct_notification_slot_tests;
#[cfg(test)]
mod direct_notification_wire_tests;
#[cfg(test)]
mod direct_request_checks_tests;
#[cfg(test)]
mod direct_sole_operator_tests;
#[cfg(test)]
mod direct_tasks_owner_tests;
#[cfg(test)]
mod dispatch_parity_tests;
/// E5: dashboard session expiry, logout and re-entry (MIK-7570.SESSION.1).
#[cfg(all(test, feature = "webui"))]
mod e5_dashboard_session_tests;
#[cfg(all(test, feature = "firewall"))]
mod egress_matrix_tests;
#[cfg(test)]
mod era_refusal_http_tests;
#[cfg(all(test, feature = "a2a", feature = "firewall"))]
mod errscan_a2a_tests;
#[cfg(test)]
mod f13_fetch_on_miss_tests;
#[cfg(test)]
mod f13_text_a_tests;
#[cfg(all(test, feature = "webui"))]
mod gateway_status_tests;
/// GH1942.HARDEN.1 rows 10 and 11: hardened requires declared elicitation.
#[cfg(test)]
mod hardened_elicitation_tests;
/// GH1942.HARDEN.1 rows 8 and 16: hardened requires a per-caller identity.
#[cfg(test)]
mod hardened_identity_tests;
#[cfg(test)]
mod identity_parity_tests;
mod judged_answer;
#[cfg(test)]
mod mcp_nonce_admission_tests;
#[cfg(test)]
mod mcp_nonce_tests;
#[cfg(test)]
mod mcp_nonce_witness_tests;
#[cfg(test)]
mod mcp_refusal_kind_tests; // MIK-8353 3d-1: refusal kinds on the invoke path
#[cfg(test)]
mod meta_fingerprint_tests;
/// MIK-8154.LEASE.1 rows: the direct route takes the shared execution lease.
#[cfg(test)]
mod mik8154_lease_rows_tests;
#[cfg(all(test, feature = "webui"))]
mod overview_sources_tests;
#[cfg(all(test, feature = "webui"))]
mod overview_tests;
/// A backend's protocol directives reach the client only where allowed.
#[cfg(test)]
mod protocol_member_scope_tests;
/// A backend's gateway-only members never reach the client.
#[cfg(test)]
mod reserved_member_ingress_tests;
#[cfg(all(test, feature = "firewall"))]
mod rule_keys_route_tests;
/// Secret injection applies on the direct route as through gateway_invoke.
#[cfg(test)]
mod secret_injection_direct_tests;
/// U17: the UI shell at deep links, hashed assets, /ui/classic (MIK-8870).
#[cfg(all(test, feature = "webui"))]
mod u17_ui_shell_tests;
/// U3: the UI live stream.
#[cfg(all(test, feature = "webui"))]
mod ui_stream_tests;
// MIK-8697: the credential canary over the router's request paths.
#[cfg(test)]
mod canary_tests;
/// A delivery record says what the gateway did to the answer.
#[cfg(all(test, feature = "firewall"))]
mod delivery_effect_tests;
/// A delivery record joins its invocation by trace, on both routes.
#[cfg(all(test, feature = "firewall"))]
mod delivery_trace_join_tests;
/// ADR-023: the security flags apply on reload.
#[cfg(all(test, feature = "firewall"))]
mod live_flags_tests;
/// ADR-023: a request keeps the generation it arrived with.
#[cfg(all(test, feature = "firewall"))]
mod live_pin_tests;
/// ADR-023: the UI view reads the flags and environment name on each response.
#[cfg(all(test, feature = "webui"))]
mod live_ui_view_tests;
/// MIK-8154 PR 2 rows: sanitize parity and passthrough on every route.
#[cfg(all(test, feature = "firewall"))]
mod mik8154_rows_tests;
#[cfg(test)]
mod mrtr9_lease_tests;
#[cfg(test)]
mod nonce_failure_class_tests;
#[cfg(all(test, feature = "firewall"))]
mod oracle_capability_tests;
#[cfg(all(test, feature = "firewall"))]
mod oracle_order_tests;
#[cfg(all(test, feature = "firewall"))]
mod oracle_parity_fixture;
#[cfg(all(test, feature = "firewall"))]
mod oracle_parity_tests;
#[cfg(all(test, feature = "firewall"))]
mod oracle_per_user_tests;
#[cfg(all(test, feature = "firewall"))]
mod oracle_response_targets_tests;
/// MIK-8406: a stored plan replay needs every plan account live.
#[cfg(test)]
mod plan_replay_liveness_tests;
/// MIK-8429: a busy custody on a playbook step ends the plan, retryable.
#[cfg(test)]
mod playbook_busy_tests;
#[cfg(test)]
mod playbook_envelope_tests;
#[cfg(test)]
mod playbook_key_tests;
#[cfg(all(test, feature = "firewall"))]
mod relay_key_settlement_tests; // MIK-8488 PR-A: site 18's key release
/// MIK-8058: a failed reload's status says whose fault it is.
#[cfg(all(test, feature = "webui"))]
mod reload_status_tests;
#[cfg(all(test, feature = "firewall"))]
pub(super) mod route_matrix_driver_tests;
#[cfg(all(test, feature = "firewall"))]
pub(super) mod route_matrix_x14_nonce_tests;
/// MIK-8504: the provisional-session cap refuses before anything runs.
/// MIK-8533: past the POST cap a sessionless legacy call is served without a session.
#[cfg(test)]
mod session_capacity_degrade_tests;
#[cfg(test)]
mod session_capacity_tests;
#[cfg(test)]
mod slot_quota_direct_tests;
#[cfg(test)]
mod stored_read_account_excluded_tests;
#[cfg(test)]
mod stored_read_account_tests;
#[cfg(test)]
mod stored_read_capability_tests;
/// MIK-8392.STORED.1 order twins: stored reads refuse in live-call order.
#[cfg(test)]
mod stored_read_order_tests;
/// MIK-8392 STORED.2: stored single-call results need a live account.
#[cfg(test)]
mod stored_replay_liveness_tests;
/// A UI write's admin record outlives a client cancel with its handler.
#[cfg(all(test, feature = "webui"))]
mod ui_audit_cancel_tests;
#[cfg(test)]
mod webhook_mount_tests;
/// MIK-8340: a withheld surfaced name answers as an absent one.
#[cfg(all(test, feature = "firewall"))]
mod withheld_listing_tests;
#[cfg(all(test, feature = "firewall"))]
mod withheld_parity_tests;
#[cfg(all(test, feature = "firewall"))]
pub(super) mod withheld_twin_tests;
/// The meta route's post-judge delivery record, shared with stdio (MIK-7920).
pub(in crate::gateway) use judged_answer::record_delivery as record_judged_delivery;
/// MIK-8518 T2: the router's grant-subject builders admit only API keys.
#[cfg(test)]
mod grant_key_builder_tests;
/// MIK-8286 / MIK-8287: an identity that names nobody is refused.
#[cfg(test)]
mod identity_collapse_tests;
#[cfg(test)]
mod log_level_admin_tests;
#[cfg(test)]
mod mcp_route_signature_tests;
#[cfg(test)]
mod meta_dispatch_edge_tests;
#[cfg(test)]
mod probe_tests;
#[cfg(test)]
mod r2_identity_keys_tests;
#[cfg(test)]
mod r2_input_keys_tests;
#[cfg(test)]
mod replay_policy_tests;
#[cfg(test)]
mod resource_prompt_scope_tests;
#[cfg(test)]
mod session_fp_once_tests;
/// MIK-7736: under standard, a gateway_invoke nonce is judged after policy.
#[cfg(all(test, feature = "metrics"))]
mod signing_nonce_order_tests;
/// MIK-8356 C9: a managed caller's cold-slot 401 on `/mcp`.
#[cfg(test)]
mod slot_verdict_g2_managed_http_tests;
/// MIK-8356: router entry rows for per-user calls judged by the caller's slot.
#[cfg(test)]
mod slot_verdict_g3_http_tests;
#[cfg(test)]
mod slot_verdict_http_tests;
#[cfg(test)]
mod slot_verdict_http_variant_tests;
/// MIK-8356 x MIK-8353: the caller verdict's effects reach the refund witness.
#[cfg(test)]
mod slot_verdict_witness_tests;
/// E1: SSO admins through the role mapping (MIK-7570.ADMINSSO.1).
#[cfg(test)]
mod sso_admin_tests;
/// MIK-8392.STORED.1 batch B: per-user stored reads, cold slots, touch-on-read.
#[cfg(test)]
mod stored_read_slot_tests;
#[cfg(test)]
mod stream_kill_tests;
/// `pub(crate)` for the A11 direct-route cells in `meta_mcp`, which need this
/// router harness and the account fixtures together. Test-only.
#[cfg(test)]
pub(crate) mod tests;
mod trace_span;
#[cfg(test)]
mod trace_span_tests;
#[cfg(all(test, feature = "webui"))]
mod ui_tool_call_cell_tests;
#[cfg(all(test, feature = "webui"))]
mod ui_tool_call_gates_tests;
#[cfg(all(test, feature = "webui"))]
mod ui_tool_call_tests;
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
    /// When this process started and what it recorded while starting. Set
    /// where server start builds the state; the web UI's uptime counts from it.
    pub process: Arc<ProcessFacts>,
}

/// Create the router.
#[allow(clippy::needless_pass_by_value)] // Arc<T> is idiomatically passed by value
pub fn create_router(state: Arc<AppState>) -> Router {
    create_router_with(state, None)
}

/// `/livez`; the invariant is stated at the route table.
async fn probe_ok() -> &'static str {
    "ok"
}

/// `/readyz`: `/livez` plus the audit log (D1-f) and the capability catalogue
/// (MIK-7268). While the log is degraded the probe itself attempts one bounded
/// append, so a pod the Service has drained still recovers without call
/// traffic (Revision 3). A backend still in its startup scan answers every
/// call with an empty or partial catalogue; no backend means none configured,
/// which is ready. `/livez` stays constant, so the kubelet unreadies the pod
/// but never restarts it.
async fn readyz(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> (axum::http::StatusCode, String) {
    match &state.transparency_log {
        // The cause is a fixed label such as `storage_full`, never a path.
        Some(log) if log.admit().await.is_err() => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "audit log unavailable: {}",
                if log.is_stalled() {
                    "stalled"
                } else {
                    log.last_failure_cause().unwrap_or("io_error")
                }
            ),
        ),
        _ if state
            .meta_mcp
            .get_capabilities()
            .is_some_and(|c| !c.initial_scan_complete()) =>
        {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "capabilities loading".to_string(),
            )
        }
        _ => (axum::http::StatusCode::OK, "ok".to_string()),
    }
}

/// The one `AuthState` builder: ingress ([`auth_middleware`], wired in
/// [`create_router_with`]) and the UI stream's per-second credential
/// re-check both judge with it, so a stream can never decide differently
/// from the request that opened it.
pub(crate) fn build_auth_state(state: &AppState) -> AuthState {
    AuthState {
        auth_config: Arc::clone(&state.auth_config),
        key_server: state.key_server.clone(),
        live_config: Arc::clone(&state.live_config),
        dashboard_bootstrap: Arc::clone(&state.dashboard_bootstrap),
        // The listener's own TLS (restart-only). An HTTPS `public_url` in front
        // is read live per response (`auth::cookie_secure`).
        tls_enabled: state.live_config.running().mtls.enabled,
        agent_auth: state.agent_auth.clone(),
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
        .route(routes::METRICS, get(handlers::metrics_handler))
        .with_state(token)
}

/// Routes on the app state that run outside authentication and the E1-f audit
/// layer, merged after both are applied: dashboard logout (E5), which an
/// expired session and an audit outage must never block, and the dashboard
/// handoff code (#2130), whose posted code is its own credential.
fn unauthenticated_routes() -> Router<Arc<AppState>> {
    #[cfg(feature = "webui")]
    {
        super::ui::session::logout_router()
    }
    #[cfg(not(feature = "webui"))]
    {
        Router::new()
    }
}

/// Webhook delivery re-validates each session against the same authorizer
/// the middleware uses, so the two cannot disagree about who may see what.
/// MIN.2: every session-stream copy is judged for its session's caller, on
/// the same process read history the answers are judged against.
fn bind_multiplexer(state: &AppState, auth_state: &AuthState) {
    state.multiplexer.set_authorizer(auth_state.clone());

    if let Some(judge) = crate::gateway::outbound::SessionJudge::new(
        helpers::read_guard(state),
        state.meta_mcp.rejection_audit(),
        state.meta_mcp.transparency_log().cloned(),
    ) {
        state.multiplexer.set_read_judge(judge);
    }
}

/// [`create_router_with`] plus the managed-account handles, which only a
/// gateway that brought custody up has.
pub(crate) fn create_router_with_accounts(
    state: Arc<AppState>,
    extra: Option<Router>,
    accounts: Option<AccountHandles>,
) -> Router {
    let auth_state = build_auth_state(&state);
    bind_multiplexer(&state, &auth_state);

    // Agent auth middleware state (cloned to avoid Arc wrapping AgentAuthState).
    let agent_auth_state = state.agent_auth.clone();

    // Key server routes run outside the standard auth middleware (they ARE the auth step).
    let maybe_ks_routes: Option<Router> = state
        .key_server
        .as_ref()
        .map(|ks| key_server_routes(Arc::clone(ks)));

    // JWKS endpoint — unauthenticated, no agent auth required.
    let jwks_route = Router::new()
        .route(routes::JWKS, get(jwks_handler))
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
    let pin_source = Arc::clone(&state.live_config);
    let protected_resource_route =
        Router::new()
            .route(
                routes::PROTECTED_RESOURCE,
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
        .route(routes::HEALTH, get(handlers::health_handler))
        // Orchestrator probes answer from the process alone. `/health` fails
        // when any backend is down, and probing it restarted every replica for
        // one flapping upstream. Reaching this handler means the config loaded
        // and the listener is up; readiness adds the audit log (D1-f) and the
        // startup capability scan (MIK-7268).
        // Graceful shutdown closes the listener, which is how both turn red.
        .route(routes::LIVEZ, get(probe_ok))
        .route(routes::READYZ, get(readyz))
        .route(routes::API_COSTS, get(backend_handlers::costs_handler))
        .route(
            routes::MCP,
            post(handlers::meta_mcp_handler)
                .get(handlers::mcp_sse_handler)
                .delete(handlers::mcp_delete_handler),
        )
        // No sub-path alias: one with a wildcard tail never served, because
        // `backend_handler` extracts the name alone and answered 500 (MIK-7650).
        .route(routes::MCP_BACKEND, post(backend_handlers::backend_handler))
        // Helpful error for deprecated SSE endpoint (common misconfiguration)
        .route(
            routes::SSE,
            get(handlers::sse_deprecated_handler).post(handlers::sse_deprecated_handler),
        );

    // Merge web UI API routes (auth-aware: admin gets full data, public gets redacted)
    #[cfg(feature = "webui")]
    {
        routes = routes.merge(super::ui::admin_audit::audited_api_router(&state));
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
    // Merged outside the main `TraceLayer` below, with its own path-only span
    // (§4.3): the callback's query carries the code and state.
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
        .merge(unauthenticated_routes())
        .layer(CatchPanicLayer::new())
        .layer(CompressionLayer::new())
        // Method and route only (#1529). Routes merged below are outside it.
        .layer(TraceLayer::new_for_http().make_span_with(trace_span::span_for))
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
    let app = app.layer(middleware::from_fn_with_state(
        origin_policy,
        origin_guard::origin_guard_middleware,
    ));

    // Added last so it runs first, on every route merged above and the
    // fallback, whether or not the route authenticates (ADR-023).
    app.layer(middleware::from_fn_with_state(pin_source, pin_generation))
}

/// Pin the published generation on a request before anything else runs. Every
/// later judgement on the request reads this one, so a reload that publishes
/// mid-request never mixes two configurations into one answer.
async fn pin_generation(
    axum::extract::State(live): axum::extract::State<Arc<crate::config_reload::LiveConfig>>,
    mut request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    request.extensions_mut().insert(live.generation());
    next.run(request).await
}

/// The refusal for a request that reached a reader without a pinned
/// generation. Fail closed: a reader never falls back to the current one.
pub(crate) const UNPINNED: &str = "Internal error: no configuration generation on this request";

/// The generation [`pin_generation`] put on this request; `None` only for a
/// request that never passed the router's outer layer.
pub(crate) fn pinned_generation(
    extensions: &axum::http::Extensions,
) -> Option<Arc<crate::config_reload::Generation>> {
    extensions
        .get::<Arc<crate::config_reload::Generation>>()
        .cloned()
}
