//! Meta-MCP implementation — meta-tools for dynamic discovery and playbooks.
//!
//! Module layout:
//! - `mod.rs` — struct + constructors + builders + dispatch + profile tools + tests
//! - `search.rs` — `code_mode_search`, `code_mode_execute`, `execute_chain`, `list_tools`, `search_tools`
//! - `invoke.rs` — `invoke_tool`, `dispatch_to_backend`, stats, kill/revive, playbook, reload
//! - `resources.rs` — `handle_resources_*` and `find_resource_owner`
//! - `protocol.rs` — `handle_prompts_*`, `handle_logging_*`, `current_log_level`
//! - `support.rs` — free functions: tag collection, ranking helpers, `MetaMcpInvoker`, augment
//! - `surfaced.rs` — `with_surfaced_tools`, `resolve_surfaced_tool`, `list_servers`

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "spec-preview")]
use dashmap::DashMap;
use parking_lot::RwLock;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::backend::BackendRegistry;
use crate::cache::ResponseCache;
use crate::capability::CapabilityBackend;
use crate::config::SurfacedToolConfig;
use crate::config_reload::ReloadContext;
use crate::context_integrity::ContextIntegrityKernel;
use crate::cost_accounting::CostTracker;
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::enforcer::BudgetEnforcer;
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::registry::CostRegistry;
use crate::gateway::state::SessionStateStore;
use crate::idempotency::{IdempotencyCache, spawn_cleanup_task};
use crate::identity_grants::{GrantSubject, LocalIdentityGrantStore};
use crate::kill_switch::{CapabilityErrorBudgetConfig, ErrorBudgetConfig, KillSwitch};
use crate::playbook::PlaybookEngine;
use crate::protocol::{JsonRpcResponse, LoggingLevel, RequestId, negotiate_version};
use crate::ranking::SearchRanker;
use crate::routing_profile::{ProfileRegistry, SessionProfileStore};
use crate::security::message_signing::{MessageSigner, NonceStore};
use crate::stats::UsageStats;
use crate::tool_registry::ToolRegistry;
use crate::transition::TransitionTracker;
use crate::trust::{
    project_tool_descriptor_trust_card, project_tool_descriptors_trust_cards,
    tools_list_result_with_trust_cards,
};
use crate::{Error, Result};

use super::meta_mcp_helpers::{
    build_code_mode_tools, build_discovery_preamble, build_initialize_result, build_meta_tools,
    build_routing_instructions, did_you_mean, extract_client_version, extract_required_str,
    wrap_tool_success,
};
use super::webhooks::WebhookRegistry;

mod invoke;
mod prompt_cache;
mod protocol;
mod resources;
mod search;
#[cfg(feature = "spec-preview")]
mod spec_preview;
mod support;
mod surfaced;

pub use prompt_cache::{CacheKeyDeriver, stable_tool_order, tool_schema_fingerprint};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of dynamically promoted tools stored per session.
///
/// When a session exceeds this limit the oldest entry is evicted (FIFO).
/// Configurable in future; hard-coded for Phase 3 initial implementation.
#[cfg(feature = "spec-preview")]
const MAX_PROMOTED_PER_SESSION: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CallerIdentityHeaderTrust {
    Disabled,
    Enabled,
}

impl CallerIdentityHeaderTrust {
    const fn from_enabled(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    pub(super) const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// Authenticated caller context for a `tools/call` dispatch.
#[derive(Debug, Clone, Default)]
pub struct MetaMcpCallerContext<'a> {
    /// Static or temporary API-key name, used for accounting and fallback grants.
    pub api_key_name: Option<&'a str>,
    /// Optional caller agent identifier.
    pub agent_id: Option<&'a str>,
    /// Verified caller subject for identity-grant evaluation.
    pub grant_subject: Option<GrantSubject>,
    /// Full verified end-user identity, when present. Carried (not collapsed to
    /// `grant_subject`) so the backend-invoke boundary can propagate the real
    /// user to a backend that requires it (MIK-6704 / ADR-007 R2).
    pub verified_identity: Option<&'a crate::key_server::oidc::VerifiedIdentity>,
}

// ============================================================================
// MetaMcp struct
// ============================================================================

/// Meta-MCP handler — the central dispatcher for all gateway meta-tools.
pub struct MetaMcp {
    pub(super) backends: Arc<BackendRegistry>,
    pub(super) capabilities: RwLock<Option<Arc<CapabilityBackend>>>,
    pub(super) cache: Option<Arc<ResponseCache>>,
    pub(super) default_cache_ttl: Duration,
    pub(super) idempotency_cache: Option<Arc<IdempotencyCache>>,
    pub(super) stats: Option<Arc<UsageStats>>,
    pub(super) ranker: Option<Arc<SearchRanker>>,
    pub(super) transition_tracker: RwLock<Option<Arc<TransitionTracker>>>,
    pub(super) playbook_engine: RwLock<PlaybookEngine>,
    pub(super) log_level: RwLock<LoggingLevel>,
    pub(super) kill_switch: Arc<KillSwitch>,
    pub(super) error_budget_config: RwLock<ErrorBudgetConfig>,
    pub(super) capability_budget_config: RwLock<CapabilityErrorBudgetConfig>,
    pub(super) webhook_registry: RwLock<Option<Arc<parking_lot::RwLock<WebhookRegistry>>>>,
    pub(super) profile_registry: Arc<ProfileRegistry>,
    pub(super) session_profiles: Arc<SessionProfileStore>,
    pub(super) reload_context: RwLock<Option<Arc<ReloadContext>>>,
    /// End-user identity-propagation strategy (MIK-6704 / ADR-007). `Some` when
    /// at least one backend is configured for propagation; the dispatch path
    /// uses it to mint a per-user credential for such backends. `None` disables
    /// propagation entirely (all backends keep static-credential behavior).
    pub(super) identity_propagation:
        RwLock<Option<Arc<dyn crate::identity_propagation::IdentityPropagation>>>,
    pub(super) code_mode_enabled: bool,
    /// Whether this gateway serves more than one principal (ADR-008 INV-2).
    ///
    /// Set at startup to `auth.enabled && (api_keys > 1 || oidc configured)`.
    /// When `true`, dispatch refuses a backend whose gateway-held OAuth token
    /// is not per-user isolated and not blessed `shared_account`, preventing
    /// one user's stored token from being served to another. `false` (a
    /// single-user gateway) never triggers the guard — the sole caller owns
    /// every token. `AtomicBool` because it is set after the `Arc<MetaMcp>` is
    /// built, once the auth config is resolved.
    pub(super) multi_user: std::sync::atomic::AtomicBool,
    /// Canonical response-projection rollout mode (MIK-5877).
    ///
    /// Defaults to [`ProjectionMode::Off`] so projection is dormant — a
    /// capability carrying a `projection` spec changes no response contract
    /// until an operator opts in. `experimental` drives the A/B split.
    pub(super) projection_mode: crate::projection::ProjectionMode,
    pub(super) secret_injector: crate::secret_injection::SecretInjector,
    /// Cost tracker — per-session and per-API-key spend accounting.
    pub(super) cost_tracker: Arc<CostTracker>,
    /// Engram-inspired O(1) tool registry with prefetching (optional).
    ///
    /// When `Some`, exact tool lookups short-circuit fuzzy search, and schema
    /// prefetching is triggered after each `gateway_invoke`.
    pub(super) tool_registry: Option<std::sync::Arc<ToolRegistry>>,
    /// Cost governance: pre-invoke budget enforcement engine (feature-gated).
    ///
    /// `None` when the `cost-governance` feature is disabled OR when the
    /// `cost_governance.enabled` config flag is `false`.
    #[cfg(feature = "cost-governance")]
    pub(crate) budget_enforcer: Option<Arc<BudgetEnforcer>>,
    /// Cost governance: tool-cost registry used by enforcer and suggestions.
    #[cfg(feature = "cost-governance")]
    pub(crate) cost_registry: Option<Arc<CostRegistry>>,
    /// Statically surfaced tools — appear directly in `tools/list`.
    ///
    /// Built from `MetaMcpConfig::surfaced_tools` at construction time.
    /// Empty by default; populated via [`MetaMcp::with_surfaced_tools`].
    pub(super) surfaced_tools: Vec<SurfacedToolConfig>,
    /// Fast lookup map for surfaced tool dispatch: tool name → server name.
    ///
    /// Pre-built from `surfaced_tools` so `handle_tools_call` only pays one
    /// `HashMap` lookup instead of a linear scan on every call.
    pub(super) surfaced_tools_map: HashMap<String, String>,
    /// Session-scoped dynamically promoted tools (SEP-1862 / Phase 3).
    ///
    /// Keyed by session ID.  Each entry is a list of `"server:tool"` strings
    /// that were auto-promoted after a successful `gateway_invoke`.  Cleared on
    /// session disconnect.  Maximum per-session size is [`MAX_PROMOTED_PER_SESSION`].
    ///
    /// Only compiled-in when the `spec-preview` feature is enabled so that the
    /// `DashMap` allocation is completely absent in production builds.
    #[cfg(feature = "spec-preview")]
    pub(super) session_promoted: Arc<DashMap<String, Vec<String>>>,

    /// Per-session FSM workflow state store (issue #113).
    ///
    /// Controls which capability tools are visible in `tools/list` based on
    /// the `visible_in_states` field of each `CapabilityDefinition`.
    /// Transitions via the `gateway_set_state` meta-tool.
    pub(super) session_state: SessionStateStore,

    /// HMAC-SHA256 response signer (ADR-001, OWASP ASI07).
    ///
    /// `Some` when `security.message_signing.enabled = true`; `None` otherwise.
    /// Zero-cost when `None` — no branch is taken on the hot path.
    pub(super) message_signer: Option<Arc<MessageSigner>>,

    /// Nonce replay-protection store (ADR-001).
    ///
    /// `Some` when `security.message_signing.enabled = true`; `None` otherwise.
    /// Populated alongside `message_signer`; both are `Some` or both `None`.
    pub(super) nonce_store: Option<Arc<NonceStore>>,

    /// When `true`, requests without a `nonce` are rejected with JSON-RPC -32001.
    ///
    /// Corresponds to `security.message_signing.require_nonce` in config.
    pub(super) require_nonce: bool,

    /// Tamper-evident hash-chain transparency log (issue #133, D3).
    ///
    /// `Some` when `security.transparency_log.enabled = true`; `None` otherwise.
    /// Zero overhead when `None` — no allocation or I/O on the hot path.
    pub(super) transparency_logger: Option<Arc<crate::security::TransparencyLogger>>,

    /// Response-side anomaly screening action mode (issue #133, D2).
    ///
    /// When `true`, responses with HIGH/CRITICAL inspection findings are blocked
    /// before delivery to the client.  When `false` (default), findings are
    /// logged but the response passes through.
    pub(super) response_inspection_action_mode: bool,

    /// Response contract config (issue #133, D1). Set when enabled.
    pub(super) response_contract: Option<Arc<crate::config::ResponseContractConfig>>,

    /// Per-action attestation validator (MIK-5223, B1-IDENT).
    ///
    /// `Some` only when the gateway is constructed with
    /// [`MetaMcp::with_attestation`]; `None` (the default) is a zero-cost
    /// no-op on the hot path — existing callers are byte-identical. When
    /// `Some`, every `gateway_invoke` presents its `attestation` token at the
    /// `gateway_invoke` boundary; rejections are recorded in the validator's
    /// audit ring buffer.
    pub(super) attestation_validator: Option<Arc<crate::attestation::AttestationValidator>>,

    /// Whether attestation is *enforced* (fail-closed) or merely *observed*.
    ///
    /// [`AttestationMode::Observe`](crate::attestation::AttestationMode) (the
    /// safe default when wired) validates and audits every presented token but
    /// never blocks a call — so enabling the validator on a live gateway
    /// cannot break unattested traffic.
    /// [`AttestationMode::Enforce`](crate::attestation::AttestationMode) rejects
    /// calls whose token is missing or invalid with JSON-RPC -32002. Ignored
    /// when `attestation_validator` is `None`.
    pub(super) attestation_mode: crate::attestation::AttestationMode,

    /// Local identity grant evaluator for personal capability dispatch.
    ///
    /// Empty by default. Public and shared tools still evaluate as allowed, but
    /// capabilities marked `personal` fail closed without matching caller,
    /// owner, and live grant evidence.
    pub(super) identity_grants: RwLock<LocalIdentityGrantStore>,

    /// Trust caller identity headers from an authenticated edge proxy.
    ///
    /// Disabled by default because direct clients can otherwise spoof headers.
    pub(super) caller_identity_header_trust: CallerIdentityHeaderTrust,

    /// Tool-result boundary classifier and policy envelope.
    ///
    /// Defaults to monitor-only. Clean benign results are returned unchanged;
    /// suspicious results receive `_context_integrity` audit metadata before
    /// response caching, idempotency completion, signing, and delivery.
    pub(super) context_integrity_kernel: RwLock<ContextIntegrityKernel>,
}

// ============================================================================
// Constructors
// ============================================================================

impl MetaMcp {
    fn build(
        backends: Arc<BackendRegistry>,
        cache: Option<Arc<ResponseCache>>,
        stats: Option<Arc<UsageStats>>,
        ranker: Option<Arc<SearchRanker>>,
        default_cache_ttl: Duration,
    ) -> Self {
        Self {
            backends,
            capabilities: RwLock::new(None),
            cache,
            default_cache_ttl,
            idempotency_cache: None,
            stats,
            ranker,
            transition_tracker: RwLock::new(None),
            webhook_registry: RwLock::new(None),
            playbook_engine: RwLock::new(PlaybookEngine::new()),
            log_level: RwLock::new(LoggingLevel::default()),
            kill_switch: Arc::new(KillSwitch::new()),
            error_budget_config: RwLock::new(ErrorBudgetConfig::default()),
            capability_budget_config: RwLock::new(CapabilityErrorBudgetConfig::default()),
            profile_registry: Arc::new(ProfileRegistry::default()),
            session_profiles: Arc::new(SessionProfileStore::new()),
            reload_context: RwLock::new(None),
            identity_propagation: RwLock::new(None),
            code_mode_enabled: false,
            multi_user: std::sync::atomic::AtomicBool::new(false),
            projection_mode: crate::projection::ProjectionMode::default(),
            secret_injector: crate::secret_injection::SecretInjector::empty(),
            cost_tracker: Arc::new(CostTracker::new()),
            tool_registry: None,
            #[cfg(feature = "cost-governance")]
            budget_enforcer: None,
            #[cfg(feature = "cost-governance")]
            cost_registry: None,
            surfaced_tools: Vec::new(),
            surfaced_tools_map: HashMap::new(),
            #[cfg(feature = "spec-preview")]
            session_promoted: Arc::new(DashMap::new()),
            session_state: SessionStateStore::new(),
            message_signer: None,
            nonce_store: None,
            require_nonce: false,
            transparency_logger: None,
            response_inspection_action_mode: false,
            response_contract: None,
            attestation_validator: None,
            attestation_mode: crate::attestation::AttestationMode::Observe,
            identity_grants: RwLock::new(LocalIdentityGrantStore::new()),
            caller_identity_header_trust: CallerIdentityHeaderTrust::Disabled,
            context_integrity_kernel: RwLock::new(ContextIntegrityKernel::default()),
        }
    }

    /// Create a new Meta-MCP handler.
    pub fn new(backends: Arc<BackendRegistry>) -> Self {
        Self::build(backends, None, None, None, Duration::from_secs(60))
    }

    /// Create a new Meta-MCP handler with cache, stats, and ranking support.
    pub fn with_features(
        backends: Arc<BackendRegistry>,
        cache: Option<Arc<ResponseCache>>,
        stats: Option<Arc<UsageStats>>,
        ranker: Option<Arc<SearchRanker>>,
        default_ttl: Duration,
    ) -> Self {
        Self::build(backends, cache, stats, ranker, default_ttl)
    }

    /// Expose the cost tracker for external use (budget configuration, REST handler).
    #[must_use]
    pub fn cost_tracker(&self) -> Arc<CostTracker> {
        Arc::clone(&self.cost_tracker)
    }

    /// Return a [`StatsSnapshot`] for the operator dashboard and other external consumers.
    ///
    /// `total_backend_tools` should be the current sum of cached tools across all backends.
    /// When no stats tracker has been attached (e.g. in tests), a zeroed snapshot is returned.
    #[must_use]
    pub fn stats_snapshot(&self, total_backend_tools: usize) -> crate::stats::StatsSnapshot {
        match self.stats.as_ref() {
            Some(s) => s.snapshot(total_backend_tools),
            None => crate::stats::StatsSnapshot {
                invocations: 0,
                cache_hits: 0,
                cache_hit_rate: 0.0,
                tools_discovered: 0,
                tools_available: total_backend_tools,
                tokens_saved: 0,
                top_tools: vec![],
                total_cached_tokens: 0,
                cached_tokens_by_server: vec![],
            },
        }
    }
}

// ============================================================================
// Builder methods
// ============================================================================

impl MetaMcp {
    /// Attach a routing profile registry.
    #[must_use]
    pub fn with_profile_registry(mut self, registry: ProfileRegistry) -> Self {
        self.profile_registry = Arc::new(registry);
        self
    }

    /// Enable Code Mode — `tools/list` returns only `gateway_search` + `gateway_execute`.
    #[must_use]
    pub fn with_code_mode(mut self, enabled: bool) -> Self {
        self.code_mode_enabled = enabled;
        self
    }

    /// Set the canonical response-projection rollout mode (MIK-5877).
    ///
    /// Defaults to [`crate::projection::ProjectionMode::Off`]. Set `on` to
    /// project whenever a capability declares a spec, or `experimental` to run
    /// the sticky-per-session A/B split.
    #[must_use]
    pub fn with_projection_mode(mut self, mode: crate::projection::ProjectionMode) -> Self {
        self.projection_mode = mode;
        self
    }

    /// Attach a per-action attestation validator (MIK-5223, B1-IDENT).
    ///
    /// [`AttestationMode::Observe`](crate::attestation::AttestationMode)
    /// validates and audits every `gateway_invoke` that presents an
    /// `attestation` token, but a missing or invalid token never blocks the
    /// call — the safe rollout position.
    /// [`AttestationMode::Enforce`](crate::attestation::AttestationMode) is
    /// fail-closed: a call whose token is missing or fails validation is
    /// rejected with JSON-RPC -32002.
    ///
    /// Leaving this unset (the default) is a zero-cost no-op on the hot path.
    #[must_use]
    pub fn with_attestation(
        mut self,
        validator: Arc<crate::attestation::AttestationValidator>,
        mode: crate::attestation::AttestationMode,
    ) -> Self {
        self.attestation_validator = Some(validator);
        self.attestation_mode = mode;
        self
    }

    /// Attach a local identity grant store for personal capability dispatch.
    #[must_use]
    pub fn with_identity_grants(mut self, grants: LocalIdentityGrantStore) -> Self {
        self.identity_grants = RwLock::new(grants);
        self
    }

    /// Enable or disable trusted caller identity headers.
    #[must_use]
    pub fn with_trusted_identity_headers(mut self, enabled: bool) -> Self {
        self.caller_identity_header_trust = CallerIdentityHeaderTrust::from_enabled(enabled);
        self
    }

    /// Attach a context integrity kernel for live tool-result wrapping.
    #[must_use]
    pub fn with_context_integrity_kernel(mut self, kernel: ContextIntegrityKernel) -> Self {
        self.context_integrity_kernel = RwLock::new(kernel);
        self
    }

    /// Attach a secret injector for credential brokering.
    #[must_use]
    pub fn with_secret_injector(
        mut self,
        injector: crate::secret_injection::SecretInjector,
    ) -> Self {
        self.secret_injector = injector;
        self
    }

    /// Enable idempotency support with a background cleanup task.
    #[allow(dead_code)]
    pub fn enable_idempotency(&mut self, cache: Arc<IdempotencyCache>, cleanup_interval: Duration) {
        spawn_cleanup_task(Arc::clone(&cache), cleanup_interval);
        self.idempotency_cache = Some(cache);
    }

    /// Enable HMAC-SHA256 response signing and nonce replay protection (ADR-001).
    ///
    /// Spawns a background eviction task for the nonce store.
    /// The caller must validate `signer` secrets before calling this method
    /// (see [`crate::security::message_signing::validate_secret`]).
    pub fn enable_message_signing(
        &mut self,
        signer: MessageSigner,
        replay_window: std::time::Duration,
        require_nonce: bool,
    ) {
        use crate::security::message_signing::{EVICTION_INTERVAL, spawn_nonce_cleanup_task};
        let nonce_store = Arc::new(NonceStore::new(replay_window));
        spawn_nonce_cleanup_task(Arc::clone(&nonce_store), EVICTION_INTERVAL);
        self.message_signer = Some(Arc::new(signer));
        self.nonce_store = Some(nonce_store);
        self.require_nonce = require_nonce;
    }

    /// Attach a transparency logger (issue #133, D3).
    ///
    /// When set, every completed tool invocation is committed to the
    /// hash-chain log.  Failures are non-fatal — a `warn!` is emitted but
    /// the invocation result is not affected.
    pub fn enable_transparency_log(&mut self, logger: crate::security::TransparencyLogger) {
        self.transparency_logger = Some(Arc::new(logger));
    }

    /// Attach the webhook registry for `gateway_webhook_status` reporting.
    pub fn set_webhook_registry(&self, registry: Arc<parking_lot::RwLock<WebhookRegistry>>) {
        *self.webhook_registry.write() = Some(registry);
    }

    /// Enable action mode for response-side anomaly screening (issue #133, D2).
    ///
    /// When called, responses with HIGH/CRITICAL inspection findings are
    /// blocked with a security error rather than only logged.
    pub fn enable_response_inspection_action_mode(&mut self) {
        self.response_inspection_action_mode = true;
    }

    /// Attach a per-tool response contract config (issue #133, D1).
    ///
    /// When set, every tool response is validated against the declared contract
    /// before delivery to the client.
    pub fn set_response_contract(&mut self, config: crate::config::ResponseContractConfig) {
        self.response_contract = Some(Arc::new(config));
    }

    /// Attach a [`ReloadContext`] to enable the `gateway_reload_config` meta-tool.
    pub fn set_reload_context(&self, ctx: Arc<ReloadContext>) {
        *self.reload_context.write() = Some(ctx);
    }

    /// Attach the end-user identity-propagation strategy (MIK-6704 / ADR-007).
    /// When set, dispatch mints a per-user credential for backends configured
    /// with `identity_propagation`.
    pub fn set_identity_propagation(
        &self,
        strategy: Arc<dyn crate::identity_propagation::IdentityPropagation>,
    ) {
        *self.identity_propagation.write() = Some(strategy);
    }

    /// Declare whether this gateway serves more than one principal (ADR-008
    /// INV-2). Set once at startup from the resolved auth config. When `true`,
    /// dispatch fails closed for a backend whose gateway-held OAuth token is
    /// neither per-user isolated nor blessed `shared_account`.
    pub fn set_multi_user(&self, multi_user: bool) {
        self.multi_user
            .store(multi_user, std::sync::atomic::Ordering::Relaxed);
    }

    /// Attach a `TransitionTracker` for predictive tool prefetch.
    pub fn set_transition_tracker(&self, tracker: Arc<TransitionTracker>) {
        *self.transition_tracker.write() = Some(tracker);
    }

    /// Set the capability backend.
    pub fn set_capabilities(&self, capabilities: Arc<CapabilityBackend>) {
        *self.capabilities.write() = Some(capabilities);
    }

    /// Replace the local identity grant store.
    pub fn set_identity_grants(&self, grants: LocalIdentityGrantStore) {
        *self.identity_grants.write() = grants;
    }

    /// Snapshot all identity-grant rows for read-only projection (e.g. the
    /// control-plane inventory). Returns owned clones so the lock is not held.
    #[must_use]
    pub fn identity_grant_rows(&self) -> Vec<crate::identity_grants::IdentityGrant> {
        self.identity_grants.read().values().cloned().collect()
    }

    /// Return whether trusted caller identity headers are enabled.
    #[must_use]
    pub const fn trust_caller_identity_headers(&self) -> bool {
        self.caller_identity_header_trust.is_enabled()
    }

    /// Replace the context integrity kernel.
    pub fn set_context_integrity_kernel(&self, kernel: ContextIntegrityKernel) {
        *self.context_integrity_kernel.write() = kernel;
    }

    /// Attach a [`ToolRegistry`] for O(1) tool schema resolution (consuming builder).
    ///
    /// Call this in the construction chain before the `MetaMcp` is wrapped in an `Arc`.
    /// After each `gateway_invoke`, the registry's prefetch engine is triggered to warm
    /// schemas for likely-next tools using the session transition history.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_tool_registry(mut self, registry: std::sync::Arc<ToolRegistry>) -> Self {
        self.tool_registry = Some(registry);
        self
    }

    /// Attach cost-governance enforcer and registry (consuming builder).
    ///
    /// Called from `server.rs` when `cost_governance.enabled = true`.
    #[cfg(feature = "cost-governance")]
    #[must_use]
    pub fn with_cost_governance(
        mut self,
        enforcer: Arc<BudgetEnforcer>,
        registry: Arc<CostRegistry>,
    ) -> Self {
        self.budget_enforcer = Some(enforcer);
        self.cost_registry = Some(registry);
        self
    }

    /// Expose the kill switch for external introspection or testing.
    #[allow(dead_code)]
    pub fn kill_switch(&self) -> Arc<KillSwitch> {
        Arc::clone(&self.kill_switch)
    }

    /// Expose the session profile store for testing and server teardown.
    #[must_use]
    #[allow(dead_code)]
    pub fn session_profiles(&self) -> Arc<SessionProfileStore> {
        Arc::clone(&self.session_profiles)
    }

    /// Expose the profile registry for testing.
    #[must_use]
    #[allow(dead_code)]
    pub fn profile_registry(&self) -> Arc<ProfileRegistry> {
        Arc::clone(&self.profile_registry)
    }

    /// Override the error-budget configuration.
    #[allow(dead_code)]
    pub fn set_error_budget_config(&self, config: ErrorBudgetConfig) {
        *self.error_budget_config.write() = config;
    }

    /// Override the per-capability error-budget configuration.
    #[allow(dead_code)]
    pub fn set_capability_budget_config(&self, config: CapabilityErrorBudgetConfig) {
        *self.capability_budget_config.write() = config;
    }
}

// ============================================================================
// Accessor helpers (pub(super) — used by sub-modules)
// ============================================================================

impl MetaMcp {
    pub(super) fn get_webhook_registry(&self) -> Option<Arc<parking_lot::RwLock<WebhookRegistry>>> {
        self.webhook_registry.read().clone()
    }

    pub(super) fn get_reload_context(&self) -> Option<Arc<ReloadContext>> {
        self.reload_context.read().clone()
    }

    /// Public accessor for the reload context — used by UI management endpoints.
    pub fn reload_context(&self) -> Option<Arc<ReloadContext>> {
        self.reload_context.read().clone()
    }

    pub(super) fn get_transition_tracker(&self) -> Option<Arc<TransitionTracker>> {
        self.transition_tracker.read().clone()
    }

    pub(super) fn get_tool_registry(&self) -> Option<std::sync::Arc<ToolRegistry>> {
        self.tool_registry.clone()
    }

    pub(super) fn get_capabilities(&self) -> Option<Arc<CapabilityBackend>> {
        self.capabilities.read().clone()
    }

    /// Return the full `Tool` objects for all dynamically promoted tools in a session.
    ///
    /// Promotion entries are stored as `"server:tool"` strings.  Each is resolved
    /// against the backend cache; entries whose backend has gone offline (cache empty)
    /// are silently omitted.
    ///
    /// Returns an empty `Vec` when no session ID is provided or when the session has
    /// no promoted tools.
    #[cfg(feature = "spec-preview")]
    pub(super) fn promoted_tools_for_session(
        &self,
        session_id: Option<&str>,
    ) -> Vec<crate::protocol::Tool> {
        let Some(sid) = session_id else {
            return Vec::new();
        };
        let Some(entry) = self.session_promoted.get(sid) else {
            return Vec::new();
        };
        entry
            .iter()
            .filter_map(|key| {
                let (server, tool) = key.split_once(':')?;
                let backend = self.backends.get(server)?;
                backend.get_cached_tool(tool)
            })
            .collect()
    }

    /// Remove all promoted tools for a session (called on session disconnect).
    #[cfg(feature = "spec-preview")]
    pub fn clear_session_promoted(&self, session_id: &str) {
        self.session_promoted.remove(session_id);
        debug!(
            session_id,
            "Cleared spec-preview promoted tools for session"
        );
    }

    /// Resolve the active `RoutingProfile` for a session.
    pub(super) fn active_profile(
        &self,
        session_id: Option<&str>,
    ) -> crate::routing_profile::RoutingProfile {
        let default_name = self.profile_registry.default_name();
        let name = session_id.map_or_else(
            || default_name.to_string(),
            |sid| self.session_profiles.get_profile_name(sid, default_name),
        );
        self.profile_registry.get(&name)
    }
}

// ============================================================================
// MCP protocol handlers — initialize + tools
// ============================================================================

impl MetaMcp {
    /// Handle `initialize` with version negotiation and optional profile binding.
    pub fn handle_initialize(
        &self,
        id: RequestId,
        params: Option<&Value>,
        session_id: Option<&str>,
        header_profile: Option<&str>,
    ) -> JsonRpcResponse {
        let client_version = extract_client_version(params);
        let negotiated_version = negotiate_version(client_version);
        debug!(
            client = client_version,
            negotiated = negotiated_version,
            "Protocol version negotiation"
        );

        let profile_hint = header_profile.or_else(|| {
            params
                .and_then(|p| p.get("profile"))
                .and_then(serde_json::Value::as_str)
        });

        if let (Some(sid), Some(name)) = (session_id, profile_hint) {
            if self.profile_registry.contains(name) {
                self.session_profiles.set_profile(sid, name);
                debug!(
                    session_id = sid,
                    profile = name,
                    "Session bound to routing profile at initialize"
                );
            } else {
                warn!(
                    session_id = sid,
                    requested = name,
                    "Requested profile not found at initialize; using registry default"
                );
            }
        }

        let instructions = self.build_instructions();
        let result = build_initialize_result(negotiated_version, &instructions);
        JsonRpcResponse::success_serialized(id, result)
    }

    fn build_instructions(&self) -> String {
        let backends = self.backends.all();
        let mut tool_count: usize = backends.iter().map(|b| b.cached_tools_count()).sum();
        let mut server_count = backends.len();

        if let Some(cap) = self.get_capabilities() {
            tool_count += cap.get_tools().len();
            server_count += 1;
        }

        let mut instructions = build_discovery_preamble(tool_count, server_count);

        if let Some(cap) = self.get_capabilities() {
            let caps = cap.list_capabilities();
            let routing = build_routing_instructions(&caps, &cap.name);
            if !routing.is_empty() {
                instructions.push_str(&routing);
            }
        }
        instructions
    }

    /// Compute live (`tool_count`, `server_count`) from the cached backend statuses.
    ///
    /// Uses only the in-memory cache — no I/O.  Both counts are 0 when the
    /// registry is empty (e.g. in unit tests).
    fn backend_counts(&self) -> (usize, usize) {
        let backends = self.backends.all();
        let server_count = backends.len();
        let tool_count = backends.iter().map(|b| b.status().tools_cached).sum();
        (tool_count, server_count)
    }

    /// Handle `tools/list` — Code Mode returns 2 tools; Traditional returns full set.
    ///
    /// When surfaced tools are configured, their schemas are appended after the
    /// meta-tools (subject to routing profile filtering).  Tools whose backend
    /// cache is empty are silently omitted rather than blocking the response.
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        self.handle_tools_list_for_session(id, None)
    }

    /// Session-aware variant of `handle_tools_list` used by the router.
    pub fn handle_tools_list_for_session(
        &self,
        id: RequestId,
        session_id: Option<&str>,
    ) -> JsonRpcResponse {
        let tools = if self.code_mode_enabled {
            build_code_mode_tools()
        } else {
            let (tool_count, server_count) = self.backend_counts();
            build_meta_tools(
                self.stats.is_some(),
                self.get_webhook_registry().is_some(),
                self.get_reload_context().is_some(),
                true, // cost_report always enabled (tracker is always present)
                tool_count,
                server_count,
            )
        };
        let mut tool_descriptors =
            project_tool_descriptors_trust_cards("gateway:meta", "mcp-gateway", &tools);

        // Append surfaced tools (skip in Code Mode — it uses a fixed 2-tool schema).
        if !self.code_mode_enabled {
            for surfaced in &self.surfaced_tools {
                if let Some(tool) = self.resolve_surfaced_tool(surfaced, session_id) {
                    let server_id = if self.backends.get(&surfaced.server).is_some() {
                        format!("backend:{}", surfaced.server)
                    } else {
                        format!("capability:{}", surfaced.server)
                    };
                    tool_descriptors.push(project_tool_descriptor_trust_card(
                        server_id,
                        &surfaced.server,
                        &tool,
                    ));
                }
            }
        }

        // Append session-promoted tools (spec-preview only).
        // Promoted tools are de-duplicated against surfaced tools: if a tool
        // was promoted AND is already surfaced, we skip the promoted copy.
        #[cfg(feature = "spec-preview")]
        if !self.code_mode_enabled {
            let promoted = self.promoted_tools_for_session(session_id);
            for tool in promoted {
                let already_present = tool_descriptors
                    .iter()
                    .any(|t| t.get("name").and_then(Value::as_str) == Some(tool.name.as_str()));
                if !already_present {
                    tool_descriptors.push(project_tool_descriptor_trust_card(
                        "gateway:promoted",
                        "mcp-gateway",
                        &tool,
                    ));
                }
            }
        }

        JsonRpcResponse::success(id, tools_list_result_with_trust_cards(tool_descriptors))
    }

    /// Dispatch the `tools/list` request with optional params — entry point for the router.
    ///
    /// When the `spec-preview` feature is active and the params contain a `query`
    /// key, delegates to the filtered handler (SEP-1821).  Otherwise falls back to
    /// the standard session-aware handler so baseline behaviour is unchanged.
    pub fn handle_tools_list_with_params(
        &self,
        id: RequestId,
        #[cfg_attr(not(feature = "spec-preview"), allow(unused_variables))] params: Option<&Value>,
        session_id: Option<&str>,
    ) -> JsonRpcResponse {
        #[cfg(feature = "spec-preview")]
        if let Some(q) = params.and_then(|p| p.get("query")).and_then(Value::as_str) {
            return self.handle_tools_list_filtered(id, q, session_id);
        }
        self.handle_tools_list_for_session(id, session_id)
    }

    /// Variant of [`handle_tools_list_with_params`] that accepts a per-request
    /// Code Mode override from the URL query parameter `?codemode=search_and_execute`.
    ///
    /// Precedence rules:
    /// - If the static config already has `code_mode.enabled = true`, the
    ///   result is always Code Mode regardless of `url_override`.
    /// - If `url_override` is `true`, Code Mode is active for this request only.
    /// - If both are `false`, the standard full meta-tool list is returned.
    ///
    /// When Code Mode is active via the URL override, the spec-preview filtered
    /// path is bypassed (Code Mode always returns exactly two tools).
    pub fn handle_tools_list_with_url_override(
        &self,
        id: RequestId,
        params: Option<&Value>,
        session_id: Option<&str>,
        url_override: bool,
    ) -> JsonRpcResponse {
        let effective_code_mode = self.code_mode_enabled || url_override;
        if effective_code_mode && !self.code_mode_enabled {
            // URL-activated Code Mode: return the two fixed tools directly.
            let tools = build_code_mode_tools();
            let tool_descriptors =
                project_tool_descriptors_trust_cards("gateway:meta", "mcp-gateway", &tools);
            return JsonRpcResponse::success(
                id,
                tools_list_result_with_trust_cards(tool_descriptors),
            );
        }
        // No override (or static config already handles it): follow normal path.
        self.handle_tools_list_with_params(id, params, session_id)
    }

    /// Handle `tools/call` — dispatch to the appropriate handler.
    ///
    /// Surfaced tool calls are intercepted before the meta-tool match arm and
    /// proxied directly to the owning backend via `gateway_invoke` semantics,
    /// giving callers transparent one-hop access to pinned tools.
    ///
    /// `api_key_name` — the name of the authenticated API key (for cost accounting).
    /// `agent_id` — optional caller agent identifier (OWASP ASI03).
    pub async fn handle_tools_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        caller: MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        // T2.4: Check surfaced tools BEFORE the meta-tool match.
        if let Some(server_name) = self.surfaced_tools_map.get(tool_name) {
            let invoke_args = json!({
                "server": server_name,
                "tool": tool_name,
                "arguments": arguments,
            });
            let result = self
                .invoke_tool(
                    &invoke_args,
                    session_id,
                    caller.api_key_name,
                    caller.agent_id,
                    caller.grant_subject.clone(),
                    caller.verified_identity,
                )
                .await;
            return match result {
                // `invoke_tool` already returns a complete MCP tools/call result
                // envelope ({content, structuredContent?, isError}) with output-
                // schema enforcement applied. A surfaced tool is called by the
                // client as a first-class tool, so the envelope must be returned
                // verbatim — re-wrapping via `wrap_tool_success` would stringify
                // the whole envelope into a text block and drop `structuredContent`
                // (which spec-compliant clients such as Open WebUI require when the
                // tool advertises an `outputSchema`).
                Ok(content) => JsonRpcResponse::success_serialized(id, content),
                Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
            };
        }

        let result = match tool_name {
            "gateway_search" => self.code_mode_search(&arguments, session_id).await,
            "gateway_execute" => {
                self.code_mode_execute(&arguments, session_id, &caller)
                    .await
            }
            "gateway_list_servers" => self.list_servers(),
            "gateway_list_tools" => self.list_tools(&arguments, session_id).await,
            "gateway_search_tools" => self.search_tools(&arguments, session_id).await,
            "gateway_invoke" => {
                self.invoke_tool(
                    &arguments,
                    session_id,
                    caller.api_key_name,
                    caller.agent_id,
                    caller.grant_subject,
                    caller.verified_identity,
                )
                .await
            }
            "gateway_get_stats" => self.get_stats(&arguments).await,
            "gateway_cost_report" => self.get_cost_report(&arguments, session_id).await,
            "gateway_webhook_status" => self.webhook_status(),
            "gateway_run_playbook" => self.run_playbook(&arguments).await,
            "gateway_kill_server" => self.kill_server(&arguments),
            "gateway_revive_server" => self.revive_server(&arguments),
            "gateway_list_disabled_capabilities" => self.list_disabled_capabilities(),
            "gateway_set_profile" => self.set_profile(&arguments, session_id),
            "gateway_get_profile" => self.get_profile(session_id),
            "gateway_list_profiles" => self.list_profiles(),
            "gateway_set_state" => self.set_state(&arguments, session_id),
            "gateway_reload_config" => self.reload_config().await,
            "gateway_reload_capabilities" => self.reload_capabilities().await,
            _ => {
                const META_TOOLS: &[&str] = &[
                    "gateway_search",
                    "gateway_execute",
                    "gateway_list_servers",
                    "gateway_list_tools",
                    "gateway_search_tools",
                    "gateway_invoke",
                    "gateway_get_stats",
                    "gateway_cost_report",
                    "gateway_webhook_status",
                    "gateway_run_playbook",
                    "gateway_kill_server",
                    "gateway_revive_server",
                    "gateway_list_disabled_capabilities",
                    "gateway_set_profile",
                    "gateway_get_profile",
                    "gateway_list_profiles",
                    "gateway_set_state",
                    "gateway_reload_config",
                    "gateway_reload_capabilities",
                ];
                let suggestion = did_you_mean(tool_name, META_TOOLS, 3, 3);
                let msg = match suggestion {
                    Some(hint) => format!("Unknown tool: {tool_name}. {hint}"),
                    None => format!("Unknown tool: {tool_name}"),
                };
                Err(Error::json_rpc(-32601, msg))
            }
        };

        match result {
            Ok(content) => {
                let has_output_schema = tool_name == "gateway_search_tools";
                wrap_tool_success(id, &content, has_output_schema)
            }
            Err(e) => JsonRpcResponse::error(Some(id), e.to_rpc_code(), e.to_string()),
        }
    }
}

// ============================================================================
// FSM workflow state meta-tool
// ============================================================================

impl MetaMcp {
    /// Handle `gateway_set_state` — transition the session's FSM workflow state.
    ///
    /// Returns the previous state, the new state, and the number of capability
    /// tools visible in the new state (across all capability backends).
    fn set_state(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let Some(sid) = session_id else {
            return Err(Error::Protocol(
                "gateway_set_state requires a session (send Mcp-Session-Id header)".to_string(),
            ));
        };

        let new_state = extract_required_str(args, "state")?;
        let previous = self.session_state.set_state(sid, new_state);

        // Count visible capability tools in the new state for the response payload.
        let visible_tools = self
            .get_capabilities()
            .map_or(0, |cap| cap.get_tools_for_state(new_state).len());

        debug!(
            session_id = sid,
            previous = %previous,
            current = new_state,
            visible_tools = visible_tools,
            "Session FSM state transition"
        );

        Ok(json!({
            "previous": previous,
            "current": new_state,
            "visible_tools": visible_tools,
            "session_id": sid,
        }))
    }
}

// ============================================================================
// Routing profile meta-tools
// ============================================================================

impl MetaMcp {
    fn set_profile(&self, args: &Value, session_id: Option<&str>) -> Result<Value> {
        let Some(sid) = session_id else {
            return Err(Error::Protocol(
                "gateway_set_profile requires a session (send Mcp-Session-Id header)".to_string(),
            ));
        };

        let profile_name = extract_required_str(args, "profile")?;

        if !self.profile_registry.contains(profile_name) {
            let available = self.profile_registry.profile_names();
            return Err(Error::Protocol(format!(
                "Unknown routing profile '{profile_name}'. Available profiles: {}",
                if available.is_empty() {
                    "none configured".to_string()
                } else {
                    available.join(", ")
                }
            )));
        }

        self.session_profiles.set_profile(sid, profile_name);
        let profile = self.profile_registry.get(profile_name);
        Ok(json!({
            "profile": profile_name,
            "session_id": sid,
            "description": profile.describe(),
            "message": format!("Routing profile set to '{profile_name}'")
        }))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn get_profile(&self, session_id: Option<&str>) -> Result<Value> {
        let profile = self.active_profile(session_id);
        Ok(json!({
            "profile": profile.name,
            "session_id": session_id,
            "description": profile.describe(),
            "available_profiles": self.profile_registry.profile_names(),
        }))
    }

    #[allow(clippy::unnecessary_wraps)]
    fn list_profiles(&self) -> Result<Value> {
        let summaries = self.profile_registry.profile_summaries();
        let total = summaries.len();
        let default_name = self.profile_registry.default_name();
        Ok(json!({ "profiles": summaries, "default": default_name, "total": total }))
    }
}

// ============================================================================
// Tests (extracted to tests.rs for LOC compliance)
// ============================================================================

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
