// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Meta-MCP implementation — meta-tools for dynamic discovery and playbooks.
//!
//! Module layout:
//! - `mod.rs` — struct, constructors, shared consts and dispatch types, test module declarations
//! - `caller_context.rs` — `MetaMcpCallerContext`
//! - `builders.rs` — `with_*` builders and setters
//! - `accessors.rs` — accessor helpers used by sibling modules
//! - `handlers.rs` — `server/discover`, `initialize`, `tools/list`
//! - `call_dispatch.rs` — `tools/call` routing and the dispatch below the gate
//! - `session_tools.rs` — FSM workflow-state and routing-profile meta-tools
//! - `search.rs` — `code_mode_search`, `code_mode_execute`, `execute_chain`, `list_tools`, `search_tools`
//! - `invoke.rs` — `invoke_tool`, `dispatch_to_backend`, stats, kill/revive, playbook, reload
//! - `resources.rs` — `handle_resources_*` and `find_resource_owner`
//! - `protocol.rs` — `handle_prompts_*`, `handle_logging_*`, `current_log_level`
//! - `support.rs` — free functions: tag collection, ranking helpers, `MetaMcpInvoker`, augment
//! - `surfaced.rs` — `with_surfaced_tools`, `resolve_surfaced_tool`, `list_servers`

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "spec-preview")]
use dashmap::DashMap;
use parking_lot::RwLock;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::attestation::signer::BnautAttestationSigner;
use crate::capability::CapabilityBackend;
use crate::config::SurfacedToolConfig;
use crate::config_reload::ReloadContext;
use crate::context_integrity::ContextIntegrityKernel;
use crate::cost_accounting::CostTracker;
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::enforcer::BudgetEnforcer;
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::registry::CostRegistry;
use crate::gateway::router::CallerStanding;
use crate::gateway::session_id::session_fp;
use crate::gateway::state::SessionStateStore;
use crate::idempotency::{IdempotencyCache, spawn_cleanup_task};
use crate::identity_grants::{GrantSubject, LocalIdentityGrantStore};
use crate::kill_switch::{CapabilityErrorBudgetConfig, ErrorBudgetConfig, KillSwitch};
use crate::playbook::PlaybookEngine;
use crate::protocol::meta::Declared;
use crate::protocol::{ChainSource, JsonRpcResponse, LoggingLevel, RequestId, negotiate_version};
use crate::ranking::SearchRanker;
use crate::routing_profile::{ProfileRegistry, SessionProfileStore};
use crate::security::message_signing::{MessageSigner, NonceStore};
use crate::transition::TransitionTracker;
use crate::trust::{
    project_tool_descriptor_trust_card, project_tool_descriptors_trust_cards,
    tools_list_result_with_trust_cards,
};
use crate::{Error, Result};
use crate::{backend::BackendRegistry, cache::ResponseCache};
use crate::{stats::UsageStats, tool_registry::ToolRegistry};

use super::meta_mcp_helpers::{
    build_code_mode_tools, build_discovery_preamble, build_initialize_result,
    build_routing_instructions, extract_client_version, extract_required_str,
};
use super::meta_mcp_tool_defs::{MetaToolExposure, ToolTotal};
use super::meta_mcp_tool_total::tool_total;
use super::webhooks::WebhookRegistry;
#[cfg(test)]
use confirmation::{CONFIRMATION_INPUT_KEY, confirmation_refusal_response};
use confirmation::{GateOutcome, destructive_confirmation_gate};

pub(crate) mod admission;
#[cfg(test)]
mod audit_record_tests;
#[cfg(test)]
mod callback_admin_denial_tests;
mod caller_forward;
mod catalogue_cache;
mod chain_interim;
#[cfg(test)]
mod chain_interim_tests;
mod confirmation;
#[cfg(all(test, feature = "cost-governance"))]
mod cost_test_support;
#[cfg(test)]
mod declared_label_carry_tests;
mod direct_route;
mod discovery_fetch;
pub(crate) mod dispatch_log;
mod dispatch_names;
mod effects;
mod events_hook;
pub(crate) mod grant_audit;
mod interim_promotion;
#[cfg(test)]
mod interim_promotion_tests;
pub(crate) mod invoke;
mod prompt_cache;
mod protocol;
mod resources;
pub(crate) mod response_security;
pub(crate) use response_security::error_response_preserving_status;
#[cfg(test)]
mod response_security_tests;
mod search;
pub(crate) mod signing;
#[cfg(feature = "spec-preview")]
mod spec_preview;
mod support;
mod surfaced;
mod task_confirmation;
pub(crate) mod task_notify;
mod task_replay;
pub(crate) mod upstream;
mod visibility;

pub use visibility::InvokeScope;

pub use prompt_cache::{CacheKeyDeriver, stable_tool_order, tool_schema_fingerprint};
pub(crate) use support::Authentication;
pub use support::prune_constant_signals;
pub(crate) use task_confirmation::{
    AdmissionOwner, TaskConfirmation, TaskConfirmationRequest, task_admission_request,
};

mod accessors;
mod builders;
mod call_dispatch;
mod caller_context;
mod handlers;
mod session_tools;
pub use caller_context::MetaMcpCallerContext;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of dynamically promoted tools stored per session.
///
/// When a session exceeds this limit the oldest entry is evicted (FIFO).
/// Configurable in future; hard-coded for Phase 3 initial implementation.
#[cfg(feature = "spec-preview")]
const MAX_PROMOTED_PER_SESSION: usize = 10;

/// Reserved prefix for principals the gateway itself assigns. A NUL cannot
/// occur in an HTTP header value or in any principal the auth layer derives
/// (hex digests and fixed words), so no presented credential starts with it.
pub(crate) const LOCAL_OPERATOR_PREFIX: char = '\0';

/// The principal the stdio transport's own contexts key their retained
/// results under. See [`MetaMcpCallerContext::owner_principal`].
pub(crate) const LOCAL_OPERATOR_PRINCIPAL: &str = "\0local-operator.v1";

/// Meta-MCP handler — the central dispatcher for all gateway meta-tools.
// Independent, unrelated switches on a long-lived handler. A state machine
// over their product would have more states than the struct has fields.
#[allow(clippy::struct_excessive_bools)]
pub struct MetaMcp {
    pub(super) backends: Arc<BackendRegistry>,
    pub(super) change_feed: std::sync::OnceLock<crate::gateway::ChangeFeed>,
    /// MCP Events hub (MIK-7630); unset while events are off or on stdio.
    pub(super) events: std::sync::OnceLock<Arc<crate::events::EventsHub>>,
    pub(super) capabilities: RwLock<Option<Arc<CapabilityBackend>>>,
    pub(super) cache: Option<Arc<ResponseCache>>,
    pub(super) default_cache_ttl: Duration,
    pub(super) idempotency_cache: Option<Arc<IdempotencyCache>>,
    /// MIK-7692: the last written stored-delivery re-check decisions.
    pub(super) grant_repeats: Arc<grant_audit::DecisionDedupe>,
    /// One bounded execution owner shared by the meta and direct transports.
    ///
    /// The ledger is in-memory and owned per [`MetaMcp`]: `State.entries` is a
    /// plain `HashMap` behind a `Mutex` (`src/idempotency/admission.rs:72-86`),
    /// with no shared storage and no persistence across a restart. That is what
    /// makes a constant caller principal safe to use as a key namespace on a
    /// single-client transport — see `STDIO_CREDENTIAL_PRINCIPAL`
    /// (`src/gateway/server/mod.rs`), where two stdio processes cannot collide
    /// because they do not share this map. If the ledger ever gains shared
    /// storage, every constant namespace has to be revisited first.
    pub(super) execution_admission: Arc<crate::idempotency::admission::ExecutionAdmission>,
    pub(super) idempotency_config: RwLock<crate::config::IdempotencyConfig>,
    /// `server.idempotency_key` and the un-keyed admission warn limit (F10).
    pub(super) unkeyed: admission::UnkeyedPolicy,
    /// Continuation keys, spent-ledger and held legacy exchanges.
    ///
    /// Here rather than on `AppState` because of lifetime: this struct is built
    /// once per gateway run, while the caller context is built per call, and a
    /// keyring rebuilt per call would refuse every retry that arrived on a
    /// later request. `AppState` shares this same `Arc` rather than minting its
    /// own — two keyrings would mint on one and redeem on the other, and every
    /// refusal would say only "continuation rejected".
    pub(super) continuation: Arc<crate::protocol::continuation::ContinuationState>,
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
    /// Where a call takes its session hold (MIK-7996); set by the wiring.
    session_lifecycle:
        std::sync::OnceLock<std::sync::Weak<crate::gateway::session_lifecycle::SessionLifecycle>>,
    pub(super) reload_context: RwLock<Option<Arc<ReloadContext>>>,
    /// End-user identity-propagation strategy (MIK-6704 / ADR-007). `Some` when
    /// at least one backend is configured for propagation; the dispatch path
    /// uses it to mint a per-user credential for such backends. `None` disables
    /// propagation entirely (all backends keep static-credential behavior).
    pub(super) identity_propagation:
        RwLock<Option<Arc<dyn crate::identity_propagation::IdentityPropagation>>>,
    /// Per-backend identity-propagation strategies, installed at startup for
    /// backends bound to an `accounts.descriptors` entry.
    ///
    /// The process-wide field above installs at most ONE minting strategy, so a
    /// deployment mixing an external token-exchange descriptor with a managed
    /// vault one could never dispatch both. A per-backend entry is consulted
    /// FIRST by the single resolver: the credential a backend gets is the one
    /// its own descriptor compiled to, never whichever kind happened to be
    /// installed process-wide. A backend with no entry keeps the existing
    /// behaviour exactly.
    pub(super) backend_identity_propagation: RwLock<
        std::collections::HashMap<
            String,
            Arc<dyn crate::identity_propagation::IdentityPropagation>,
        >,
    >,
    /// Per-DESCRIPTOR account strategies, shared with the capability executor.
    ///
    /// The map above is keyed by backend name, which a REST capability does not
    /// have: it names an `accounts.descriptors` map key directly and may be
    /// that account's only consumer. The shared installer writes ONE strategy
    /// per descriptor here and hands the same `Arc` to the per-backend map, so
    /// both consumers of one account hold one instance.
    pub(super) account_strategies: Arc<crate::identity_propagation::AccountStrategyRegistry>,
    /// The dispatch sites' connect offer (MIK-6745 §9.2); `None` until installed.
    pub(super) connect_offers: RwLock<Option<Arc<crate::gateway::router::ConnectOffers>>>,
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

    /// Which meta-tools this gateway exposes, from `MetaMcpConfig::exposed_meta_tools`.
    ///
    /// Consulted on both `tools/list` and `tools/call`. The default exposes every
    /// meta-tool, so an existing deployment is unaffected.
    pub(super) meta_tool_exposure: MetaToolExposure,
    /// Meta catalogues already built, shared by identity (MIK-7916).
    meta_catalogues: catalogue_cache::MetaCatalogues,
    /// Their trust-card projections, recognised by the catalogue's `Arc`.
    meta_projections: crate::trust::SharedProjections,
    /// List `gateway_get_stats`, from `MetaMcpConfig::expose_stats_tool`.
    ///
    /// Enumeration only: the handler answers whoever calls it by name either
    /// way. Separate from `meta_tool_exposure` because that is an allow-list
    /// over the whole surface, while this is one tool's own gate.
    pub(super) expose_stats_tool: bool,
    /// Per-backend bound for `prompts/list` and `resources/list`
    /// aggregation. Configurable via `meta_mcp.prompts_resources_fetch_timeout`
    /// (default 10s); overridable per-instance for tests.
    pub(super) prompts_resources_fetch_timeout: std::time::Duration,
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

    /// Which stdio `tools/call` requests get a signing context. HTTP reads the
    /// live posture per request; stdio has one process-lifetime posture, set at
    /// build time, so a hardened stdio caller is signed on every tool call
    /// exactly as an HTTP one is (MIK-7886).
    pub(super) signing_scope: signing::SigningScope,

    /// Runtime provenance receipt signer (MIK-6905).
    ///
    /// `Some` when `security.provenance_stamping = true`; `None` otherwise.
    /// When `None` the stamping block is skipped entirely, so result payloads
    /// are byte-identical to the un-stamped path (rung 1.2 guarantee).
    pub(super) provenance_signer: Option<Arc<BnautAttestationSigner>>,

    /// ASI07 chain identity and emission mode; `None` = feature off.
    pub(super) chain_signer: Option<Arc<response_security::ChainIdentity>>,

    /// Shadow claim-capture sink (MIK-6908, rung 3.1).
    ///
    /// `Some` when `security.claim_capture.enabled = true`; `None` otherwise.
    /// Only ever consulted alongside `provenance_signer` — capture has
    /// nothing to record without a signed receipt.
    pub(super) claim_capture: Option<Arc<crate::trust::ClaimCaptureSink>>,

    /// When `true`, requests without a `nonce` are rejected with JSON-RPC -32001.
    ///
    /// Corresponds to `security.message_signing.require_nonce` in config.
    pub(super) require_nonce: bool,

    /// Tamper-evident hash-chain transparency log (issue #133, D3).
    ///
    /// `Some` when `security.transparency_log.enabled = true`; `None` otherwise.
    /// Zero overhead when `None` — no allocation or I/O on the hot path.
    pub(super) transparency_logger: Option<Arc<crate::security::TransparencyLogger>>,

    /// MIK-7116.MIN.2: auditor of withheld frames, built on first use.
    rejection_audit: std::sync::OnceLock<Arc<crate::gateway::outbound::RejectionAudit>>,

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
    pub(super) identity_grants: Arc<RwLock<LocalIdentityGrantStore>>,

    /// Authorization-policy generation mixed into every response-cache key.
    ///
    /// One counter for this handler. Bumped in [`Self::set_identity_grants`]
    /// after the new grant store is published, while that write lock is still
    /// held. Captured once per invoke with `Acquire` before authorization
    /// runs; that snapshot is the only value either cache-key build may use.
    /// A second load at the write site publishes a pre-bump body under the
    /// post-bump epoch.
    pub(super) policy_epoch: Arc<AtomicU64>,

    /// Which caller identity headers are honoured, and from whom. Off by
    /// default because direct clients can otherwise spoof headers.
    caller_identity: crate::security::caller_identity::CallerIdentityConfig,
    /// Verifier for `Cf-Access-Jwt-Assertion`, built iff the mode is
    /// `cloudflare_access`.
    access_verifier: Option<Arc<crate::key_server::OidcVerifier>>,

    /// Tool-result boundary classifier and policy envelope.
    ///
    /// Defaults to monitor-only. Clean benign results are returned unchanged;
    /// suspicious results receive `_context_integrity` audit metadata before
    /// response caching, idempotency completion, signing, and delivery.
    pub(super) context_integrity_kernel: RwLock<ContextIntegrityKernel>,

    /// Security firewall used to scan aggregated tool-list / search responses
    /// (OWASP ASI01 tool-poisoning defense, MIK security-audit v3.1.3).
    ///
    /// `Some` mirrors the same `Arc<Firewall>` held by `AppState`, so the
    /// Meta-MCP discovery surface (`gateway_list_tools` / `gateway_search_tools`)
    /// scans and redacts backend-supplied tool descriptions with the exact
    /// config as the direct `tools/call` path. `None` (the default, and the
    /// stdio path) disables scanning — a zero-cost no-op on the hot path.
    pub(super) firewall: Option<Arc<invoke::egress::Firewall>>,
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
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            backends,
            change_feed: std::sync::OnceLock::new(),
            events: std::sync::OnceLock::new(),
            capabilities: RwLock::new(None),
            cache,
            default_cache_ttl,
            idempotency_cache: None,
            grant_repeats: Arc::default(),
            execution_admission: crate::idempotency::admission::ExecutionAdmission::new(clock),
            idempotency_config: RwLock::new(crate::config::IdempotencyConfig::default()),
            unkeyed: admission::UnkeyedPolicy::default(),
            continuation: Arc::new(crate::protocol::continuation::ContinuationState::new()),
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
            session_lifecycle: std::sync::OnceLock::new(),
            reload_context: RwLock::new(None),
            identity_propagation: RwLock::new(None),
            backend_identity_propagation: RwLock::new(std::collections::HashMap::new()),
            account_strategies: Arc::new(
                crate::identity_propagation::AccountStrategyRegistry::default(),
            ),
            connect_offers: RwLock::new(None),
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
            meta_tool_exposure: MetaToolExposure::expose_all(),
            meta_catalogues: catalogue_cache::MetaCatalogues::default(),
            meta_projections: crate::trust::SharedProjections::default(),
            expose_stats_tool: false,
            prompts_resources_fetch_timeout: std::time::Duration::from_secs(10),
            #[cfg(feature = "spec-preview")]
            session_promoted: Arc::new(DashMap::new()),
            session_state: SessionStateStore::new(),
            message_signer: None,
            nonce_store: None,
            signing_scope: signing::SigningScope::InvokeOnly,
            provenance_signer: None,
            chain_signer: None,
            claim_capture: None,
            require_nonce: false,
            transparency_logger: None,
            rejection_audit: std::sync::OnceLock::new(),
            response_inspection_action_mode: false,
            response_contract: None,
            attestation_validator: None,
            attestation_mode: crate::attestation::AttestationMode::Observe,
            identity_grants: Arc::new(RwLock::new(LocalIdentityGrantStore::new())),
            policy_epoch: Arc::new(AtomicU64::new(0)),
            caller_identity: crate::security::caller_identity::CallerIdentityConfig::default(),
            access_verifier: None,
            context_integrity_kernel: RwLock::new(ContextIntegrityKernel::default()),
            firewall: None,
        }
    }

    /// Create a new Meta-MCP handler.
    pub fn new(backends: Arc<BackendRegistry>) -> Self {
        Self::with_features(backends, None, None, None, Duration::from_secs(60))
    }

    /// Create a new Meta-MCP handler with cache, stats, and ranking support.
    pub fn with_features(
        backends: Arc<BackendRegistry>,
        cache: Option<Arc<ResponseCache>>,
        stats: Option<Arc<UsageStats>>,
        ranker: Option<Arc<SearchRanker>>,
        default_ttl: Duration,
    ) -> Self {
        Self::with_features_and_clock(
            backends,
            cache,
            stats,
            ranker,
            default_ttl,
            Arc::new(crate::protocol::continuation::now_unix_secs),
        )
    }

    /// Build the real handler with its serving runtime's trusted epoch source.
    pub(crate) fn with_features_and_clock(
        backends: Arc<BackendRegistry>,
        cache: Option<Arc<ResponseCache>>,
        stats: Option<Arc<UsageStats>>,
        ranker: Option<Arc<SearchRanker>>,
        default_ttl: Duration,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self::build(backends, cache, stats, ranker, default_ttl, clock)
    }

    /// The continuation state this run mints and redeems with.
    ///
    /// Handed to `AppState` so the legacy bridge redeems against the same
    /// keyring and the same spent-ledger this path mints into.
    #[must_use]
    pub fn continuation(&self) -> Arc<crate::protocol::continuation::ContinuationState> {
        Arc::clone(&self.continuation)
    }

    pub(crate) fn execution_admission(
        &self,
    ) -> &Arc<crate::idempotency::admission::ExecutionAdmission> {
        &self.execution_admission
    }

    pub(crate) fn set_idempotency_config(&self, config: crate::config::IdempotencyConfig) {
        *self.idempotency_config.write() = config;
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
                top_tools: vec![],
                total_cached_tokens: 0,
                cached_tokens_by_server: vec![],
            },
        }
    }
}

/// The session a request belongs to, if it has one.
///
/// MCP 2026-07-28 removed protocol-level sessions, and the router spells that
/// absence as an empty id rather than `None` (`router::handlers`, the
/// `declares_modern_by_header` branch). The rest of the router already reads
/// it that way — `router::helpers::attach_session_header` omits the header
/// rather than emitting an empty one — so an empty id is not a session with an
/// unusual name, it is the absence of one.
///
/// Routing profiles must read it the same way or they break `ORDER.2`: the
/// empty key is shared by *every* sessionless caller, so a profile stored
/// under it does not merely vary the tool set per connection, it varies it
/// across connections.
fn session_key(session_id: Option<&str>) -> Option<&str> {
    session_id.filter(|sid| !sid.is_empty())
}

/// Refusal shared by the two routing-profile meta-tools.
///
/// Both are refused, not only the writer: answering `gateway_get_profile`
/// would describe a selection the caller cannot make and cannot rely on.
const NO_SESSION_FOR_PROFILE: &str = "Routing profiles are per-session, and this connection has no session. \
     MCP 2026-07-28 removed protocol-level sessions; the tool set is decided \
     by the authorization presented on each request.";

/// The same refusal for the FSM workflow state, and for the same reason: the
/// state is stored per session, and a connection with no session would be
/// storing it under a key every other sessionless connection also reads.
///
/// It also closes the recovery route: a sessionless caller cannot reach that
/// shared state by supplying a header its protocol revision no longer uses,
/// because `session_key` maps the empty header to the same `None`.
const NO_SESSION_FOR_STATE: &str = "The workflow state is per-session, and this connection has no session. \
     MCP 2026-07-28 removed protocol-level sessions; capability visibility is \
     decided by the authorization presented on each request.";

/// The request `dispatch_below_gate_shaped` routes, common to both entry
/// points above it.
struct DispatchTarget<'a> {
    id: RequestId,
    tool_name: &'a str,
    arguments: Value,
    session_id: Option<&'a str>,
    caller: &'a MetaMcpCallerContext<'a>,
}

/// How a dispatch's own result is presented, and the only thing the two
/// entry points above disagree about. The routing, the checks and the error
/// side are one code path.
#[derive(Clone, Copy)]
enum ResultShape {
    /// The synchronous meta-tool reply: `wrap_tool_success`, unchanged.
    Wrapped,
    /// The tool's result as it came back, for a task to settle on.
    Native,
}

// ============================================================================
// Tests (extracted to tests.rs for LOC compliance)
// ============================================================================

#[cfg(test)]
pub(crate) mod account_resolver_fixture;
#[cfg(test)]
mod account_resolver_gate;
#[cfg(test)]
mod account_resolver_tests;
#[cfg(test)]
mod account_rest_fixture;
#[cfg(test)]
mod account_rest_tests;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Publish a grant store and advance the policy epoch, in that order, under
/// the store's write lock.
///
/// THE ONE PLACE THAT ORDERING LIVES. `MetaMcp::set_identity_grants` and
/// `ReloadContext::reload_identity_grants` both route through here rather than
/// each spelling out write-then-bump: duplicating four lines at a second site
/// is how the `Release` gets dropped in a later edit, and the failure is
/// silent — a reader observing the new epoch while still seeing the old
/// grants.
pub(crate) fn publish_identity_grants(
    sink: &RwLock<LocalIdentityGrantStore>,
    epoch: &AtomicU64,
    grants: LocalIdentityGrantStore,
) {
    let mut lock = sink.write();
    *lock = grants;
    let prev = epoch.fetch_add(1, Ordering::Release);
    debug_assert!(
        epoch.load(Ordering::Relaxed) > prev,
        "policy epoch must be monotonic; a reset reuses keys minted under superseded grants"
    );
}

// NOTE, and it is a finding rather than a style choice: `policy_epoch_tests.rs`
// once had no `mod` declaration anywhere in `src/`, so it never compiled while
// the live-identity-grant-reload design cited it as proof that a pre-change
// response-cache entry cannot be served after `set_identity_grants`. Declared
// below now, and it discriminates: dropping the `fetch_add` in
// `publish_identity_grants` reddens both cells. Registering this one explicitly
// so the same cannot happen to these.
#[cfg(test)]
#[path = "grant_reload_tests.rs"]
mod grant_reload_tests;

#[cfg(test)]
#[path = "grant_agent_key_tests.rs"]
mod grant_agent_key_tests;

#[cfg(test)]
#[path = "authz_tests.rs"]
mod authz_tests;

#[cfg(test)]
#[path = "search_disclosure_e2e.rs"]
mod search_disclosure_e2e;

#[cfg(test)]
#[path = "trace_correlation_tests.rs"]
mod trace_correlation_tests;

#[cfg(test)]
#[path = "chain_resume_live_tests.rs"]
mod chain_resume_live_tests;

#[cfg(test)]
#[path = "account_entry_point_authz_tests.rs"]
mod account_entry_point_authz_tests;

#[cfg(test)]
#[path = "search_ranking_authz_tests.rs"]
mod search_ranking_authz_tests;

#[cfg(test)]
#[path = "search_login_gate_tests.rs"]
mod search_login_gate_tests;

#[cfg(test)]
#[path = "era_gate_tests.rs"]
mod era_gate_tests;

#[cfg(test)]
#[path = "outbound_log_tests.rs"]
mod outbound_log_tests;

#[cfg(test)]
#[path = "surface_compaction_tests.rs"]
mod surface_compaction_tests;

#[cfg(test)]
#[path = "catalogue_isolation_tests.rs"]
mod catalogue_isolation_tests;

#[cfg(test)]
#[path = "catalogue_per_caller_tests.rs"]
mod catalogue_per_caller_tests;

#[cfg(test)]
mod test_callers;
#[cfg(test)]
pub(super) use test_callers::{anonymous_caller, callback_capability, identified_caller};

#[cfg(test)]
pub(super) mod grant_audit_fixture;
#[cfg(test)]
mod grant_decision_audit_tests;
#[cfg(test)]
mod grant_decision_slot_tests;
#[cfg(test)]
mod grant_replay_dedupe_tests;
#[cfg(test)]
#[path = "policy_epoch_tests.rs"]
mod policy_epoch_tests;
#[cfg(test)]
mod task_notify_tests;

mod session_end;

#[cfg(test)]
#[path = "session_bound_tests.rs"]
mod session_bound_tests;

#[cfg(test)]
#[path = "session_cleanup_tests.rs"]
mod session_cleanup_tests;

#[cfg(test)]
#[path = "session_inflight_tests.rs"]
pub(crate) mod session_inflight_tests;

#[cfg(all(test, feature = "firewall"))]
#[path = "dispatch_reads_tests.rs"]
mod dispatch_reads_tests;
