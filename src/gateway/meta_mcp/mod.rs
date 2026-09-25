// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[cfg(feature = "spec-preview")]
use dashmap::DashMap;
use parking_lot::RwLock;
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::attestation::signer::BnautAttestationSigner;
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
use crate::gateway::router::CallerStanding;
use crate::gateway::state::SessionStateStore;
use crate::idempotency::{IdempotencyCache, spawn_cleanup_task};
use crate::identity_grants::{GrantSubject, LocalIdentityGrantStore};
use crate::kill_switch::{CapabilityErrorBudgetConfig, ErrorBudgetConfig, KillSwitch};
use crate::playbook::PlaybookEngine;
use crate::protocol::meta::Declared;
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
    build_code_mode_tools, build_discovery_preamble, build_initialize_result,
    build_routing_instructions, did_you_mean, extract_client_version, extract_required_str,
    wrap_tool_success,
};
use super::meta_mcp_tool_defs::{
    MetaToolExposure, MetaToolGates, ToolTotal, build_meta_tools_filtered,
    require_gateway_invoke_nonce,
};
use super::meta_mcp_tool_total::tool_total;
use super::webhooks::WebhookRegistry;
#[cfg(test)]
use confirmation::{CONFIRMATION_INPUT_KEY, confirmation_refusal_response};
use confirmation::{GateOutcome, destructive_confirmation_gate};

pub(crate) mod admission;
mod caller_forward;
mod chain_interim;
#[cfg(test)]
mod chain_interim_tests;
mod confirmation;
mod direct_route;
mod discovery_fetch;
mod interim_promotion;
#[cfg(test)]
mod interim_promotion_tests;
pub(crate) mod invoke;
mod prompt_cache;
mod protocol;
mod resources;
pub(crate) mod response_security;
#[cfg(test)]
mod response_security_tests;
mod search;
pub(crate) mod signing;
#[cfg(feature = "spec-preview")]
mod spec_preview;
mod support;
mod surfaced;
mod task_confirmation;
pub(crate) mod upstream;
mod visibility;

pub use visibility::InvokeScope;

pub use prompt_cache::{CacheKeyDeriver, stable_tool_order, tool_schema_fingerprint};
pub(crate) use support::Authentication;
pub use support::prune_constant_signals;
pub(crate) use task_confirmation::{
    TaskConfirmation, TaskConfirmationRequest, task_admission_request,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of dynamically promoted tools stored per session.
///
/// When a session exceeds this limit the oldest entry is evicted (FIFO).
/// Configurable in future; hard-coded for Phase 3 initial implementation.
#[cfg(feature = "spec-preview")]
const MAX_PROMOTED_PER_SESSION: usize = 10;

/// Authenticated caller context for a `tools/call` dispatch.
///
/// Deliberately has **no `Default`**: the authorizer is mandatory, and a
/// derived default would let a construction site acquire one by omission. Every
/// site names the authorizer it means, which in tests makes a permissive one
/// visible in the test source rather than hidden in a struct default.
pub struct MetaMcpCallerContext<'a> {
    /// Explicit request era, classified by the transport from reserved metadata.
    pub is_modern: bool,
    /// Validated protocol revision this request is served under.
    ///
    /// Classifier output, never the duplicate-header sentinel. `None` skips
    /// outer response-cache get/set and, on an attached executor, inner cache.
    /// Distinct from `is_modern` and from any peer `era` field on this struct.
    pub protocol_revision: Option<&'a str>,
    /// Stable validated credential principal; display names are never authority.
    pub credential_principal: Option<&'a str>,
    /// Whether a credential was presented and validated. Explicit, never
    /// inferred from `credential_principal` (see [`Authentication`]).
    pub(crate) authentication: Authentication,
    /// Outer execution owner; an inner step can mark dispatch but cannot settle it.
    pub(crate) execution: Option<&'a admission::SyncLease>,
    /// Private external origin and completed signing admission, never backend metadata.
    pub(crate) signing: Option<&'a signing::SigningInvocationContext>,
    /// Decides whether this caller may invoke a given backend tool.
    ///
    /// Borrowed, never stored: `AppState` owns `meta_mcp`, so holding an
    /// `Arc<AppState>` inside `MetaMcp` would be a cycle that never frees.
    pub authorizer: &'a (dyn crate::gateway::authz::ToolAuthorizer + Sync),
    /// Static or temporary API-key name, used for accounting and fallback grants.
    pub api_key_name: Option<&'a str>,
    /// The calling agent's PROVEN principal, for access decisions.
    ///
    /// A distinct type, not an `Option<&str>` beside a declared one: two
    /// interchangeable string fields would leave the wrong value representable
    /// at every call site. `ProvenAgentId` has no public constructor, so a
    /// caller-supplied label cannot reach an authorization input without a
    /// compile error.
    pub agent_id: Option<crate::security::ProvenAgentId<'a>>,
    /// The calling agent's DECLARED tag, for audit and cost attribution only.
    ///
    /// Recorded alongside the proven principal and never instead of it: a
    /// record that collapses them cannot distinguish "agent-a proved it" from
    /// "someone said agent-a", which is the signal funded change 4 exists to
    /// create.
    pub agent_declared: Option<crate::security::DeclaredAgentLabel<'a>>,
    /// Verified caller subject for identity-grant evaluation.
    pub grant_subject: Option<GrantSubject>,
    /// Full verified end-user identity, when present. Carried (not collapsed to
    /// `grant_subject`) so the backend-invoke boundary can propagate the real
    /// user to a backend that requires it (MIK-6704 / ADR-007 R2).
    pub verified_identity: Option<&'a crate::key_server::oidc::VerifiedIdentity>,
    /// Whether the caller holds admin. Carried here because meta-tools with
    /// admin-only PARAMETERS cannot be gated by the tool-name allow-list in
    /// `router::authorization`, which only knows whole tools.
    pub is_admin: bool,
    /// What this caller declared on **this** request.
    ///
    /// A parsed set rather than a single "may be asked for input" bit, because
    /// MRTR.9 refuses per requested method and MRTR.9a per requested *mode*: a
    /// client that declared `elicitation` and not `sampling` may be sent one
    /// and not the other, and one that declared elicitation in form mode alone
    /// may not be sent a url request. On stdio there is no per-request
    /// declaration to read, so this is [`Declared::NONE`] — absent means
    /// absent, and a caller that declared nothing is never sent a continuation.
    pub input_capabilities: Declared,
    /// How this caller can be asked to confirm a destructive action.
    ///
    /// A transport that has no way to reach an operator carries
    /// [`ConfirmationChannel::Unavailable`] and its destructive calls are
    /// refused. Deciding that here, rather than at one edge, is what makes the
    /// gate apply to every transport that dispatches.
    pub confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel<'a>,
    /// The multi-round-trip fields this call carried, already parsed.
    ///
    /// Borrowed inbound shape, still attacker-controlled: `request_state` here
    /// is whatever the client sent back, and only becomes trustworthy once the
    /// gateway opens it as one of its own sealed envelopes. Nothing downstream
    /// may forward this field to a backend verbatim.
    pub retry: &'a crate::protocol::mrtr::RetryFields,
    /// Background-task intent, taken after the destructive confirmation gate.
    /// `None` on every synchronous call and on the worker's rebuilt context.
    pub task: Option<crate::gateway::task_service::TaskIntent>,
    /// Which protocol era this caller declared on **this** request.
    ///
    /// Carried rather than re-derived: both production sites already hold the
    /// `RequestShape` classification that `initialize` advertises against, and
    /// a second era predicate computed downstream is exactly the drift
    /// [`crate::protocol::meta::classify_request`] exists to prevent.
    ///
    /// No `Default`, for the same reason the authorizer has none — a defaulted
    /// era is a site that silently claims an era it never saw.
    ///
    /// SCAFFOLD as of this commit: the reader is the MRTR.9 gate at
    /// `meta_mcp::invoke` (`interim.undeclared(caller.input_capabilities)`),
    /// which must merge the session declaration for `Legacy` and read only the
    /// request's own `_meta` for `Modern`. That merge is `MIK-7212.WIRE.1`
    /// through `WIRE.4` and lands next; until it does, nothing on the
    /// production path reads this field.
    pub era: crate::protocol::meta::Era,
    /// How this caller can be sent a request of the gateway's own — a bridged
    /// `sampling/createMessage` or `elicitation/create`.
    ///
    /// Distinct from `confirmation`, which answers a narrower question and
    /// would become a general client-request pipe if reused for this. A
    /// transport with nowhere to send carries
    /// [`crate::gateway::input_bridge::NoClientChannel`], so "cannot ask" is a
    /// channel that refuses rather than an absent one every read site must
    /// remember to check.
    pub channel: &'a dyn crate::gateway::input_bridge::ClientChannel,
}

impl<'a> MetaMcpCallerContext<'a> {
    /// The fields the chokepoint reads, as the view discovery is judged by.
    #[must_use]
    pub fn scope(&self) -> InvokeScope<'_> {
        InvokeScope {
            authorizer: self.authorizer,
            is_admin: self.is_admin,
            api_key_name: self.api_key_name,
            agent_id: self.agent_id,
            grant_subject: self.grant_subject.as_ref(),
        }
    }

    /// The same caller, presenting different multi-round-trip fields.
    ///
    /// A chain runs its steps as one caller, and only the step that was
    /// stopped may redeem the answers. Rebuilding the context per step is what
    /// keeps that structural: `task` is not carried, because a chain step
    /// never begins a background task of its own — the intent was already
    /// taken at the dispatch gate above.
    pub(crate) fn with_retry<'b>(
        &self,
        retry: &'b crate::protocol::mrtr::RetryFields,
    ) -> MetaMcpCallerContext<'b>
    where
        'a: 'b,
    {
        MetaMcpCallerContext {
            is_modern: self.is_modern,
            protocol_revision: self.protocol_revision,
            credential_principal: self.credential_principal,
            authentication: self.authentication,
            execution: self.execution,
            signing: self.signing,
            authorizer: self.authorizer,
            api_key_name: self.api_key_name,
            agent_id: self.agent_id,
            agent_declared: None,
            grant_subject: self.grant_subject.clone(),
            verified_identity: self.verified_identity,
            is_admin: self.is_admin,
            input_capabilities: self.input_capabilities,
            confirmation: self.confirmation.clone(),
            retry,
            task: None,
            era: self.era,
            channel: self.channel,
        }
    }
}

/// Turn a dispatch error into a JSON-RPC error response, keeping the HTTP
/// status when the error is an authorization refusal.
///
/// The refusal already knows its status; every other error does not carry one
/// and gets the caller's default. The status rides in the error's optional
/// `data` because that is the only channel that survives this conversion —
/// `JsonRpcResponse` has no status of its own, and re-deriving one at the HTTP
/// boundary from the JSON-RPC code cannot work: eight of the nine refusal
/// branches emit the generic `-32600`, and `-32003` already means something
/// else elsewhere.
fn error_response_preserving_status(id: RequestId, error: &crate::Error) -> JsonRpcResponse {
    let mut response = match error {
        crate::Error::ResponseFirewallRefused => JsonRpcResponse::delivery_refusal_error(
            Some(id),
            error.to_rpc_code(),
            &error.to_string(),
        ),
        _ => JsonRpcResponse::error(Some(id), error.to_rpc_code(), error.to_string()),
    };
    if let Some(ref mut rpc_error) = response.error {
        // Written unconditionally, so this function is the sole authority on
        // the field. `JsonRpcResponse::error` starts it at `None` and nothing
        // else in the gateway writes it today, but a future path that forwarded
        // a backend's error data could otherwise hand a backend the power to
        // choose the gateway's HTTP status. Assigning both arms closes that
        // without depending on the audit staying true.
        rpc_error.data = match error {
            crate::Error::Forbidden { status, .. } => Some(serde_json::json!({
                crate::gateway::authz::HTTP_STATUS_DATA_KEY: status,
            })),
            // A gateway-authored refusal may carry a recovery payload the
            // client needs: MRTR.9 names the capability an input request would
            // have required and MRTR.9a the mode, which is the difference
            // between a client that can fix its declaration and retry and one
            // that only sees prose. Named keys only, never the whole object:
            // `invoke_tool` puts a *backend's* error data into this variant, and
            // forwarding it wholesale would hand a backend the status field.
            crate::Error::JsonRpc {
                data: Some(data), ..
            } => {
                let forwarded: serde_json::Map<String, serde_json::Value> = [
                    invoke::REQUIRED_CAPABILITIES_DATA_KEY,
                    invoke::UNSUPPORTED_ELICITATION_MODE_DATA_KEY,
                ]
                .into_iter()
                .filter_map(|key| Some((key.to_string(), data.get(key)?.clone())))
                .collect();
                // `None` rather than `{}`: a backend error carrying none of these
                // keys leaves `data` absent exactly as when one key was forwarded.
                (!forwarded.is_empty()).then_some(serde_json::Value::Object(forwarded))
            }
            _ => None,
        };
        // A connect offer only under the gateway's own seal (MIK-6745, ADR-008).
        rpc_error.data =
            crate::personal_accounts::refusal::offer_data(error).or(rpc_error.data.take());
    }
    response
}

/// Meta-MCP handler — the central dispatcher for all gateway meta-tools.
// Independent, unrelated switches on a long-lived handler. A state machine
// over their product would have more states than the struct has fields.
#[allow(clippy::struct_excessive_bools)]
pub struct MetaMcp {
    pub(super) backends: Arc<BackendRegistry>,
    pub(super) capabilities: RwLock<Option<Arc<CapabilityBackend>>>,
    pub(super) cache: Option<Arc<ResponseCache>>,
    pub(super) default_cache_ttl: Duration,
    pub(super) idempotency_cache: Option<Arc<IdempotencyCache>>,
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

    /// Runtime provenance receipt signer (MIK-6905).
    ///
    /// `Some` when `security.provenance_stamping = true`; `None` otherwise.
    /// When `None` the stamping block is skipped entirely, so result payloads
    /// are byte-identical to the un-stamped path (rung 1.2 guarantee).
    pub(super) provenance_signer: Option<Arc<BnautAttestationSigner>>,

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
    #[cfg(feature = "firewall")]
    pub(super) firewall: Option<Arc<crate::security::firewall::Firewall>>,
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
            capabilities: RwLock::new(None),
            cache,
            default_cache_ttl,
            idempotency_cache: None,
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
            expose_stats_tool: false,
            prompts_resources_fetch_timeout: std::time::Duration::from_secs(10),
            #[cfg(feature = "spec-preview")]
            session_promoted: Arc::new(DashMap::new()),
            session_state: SessionStateStore::new(),
            message_signer: None,
            nonce_store: None,
            provenance_signer: None,
            claim_capture: None,
            require_nonce: false,
            transparency_logger: None,
            response_inspection_action_mode: false,
            response_contract: None,
            attestation_validator: None,
            attestation_mode: crate::attestation::AttestationMode::Observe,
            identity_grants: Arc::new(RwLock::new(LocalIdentityGrantStore::new())),
            policy_epoch: Arc::new(AtomicU64::new(0)),
            caller_identity: crate::security::caller_identity::CallerIdentityConfig::default(),
            access_verifier: None,
            context_integrity_kernel: RwLock::new(ContextIntegrityKernel::default()),
            #[cfg(feature = "firewall")]
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

    /// Restrict which meta-tools this gateway exposes (consuming builder).
    ///
    /// An empty list exposes every meta-tool. A non-empty list is an allow-list:
    /// a meta-tool that is not named is neither listed nor callable. Unrecognised
    /// names are logged and dropped rather than aborting startup, matching
    /// `with_surfaced_tools`.
    #[must_use]
    pub fn with_exposed_meta_tools(mut self, names: &[String]) -> Self {
        self.meta_tool_exposure = MetaToolExposure::from_names(names);
        self
    }

    /// List `gateway_get_stats` in `tools/list` (consuming builder).
    ///
    /// Off by default. The tool stays callable by name regardless; this
    /// governs enumeration only.
    #[must_use]
    pub fn with_expose_stats_tool(mut self, enabled: bool) -> Self {
        self.expose_stats_tool = enabled;
        self
    }

    /// Whether the name is one of this gateway's own meta-tools *and* this
    /// gateway will confirm it exists.
    ///
    /// The router asks before its own admin pre-check, so an unexposed admin
    /// tool is answered by the dispatcher's unrecognised-tool refusal rather
    /// than by an admin refusal that confirms the tool is real. The roster
    /// half is what keeps a surfaced backend tool out: `is_exposed` answers
    /// `true` for every ungoverned name by design, so on its own it cannot
    /// tell a caller whether the name is *ours*.
    pub(crate) fn exposes_meta_tool(&self, name: &str) -> bool {
        super::meta_mcp_tool_defs::is_governed_meta_tool(name)
            && self.meta_tool_exposure.is_exposed(name)
    }

    /// Override the per-backend `prompts/list` and `resources/list` fetch
    /// timeout. The default comes from
    /// `meta_mcp.prompts_resources_fetch_timeout` (10s); this lets tests run
    /// with a shorter bound.
    #[must_use]
    pub fn with_prompts_resources_fetch_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.prompts_resources_fetch_timeout = timeout;
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
        self.identity_grants = Arc::new(RwLock::new(grants));
        self
    }

    /// Set which caller identity headers are honoured (`security.caller_identity`).
    #[must_use]
    pub fn with_caller_identity(
        mut self,
        config: crate::security::caller_identity::CallerIdentityConfig,
    ) -> Self {
        self.access_verifier = (config.mode
            == crate::security::caller_identity::CallerIdentityMode::CloudflareAccess)
            .then(|| {
                Arc::new(crate::key_server::OidcVerifier::cloudflare_access(
                    &config.cloudflare_access,
                ))
            });
        if config.mode == crate::security::caller_identity::CallerIdentityMode::TrustedProxy {
            // The allowlist proves the request came through a proxy, not that
            // the proxy wrote the header; that half is the proxy's job.
            tracing::warn!(
                authority = %config.authority,
                proxies = config.trusted_proxies.len(),
                "caller_identity trusted_proxy: each proxy MUST strip or overwrite \
                 client-supplied X-Gateway-Identity-* headers"
            );
        }
        self.caller_identity = config;
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
    ///
    /// Called unconditionally from the boot path; while the cache is `None`
    /// every client-supplied idempotency key is inert.
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

    /// Enable signed runtime provenance stamping (MIK-6905, rung 1.2).
    ///
    /// When set, every aggregated tool result is stamped with a signed
    /// `_meta.provenance` receipt. Off by default; the field is `None` unless
    /// this is called, so the stamping branch never runs on the hot path
    /// otherwise.
    pub fn enable_provenance_stamping(&mut self, signer: BnautAttestationSigner) {
        self.provenance_signer = Some(Arc::new(signer));
    }

    /// Enable shadow claim capture (MIK-6908, rung 3.1).
    ///
    /// Only has an observable effect once `provenance_signer` is also
    /// `Some` — capture runs alongside stamping at the same chokepoint, not
    /// independently of it.
    pub fn enable_claim_capture(&mut self, sink: Arc<crate::trust::ClaimCaptureSink>) {
        self.claim_capture = Some(sink);
    }

    /// Attach a transparency logger (issue #133, D3).
    ///
    /// When set, every completed tool invocation is committed to the
    /// hash-chain log.  Failures are non-fatal — a `warn!` is emitted but
    /// the invocation result is not affected.
    ///
    /// Takes an `Arc` (rather than an owned logger) so the caller can retain
    /// a second handle — e.g. `AppState.transparency_log` (MIK-6740) — that
    /// writes into the same tamper-evident chain from the direct backend
    /// route, which does not go through `MetaMcp`.
    pub fn enable_transparency_log(&mut self, logger: Arc<crate::security::TransparencyLogger>) {
        // The account registry mints credentials for REST capabilities under
        // the same "no mint without a durable audit record" rule as the
        // Meta-MCP route, and it is reached through the capability executor
        // rather than through `self`, so it needs its own handle on the sink.
        self.account_strategies
            .set_audit_logger(Arc::clone(&logger));
        self.transparency_logger = Some(logger);
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

    /// Attach the security firewall used to scan aggregated tool-list / search
    /// responses (OWASP ASI01 tool-poisoning defense).
    ///
    /// Wired at startup from the same `Arc<Firewall>` held by `AppState`, so
    /// the discovery surface and the direct `tools/call` path share one config.
    #[cfg(feature = "firewall")]
    pub fn set_firewall(&mut self, firewall: Option<Arc<crate::security::firewall::Firewall>>) {
        self.firewall = firewall;
    }

    /// Firewall-scan an aggregated tool-list / search response value in place
    /// (OWASP ASI01 tool-poisoning). Backend-supplied `description` strings are
    /// scanned for prompt injection and have embedded credentials redacted
    /// before the discovery response reaches the client.
    ///
    /// No-op when the firewall is absent or response scanning is disabled — the
    /// same gate the `tools/call` path uses ([`Firewall::check_response`]
    /// short-circuits), so behavior is unchanged when the feature/config is off.
    #[cfg(feature = "firewall")]
    pub(super) fn scan_tool_list_value(&self, value: &mut serde_json::Value) {
        let Some(ref fw) = self.firewall else {
            return;
        };
        let verdict = fw.check_response(
            "meta:tools/list",
            "meta-mcp",
            "tools/list",
            value,
            "meta-mcp",
        );
        if verdict.action == crate::security::firewall::FirewallAction::Warn {
            tracing::warn!(
                findings = verdict.findings.len(),
                "Firewall: meta tools/list response warning"
            );
        }
    }

    /// No-op tool-list scan when the `firewall` feature is disabled.
    #[cfg(not(feature = "firewall"))]
    #[allow(clippy::unused_self)]
    pub(super) fn scan_tool_list_value(&self, _value: &mut serde_json::Value) {}

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

    /// Install the strategy for ONE backend (account-descriptor binding).
    ///
    /// Called at startup, before serving, once per backend whose `account`
    /// reference resolved. The resolver prefers this over the process-wide
    /// strategy, which is what lets an external minting descriptor and a
    /// managed vault descriptor coexist in one configuration.
    pub fn set_backend_identity_propagation(
        &self,
        backend: &str,
        strategy: Arc<dyn crate::identity_propagation::IdentityPropagation>,
    ) {
        self.backend_identity_propagation
            .write()
            .insert(backend.to_string(), strategy);
    }

    /// The strategy installed for `backend`, if it has its own.
    pub(super) fn backend_identity_strategy(
        &self,
        backend: &str,
    ) -> Option<Arc<dyn crate::identity_propagation::IdentityPropagation>> {
        self.backend_identity_propagation
            .read()
            .get(backend)
            .map(Arc::clone)
    }

    /// The per-descriptor account strategies.
    ///
    /// Handed out rather than consulted here: the REST consumer reaches it
    /// through `CapabilityExecutor`, which has no view of `MetaMcp`. The same
    /// `Arc` on both sides is what makes it ONE registry rather than two.
    pub(crate) fn account_strategies(
        &self,
    ) -> Arc<crate::identity_propagation::AccountStrategyRegistry> {
        Arc::clone(&self.account_strategies)
    }

    /// Declare whether this gateway serves more than one principal (ADR-008
    /// INV-2). Set once at startup from the resolved auth config. When `true`,
    /// dispatch fails closed for a backend whose gateway-held OAuth token is
    /// neither per-user isolated nor blessed `shared_account`.
    pub fn set_multi_user(&self, multi_user: bool) {
        self.multi_user
            .store(multi_user, std::sync::atomic::Ordering::Relaxed);
        // Propagate to the capability backend too (MIK-6751, ADR-008 parity):
        // it enforces its own OAuth-isolation guard and cannot see this field
        // directly. `set_capabilities` re-syncs the reverse case (capabilities
        // attached after this call).
        if let Some(cap) = self.capabilities.read().as_ref() {
            cap.set_multi_user(multi_user);
        }
    }

    /// ADR-008 INV-2 fail-closed guard, shared by the meta-MCP dispatch
    /// (`invoke_tool_traced`) and the direct backend route (`POST /mcp/{name}`,
    /// `backend_handlers`). On a multi-user gateway a backend whose OAuth token
    /// is held once by the gateway (keyed by backend, not by user —
    /// `src/oauth/storage.rs`) must NOT have that token attached for an
    /// arbitrary caller: doing so serves user A's login to user B. Refuse UNLESS
    /// a per-user credential was resolved (`has_per_user_credential`) or the
    /// operator blessed the account as shared (`oauth.shared_account = true`). A
    /// single-user gateway never enters this branch, and this never falls back
    /// to the shared token (INV-1): it refuses.
    pub(crate) fn enforce_oauth_isolation(
        &self,
        server: &str,
        has_per_user_credential: bool,
    ) -> Result<()> {
        match self.backends.get(server) {
            Some(backend) => {
                self.enforce_oauth_isolation_for(&backend, server, has_per_user_credential)
            }
            None => Ok(()),
        }
    }

    /// INV-2 check against a captured `Backend` instance rather than a name.
    /// Callers holding the `Arc<Backend>` they will forward to MUST use this so
    /// the check and the later `backend.request` bind to the SAME instance —
    /// eliminating the hot-reload TOCTOU where a name re-lookup could evaluate a
    /// different backend than the one used (ADR-008 INV-2, MIK-6742 R2-1).
    ///
    /// Despite the name this covers every personal binding a backend can carry,
    /// not only `oauth`: see the enumeration in the body. The name is kept
    /// because twenty call sites and the public `enforce_oauth_isolation`
    /// wrapper spell it.
    pub(crate) fn enforce_oauth_isolation_for(
        &self,
        backend: &crate::backend::Backend,
        server: &str,
        has_per_user_credential: bool,
    ) -> Result<()> {
        if !self.multi_user.load(std::sync::atomic::Ordering::Relaxed) || has_per_user_credential {
            return Ok(());
        }

        // THREE independent ways a backend is bound to one person, enumerated
        // from `BackendConfig` (`config::BackendConfig::oauth`, `::account`,
        // `::identity_propagation`) rather than discovered one leak at a time.
        // Any of them means the gateway-held static credential is somebody's
        // personal login, and every caller of this function resolves no per-user
        // credential of its own (MIK-6745.JOURNEY.3).
        // Each arm carries its OWN remediation: a single generic fix line sent
        // the propagation arm to "enable identity propagation", which is already
        // enabled and required there.
        let (reason, fix) = if backend.oauth_requires_per_user_isolation() {
            (
                "uses a gateway-held OAuth login that is not isolated per user",
                "supply a per-user credential by enabling identity propagation for \
                 this backend, or set `oauth.shared_account = true` if this is a \
                 genuinely shared service account",
            )
        } else if backend.account_descriptor_id().is_some() {
            // A surviving `account` reference is `personal_managed`:
            // `config::account_bindings::Bound::effective` erases it for both
            // `shared` (the operator's escape hatch) and `external` (which
            // compiles to the `identity_propagation` arm below). It also
            // survives a registration rebuilt from raw config that lost its
            // compiled strategy -- the state `refuse_unbound_account_backend`
            // refuses on the call path, refused here for the same reason.
            (
                "is bound to a personal account descriptor",
                "give the descriptor a per-user binding, or use an \
                 `accounts.descriptors` entry with `mode: shared` if this is a \
                 genuinely shared service account",
            )
        } else if backend
            .identity_propagation_config()
            .is_some_and(|cfg| cfg.required)
        {
            // `required` means there is no best-effort downgrade that would
            // still be that person (ADR-007 IDP.2/IDP.3).
            (
                "requires an end-user identity credential that this route cannot resolve",
                "this route carries no end-user identity, so a required propagation \
                 can never be satisfied on it: keep the backend off the meta routes, \
                 or set `identity_propagation.required = false` and give it a \
                 genuinely shared service account",
            )
        } else {
            return Ok(());
        };

        // `fix` rides the log too, not only the JSON-RPC error below
        // (MIK-7334.CATALOGUE.1 §11.8). The omission route -- every
        // `meta_route_isolation_refused` call site -- evaluates this as
        // `.is_err()` and DISCARDS the error, so the remedy would otherwise
        // travel only in the channel that is thrown away on the one path where
        // a caller is told nothing. Fail closed to the caller, and give whoever
        // configured the backend a line they can act on without reading source.
        warn!(
            server = %server,
            reason,
            fix,
            "refused: multi-user gateway would serve one user's personal backend \
             credential to another (ADR-008 INV-2)"
        );
        Err(Error::json_rpc(
            -32001,
            format!(
                "Backend '{server}' {reason}. On a multi-user gateway this call is \
                 refused so one user's credential is never served to another. \
                 Fix: {fix}."
            ),
        ))
    }

    /// True when a meta-route aggregation / ownership scan must SKIP `backend`
    /// on a multi-user gateway because forwarding the gateway-held OAuth token
    /// would leak one user's backend view to another. List/find paths call this
    /// to omit the backend (fail closed) BEFORE any cold-cache metadata fetch,
    /// not after — closing the metadata-leak + guard-ordering gap (MIK-6742 R2-1).
    pub(crate) fn meta_route_isolation_refused(&self, backend: &crate::backend::Backend) -> bool {
        self.enforce_oauth_isolation_for(backend, &backend.name, false)
            .is_err()
    }

    /// The caller's per-user credential for `server`: headers and cache binding.
    ///
    /// ONE resolution per request per backend, returning BOTH halves, because
    /// the isolation verdict and the slot selection must not disagree about who
    /// the caller is (design §4.3's residual) — and because resolving twice
    /// would mint twice.
    ///
    /// Context-taking convenience over
    /// [`Self::caller_credential_for_identity`], which holds the contract and
    /// serves the routes that are dispatched without a caller context.
    pub(crate) async fn caller_credential_for(
        &self,
        server: &str,
        caller: &MetaMcpCallerContext<'_>,
    ) -> (Vec<(String, String)>, Option<String>) {
        self.caller_credential_for_identity(server, caller.verified_identity)
            .await
    }

    /// The credential-aware sibling of [`Self::meta_route_isolation_refused`],
    /// for the catalogue paths that fetch over the CALLER'S OWN pool slot.
    ///
    /// SEPARATE FUNCTION ON PURPOSE (MIK-7334.CATALOGUE.1 R2). A third `bool`
    /// parameter on the identity-free helper would make all fourteen call sites
    /// editable and one wrong edit invisible in the diff. A site opts in by NAME
    /// here, so the seven that must keep failing closed are untouched.
    ///
    /// ONLY admissible where the operation AFTER the check runs on the same slot
    /// the credential selected. `has_per_user_credential = true` does not narrow
    /// [`Self::enforce_oauth_isolation_for`] — it returns `Ok(())` before any
    /// isolation arm is evaluated — so calling this at a site that then fetches
    /// over `shared_transport()` would hand an arbitrary caller the gateway's own
    /// backend login. `handle_logging_set_level` keeps the identity-free
    /// helper; the list handlers, the resource-owner lookup and `prompts/get`
    /// qualified once they fetched and forwarded on the caller's own slot.
    ///
    /// THE VERDICT IS DERIVED FROM THE SLOT, NOT FROM CREDENTIAL POSSESSION
    /// (MIK-7544). An earlier revision read `!propagated_headers.is_empty()`,
    /// copied from the direct route. The direct route forwards the headers it
    /// tested; this one does not. `Backend::get_cached_list_for` drops them on
    /// every slot but `PerUser`, so an isolated-OAuth backend configured
    /// `stateless` was admitted as "credentialed caller" and then fetched under
    /// the GATEWAY-HELD account, whose catalogue landed in the one entry every
    /// caller reads. Asking `fetch_carries_caller_identity` — the same
    /// `pool_key_for` derivation the fill uses for `identity_key` — makes guard
    /// and fetch one decision that cannot disagree.
    ///
    /// The two routes therefore mean the same thing by the parameter and differ
    /// only in how they earn it: a per-user credential that THIS fetch will
    /// actually carry for THIS backend and THIS caller, never "the caller
    /// authenticated".
    pub(crate) fn meta_route_isolation_refused_for_caller(
        &self,
        backend: &crate::backend::Backend,
        binding: Option<&str>,
    ) -> bool {
        self.enforce_oauth_isolation_for(
            backend,
            &backend.name,
            backend.fetch_carries_caller_identity(binding),
        )
        .is_err()
    }

    /// Attach a `TransitionTracker` for predictive tool prefetch.
    pub fn set_transition_tracker(&self, tracker: Arc<TransitionTracker>) {
        *self.transition_tracker.write() = Some(tracker);
    }

    /// Set the capability backend.
    pub fn set_capabilities(&self, capabilities: Arc<CapabilityBackend>) {
        // Sync current multi-user state onto the newly attached backend
        // (MIK-6751): this may run before or after `set_multi_user` at
        // startup / hot-reload, so both setters push their own state.
        capabilities.set_multi_user(self.multi_user.load(std::sync::atomic::Ordering::Relaxed));
        *self.capabilities.write() = Some(capabilities);
    }

    /// Replace the local identity grant store.
    ///
    /// The store is published first, under the write lock; the epoch then
    /// advances with `Release` while that lock is still held, so a reader that
    /// observes the new epoch cannot still see the old grants. Bump-then-write
    /// is the 4.g race on the writer side.
    ///
    /// UNCONDITIONAL by contract. Whether a publish is worth making at all is
    /// the CALLER's question, and the reload path answers it by comparing
    /// normalised store contents before it gets here (T8/T8b). Moving that
    /// comparison into this function would red
    /// `policy_epoch_tests`, whose cells publish an empty store into an empty
    /// one and require the epoch to move: to them the publish IS the event.
    pub fn set_identity_grants(&self, grants: LocalIdentityGrantStore) {
        publish_identity_grants(&self.identity_grants, &self.policy_epoch, grants);
    }

    /// The shared grant sink and its epoch, for a publisher outside `MetaMcp`.
    ///
    /// Handed out as `Arc`s rather than reached through a `Weak<MetaMcp>`
    /// because an upgrade that fails is a revocation silently lost — the defect
    /// class this whole conjunct exists to remove, reintroduced at the sink.
    /// A publisher holding these two cannot fail to find its target.
    #[must_use]
    pub(crate) fn identity_grant_sink(
        &self,
    ) -> (Arc<RwLock<LocalIdentityGrantStore>>, Arc<AtomicU64>) {
        (
            Arc::clone(&self.identity_grants),
            Arc::clone(&self.policy_epoch),
        )
    }

    /// Snapshot all identity-grant rows for read-only projection (e.g. the
    /// control-plane inventory). Returns owned clones so the lock is not held.
    #[must_use]
    pub fn identity_grant_rows(&self) -> Vec<crate::identity_grants::IdentityGrant> {
        self.identity_grants.read().values().cloned().collect()
    }

    /// The caller identity header configuration.
    pub(crate) const fn caller_identity(
        &self,
    ) -> &crate::security::caller_identity::CallerIdentityConfig {
        &self.caller_identity
    }

    /// The Access assertion verifier, present iff the mode is `cloudflare_access`.
    pub(crate) fn access_verifier(&self) -> Option<&crate::key_server::OidcVerifier> {
        self.access_verifier.as_deref()
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

    /// Snapshot both running budget configurations.
    ///
    /// Test-only: the budgets are read inside dispatch, so a caller outside
    /// this module has no other way to observe what startup applied.
    #[cfg(test)]
    pub(crate) fn budget_configs(&self) -> (ErrorBudgetConfig, CapabilityErrorBudgetConfig) {
        (
            self.error_budget_config.read().clone(),
            self.capability_budget_config.read().clone(),
        )
    }

    /// Override the error-budget configuration.
    pub fn set_error_budget_config(&self, config: ErrorBudgetConfig) {
        *self.error_budget_config.write() = config;
    }

    /// Override the per-capability error-budget configuration.
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
    /// Returns an empty `Vec` when the caller has no session — no id, or the
    /// empty id a modern sessionless connection presents (`session_key`) — and
    /// when the session has no promoted tools.
    ///
    /// The `session_key` filter lives here rather than at the three call sites
    /// (`mod.rs:1266`, `mod.rs:1330`, `spec_preview.rs:112`) so that a future
    /// list-shaping caller inherits it: promotions written under the shared
    /// empty key would otherwise be read back by every other modern connection
    /// (`MIK-7272.ORDER.2`).
    #[cfg(feature = "spec-preview")]
    pub(super) fn promoted_tools_for_session(
        &self,
        session_id: Option<&str>,
    ) -> Vec<(String, crate::protocol::Tool)> {
        let Some(sid) = session_key(session_id) else {
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
                // INV-2 (MIK-6742): never surface an OAuth-isolated backend's cached
                // tool to another user on a multi-user gateway. Omit (fail closed).
                if self.meta_route_isolation_refused(&backend) {
                    return None;
                }
                Some((server.to_string(), backend.get_cached_tool(tool)?))
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
    ///
    /// A caller with no session gets the default and cannot be given anything
    /// else: see [`session_key`] for why an empty id is no session at all.
    /// This is the one site `surfaced`, `invoke` and `spec_preview` read the
    /// profile through, so closing it closes the read for all three.
    pub(super) fn active_profile(
        &self,
        session_id: Option<&str>,
    ) -> crate::routing_profile::RoutingProfile {
        let default_name = self.profile_registry.default_name();
        let name = session_key(session_id).map_or_else(
            || default_name.to_string(),
            |sid| self.session_profiles.get_profile_name(sid, default_name),
        );
        self.profile_registry.get(&name)
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

// ============================================================================
// MCP protocol handlers — initialize + tools
// ============================================================================

impl MetaMcp {
    /// Build the `server/discover` document (MCP 2026-07-28).
    ///
    /// The revision removes the `initialize` handshake, so this RPC is how a
    /// peer learns what the gateway speaks. Servers **MUST** implement it, and
    /// a client **MAY** call it before anything else — on stdio it is also the
    /// backward-compatibility probe, since a legacy server answers it with an
    /// error rather than a document.
    ///
    /// The version list and identity come from the same source as the
    /// `initialize` result (`build_initialize_result`). Assembling them
    /// separately would let the two answers drift, and a peer would get one
    /// story from the handshake and another from discovery.
    #[must_use]
    pub fn discover_document(&self, modern_enabled: bool) -> serde_json::Value {
        // Modern, because this document IS the 2026 surface. Only identity and
        // the version list are taken from it -- capabilities are rebuilt below
        // -- so the era passed here is a statement of what surface this is,
        // not a second source for the extension list.
        let handshake = crate::gateway::meta_mcp_helpers::build_initialize_result(
            crate::protocol::PROTOCOL_VERSION,
            "",
            crate::protocol::meta::Era::Modern,
        );

        // Field names and placement are the specification's, transcribed from
        // the `DiscoverResult` example rather than invented: `supportedVersions`
        // (not `protocolVersions`), and `serverInfo` inside `_meta` under its
        // reverse-DNS key rather than at the top level. A first cut used the
        // obvious names, and every test passed — because the tests asserted the
        // same invented names. A wire format that agrees with itself is not a
        // wire format anyone else can read.
        // Discovery advertises what this gateway can actually serve, which is
        // the legacy negotiation list plus the modern revisions when the switch
        // that serves them is on. Leaving the modern revision out made enabling
        // it unreachable: a conforming peer asks discovery which revisions
        // exist, and the one the switch had just turned on was not among them.
        //
        // Added HERE and not to `SUPPORTED_VERSIONS`, which is what a legacy
        // `initialize` negotiates over. A stateless revision cannot be reached
        // through a handshake it deleted, so advertising it there would offer a
        // 2025 client a version the handshake can never settle on.
        let mut versions: Vec<&str> = crate::protocol::SUPPORTED_VERSIONS.to_vec();
        if modern_enabled {
            for version in crate::protocol::meta::MODERN_VERSIONS {
                if !versions.contains(version) {
                    versions.push(version);
                }
            }
        }

        // Capabilities are rebuilt here rather than taken from `handshake`,
        // and that is the one thing discovery does NOT share with the
        // handshake. The extension set is era-specific: `initialize` answers
        // 2025 clients, which cannot use a 2026 extension and whose result is
        // pinned byte-for-byte by an existing criterion, while this document is
        // the 2026 surface and is where a peer looks for what the gateway
        // speaks. Identity and the version list still come from one source, so
        // the drift this guards against stays guarded.
        let capabilities = crate::gateway::meta_mcp_helpers::build_server_capabilities(
            crate::gateway::meta_mcp_helpers::discovery_extensions(),
        );

        serde_json::json!({
            "resultType": "complete",
            "supportedVersions": versions,
            "capabilities": capabilities,
            "_meta": {
                "io.modelcontextprotocol/serverInfo": handshake.server_info,
            },
        })
    }

    /// Handle `initialize` with version negotiation and optional profile binding.
    pub fn handle_initialize(
        &self,
        id: RequestId,
        params: Option<&Value>,
        session_id: Option<&str>,
        header_profile: Option<&str>,
        era: crate::protocol::meta::Era,
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        let client_version = extract_client_version(params);
        let negotiated_version = negotiate_version(client_version);
        // NFR.OBS.1. The session is served under this value from here on, and
        // the observation record has to report it rather than the client's ask
        // -- the two differ whenever the ask is unsupported. Bound at the one
        // site that negotiates, so no second derivation can drift from it.
        crate::protocol_revision_telemetry::bind_session_revision(session_id, negotiated_version);
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

        if let (Some(sid), Some(name)) = (session_key(session_id), profile_hint) {
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

        let instructions = self.build_instructions(scope, session_id);
        // `era` is threaded from the dispatcher rather than re-derived from
        // `params` here: the dispatcher reads the mirrored header as well as
        // `_meta`, and a second derivation is the two-predicate defect
        // `protocol::meta::classify_request` records.
        let result = build_initialize_result(negotiated_version, &instructions, era);
        JsonRpcResponse::success_serialized(id, result)
    }

    /// The initialize instructions as this caller may read them: counts over
    /// what it could invoke, and a guide naming only those capabilities (A3).
    fn build_instructions(&self, scope: InvokeScope<'_>, session_id: Option<&str>) -> String {
        let (tool_total, server_count) = self.admitted_counts(scope, session_id);
        let mut instructions =
            build_discovery_preamble(tool_total, server_count, &self.meta_tool_exposure);

        if let Some(cap) = self.get_capabilities()
            && self.admits_backend(&cap.name, scope, session_id)
        {
            let mut caps = cap.list_capabilities();
            caps.retain(|c| {
                self.may_invoke(&cap.name, &c.name, scope, session_id)
                    .is_ok()
            });
            for c in &mut caps {
                c.metadata
                    .chains_with
                    .retain(|t| self.may_invoke(&cap.name, t, scope, session_id).is_ok());
            }
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
    fn backend_counts(&self) -> (ToolTotal, usize) {
        let backends = self.backends.all();
        let server_count = backends.len();
        (tool_total(&backends), server_count)
    }

    /// Handle `tools/list` — Code Mode returns 2 tools; Traditional returns full set.
    ///
    /// When surfaced tools are configured, their schemas are appended after the
    /// meta-tools (subject to routing profile filtering).  Tools whose backend
    /// cache is empty are silently omitted rather than blocking the response.
    pub fn handle_tools_list(&self, id: RequestId) -> JsonRpcResponse {
        // Admin standing: this wrapper has no caller to read and no production
        // call site — every live path (`..._with_url_override` for HTTP,
        // `..._with_params` for stdio) supplies real standing. It answers the
        // "what is the whole meta surface" question the surface-count gates
        // ask, so lowering it here would shrink a documented count without any
        // caller's disclosure actually changing.
        self.handle_tools_list_for_session(id, None, InvokeScope::unscoped(CallerStanding::Admin))
    }

    fn shadow_tools_list_assembly(
        &self,
        session_id: Option<&str>,
        request_variant: bool,
    ) -> crate::protocol_revision_telemetry::ToolsListShadow {
        // Static Code Mode returns the same two meta-tools only on the standard
        // path. A spec-preview query returns filtered backend tools instead.
        if self.code_mode_enabled && !request_variant {
            return crate::protocol_revision_telemetry::observe_tools_list(
                crate::protocol_revision_telemetry::ListFilters::default(),
            );
        }
        let profile = self.active_profile(session_id).is_restrictive()
            && (request_variant || !self.surfaced_tools.is_empty());
        #[cfg(feature = "spec-preview")]
        let session = !self.promoted_tools_for_session(session_id).is_empty();
        #[cfg(not(feature = "spec-preview"))]
        let session = false;
        crate::protocol_revision_telemetry::observe_tools_list(
            crate::protocol_revision_telemetry::ListFilters {
                // The caller's invoke predicate shapes the surfaced tools (A3),
                // so it shapes this list exactly when there are any to shape.
                principal: !self.surfaced_tools.is_empty(),
                profile,
                session,
                request: request_variant,
            },
        )
    }

    /// The meta-tools this caller is served, after the operator allow-list and
    /// the caller's standing have both had their say.
    ///
    /// The single authority for "what does this caller get to see": `tools/list`
    /// builds its answer here, and the gateway-owned guides are projected
    /// through the same set (`resources::try_serve_guide`) so no served text
    /// can name a tool the same caller's catalogue withholds.
    ///
    /// `counts` feed the descriptions: `tools/list` passes the caller's
    /// admitted counts; the guide projection reads names only.
    pub(super) fn meta_tools_for(
        &self,
        standing: CallerStanding,
        counts: (ToolTotal, usize),
    ) -> Vec<crate::protocol::Tool> {
        let mut tools = if self.code_mode_enabled {
            self.meta_tool_exposure.filter(build_code_mode_tools())
        } else {
            let (tool_count, server_count) = counts;
            build_meta_tools_filtered(
                MetaToolGates {
                    // The collector is always attached, so its presence was
                    // never a gate. The operator opt-in is.
                    stats: self.expose_stats_tool,
                    reload: self.get_reload_context().is_some(),
                    // Follows `cost_governance.enabled`, which is what decides
                    // whether a registry is attached at all. Without the
                    // feature there is nothing to report.
                    #[cfg(feature = "cost-governance")]
                    cost_report: self.cost_registry.is_some(),
                    #[cfg(not(feature = "cost-governance"))]
                    cost_report: false,
                    // Attachment, not configuration: the registry is set after
                    // construction and never over stdio, so this is read here
                    // rather than passed in.
                    webhook_status: self.get_webhook_registry().is_some(),
                    playbooks: !self.playbook_engine.read().is_empty(),
                    profiles: self.profile_registry.has_configured_profiles(),
                },
                tool_count,
                server_count,
                &self.meta_tool_exposure,
            )
        };
        if self.signing_enabled() && self.require_nonce {
            require_gateway_invoke_nonce(&mut tools);
        }
        // The admin axis, applied to disclosure by the same predicate that
        // gates dispatch in `handle_tools_call`. Listing a tool the caller is
        // then refused is a catalogue entry that exists only to be denied.
        tools.retain(|tool| standing.permits(&tool.name));
        tools
    }

    /// Session-aware variant of `handle_tools_list` used by the router.
    pub fn handle_tools_list_for_session(
        &self,
        id: RequestId,
        session_id: Option<&str>,
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        self.shadow_tools_list_assembly(session_id, false);
        let standing = CallerStanding::from(scope);
        let tools = self.meta_tools_for(standing, self.admitted_counts(scope, session_id));
        let mut tool_descriptors =
            project_tool_descriptors_trust_cards("gateway:meta", "mcp-gateway", &tools);

        // Append surfaced tools (skip in Code Mode — it uses a fixed 2-tool schema).
        if !self.code_mode_enabled {
            for surfaced in &self.surfaced_tools {
                if let Some(tool) = self.resolve_surfaced_tool(surfaced, session_id, scope) {
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
            for (server, tool) in promoted {
                if self
                    .may_invoke(&server, &tool.name, scope, session_id)
                    .is_err()
                {
                    continue;
                }
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
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        #[cfg(feature = "spec-preview")]
        if let Some(q) = params.and_then(|p| p.get("query")).and_then(Value::as_str) {
            return self.handle_tools_list_filtered(id, q, session_id, scope);
        }
        self.handle_tools_list_for_session(id, session_id, scope)
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
        scope: InvokeScope<'_>,
    ) -> JsonRpcResponse {
        let effective_code_mode = self.code_mode_enabled || url_override;
        if effective_code_mode && !self.code_mode_enabled {
            // URL-activated Code Mode: return the two fixed tools directly.
            crate::protocol_revision_telemetry::observe_tools_list(
                crate::protocol_revision_telemetry::ListFilters {
                    request: true,
                    ..crate::protocol_revision_telemetry::ListFilters::default()
                },
            );
            // Still filtered - a URL parameter must not widen what the
            // operator exposed.
            let mut tools = self.meta_tool_exposure.filter(build_code_mode_tools());
            tools.retain(|tool| CallerStanding::from(scope).permits(&tool.name));
            let tool_descriptors =
                project_tool_descriptors_trust_cards("gateway:meta", "mcp-gateway", &tools);
            return JsonRpcResponse::success(
                id,
                tools_list_result_with_trust_cards(tool_descriptors),
            );
        }
        // No override (or static config already handles it): follow normal path.
        self.handle_tools_list_with_params(id, params, session_id, scope)
    }

    /// Route a call that names a backend tool directly, or `None` when the
    /// name belongs to the meta-tool surface.
    ///
    /// Two ways a backend tool answers to its own name: an operator surfaced
    /// it, or the call is a retry whose origin the sealed envelope names.
    async fn route_direct_backend_call(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        if let Some(server_name) = self.surfaced_tools_map.get(tool_name) {
            let server_name = server_name.clone();
            // A tool the catalogue will not disclose must not answer to its
            // own name either: unlisted-but-invocable is the same defect as
            // listed-but-refused, read the other way round. Worded like the
            // unrecognised-tool fallback so the refusal does not confirm the
            // existence of something the gateway declined to publish.
            if self.surfaced_schema_withheld(&server_name, tool_name) {
                return Some(error_response_preserving_status(
                    id,
                    &Error::json_rpc(-32601, format!("Unknown tool: {tool_name}")),
                ));
            }
            // Nor a surfaced tool this caller could not invoke (A3).
            if let Some(absent) =
                self.withheld_surfaced(&server_name, tool_name, caller, session_id)
            {
                return Some(error_response_preserving_status(id, &absent));
            }
            return Some(
                self.invoke_named_backend_tool(
                    id,
                    &server_name,
                    tool_name,
                    arguments.clone(),
                    session_id,
                    caller,
                )
                .await,
            );
        }
        self.route_retry_to_origin_backend(id, tool_name, arguments, session_id, caller)
            .await
    }

    /// Route a retry to the backend that opened the exchange, or `None` when
    /// the call is not a retry this gateway minted a continuation for.
    ///
    /// // A retry names the backend tool it continues, not `gateway_invoke`,
    /// // and a backend tool answers to its own name only where an operator
    /// // surfaced it. Routing this by name would refuse every honest retry on
    /// // an unpinned tool with the -32601 fallback below, so the backend comes
    /// // from the envelope the gateway itself minted. The name the client
    /// // presented is not trusted by being routed: it is checked against the
    /// // digest sealed in that same envelope before anything dispatches.
    /// //
    /// // Two meta-tools are left alone, and only two. `gateway_invoke` and
    /// // `gateway_execute` carry their own server and tool and route into
    /// // `invoke_tool`, where `redeem_retry` opens the same envelope: a retry
    /// // wrapped in either reaches the guard by its ordinary path, so routing
    /// // it from here would only open it twice.
    /// //
    /// // Every other meta-tool is answered by the gateway itself and never
    /// // enters that scope. Exempting the whole `gateway_` prefix therefore
    /// // let a retry naming one — `gateway_list_servers`, say — run as a fresh
    /// // call with its continuation never examined, which is the repeat the
    /// // envelope exists to prevent (MIK-7215). Such a retry is routed like
    /// // any other: the envelope names a backend, the presented name is not
    /// // that backend's tool, and the digest check refuses it downstream.
    async fn route_retry_to_origin_backend(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: &Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> Option<JsonRpcResponse> {
        if matches!(tool_name, "gateway_invoke" | "gateway_execute") {
            return None;
        }
        let server_name = match invoke::retry_origin_backend(&self.continuation, caller.retry)? {
            Ok(server) => server,
            Err(error) => return Some(error_response_preserving_status(id, &error)),
        };
        Some(
            self.invoke_named_backend_tool(
                id,
                &server_name,
                tool_name,
                arguments.clone(),
                session_id,
                caller,
            )
            .await,
        )
    }

    /// Dispatch a backend tool the client named directly, returning the
    /// backend's own result envelope untouched.
    ///
    /// `invoke_tool` already returns a complete MCP tools/call result
    /// (`{content, structuredContent?, isError}`) with output-schema
    /// enforcement applied. A tool called by its own name is a first-class
    /// tool to the client, so that envelope is returned verbatim: re-wrapping
    /// it via `wrap_tool_success` would stringify the whole envelope into a
    /// text block and drop `structuredContent`, which spec-compliant clients
    /// such as Open `WebUI` require when a tool advertises an `outputSchema`.
    async fn invoke_named_backend_tool(
        &self,
        id: RequestId,
        server_name: &str,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        let invoke_args =
            admission::named_tool_envelope(server_name, tool_name, &arguments, caller);
        match self.invoke_tool(&invoke_args, session_id, caller).await {
            Ok(content) => JsonRpcResponse::success_serialized(id, content),
            Err(e) => error_response_preserving_status(id, &e),
        }
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
        mut caller: MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        // Operator exposure allow-list. Enforced ahead of the admin gate, not
        // beside it: a meta-tool hidden from `tools/list` but still executable is
        // security theatre, and the admin gate answering first would disclose the
        // tool's existence to the caller the allow-list is hiding it from. Reaching
        // this check before the admin gate is what makes the refusal wording below
        // load-bearing rather than decorative. `exposed_meta_tools` promises
        // that an unlisted tool "is not callable either". Names outside the
        // governed meta-tool set - surfaced and backend tools - are unaffected.
        //
        // The refusal is worded exactly like the unrecognised-tool fallback below:
        // an operator hiding a tool must not get a reply confirming it exists and
        // was deliberately withheld.
        if !self.meta_tool_exposure.is_exposed(tool_name) {
            // Built the same way the fallback below builds its no-suggestion
            // form, and returned through the same helper, so the two answers
            // are byte-identical. Constructing the response directly here
            // produced a message without the error type's
            // "JSON-RPC error -32601: " prefix, and that difference was itself
            // the disclosure. The fallback's did-you-mean hint is deliberately
            // not reached: a hidden tool name matches itself, so a suggestion
            // would name the tool the allow-list is hiding.
            return error_response_preserving_status(
                id,
                &crate::Error::json_rpc(-32601, format!("Unknown tool: {tool_name}")),
            );
        }

        // Admin gate for the meta-tools that change the gateway for every
        // session. Enforced HERE, at the dispatcher, and not only at the HTTP
        // router that also checks it.
        //
        // The router checks this too, and stdio marks its caller admin because
        // the client that spawned the process already holds whatever the
        // operator holds. Neither fact is why the check lives here: a gate at
        // one entry point is correct for every caller that exists today and
        // silently absent for the next one added, which is the shape that hid
        // the playbook defect. Placing it at the point of dispatch costs a
        // redundant comparison on the router path and removes the possibility.
        //
        // It also caught a live one immediately. Moving it here refused stdio,
        // because that path passed a default context whose `is_admin` is false
        // and nothing had ever checked it.
        // The same predicate `tools/list` filters its answer with
        // (`meta_tools_for`), so a caller is never shown a tool this gate
        // would then refuse.
        if !CallerStanding::of_admin_flag(caller.is_admin).permits(tool_name) {
            return JsonRpcResponse::error(
                Some(id),
                -32600,
                format!("Tool '{tool_name}' requires admin access"),
            );
        }

        let confirmed_in_band =
            match destructive_confirmation_gate(&id, tool_name, &arguments, session_id, &caller)
                .await
            {
                GateOutcome::Refuse(response) => return *response,
                GateOutcome::Proceed => false,
                GateOutcome::ProceedConfirmed => true,
            };

        if let Some(intent) = caller.task.take() {
            return self.begin_task(id, tool_name, arguments, intent).await;
        }

        self.dispatch_below_gate(
            id,
            tool_name,
            arguments,
            session_id,
            &caller,
            confirmed_in_band,
        )
        .await
    }

    async fn begin_task(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        intent: crate::gateway::task_service::TaskIntent,
    ) -> JsonRpcResponse {
        let task = crate::gateway::task_service::Task::create_at(
            tool_name,
            chrono::Utc::now(),
            intent.options,
        );
        let backend = task_backend_name(self, tool_name, &arguments);
        let executor = Arc::clone(&intent.executor);
        let call = crate::gateway::task_service::TaskCall {
            tool: tool_name.to_owned(),
            arguments,
        };
        match executor.begin(intent, task, backend, call).await {
            Ok(outcome) => outcome.into_response(id),
            Err(_) => JsonRpcResponse::error(Some(id), -32603, "task store unavailable"),
        }
    }

    /// The dispatch tail below the confirmation gate. The request thread and
    /// the task worker call the same function; there is no parallel handler.
    pub(crate) async fn dispatch_below_gate(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
        confirmed_in_band: bool,
    ) -> JsonRpcResponse {
        self.dispatch_below_gate_shaped(
            DispatchTarget {
                id,
                tool_name,
                arguments,
                session_id,
                caller,
            },
            ResultShape::Wrapped,
            confirmed_in_band,
        )
        .await
    }

    /// The same dispatch, answered with the tool's own result verbatim.
    ///
    /// One caller: the task worker, because a task settles on what the backend
    /// said and not on how a synchronous reply presents it (adapter design r3
    /// §4 — "result verbatim **including `isError: true`**"). The meta-tool
    /// wrapper below buries exactly that: it pretty-prints the result into a
    /// single text block, drops `structuredContent` for every tool without an
    /// output schema, and states `isError: false` over whatever the backend
    /// reported. It also hides an interim round — `resultType:
    /// "input_required"` inside a JSON string is not a claim the settlement
    /// classifier can read, so a question would be committed as an answer.
    ///
    /// Only this last step differs. The routing above is the identical call:
    /// the same direct-backend route, the same match arms, the same
    /// authorization, firewall, destructive, capability and signing contexts,
    /// and the same `error_response_preserving_status` on the error side.
    /// Settlement strips the internal HTTP-status key from that error itself.
    pub(crate) async fn dispatch_below_gate_native_result(
        &self,
        id: RequestId,
        tool_name: &str,
        arguments: Value,
        session_id: Option<&str>,
        caller: &MetaMcpCallerContext<'_>,
    ) -> JsonRpcResponse {
        self.dispatch_below_gate_shaped(
            DispatchTarget {
                id,
                tool_name,
                arguments,
                session_id,
                caller,
            },
            ResultShape::Native,
            // A task worker dispatches what was admitted on the request
            // thread; the confirmation, if there was one, was spent there and
            // this context carries no `requestState` to spend again.
            false,
        )
        .await
    }

    async fn dispatch_below_gate_shaped(
        &self,
        target: DispatchTarget<'_>,
        shape: ResultShape,
        confirmed_in_band: bool,
    ) -> JsonRpcResponse {
        let DispatchTarget {
            id,
            tool_name,
            arguments,
            session_id,
            caller,
        } = target;
        // T2.4: a call naming a backend tool directly — because an operator
        // surfaced it, or because it is a retry of an exchange this gateway
        // opened — is routed BEFORE the meta-tool match.
        //
        // Skipped for a retry the gate just redeemed: the envelope is a
        // single-use handle and the gate spent it, so routing this call by its
        // `requestState` would present an already-spent continuation to a
        // second consumer and the approved action would die as a stale retry.
        // A retry that reaches here confirmed is, by construction, ours.
        if !confirmed_in_band
            && let Some(response) = self
                .route_direct_backend_call(id.clone(), tool_name, &arguments, session_id, caller)
                .await
        {
            return response;
        }

        if let Some(execution) = caller.execution
            && let Err(error) =
                self.mark_management_dispatch(tool_name, &arguments, session_id, execution)
        {
            return error_response_preserving_status(id, &error);
        }

        let result = match tool_name {
            "gateway_search" => self.code_mode_search(&arguments, session_id, caller).await,
            "gateway_execute" => self.code_mode_execute(&arguments, session_id, caller).await,
            "gateway_list_servers" => self.list_servers(caller.scope(), session_id).await,
            "gateway_list_tools" => self.list_tools(&arguments, session_id, caller).await,
            "gateway_search_tools" => self.search_tools(&arguments, session_id, caller).await,
            "gateway_invoke" => self.invoke_tool(&arguments, session_id, caller).await,
            "gateway_get_stats" => self.get_stats(&arguments, caller.is_admin).await,
            "gateway_cost_report" => self.get_cost_report(&arguments, session_id, caller).await,
            "gateway_webhook_status" => self.webhook_status(),
            "gateway_run_playbook" => self.run_playbook(&arguments, caller).await,
            "gateway_kill_server" => self.kill_server(&arguments),
            "gateway_revive_server" => self.revive_server(&arguments),
            "gateway_list_disabled_capabilities" => {
                self.list_disabled_capabilities(caller.scope(), session_id)
            }
            "gateway_set_profile" => self.set_profile(&arguments, session_id, caller.is_admin),
            "gateway_get_profile" => self.get_profile(session_id, caller.is_admin),
            "gateway_list_profiles" => self.list_profiles(),
            "gateway_set_state" => self.set_state(&arguments, session_id, caller.scope()),
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
                // The candidate pool is the EXPOSED set, not the static list.
                // The early return above keeps a hidden tool's exact name from
                // being confirmed; a near miss of that name reached here and
                // the suggester, drawing from every meta-tool that exists,
                // would answer with the name the allow-list is hiding. Filtering
                // the pool removes the route -- there is no longer a spelling
                // that makes this branch name an unexposed tool -- rather than
                // wording the hint more carefully and leaving the route open.
                let exposed: Vec<&str> = META_TOOLS
                    .iter()
                    .copied()
                    .filter(|name| self.meta_tool_exposure.is_exposed(name))
                    // Nor a tool this caller's standing withholds (A3).
                    .filter(|name| CallerStanding::from(caller.scope()).permits(name))
                    .collect();
                let suggestion = did_you_mean(tool_name, &exposed, 3, 3);
                let msg = match suggestion {
                    Some(hint) => format!("Unknown tool: {tool_name}. {hint}"),
                    None => format!("Unknown tool: {tool_name}"),
                };
                Err(Error::json_rpc(-32601, msg))
            }
        };

        match result {
            Ok(content) => match shape {
                // MRTR.11a: an interim round must not be pretty-printed into
                // `content[0].text`. `wrap_tool_success` states `is_error:
                // false` and buries `resultType` inside a JSON string, where
                // neither a protocol client nor the firewall's
                // `PreserveInputRequired` policy can read it — a question
                // committed as an answer. The task worker already escapes via
                // `ResultShape::Native`; this is the same escape for the
                // synchronous thread, gated so a backend cannot mint one.
                ResultShape::Wrapped => {
                    match interim_promotion::promote_interim(&content, caller.input_capabilities) {
                        interim_promotion::Promotion::Native => {
                            JsonRpcResponse::success(id, content)
                        }
                        interim_promotion::Promotion::Wrap => {
                            let has_output_schema = tool_name == "gateway_search_tools";
                            wrap_tool_success(id, &content, has_output_schema)
                        }
                        interim_promotion::Promotion::UpstreamFault(message) => {
                            error_response_preserving_status(id, &Error::json_rpc(-32603, message))
                        }
                    }
                }
                ResultShape::Native => JsonRpcResponse::success(id, content),
            },
            Err(e) => error_response_preserving_status(id, &e),
        }
    }
}

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

fn task_backend_name(meta: &MetaMcp, tool_name: &str, arguments: &Value) -> String {
    if let Some(server) = meta.surfaced_tools_map.get(tool_name) {
        return server.clone();
    }
    match tool_name {
        "gateway_invoke" => arguments
            .get("server")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        "gateway_execute" => arguments
            .get("tool")
            .and_then(Value::as_str)
            .and_then(|tool_ref| tool_ref.split_once(':'))
            .map_or_else(|| "execute".to_owned(), |(server, _)| server.to_owned()),
        "gateway_run_playbook" => "playbook".to_owned(),
        other => other.to_owned(),
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
    fn set_state(
        &self,
        args: &Value,
        session_id: Option<&str>,
        scope: InvokeScope<'_>,
    ) -> Result<Value> {
        // Refused rather than filtered, and refused HERE rather than inside
        // `SessionStateStore`: the write is the whole point of this call, so a
        // store that quietly dropped it would turn a refusal the caller can see
        // into a silent no-op — a worse defect than the one being fixed. The
        // read side is guarded in the store's readers instead (`ORDER.2` Q4,
        // ratified 2026-09-06).
        let Some(sid) = session_key(session_id) else {
            return Err(Error::Protocol(NO_SESSION_FOR_STATE.to_string()));
        };

        let new_state = extract_required_str(args, "state")?;
        let previous = self.session_state.set_state(sid, new_state);

        // Count the visible capability tools this caller could invoke (A3).
        let visible_tools = self.get_capabilities().map_or(0, |cap| {
            cap.get_tools_for_state(new_state)
                .iter()
                .filter(|t| {
                    self.may_invoke(&cap.name, &t.name, scope, session_id)
                        .is_ok()
                })
                .count()
        });

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

/// A profile as a caller may see it. The allow/deny patterns name backends and
/// tools a non-admin may not reach, so only an admin is shown them (A3).
fn described(profile: &crate::routing_profile::RoutingProfile, is_admin: bool) -> Value {
    if is_admin {
        profile.describe()
    } else {
        json!({ "name": profile.name, "description": profile.description })
    }
}

impl MetaMcp {
    fn set_profile(&self, args: &Value, session_id: Option<&str>, is_admin: bool) -> Result<Value> {
        let Some(sid) = session_key(session_id) else {
            return Err(Error::Protocol(NO_SESSION_FOR_PROFILE.to_string()));
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
            "description": described(&profile, is_admin),
            "message": format!("Routing profile set to '{profile_name}'")
        }))
    }

    fn get_profile(&self, session_id: Option<&str>, is_admin: bool) -> Result<Value> {
        let Some(sid) = session_key(session_id) else {
            return Err(Error::Protocol(NO_SESSION_FOR_PROFILE.to_string()));
        };
        let profile = self.active_profile(Some(sid));
        Ok(json!({
            "profile": profile.name,
            "session_id": sid,
            "description": described(&profile, is_admin),
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
mod account_resolver_fixture;
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

/// Whether the peer behind `backend` has had `method` removed from under it
/// (MIK-7217, OUTBOUND.1).
///
/// The gateway is the only place that knows both which revision the backend
/// speaks and which methods that revision deleted, so it is the only place the
/// refusal can be made without spending a round trip to hear it. Sending one
/// anyway is not harmless: a modern peer answers `method not found`, which is
/// indistinguishable from a peer that is merely missing a feature, so the
/// gateway would be manufacturing the ambiguity it exists to resolve.
///
/// Unresolved and legacy eras both forward. Silence is not evidence of
/// modernity, and refusing on a guess would take `logging/setLevel` away from
/// every 2025 backend whose era probe has not come back yet.
///
/// `pub(in crate::gateway)`, widened from private, so the direct backend
/// route (`gateway::router::backend_handlers`) can reuse this one mechanism
/// instead of a second copy of the revision's removed-method list (MIK-7217,
/// OUTBOUND.1).
pub(in crate::gateway) async fn era_removed_method(
    backend: &crate::backend::Backend,
    method: &str,
) -> bool {
    let era = backend.cached_era().await;
    if era != Some(crate::protocol::era::Era::Modern) {
        return false;
    }
    if !crate::protocol::meta::REMOVED_IN_2026_07_28.contains(&method) {
        return false;
    }
    // `debug!`, not `warn!`: the refusal is triggered by whatever method a
    // client asks for, so at `warn!` a client polling a removed method sets
    // the gateway's log volume. The counter below carries the same event at a
    // volume an operator controls.
    tracing::debug!(
        backend = %backend.name,
        method,
        "Refusing a method the backend's protocol revision removed"
    );
    telemetry_metrics::counter!(
        "mcp_gateway_removed_method_refused_total",
        "backend" => backend.name.clone(),
        "method" => method.to_string(),
        "era" => "modern"
    )
    .increment(1);
    true
}

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
pub(super) use test_callers::{anonymous_caller, identified_caller};

#[cfg(test)]
#[path = "policy_epoch_tests.rs"]
mod policy_epoch_tests;
