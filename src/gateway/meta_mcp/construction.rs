// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MetaMcp` constructors.

#[cfg(feature = "spec-preview")]
use super::DashMap;
use super::{
    Arc, AtomicU64, BackendRegistry, CapabilityErrorBudgetConfig, ContextIntegrityKernel,
    CostTracker, Duration, ErrorBudgetConfig, KillSwitch, LocalIdentityGrantStore, LoggingLevel,
    MetaMcp, MetaToolExposure, PlaybookEngine, ProfileRegistry, ResponseCache, RwLock,
    SearchRanker, SessionProfileStore, SessionStateStore, UsageStats, admission, catalogue_cache,
    signing,
};

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
        clock: Arc<
            dyn Fn() -> std::result::Result<u64, crate::clock::ClockBeforeEpoch> + Send + Sync,
        >,
    ) -> Self {
        Self {
            backends: super::scoped_backends::Registry::new(backends),
            change_feed: std::sync::OnceLock::new(),
            events: std::sync::OnceLock::new(),
            counters: std::sync::OnceLock::new(),
            capabilities: RwLock::new(None),
            cache,
            default_cache_ttl,
            idempotency_cache: None,
            grant_repeats: Arc::default(),
            execution_admission: crate::idempotency::admission::ExecutionAdmission::new_fallible(
                clock,
            ),
            idempotency_config: RwLock::new(crate::config::IdempotencyConfig::default()),
            unkeyed: admission::UnkeyedPolicy::default(),
            lacked_warned: parking_lot::Mutex::default(),
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
            cost_tracker: Arc::new(CostTracker::new()),
            tool_registry: None,
            #[cfg(feature = "cost-governance")]
            budget_enforcer: None,
            #[cfg(feature = "cost-governance")]
            cost_registry: None,
            surfaced: Arc::default(),
            meta_tool_exposure: MetaToolExposure::expose_all(),
            meta_catalogues: catalogue_cache::MetaCatalogues::default(),
            meta_projections: crate::trust::SharedProjections::default(),
            expose_stats_tool: false,
            prompts_resources_fetch_timeout: std::time::Duration::from_secs(10),
            #[cfg(feature = "spec-preview")]
            session_promoted: Arc::new(DashMap::new()),
            window_seal: Arc::default(),
            session_state: SessionStateStore::new(),
            message_signer: None,
            nonce_store: None,
            signing_scope: signing::SigningScope::InvokeOnly,
            provenance_signer: None,
            public_provenance_signer: None,
            chain_signer: None,
            // Production installs the resolved key in build_meta_mcp (G-META);
            // a MetaMcp built in test code starts with the fixed test key.
            #[cfg(not(test))]
            record_key: None,
            #[cfg(test)]
            record_key: Some(Arc::new(crate::gateway::record_principal::test_record_key())),
            claim_capture: None,
            require_nonce: false,
            transparency_logger: None,
            rejection_audit: std::sync::OnceLock::new(),
            response_inspection: crate::security::response_inspect::ResponseInspectionMode::Observe,
            response_contract: None,
            attestation_validator: None,
            attestation_mode: crate::attestation::AttestationMode::Observe,
            identity_grants: Arc::new(RwLock::new(LocalIdentityGrantStore::new())),
            policy_epoch: Arc::new(AtomicU64::new(0)),
            caller_identity: crate::security::caller_identity::CallerIdentityConfig::default(),
            access_verifier: None,
            context_integrity_kernel: RwLock::new(ContextIntegrityKernel::default()),
            firewall: None,
            inflight_calls: Arc::default(),
            #[cfg(feature = "webui")]
            ui_calls: Arc::new(tokio::sync::Semaphore::new(
                crate::gateway::ui_call::MAX_UI_CALLS,
            )),
        }
    }

    /// The permits web UI tool calls run under (U12).
    #[cfg(feature = "webui")]
    pub(crate) fn ui_call_permits(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.ui_calls
    }

    /// The registry a client's explicit cancel is looked up in.
    pub(crate) fn inflight_calls(
        &self,
    ) -> &Arc<crate::gateway::router::inflight_calls::InFlightCalls> {
        &self.inflight_calls
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
            Arc::new(crate::clock::unix_secs),
        )
    }

    /// Build the real handler with its serving runtime's trusted epoch source.
    pub(crate) fn with_features_and_clock(
        backends: Arc<BackendRegistry>,
        cache: Option<Arc<ResponseCache>>,
        stats: Option<Arc<UsageStats>>,
        ranker: Option<Arc<SearchRanker>>,
        default_ttl: Duration,
        clock: Arc<
            dyn Fn() -> std::result::Result<u64, crate::clock::ClockBeforeEpoch> + Send + Sync,
        >,
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

    /// The zone daily budgets count days in (ADR-026): the budget enforcer's,
    /// or the host's when none runs.
    #[cfg_attr(
        not(feature = "cost-governance"),
        expect(
            clippy::unused_self,
            reason = "only the budget enforcer is read through self"
        )
    )]
    pub(crate) fn day_zone(&self) -> &'static str {
        #[cfg(feature = "cost-governance")]
        if let Some(enforcer) = &self.budget_enforcer {
            return enforcer.day_zone();
        }
        crate::local_day::host_zone_name()
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

    /// Install the process's record key (MIK-8697 §16.11).
    pub(crate) fn set_record_key(
        &mut self,
        key: Arc<crate::gateway::record_principal::RecordPrincipalKey>,
    ) {
        self.record_key = Some(key);
    }

    /// The record key every record this gateway writes is keyed with.
    ///
    /// # Panics
    ///
    /// When `build_meta_mcp` did not install one: writing the record unkeyed
    /// would be the leak MIK-8697 closes, so the write fails instead.
    pub(crate) fn record_key(&self) -> &crate::gateway::record_principal::RecordPrincipalKey {
        // The one non-test MetaMcp construction is build_meta_mcp, which calls
        // set_record_key unconditionally (row G-META pins both).
        self.record_key
            .as_deref()
            // invariant: build_meta_mcp installed the key (G-META).
            .expect("the record key is installed by build_meta_mcp before any record is written")
    }
}
