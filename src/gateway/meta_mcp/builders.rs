// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MetaMcp` builder methods.

use super::{
    Arc, AtomicU64, CapabilityBackend, CapabilityErrorBudgetConfig, ContextIntegrityKernel,
    Duration, Error, ErrorBudgetConfig, IdempotencyCache, KillSwitch, LocalIdentityGrantStore,
    MessageSigner, MetaMcp, MetaToolExposure, NonceStore, ProfileRegistry, ReloadContext, Result,
    RwLock, SessionProfileStore, ToolRegistry, TransitionTracker, WebhookRegistry, catalogue_cache,
    publish_identity_grants, signing, spawn_cleanup_task, warn,
};
#[cfg(feature = "cost-governance")]
use super::{BudgetEnforcer, CostRegistry};

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
        // The exposure is the one build input outside the catalogue key.
        self.meta_catalogues = catalogue_cache::MetaCatalogues::default();
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
        super::super::meta_mcp_tool_defs::is_governed_meta_tool(name)
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
    /// the A/B split, sticky per caller key.
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

    /// Set the stdio signing scope from the configured posture.
    pub(crate) fn set_signing_scope(&mut self, scope: signing::SigningScope) {
        self.signing_scope = scope;
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
    pub(in crate::gateway) fn backend_identity_strategy(
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
    ///
    /// Checked against the captured `Backend` instance, never a name.
    /// Callers holding the `Arc<Backend>` they will forward to MUST use this so
    /// the check and the later `backend.request` bind to the SAME instance —
    /// eliminating the hot-reload TOCTOU where a name re-lookup could evaluate a
    /// different backend than the one used (ADR-008 INV-2, MIK-6742 R2-1).
    ///
    /// Despite the name this covers every personal binding a backend can carry,
    /// not only `oauth`: see the enumeration in the body. The name is kept
    /// because many call sites spell it.
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
        // Any of them makes the static credential somebody's personal login,
        // and no caller here resolves a per-user one (MIK-6745.JOURNEY.3). Each
        // arm carries its OWN remediation.
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
