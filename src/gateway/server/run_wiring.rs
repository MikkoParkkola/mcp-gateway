// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Steps of [`Gateway::run`] moved out of `run.rs` unchanged, so the startup
//! sequence stays readable and under the file-size ceiling. Every log line
//! keeps `run`'s target, so an operator's filter on it still matches.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use super::task_runtime;
use super::warmstart::WarmerGuard;
use super::{
    Gateway, account_bindings, cleartext, configured_minting_strategy_kind,
    leaky_single_user_backends, support,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::{AgentAuthState, AgentDefinition, AgentRegistry, GatewayKeyPair};
use crate::gateway::stop_budget::StopBudget;
use crate::gateway::subscription_registry::SubscriptionRegistry;
use crate::gateway::task_service::{TaskExecutor, TaskService};
use crate::playbook::PlaybookEngine;
use crate::{Error, Result};

/// The log target the moved lines had in `run.rs`.
const RUN_TARGET: &str = "mcp_gateway::gateway::server::run";

impl Gateway {
    /// Log the policy and feature states once the shared builder has run.
    pub(super) fn log_feature_states(&self) {
        // Log policy and feature states now that the shared builder has run.
        if self.config.security.tool_policy.enabled {
            info!(target: RUN_TARGET, "Tool security policy enabled");
        }
        if self.config.mtls.enabled {
            info!(
            target: RUN_TARGET,
                policies = self.config.mtls.policies.len(),
                require_client_cert = self.config.mtls.require_client_cert,
                "mTLS enabled"
            );
        }
        info!(target: RUN_TARGET, "Usage statistics tracking enabled");
        info!(
            target: RUN_TARGET,
            enabled = true,
            default_ttl = ?self.config.cache.default_ttl,
            max_entries = self.config.cache.max_entries,
            "Response cache initialized"
        );
        if !self.config.routing_profiles.is_empty() {
            info!(
            target: RUN_TARGET,
                profiles = ?self.config.routing_profiles.keys().collect::<Vec<_>>(),
                default = %self.config.default_routing_profile,
                "Routing profiles loaded"
            );
        }
    }

    /// The agent registry from config and the auth state built on it.
    pub(super) fn build_agent_auth(&self) -> Result<AgentAuthState> {
        // Build agent registry from config.
        let agent_registry = Arc::new(AgentRegistry::new());
        for def in &self.config.agent_auth.agents {
            let secret = def.resolved_hs256_secret(self.env.startup())?;
            agent_registry.register(AgentDefinition {
                client_id: def.client_id.clone(),
                name: def.name.clone(),
                hs256_secret: secret,
                rs256_public_key: def.rs256_public_key.clone(),
                scopes: def.scopes.clone(),
                issuer: def.issuer.clone(),
                audience: def.audience.clone(),
            });
        }
        let agent_auth =
            AgentAuthState::new(self.config.agent_auth.enabled, Arc::clone(&agent_registry));
        if self.config.agent_auth.enabled {
            info!(
            target: RUN_TARGET,
                agents = agent_registry.len(),
                "Agent auth (issue #80) enabled"
            );
        }
        Ok(agent_auth)
    }

    /// The process-wide minting strategy and the per-backend account
    /// strategies, installed before serving.
    pub(super) fn install_identity_propagation(
        &self,
        meta_mcp: &MetaMcp,
        gateway_key_pair: &Arc<GatewayKeyPair>,
    ) -> Result<()> {
        // Wire end-user identity propagation (MIK-6704 / ADR-007, MIK-6729):
        // when a backend opts into a *minting* strategy, give MetaMcp the single
        // process-wide strategy that matches the configured kind. Config
        // validation (`validate_single_minting_strategy_kind`) already guarantees
        // at most one minting kind across all backends, and one strategy instance
        // serves every backend of that kind. Each backend's per-request details
        // (audience, token-exchange endpoint/scope) arrive via the
        // `BackendDescriptor` at `propagate()` time, not from this instance.
        //
        // Passthrough (ADR-008 rung 2, MIK-6746) mints NOTHING: the caller attaches its own backend
        // credential and the direct route forwards it verbatim. So a Passthrough-only deployment
        // must NOT install a minting strategy. Doing so would let the meta route
        // (`gateway_invoke`), whose resolver keys off the globally-installed strategy rather than
        // the per-backend `strategy` enum, mint a credential for a Passthrough backend and violate
        // INV-4 (GPT review F1). With the strategy unset the meta route fails closed (required) or
        // falls back to static creds (optional) instead of minting. Mixed deployments (>=1 minting
        // backend plus >=1 passthrough backend) still install the strategy for the minting backend;
        // honoring passthrough on the meta route for that residual case needs the per-backend
        // strategy check in the (currently locked) resolver, tracked on MIK-6746. Interim contract:
        // passthrough is direct-route-only.
        match configured_minting_strategy_kind(&self.config) {
            Some(crate::identity_propagation::PropagationStrategyKind::SignedAssertion) => {
                use crate::identity_propagation::SignedAssertionStrategy;
                // 5-minute assertion lifetime (bounded further by the clamp).
                let strategy = Arc::new(SignedAssertionStrategy::new(
                    Arc::clone(gateway_key_pair),
                    300,
                ));
                meta_mcp.set_identity_propagation(strategy);
                info!(target: RUN_TARGET, "End-user identity propagation enabled (signed-assertion strategy)");
            }
            Some(crate::identity_propagation::PropagationStrategyKind::TokenExchange) => {
                use crate::identity_propagation::TokenExchangeStrategy;
                // 5-minute subject-token lifetime; the exchanged downstream token
                // lives for whatever TTL the endpoint returns (or a safe default).
                let strategy = Arc::new(TokenExchangeStrategy::new(
                    Arc::clone(gateway_key_pair),
                    300,
                ));
                meta_mcp.set_identity_propagation(strategy);
                info!(target: RUN_TARGET, "End-user identity propagation enabled (RFC 8693 token-exchange strategy)");
            }
            // Passthrough / Vault / no identity_propagation: install nothing.
            _ => {}
        }

        // Per-backend strategies for `accounts.descriptors` bindings, installed
        // BEFORE serving. This is where a managed account's vault custody and
        // an external descriptor's minting strategy coexist: each is bound to
        // its own backend, and the resolver prefers the per-backend entry over
        // the single process-wide one above. A managed binding with no custody
        // refuses here rather than dispatching as though it were shared.
        self.install_account_bindings(
            gateway_key_pair,
            meta_mcp,
            account_bindings::ServeMode::Http,
        )
    }

    /// Declare multi-user status, and warn when single-user suppresses the
    /// per-user isolation guard for a leaky backend.
    pub(super) fn declare_multi_user(&self, meta_mcp: &MetaMcp) {
        // ADR-008 INV-2 (MIK-6752): declare multi-user status so dispatch can
        // fail closed on gateway-held OAuth tokens that are not per-user
        // isolated. Detection is fail-closed — any enabled auth is treated as
        // multi-user (a single shared API key or bearer can be handed to a whole
        // team; count alone cannot prove otherwise) unless the operator sets
        // `auth.single_user = true`. More than one credential or any OIDC issuer is
        // a hard multi-user signal. See `AuthConfig::implies_multi_user`.
        let multi_user = self
            .config
            .auth
            .implies_multi_user(!self.config.key_server.oidc.is_empty());
        meta_mcp.set_multi_user(multi_user);
        if multi_user {
            info!(
            target: RUN_TARGET,
                "Multi-user gateway detected — per-user OAuth isolation guard active (ADR-008 INV-2)"
            );
        }

        // MIK-6784 (GW.3): warn when the operator has asserted `single_user =
        // true` (the sole switch that can suppress the per-user isolation guard)
        // while a backend still relies on a gateway-held OAuth token that is NOT
        // blessed for shared use (`oauth.enabled && !shared_account`). In that
        // configuration the single-user assertion is the ONLY thing preventing
        // one user's token — and its upstream MCP session — from being served to
        // another; if the gateway is ever reached by more than one identity the
        // isolation the guard would have provided is silently gone. We warn
        // rather than refuse because a genuinely single-user deployment is valid.
        // Only while the assertion actually holds the guard off (#2241).
        if self.config.auth.single_user && !multi_user {
            let leaky_backends = leaky_single_user_backends(&self.config);
            if !leaky_backends.is_empty() {
                warn!(
                target: RUN_TARGET,
                        backends = ?leaky_backends,
                        "auth.single_user=true suppresses the per-user OAuth isolation guard, but \
                         these backends hold a non-shared gateway OAuth token. If more than one user \
                         reaches this gateway their tokens and upstream MCP sessions will be shared \
                         (MIK-6784). Fix: remove single_user, set oauth.shared_account=true only \
                         for genuinely shared service accounts, or enable per-user identity \
                         propagation."
                    );
            }
        }
    }

    /// Refuse a start that must not serve, and warn about a disarmed
    /// control, before any listener opens.
    pub(super) fn refuse_or_warn_before_bind(&self) -> Result<()> {
        // Refuse BEFORE opening ANY listener, so a configuration that must not
        // serve never opens a port at all. Only this path reaches it; stdio mode
        // has no listener and is untouched.
        //
        // Ahead of the WebSocket spawn as well as the HTTP bind. It used to sit
        // between them, which spawned a listener on the same host for a config
        // the next line refused — a port opened by a start that then failed,
        // contradicting the guarantee this comment makes.
        if let Some(reason) = support::start_refusal(&self.config) {
            error!(target: RUN_TARGET, "{reason}");
            return Err(Error::Config(reason));
        }

        // Warned on EVERY start while the escape hatch is set, and not only when
        // authentication is off. The narrower condition missed the shape the
        // hatch is most often reached from: authentication enabled with `/mcp`
        // public, which is exactly the exposure it is suppressing. An operator
        // reading their logs then saw no sign that the control was disarmed.
        if self.config.server.allow_unauthenticated_network_bind {
            warn!(
            target: RUN_TARGET,
                host = %self.config.server.host,
                "server.allow_unauthenticated_network_bind is set: this gateway serves \
                 callers on the network that it has not authenticated. Authentication \
                 is expected to terminate in front of it."
            );
        }
        if let Some(warning) = cleartext::cleartext_http_warning(&self.config) {
            warn!(target: RUN_TARGET, "{warning}");
        }
        Ok(())
    }

    /// Wait for the record writes handed off dropped requests (D2.5); one
    /// still open at the deadline is reported, never silently lost.
    pub(super) async fn drain_audit_jobs(
        jobs: &crate::gateway::meta_mcp::invoke::audit_owner::AuditJobs,
        drain_timeout: std::time::Duration,
    ) {
        let open = jobs.drain(drain_timeout).await;
        if open > 0 {
            warn!(
                target: RUN_TARGET,
                open_audit_jobs = open,
                "Drain timeout reached with audit records still being written"
            );
        }
    }

    /// Wait, up to `drain_timeout`, for every in-flight request to finish.
    pub(super) async fn drain_inflight(
        inflight: &tokio::sync::Semaphore,
        drain_timeout: std::time::Duration,
    ) {
        // Graceful drain: wait for in-flight requests to complete.
        // The semaphore has 10,000 permits; each in-flight request holds one.
        // We try to acquire all 10,000 (meaning all requests finished) with a timeout.
        info!(target: RUN_TARGET, timeout = ?drain_timeout, "Draining in-flight requests...");

        let drain_result = tokio::time::timeout(drain_timeout, inflight.acquire_many(10_000)).await;

        match drain_result {
            Ok(Ok(_permits)) => {
                info!(target: RUN_TARGET, "All in-flight requests completed");
            }
            Ok(Err(_)) => {
                warn!(target: RUN_TARGET, "Inflight semaphore closed unexpectedly during drain");
            }
            Err(_) => {
                let available = inflight.available_permits();
                let remaining = 10_000_usize.saturating_sub(available);
                warn!(
                target: RUN_TARGET,
                        remaining_requests = remaining,
                        "Drain timeout reached, proceeding with shutdown"
                    );
            }
        }
    }

    /// T2.6: warn once for each surfaced tool whose backend is not warmed at
    /// start (moved from `run.rs` unchanged).
    pub(super) fn warn_cold_surfaced_tools(&self) {
        // T2.6: warn when a surfaced tool's backend is not in warm_start.
        for surfaced in &self.config.meta_mcp.surfaced_tools {
            if !self.config.meta_mcp.warm_start.contains(&surfaced.server) {
                warn!(
                    target: RUN_TARGET,
                    tool = %surfaced.tool,
                    server = %surfaced.server,
                    "Surfaced tool's backend is not in meta_mcp.warm_start — \
                     schema may be absent until the backend is first used"
                );
            }
        }
    }

    /// Load the configured playbook directories into `meta_mcp` (moved from
    /// `run.rs` unchanged).
    pub(super) fn load_playbooks(&self, meta_mcp: &MetaMcp) {
        // Load playbooks if enabled
        if self.config.playbooks.enabled {
            let mut engine = PlaybookEngine::new();
            let mut total_playbooks = 0;
            for dir in &self.config.playbooks.directories {
                match engine.load_from_directory(dir) {
                    Ok(count) => {
                        total_playbooks += count;
                        debug!(target: RUN_TARGET, directory = %dir, count, "Loaded playbooks");
                    }
                    Err(e) => {
                        debug!(target: RUN_TARGET, directory = %dir, error = %e, "Failed to load playbooks");
                    }
                }
            }
            if total_playbooks > 0 {
                info!(target: RUN_TARGET, playbooks = total_playbooks, "Playbook engine ready");
            }
            meta_mcp.set_playbook_engine(engine);
        }
    }

    /// Open the durable task runtime, install the upstream recovery adapter and
    /// start the expiry sweep, before any listener exists (moved from `run.rs`
    /// unchanged). A sweep that cannot start shuts the opened service first.
    pub(super) async fn open_tasks(
        &self,
        task_store_dir: &Path,
        subscriptions: &Arc<SubscriptionRegistry>,
        meta_mcp: &MetaMcp,
    ) -> Result<(
        Arc<TaskService>,
        Arc<TaskExecutor>,
        crate::gateway::task_service::execution::ExpirySweep,
    )> {
        // The runtime shares meta-MCP's admission authority rather than opening
        // one of its own: a task and a later synchronous call carrying the same
        // owner and idempotency key have to meet at ONE admission index, or the
        // backend runs twice for what the caller sent once.
        //
        // The adapters that are BOTH named in `tasks.recovery_adapters` and
        // still configured backends. Computed here because this is the one
        // place that can see both lists before `AppState` exists; it is the
        // weakest evaluable test on purpose, since deferring a row is not a
        // trust claim and issues no upstream call. Empty means the recovery
        // below is byte-identical to the no-adapter behaviour.
        let managed_adapters: Vec<String> = self.managed_recovery_adapters();
        let (task_service, task_executor) = task_runtime::open(
            &self.config,
            task_store_dir,
            Arc::clone(subscriptions),
            meta_mcp,
            &managed_adapters,
        )
        .await
        .map_err(|error| {
            // A held lease is most often a stdio gateway on the same
            // directory (MIK-7272.OWNER.2, design D6 rev 5 item 7).
            Error::Config(format!(
                "task store at '{}' could not be opened: {error} (a task record refused \
                 here is named in the task store warning above; if the store is held by \
                 another gateway process, possibly a stdio gateway using \
                 '<store_dir>/stdio', give each gateway its own tasks.store_dir)",
                task_store_dir.display()
            ))
        })?;
        let skipped = task_service.skipped_records();
        info!(
            target: RUN_TARGET,
            path = %task_store_dir.display(),
            max_workers = self.config.tasks.max_workers,
            skipped_kept_key = skipped.reserved,
            skipped_sealed = skipped.sealed,
            "Durable task store opened"
        );
        // The trusted upstream adapter, installed after the store recovered and
        // before the socket serves. It needs the started backend registry, which
        // is why it cannot be a constructor argument to `open`. With no
        // configured names it is not installed at all and every upstream path
        // stays unreachable.
        if !managed_adapters.is_empty() {
            let installed = task_executor.install_recovery(Arc::new(
                crate::gateway::meta_mcp::upstream::NativeUpstreamTasks::new(
                    Arc::clone(&self.backends),
                    &managed_adapters,
                ),
            ));
            info!(
                target: RUN_TARGET,
                adapters = ?managed_adapters,
                installed,
                "Upstream task recovery adapter configured"
            );
        }
        // The periodic expiry owner, started only now: the recovery inside
        // `open_runtime_with_admission` has succeeded, so the sweep can never see
        // a row a restart had not yet settled. The guard is held for the server's
        // lifetime and joined below, before the store closes — dropping it on an
        // early return signals the loop to stop without cutting a deletion that
        // is already in flight.
        let expiry_sweep: crate::gateway::task_service::execution::ExpirySweep =
            match task_executor.start_expiry(self.config.tasks.expiry_interval) {
                Ok(sweep) => sweep,
                Err(error) => {
                    let _ = task_service.shutdown().await;
                    return Err(Error::Config(format!(
                        "task expiry sweep at {:?} could not be started: {error}",
                        self.config.tasks.expiry_interval
                    )));
                }
            };
        info!(
            target: RUN_TARGET,
            interval = ?self.config.tasks.expiry_interval,
            "Durable task expiry sweep started"
        );
        Ok((task_service, task_executor, expiry_sweep))
    }

    /// The stop's last stages, in order: release account custody, let the
    /// warmers unwind, stop every backend by the backend deadline, then detach
    /// whatever custody was not released (moved from `run.rs` unchanged).
    pub(super) async fn stop_custody_and_backends(
        &self,
        budget: &StopBudget,
        total: Duration,
        warmer: WarmerGuard,
    ) {
        // Release the custody store before the backends go: the drain above is
        // what guarantees no in-flight request is still holding a credential.
        // Not covered by gateway_bootstrap_tests — no test drives `run`.
        budget
            .stage("account custody shutdown", total, async {
                if let Err(e) = self
                    .shutdown_account_custody_by(budget.post_listener_end())
                    .await
                {
                    warn!(target: RUN_TARGET, error = %e, "Personal account custody shutdown failed");
                }
            })
            .await;

        // Stop all backends, after their warmers can no longer start one.
        info!(target: RUN_TARGET, "Shutting down backends...");
        // It may use the time up to Db: an aborted warm-start must have unwound
        // before the backends are listed.
        budget
            .stage_until_backend_end("warmer cancel", warmer.cancel())
            .await;
        // One deadline for the whole stage: each stdio backend gets its EOF,
        // then SIGTERM, then the kill, planned to end by then. The stop budget
        // fixes it, however long the stages before took.
        let stop_deadline = budget.backend_end();
        #[allow(
            clippy::disallowed_methods,
            reason = "Lifecycle: gateway startup, wiring or shutdown; no caller request"
        )]
        self.backends
            .stop_all_by(stop_deadline, crate::backend::Handover::AtEntry)
            .await;

        // Whatever the custody stage did not release (it was skipped or cut):
        // never drop the store on this thread when `self` drops.
        self.detach_custody_release();
    }
}
