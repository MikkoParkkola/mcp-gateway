// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Steps of [`Gateway::run`] moved out of `run.rs` unchanged, so the startup
//! sequence stays readable and under the file-size ceiling. Every log line
//! keeps `run`'s target, so an operator's filter on it still matches.
use std::sync::Arc;

use tracing::{error, info, warn};

use super::{
    Gateway, account_bindings, cleartext, configured_minting_strategy_kind,
    leaky_single_user_backends, support,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::{AgentAuthState, AgentDefinition, AgentRegistry, GatewayKeyPair};
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
        if self.config.cache.enabled {
            info!(
            target: RUN_TARGET,
                enabled = true,
                default_ttl = ?self.config.cache.default_ttl,
                max_entries = self.config.cache.max_entries,
                "Response cache initialized"
            );
        }
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
        let account_custody = self.custody.as_ref().map(|custody| {
            Arc::clone(custody) as Arc<dyn crate::personal_accounts::AccountCustody>
        });
        account_bindings::install_account_strategies(
            &self.config,
            account_custody.as_ref(),
            gateway_key_pair,
            meta_mcp,
            account_bindings::ServeMode::Http,
        )?;
        Ok(())
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
}
