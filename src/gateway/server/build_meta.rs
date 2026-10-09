// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared `MetaMcp` construction both serve modes use (moved from `server/mod.rs`, MIK-8144).

use std::sync::Arc;

use tracing::{info, warn};

use super::Gateway;
use super::identity_grants::load_configured_identity_grants;
use super::provenance_signer::{provenance_key, resolve_provenance_signer};
use super::{expand_home_path, persistence};
use crate::cache::ResponseCache;
use crate::gateway::meta_mcp::MetaMcp;
use crate::mtls::MtlsPolicy;
use crate::ranking::SearchRanker;
use crate::routing_profile::ProfileRegistry;
use crate::security::ToolPolicy;
#[cfg(feature = "firewall")]
use crate::security::firewall::Firewall;
use crate::stats::UsageStats;
use crate::transition::TransitionTracker;
use crate::{Error, Result};

/// Shared components produced by [`Gateway::build_meta_mcp`].
///
/// Both the HTTP server (`Gateway::run`) and the stdio server
/// (`Gateway::run_stdio`) require identical `MetaMcp` initialisation.  This
/// struct carries the results so callers can destructure exactly what they need
/// without duplicating the construction logic.
pub(super) struct BuiltMetaMcp {
    pub(super) meta_mcp: Arc<MetaMcp>,
    pub(super) tool_policy: Arc<ToolPolicy>,
    pub(super) mtls_policy: Arc<MtlsPolicy>,
    /// Ranker handle retained for graceful-shutdown persistence (HTTP mode).
    pub(super) ranker: Arc<SearchRanker>,
    /// On-disk path for ranker persistence.
    pub(super) ranker_path: std::path::PathBuf,
    /// Transition tracker retained for shutdown persistence (HTTP mode).
    pub(super) transition_tracker: Arc<TransitionTracker>,
    /// On-disk path for transition persistence.
    pub(super) transition_path: std::path::PathBuf,
    /// Data directory used by cost-governance persistence.
    pub(super) data_dir: std::path::PathBuf,
    /// Transparency log handle, `None` when disabled (issue #133, D3).
    /// Threaded into `AppState` so the direct backend route
    /// (`backend_handlers::backend_handler`), which does not go through
    /// `MetaMcp`, can also write identity-propagation audit events into the
    /// same tamper-evident chain (MIK-6740).
    pub(super) transparency_log: Option<Arc<crate::security::TransparencyLogger>>,
}

impl Gateway {
    /// A firewall with its own transition tracker, sharing `meta_mcp`'s relay
    /// detector (COLLUDE.1). Both transports build theirs here, so each leaves
    /// the continuations `meta_mcp` minted unredacted (#2210).
    #[cfg(feature = "firewall")]
    pub(super) fn response_firewall(&self, meta_mcp: &MetaMcp) -> Arc<Firewall> {
        let fw_cfg = self.config.security.firewall.clone();
        let fw_enabled = fw_cfg.enabled;
        let tt = fw_cfg
            .anomaly_detection
            .then(|| Arc::new(TransitionTracker::new()));
        let fw = Arc::new(
            Firewall::from_config(fw_cfg, tt)
                .with_env(Arc::clone(&self.env))
                .with_continuations(meta_mcp.continuation())
                .with_posture(self.config.security.posture)
                .with_reads(Arc::clone(&self.reads))
                .sharing_relay_with(meta_mcp.firewall.as_deref()),
        );
        if fw_enabled {
            info!("Security firewall enabled (RFC-0071)");
        }
        fw
    }

    /// Build [`MetaMcp`] and all supporting components shared between HTTP and
    /// stdio modes.
    ///
    /// Eliminates ~100 lines of duplication between [`Self::run`] and
    /// [`Self::run_stdio`].  The returned [`BuiltMetaMcp`] carries handles that
    /// callers may need for graceful shutdown or further wiring.
    ///
    /// # Errors
    ///
    /// Rejects invalid effective signing configuration before shared setup.
    #[allow(clippy::too_many_lines)]
    pub(super) async fn build_meta_mcp(&self) -> Result<BuiltMetaMcp> {
        let signing = self
            .config
            .security
            .message_signing
            .resolve_with_env(&self.env.get())?;
        // ── Response cache ───────────────────────────────────────────────────
        let cache = if self.config.cache.enabled {
            let cache = if self.config.cache.max_entries > 0 {
                Arc::new(ResponseCache::with_max_entries(
                    self.config.cache.max_entries,
                ))
            } else {
                Arc::new(ResponseCache::new())
            };
            Some(cache)
        } else {
            None
        };

        // ── Security policies ────────────────────────────────────────────────
        let tool_policy = Arc::new(ToolPolicy::from_config(&self.config.security.tool_policy));
        let mtls_policy = Arc::new(MtlsPolicy::from_config(&self.config.mtls));

        // ── Usage stats + search ranker with on-disk persistence ─────────────
        let usage_stats = Some(Arc::new(UsageStats::new()));

        #[cfg(test)]
        let data_dir = self.test_seams.data_dir();
        #[cfg(not(test))]
        let data_dir = persistence::standard_data_dir();
        persistence::ensure_data_dir(&data_dir);

        let ranker_path = data_dir.join("usage.json");
        let ranker = Arc::new(SearchRanker::new());
        persistence::load_if_exists(
            &ranker_path,
            |path| ranker.load(path),
            "Failed to load search ranker usage data",
            "Loaded search ranking usage data",
        );

        // ── Transition tracker ───────────────────────────────────────────────
        let transition_path = data_dir.join("transitions.json");
        let transition_tracker = Arc::new(TransitionTracker::new());
        persistence::load_if_exists(
            &transition_path,
            |path| transition_tracker.load(path),
            "Failed to load transition tracking data",
            "Loaded transition tracking data",
        );

        // ── Routing profiles + secret injector ──────────────────────────────
        let profile_registry = ProfileRegistry::from_config(
            &self.config.routing_profiles,
            &self.config.default_routing_profile,
        );
        let secret_injector =
            crate::secret_injection::SecretInjector::from_backend_configs(&self.config.backends)
                .with_env(Arc::clone(&self.env));

        // ── Cost governance (feature-gated) ──────────────────────────────────
        #[cfg(feature = "cost-governance")]
        let (cost_registry_opt, budget_enforcer_opt) =
            persistence::boot_cost_governance(&self.config.cost_governance, &data_dir);

        // ── MetaMcp builder ──────────────────────────────────────────────────
        #[allow(unused_mut)]
        let mut meta_mcp_builder = MetaMcp::with_features(
            Arc::clone(&self.backends),
            cache,
            usage_stats,
            Some(Arc::clone(&ranker)),
            self.config.cache.default_ttl,
        )
        .with_profile_registry(profile_registry)
        .with_code_mode(self.config.code_mode.enabled)
        .with_projection_mode(self.config.meta_mcp.projection_mode)
        .with_secret_injector(secret_injector)
        .with_surfaced_tools(self.config.meta_mcp.surfaced_tools.clone())
        .with_exposed_meta_tools(&self.config.meta_mcp.exposed_meta_tools)
        .with_expose_stats_tool(self.config.meta_mcp.expose_stats_tool)
        .with_prompts_resources_fetch_timeout(self.config.meta_mcp.prompts_resources_fetch_timeout)
        .with_caller_identity(self.config.security.caller_identity.clone());

        #[cfg(feature = "cost-governance")]
        if let (Some(registry), Some(enforcer)) = (cost_registry_opt, budget_enforcer_opt) {
            meta_mcp_builder = meta_mcp_builder.with_cost_governance(enforcer, registry);
        }

        meta_mcp_builder.set_idempotency_config(self.config.idempotency.clone());
        meta_mcp_builder.set_idempotency_key_mode(self.config.server.idempotency_key);

        // ── Per-action attestation (MIK-5223 / MIK-6163, B1-IDENT) ────────────
        // Wire the attestation validator from operator config (env-driven).
        // Default is OFF: no validator. `observe` audits every presented token
        // but never blocks a call. `enforce` refuses unattested calls on the
        // meta and direct routes. Unknown values, and `enforce` without a
        // signing key, fail startup (`resolve_attestation_wiring`).
        if let Some((validator, mode)) =
            crate::attestation::attestation_wiring_from_overlay(&self.env.get())
                .map_err(Error::Config)?
        {
            info!(
                ?mode,
                "Per-action attestation wired on the meta route and every direct-route method"
            );
            meta_mcp_builder = meta_mcp_builder.with_attestation(validator, mode);
        }

        if signing.enabled {
            let previous =
                (!signing.previous_secret.is_empty()).then(|| signing.previous_secret.into_bytes());
            meta_mcp_builder.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    signing.shared_secret.into_bytes(),
                    previous,
                    signing.key_id,
                ),
                std::time::Duration::from_secs(signing.replay_window),
                signing.require_nonce,
            );
            meta_mcp_builder.set_signing_scope(super::super::meta_mcp::signing::SigningScope::of(
                self.config.security.posture,
            ));
        }
        let security = &self.config.security;
        if let Some(chain) = &security.signature_chain {
            meta_mcp_builder.set_chain_signer(chain.resolve_with_env(&self.env.get())?, chain.emit);
            let keys = security.remote_server_signing.trusted_keys.clone();
            let window = security.message_signing.replay_window;
            meta_mcp_builder.set_chain_trust(chain.max_links, keys, window);
        }

        let mut meta_mcp = Arc::new(meta_mcp_builder);
        meta_mcp.set_context_integrity_kernel(
            crate::context_integrity::ContextIntegrityKernel::new(
                self.config.security.context_integrity.policy(),
            ),
        );
        info!(
            preset = ?self.config.security.context_integrity.preset,
            license_tier = self.config.security.context_integrity.license_tier(),
            "Context integrity policy configured"
        );
        meta_mcp.set_transition_tracker(Arc::clone(&transition_tracker));

        // Apply the operator's `error_budget:` section to the running budgets
        // (GH #475). Absent keys keep the values that have been shipping, so a
        // config without the section leaves both budgets exactly as before.
        let backend_budget = self.config.error_budget.backend_config();
        let capability_budget = self.config.error_budget.capability_config();
        // Logged because the budgets are otherwise unobservable: nothing emits a
        // metric or an event carrying the effective threshold, so a gateway
        // running a configured value and one running the default are
        // indistinguishable from outside, and a regression that silently ignored
        // the section would produce no signal at all.
        info!(
            backend_threshold = backend_budget.threshold,
            backend_window_size = backend_budget.window_size,
            backend_min_samples = backend_budget.min_samples,
            backend_window_duration_secs = backend_budget.window_duration.as_secs(),
            capability_threshold = capability_budget.threshold,
            capability_window_size = capability_budget.window_size,
            capability_min_samples = capability_budget.min_samples,
            capability_window_duration_secs = capability_budget.window_duration.as_secs(),
            capability_cooldown_secs = capability_budget.cooldown.as_secs(),
            "Error budgets configured"
        );
        meta_mcp.set_error_budget_config(backend_budget);
        meta_mcp.set_capability_budget_config(capability_budget);

        // ── Transparency log (issue #133, D3) ─────────────────────────────────
        // The opened `Arc` is kept as `transparency_log` (not just handed to
        // `MetaMcp`) so `AppState` can hold a second clone — the direct
        // backend route writes identity-propagation audit events straight
        // into this chain without going through `MetaMcp` (MIK-6740).
        let mut transparency_log: Option<Arc<crate::security::TransparencyLogger>> = None;
        if self.config.security.transparency_log.enabled {
            let tl_cfg = Arc::new((&self.config.security.transparency_log).into());
            // Auth on: the log is required (D1-a) and a failed append
            // withholds the call's result (D1-f).
            let auth_on = self.config.auth.enabled;
            let policy = if auth_on {
                crate::security::audit::AuditFailurePolicy::FailClosed
            } else {
                crate::security::audit::AuditFailurePolicy::BestEffort
            };
            match crate::security::TransparencyLogger::open(tl_cfg) {
                Ok(logger) => {
                    let logger = Arc::new(logger.with_failure_policy(policy));
                    Arc::get_mut(&mut meta_mcp)
                        .expect("no other Arc references at this point")
                        .enable_transparency_log(Arc::clone(&logger));
                    transparency_log = Some(logger);
                    info!("Transparency log enabled");
                }
                // Two writers of one log fork its chain, so this refuses
                // whatever the auth setting.
                Err(e) if crate::security::transparency_log::is_lease_held(&e) => {
                    return Err(Error::Config(format!("refusing to start: {e}")));
                }
                Err(e) if auth_on => {
                    return Err(Error::Config(format!(
                        "auth is enabled, so the audit log (security.transparency_log) must \
                         open: {e}"
                    )));
                }
                Err(e) => {
                    warn!(error = %e, "Failed to open transparency log — continuing without it");
                }
            }
        }

        // ── Runtime provenance stamping (MIK-6905) ────────────────────────────
        // Off by default. When enabled, sign a facts-only receipt into
        // `_meta.provenance` on every aggregated tool result, reusing the
        // gateway's attestation signing key (one signing identity, B4-PLATFORM).
        if self.config.security.provenance_stamping {
            let (key, key_id) = provenance_key(&self.env.get());
            match resolve_provenance_signer(&key, &key_id) {
                Some(signer) => {
                    Arc::get_mut(&mut meta_mcp)
                        .expect("no other Arc references at this point")
                        .enable_provenance_stamping(signer);
                    info!(
                        "Runtime provenance stamping enabled — signed _meta.provenance on tool \
                         results"
                    );
                }
                None => {
                    // Fail closed. An empty HMAC key yields publicly computable
                    // signatures, and the eval harness trusts any receipt that
                    // verifies — so an empty-key signer lets anyone forge "signed"
                    // ground truth. Leaving the signer uninstalled keeps output
                    // byte-identical to stamping-off, which is strictly safer
                    // than emitting forgeable receipts.
                    warn!(
                        env = crate::attestation::ATTESTATION_SIGNING_KEY_ENV,
                        "provenance_stamping enabled but no signing key is set; stamping stays \
                         DISABLED (fail-closed) — set the signing key to emit verifiable receipts"
                    );
                }
            }
        }

        // ── Shadow claim capture (MIK-6908, rung 3.1) ─────────────────────────
        // Off by default. When enabled, shadow-captures the derived claim
        // alongside each signed provenance receipt to an append-only NDJSON
        // file, for offline scoring via `provenance-eval` (rung 3.4). Has no
        // observable effect unless `provenance_stamping` is also enabled —
        // capture piggybacks on that chokepoint rather than adding a new one.
        if self.config.security.claim_capture.enabled {
            let capture_path = expand_home_path(&self.config.security.claim_capture.path);
            match crate::trust::ClaimCaptureSink::open(&capture_path) {
                Ok(sink) => {
                    Arc::get_mut(&mut meta_mcp)
                        .expect("no other Arc references at this point")
                        .enable_claim_capture(Arc::new(sink));
                    info!(
                        "Shadow claim capture enabled — capturing derived claims for offline scoring"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "Failed to open claim-capture sink — continuing without it");
                }
            }
        }

        // ── Response inspection action mode (issue #133, D2) ──────────────────
        if self.config.security.response_inspection.enabled
            && self.config.security.response_inspection.action_mode
        {
            Arc::get_mut(&mut meta_mcp)
                .expect("no other Arc references at this point")
                .enable_response_inspection_action_mode();
            info!("Response inspection action mode enabled — HIGH/CRITICAL findings will block");
        } else if self.config.security.response_inspection.enabled {
            info!("Response inspection enabled in observe mode");
        }

        // ── Response contract gate (issue #133, D1) ───────────────────────────
        if self.config.security.response_contract.enabled {
            Arc::get_mut(&mut meta_mcp)
                .expect("no other Arc references at this point")
                .set_response_contract(self.config.security.response_contract.clone());
            let action = if self.config.security.response_contract.action_mode {
                "action"
            } else {
                "observe"
            };
            info!(action, "Response contract gate enabled");
        }

        // ── Idempotency (MIK-7272.SUB.4) ─────────────────────────────────────
        // Unconditional and unconfigurable: an idempotency key is a correctness
        // mechanism, and a toggle could only switch duplicated side effects
        // back on. Bounds are the constants in `crate::idempotency`.
        // This is the only production construction site of `MetaMcp`, and both
        // `run` and `run_stdio` reach it, so the cache is `Some` on every boot.
        // All three of the criterion's routes reach a guard from here: generic
        // `tools/call` through `meta_mcp/invoke.rs`, stdio through the real
        // `RetryFields` `dispatch_single_with_sink` builds (`:1886`), and the
        // direct `POST /mcp/{name}` bypass through its own local re-enforcement
        // (`meta_mcp/direct_route.rs`, called at `backend_handlers.rs:781`).
        // Reaching a guard is not the whole criterion: the direct route still
        // RELEASES the client's key when the backend call fails, which is the
        // broken-stream case SUB.4 is written about, so the row is PARTIAL —
        // see `docs/design/2026-08-31-sub-4-idempotency-wiring.md`.
        Arc::get_mut(&mut meta_mcp)
            .expect("no other Arc references at this point")
            .enable_idempotency(
                Arc::new(crate::idempotency::IdempotencyCache::new()),
                crate::idempotency::CLEANUP_INTERVAL,
            );

        // ── Local identity grants (MIK-6553 free/core) ───────────────────────
        if let Some((path, grants)) =
            load_configured_identity_grants(&self.config.security.identity_grants).await?
        {
            let count = grants.len();
            Arc::get_mut(&mut meta_mcp)
                .expect("no other Arc references at this point")
                .set_identity_grants(grants);
            info!(
                grants = count,
                path = %path.display(),
                "Local identity grants loaded"
            );
        }

        // ── Security firewall (RFC-0071) ──────────────────────────────────────
        // Wire a firewall into `MetaMcp` so the aggregated discovery surface
        // (`gateway_list_tools` / `gateway_search_tools`) is scanned. The direct
        // `tools/call` + `tools/list` path builds its own firewall in `run()`
        // (see `AppState`); each keeps its own `TransitionTracker`.
        #[cfg(feature = "firewall")]
        {
            let fw = self.response_firewall(&meta_mcp);
            Arc::get_mut(&mut meta_mcp)
                .expect("no other Arc references at this point")
                .set_firewall(Some(fw));
        }

        Ok(BuiltMetaMcp {
            meta_mcp,
            tool_policy,
            mtls_policy,
            ranker,
            ranker_path,
            transition_tracker,
            transition_path,
            data_dir,
            transparency_log,
        })
    }
}
