// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend-wide state readers and breaker controls on the canonical Shared
//! slot. Split out of `lifecycle.rs` and `ops.rs` to keep both under the
//! file-size ratchet (`scripts/dev/check-file-size.py`).

use std::sync::atomic::Ordering;

use super::Backend;
use super::pool::PoolKey;
use super::registry::{BackendLifecycle, BackendRuntimeState, BackendRuntimeStatus, BackendStatus};
use crate::config::TransportConfig;

impl Backend {
    /// Check if backend is running (canonical shared slot connected).
    pub fn is_running(&self) -> bool {
        self.pool
            .get(&PoolKey::Shared)
            .and_then(|entry| {
                entry
                    .value()
                    .transport
                    .read()
                    .as_ref()
                    .map(|t| t.is_connected())
            })
            .unwrap_or(false)
    }

    /// Get circuit breaker stats for this backend's canonical Shared slot
    /// (MIK-6735 fix 1).
    pub fn circuit_breaker_stats(&self) -> crate::failsafe::CircuitBreakerStats {
        self.shared_entry().failsafe.circuit_breaker.stats()
    }

    /// Drive this backend's canonical Shared-slot circuit breaker open.
    ///
    /// The counterpart to [`Self::reset_circuit_breaker`], for the one caller
    /// that has decided a backend is failing without having a failed request to
    /// show for it: the health probe's unserved escalation (MIK-7217,
    /// OUTBOUND.2), whose evidence is a run of complete answers that served
    /// nothing. Expressed as the configured number of failures rather than a
    /// state write, so the breaker's own accounting - open event, failure
    /// count, the half-open timer - stays the single description of why it is
    /// open. The trip is not warm-up's own, so it sets the provenance flag
    /// under the flag's lock and a warm-up success cannot reset it (#2219).
    pub(crate) fn trip_circuit_breaker(&self, reason: &str) {
        let entry = self.shared_entry();
        let mut not_warmup_trip = entry.request_failed_since_close.lock();
        *not_warmup_trip = true;
        let threshold = entry.failsafe.circuit_breaker.stats().failure_threshold;
        for _ in 0..threshold {
            entry
                .failsafe
                .circuit_breaker
                .record_failure(reason, std::time::Duration::ZERO);
        }
    }

    /// Force this backend's canonical Shared-slot circuit breaker back to
    /// `Closed` (MIK-5983; slot-scoped per MIK-6735 fix 1).
    ///
    /// Called by `gateway_revive_server` so the documented manual recovery
    /// path also clears a tripped breaker, not just the kill switch.
    pub fn reset_circuit_breaker(&self) {
        self.shared_entry().failsafe.circuit_breaker.reset();
    }

    /// Whether this backend's canonical Shared-slot circuit breaker is
    /// currently tripped (`Open` or `HalfOpen` -- i.e. not `Closed`; slot-scoped
    /// per MIK-6735 fix 1).
    #[must_use]
    pub fn is_circuit_tripped(&self) -> bool {
        self.shared_entry().failsafe.circuit_breaker.state()
            != crate::failsafe::CircuitState::Closed
    }
}

impl Backend {
    /// Pass-through mode: exempt from input sanitization on every route, and
    /// from tool policy on `/mcp/{name}`. Only for fully-trusted backends.
    #[must_use]
    pub fn passthrough(&self) -> bool {
        self.config.passthrough
    }

    /// Whether this backend is a local process the gateway's filesystem view
    /// applies to (MIK-8939): only stdio. Exhaustive with no wildcard arm, so a
    /// transport added later does not compile until someone classes it.
    #[must_use]
    pub(crate) fn is_local_process(&self) -> bool {
        match &self.config.transport {
            TransportConfig::Stdio { .. } => true,
            TransportConfig::Http { .. } | TransportConfig::WebSocket { .. } => false,
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { .. } => false,
        }
    }

    /// Return the HTTP URL if this backend uses an HTTP-based transport.
    ///
    /// Returns `None` for stdio backends.
    #[must_use]
    pub fn transport_url(&self) -> Option<&str> {
        match &self.config.transport {
            TransportConfig::Http { http_url: url, .. }
            | TransportConfig::WebSocket { ws_url: url, .. } => Some(url.as_str()),
            TransportConfig::Stdio { .. } => None,
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => Some(a2a_url.as_str()),
        }
    }

    /// Coarse lifecycle state, distinct from health.
    ///
    /// `running: bool` cannot express "stopped on purpose". Reporting a
    /// deliberately-stopped backend as unhealthy would trip its circuit breaker
    /// and show it as broken while it behaves exactly as configured; reporting
    /// it as healthy would hide that its process is gone.
    ///
    /// A backend is `Dormant` only if it opted into being stopped when idle,
    /// its transport is released, and nothing is actually wrong with it. If the
    /// breaker is open or the health tracker says otherwise, it is `Unhealthy`
    /// regardless — a real failure is never disguised as a nap.
    #[must_use]
    pub fn lifecycle(&self) -> BackendLifecycle {
        if self.shared_slot_refused() {
            return BackendLifecycle::PerUser;
        }
        if self.is_running() {
            return BackendLifecycle::Running;
        }
        let entry = self.shared_entry();
        if self.is_circuit_tripped() || !entry.failsafe.health_metrics().healthy {
            return BackendLifecycle::Unhealthy;
        }
        // Dormant only if the reaper actually stopped it. Inferring from
        // configuration alone would report a backend whose first start FAILED as
        // sleeping: nothing has updated the failsafe yet, so it still looks
        // healthy, and "never came up" would be indistinguishable from "resting".
        if entry
            .stopped_when_idle
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return BackendLifecycle::Dormant;
        }
        BackendLifecycle::NotStarted
    }

    /// The per-request timeout this backend was configured with.
    ///
    /// Exposed so callers that wrap a backend call in a ceiling of their own can
    /// derive it from the operator's setting instead of hard-coding a number
    /// that silently pre-empts any backend configured to take longer.
    #[must_use]
    pub fn request_timeout(&self) -> std::time::Duration {
        self.config.timeout
    }

    /// Get backend status.
    ///
    /// Reports the canonical Shared slot's circuit/health state (MIK-6735
    /// fix 1): this is the backend-wide, single-tenant view -- the same one
    /// `status()` reported before per-user slots existed -- and deliberately
    /// does not aggregate across per-user slots, which each fail
    /// independently and are not surfaced individually here.
    pub fn status(&self) -> BackendStatus {
        let entry = self.shared_entry();
        let health = entry.failsafe.health_metrics();
        let (tools_cached, tools_known) = self.cached_tools_count_and_known();
        BackendStatus {
            name: self.name.clone(),
            running: self.is_running(),
            lifecycle: self.lifecycle(),
            transport: self.config.transport.transport_type().to_string(),
            tools_cached,
            tools_known,
            circuit_state: entry.failsafe.circuit_breaker.state(),
            request_count: self.request_count.load(Ordering::Relaxed),
            healthy: health.healthy,
            consecutive_failures: health.consecutive_failures,
            latency_p95_ms: health.latency_p95_ms,
            runtime: self.runtime_status(),
        }
    }

    fn runtime_status(&self) -> Option<BackendRuntimeStatus> {
        let plan = self.runtime_plan.as_ref()?;
        let state = if plan.is_denied() {
            BackendRuntimeState::Denied
        } else if plan.requires_confirmation() {
            BackendRuntimeState::ConfirmationRequired
        } else {
            BackendRuntimeState::Ready
        };

        Some(BackendRuntimeStatus {
            profile: self
                .config
                .runtime_profile
                .clone()
                .unwrap_or_else(|| plan.policy.id.clone()),
            provider: plan.provider,
            policy_id: plan.policy.id.clone(),
            license_tier: plan.audit.license_tier,
            state,
            denied_reasons: plan.denied.iter().map(|denial| denial.reason).collect(),
            confirmation_ids: plan
                .confirmations
                .iter()
                .map(|confirmation| confirmation.id.clone())
                .collect(),
            restart_max_attempts: plan.policy.restart.max_restarts,
            restart_backoff_secs: plan.policy.restart.backoff_secs,
            health_check: plan.lifecycle.health_check.clone(),
            restart_command_hint: plan.lifecycle.restart_command_hint.clone(),
            rollback_step: plan.rollback_step.clone(),
        })
    }

    /// The operator's state for this backend, with why and when it retries.
    ///
    /// Read from the canonical Shared slot only, the same scope as
    /// [`Self::status`]: a per-user slot's sign-in is one user's, not the
    /// server's.
    #[cfg(feature = "webui")]
    pub(crate) fn server_state(
        &self,
        now: std::time::SystemTime,
    ) -> super::server_state::StateView {
        #[cfg(all(test, feature = "webui"))]
        self.server_state_evaluations.fetch_add(1, Ordering::SeqCst);
        super::server_state::decide(&self.state_inputs(), now)
    }

    /// Why the runtime policy refuses every start of this backend, or `None`
    /// when it does not. The Overview uses it to list denied servers without
    /// `status()`, which also sorts latency samples it never shows.
    #[cfg(feature = "webui")]
    pub(crate) fn startup_denial(&self) -> Option<&[crate::runtime::RuntimeDenyReason]> {
        let plan = self.runtime_plan.as_ref()?;
        // The planner fills `audit.denied_reasons` from `denied`, in order.
        plan.is_denied()
            .then_some(plan.audit.denied_reasons.as_slice())
    }

    /// How many times [`Self::server_state`] ran on this backend.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) fn server_state_evaluations_for_test(&self) -> usize {
        self.server_state_evaluations
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether this backend loads only because its operator accepted sending
    /// its credentials in cleartext (`allow_cleartext_credentials`).
    pub(crate) fn cleartext_override_in_effect(&self) -> bool {
        crate::config::Config::cleartext_override_in_effect(&self.name, &self.config)
    }

    #[cfg(feature = "webui")]
    fn state_inputs(&self) -> super::server_state::StateInputs {
        let entry = self.shared_entry();
        let health = entry.failsafe.health_metrics();
        let breaker = entry.failsafe.circuit_breaker.stats();
        let plan = self.runtime_plan.as_ref();
        super::server_state::StateInputs {
            denied: plan.is_some_and(crate::runtime::RuntimePlan::is_denied),
            denial_reasons: plan
                .map(|p| p.denied.iter().map(|d| d.reason).collect())
                .unwrap_or_default(),
            auth_wait: entry.auth_wait.load(Ordering::Relaxed),
            breaker: breaker.state,
            retry_after: std::time::Duration::from_millis(breaker.retry_after_ms),
            healthy: health.healthy,
            consecutive_failures: health.consecutive_failures,
            running: self.is_running(),
            reaped: entry.stopped_when_idle.load(Ordering::SeqCst),
            ever_started: entry.ever_started.load(Ordering::Relaxed),
            start_failed: entry.start_failed.load(Ordering::Relaxed),
            slow: entry.failsafe.health_tracker.slow(),
        }
    }

    /// Get health metrics for this backend's canonical Shared slot (MIK-6735
    /// fix 1).
    pub fn health_metrics(&self) -> crate::failsafe::HealthMetrics {
        self.shared_entry().failsafe.health_metrics()
    }
}
