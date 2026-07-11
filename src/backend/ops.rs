// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request/notify dispatch through the per-identity pool, plus status,
//! circuit-breaker, and health-metric accessors on [`super::Backend`].

use std::sync::atomic::Ordering;

use serde_json::Value;

use super::Backend;
use super::registry::{BackendRuntimeState, BackendRuntimeStatus, BackendStatus};
use crate::config::TransportConfig;
use crate::failsafe::with_retry;
use crate::protocol::JsonRpcResponse;
use crate::{Error, Result};

impl Backend {
    /// Internal request without `ensure_started` (to avoid recursion)
    pub(super) async fn request_internal(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<JsonRpcResponse> {
        let transport = self
            .shared_transport()
            .ok_or_else(|| Error::BackendUnavailable(self.name.clone()))?;

        transport.request(method, params).await
    }

    /// Send a request to the backend
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the request itself fails after retries.
    #[tracing::instrument(
        skip(self, params),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        self.request_with_headers(method, params, &[], None).await
    }

    /// This backend's end-user identity-propagation config, if configured
    /// (MIK-6704 / ADR-007). `None` -> static-credential behavior unchanged.
    #[must_use]
    pub fn identity_propagation_config(
        &self,
    ) -> Option<&crate::identity_propagation::IdentityPropagationConfig> {
        self.config.identity_propagation.as_ref()
    }

    /// Whether this backend's configured transport can carry per-request
    /// outbound headers, e.g. a propagated end-user identity credential
    /// (MIK-6710).
    ///
    /// Delegates to [`TransportConfig::carries_identity_headers`], which is
    /// evaluated from config alone -- valid before [`Backend::start`] has ever
    /// run. The identity-propagation dispatch gate
    /// (`MetaMcp::resolve_caller_credential`, the direct backend route's
    /// passthrough branch) checks this BEFORE minting or forwarding a
    /// credential, so a `required` backend bound to a transport that would
    /// silently drop `extra_headers` (stdio, websocket) is refused instead of
    /// running unauthenticated.
    #[must_use]
    pub fn transport_carries_identity_headers(&self) -> bool {
        self.config.transport.carries_identity_headers()
    }

    /// Whether this backend relies on a single gateway-held OAuth token that is
    /// NOT blessed for shared use (ADR-008 INV-2).
    ///
    /// `true` means the gateway stores one token for this backend and would
    /// attach it to any caller's request -- unsafe on a multi-user gateway
    /// unless a per-user credential is supplied instead. The dispatch guard
    /// uses this to fail closed. `oauth.shared_account = true` opts out (the
    /// operator has declared the account genuinely shared).
    #[must_use]
    pub fn oauth_requires_per_user_isolation(&self) -> bool {
        self.config
            .oauth
            .as_ref()
            .is_some_and(|o| o.enabled && !o.shared_account)
    }

    /// Send a request, adding per-request outbound headers (e.g. a propagated
    /// end-user identity credential -- MIK-6704). The headers are forwarded by
    /// value to the transport's `request_with_headers`, never stored on the
    /// backend, so concurrent per-user requests stay isolated (IDP.3).
    ///
    /// `identity_key` is the caller's stable identity binding (MIK-6784); the
    /// transport uses it to partition upstream `MCP-Session-Id` state so one
    /// user's session is never reused for another. `None` selects the shared
    /// default bucket (single-tenant behavior unchanged).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the request itself fails after retries.
    pub async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        let start_time = std::time::Instant::now();

        // Derive the per-identity pool slot FIRST (MIK-6735 fix 1, adversarial
        // review of commit bfd62b91). Each slot owns its own circuit breaker +
        // rate limiter + health tracker, so which slot's failsafe to gate on
        // must be known before the `can_proceed()` check runs -- gating on a
        // single backend-wide `Failsafe` let one caller identity's outage trip
        // the breaker for every other identity sharing the backend, the exact
        // cross-tenant blast radius this pool exists to eliminate. A non-per-
        // user backend, or a per-user backend request without a resolved
        // identity, collapses to the shared canonical slot (IDP.5); a per-user
        // request gets its own transport/session/failsafe so users never
        // collide (IDP.7).
        let key = self.pool_key_for(identity_key);
        let entry = self.pooled_entry(&key);

        // Check THIS slot's failsafe, not the backend's.
        if !entry.failsafe.can_proceed() {
            telemetry_metrics::gauge!(
                "mcp_backend_circuit_state",
                "backend" => self.name.clone()
            )
            .set(0.0_f64);
            tracing::warn!(backend = %self.name, ?key, "Request rejected by circuit breaker");
            return Err(Error::CircuitOpen(self.name.clone()));
        }
        telemetry_metrics::gauge!(
            "mcp_backend_circuit_state",
            "backend" => self.name.clone()
        )
        .set(1.0_f64);

        // Acquire semaphore
        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        // Ensure this slot's transport is live.
        let transport = self.ensure_entry_started(&key).await?;

        // Execute with retry
        let name = self.name.clone();
        // Own the identity key so the retry closure (Fn, invoked once per
        // attempt) can hand a borrow to each attempt's future without tying the
        // closure to the caller's borrow lifetime (MIK-6784).
        let identity_key = identity_key.map(str::to_string);
        let result = with_retry(&entry.failsafe.retry_policy, &name, || {
            let transport = std::sync::Arc::clone(&transport);
            let method = method.to_string();
            let params = params.clone();
            let extra_headers = extra_headers.to_vec();
            let identity_key = identity_key.clone();
            async move {
                transport
                    .request_with_headers(&method, params, &extra_headers, identity_key.as_deref())
                    .await
            }
        })
        .await;

        // Calculate latency
        let latency = start_time.elapsed();

        // Record success/failure against the SAME slot's failsafe used for the
        // `can_proceed()` gate above, so gating and recording are always
        // symmetric even if a concurrent idle-eviction later replaces this
        // slot's `PooledEntry` for `key` (MIK-6735 fix 1).
        match &result {
            Ok(_) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Request completed successfully"
                );
                entry.failsafe.record_success(latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "ok"
                )
                .increment(1);
            }
            Err(e) => {
                tracing::error!(error = %e, latency_ms = latency.as_millis(), "Request failed");
                entry.failsafe.record_failure(&e.to_string(), latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "error"
                )
                .increment(1);
            }
        }
        telemetry_metrics::histogram!(
            "mcp_backend_request_duration_seconds",
            "backend" => self.name.clone()
        )
        .record(latency.as_secs_f64());

        result
    }

    /// Send a notification to the backend via the canonical shared slot's
    /// session (non-per-user backends; single-tenant behavior unchanged).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the notification cannot be sent.
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        self.notify_with_headers(method, params, None).await
    }

    /// Send a notification carrying the caller's identity key so it is routed
    /// through the SAME pool slot -- and the SAME upstream `MCP-Session-Id`
    /// bucket -- that a prior `request_with_headers` call for that identity
    /// used (MIK-6735 fix 2, adversarial review of commit bfd62b91).
    ///
    /// Before this fix, every notification hardcoded `ensure_started()` (the
    /// canonical Shared slot) regardless of the caller's identity, so on a
    /// `PerUser` backend a notification correlating a request that went
    /// through a per-user slot (e.g. `notifications/cancelled`) went out on
    /// the wrong upstream session -- or, even once routed to the right
    /// transport instance, with no session ID at all, since
    /// [`crate::transport::Transport::notify`] never threaded an identity key
    /// through to the transport's session-bucket lookup either. Both layers
    /// are fixed together here: `identity_key` selects the same `PoolKey` as
    /// `request_with_headers` (IDP.7), and is forwarded to
    /// [`crate::transport::Transport::notify_with_headers`] so an HTTP
    /// transport selects the matching `MCP-Session-Id` bucket. `None`
    /// preserves the unchanged Shared-slot path (IDP.5).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend is unavailable, the concurrency limit
    /// is reached, or the notification cannot be sent.
    #[tracing::instrument(
        skip(self, params),
        fields(
            backend = %self.name,
            method = %method,
            request_id = %uuid::Uuid::new_v4()
        )
    )]
    pub async fn notify_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        identity_key: Option<&str>,
    ) -> Result<()> {
        let start_time = std::time::Instant::now();

        // Derive the same slot `request_with_headers` would use for this
        // identity, and gate/record against ITS failsafe (mirrors fix 1).
        let key = self.pool_key_for(identity_key);
        let entry = self.pooled_entry(&key);

        if !entry.failsafe.can_proceed() {
            telemetry_metrics::gauge!(
                "mcp_backend_circuit_state",
                "backend" => self.name.clone()
            )
            .set(0.0_f64);
            tracing::warn!(backend = %self.name, ?key, "Notification rejected by circuit breaker");
            return Err(Error::CircuitOpen(self.name.clone()));
        }
        telemetry_metrics::gauge!(
            "mcp_backend_circuit_state",
            "backend" => self.name.clone()
        )
        .set(1.0_f64);

        let _permit = self.semaphore.acquire().await.map_err(|_| {
            tracing::warn!("Concurrency limit reached");
            Error::BackendUnavailable("Concurrency limit reached".to_string())
        })?;

        self.request_count.fetch_add(1, Ordering::Relaxed);

        let transport = self.ensure_entry_started(&key).await?;

        let result = transport
            .notify_with_headers(method, params, identity_key)
            .await;
        let latency = start_time.elapsed();

        match &result {
            Ok(()) => {
                tracing::info!(
                    latency_ms = latency.as_millis(),
                    "Notification sent successfully"
                );
                entry.failsafe.record_success(latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "ok"
                )
                .increment(1);
            }
            Err(e) => {
                tracing::error!(error = %e, latency_ms = latency.as_millis(), "Notification failed");
                entry.failsafe.record_failure(&e.to_string(), latency);
                telemetry_metrics::counter!(
                    "mcp_backend_requests_total",
                    "backend" => self.name.clone(),
                    "status" => "error"
                )
                .increment(1);
            }
        }
        telemetry_metrics::histogram!(
            "mcp_backend_request_duration_seconds",
            "backend" => self.name.clone()
        )
        .record(latency.as_secs_f64());

        result
    }

    /// Return `true` if this backend is configured for pass-through mode.
    ///
    /// When `true`, the direct `/mcp/{name}` endpoint skips tool policy
    /// enforcement and input sanitization for `tools/call` requests.
    /// This must only be enabled for fully-trusted internal backends.
    #[must_use]
    pub fn passthrough(&self) -> bool {
        self.config.passthrough
    }

    /// Return the HTTP URL if this backend uses an HTTP-based transport.
    ///
    /// Returns `None` for stdio backends.
    #[must_use]
    pub fn transport_url(&self) -> Option<&str> {
        match &self.config.transport {
            TransportConfig::Http { http_url, .. } => Some(http_url.as_str()),
            TransportConfig::Stdio { .. } => None,
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => Some(a2a_url.as_str()),
        }
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
        BackendStatus {
            name: self.name.clone(),
            running: self.is_running(),
            transport: self.config.transport.transport_type().to_string(),
            tools_cached: self.cached_tools_count(),
            circuit_state: entry.failsafe.circuit_breaker.state().as_str().to_string(),
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

    /// Get circuit breaker stats for this backend's canonical Shared slot
    /// (MIK-6735 fix 1).
    pub fn circuit_breaker_stats(&self) -> crate::failsafe::CircuitBreakerStats {
        self.shared_entry().failsafe.circuit_breaker.stats()
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

    /// Get health metrics for this backend's canonical Shared slot (MIK-6735
    /// fix 1).
    pub fn health_metrics(&self) -> crate::failsafe::HealthMetrics {
        self.shared_entry().failsafe.health_metrics()
    }
}
