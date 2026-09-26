// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failsafe mechanisms: circuit breaker, retry, rate limiting, health tracking

mod circuit_breaker;
mod health;
mod rate_limiter;
mod retry;

pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerStats, CircuitState, build_circuit_breaker_error,
};
pub use health::{HealthMetrics, HealthTracker};
pub use rate_limiter::RateLimiter;
pub use retry::{RetryPolicy, with_retry};

use std::sync::Arc;

use crate::config::FailsafeConfig;

/// Combined failsafe wrapper for backends
#[derive(Clone)]
pub struct Failsafe {
    /// Circuit breaker
    pub circuit_breaker: Arc<CircuitBreaker>,
    /// Rate limiter
    pub rate_limiter: Arc<RateLimiter>,
    /// Retry policy
    pub retry_policy: RetryPolicy,
    /// Health tracker
    pub health_tracker: Arc<HealthTracker>,
}

impl Failsafe {
    /// Create a new failsafe from configuration
    #[must_use]
    pub fn new(name: &str, config: &FailsafeConfig) -> Self {
        Self {
            circuit_breaker: Arc::new(CircuitBreaker::new(name, &config.circuit_breaker)),
            rate_limiter: Arc::new(RateLimiter::new(&config.rate_limit)),
            retry_policy: RetryPolicy::new(&config.retry),
            health_tracker: Arc::new(HealthTracker::new(name)),
        }
    }

    /// Admit a request, or say which guard refused it.
    ///
    /// The breaker is asked first, so an open circuit does not spend a
    /// rate-limit token. The two refusals are distinct errors on purpose: a
    /// rate-limit refusal is the gateway throttling a caller, not a backend
    /// failure, and reporting it as `CircuitOpen` let the error budgets count
    /// it as one, so one caller's burst disabled a capability for all (F23).
    ///
    /// # Errors
    ///
    /// `CircuitOpen` while the breaker refuses; `RateLimited` when the
    /// limiter has no token.
    ///
    /// Also sets `mcp_backend_circuit_state` from the breaker's decision alone,
    /// so the request and notification paths cannot drift and a rate-limit
    /// refusal never reports an open circuit, and counts each limiter refusal
    /// in `mcp_backend_rate_limited_total{backend}`.
    pub fn admit(&self, backend: &str) -> crate::Result<()> {
        let closed = self.circuit_breaker.can_proceed();
        telemetry_metrics::gauge!("mcp_backend_circuit_state", "backend" => backend.to_string())
            .set(if closed { 1.0_f64 } else { 0.0_f64 });
        if !closed {
            return Err(crate::Error::circuit_open(backend, &self.circuit_breaker));
        }
        if !self.rate_limiter.try_acquire() {
            // The operator's view of limiter refusals: they are excluded from
            // the error budgets and from the circuit gauge, so this counter is
            // the only place they show (F23b, MIK-7579).
            telemetry_metrics::counter!(
                "mcp_backend_rate_limited_total",
                "backend" => backend.to_string()
            )
            .increment(1);
            return Err(crate::Error::RateLimited(backend.to_string()));
        }
        Ok(())
    }

    /// Record a success with latency
    pub fn record_success(&self, latency: std::time::Duration) {
        self.circuit_breaker.record_success();
        self.health_tracker.record_success(latency);
    }

    /// Record a failure, threading the failure `reason` and request `latency`
    /// into the circuit breaker so a Closed→Open trip is diagnosable (MIK-6119).
    pub fn record_failure(&self, reason: &str, latency: std::time::Duration) {
        self.circuit_breaker.record_failure(reason, latency);
        self.health_tracker.record_failure();
    }

    /// Record a throttled response: reachable, but no evidence of health.
    ///
    /// The backend answered, so the health tracker counts it and a throttled
    /// backend cannot be made to look down. The circuit breaker sees nothing:
    /// a `429` neither breaks a failure streak nor closes a half-open circuit,
    /// because being told to slow down is not proof of recovery.
    pub fn record_rate_limited(&self, reason: &str, latency: std::time::Duration) {
        tracing::debug!(
            reason,
            latency_ms = latency.as_millis(),
            "Rate-limited response excluded from failure accounting"
        );
        self.health_tracker.record_success(latency);
    }

    /// Record a dispatch failure, excluding rate-limited responses from failure
    /// accounting (GH #475). A `429` proves the backend is reachable, so it
    /// records transport health as a success and no failure anywhere: a
    /// throttled backend is not an unhealthy one, and counting it as such trips
    /// the breaker on a backend that is working exactly as designed.
    ///
    /// Returns `true` when the failure was excluded, so the caller can label
    /// its telemetry with what actually happened.
    pub fn record_dispatch_failure(&self, reason: &str, latency: std::time::Duration) -> bool {
        if crate::gateway::recovery::is_rate_limited(reason) {
            self.record_rate_limited(reason, latency);
            return true;
        }
        self.record_failure(reason, latency);
        false
    }

    /// Get health metrics
    #[must_use]
    pub fn health_metrics(&self) -> HealthMetrics {
        self.health_tracker.metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CircuitBreakerConfig, FailsafeConfig};
    use std::time::Duration;

    /// GH475.RL.3 — a throttle must not break a failure streak. Two failures
    /// with a rate-limited response between them still trip the circuit.
    #[test]
    fn a_rate_limited_response_does_not_reset_the_failure_streak() {
        let config = FailsafeConfig {
            circuit_breaker: CircuitBreakerConfig {
                enabled: true,
                failure_threshold: 2,
                ..Default::default()
            },
            ..Default::default()
        };
        let failsafe = Failsafe::new("throttled-backend", &config);
        let latency = Duration::from_millis(1);

        failsafe.record_failure("boom", latency);
        failsafe.record_rate_limited("429 too many requests", latency);
        failsafe.record_failure("boom", latency);

        assert!(
            matches!(failsafe.admit("b"), Err(crate::Error::CircuitOpen { .. })),
            "the circuit must be open: a throttle is not evidence the backend recovered"
        );
    }

    /// F23 T4 — an exhausted limiter with a closed breaker refuses as
    /// `RateLimited`, and the refusal leaves the breaker closed.
    #[test]
    fn an_exhausted_limiter_refuses_rate_limited_and_leaves_the_breaker_closed() {
        let mut config = FailsafeConfig::default();
        config.rate_limit.enabled = true;
        config.rate_limit.requests_per_second = 1;
        config.rate_limit.burst_size = 1;
        let failsafe = Failsafe::new("limited-backend", &config);

        assert!(failsafe.admit("b").is_ok(), "the burst token admits");
        assert!(
            matches!(failsafe.admit("b"), Err(crate::Error::RateLimited(_))),
            "an empty bucket is a rate-limit refusal, not an open circuit"
        );
        assert_eq!(failsafe.circuit_breaker.state(), CircuitState::Closed);
    }
}
