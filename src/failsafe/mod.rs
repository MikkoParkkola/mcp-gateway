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

    /// Check if requests can proceed
    #[must_use]
    pub fn can_proceed(&self) -> bool {
        self.circuit_breaker.can_proceed() && self.rate_limiter.try_acquire()
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
            tracing::debug!(
                reason,
                latency_ms = latency.as_millis(),
                "Rate-limited response excluded from failure accounting"
            );
            self.health_tracker.record_success(latency);
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
