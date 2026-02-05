//! Failsafe mechanisms: circuit breaker, retry, rate limiting, health tracking

mod circuit_breaker;
mod health;
mod rate_limiter;
mod retry;

pub use circuit_breaker::{CircuitBreaker, CircuitState};
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

    /// Record a failure
    pub fn record_failure(&self) {
        self.circuit_breaker.record_failure();
        self.health_tracker.record_failure();
    }

    /// Get health metrics
    #[must_use]
    pub fn health_metrics(&self) -> HealthMetrics {
        self.health_tracker.metrics()
    }
}
