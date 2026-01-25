//! Failsafe mechanisms: circuit breaker, retry, rate limiting

mod circuit_breaker;
mod rate_limiter;
mod retry;

pub use circuit_breaker::{CircuitBreaker, CircuitState};
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
}

impl Failsafe {
    /// Create a new failsafe from configuration
    #[must_use]
    pub fn new(name: &str, config: &FailsafeConfig) -> Self {
        Self {
            circuit_breaker: Arc::new(CircuitBreaker::new(name, &config.circuit_breaker)),
            rate_limiter: Arc::new(RateLimiter::new(&config.rate_limit)),
            retry_policy: RetryPolicy::new(&config.retry),
        }
    }

    /// Check if requests can proceed
    #[must_use]
    pub fn can_proceed(&self) -> bool {
        self.circuit_breaker.can_proceed() && self.rate_limiter.try_acquire()
    }

    /// Record a success
    pub fn record_success(&self) {
        self.circuit_breaker.record_success();
    }

    /// Record a failure
    pub fn record_failure(&self) {
        self.circuit_breaker.record_failure();
    }
}
