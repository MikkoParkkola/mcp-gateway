//! Circuit breaker implementation

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tracing::{debug, info, warn, instrument};

use crate::config::CircuitBreakerConfig;

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed (allowing requests)
    Closed,
    /// Circuit is open (blocking requests)
    Open,
    /// Circuit is half-open (allowing limited requests to test)
    HalfOpen,
}

/// Circuit breaker for backend protection
pub struct CircuitBreaker {
    /// Backend name
    name: String,
    /// Configuration
    enabled: bool,
    failure_threshold: u32,
    success_threshold: u32,
    reset_timeout: Duration,
    /// State
    state: RwLock<CircuitState>,
    /// Failure count
    failures: AtomicU32,
    /// Success count (in half-open)
    successes: AtomicU32,
    /// Last state change timestamp (as millis since epoch)
    last_state_change: AtomicU64,
    /// Time when circuit opened (for error messages)
    opened_at: RwLock<Option<SystemTime>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    #[must_use]
    pub fn new(name: &str, config: &CircuitBreakerConfig) -> Self {
        Self {
            name: name.to_string(),
            enabled: config.enabled,
            failure_threshold: config.failure_threshold,
            success_threshold: config.success_threshold,
            reset_timeout: config.reset_timeout,
            state: RwLock::new(CircuitState::Closed),
            failures: AtomicU32::new(0),
            successes: AtomicU32::new(0),
            last_state_change: AtomicU64::new(0),
            opened_at: RwLock::new(None),
        }
    }

    /// Check if requests can proceed
    #[instrument(skip(self), fields(backend = %self.name))]
    pub fn can_proceed(&self) -> bool {
        if !self.enabled {
            return true;
        }

        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                debug!("Circuit closed, allowing request");
                true
            }
            CircuitState::Open => {
                // Check if reset timeout has passed
                let last_change_millis = self.last_state_change.load(Ordering::Relaxed);
                let now_millis = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let elapsed = now_millis.saturating_sub(last_change_millis);

                if elapsed >= self.reset_timeout.as_millis() as u64 {
                    info!(elapsed_ms = elapsed, "Reset timeout passed, transitioning to half-open");
                    self.transition_to(CircuitState::HalfOpen);
                    true
                } else {
                    let remaining = (self.reset_timeout.as_millis() as u64).saturating_sub(elapsed);
                    debug!(
                        elapsed_ms = elapsed,
                        remaining_ms = remaining,
                        "Circuit open, blocking request"
                    );
                    false
                }
            }
            CircuitState::HalfOpen => {
                debug!("Circuit half-open, allowing test request");
                true
            }
        }
    }

    /// Record a successful request
    #[instrument(skip(self), fields(backend = %self.name))]
    pub fn record_success(&self) {
        if !self.enabled {
            return;
        }

        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                let prev_failures = self.failures.swap(0, Ordering::Relaxed);
                if prev_failures > 0 {
                    debug!(
                        previous_failures = prev_failures,
                        "Success recorded, failures reset"
                    );
                }
            }
            CircuitState::HalfOpen => {
                let successes = self.successes.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(
                    successes,
                    threshold = self.success_threshold,
                    "Success in half-open state"
                );
                if successes >= self.success_threshold {
                    info!(
                        successes,
                        "Success threshold reached, closing circuit"
                    );
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {
                debug!("Success recorded but circuit is open");
            }
        }
    }

    /// Record a failed request
    #[instrument(skip(self), fields(backend = %self.name))]
    pub fn record_failure(&self) {
        if !self.enabled {
            return;
        }

        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(
                    failures,
                    threshold = self.failure_threshold,
                    "Failure recorded in closed state"
                );
                if failures >= self.failure_threshold {
                    warn!(
                        failures,
                        "Failure threshold reached, opening circuit"
                    );
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                warn!("Failure in half-open state, reopening circuit");
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {
                debug!("Failure recorded but circuit already open");
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Get detailed status for error messages
    pub fn status_message(&self) -> String {
        let state = self.state();
        let failures = self.failures.load(Ordering::Relaxed);

        match state {
            CircuitState::Closed => format!(
                "Circuit breaker for '{}' is closed ({} failures)",
                self.name, failures
            ),
            CircuitState::Open => {
                let opened_at = self.opened_at.read();
                if let Some(opened) = *opened_at {
                    let elapsed = SystemTime::now()
                        .duration_since(opened)
                        .unwrap_or_default();
                    format!(
                        "Backend '{}' circuit breaker is open ({} failures in last {} seconds, retry in {} seconds)",
                        self.name,
                        failures,
                        elapsed.as_secs(),
                        self.reset_timeout.as_secs().saturating_sub(elapsed.as_secs())
                    )
                } else {
                    format!(
                        "Backend '{}' circuit breaker is open ({} failures)",
                        self.name, failures
                    )
                }
            }
            CircuitState::HalfOpen => format!(
                "Circuit breaker for '{}' is half-open (testing recovery)",
                self.name
            ),
        }
    }

    /// Transition to a new state
    #[instrument(skip(self), fields(backend = %self.name))]
    fn transition_to(&self, new_state: CircuitState) {
        let mut state = self.state.write();
        let old_state = *state;

        if old_state == new_state {
            return;
        }

        *state = new_state;

        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.last_state_change.store(now_millis, Ordering::Relaxed);

        match new_state {
            CircuitState::Closed => {
                self.failures.store(0, Ordering::Relaxed);
                self.successes.store(0, Ordering::Relaxed);
                *self.opened_at.write() = None;
                info!(
                    from_state = ?old_state,
                    "Circuit breaker closed"
                );
            }
            CircuitState::Open => {
                let failures = self.failures.load(Ordering::Relaxed);
                let now = SystemTime::now();
                *self.opened_at.write() = Some(now);
                warn!(
                    from_state = ?old_state,
                    failures,
                    reset_timeout_secs = self.reset_timeout.as_secs(),
                    "Circuit breaker opened"
                );
            }
            CircuitState::HalfOpen => {
                self.successes.store(0, Ordering::Relaxed);
                debug!(
                    from_state = ?old_state,
                    "Circuit breaker half-open"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 3,
            success_threshold: 2,
            reset_timeout: Duration::from_millis(100),
        }
    }

    #[test]
    fn test_initial_state_is_closed() {
        let cb = CircuitBreaker::new("test", &test_config());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.can_proceed());
    }

    #[test]
    fn test_opens_after_failure_threshold() {
        let cb = CircuitBreaker::new("test", &test_config());

        // Record failures
        for _ in 0..2 {
            cb.record_failure();
            assert_eq!(cb.state(), CircuitState::Closed);
            assert!(cb.can_proceed());
        }

        // Third failure should open circuit
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_proceed());
    }

    #[test]
    fn test_resets_failures_on_success() {
        let cb = CircuitBreaker::new("test", &test_config());

        // Record some failures
        cb.record_failure();
        cb.record_failure();

        // Success resets counter
        cb.record_success();
        assert_eq!(cb.failures.load(Ordering::Relaxed), 0);

        // Should need 3 more failures to open
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_transitions_to_half_open_after_timeout() {
        let cb = CircuitBreaker::new("test", &test_config());

        // Open the circuit
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should transition to half-open
        assert!(cb.can_proceed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_closes_after_success_threshold_in_half_open() {
        let cb = CircuitBreaker::new("test", &test_config());

        // Manually set to half-open
        *cb.state.write() = CircuitState::HalfOpen;

        // First success
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Second success should close
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_reopens_on_failure_in_half_open() {
        let cb = CircuitBreaker::new("test", &test_config());

        // Manually set to half-open
        *cb.state.write() = CircuitState::HalfOpen;

        // Any failure reopens
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_disabled_circuit_breaker_always_allows() {
        let mut config = test_config();
        config.enabled = false;
        let cb = CircuitBreaker::new("test", &config);

        // Record many failures
        for _ in 0..10 {
            cb.record_failure();
        }

        // Should still allow requests
        assert!(cb.can_proceed());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_status_message_includes_timing() {
        let cb = CircuitBreaker::new("test", &test_config());

        // Open the circuit
        for _ in 0..3 {
            cb.record_failure();
        }

        let message = cb.status_message();
        assert!(message.contains("Backend 'test' circuit breaker is open"));
        assert!(message.contains("failures"));
    }
}
