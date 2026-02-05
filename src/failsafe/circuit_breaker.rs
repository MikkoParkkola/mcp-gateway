//! Circuit breaker implementation

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, info, warn};

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
        }
    }

    /// Check if requests can proceed
    #[tracing::instrument(skip(self), fields(backend = %self.name))]
    pub fn can_proceed(&self) -> bool {
        if !self.enabled {
            return true;
        }

        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                tracing::trace!("Circuit closed, allowing request");
                true
            }
            CircuitState::Open => {
                // Check if reset timeout has passed
                let last_change = self.last_state_change.load(Ordering::Relaxed);
                let now = Instant::now()
                    .duration_since(
                        Instant::now()
                            .checked_sub(Duration::from_millis(last_change))
                            .unwrap(),
                    )
                    .as_millis() as u64;

                if now >= self.reset_timeout.as_millis() as u64 {
                    tracing::debug!("Reset timeout elapsed, transitioning to half-open");
                    self.transition_to(CircuitState::HalfOpen);
                    true
                } else {
                    tracing::warn!("Circuit open, rejecting request");
                    false
                }
            }
            CircuitState::HalfOpen => {
                tracing::debug!("Circuit half-open, allowing probe request");
                true
            }
        }
    }

    /// Record a successful request
    #[tracing::instrument(skip(self), fields(backend = %self.name))]
    pub fn record_success(&self) {
        if !self.enabled {
            return;
        }

        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failures.store(0, Ordering::Relaxed);
                tracing::trace!("Success in closed state, reset failure count");
            }
            CircuitState::HalfOpen => {
                let successes = self.successes.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(successes, threshold = self.success_threshold, "Success in half-open state");
                if successes >= self.success_threshold {
                    self.transition_to(CircuitState::Closed);
                }
            }
            CircuitState::Open => {
                tracing::trace!("Success recorded in open state (ignored)");
            }
        }
    }

    /// Record a failed request
    #[tracing::instrument(skip(self), fields(backend = %self.name))]
    pub fn record_failure(&self) {
        if !self.enabled {
            return;
        }

        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(failures, threshold = self.failure_threshold, "Failure in closed state");
                if failures >= self.failure_threshold {
                    self.transition_to(CircuitState::Open);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                tracing::warn!("Failure in half-open state, reopening circuit");
                self.transition_to(CircuitState::Open);
            }
            CircuitState::Open => {
                tracing::trace!("Failure recorded in open state (ignored)");
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Transition to a new state
    fn transition_to(&self, new_state: CircuitState) {
        let mut state = self.state.write();
        let old_state = *state;

        if old_state == new_state {
            return;
        }

        *state = new_state;
        self.last_state_change.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            Ordering::Relaxed,
        );

        match new_state {
            CircuitState::Closed => {
                self.failures.store(0, Ordering::Relaxed);
                self.successes.store(0, Ordering::Relaxed);
                info!(backend = %self.name, "Circuit breaker closed");
            }
            CircuitState::Open => {
                warn!(
                    backend = %self.name,
                    failures = self.failures.load(Ordering::Relaxed),
                    "Circuit breaker opened"
                );
            }
            CircuitState::HalfOpen => {
                self.successes.store(0, Ordering::Relaxed);
                debug!(backend = %self.name, "Circuit breaker half-open");
            }
        }
    }
}
