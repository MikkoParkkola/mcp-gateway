//! Circuit breaker implementation

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

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

impl CircuitState {
    /// Return the lowercase kebab-case label used in API responses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// Snapshot of circuit-breaker observability data, cheap to clone.
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    /// Current state
    pub state: CircuitState,
    /// Number of times the circuit has tripped (Closed→Open)
    pub trips_count: u64,
    /// Epoch-millisecond timestamp of the last trip (0 = never)
    pub last_trip_ms: u64,
    /// Milliseconds until a retry probe is allowed (0 when not open)
    pub retry_after_ms: u64,
    /// Current consecutive failure count
    pub current_failures: u32,
    /// Configured failure threshold
    pub failure_threshold: u32,
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
    /// Number of times the circuit has transitioned Closed→Open
    trips_count: AtomicU64,
    /// Epoch-millisecond timestamp of the last Closed→Open transition (0 = never)
    last_trip_ms: AtomicU64,
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
            trips_count: AtomicU64::new(0),
            last_trip_ms: AtomicU64::new(0),
        }
    }

    /// Check if requests can proceed.
    ///
    /// When the circuit is `Open`, checks whether the reset timeout has elapsed
    /// since the last state change using wall-clock epoch milliseconds (the same
    /// unit used by [`transition_to`]).  If the timeout has elapsed, the circuit
    /// moves to `HalfOpen` and returns `true`.
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
                // Compare elapsed epoch-ms against the reset timeout.
                let last_change_ms = self.last_state_change.load(Ordering::Relaxed);
                let now_ms = epoch_millis_now();
                let elapsed_ms = now_ms.saturating_sub(last_change_ms);
                #[allow(clippy::cast_possible_truncation)]
                let timeout_ms = self.reset_timeout.as_millis() as u64;

                if elapsed_ms >= timeout_ms {
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

    /// Return a rich observability snapshot without holding any lock.
    ///
    /// The `retry_after_ms` field is non-zero only when the circuit is `Open`
    /// and is computed as `reset_timeout - elapsed_since_trip`.  It is clamped
    /// to zero when the reset timeout has already elapsed.
    #[must_use]
    pub fn stats(&self) -> CircuitBreakerStats {
        let state = *self.state.read();
        let last_trip_ms = self.last_trip_ms.load(Ordering::Relaxed);

        let retry_after_ms = if state == CircuitState::Open && last_trip_ms > 0 {
            let now_ms = epoch_millis_now();
            let elapsed_ms = now_ms.saturating_sub(last_trip_ms);
            #[allow(clippy::cast_possible_truncation)]
            let reset_ms = self.reset_timeout.as_millis() as u64;
            reset_ms.saturating_sub(elapsed_ms)
        } else {
            0
        };

        CircuitBreakerStats {
            state,
            trips_count: self.trips_count.load(Ordering::Relaxed),
            last_trip_ms,
            retry_after_ms,
            current_failures: self.failures.load(Ordering::Relaxed),
            failure_threshold: self.failure_threshold,
        }
    }

    /// Transition to a new state
    fn transition_to(&self, new_state: CircuitState) {
        let mut state = self.state.write();
        let old_state = *state;

        if old_state == new_state {
            return;
        }

        *state = new_state;
        let epoch_ms = epoch_millis_now();
        self.last_state_change.store(epoch_ms, Ordering::Relaxed);

        match new_state {
            CircuitState::Closed => {
                self.failures.store(0, Ordering::Relaxed);
                self.successes.store(0, Ordering::Relaxed);
                info!(backend = %self.name, "Circuit breaker closed");
            }
            CircuitState::Open => {
                // Record the trip
                self.trips_count.fetch_add(1, Ordering::Relaxed);
                self.last_trip_ms.store(epoch_ms, Ordering::Relaxed);
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

/// Build a human-readable error message when a request is blocked by an open circuit breaker.
///
/// Included fields: current state, how long ago the circuit tripped, and how long
/// until a retry probe will be allowed.
///
/// # Example
///
/// ```text
/// Circuit breaker for 'my-backend' is open (tripped 1 time(s)).
/// Opened ~500ms ago. Retry probe allowed in ~29500ms.
/// ```
#[must_use]
pub fn build_circuit_breaker_error(server: &str, stats: &CircuitBreakerStats) -> String {
    let state_label = stats.state.as_str();
    let trips = stats.trips_count;

    match stats.state {
        CircuitState::Open => {
            let opened_ago_ms = if stats.last_trip_ms > 0 {
                epoch_millis_now().saturating_sub(stats.last_trip_ms)
            } else {
                0
            };
            format!(
                "Circuit breaker for '{server}' is {state_label} (tripped {trips} time(s)). \
                 Opened ~{opened_ago_ms}ms ago. \
                 Retry probe allowed in ~{retry_after_ms}ms.",
                retry_after_ms = stats.retry_after_ms,
            )
        }
        _ => format!(
            "Circuit breaker for '{server}' is {state_label}. \
             Request rejected by failsafe mechanisms.",
        ),
    }
}

/// Current time as milliseconds since UNIX epoch.
///
/// Truncation to `u64` is safe: epoch-ms fits comfortably for centuries.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn epoch_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(enabled: bool, failure_threshold: u32) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled,
            failure_threshold,
            success_threshold: 2,
            reset_timeout: Duration::from_secs(30),
        }
    }

    // ── CircuitState::as_str ──────────────────────────────────────────────

    #[test]
    fn circuit_state_as_str_returns_lowercase_kebab() {
        assert_eq!(CircuitState::Closed.as_str(), "closed");
        assert_eq!(CircuitState::Open.as_str(), "open");
        assert_eq!(CircuitState::HalfOpen.as_str(), "half_open");
    }

    // ── stats snapshot ────────────────────────────────────────────────────

    #[test]
    fn stats_initial_state_is_closed_with_zero_trips() {
        let cb = CircuitBreaker::new("test", &make_config(true, 3));
        let s = cb.stats();
        assert_eq!(s.state, CircuitState::Closed);
        assert_eq!(s.trips_count, 0);
        assert_eq!(s.last_trip_ms, 0);
        assert_eq!(s.retry_after_ms, 0);
        assert_eq!(s.current_failures, 0);
        assert_eq!(s.failure_threshold, 3);
    }

    #[test]
    fn stats_trips_count_increments_on_each_open() {
        // Use zero reset_timeout so the circuit transitions to HalfOpen immediately
        // on the next can_proceed() call, allowing us to test the full trip cycle.
        let cfg = CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            success_threshold: 1,
            reset_timeout: Duration::ZERO,
        };
        let cb = CircuitBreaker::new("test", &cfg);

        // GIVEN: a fresh circuit breaker
        assert_eq!(cb.stats().trips_count, 0);

        // WHEN: a failure triggers the first trip
        cb.record_failure();

        // THEN: trips_count == 1 and last_trip_ms is set
        assert_eq!(cb.stats().trips_count, 1);
        assert_ne!(cb.stats().last_trip_ms, 0);

        // Recover: zero timeout means can_proceed() immediately transitions to HalfOpen
        assert!(cb.can_proceed(), "zero timeout should allow HalfOpen probe");
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // One success closes the circuit (success_threshold = 1)
        cb.record_success();
        assert_eq!(cb.stats().state, CircuitState::Closed);

        // WHEN: another failure trips the circuit again
        cb.record_failure();

        // THEN: trips_count == 2
        assert_eq!(cb.stats().trips_count, 2);
    }

    #[test]
    fn stats_retry_after_ms_is_nonzero_when_open() {
        let cfg = CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            success_threshold: 1,
            reset_timeout: Duration::from_secs(60),
        };
        let cb = CircuitBreaker::new("test", &cfg);
        cb.record_failure();
        let s = cb.stats();
        assert_eq!(s.state, CircuitState::Open);
        assert!(s.retry_after_ms > 0, "retry_after_ms should be >0 when open");
        assert!(s.retry_after_ms <= 60_000, "retry_after_ms must not exceed reset_timeout");
    }

    #[test]
    fn stats_retry_after_ms_is_zero_when_closed() {
        let cb = CircuitBreaker::new("test", &make_config(true, 3));
        assert_eq!(cb.stats().retry_after_ms, 0);
    }

    // ── existing behaviour preserved ──────────────────────────────────────

    #[test]
    fn circuit_starts_closed_and_allows_requests() {
        let cb = CircuitBreaker::new("test", &make_config(true, 3));
        assert!(cb.can_proceed());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_opens_after_failure_threshold_reached() {
        let cb = CircuitBreaker::new("test", &make_config(true, 3));
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_proceed());
    }

    #[test]
    fn disabled_circuit_always_allows_requests() {
        let cb = CircuitBreaker::new("test", &make_config(false, 1));
        cb.record_failure();
        assert!(cb.can_proceed());
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    // ── build_circuit_breaker_error ───────────────────────────────────────

    #[test]
    fn circuit_breaker_error_open_state_includes_trips_and_retry() {
        // GIVEN: an open circuit breaker stats snapshot
        let stats = CircuitBreakerStats {
            state: CircuitState::Open,
            trips_count: 2,
            last_trip_ms: epoch_millis_now().saturating_sub(500),
            retry_after_ms: 29_500,
            current_failures: 3,
            failure_threshold: 3,
        };
        // WHEN: building the error message
        let msg = build_circuit_breaker_error("my-backend", &stats);
        // THEN: it mentions open state, trip count, and retry info
        assert!(msg.contains("my-backend"), "must include server name");
        assert!(msg.contains("open"), "must include state");
        assert!(msg.contains("2 time(s)"), "must include trip count");
        assert!(msg.contains("Retry probe"), "must mention retry info");
    }

    #[test]
    fn circuit_breaker_error_half_open_state_is_generic() {
        // GIVEN: a half-open circuit breaker stats snapshot
        let stats = CircuitBreakerStats {
            state: CircuitState::HalfOpen,
            trips_count: 1,
            last_trip_ms: epoch_millis_now(),
            retry_after_ms: 0,
            current_failures: 0,
            failure_threshold: 3,
        };
        // WHEN: building the error message
        let msg = build_circuit_breaker_error("my-backend", &stats);
        // THEN: it mentions the state but no retry probe timing
        assert!(msg.contains("my-backend"));
        assert!(msg.contains("half_open"));
        assert!(!msg.contains("Retry probe"), "half_open does not need retry timing");
    }

    #[test]
    fn circuit_breaker_error_closed_state_is_generic() {
        // GIVEN: a closed circuit breaker (unusual to error, but handled)
        let stats = CircuitBreakerStats {
            state: CircuitState::Closed,
            trips_count: 0,
            last_trip_ms: 0,
            retry_after_ms: 0,
            current_failures: 0,
            failure_threshold: 3,
        };
        // WHEN: building the error message
        let msg = build_circuit_breaker_error("my-backend", &stats);
        // THEN: it mentions closed state
        assert!(msg.contains("my-backend"));
        assert!(msg.contains("closed"));
    }
}
