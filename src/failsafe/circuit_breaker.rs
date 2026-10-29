// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Circuit breaker implementation

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::config::CircuitBreakerConfig;

/// Circuit breaker state
///
/// Serialises as its [`Self::as_str`] label, so a typed field and the label
/// can never disagree on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Circuit is closed (allowing requests)
    Closed,
    /// Circuit is open (blocking requests)
    Open,
    /// Circuit is half-open (allowing limited requests to test)
    HalfOpen,
}

impl CircuitState {
    /// Return the lowercase `snake_case` label used in API responses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

#[must_use]
pub(crate) fn next_state_after_failure(
    state: CircuitState,
    failures_after_event: u32,
    failure_threshold: u32,
) -> CircuitState {
    match state {
        CircuitState::Closed if failures_after_event >= failure_threshold => CircuitState::Open,
        CircuitState::Closed => CircuitState::Closed,
        CircuitState::HalfOpen | CircuitState::Open => CircuitState::Open,
    }
}

#[must_use]
pub(crate) fn next_state_after_success(
    state: CircuitState,
    successes_after_event: u32,
    success_threshold: u32,
) -> CircuitState {
    match state {
        CircuitState::HalfOpen if successes_after_event >= success_threshold => {
            CircuitState::Closed
        }
        CircuitState::HalfOpen => CircuitState::HalfOpen,
        CircuitState::Closed => CircuitState::Closed,
        CircuitState::Open => CircuitState::Open,
    }
}

/// Snapshot of circuit-breaker observability data, cheap to clone.
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    /// Current state
    pub state: CircuitState,
    /// Number of times the circuit has tripped (Closed→Open)
    pub trips_count: u64,
    /// Epoch-millisecond timestamp of the last trip, `None` when the trip
    /// could not be dated or the breaker never tripped (MIK-8202 P4b).
    pub last_trip_ms: Option<u64>,
    /// Milliseconds until a retry probe is allowed (0 when not open)
    pub retry_after_ms: u64,
    /// Current consecutive failure count
    pub current_failures: u32,
    /// Configured failure threshold
    pub failure_threshold: u32,
}

/// Structured record of the most recent Closed→Open (or HalfOpen→Open)
/// transition, so the *cause* of a trip is recoverable post-hoc without
/// parsing logs (MIK-6119 GATEWAY.FLAP.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakerOpenEvent {
    /// Backend (or client) name whose breaker tripped.
    pub backend: String,
    /// Failure reason that triggered the trip (the error string at the call site).
    pub reason: String,
    /// Latency (ms) of the request that triggered the trip.
    pub latency_ms: u64,
    /// Consecutive failure count at the moment of the trip.
    pub consecutive_fail_count: u32,
}

/// Circuit breaker for backend or client protection.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Backend name
    name: String,
    /// Configuration
    failure_threshold: u32,
    success_threshold: u32,
    reset_timeout: Duration,
    /// State
    state: RwLock<CircuitState>,
    /// Failure count
    failures: AtomicU32,
    /// Success count (in half-open)
    successes: AtomicU32,
    /// When the state last changed, on the monotonic clock: the open-state
    /// age is a duration, so a dark wall clock never wedges the breaker
    /// (MIK-8202 P4b). Tokio's `Instant`, so a paused test clock advances it.
    last_state_change: Mutex<tokio::time::Instant>,
    /// Number of times the circuit has transitioned Closed→Open
    trips_count: AtomicU64,
    /// Epoch-millisecond timestamp of the last Closed→Open transition, 0
    /// when never or undated; 0 is never read as a time (MIK-8202 P4b).
    last_trip_ms: AtomicU64,
    /// Structured record of the most recent Open transition (MIK-6119).
    last_open_event: RwLock<Option<BreakerOpenEvent>>,
    /// Told of every transition (the operational events source).
    observer: crate::observer::Observer<HealthChange>,
}

/// A breaker moved from one state to another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HealthChange {
    pub backend: String,
    pub from: CircuitState,
    pub to: CircuitState,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    #[must_use]
    pub fn new(name: &str, config: &CircuitBreakerConfig) -> Self {
        Self {
            name: name.to_string(),
            failure_threshold: config.failure_threshold,
            success_threshold: config.success_threshold,
            reset_timeout: config.reset_timeout,
            state: RwLock::new(CircuitState::Closed),
            failures: AtomicU32::new(0),
            successes: AtomicU32::new(0),
            last_state_change: Mutex::new(tokio::time::Instant::now()),
            trips_count: AtomicU64::new(0),
            last_trip_ms: AtomicU64::new(0),
            last_open_event: RwLock::new(None),
            observer: crate::observer::Observer::default(),
        }
    }

    /// Attach the observer told of every transition.
    pub(crate) fn observe(&self, observer: crate::observer::ObserverFn<HealthChange>) {
        self.observer.set(observer);
    }

    /// Check if requests can proceed.
    ///
    /// When the circuit is `Open`, checks whether the reset timeout has elapsed
    /// since the last state change on the monotonic clock. If the timeout has
    /// elapsed, the circuit moves to `HalfOpen` and returns `true`.
    #[tracing::instrument(skip(self), fields(backend = %self.name))]
    pub fn can_proceed(&self) -> bool {
        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                tracing::trace!("Circuit closed, allowing request");
                true
            }
            CircuitState::Open => {
                let elapsed = tokio::time::Instant::now()
                    .saturating_duration_since(*self.last_state_change.lock());

                if elapsed >= self.reset_timeout {
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
        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failures.store(0, Ordering::Relaxed);
                tracing::trace!("Success in closed state, reset failure count");
            }
            CircuitState::HalfOpen => {
                let successes = self.successes.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(
                    successes,
                    threshold = self.success_threshold,
                    "Success in half-open state"
                );
                let next_state = next_state_after_success(state, successes, self.success_threshold);
                if next_state != state {
                    self.transition_to(next_state);
                }
            }
            CircuitState::Open => {
                tracing::trace!("Success recorded in open state (ignored)");
            }
        }
    }

    /// Force the breaker back to `Closed` and clear all failure/success counters.
    ///
    /// This is the manual recovery lever behind the `gateway_revive_server`
    /// meta-tool (MIK-5983): the `CIRCUIT_OPEN` error message directs operators
    /// to that tool, so reviving a backend must also close a tripped breaker.
    /// Without this, the documented recovery path was a no-op for breaker trips
    /// (observed live 2026-06-11: a memory backend's breaker wedged open 6.5h).
    #[tracing::instrument(skip(self), fields(backend = %self.name))]
    pub fn reset(&self) {
        let state = *self.state.read();
        if state == CircuitState::Closed {
            // transition_to() early-returns on same-state transitions; still
            // clear the failure window so a half-accumulated count does not
            // survive the revive.
            self.failures.store(0, Ordering::Relaxed);
            self.successes.store(0, Ordering::Relaxed);
        } else {
            self.transition_to(CircuitState::Closed);
        }
    }

    /// Record a failed request.
    ///
    /// `reason` is the failure cause (error string) and `latency` the elapsed
    /// request time; both are captured into a structured [`BreakerOpenEvent`]
    /// on a Closed→Open (or HalfOpen→Open) transition so a flap is diagnosable
    /// post-hoc without log parsing (MIK-6119).
    #[tracing::instrument(skip(self), fields(backend = %self.name))]
    pub fn record_failure(&self, reason: &str, latency: Duration) {
        let state = *self.state.read();

        match state {
            CircuitState::Closed => {
                let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    failures,
                    threshold = self.failure_threshold,
                    "Failure in closed state"
                );
                let next_state = next_state_after_failure(state, failures, self.failure_threshold);
                if next_state != state {
                    self.capture_open_event(reason, latency, failures);
                    self.transition_to(next_state);
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open goes back to open
                tracing::warn!("Failure in half-open state, reopening circuit");
                let next_state = next_state_after_failure(state, 1, self.failure_threshold);
                if next_state != state {
                    let count = self.failures.load(Ordering::Relaxed).max(1);
                    self.capture_open_event(reason, latency, count);
                    self.transition_to(next_state);
                }
            }
            CircuitState::Open => {
                tracing::trace!("Failure recorded in open state (ignored)");
            }
        }
    }

    /// Capture + emit the single structured open-event for a trip: stores it
    /// for retrieval via [`Self::last_open_event`], logs one `warn` carrying
    /// all four fields, and increments `mcp_circuit_breaker_opened_total`
    /// labelled by `backend` and `reason` (MIK-6119 GATEWAY.FLAP.2).
    fn capture_open_event(&self, reason: &str, latency: Duration, consecutive_fail_count: u32) {
        let latency_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
        warn!(
            backend = %self.name,
            reason = %reason,
            latency_ms,
            consecutive_fail_count,
            "Circuit breaker opened"
        );
        telemetry_metrics::counter!(
            "mcp_circuit_breaker_opened_total",
            "backend" => self.name.clone(),
            "reason" => reason.to_string()
        )
        .increment(1);
        *self.last_open_event.write() = Some(BreakerOpenEvent {
            backend: self.name.clone(),
            reason: reason.to_string(),
            latency_ms,
            consecutive_fail_count,
        });
    }

    /// Most recent structured open-event, or `None` if the breaker has never
    /// tripped. Lets callers diagnose *why* a trip happened without log parsing.
    #[must_use]
    pub fn last_open_event(&self) -> Option<BreakerOpenEvent> {
        self.last_open_event.read().clone()
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Return a rich observability snapshot.
    ///
    /// The `retry_after_ms` field is non-zero only when the circuit is `Open`
    /// and is computed as `reset_timeout - elapsed_since_trip` on the
    /// monotonic clock. It is clamped to zero when the reset timeout has
    /// already elapsed.
    #[must_use]
    pub fn stats(&self) -> CircuitBreakerStats {
        let state = *self.state.read();
        let last_trip_ms = match self.last_trip_ms.load(Ordering::Relaxed) {
            0 => None,
            ms => Some(ms),
        };

        let retry_after_ms = if state == CircuitState::Open {
            let elapsed = tokio::time::Instant::now()
                .saturating_duration_since(*self.last_state_change.lock());
            #[allow(clippy::cast_possible_truncation)]
            let retry_after_ms = self.reset_timeout.saturating_sub(elapsed).as_millis() as u64;
            retry_after_ms
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
        *self.last_state_change.lock() = tokio::time::Instant::now();
        // A trip on a dark clock is undated (0 reads back as `None`); it is
        // never stamped 0 as a time (MIK-8202 P4b).
        let trip_ms = crate::clock::unix_millis().unwrap_or_default();

        match new_state {
            CircuitState::Closed => {
                self.failures.store(0, Ordering::Relaxed);
                self.successes.store(0, Ordering::Relaxed);
            }
            CircuitState::Open => {
                // Record the trip. The rich, structured "Circuit breaker opened"
                // event (backend + reason + latency_ms + consecutive_fail_count)
                // is emitted once by `capture_open_event` before this transition
                // (MIK-6119) — keep this arm to bookkeeping only to avoid a
                // duplicate log line.
                self.trips_count.fetch_add(1, Ordering::Relaxed);
                self.last_trip_ms.store(trip_ms, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                self.successes.store(0, Ordering::Relaxed);
            }
        }
        drop(state);
        // The observer first: a stalled log sink must not delay it.
        self.observer.call(HealthChange {
            backend: self.name.clone(),
            from: old_state,
            to: new_state,
        });
        // After the release too: status readers take the state lock, and a log
        // sink that stops reading must not hold them up.
        match new_state {
            CircuitState::Closed => info!(backend = %self.name, "Circuit breaker closed"),
            CircuitState::Open => debug!(backend = %self.name, "Circuit breaker state → Open"),
            CircuitState::HalfOpen => debug!(backend = %self.name, "Circuit breaker half-open"),
        }
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    fn any_circuit_state() -> CircuitState {
        match kani::any::<u8>() % 3 {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            _ => CircuitState::HalfOpen,
        }
    }

    #[kani::proof]
    fn circuit_failure_transition_contract() {
        let state = any_circuit_state();
        let failures_after_event: u32 = kani::any();
        let failure_threshold: u32 = kani::any();

        let next = next_state_after_failure(state, failures_after_event, failure_threshold);

        match state {
            CircuitState::Closed => {
                if failures_after_event >= failure_threshold {
                    assert_eq!(next, CircuitState::Open);
                } else {
                    assert_eq!(next, CircuitState::Closed);
                }
            }
            CircuitState::HalfOpen | CircuitState::Open => {
                assert_eq!(next, CircuitState::Open);
            }
        }
    }

    #[kani::proof]
    fn circuit_success_transition_contract() {
        let state = any_circuit_state();
        let successes_after_event: u32 = kani::any();
        let success_threshold: u32 = kani::any();

        let next = next_state_after_success(state, successes_after_event, success_threshold);

        match state {
            CircuitState::HalfOpen => {
                if successes_after_event >= success_threshold {
                    assert_eq!(next, CircuitState::Closed);
                } else {
                    assert_eq!(next, CircuitState::HalfOpen);
                }
            }
            CircuitState::Closed => assert_eq!(next, CircuitState::Closed),
            CircuitState::Open => assert_eq!(next, CircuitState::Open),
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
            // A trip the clock could not date, or a clock that went dark
            // since, renders "unknown": never a time measured from 0
            // (MIK-8202 P4b).
            let opened = stats
                .last_trip_ms
                .and_then(|trip| {
                    crate::clock::unix_millis()
                        .ok()
                        .map(|now| now.saturating_sub(trip))
                })
                .map_or_else(
                    || "an unknown time ago".to_owned(),
                    |ms| format!("~{ms}ms ago"),
                );
            format!(
                "Circuit breaker for '{server}' is {state_label} (tripped {trips} time(s)). \
                 Opened {opened}. \
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

#[cfg(test)]
#[path = "circuit_breaker_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "circuit_breaker_clock_tests.rs"]
mod clock_tests;

#[cfg(test)]
#[path = "circuit_breaker_clock_compile_red_tests.rs"]
mod clock_compile_red_tests;

#[cfg(test)]
#[path = "circuit_breaker_logging_tests.rs"]
mod logging_tests;
