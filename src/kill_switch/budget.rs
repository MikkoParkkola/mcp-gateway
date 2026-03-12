//! Sliding-window error budget primitives and configuration types.
//!
//! Provides [`BudgetWindow`] (the core sliding-window tracker) together with the
//! two configuration structs that govern how backends and individual capabilities
//! are monitored: [`ErrorBudgetConfig`] and [`CapabilityErrorBudgetConfig`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ============================================================================
// Sliding-window error budget
// ============================================================================

/// Sliding-window call tracker for error-rate computation.
///
/// Maintains up to `max_calls` entries OR entries younger than `max_age`.
/// Old entries are evicted lazily on each `record` call.
#[derive(Debug)]
pub(crate) struct BudgetWindow {
    /// Ring buffer of `(timestamp, success)` pairs.
    entries: VecDeque<(Instant, bool)>,
    /// Maximum number of entries to retain.
    max_calls: usize,
    /// Maximum age of entries before they are evicted.
    max_age: Duration,
}

impl BudgetWindow {
    /// Create a new window.
    pub fn new(max_calls: usize, max_age: Duration) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_calls.min(4096)),
            max_calls,
            max_age,
        }
    }

    /// Record a call outcome and evict expired entries.
    pub fn record(&mut self, success: bool) {
        self.evict_old();
        self.entries.push_back((Instant::now(), success));
        // Enforce size cap
        if self.entries.len() > self.max_calls {
            self.entries.pop_front();
        }
    }

    /// Compute the error rate over all valid entries (0.0–1.0).
    pub fn error_rate(&mut self) -> f64 {
        self.evict_old();
        let total = self.entries.len();
        if total == 0 {
            return 0.0;
        }
        let failures = self.entries.iter().filter(|(_, ok)| !ok).count();
        #[allow(clippy::cast_precision_loss)]
        let rate = failures as f64 / total as f64;
        rate
    }

    /// Return `(successes, failures)` counts after eviction.
    pub fn counts(&mut self) -> (usize, usize) {
        self.evict_old();
        let failures = self.entries.iter().filter(|(_, ok)| !ok).count();
        let successes = self.entries.len() - failures;
        (successes, failures)
    }

    /// Clear all entries (used on revive).
    pub fn reset(&mut self) {
        self.entries.clear();
    }

    /// Remove entries older than `max_age`.
    fn evict_old(&mut self) {
        let now = Instant::now();
        while let Some((ts, _)) = self.entries.front() {
            if now.duration_since(*ts) > self.max_age {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

// ============================================================================
// Error budget configuration
// ============================================================================

/// Configuration for the per-backend error budget.
#[derive(Debug, Clone)]
pub struct ErrorBudgetConfig {
    /// Failure rate threshold that triggers auto-kill (0.0–1.0).
    ///
    /// Default: `0.8` (80% failure rate). A backend must sustain a very high
    /// error rate before being auto-killed, preventing single-capability
    /// failures on large backends (e.g. fulcrum's 234 tools) from killing the
    /// entire server.
    pub threshold: f64,
    /// Number of calls in the sliding window.
    ///
    /// Default: `100`.
    pub window_size: usize,
    /// Maximum age of calls in the sliding window.
    ///
    /// Default: 5 minutes.
    pub window_duration: Duration,
    /// Minimum number of calls in the window before the kill switch is
    /// evaluated.
    ///
    /// Default: `10`. Prevents a single early failure from triggering an
    /// auto-kill before enough samples have accumulated.
    pub min_samples: usize,
}

impl Default for ErrorBudgetConfig {
    fn default() -> Self {
        Self {
            threshold: 0.8,
            window_size: 100,
            window_duration: Duration::from_secs(5 * 60),
            min_samples: 10,
        }
    }
}

/// Configuration for the per-capability error budget.
///
/// Capabilities operate in the same backend but are tracked independently.
/// When a single capability exceeds its threshold only that capability is
/// disabled; the backend and its other capabilities remain healthy.
///
/// Auto-recovery: after `cooldown` has elapsed since the capability was
/// disabled, the next call to it automatically re-enables it and resets its
/// window — no operator action required.
#[derive(Debug, Clone)]
pub struct CapabilityErrorBudgetConfig {
    /// Failure rate threshold that triggers per-capability auto-disable (0.0–1.0).
    ///
    /// Default: `0.8` (80% failure rate). Matches the backend-level default.
    pub threshold: f64,
    /// Number of calls in the per-capability sliding window.
    ///
    /// Default: `50`. Smaller than the backend window to detect failing
    /// capabilities faster.
    pub window_size: usize,
    /// Maximum age of calls in the per-capability sliding window.
    ///
    /// Default: 5 minutes.
    pub window_duration: Duration,
    /// Minimum number of calls before the per-capability budget is evaluated.
    ///
    /// Default: `5`. Lower than the backend default since individual
    /// capabilities receive fewer calls.
    pub min_samples: usize,
    /// How long a disabled capability stays offline before auto-recovering.
    ///
    /// Default: 5 minutes. After this period the capability is transparently
    /// re-enabled on its next invocation so transient outages heal themselves.
    pub cooldown: Duration,
}

impl Default for CapabilityErrorBudgetConfig {
    fn default() -> Self {
        Self {
            threshold: 0.8,
            window_size: 50,
            window_duration: Duration::from_secs(5 * 60),
            min_samples: 5,
            cooldown: Duration::from_secs(5 * 60),
        }
    }
}
