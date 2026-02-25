//! Production safety — kill switches and error budgets for backend servers.
//!
//! Provides two complementary mechanisms:
//!
//! - **Kill switch** (`KillSwitch`): operator-controlled, instant disable/re-enable of
//!   any backend by name. Changes take effect on the next `gateway_invoke` call.
//!
//! - **Error budget** (`ErrorBudget`): per-backend sliding-window error-rate tracker.
//!   When a backend exceeds its configured failure threshold it is automatically killed.
//!   The operator can revive it manually via `gateway_revive_server`.
//!
//! Both share the same underlying `DashSet` of killed server names so the state is
//! always consistent regardless of which mechanism triggered the kill.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::DashSet;
use tracing::{info, warn};

// ============================================================================
// Kill switch
// ============================================================================

/// Operator-controlled kill switch for backend servers.
///
/// Backed by a `DashSet` for lock-free concurrent reads. Writes (kill/revive)
/// are rare; reads happen on every `gateway_invoke` call.
#[derive(Debug, Default)]
pub struct KillSwitch {
    /// Set of server names that are currently disabled.
    killed: DashSet<String>,
    /// Per-backend error budgets (sliding window).
    budgets: DashMap<String, Arc<parking_lot::Mutex<BudgetWindow>>>,
}

impl KillSwitch {
    /// Create a new kill switch with no servers disabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            killed: DashSet::new(),
            budgets: DashMap::new(),
        }
    }

    // ── Operator control ──────────────────────────────────────────────────────

    /// Immediately disable routing to `server`.
    ///
    /// Idempotent — calling this on an already-killed server is a no-op.
    pub fn kill(&self, server: &str) {
        if self.killed.insert(server.to_string()) {
            warn!(server = server, "Kill switch engaged: server disabled");
        }
    }

    /// Re-enable routing to `server`.
    ///
    /// Idempotent — calling this on an already-live server is a no-op.
    /// Also resets the error-budget window so the backend gets a clean slate.
    pub fn revive(&self, server: &str) {
        if self.killed.remove(server).is_some() {
            info!(server = server, "Kill switch released: server re-enabled");
        }
        // Reset the budget window so the revived server starts fresh.
        if let Some(budget) = self.budgets.get(server) {
            budget.lock().reset();
        }
    }

    /// Returns `true` when `server` is currently disabled.
    #[must_use]
    #[inline]
    pub fn is_killed(&self, server: &str) -> bool {
        self.killed.contains(server)
    }

    /// Returns the set of currently-killed server names (snapshot).
    #[must_use]
    pub fn killed_servers(&self) -> Vec<String> {
        self.killed.iter().map(|s| s.clone()).collect()
    }

    // ── Error budget ──────────────────────────────────────────────────────────

    /// Record a successful call for `server`.
    ///
    /// Only updates the budget window; does not change kill state.
    pub fn record_success(&self, server: &str, window_size: usize, window_duration: Duration) {
        self.get_or_create_budget(server, window_size, window_duration)
            .lock()
            .record(true);
    }

    /// Record a failed call for `server`, auto-killing when the budget is exhausted.
    ///
    /// The kill switch is **not** evaluated until the window contains at least
    /// `min_samples` calls. This prevents a single early failure from killing a
    /// backend before enough data has been collected.
    ///
    /// Returns `true` when this failure triggered a new auto-kill.
    pub fn record_failure(
        &self,
        server: &str,
        window_size: usize,
        window_duration: Duration,
        threshold: f64,
        min_samples: usize,
    ) -> bool {
        let budget = self.get_or_create_budget(server, window_size, window_duration);
        let mut window = budget.lock();
        window.record(false);

        // Do not evaluate until we have enough data.
        let (successes, failures) = window.counts();
        let total = successes + failures;
        if total < min_samples {
            return false;
        }

        let rate = window.error_rate();
        let usage_fraction = rate / threshold;

        if (0.8..1.0).contains(&usage_fraction) {
            warn!(
                server = server,
                error_rate = rate,
                threshold = threshold,
                "Error budget at 80% — approaching auto-kill threshold"
            );
        }

        if rate >= threshold && !self.is_killed(server) {
            warn!(
                server = server,
                error_rate = rate,
                threshold = threshold,
                "Error budget exhausted — auto-killing server"
            );
            self.killed.insert(server.to_string());
            return true;
        }

        false
    }

    /// Retrieve the current error rate (0.0–1.0) for `server`.
    ///
    /// Returns `0.0` when no calls have been recorded yet.
    #[must_use]
    pub fn error_rate(&self, server: &str) -> f64 {
        self.budgets
            .get(server)
            .map_or(0.0, |b| b.lock().error_rate())
    }

    /// Retrieve the window call counts for `server` as `(successes, failures)`.
    #[must_use]
    pub fn window_counts(&self, server: &str) -> (usize, usize) {
        self.budgets
            .get(server)
            .map_or((0, 0), |b| b.lock().counts())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn get_or_create_budget(
        &self,
        server: &str,
        window_size: usize,
        window_duration: Duration,
    ) -> Arc<parking_lot::Mutex<BudgetWindow>> {
        self.budgets
            .entry(server.to_string())
            .or_insert_with(|| Arc::new(parking_lot::Mutex::new(BudgetWindow::new(window_size, window_duration))))
            .clone()
    }
}

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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── KillSwitch::kill / revive / is_killed ────────────────────────────────

    #[test]
    fn kill_server_marks_it_as_killed() {
        // GIVEN: a fresh kill switch
        let ks = KillSwitch::new();
        // WHEN: a server is killed
        ks.kill("backend-a");
        // THEN: it reports as killed
        assert!(ks.is_killed("backend-a"));
    }

    #[test]
    fn revive_server_unmarks_it() {
        // GIVEN: a killed server
        let ks = KillSwitch::new();
        ks.kill("backend-a");
        // WHEN: it is revived
        ks.revive("backend-a");
        // THEN: it is no longer killed
        assert!(!ks.is_killed("backend-a"));
    }

    #[test]
    fn kill_is_idempotent() {
        let ks = KillSwitch::new();
        ks.kill("srv");
        ks.kill("srv"); // second call must not panic
        assert!(ks.is_killed("srv"));
    }

    #[test]
    fn revive_is_idempotent() {
        let ks = KillSwitch::new();
        ks.revive("srv"); // reviving a live server must not panic
        assert!(!ks.is_killed("srv"));
    }

    #[test]
    fn unknown_server_is_not_killed() {
        let ks = KillSwitch::new();
        assert!(!ks.is_killed("nonexistent"));
    }

    #[test]
    fn killed_servers_returns_snapshot() {
        let ks = KillSwitch::new();
        ks.kill("a");
        ks.kill("b");
        let mut killed = ks.killed_servers();
        killed.sort();
        assert_eq!(killed, vec!["a", "b"]);
    }

    #[test]
    fn killed_servers_empty_when_none_killed() {
        let ks = KillSwitch::new();
        assert!(ks.killed_servers().is_empty());
    }

    // ── Error budget: auto-kill ──────────────────────────────────────────────

    /// Shared test helper: `min_samples = 1` lets tests exercise auto-kill
    /// without needing to accumulate a minimum window of calls first.
    const NO_MIN: usize = 1;

    #[test]
    fn auto_kill_triggers_at_threshold() {
        // GIVEN: window of 4 calls, threshold 0.5, min_samples=1
        let ks = KillSwitch::new();
        let (size, dur, thresh) = (4, Duration::from_secs(300), 0.5);
        // WHEN: 2 successes then 2 failures (50% error rate == threshold)
        ks.record_success("srv", size, dur);
        ks.record_success("srv", size, dur);
        let triggered1 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
        let triggered2 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
        // THEN: second failure tips rate to 50% → auto-kill; first does not
        assert!(!triggered1, "first failure should not yet trigger auto-kill");
        assert!(triggered2, "second failure should trigger auto-kill");
        assert!(ks.is_killed("srv"));
    }

    #[test]
    fn no_auto_kill_below_threshold() {
        // GIVEN: window of 10 calls, threshold 0.5, min_samples=1
        let ks = KillSwitch::new();
        let (size, dur, thresh) = (10, Duration::from_secs(300), 0.5);
        // WHEN: 6 successes + 4 failures (40% error rate < 50%)
        for _ in 0..6 {
            ks.record_success("srv", size, dur);
        }
        for _ in 0..4 {
            ks.record_failure("srv", size, dur, thresh, NO_MIN);
        }
        // THEN: server is NOT killed
        assert!(!ks.is_killed("srv"), "40% error rate should not trigger kill");
    }

    #[test]
    fn auto_kill_does_not_fire_twice() {
        // GIVEN: window of 2, threshold 0.5, min_samples=1
        let ks = KillSwitch::new();
        let (size, dur, thresh) = (2, Duration::from_secs(300), 0.5);
        // First failure: rate=100% >= 50% → auto-kills
        let triggered1 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
        assert!(triggered1, "first failure should trigger auto-kill (100% error rate)");
        assert!(ks.is_killed("srv"));
        // Second failure: server already killed, must NOT re-trigger
        let triggered2 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
        assert!(!triggered2, "already-killed server must not re-trigger");
        // Third failure: still must not re-trigger
        let triggered3 = ks.record_failure("srv", size, dur, thresh, NO_MIN);
        assert!(!triggered3, "already-killed server must not re-trigger on 3rd call");
    }

    #[test]
    fn revive_resets_error_budget() {
        // GIVEN: server auto-killed by budget (min_samples=1, threshold=0.5)
        let ks = KillSwitch::new();
        let thresh = 0.5;
        let (size, dur) = (4, Duration::from_secs(300));
        // Two failures → 100% error rate → auto-kill
        ks.record_failure("srv", size, dur, thresh, NO_MIN);
        ks.record_failure("srv", size, dur, thresh, NO_MIN);
        assert!(ks.is_killed("srv"), "should be auto-killed");
        // WHEN: revived
        ks.revive("srv");
        assert!(!ks.is_killed("srv"), "should be alive after revive");
        // THEN: 3 successes followed by 1 failure → 25% error rate < threshold
        ks.record_success("srv", size, dur);
        ks.record_success("srv", size, dur);
        ks.record_success("srv", size, dur);
        let triggered = ks.record_failure("srv", size, dur, thresh, NO_MIN);
        assert!(!triggered, "25% error rate after revive must not trigger auto-kill");
        assert!(!ks.is_killed("srv"), "server must remain alive");
    }

    // ── min_samples guard ────────────────────────────────────────────────────

    #[test]
    fn min_samples_prevents_kill_below_sample_count() {
        // GIVEN: 100% failure rate but only 9 calls (< min_samples=10)
        let ks = KillSwitch::new();
        let (size, dur, thresh, min) = (100, Duration::from_secs(300), 0.8, 10);
        for _ in 0..9 {
            let triggered = ks.record_failure("srv", size, dur, thresh, min);
            assert!(!triggered, "kill must not fire before min_samples reached");
        }
        // THEN: server is alive despite 100% error rate
        assert!(!ks.is_killed("srv"), "should not be killed before min_samples");
    }

    #[test]
    fn min_samples_allows_kill_once_sample_count_reached() {
        // GIVEN: 90% failure rate, min_samples=10
        let ks = KillSwitch::new();
        let (size, dur, thresh, min) = (100, Duration::from_secs(300), 0.8, 10);
        // 1 success + 9 failures → window has exactly 10 samples at 90% error rate
        ks.record_success("srv", size, dur);
        for i in 0..9usize {
            let triggered = ks.record_failure("srv", size, dur, thresh, min);
            if i < 8 {
                // Total samples still < 10 after first 8 failures (1 success + 8 failures = 9)
                assert!(!triggered, "kill must not fire before min_samples reached (iteration {i})");
            } else {
                // 10th sample: 9/10 = 90% >= 80% threshold → auto-kill
                assert!(triggered, "kill must fire at min_samples when threshold exceeded");
            }
        }
        assert!(ks.is_killed("srv"));
    }

    #[test]
    fn min_samples_one_is_equivalent_to_no_guard() {
        // GIVEN: min_samples=1 — a single failure at 100% rate must auto-kill immediately
        let ks = KillSwitch::new();
        let (size, dur, thresh) = (100, Duration::from_secs(300), 0.5);
        let triggered = ks.record_failure("srv", size, dur, thresh, 1);
        assert!(triggered, "single failure with min_samples=1 must trigger kill");
        assert!(ks.is_killed("srv"));
    }

    // ── Default threshold is 0.8, not 0.5 ───────────────────────────────────

    #[test]
    fn default_threshold_does_not_kill_at_50_percent() {
        // GIVEN: default threshold (0.8) with min_samples=10
        let cfg = ErrorBudgetConfig::default();
        let ks = KillSwitch::new();
        // Fill window with exactly 50% failures (5 out of 10)
        for _ in 0..5 {
            ks.record_success("srv", cfg.window_size, cfg.window_duration);
        }
        for _ in 0..5 {
            ks.record_failure("srv", cfg.window_size, cfg.window_duration, cfg.threshold, cfg.min_samples);
        }
        // 50% error rate is below 80% default threshold
        assert!(!ks.is_killed("srv"), "50% error rate must not trigger kill at default 0.8 threshold");
    }

    // ── Error budget: error_rate / window_counts ─────────────────────────────

    #[test]
    fn error_rate_zero_with_no_calls() {
        let ks = KillSwitch::new();
        assert!(ks.error_rate("unknown") < f64::EPSILON);
    }

    #[test]
    fn error_rate_computed_correctly() {
        let ks = KillSwitch::new();
        let (size, dur) = (10, Duration::from_secs(300));
        ks.record_success("srv", size, dur);
        ks.record_success("srv", size, dur);
        // threshold=1.0 ensures auto-kill can never trigger; min=1 is irrelevant here
        ks.record_failure("srv", size, dur, 1.0, 1);
        let rate = ks.error_rate("srv");
        assert!((rate - 1.0 / 3.0).abs() < 1e-10, "expected 33% error rate");
    }

    #[test]
    fn window_counts_returns_successes_and_failures() {
        let ks = KillSwitch::new();
        let (size, dur) = (100, Duration::from_secs(300));
        for _ in 0..3 {
            ks.record_success("srv", size, dur);
        }
        ks.record_failure("srv", size, dur, 1.0, 1);
        let (s, f) = ks.window_counts("srv");
        assert_eq!(s, 3);
        assert_eq!(f, 1);
    }

    // ── BudgetWindow ─────────────────────────────────────────────────────────

    #[test]
    fn budget_window_evicts_when_full() {
        // GIVEN: window of 3
        let mut w = BudgetWindow::new(3, Duration::from_secs(300));
        w.record(true);
        w.record(true);
        w.record(false);
        w.record(false); // this evicts the first entry (success)
        let (s, f) = w.counts();
        assert_eq!(s + f, 3, "window must not exceed max_calls");
    }

    #[test]
    fn budget_window_evicts_expired_entries() {
        // GIVEN: window with 1ms max_age
        let mut w = BudgetWindow::new(100, Duration::from_millis(1));
        w.record(false);
        // Wait for entry to expire
        std::thread::sleep(Duration::from_millis(5));
        w.record(true); // triggers eviction of the expired failure
        let (s, f) = w.counts();
        assert_eq!(f, 0, "expired failure must be evicted");
        assert_eq!(s, 1);
    }

    #[test]
    fn budget_window_reset_clears_all_entries() {
        let mut w = BudgetWindow::new(10, Duration::from_secs(60));
        w.record(false);
        w.record(false);
        w.reset();
        assert!(w.error_rate() < f64::EPSILON);
        let (s, f) = w.counts();
        assert_eq!(s, 0);
        assert_eq!(f, 0);
    }

    // ── ErrorBudgetConfig defaults ────────────────────────────────────────────

    #[test]
    fn error_budget_config_default_values() {
        let cfg = ErrorBudgetConfig::default();
        assert!((cfg.threshold - 0.8).abs() < 1e-10, "default threshold must be 0.8");
        assert_eq!(cfg.window_size, 100);
        assert_eq!(cfg.window_duration, Duration::from_secs(300));
        assert_eq!(cfg.min_samples, 10, "default min_samples must be 10");
    }
}
