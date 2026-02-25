//! Production safety — kill switches and error budgets for backend servers.
//!
//! Provides three complementary mechanisms:
//!
//! - **Kill switch** (`KillSwitch`): operator-controlled, instant disable/re-enable of
//!   any backend by name. Changes take effect on the next `gateway_invoke` call.
//!
//! - **Backend error budget** (`ErrorBudget`): per-backend sliding-window error-rate
//!   tracker. When a backend exceeds its configured failure threshold it is automatically
//!   killed. The operator can revive it manually via `gateway_revive_server`.
//!
//! - **Per-capability error budget**: per-capability sliding-window error-rate tracker.
//!   When a single capability exceeds its threshold, only that capability is disabled —
//!   the rest of the backend remains healthy. Disabled capabilities auto-recover after
//!   a configurable cooldown period (default 5 min). The backend-level kill switch
//!   is a secondary safeguard that fires when cumulative errors exceed its threshold.
//!
//! Both the backend kill set and the disabled-capability map are backed by lock-free
//! `DashMap`/`DashSet` structures so the read hot-path (every `gateway_invoke`) is
//! contention-free.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::DashSet;
use tracing::{info, warn};

// ============================================================================
// Kill switch
// ============================================================================

/// Operator-controlled kill switch for backend servers with per-capability
/// error budgets.
///
/// Backed by lock-free `DashSet`/`DashMap` structures for contention-free
/// reads on every `gateway_invoke` call. Writes (kill/revive) are rare.
#[derive(Debug, Default)]
pub struct KillSwitch {
    /// Set of backend server names that are currently disabled.
    killed: DashSet<String>,
    /// Per-backend error budgets (sliding window).
    budgets: DashMap<String, Arc<parking_lot::Mutex<BudgetWindow>>>,
    /// Per-capability error budgets.
    ///
    /// Key: `"{backend}:{capability}"`. Each entry tracks the sliding-window
    /// error rate for a single capability independently of its backend.
    capability_budgets: DashMap<String, Arc<parking_lot::Mutex<BudgetWindow>>>,
    /// Disabled capabilities with the `Instant` at which they were disabled.
    ///
    /// Key: `"{backend}:{capability}"`. Capabilities are re-enabled
    /// automatically once the cooldown period elapses.
    disabled_capabilities: DashMap<String, Instant>,
}

impl KillSwitch {
    /// Create a new kill switch with no servers or capabilities disabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            killed: DashSet::new(),
            budgets: DashMap::new(),
            capability_budgets: DashMap::new(),
            disabled_capabilities: DashMap::new(),
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

    // ── Backend error budget ──────────────────────────────────────────────────

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

    // ── Per-capability error budget ───────────────────────────────────────────

    /// Build the composite key used for per-capability budget and disabled maps.
    fn capability_key(backend: &str, capability: &str) -> String {
        format!("{backend}:{capability}")
    }

    /// Returns `true` when `capability` on `backend` is currently disabled.
    ///
    /// Does **not** perform cooldown-based auto-recovery. Use
    /// [`is_capability_disabled_with_cooldown`] on the invocation hot-path to
    /// trigger transparent recovery when the cooldown has elapsed.
    #[must_use]
    pub fn is_capability_disabled(&self, backend: &str, capability: &str) -> bool {
        let key = Self::capability_key(backend, capability);
        self.is_capability_key_disabled(&key, None)
    }

    /// Returns `true` when `capability` on `backend` is currently disabled,
    /// performing transparent auto-recovery if `cooldown` has elapsed.
    ///
    /// This is the preferred method for the hot-path invocation check because
    /// it combines the disabled test with the auto-recovery sweep in one call.
    #[must_use]
    pub fn is_capability_disabled_with_cooldown(
        &self,
        backend: &str,
        capability: &str,
        cooldown: Duration,
    ) -> bool {
        let key = Self::capability_key(backend, capability);
        self.is_capability_key_disabled(&key, Some(cooldown))
    }

    /// Record a successful call for `(backend, capability)`.
    ///
    /// `cfg` supplies window sizing and cooldown configuration.
    /// Also triggers transparent auto-recovery if the capability's cooldown
    /// has elapsed since it was auto-disabled.
    pub fn record_capability_success(
        &self,
        backend: &str,
        capability: &str,
        cfg: &CapabilityErrorBudgetConfig,
    ) {
        let key = Self::capability_key(backend, capability);
        // Trigger auto-recovery check on success path too.
        self.is_capability_key_disabled(&key, Some(cfg.cooldown));
        self.get_or_create_capability_budget(&key, cfg.window_size, cfg.window_duration)
            .lock()
            .record(true);
    }

    /// Record a failed call for `(backend, capability)`, auto-disabling the
    /// capability when its budget is exhausted.
    ///
    /// `cfg` supplies threshold, window sizing, min-samples, and cooldown.
    ///
    /// Returns `true` when this failure triggered a new auto-disable.
    /// The backend-level budget is unaffected — callers must still call
    /// [`record_failure`] separately to update the backend budget.
    pub fn record_capability_failure(
        &self,
        backend: &str,
        capability: &str,
        cfg: &CapabilityErrorBudgetConfig,
    ) -> bool {
        let key = Self::capability_key(backend, capability);

        // Check if it is already disabled (respecting cooldown).
        if self.is_capability_key_disabled(&key, Some(cfg.cooldown)) {
            // Record the failure in the window even while disabled so that
            // the error rate reflects reality when it recovers.
            self.get_or_create_capability_budget(&key, cfg.window_size, cfg.window_duration)
                .lock()
                .record(false);
            return false;
        }

        let budget =
            self.get_or_create_capability_budget(&key, cfg.window_size, cfg.window_duration);
        let mut window = budget.lock();
        window.record(false);

        let (successes, failures) = window.counts();
        let total = successes + failures;
        if total < cfg.min_samples {
            return false;
        }

        let rate = window.error_rate();
        let usage_fraction = rate / cfg.threshold;

        if (0.8..1.0).contains(&usage_fraction) {
            warn!(
                capability = key,
                error_rate = rate,
                threshold = cfg.threshold,
                "Capability error budget at 80% — approaching auto-disable threshold"
            );
        }

        if rate >= cfg.threshold {
            warn!(
                capability = key,
                error_rate = rate,
                threshold = cfg.threshold,
                "Capability error budget exhausted — auto-disabling capability"
            );
            drop(window);
            self.disabled_capabilities.insert(key, Instant::now());
            return true;
        }

        false
    }

    /// Revive a previously disabled capability and reset its budget window.
    pub fn revive_capability(&self, backend: &str, capability: &str) {
        let key = Self::capability_key(backend, capability);
        if self.disabled_capabilities.remove(&key).is_some() {
            info!(
                capability = key,
                "Capability revived — re-enabled by operator"
            );
        }
        if let Some(budget) = self.capability_budgets.get(&key) {
            budget.lock().reset();
        }
    }

    /// List all currently disabled capabilities as `"backend:capability"` keys.
    ///
    /// Entries whose cooldown has expired are transparently removed (auto-recovery)
    /// before the list is returned. Callers receive only genuinely disabled entries.
    #[must_use]
    pub fn disabled_capabilities(&self, cooldown: Duration) -> Vec<String> {
        // First, purge any expired entries.
        let expired: Vec<String> = self
            .disabled_capabilities
            .iter()
            .filter(|e| e.value().elapsed() >= cooldown)
            .map(|e| e.key().clone())
            .collect();

        for key in &expired {
            self.disabled_capabilities.remove(key);
            if let Some(budget) = self.capability_budgets.get(key) {
                budget.lock().reset();
            }
            info!(
                capability = key,
                "Capability auto-recovered after cooldown (list sweep)"
            );
        }

        self.disabled_capabilities
            .iter()
            .map(|e| e.key().clone())
            .collect()
    }

    /// Retrieve the current error rate (0.0–1.0) for a capability.
    #[must_use]
    pub fn capability_error_rate(&self, backend: &str, capability: &str) -> f64 {
        let key = Self::capability_key(backend, capability);
        self.capability_budgets
            .get(&key)
            .map_or(0.0, |b| b.lock().error_rate())
    }

    /// Retrieve the window call counts for a capability as `(successes, failures)`.
    #[must_use]
    pub fn capability_window_counts(&self, backend: &str, capability: &str) -> (usize, usize) {
        let key = Self::capability_key(backend, capability);
        self.capability_budgets
            .get(&key)
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
            .or_insert_with(|| {
                Arc::new(parking_lot::Mutex::new(BudgetWindow::new(
                    window_size,
                    window_duration,
                )))
            })
            .clone()
    }

    fn get_or_create_capability_budget(
        &self,
        key: &str,
        window_size: usize,
        window_duration: Duration,
    ) -> Arc<parking_lot::Mutex<BudgetWindow>> {
        self.capability_budgets
            .entry(key.to_string())
            .or_insert_with(|| {
                Arc::new(parking_lot::Mutex::new(BudgetWindow::new(
                    window_size,
                    window_duration,
                )))
            })
            .clone()
    }

    /// Check whether a capability key is disabled, optionally auto-recovering.
    fn is_capability_key_disabled(&self, key: &str, cooldown: Option<Duration>) -> bool {
        if let Some(entry) = self.disabled_capabilities.get(key) {
            if let Some(cd) = cooldown {
                if entry.elapsed() >= cd {
                    // Cooldown elapsed — auto-recover.
                    drop(entry);
                    self.disabled_capabilities.remove(key);
                    if let Some(budget) = self.capability_budgets.get(key) {
                        budget.lock().reset();
                    }
                    info!(capability = key, "Capability auto-recovered after cooldown");
                    return false;
                }
            }
            return true;
        }
        false
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

    // ── Capability budget test helpers ───────────────────────────────────────

    /// Build a `CapabilityErrorBudgetConfig` from raw test parameters.
    fn cap_cfg(
        window_size: usize,
        window_duration: Duration,
        threshold: f64,
        min_samples: usize,
        cooldown: Duration,
    ) -> CapabilityErrorBudgetConfig {
        CapabilityErrorBudgetConfig {
            threshold,
            window_size,
            window_duration,
            min_samples,
            cooldown,
        }
    }

    /// Build a capability budget config with `min_samples = 1` (no guard).
    fn cap_cfg_no_min(
        window_size: usize,
        window_duration: Duration,
        threshold: f64,
        cooldown: Duration,
    ) -> CapabilityErrorBudgetConfig {
        cap_cfg(window_size, window_duration, threshold, 1, cooldown)
    }

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
                assert!(
                    !triggered,
                    "kill must not fire before min_samples reached (iteration {i})"
                );
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
            ks.record_failure(
                "srv",
                cfg.window_size,
                cfg.window_duration,
                cfg.threshold,
                cfg.min_samples,
            );
        }
        // 50% error rate is below 80% default threshold
        assert!(
            !ks.is_killed("srv"),
            "50% error rate must not trigger kill at default 0.8 threshold"
        );
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

    // ── CapabilityErrorBudgetConfig defaults ─────────────────────────────────

    #[test]
    fn capability_error_budget_config_default_values() {
        let cfg = CapabilityErrorBudgetConfig::default();
        assert!((cfg.threshold - 0.8).abs() < 1e-10, "default threshold must be 0.8");
        assert_eq!(cfg.window_size, 50);
        assert_eq!(cfg.window_duration, Duration::from_secs(300));
        assert_eq!(cfg.min_samples, 5, "default min_samples must be 5");
        assert_eq!(cfg.cooldown, Duration::from_secs(300));
    }

    // ── Per-capability: is_capability_disabled ────────────────────────────────

    #[test]
    fn unknown_capability_is_not_disabled() {
        let ks = KillSwitch::new();
        assert!(!ks.is_capability_disabled("fulcrum", "calendar_get_event"));
    }

    #[test]
    fn capability_not_disabled_after_success_only() {
        // GIVEN: only success records
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(50, Duration::from_secs(300), 1.0, Duration::from_secs(300));
        for _ in 0..10 {
            ks.record_capability_success("fulcrum", "calendar_get", &cfg);
        }
        // THEN: capability is not disabled
        assert!(!ks.is_capability_disabled("fulcrum", "calendar_get"));
    }

    // ── Per-capability: single capability failure doesn't kill backend ────────

    #[test]
    fn single_capability_failure_does_not_kill_backend() {
        // GIVEN: a capability with 100% error rate but backend has other successes
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(50, Duration::from_secs(300), 0.8, Duration::from_secs(300));

        // Backend gets many successes from other capabilities (backend-level budget)
        for _ in 0..20 {
            ks.record_success("fulcrum", 100, Duration::from_secs(300));
        }

        // One bad capability fires repeatedly
        for _ in 0..10 {
            ks.record_capability_failure("fulcrum", "broken_tool", &cfg);
        }

        // THEN: backend is alive; only the capability is disabled
        assert!(
            !ks.is_killed("fulcrum"),
            "backend must NOT be killed by a single capability's failures"
        );
        assert!(
            ks.is_capability_disabled("fulcrum", "broken_tool"),
            "broken_tool capability must be disabled"
        );
        // Other capabilities are unaffected
        assert!(
            !ks.is_capability_disabled("fulcrum", "healthy_tool"),
            "unaffected capability must remain enabled"
        );
    }

    // ── Per-capability: auto-disable at threshold ─────────────────────────────

    #[test]
    fn capability_auto_disabled_when_threshold_exceeded() {
        // GIVEN: min_samples=1, threshold=0.5
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(10, Duration::from_secs(300), 0.5, Duration::from_secs(300));

        // 1 success + 1 failure → 50% error rate == threshold → auto-disable
        ks.record_capability_success("fulcrum", "tool_a", &cfg);
        let triggered = ks.record_capability_failure("fulcrum", "tool_a", &cfg);
        assert!(triggered, "50% error rate should trigger auto-disable");
        assert!(ks.is_capability_disabled("fulcrum", "tool_a"));
    }

    #[test]
    fn capability_not_disabled_below_threshold() {
        // GIVEN: 40% error rate < 50% threshold
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(10, Duration::from_secs(300), 0.5, Duration::from_secs(300));

        for _ in 0..6 {
            ks.record_capability_success("fulcrum", "tool_b", &cfg);
        }
        for _ in 0..4 {
            ks.record_capability_failure("fulcrum", "tool_b", &cfg);
        }
        assert!(
            !ks.is_capability_disabled("fulcrum", "tool_b"),
            "40% error rate must not disable capability"
        );
    }

    #[test]
    fn capability_auto_disable_does_not_fire_twice() {
        // GIVEN: already-disabled capability
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(300));

        let first = ks.record_capability_failure("fulcrum", "tool_c", &cfg);
        assert!(first, "first failure (100% rate) should trigger auto-disable");

        let second = ks.record_capability_failure("fulcrum", "tool_c", &cfg);
        assert!(!second, "already-disabled capability must not re-trigger");
    }

    // ── Per-capability: min_samples guard ────────────────────────────────────

    #[test]
    fn capability_min_samples_prevents_disable_below_sample_count() {
        // GIVEN: 100% failure rate but only 4 calls < min_samples=5
        let ks = KillSwitch::new();
        let cfg = cap_cfg(50, Duration::from_secs(300), 0.8, 5, Duration::from_secs(300));

        for _ in 0..4 {
            let triggered = ks.record_capability_failure("fulcrum", "tool_d", &cfg);
            assert!(!triggered, "must not disable before min_samples reached");
        }
        assert!(!ks.is_capability_disabled("fulcrum", "tool_d"));
    }

    #[test]
    fn capability_min_samples_allows_disable_once_reached() {
        // GIVEN: 80% failure rate, min_samples=5
        let ks = KillSwitch::new();
        let cfg = cap_cfg(50, Duration::from_secs(300), 0.8, 5, Duration::from_secs(300));

        // 1 success + 4 failures = 5 samples, 80% error rate == threshold
        ks.record_capability_success("fulcrum", "tool_e", &cfg);
        for i in 0..4usize {
            let triggered = ks.record_capability_failure("fulcrum", "tool_e", &cfg);
            if i < 3 {
                assert!(!triggered, "must not trigger before 5th sample (iteration {i})");
            } else {
                // 5th sample: 4/5 = 80% >= threshold
                assert!(triggered, "must trigger at 5th sample when threshold met");
            }
        }
        assert!(ks.is_capability_disabled("fulcrum", "tool_e"));
    }

    // ── Per-capability: auto-recovery after cooldown ──────────────────────────

    #[test]
    fn capability_auto_recovers_after_cooldown() {
        // GIVEN: a disabled capability with a 10ms cooldown
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_millis(10));

        let triggered = ks.record_capability_failure("fulcrum", "tool_f", &cfg);
        assert!(triggered, "should be disabled immediately");
        // Without cooldown param: confirms it is in the disabled set (no recovery check)
        assert!(ks.is_capability_disabled("fulcrum", "tool_f"));

        // Wait for cooldown to elapse
        std::thread::sleep(Duration::from_millis(20));

        // THEN: capability auto-recovers when checked with the cooldown
        // (the hot-path uses is_capability_disabled_with_cooldown)
        assert!(
            !ks.is_capability_disabled_with_cooldown("fulcrum", "tool_f", cfg.cooldown),
            "capability must auto-recover after cooldown when checked with cooldown param"
        );
        // And now the no-cooldown check also shows it as enabled (entry was purged)
        assert!(
            !ks.is_capability_disabled("fulcrum", "tool_f"),
            "capability must be purged from disabled set after auto-recovery"
        );
    }

    #[test]
    fn capability_does_not_recover_before_cooldown_elapses() {
        // GIVEN: a disabled capability with a 60s cooldown
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(60));

        ks.record_capability_failure("fulcrum", "tool_g", &cfg);
        assert!(ks.is_capability_disabled("fulcrum", "tool_g"));

        // Immediately check — cooldown has not elapsed
        assert!(
            ks.is_capability_disabled("fulcrum", "tool_g"),
            "capability must not recover before cooldown elapses"
        );
    }

    // ── Per-capability: revive_capability ────────────────────────────────────

    #[test]
    fn revive_capability_re_enables_disabled_capability() {
        // GIVEN: a disabled capability
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(300));

        ks.record_capability_failure("fulcrum", "tool_h", &cfg);
        assert!(ks.is_capability_disabled("fulcrum", "tool_h"));

        // WHEN: revived by operator
        ks.revive_capability("fulcrum", "tool_h");

        // THEN: capability is re-enabled
        assert!(
            !ks.is_capability_disabled("fulcrum", "tool_h"),
            "capability must be re-enabled after operator revive"
        );
    }

    #[test]
    fn revive_capability_resets_error_budget() {
        // GIVEN: a revived capability that receives successes
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(4, Duration::from_secs(300), 0.5, Duration::from_secs(300));

        // Disable it by recording 2 failures (100% error rate > 0.5 threshold)
        for _ in 0..2 {
            ks.record_capability_failure("fulcrum", "tool_i", &cfg);
        }
        ks.revive_capability("fulcrum", "tool_i");

        // After revive: 3 successes + 1 failure = 25% error rate (below threshold)
        for _ in 0..3 {
            ks.record_capability_success("fulcrum", "tool_i", &cfg);
        }
        let retrigger = ks.record_capability_failure("fulcrum", "tool_i", &cfg);
        assert!(!retrigger, "25% error rate after revive must not re-trigger");
        assert!(!ks.is_capability_disabled("fulcrum", "tool_i"));
    }

    #[test]
    fn revive_capability_is_idempotent_on_live_capability() {
        let ks = KillSwitch::new();
        // Reviving a capability that was never disabled must not panic
        ks.revive_capability("fulcrum", "never_disabled");
        assert!(!ks.is_capability_disabled("fulcrum", "never_disabled"));
    }

    // ── Per-capability: disabled_capabilities list ────────────────────────────

    #[test]
    fn disabled_capabilities_returns_empty_when_none_disabled() {
        let ks = KillSwitch::new();
        let list = ks.disabled_capabilities(Duration::from_secs(300));
        assert!(list.is_empty());
    }

    #[test]
    fn disabled_capabilities_lists_disabled_entries() {
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_secs(300));

        ks.record_capability_failure("fulcrum", "tool_j", &cfg);
        ks.record_capability_failure("fulcrum", "tool_k", &cfg);

        let mut list = ks.disabled_capabilities(cfg.cooldown);
        list.sort();
        assert_eq!(list, vec!["fulcrum:tool_j", "fulcrum:tool_k"]);
    }

    #[test]
    fn disabled_capabilities_purges_expired_entries_on_list() {
        // GIVEN: two disabled capabilities with a 10ms cooldown
        let ks = KillSwitch::new();
        let cfg = cap_cfg_no_min(2, Duration::from_secs(300), 0.5, Duration::from_millis(10));

        ks.record_capability_failure("fulcrum", "tool_l", &cfg);
        ks.record_capability_failure("fulcrum", "tool_m", &cfg);

        // Both should be disabled immediately (use long cooldown for initial check)
        let before = ks.disabled_capabilities(Duration::from_secs(300));
        assert_eq!(before.len(), 2, "both capabilities should be listed as disabled");

        // Wait for both cooldowns to expire
        std::thread::sleep(Duration::from_millis(20));

        // WHEN: listing with the actual short cooldown
        let after = ks.disabled_capabilities(cfg.cooldown);

        // THEN: both entries are purged (expired), list is empty
        assert!(
            after.is_empty(),
            "expired entries must be purged from the disabled list"
        );
    }

    // ── Per-capability: error_rate / window_counts ────────────────────────────

    #[test]
    fn capability_error_rate_zero_with_no_calls() {
        let ks = KillSwitch::new();
        assert!(ks.capability_error_rate("fulcrum", "unknown") < f64::EPSILON);
    }

    #[test]
    fn capability_window_counts_initial_state() {
        let ks = KillSwitch::new();
        let (s, f) = ks.capability_window_counts("fulcrum", "unknown");
        assert_eq!(s, 0);
        assert_eq!(f, 0);
    }

    #[test]
    fn capability_error_rate_computed_correctly() {
        let ks = KillSwitch::new();
        // threshold=1.0 means auto-disable can never trigger
        let cfg = cap_cfg_no_min(10, Duration::from_secs(300), 1.0, Duration::from_secs(300));
        ks.record_capability_success("srv", "cap", &cfg);
        ks.record_capability_success("srv", "cap", &cfg);
        ks.record_capability_failure("srv", "cap", &cfg);
        let rate = ks.capability_error_rate("srv", "cap");
        assert!(
            (rate - 1.0 / 3.0).abs() < 1e-10,
            "expected 33% error rate, got {rate}"
        );
    }

    // ── Backend-level budget still works as fallback ──────────────────────────

    #[test]
    fn backend_level_budget_still_kills_when_all_capabilities_fail() {
        // GIVEN: many different capabilities all failing — backend threshold exceeded
        let ks = KillSwitch::new();
        let (backend_ws, backend_wd, thresh, min) = (20, Duration::from_secs(300), 0.8, 1_usize);
        let cap_cfg_val =
            cap_cfg_no_min(20, Duration::from_secs(300), 0.8, Duration::from_secs(300));

        // Flood the backend budget with failures (each represents a different
        // capability, so none individually dominates)
        for i in 0..20u32 {
            let cap = format!("tool_{i}");
            // Record on backend budget
            ks.record_failure("fulcrum", backend_ws, backend_wd, thresh, min);
            // Also record on per-capability budget
            ks.record_capability_failure("fulcrum", &cap, &cap_cfg_val);
        }

        // THEN: backend is killed because cumulative error rate exceeds threshold
        assert!(
            ks.is_killed("fulcrum"),
            "backend must be killed when cumulative error rate exceeds backend threshold"
        );
    }
}
