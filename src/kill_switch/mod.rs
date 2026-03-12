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

pub mod budget;

pub use budget::{CapabilityErrorBudgetConfig, ErrorBudgetConfig};

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::DashSet;
use tracing::{info, warn};

use budget::BudgetWindow;

#[cfg(test)]
mod tests;

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
