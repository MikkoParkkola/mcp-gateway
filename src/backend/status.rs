// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend-wide state readers and breaker controls on the canonical Shared
//! slot. Split out of `lifecycle.rs` and `ops.rs` to keep both under the
//! file-size ratchet (`scripts/dev/check-file-size.py`).

use super::Backend;
use super::pool::PoolKey;

impl Backend {
    /// Check if backend is running (canonical shared slot connected).
    pub fn is_running(&self) -> bool {
        self.pool
            .get(&PoolKey::Shared)
            .and_then(|entry| {
                entry
                    .value()
                    .transport
                    .read()
                    .as_ref()
                    .map(|t| t.is_connected())
            })
            .unwrap_or(false)
    }

    /// Get circuit breaker stats for this backend's canonical Shared slot
    /// (MIK-6735 fix 1).
    pub fn circuit_breaker_stats(&self) -> crate::failsafe::CircuitBreakerStats {
        self.shared_entry().failsafe.circuit_breaker.stats()
    }

    /// Drive this backend's canonical Shared-slot circuit breaker open.
    ///
    /// The counterpart to [`Self::reset_circuit_breaker`], for the one caller
    /// that has decided a backend is failing without having a failed request to
    /// show for it: the health probe's unserved escalation (MIK-7217,
    /// OUTBOUND.2), whose evidence is a run of complete answers that served
    /// nothing. Expressed as the configured number of failures rather than a
    /// state write, so the breaker's own accounting - open event, failure
    /// count, the half-open timer - stays the single description of why it is
    /// open.
    pub(crate) fn trip_circuit_breaker(&self, reason: &str) {
        let entry = self.shared_entry();
        let threshold = entry.failsafe.circuit_breaker.stats().failure_threshold;
        for _ in 0..threshold {
            entry
                .failsafe
                .circuit_breaker
                .record_failure(reason, std::time::Duration::ZERO);
        }
    }

    /// Force this backend's canonical Shared-slot circuit breaker back to
    /// `Closed` (MIK-5983; slot-scoped per MIK-6735 fix 1).
    ///
    /// Called by `gateway_revive_server` so the documented manual recovery
    /// path also clears a tripped breaker, not just the kill switch.
    pub fn reset_circuit_breaker(&self) {
        self.shared_entry().failsafe.circuit_breaker.reset();
    }

    /// Whether this backend's canonical Shared-slot circuit breaker is
    /// currently tripped (`Open` or `HalfOpen` -- i.e. not `Closed`; slot-scoped
    /// per MIK-6735 fix 1).
    #[must_use]
    pub fn is_circuit_tripped(&self) -> bool {
        self.shared_entry().failsafe.circuit_breaker.state()
            != crate::failsafe::CircuitState::Closed
    }
}
