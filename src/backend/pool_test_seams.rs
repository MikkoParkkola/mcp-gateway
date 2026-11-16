// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Test-only seams on a backend's pool: reach a slot, seed its transport, trip its breaker.

use super::{Arc, Backend, PoolKey, PooledEntry, Transport};

impl Backend {
    /// Test-only: the shared slot, so a test can hold its start lock as a
    /// start in flight does.
    #[cfg(test)]
    pub(crate) fn shared_entry_for_test(&self) -> Arc<PooledEntry> {
        self.shared_entry()
    }

    #[cfg(test)]
    pub(crate) fn set_transport_for_test(&self, transport: Arc<dyn Transport>) {
        let entry = self.shared_entry();
        *entry.transport.write() = Some(transport);
    }

    /// Test-only: seed one slot's transport.
    #[cfg(test)]
    pub(crate) fn set_pooled_transport_for_test(
        &self,
        key: &PoolKey,
        transport: Arc<dyn Transport>,
    ) {
        let entry = self.pooled_entry(key).expect("test slot admitted");
        *entry.transport.write() = Some(transport);
    }

    /// Test-only: how many callers wait on the shared slot's tools fill in
    /// flight, a join observed, not timed.
    #[cfg(all(test, feature = "cost-governance"))]
    pub(crate) fn tools_waiters_for_test(&self) -> usize {
        self.pool
            .get(&PoolKey::Shared)
            .map_or(0, |entry| entry.value().tools_cache.waiters_for_test())
    }

    /// Test-only: one slot's transport, for `Arc::ptr_eq` isolation checks.
    #[cfg(test)]
    pub(crate) fn pooled_transport_for_test(&self, key: &PoolKey) -> Option<Arc<dyn Transport>> {
        self.pool
            .get(key)
            .and_then(|entry| entry.value().transport.read().clone())
    }

    /// Test-only: the consecutive and lifetime unserved probe counts (rows
    /// 10 to 11b: two values, two reset rules).
    #[cfg(test)]
    pub(crate) fn unserved_counts_for_test(&self) -> (u64, u64) {
        (
            self.unserved_consecutive
                .load(std::sync::atomic::Ordering::SeqCst),
            self.unserved_total
                .load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// Test-only: trip this backend's canonical Shared-slot circuit breaker
    /// open, by the same route the health probe's unserved escalation uses.
    #[cfg(test)]
    pub(crate) fn trip_circuit_breaker_for_test(&self) {
        self.trip_circuit_breaker("test-trip");
    }

    /// Test-only: record enough failed requests on the canonical Shared slot
    /// that its health tracker reports the backend down, as a real outage does.
    #[cfg(test)]
    pub(crate) fn fail_requests_for_test(&self) {
        let entry = self.shared_entry();
        for _ in 0..3 {
            entry
                .failsafe
                .record_failure("test-failure", std::time::Duration::ZERO);
        }
    }

    /// Test-only: trip an arbitrary pool slot's circuit breaker open
    /// Generalizes [`Self::trip_circuit_breaker_for_test`]
    /// (Shared-only) to any [`PoolKey`], so cross-tenant isolation tests can
    /// trip one identity's slot without touching another's.
    #[cfg(test)]
    pub(crate) fn trip_circuit_breaker_for_test_key(&self, key: &PoolKey) {
        let entry = self.pooled_entry(key).expect("test slot admitted");
        let threshold = entry.failsafe.circuit_breaker.stats().failure_threshold;
        for _ in 0..threshold {
            entry
                .failsafe
                .circuit_breaker
                .record_failure("test-trip", std::time::Duration::ZERO);
        }
    }
}
