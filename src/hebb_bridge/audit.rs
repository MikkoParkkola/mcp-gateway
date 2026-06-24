//! Hebb bridge audit log (MIK-NEW.RUNTIME.2 — B1-IDENT distinguishable).
//!
//! Every recall/remember call through the bridge is recorded with a
//! monotonically-increasing sequence number that is observably distinct from
//! other gateway audit signals (e.g. `agent_tool_audit`, `attestation_audit`).
//!
//! The audit signal is emitted via `hebb_bridge_audit` tracing events — a
//! name distinct from pre-existing audit streams so the three are
//! independently attributable (B1-IDENT).

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// One audit record for a hebb bridge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HebbBridgeAuditRecord {
    /// Monotonic sequence number — unique per record (B1-IDENT).
    pub seq: u64,
    /// RFC-3339 timestamp of the operation.
    pub timestamp: String,
    /// Sandbox identifier (from the per-sandbox auth header).
    pub sandbox_id: String,
    /// Operation: `"recall"` or `"remember"`.
    pub operation: String,
    /// Entity identifier accessed.
    pub entity_id: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error detail when the operation failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
    /// Operation duration in microseconds.
    pub duration_micros: u64,
}

/// Fixed-capacity audit trail for hebb bridge operations.
///
/// Distinct from [`crate::attestation::AuditRingBuffer`] and
/// `agent_tool_audit` — the three audit streams are independently
/// attributable (B1-IDENT).
#[derive(Debug)]
pub struct HebbBridgeAuditor {
    /// Sandbox namespace for audit attribution.
    #[allow(dead_code)]
    namespace: String,
    /// Ring buffer of audit records.
    records: Mutex<Vec<HebbBridgeAuditRecord>>,
    /// Maximum records to retain.
    max_entries: usize,
    /// Monotonic sequence counter.
    sequence: AtomicU64,
}

impl HebbBridgeAuditor {
    /// Create an auditor for `namespace` retaining at most `max_entries` records.
    #[must_use]
    pub fn new(namespace: String, max_entries: usize) -> Self {
        Self {
            namespace,
            records: Mutex::new(Vec::with_capacity(max_entries.min(1024))),
            max_entries: max_entries.max(1),
            sequence: AtomicU64::new(0),
        }
    }

    /// Record an audit entry, evicting the oldest when at capacity.
    ///
    /// Emits a `hebb_bridge_audit` tracing event — observably distinct from
    /// `attestation_audit` and `agent_tool_audit` (B1-IDENT).
    pub fn record(&self, mut record: HebbBridgeAuditRecord) -> u64 {
        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        record.seq = seq;

        // Emit the tracing event BEFORE locking the buffer so the signal
        // is observable even under buffer contention.
        tracing::info!(
            seq,
            sandbox_id = %record.sandbox_id,
            operation = %record.operation,
            entity_id = %record.entity_id,
            success = record.success,
            duration_micros = record.duration_micros,
            "hebb_bridge_audit"
        );

        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if records.len() >= self.max_entries {
            records.remove(0);
        }
        records.push(record);
        seq
    }

    /// Snapshot of current audit records, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<HebbBridgeAuditRecord> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Number of records currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the buffer holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total records ever recorded (monotonic, survives eviction).
    #[must_use]
    pub fn total_records(&self) -> u64 {
        self.sequence.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auditor_starts_empty() {
        let auditor = HebbBridgeAuditor::new("test-ns".into(), 100);
        assert!(auditor.is_empty());
        assert_eq!(auditor.len(), 0);
        assert_eq!(auditor.total_records(), 0);
    }

    #[test]
    fn auditor_records_and_returns_sequence() {
        let auditor = HebbBridgeAuditor::new("test-ns".into(), 100);
        let seq = auditor.record(HebbBridgeAuditRecord {
            seq: 0,
            timestamp: "2026-06-12T00:00:00Z".into(),
            sandbox_id: "sb-1".into(),
            operation: "recall".into(),
            entity_id: "ent-1".into(),
            success: true,
            error_detail: None,
            duration_micros: 42,
        });
        assert_eq!(seq, 0);
        assert_eq!(auditor.len(), 1);
        assert_eq!(auditor.total_records(), 1);
    }

    #[test]
    fn auditor_evicts_oldest_at_capacity() {
        let auditor = HebbBridgeAuditor::new("test-ns".into(), 2);
        for i in 0..3 {
            auditor.record(HebbBridgeAuditRecord {
                seq: 0,
                timestamp: String::new(),
                sandbox_id: format!("sb-{i}"),
                operation: "recall".into(),
                entity_id: format!("ent-{i}"),
                success: true,
                error_detail: None,
                duration_micros: 0,
            });
        }
        assert_eq!(auditor.len(), 2);
        let snap = auditor.snapshot();
        assert_eq!(snap[0].sandbox_id, "sb-1");
        assert_eq!(snap[1].sandbox_id, "sb-2");
        assert_eq!(auditor.total_records(), 3); // total survives eviction
    }

    #[test]
    fn auditor_sequences_are_monotonic() {
        let auditor = HebbBridgeAuditor::new("test-ns".into(), 100);
        let s0 = auditor.record(HebbBridgeAuditRecord {
            seq: 0,
            timestamp: "t0".into(),
            sandbox_id: "sb".into(),
            operation: "recall".into(),
            entity_id: "e0".into(),
            success: true,
            error_detail: None,
            duration_micros: 0,
        });
        let s1 = auditor.record(HebbBridgeAuditRecord {
            seq: 0,
            timestamp: "t1".into(),
            sandbox_id: "sb".into(),
            operation: "remember".into(),
            entity_id: "e1".into(),
            success: true,
            error_detail: None,
            duration_micros: 0,
        });
        assert!(s1 > s0);
        assert_eq!(auditor.total_records(), 2);
    }
}
