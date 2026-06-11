//! Audit trail for runtime operations.
//!
//! Records substrate compilations, divergence detections, and override
//! applications.  Each record carries a [`SubstrateId`] tag for
//! attributability.

use serde::{Deserialize, Serialize};

/// Unique substrate identifier for audit attribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SubstrateId(pub String);

/// Type of audit event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditEventKind {
    /// Descriptor compiled to a substrate.
    Compiled,
    /// Divergence detected between substrates.
    Divergence,
    /// Override hook applied.
    OverrideApplied,
}

/// A single audit record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    /// Substrate that produced this event.
    pub substrate_id: SubstrateId,

    /// Event type.
    pub kind: AuditEventKind,

    /// Human-readable detail.
    pub detail: String,

    /// Timestamp (milliseconds since UNIX epoch).
    pub timestamp_ms: u64,
}

/// Append-only audit trail.
#[derive(Debug, Clone, Default)]
pub struct AuditTrail {
    records: Vec<AuditRecord>,
}

impl AuditTrail {
    /// Create an empty audit trail.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a record.
    pub fn record(&mut self, record: AuditRecord) {
        self.records.push(record);
    }

    /// View all records.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Log a compilation event.
    pub fn log_compilation(&mut self, substrate: SubstrateId, sandbox_name: &str) {
        self.record(AuditRecord {
            substrate_id: substrate,
            kind: AuditEventKind::Compiled,
            detail: format!("compiled sandbox '{sandbox_name}'"),
            timestamp_ms: current_timestamp_ms(),
        });
    }

    /// Log a divergence event.
    pub fn log_divergence(
        &mut self,
        substrate_a: &SubstrateId,
        substrate_b: &SubstrateId,
        field: &str,
        value_a: &str,
        value_b: &str,
    ) {
        self.record(AuditRecord {
            substrate_id: substrate_a.clone(),
            kind: AuditEventKind::Divergence,
            detail: format!(
                "divergence on '{field}': {}={}, {}={}",
                substrate_a.0, value_a, substrate_b.0, value_b,
            ),
            timestamp_ms: current_timestamp_ms(),
        });
    }

    /// Log an override-applied event.
    pub fn log_override(&mut self, substrate: SubstrateId, sandbox_name: &str) {
        self.record(AuditRecord {
            substrate_id: substrate,
            kind: AuditEventKind::OverrideApplied,
            detail: format!("override applied to sandbox '{sandbox_name}'"),
            timestamp_ms: current_timestamp_ms(),
        });
    }
}

fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            #[allow(clippy::cast_possible_truncation)]
            { d.as_millis() as u64 }
        })
}
