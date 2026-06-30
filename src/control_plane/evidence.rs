// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Evidence export for compliance and incident response.
//!
//! AC.5: Evidence export supports compliance and incident response by exporting
//! time-bounded audit evidence, approval history, TrustCard/eval summaries,
//! and runtime health in redacted NDJSON plus JSON bundle formats, with stable
//! schema/version metadata.
//!
//! CHECK: `cargo test --all-features control_plane_evidence_export_redaction_schema` exits 0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::domain::{
    ApprovalRequest, AuditEvidence, EvidenceExportRequest, ExportFormat, RuntimeHealth,
    TrustCardSummary,
};
use super::storage::ControlPlaneStore;

/// Schema version for exported evidence bundles.
pub const EVIDENCE_EXPORT_SCHEMA_VERSION: &str = "1.0.0";

/// Fields that must be redacted (secrets, arguments, raw payloads).
const REDACT_FIELDS: &[&str] = &[
    "secret",
    "password",
    "token",
    "api_key",
    "bearer",
    "credential",
    "private_key",
    "arguments",
    "env",
];

/// Redacted evidence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedAuditEvidence {
    pub id: String,
    pub event_type: String,
    pub actor: String,
    pub role: String,
    pub target_id: String,
    pub previous_state_hash: Option<String>,
    pub new_state_hash: Option<String>,
    pub decision: String,
    pub trace_id: Option<String>,
    pub request_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    /// Redacted payload — secrets and arguments stripped.
    pub payload: serde_json::Value,
}

/// Exported evidence bundle (JSON format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExportBundle {
    /// Schema version for the export format.
    pub schema_version: String,
    /// Timestamp when the export was generated.
    pub exported_at: DateTime<Utc>,
    /// Time range of the exported data.
    pub from: Option<DateTime<Utc>>,
    /// Time range of the exported data.
    pub to: Option<DateTime<Utc>>,
    /// Audit evidence entries (redacted).
    pub audit_evidence: Vec<RedactedAuditEvidence>,
    /// Approval history.
    pub approval_history: Vec<ApprovalRequest>,
    /// TrustCard / evaluation summaries.
    pub trust_cards: Vec<TrustCardSummary>,
    /// Runtime health records.
    pub runtime_health: Vec<RuntimeHealth>,
    /// Export metadata.
    pub metadata: ExportMetadata,
}

/// Metadata for an evidence export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    /// Gateway version that produced the export.
    pub gateway_version: String,
    /// Total number of audit records.
    pub total_audit_records: usize,
    /// Total number of approval records.
    pub total_approval_records: usize,
    /// Whether the export was redacted.
    pub redacted: bool,
}

/// Evidence exporter.
pub struct EvidenceExporter {
    store: Arc<dyn ControlPlaneStore>,
}

impl EvidenceExporter {
    /// Create a new evidence exporter.
    pub fn new(store: Arc<dyn ControlPlaneStore>) -> Self {
        Self { store }
    }

    /// Export evidence in the requested format.
    ///
    /// # Errors
    ///
    /// Returns a `StoreError` if the store operations fail.
    pub async fn export(
        &self,
        request: &EvidenceExportRequest,
    ) -> Result<String, super::storage::StoreError> {
        let audit_evidence = self
            .store
            .list_audit_evidence(request.from, request.to)
            .await?;
        let approval_history = self.store.list_approval_requests().await?;
        let trust_cards = self.store.list_trust_cards().await?;
        let runtime_health = self.store.get_runtime_health().await?;

        // Redact all audit evidence
        let redacted: Vec<RedactedAuditEvidence> = audit_evidence
            .into_iter()
            .map(|e| redact_evidence(&e, request.redact))
            .collect();

        // Filter approvals by time range
        let filtered_approvals: Vec<ApprovalRequest> = approval_history
            .into_iter()
            .filter(|a| {
                if let Some(from) = request.from {
                    a.created_at >= from
                } else {
                    true
                }
            })
            .filter(|a| {
                if let Some(to) = request.to {
                    a.created_at <= to
                } else {
                    true
                }
            })
            .collect();

        // Filter trust cards — all returned (they represent current state)
        // Filter runtime health — all returned

        let bundle = EvidenceExportBundle {
            schema_version: EVIDENCE_EXPORT_SCHEMA_VERSION.to_string(),
            exported_at: Utc::now(),
            from: request.from,
            to: request.to,
            audit_evidence: redacted.clone(),
            approval_history: filtered_approvals.clone(),
            trust_cards,
            runtime_health,
            metadata: ExportMetadata {
                gateway_version: env!("CARGO_PKG_VERSION").to_string(),
                total_audit_records: redacted.len(),
                total_approval_records: filtered_approvals.len(),
                redacted: request.redact,
            },
        };

        match request.format {
            ExportFormat::Ndjson => {
                let mut lines = Vec::new();
                // Header line with schema version
                lines.push(
                    serde_json::to_string(&serde_json::json!({
                        "type": "header",
                        "schema_version": EVIDENCE_EXPORT_SCHEMA_VERSION,
                        "exported_at": bundle.exported_at.to_rfc3339(),
                        "redacted": request.redact,
                    }))
                    .map_err(super::storage::StoreError::Serialization)?,
                );
                // One line per audit evidence
                for ev in &redacted {
                    lines.push(
                        serde_json::to_string(ev)
                            .map_err(super::storage::StoreError::Serialization)?,
                    );
                }
                // One line per approval
                for ap in &filtered_approvals {
                    lines.push(
                        serde_json::to_string(ap)
                            .map_err(super::storage::StoreError::Serialization)?,
                    );
                }
                Ok(lines.join("\n"))
            }
            ExportFormat::JsonBundle => {
                serde_json::to_string_pretty(&bundle)
                    .map_err(super::storage::StoreError::Serialization)
            }
        }
    }
}

/// Redact sensitive fields from audit evidence.
///
/// AC.5: exported fixtures omit raw secrets/arguments and include schema_version.
fn redact_evidence(evidence: &AuditEvidence, redact: bool) -> RedactedAuditEvidence {
    let payload = if redact {
        redact_json_value(&evidence.payload)
    } else {
        evidence.payload.clone()
    };

    RedactedAuditEvidence {
        id: evidence.id.clone(),
        event_type: evidence.event_type.clone(),
        actor: evidence.actor.clone(),
        role: evidence.role.clone(),
        target_id: evidence.target_id.clone(),
        previous_state_hash: evidence.previous_state_hash.clone(),
        new_state_hash: evidence.new_state_hash.clone(),
        decision: evidence.decision.clone(),
        trace_id: evidence.trace_id.clone(),
        request_id: evidence.request_id.clone(),
        timestamp: evidence.timestamp,
        payload,
    }
}

/// Recursively redact sensitive fields from a JSON value.
fn redact_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, val) in map {
                if is_sensitive_key(key) {
                    new_map.insert(key.clone(), serde_json::Value::String("[REDACTED]".into()));
                } else {
                    new_map.insert(key.clone(), redact_json_value(val));
                }
            }
            serde_json::Value::Object(new_map)
        }
        serde_json::Value::Array(arr) => {
            let new_arr: Vec<serde_json::Value> =
                arr.iter().map(redact_json_value).collect();
            serde_json::Value::Array(new_arr)
        }
        other => other.clone(),
    }
}

/// Check if a key name indicates sensitive content.
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    REDACT_FIELDS.iter().any(|f| lower.contains(f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::domain::{
        ApprovalStatus, EvidenceExportRequest, ExportFormat,
    };
    use crate::control_plane::storage::EmbeddedControlPlaneStore;

    fn make_audit_evidence(id: &str) -> AuditEvidence {
        AuditEvidence {
            id: id.to_string(),
            event_type: "grant.created".into(),
            actor: "admin".into(),
            role: "admin".into(),
            target_id: "grant-1".into(),
            previous_state_hash: Some("sha256:aaa".into()),
            new_state_hash: Some("sha256:bbb".into()),
            decision: "created".into(),
            trace_id: Some("trace-1".into()),
            request_id: Some("req-1".into()),
            timestamp: Utc::now(),
            payload: serde_json::json!({
                "name": "Test Grant",
                "api_key": "secret-key-12345",
                "token": "bearer-token-abcdef",
                "password": "super-secret",
                "arguments": ["--verbose", "--secret", "x"],
                "safe_field": "visible",
                "nested": {
                    "credential": "nested-secret",
                    "public": "hello"
                }
            }),
        }
    }

    /// AC.5: Evidence export supports compliance and incident response.
    /// CHECK: `cargo test --all-features control_plane_evidence_export_redaction_schema` exits 0
    #[tokio::test]
    async fn control_plane_evidence_export_redaction_schema() {
        let store = Arc::new(EmbeddedControlPlaneStore::new());

        // Seed some audit evidence
        let evidence = make_audit_evidence("ev-1");
        store
            .record_audit_evidence(evidence)
            .await
            .expect("record evidence");

        // Seed an approval request
        let approval = ApprovalRequest {
            id: "apr-1".into(),
            request_type: "grant".into(),
            target_id: "grant-1".into(),
            action: "create".into(),
            payload: serde_json::json!({"name": "Test"}),
            status: ApprovalStatus::Approved,
            requested_by: "developer".into(),
            reviewed_by: Some("sec-reviewer".into()),
            reviewer_comment: Some("LGTM".into()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        };
        store
            .create_approval_request(approval)
            .await
            .expect("create approval");

        let exporter = EvidenceExporter::new(store);

        // Export as JSON bundle (redacted)
        let request = EvidenceExportRequest {
            from: None,
            to: None,
            format: ExportFormat::JsonBundle,
            redact: true,
            include_trust_cards: true,
            include_health: true,
        };

        let json_output = exporter.export(&request).await.expect("export");
        let bundle: EvidenceExportBundle =
            serde_json::from_str(&json_output).expect("parse bundle");

        // Schema version must be present
        assert_eq!(bundle.schema_version, EVIDENCE_EXPORT_SCHEMA_VERSION);

        // Redacted: secrets must be stripped
        let ev = &bundle.audit_evidence[0];
        let payload = &ev.payload;

        // Sensitive fields redacted
        assert_eq!(payload["api_key"], "[REDACTED]");
        assert_eq!(payload["token"], "[REDACTED]");
        assert_eq!(payload["password"], "[REDACTED]");
        assert_eq!(payload["arguments"], "[REDACTED]");
        assert_eq!(payload["nested"]["credential"], "[REDACTED]");

        // Safe fields preserved
        assert_eq!(payload["safe_field"], "visible");
        assert_eq!(payload["nested"]["public"], "hello");
        assert_eq!(payload["name"], "Test Grant");

        // Approval history present
        assert_eq!(bundle.approval_history.len(), 1);
        assert_eq!(bundle.approval_history[0].id, "apr-1");

        // Metadata present
        assert_eq!(bundle.metadata.redacted, true);
        assert_eq!(bundle.metadata.total_audit_records, 1);

        // Export as NDJSON (redacted)
        let ndjson_request = EvidenceExportRequest {
            format: ExportFormat::Ndjson,
            ..request
        };
        let ndjson_output = exporter.export(&ndjson_request).await.expect("ndjson export");

        // First line must be the header with schema version
        let first_line = ndjson_output.lines().next().expect("first line");
        let header: serde_json::Value =
            serde_json::from_str(first_line).expect("parse header");
        assert_eq!(header["schema_version"], EVIDENCE_EXPORT_SCHEMA_VERSION);
        assert_eq!(header["type"], "header");
        assert_eq!(header["redacted"], true);

        // Must have at least 2 more lines (evidence + approval)
        let lines: Vec<&str> = ndjson_output.lines().skip(1).collect();
        assert!(lines.len() >= 2, "Expected >=2 data lines, got {}", lines.len());
    }

    #[test]
    fn redaction_strips_nested_secrets() {
        let evidence = make_audit_evidence("ev-1");
        let redacted = redact_evidence(&evidence, true);

        let payload = &redacted.payload;
        assert_eq!(payload["api_key"], "[REDACTED]");
        assert_eq!(payload["safe_field"], "visible");
        assert_eq!(payload["nested"]["credential"], "[REDACTED]");
        assert_eq!(payload["nested"]["public"], "hello");
    }

    #[test]
    fn no_redaction_preserves_all_fields() {
        let evidence = make_audit_evidence("ev-1");
        let clean = redact_evidence(&evidence, false);

        let payload = &clean.payload;
        assert_eq!(payload["api_key"], "secret-key-12345");
        assert_eq!(payload["token"], "bearer-token-abcdef");
        assert_eq!(payload["safe_field"], "visible");
    }

    #[test]
    fn schema_version_is_stable() {
        // Schema version must be a valid semver string
        let parts: Vec<&str> = EVIDENCE_EXPORT_SCHEMA_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].parse::<u32>().is_ok());
        assert!(parts[1].parse::<u32>().is_ok());
        assert!(parts[2].parse::<u32>().is_ok());
    }

    #[test]
    fn export_format_serialization() {
        let formats = vec![
            (ExportFormat::Ndjson, "\"ndjson\""),
            (ExportFormat::JsonBundle, "\"json_bundle\""),
        ];
        for (format, expected) in formats {
            let json = serde_json::to_string(&format).expect("serialize");
            assert_eq!(json, expected);
        }
    }
}