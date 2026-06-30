// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Control-plane domain models for Enterprise ControlPlaneUI.
//!
//! Every object supports serde round-trip serialization.
//! AC.1: covers servers, tools, TrustCards, evaluations, grants, policies,
//! users/groups, runtime health, approval requests, and audit evidence.

#![allow(missing_docs)] // Domain model types are self-documenting

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── ControlPlaneServer ────────────────────────────────────────────────────────

/// A managed MCP server visible in the control plane inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlPlaneServer {
    /// Unique server identifier.
    pub id: String,
    /// Human-readable server name.
    pub name: String,
    /// Transport protocol (e.g. "stdio", "streamable-http", "sse").
    pub transport: String,
    /// Whether the server is currently running / reachable.
    pub running: bool,
    /// Number of tools cached from this server.
    pub tool_count: usize,
    /// Timestamp of last successful health check.
    pub last_health_at: Option<DateTime<Utc>>,
    /// Server health status.
    pub health: RuntimeHealth,
    /// Labels / tags for organising servers.
    pub labels: Vec<String>,
}

// ── ControlPlaneTool ──────────────────────────────────────────────────────────

/// A tool registered in the control plane inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlPlaneTool {
    /// Unique tool identifier.
    pub id: String,
    /// Tool name.
    pub name: String,
    /// Owning server identifier.
    pub server_id: String,
    /// Owning server name (denormalised for display).
    pub server_name: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// JSON Schema for tool input (optional).
    pub input_schema: Option<serde_json::Value>,
    /// Whether the tool is currently callable.
    pub enabled: bool,
}

// ── TrustCardSummary ──────────────────────────────────────────────────────────

/// Summary of a TrustCard evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustCardSummary {
    /// TrustCard identifier.
    pub id: String,
    /// Associated server or tool identifier.
    pub subject_id: String,
    /// Subject type ("server" or "tool").
    pub subject_type: String,
    /// Overall trust score (0.0–1.0, higher = more trusted).
    pub score: f64,
    /// Human-readable verdict.
    pub verdict: String,
    /// When the TrustCard was last evaluated.
    pub evaluated_at: DateTime<Utc>,
    /// Evaluator name (e.g. "TrustLab", "manual-review").
    pub evaluator: String,
}

// ── EvaluationEvidence ────────────────────────────────────────────────────────

/// Evidence collected during a TrustCard or TrustLab evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationEvidence {
    /// Evidence identifier.
    pub id: String,
    /// Associated TrustCard identifier.
    pub trust_card_id: String,
    /// Evidence type (e.g. "behavioural", "static-analysis", "runtime-scan").
    pub evidence_type: String,
    /// Evidence payload (structured JSON).
    pub payload: serde_json::Value,
    /// When the evidence was collected.
    pub collected_at: DateTime<Utc>,
    /// Collector / source identifier.
    pub collector: String,
}

// ── GrantState ────────────────────────────────────────────────────────────────

/// The lifecycle state of an identity grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// Grant is pending approval.
    PendingApproval,
    /// Grant has been applied to the system.
    Applied,
    /// Grant has been rejected.
    Rejected,
    /// Grant has been rolled back to a previous state.
    RolledBack,
    /// Grant has expired.
    Expired,
}

// ── IdentityGrant ─────────────────────────────────────────────────────────────

/// An identity grant binding a subject to a resource with a specific permission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityGrant {
    /// Grant identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The subject (e.g. "user:alice", "group:engineering").
    pub subject: String,
    /// The resource (e.g. "tool:search", "server:brave").
    pub resource: String,
    /// Current lifecycle state.
    pub state: GrantState,
    /// Previous state before the last transition (for rollback).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<serde_json::Value>,
    /// State to roll back to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_state: Option<serde_json::Value>,
    /// Who created this grant.
    pub created_by: String,
    /// When the grant was created.
    pub created_at: DateTime<Utc>,
    /// When the grant was last modified.
    pub updated_at: DateTime<Utc>,
    /// Monotonic version counter.
    pub version: u64,
    /// Additional metadata (arbitrary JSON).
    #[serde(default)]
    pub metadata: serde_json::Value,
}

// ── PolicyBinding ─────────────────────────────────────────────────────────────

/// A policy binding attached to a server, tool, or identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyBinding {
    /// Binding identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Policy type (e.g. "tool_allowlist", "tool_denylist", "server_access").
    pub policy_type: String,
    /// Target specification (e.g. "server:brave", "tool:search_*").
    pub target: String,
    /// Policy rules as structured JSON.
    pub rules: serde_json::Value,
    /// Priority for conflict resolution (higher = wins).
    pub priority: i32,
    /// Whether this binding is currently active.
    pub enabled: bool,
    /// Who created this binding.
    pub created_by: String,
    /// When the binding was created.
    pub created_at: DateTime<Utc>,
    /// When the binding was last modified.
    pub updated_at: DateTime<Utc>,
    /// Monotonic version counter.
    pub version: u64,
}

// ── ApprovalStatus ────────────────────────────────────────────────────────────

/// Status of an approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Awaiting review.
    Pending,
    /// Approved by a security reviewer or admin.
    Approved,
    /// Rejected by a security reviewer or admin.
    Rejected,
    /// The mutation was rolled back after being applied.
    RolledBack,
    /// The request expired before being reviewed.
    Expired,
}

// ── ApprovalRequest ───────────────────────────────────────────────────────────

/// An approval request for a grant or policy mutation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalRequest {
    /// Request identifier.
    pub id: String,
    /// Type of mutation requested ("grant" or "policy").
    pub request_type: String,
    /// The target object identifier (grant ID or policy ID).
    pub target_id: String,
    /// The action being requested ("create", "update", "delete").
    pub action: String,
    /// The proposed payload (serialised grant or policy).
    pub payload: serde_json::Value,
    /// Current approval status.
    pub status: ApprovalStatus,
    /// Who requested this change.
    pub requested_by: String,
    /// Who approved or rejected this change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    /// Reviewer's comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_comment: Option<String>,
    /// When the request was created.
    pub created_at: DateTime<Utc>,
    /// When the request was last updated.
    pub updated_at: DateTime<Utc>,
    /// Optional expiry time for the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

// ── AuditEvidence ─────────────────────────────────────────────────────────────

/// A durable audit record capturing a control-plane state transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvidence {
    /// Audit record identifier.
    pub id: String,
    /// Type of event (e.g. "grant.created", "policy.rolled_back").
    pub event_type: String,
    /// The actor who performed the action.
    pub actor: String,
    /// The RBAC role of the actor at the time.
    pub role: String,
    /// The target object identifier.
    pub target_id: String,
    /// Hash of the previous state (SHA-256 hex, optional for creates).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_state_hash: Option<String>,
    /// Hash of the new state (SHA-256 hex, optional for deletes/rejects).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_state_hash: Option<String>,
    /// Decision outcome ("created", "approved", "rejected", "applied", "rolled_back").
    pub decision: String,
    /// Distributed trace identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Correlated API request identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Additional event payload (arbitrary JSON).
    #[serde(default)]
    pub payload: serde_json::Value,
}

// ── EvidenceExportRequest ─────────────────────────────────────────────────────

/// Request to export evidence for compliance or incident response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceExportRequest {
    /// Start of the time window (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<DateTime<Utc>>,
    /// End of the time window (exclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<DateTime<Utc>>,
    /// Desired export format.
    pub format: ExportFormat,
    /// Whether to redact secrets and arguments.
    #[serde(default = "default_redact")]
    pub redact: bool,
    /// Whether to include TrustCard summaries.
    #[serde(default = "default_true")]
    pub include_trust_cards: bool,
    /// Whether to include runtime health snapshots.
    #[serde(default = "default_true")]
    pub include_health: bool,
}

fn default_redact() -> bool {
    true
}

fn default_true() -> bool {
    true
}

// ── ExportFormat ──────────────────────────────────────────────────────────────

/// Format options for evidence export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// Newline-delimited JSON (one JSON object per line).
    Ndjson,
    /// Single JSON object bundle.
    JsonBundle,
}

// ── RuntimeHealth ─────────────────────────────────────────────────────────────

/// Runtime health status of a server or the gateway itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeHealth {
    /// Fully operational.
    Healthy,
    /// Operating but with degraded performance.
    Degraded,
    /// Not reachable or not running.
    Down,
    /// Health status is unknown (not yet checked).
    Unknown,
}

impl RuntimeHealth {
    /// Human-readable label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "Healthy",
            Self::Degraded => "Degraded",
            Self::Down => "Down",
            Self::Unknown => "Unknown",
        }
    }
}

// ── User ──────────────────────────────────────────────────────────────────────

/// A control-plane user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    /// User identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Assigned roles (e.g. ["admin"], ["developer"]).
    pub roles: Vec<String>,
    /// Group memberships.
    pub groups: Vec<String>,
    /// Optional email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether the user account is active.
    pub active: bool,
    /// When the user was created.
    pub created_at: DateTime<Utc>,
    /// When the user was last modified.
    pub updated_at: DateTime<Utc>,
}

// ── Group ─────────────────────────────────────────────────────────────────────

/// A control-plane group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    /// Group identifier.
    pub id: String,
    /// Group name.
    pub name: String,
    /// Group description.
    pub description: String,
    /// Member user identifiers.
    pub members: Vec<String>,
    /// When the group was created.
    pub created_at: DateTime<Utc>,
    /// When the group was last modified.
    pub updated_at: DateTime<Utc>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_utc() -> DateTime<Utc> {
        DateTime::from_timestamp(1736942400, 0).unwrap()
    }

    /// AC.1: Control-plane domain model serde round-trip tests for every object.
    /// CHECK: `cargo test --all-features control_plane_domain_roundtrip` exits 0
    #[test]
    fn control_plane_domain_roundtrip() {
        // ControlPlaneServer round-trip
        {
            let original = ControlPlaneServer {
                id: "srv-1".into(),
                name: "tavily-search".into(),
                transport: "streamable-http".into(),
                running: true,
                tool_count: 5,
                last_health_at: Some(test_utc()),
                health: RuntimeHealth::Healthy,
                labels: vec!["search".into(), "production".into()],
            };
            let json = serde_json::to_string(&original).expect("serialize ControlPlaneServer");
            let parsed: ControlPlaneServer =
                serde_json::from_str(&json).expect("deserialize ControlPlaneServer");
            assert_eq!(original, parsed, "ControlPlaneServer round-trip");
        }

        // ControlPlaneTool round-trip
        {
            let original = ControlPlaneTool {
                id: "tool-1".into(),
                name: "search_web".into(),
                server_id: "srv-1".into(),
                server_name: "tavily-search".into(),
                description: Some("Search the web".into()),
                input_schema: Some(serde_json::json!({"type": "object"})),
                enabled: true,
            };
            let json = serde_json::to_string(&original).expect("serialize ControlPlaneTool");
            let parsed: ControlPlaneTool =
                serde_json::from_str(&json).expect("deserialize ControlPlaneTool");
            assert_eq!(original, parsed, "ControlPlaneTool round-trip");
        }

        // TrustCardSummary round-trip
        {
            let original = TrustCardSummary {
                id: "tc-1".into(),
                subject_id: "srv-1".into(),
                subject_type: "server".into(),
                score: 0.85,
                verdict: "Trusted with caution".into(),
                evaluated_at: test_utc(),
                evaluator: "TrustLab".into(),
            };
            let json = serde_json::to_string(&original).expect("serialize TrustCardSummary");
            let parsed: TrustCardSummary =
                serde_json::from_str(&json).expect("deserialize TrustCardSummary");
            assert_eq!(original, parsed, "TrustCardSummary round-trip");
        }

        // EvaluationEvidence round-trip
        {
            let original = EvaluationEvidence {
                id: "ev-1".into(),
                trust_card_id: "tc-1".into(),
                evidence_type: "behavioural".into(),
                payload: serde_json::json!({"http_calls": 42}),
                collected_at: test_utc(),
                collector: "ShadowRadar".into(),
            };
            let json = serde_json::to_string(&original).expect("serialize EvaluationEvidence");
            let parsed: EvaluationEvidence =
                serde_json::from_str(&json).expect("deserialize EvaluationEvidence");
            assert_eq!(original, parsed, "EvaluationEvidence round-trip");
        }

        // IdentityGrant round-trip
        {
            let original = IdentityGrant {
                id: "grant-1".into(),
                name: "Developer Access".into(),
                description: Some("Read-only access for developers".into()),
                subject: "user:alice".into(),
                resource: "tool:search_*".into(),
                state: GrantState::Applied,
                previous_state: None,
                rollback_state: None,
                created_by: "admin".into(),
                created_at: test_utc(),
                updated_at: test_utc(),
                version: 1,
                metadata: serde_json::json!({}),
            };
            let json = serde_json::to_string(&original).expect("serialize IdentityGrant");
            let parsed: IdentityGrant =
                serde_json::from_str(&json).expect("deserialize IdentityGrant");
            assert_eq!(original, parsed, "IdentityGrant round-trip");
        }

        // PolicyBinding round-trip
        {
            let original = PolicyBinding {
                id: "pb-1".into(),
                name: "Search Allowlist".into(),
                policy_type: "tool_allowlist".into(),
                target: "server:brave".into(),
                rules: serde_json::json!({"allow": ["search_*"]}),
                priority: 10,
                enabled: true,
                created_by: "admin".into(),
                created_at: test_utc(),
                updated_at: test_utc(),
                version: 1,
            };
            let json = serde_json::to_string(&original).expect("serialize PolicyBinding");
            let parsed: PolicyBinding =
                serde_json::from_str(&json).expect("deserialize PolicyBinding");
            assert_eq!(original, parsed, "PolicyBinding round-trip");
        }

        // ApprovalRequest round-trip
        {
            let original = ApprovalRequest {
                id: "apr-1".into(),
                request_type: "grant".into(),
                target_id: "grant-1".into(),
                action: "create".into(),
                payload: serde_json::json!({"name": "Test Grant"}),
                status: ApprovalStatus::Pending,
                requested_by: "developer".into(),
                reviewed_by: None,
                reviewer_comment: None,
                created_at: test_utc(),
                updated_at: test_utc(),
                expires_at: None,
            };
            let json = serde_json::to_string(&original).expect("serialize ApprovalRequest");
            let parsed: ApprovalRequest =
                serde_json::from_str(&json).expect("deserialize ApprovalRequest");
            assert_eq!(original, parsed, "ApprovalRequest round-trip");
        }

        // AuditEvidence round-trip
        {
            let original = AuditEvidence {
                id: "audit-1".into(),
                event_type: "grant.created".into(),
                actor: "admin".into(),
                role: "admin".into(),
                target_id: "grant-1".into(),
                previous_state_hash: Some("sha256:abc123".into()),
                new_state_hash: Some("sha256:def456".into()),
                decision: "created".into(),
                trace_id: Some("trace-1".into()),
                request_id: Some("req-1".into()),
                timestamp: test_utc(),
                payload: serde_json::json!({"ip": "10.0.0.1"}),
            };
            let json = serde_json::to_string(&original).expect("serialize AuditEvidence");
            let parsed: AuditEvidence =
                serde_json::from_str(&json).expect("deserialize AuditEvidence");
            assert_eq!(original, parsed, "AuditEvidence round-trip");
        }

        // GrantState round-trip
        {
            for state in [
                GrantState::PendingApproval,
                GrantState::Applied,
                GrantState::Rejected,
                GrantState::RolledBack,
                GrantState::Expired,
            ] {
                let json = serde_json::to_string(&state).expect("serialize GrantState");
                let parsed: GrantState =
                    serde_json::from_str(&json).expect("deserialize GrantState");
                assert_eq!(state, parsed, "GrantState round-trip");
            }
        }

        // ApprovalStatus round-trip
        {
            for status in [
                ApprovalStatus::Pending,
                ApprovalStatus::Approved,
                ApprovalStatus::Rejected,
                ApprovalStatus::RolledBack,
                ApprovalStatus::Expired,
            ] {
                let json = serde_json::to_string(&status).expect("serialize ApprovalStatus");
                let parsed: ApprovalStatus =
                    serde_json::from_str(&json).expect("deserialize ApprovalStatus");
                assert_eq!(status, parsed, "ApprovalStatus round-trip");
            }
        }

        // RuntimeHealth round-trip
        {
            for health in [
                RuntimeHealth::Healthy,
                RuntimeHealth::Degraded,
                RuntimeHealth::Down,
                RuntimeHealth::Unknown,
            ] {
                let json = serde_json::to_string(&health).expect("serialize RuntimeHealth");
                let parsed: RuntimeHealth =
                    serde_json::from_str(&json).expect("deserialize RuntimeHealth");
                assert_eq!(health, parsed, "RuntimeHealth round-trip");
            }
        }

        // ExportFormat round-trip
        {
            for fmt in [ExportFormat::Ndjson, ExportFormat::JsonBundle] {
                let json = serde_json::to_string(&fmt).expect("serialize ExportFormat");
                let parsed: ExportFormat =
                    serde_json::from_str(&json).expect("deserialize ExportFormat");
                assert_eq!(fmt, parsed, "ExportFormat round-trip");
            }
        }

        // User round-trip
        {
            let original = User {
                id: "user-1".into(),
                name: "Alice Developer".into(),
                roles: vec!["developer".into()],
                groups: vec!["engineering".into()],
                email: Some("alice@example.com".into()),
                active: true,
                created_at: test_utc(),
                updated_at: test_utc(),
            };
            let json = serde_json::to_string(&original).expect("serialize User");
            let parsed: User = serde_json::from_str(&json).expect("deserialize User");
            assert_eq!(original, parsed, "User round-trip");
        }

        // Group round-trip
        {
            let original = Group {
                id: "group-1".into(),
                name: "Engineering".into(),
                description: "All engineering team members".into(),
                members: vec!["user-1".into(), "user-2".into()],
                created_at: test_utc(),
                updated_at: test_utc(),
            };
            let json = serde_json::to_string(&original).expect("serialize Group");
            let parsed: Group = serde_json::from_str(&json).expect("deserialize Group");
            assert_eq!(original, parsed, "Group round-trip");
        }

        // EvidenceExportRequest round-trip
        {
            let original = EvidenceExportRequest {
                from: None,
                to: None,
                format: ExportFormat::Ndjson,
                redact: true,
                include_trust_cards: true,
                include_health: false,
            };
            let json = serde_json::to_string(&original).expect("serialize EvidenceExportRequest");
            let parsed: EvidenceExportRequest =
                serde_json::from_str(&json).expect("deserialize EvidenceExportRequest");
            assert_eq!(parsed.format, ExportFormat::Ndjson);
            assert!(parsed.redact);
            assert!(!parsed.include_health);
        }
    }

    #[test]
    fn runtime_health_labels() {
        assert_eq!(RuntimeHealth::Healthy.label(), "Healthy");
        assert_eq!(RuntimeHealth::Degraded.label(), "Degraded");
        assert_eq!(RuntimeHealth::Down.label(), "Down");
        assert_eq!(RuntimeHealth::Unknown.label(), "Unknown");
    }
}