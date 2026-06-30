// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Enterprise ControlPlaneUI module.
//!
//! Provides a governance control plane for managing MCP servers, tools,
//! TrustCards, evaluation evidence, users/groups, grants, policies,
//! approvals, runtime health, and audit evidence.
//!
//! # License Tier
//!
//! This module is gated behind the Enterprise license tier.
//! Free/core exposes only read-only local status/summary surfaces.
//!
//! # Architecture
//!
//! - [`domain`] — Domain models with serde round-trip support (AC.1)
//! - [`storage`] — `ControlPlaneStore` trait + embedded backend (AC.6)
//! - [`rbac`] — Role-based access control (AC.3)
//! - [`license`] — Enterprise license boundary enforcement (AC.7)
//! - [`api`] — Read-only API routes + mutation stubs (AC.2)
//! - [`reconciler`] — Grant/policy reconciliation + approval + rollback (AC.4)
//! - [`evidence`] — Evidence export with redaction (AC.5)
//! - [`otel`] — OpenTelemetry/SIEM event export (AC.9)
//! - [`ui`] — Web UI integration (AC.8)

pub mod api;
pub mod domain;
pub mod evidence;
pub mod license;
pub mod otel;
pub mod rbac;
pub mod reconciler;
pub mod storage;
#[cfg(feature = "webui")]
pub mod ui;

// Re-export key types for convenience
pub use api::{ControlPlaneApiState, control_plane_router};
pub use domain::{
    ApprovalRequest, ApprovalStatus, AuditEvidence, ControlPlaneServer, ControlPlaneTool,
    EvaluationEvidence, EvidenceExportRequest, ExportFormat, GrantState, Group,
    IdentityGrant, PolicyBinding, RuntimeHealth, TrustCardSummary, User,
};
pub use evidence::{EvidenceExportBundle, EvidenceExporter, RedactedAuditEvidence};
pub use license::{GatedFeature, LicenseGate, LicenseTier};
pub use otel::{SiemEmitter, SiemEvent, TracingSiemEmitter, build_siem_event};
pub use rbac::{Action, RbacEngine, RbacResult, Role, check_rbac};
pub use reconciler::{ControlPlaneReconciler, ReconcilerError, ReconcilerResult};
pub use storage::{ControlPlaneStore, EmbeddedControlPlaneStore, StoreError, SCHEMA_VERSION};
#[cfg(feature = "webui")]
pub use ui::{control_plane_dashboard_handler, control_plane_web_router};
