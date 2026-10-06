// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Passive `ShadowRadar` report model for unmanaged MCP discovery.
//!
//! The report builder only normalizes already-discovered config/process
//! evidence. It never handshakes with, lists tools from, or invokes a
//! discovered server.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::config::TransportConfig;

use super::{DiscoveredServer, DiscoverySource};

mod build;
mod helpers;
use helpers::{
    build_action_groups, classify_data_risk, classify_ownership, classify_remediation,
    classify_severity, ensure_unique_ids, evidence_refs, executable_name, is_loopback_url,
    risk_reasons, sanitize_url, stable_shadow_id,
};

/// Stable schema version for `ShadowRadar` reports.
pub const SHADOW_REPORT_SCHEMA_VERSION: &str = "shadow_radar.v1";

/// Stable schema version for derived consumer handoff feeds.
pub const SHADOW_HANDOFF_SCHEMA_VERSION: &str = "shadow_radar.handoff.v1";

/// Stable schema version for the enterprise-boundary contract.
pub const SHADOW_ENTERPRISE_BOUNDARY_SCHEMA_VERSION: &str = "shadow_radar.enterprise_boundary.v1";

/// Passive local `ShadowRadar` report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowScanReport {
    /// Stable report schema.
    pub schema_version: String,
    /// License tier for this report mode.
    pub license_tier: ShadowLicenseTier,
    /// Scanner mode.
    pub mode: ShadowScanMode,
    /// True when no active probes or tool invocations were performed.
    pub passive: bool,
    /// True only if the scanner invoked discovered tools.
    pub tools_invoked: bool,
    /// Summary counts for dashboards and doctor output.
    pub summary: ShadowScanSummary,
    /// Unmanaged assets, sorted by stable id.
    pub assets: Vec<ShadowAsset>,
    /// Actionability-first grouping for humans and control planes.
    pub action_groups: Vec<ShadowActionGroup>,
}

/// License tier for the scan surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowLicenseTier {
    /// Workstation-local passive discovery ships in the free/core product.
    FreeCore,
    /// Fleet, SIEM, scheduled drift, and policy remediation belong to enterprise.
    Enterprise,
}

/// Scan mode used for this report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowScanMode {
    /// Local configs, local process table, and environment hints only.
    LocalPassive,
    /// Placeholder for scheduled fleet inventory and drift evidence.
    EnterpriseFleet,
}

/// Report summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowScanSummary {
    /// Count of discovered assets before registered-backend filtering.
    pub discovered_total: usize,
    /// Count already registered in gateway config.
    pub managed_total: usize,
    /// Count missing from gateway config.
    pub unmanaged_total: usize,
    /// Count with high or critical severity.
    pub high_or_critical_total: usize,
    /// Count that can be adopted through the gateway config path.
    pub adoptable_total: usize,
    /// Count of unmanaged HTTP endpoints that are not loopback-local.
    pub network_exposed_total: usize,
}

/// Actionability grouping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowActionGroup {
    /// Recommended action.
    pub action: ShadowRemediationAction,
    /// Number of assets in this group.
    pub count: usize,
    /// Stable asset ids in this group.
    pub asset_ids: Vec<String>,
}

/// One unmanaged MCP asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowAsset {
    /// Stable id for diffing repeated reports.
    pub id: String,
    /// Stable id alias for external ingestion contracts.
    pub asset_id: String,
    /// Stable asset kind for SIEM and control-plane ingestion.
    pub kind: String,
    /// Discovered server name.
    pub name: String,
    /// Human-readable description from the source.
    pub description: String,
    /// Discovery source.
    pub source: DiscoverySource,
    /// Ownership inference.
    pub ownership: ShadowOwnership,
    /// Transport summary with private URL parts removed.
    pub transport: ShadowTransport,
    /// Auth exposure classification.
    pub auth_exposure: ShadowAuthExposure,
    /// Gateway trust status.
    pub trust_status: ShadowTrustStatus,
    /// Stable management status for public JSON consumers.
    pub management_status: String,
    /// Data risk classification.
    pub data_risk: ShadowDataRisk,
    /// Severity of this unmanaged asset.
    pub severity: ShadowRiskSeverity,
    /// Evidence that does not include command arguments or private URL values.
    pub evidence: ShadowEvidence,
    /// Recommended next step.
    pub remediation: ShadowRemediation,
    /// Short, stable reasons behind the classification.
    pub risk_reasons: Vec<String>,
    /// Structured risk taxonomy for downstream ingestion.
    pub risks: Vec<ShadowRiskFinding>,
    /// Human-safe remediation hints.
    pub remediation_hints: Vec<String>,
}

/// Structured risk finding for a `ShadowAsset`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowRiskFinding {
    /// Stable machine code.
    pub code: String,
    /// Severity inherited from the asset classification.
    pub severity: ShadowRiskSeverity,
    /// Human-readable description.
    pub detail: String,
}

/// Ownership inference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowOwnership {
    /// Asset came from a client config file.
    ClientConfig,
    /// Asset came from the local process table.
    LocalProcess,
    /// Asset came from an environment variable.
    Environment,
    /// Owner cannot be inferred from passive evidence.
    Unknown,
}

/// Transport evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowTransport {
    /// Transport kind: stdio, http, websocket, or a2a.
    pub kind: String,
    /// Sanitized endpoint. Userinfo, query, and fragment are removed.
    pub endpoint: Option<String>,
    /// True for loopback HTTP endpoints or local stdio processes.
    pub local_only: bool,
}

/// Auth exposure classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowAuthExposure {
    /// Stdio transport runs locally and has no transport-auth signal.
    StdioProcess,
    /// Loopback HTTP endpoint with no auth metadata visible in passive scan.
    LocalHttpNoAuthMetadata,
    /// Non-loopback HTTP endpoint with no auth metadata visible in passive scan.
    NetworkHttpNoAuthMetadata,
    /// HTTP endpoint whose client config sends an auth header, judged by key
    /// name only. A passive scan cannot verify the server enforces it.
    HttpAuthHeader,
    /// Transport cannot be classified.
    Unknown,
}

/// Gateway trust status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowTrustStatus {
    /// Asset is not registered in the gateway config used for comparison.
    Unmanaged,
}

/// Data risk classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowDataRisk {
    /// Passive evidence did not reveal a known sensitive domain.
    Unknown,
    /// Passive evidence suggests personal, business, or private data access.
    SensitiveData,
    /// Passive evidence suggests filesystem, browser, shell, or elevated access.
    HighPrivilege,
}

/// Severity classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ShadowRiskSeverity {
    /// Informational local unmanaged asset.
    Low,
    /// Needs owner review before becoming production dependency.
    Medium,
    /// Sensitive or network-exposed unmanaged asset.
    High,
    /// Sensitive unmanaged asset reachable beyond loopback.
    Critical,
}

/// Recommended action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ShadowRemediationAction {
    /// Ignore with a documented reason.
    IgnoreWithReason,
    /// Adopt into gateway config after review.
    AdoptIntoGateway,
    /// Ask a human to confirm the owner and intended use.
    RequestOwner,
    /// Quarantine or restrict until auth/trust is proven.
    Quarantine,
    /// Disable a stale or risky endpoint after approval.
    Disable,
    /// Enterprise policy workflow for fleet, SIEM, or owner assignment.
    EnterprisePolicyTicket,
}

/// Confidence in the recommended action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowConfidence {
    /// Passive evidence is strong enough for a deterministic suggestion.
    High,
    /// Passive evidence is useful but needs human confirmation.
    Medium,
    /// Passive evidence is weak.
    Low,
}

/// Remediation metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowRemediation {
    /// Recommended action.
    pub action: ShadowRemediationAction,
    /// Confidence in that action.
    pub confidence: ShadowConfidence,
    /// True when a human must approve before mutating config or runtime state.
    pub confirmation_required: bool,
    /// Whether an active probe is required before this can be trusted.
    pub active_probe_required: bool,
    /// Verification command or check.
    pub verification_step: String,
    /// Rollback step.
    pub rollback_step: String,
    /// Dry-run command for this class of finding.
    pub dry_run_command: Option<String>,
    /// Apply command when safe adoption is available.
    pub apply_command: Option<String>,
}

/// Passive evidence for a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowEvidence {
    /// Config path where the asset was found.
    pub config_path: Option<String>,
    /// Local process id.
    pub pid: Option<u32>,
    /// Detected port.
    pub port: Option<u16>,
    /// True when a command was present but arguments were intentionally omitted.
    pub command_present: bool,
    /// Executable basename only. Arguments are never included.
    pub executable: Option<String>,
    /// Sanitized endpoint if available.
    pub endpoint: Option<String>,
    /// Gateway config used for managed/unmanaged comparison.
    pub gateway_config: Option<String>,
}

/// Derived `ShadowRadar` feeds for product surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowConsumerHandoff {
    /// Stable handoff schema.
    pub schema_version: String,
    /// Source report schema used to build this handoff.
    pub source_report_schema: String,
    /// True when no active probes or tool invocations were performed.
    pub passive: bool,
    /// True only if the scanner invoked discovered tools.
    pub tools_invoked: bool,
    /// TrustCard-ready summaries keyed by `ShadowRadar` asset id.
    pub trustcard_inputs: Vec<ShadowTrustCardInput>,
    /// Doctor-ready findings keyed by `ShadowRadar` asset id.
    pub doctor_findings: Vec<ShadowDoctorFinding>,
    /// Control-plane inventory rows keyed by `ShadowRadar` asset id.
    pub control_plane_assets: Vec<ShadowControlPlaneAsset>,
    /// Enterprise-only extension boundary for fleet and SIEM consumers.
    pub enterprise_boundary: ShadowEnterpriseBoundary,
}

/// Explicit free/core versus enterprise separation for `ShadowRadar`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowEnterpriseBoundary {
    /// Stable boundary schema.
    pub schema_version: String,
    /// Current local scan contract.
    pub free_core_scan: ShadowScanBoundary,
    /// Enterprise scan contract for fleet-wide operation.
    pub enterprise_scan: ShadowScanBoundary,
    /// Enterprise-only capabilities intentionally absent from local scans.
    pub enterprise_capabilities: Vec<ShadowEnterpriseCapability>,
    /// Machine-readable evidence export contracts.
    pub evidence_exports: Vec<ShadowEvidenceExportContract>,
    /// Local passive unmanaged asset count copied from the source report.
    pub local_unmanaged_total: usize,
    /// Local passive network-exposed asset count copied from the source report.
    pub local_network_exposed_total: usize,
    /// True when enterprise policy automation must create an auditable event.
    pub audit_required: bool,
    /// True when remediation still needs owner or admin confirmation.
    pub human_approval_required: bool,
}

/// Scan behavior allowed at a license boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowScanBoundary {
    /// License tier that owns this scan behavior.
    pub license_tier: ShadowLicenseTier,
    /// Scan mode.
    pub mode: ShadowScanMode,
    /// Passive or active scan activity.
    pub activity: ShadowScanActivity,
    /// Capabilities available at this boundary.
    pub allowed_capabilities: Vec<ShadowScanCapability>,
    /// Capabilities intentionally unavailable at this boundary.
    pub denied_capabilities: Vec<ShadowScanCapability>,
}

/// Whether a scan is passive or may actively probe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowScanActivity {
    /// Reads already-observed evidence only.
    Passive,
}

/// Scan capability used in the license-boundary contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowScanCapability {
    /// Enumerate configured network ranges.
    NetworkRangeScan,
    /// Run on an automatic schedule.
    ScheduledScan,
    /// Aggregate more than one host or user.
    FleetScope,
    /// Invoke tools on discovered servers.
    ToolInvocation,
    /// Change gateway config or runtime state.
    ConfigMutation,
}

/// Enterprise-only `ShadowRadar` capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowEnterpriseCapability {
    /// Scan configured network ranges or fleet endpoints.
    NetworkRangeScan,
    /// Run inventory scans on an org-wide schedule.
    ScheduledFleetInventory,
    /// Record drift between repeated fleet scans.
    DriftEvidence,
    /// Export detection evidence to SIEM or WAF tooling.
    SiemExport,
    /// Assign findings to owners or groups.
    OwnerAssignment,
    /// Open or update policy remediation workflows.
    PolicyRemediation,
}

/// Evidence export contract for enterprise consumers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowEvidenceExportContract {
    /// Export capability.
    pub capability: ShadowEnterpriseCapability,
    /// Export schema or destination contract.
    pub schema_version: String,
    /// Export target class.
    pub target: String,
    /// True when this export is enterprise licensed.
    pub requires_enterprise_license: bool,
    /// True if export payloads can include sensitive values.
    pub sensitive_values_included: bool,
    /// Payload fields allowed by the contract.
    pub payload_scope: Vec<String>,
}

/// `ShadowRadar` fields needed to render a `TrustCard`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowTrustCardInput {
    /// `ShadowRadar` asset id.
    pub asset_id: String,
    /// Discovered server name.
    pub server_name: String,
    /// Transport kind.
    pub transport_kind: String,
    /// Sanitized endpoint, when the asset is HTTP/A2A backed.
    pub endpoint: Option<String>,
    /// Discovery source.
    pub source: DiscoverySource,
    /// Gateway trust status.
    pub trust_status: ShadowTrustStatus,
    /// Data risk classification.
    pub data_risk: ShadowDataRisk,
    /// Severity classification.
    pub severity: ShadowRiskSeverity,
    /// Stable classification reasons.
    pub risk_reasons: Vec<String>,
    /// Recommended next action.
    pub recommended_action: ShadowRemediationAction,
    /// Human-safe evidence pointers.
    pub evidence_refs: Vec<String>,
}

/// Doctor status for a `ShadowRadar` finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShadowDoctorStatus {
    /// Finding should be shown as informational.
    Info,
    /// Finding needs owner review before automated action.
    Warning,
    /// Finding should block silent adoption until reviewed.
    Critical,
}

/// `ShadowRadar` fields needed for doctor output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowDoctorFinding {
    /// Stable doctor finding id.
    pub finding_id: String,
    /// `ShadowRadar` asset id.
    pub asset_id: String,
    /// Doctor status.
    pub status: ShadowDoctorStatus,
    /// Short finding category.
    pub category: String,
    /// Human-readable finding detail.
    pub detail: String,
    /// Recommended next action.
    pub remediation_action: ShadowRemediationAction,
    /// Verification command or check.
    pub verification_step: String,
}

/// `ShadowRadar` fields needed by a control-plane inventory view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowControlPlaneAsset {
    /// `ShadowRadar` asset id.
    pub asset_id: String,
    /// Display name for the inventory row.
    pub display_name: String,
    /// Ownership inference.
    pub ownership: ShadowOwnership,
    /// Transport kind.
    pub transport_kind: String,
    /// True for loopback HTTP endpoints or local stdio processes.
    pub local_only: bool,
    /// Sanitized endpoint, when available.
    pub endpoint: Option<String>,
    /// Severity classification.
    pub severity: ShadowRiskSeverity,
    /// Recommended next action.
    pub recommended_action: ShadowRemediationAction,
    /// True when a human must approve before mutation.
    pub confirmation_required: bool,
    /// Human-safe evidence pointers.
    pub evidence_refs: Vec<String>,
}

impl ShadowTransport {
    fn from_transport(transport: &TransportConfig) -> Self {
        let (kind, url) = match transport {
            TransportConfig::Stdio { .. } => {
                return Self {
                    kind: "stdio".to_string(),
                    endpoint: None,
                    local_only: true,
                };
            }
            TransportConfig::Http { http_url, .. } => ("http", http_url),
            TransportConfig::WebSocket { ws_url, .. } => ("websocket", ws_url),
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => ("a2a", a2a_url),
        };
        Self {
            kind: kind.to_string(),
            endpoint: sanitize_url(url),
            local_only: is_loopback_url(url),
        }
    }
}

impl ShadowAuthExposure {
    /// The transport's exposure, unless an HTTP server is sent an auth header.
    /// Only header names are read: values are secrets (MIK-7716).
    fn from_server(server: &DiscoveredServer) -> Self {
        let exposure = Self::from_transport(&server.transport);
        let http = matches!(
            exposure,
            Self::LocalHttpNoAuthMetadata | Self::NetworkHttpNoAuthMetadata
        );
        if http && server.headers.keys().any(is_auth_header) {
            Self::HttpAuthHeader
        } else {
            exposure
        }
    }

    fn from_transport(transport: &TransportConfig) -> Self {
        match transport {
            TransportConfig::Stdio { .. } => Self::StdioProcess,
            TransportConfig::Http { http_url: url, .. }
            | TransportConfig::WebSocket { ws_url: url, .. } => {
                if is_loopback_url(url) {
                    Self::LocalHttpNoAuthMetadata
                } else {
                    Self::NetworkHttpNoAuthMetadata
                }
            }
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => {
                if is_loopback_url(a2a_url) {
                    Self::LocalHttpNoAuthMetadata
                } else {
                    Self::NetworkHttpNoAuthMetadata
                }
            }
        }
    }
}

impl ShadowEvidence {
    fn from_server(
        server: &DiscoveredServer,
        gateway_config: Option<&str>,
        endpoint: Option<&str>,
    ) -> Self {
        let executable = server.metadata.command.as_deref().and_then(executable_name);
        Self {
            config_path: server
                .metadata
                .config_path
                .as_ref()
                .map(|path| path.display().to_string()),
            pid: server.metadata.pid,
            port: server.metadata.port,
            command_present: server.metadata.command.is_some(),
            executable,
            endpoint: endpoint.map(ToOwned::to_owned),
            gateway_config: gateway_config.map(ToOwned::to_owned),
        }
    }
}

impl ShadowTrustCardInput {
    fn from_asset(asset: &ShadowAsset) -> Self {
        Self {
            asset_id: asset.id.clone(),
            server_name: asset.name.clone(),
            transport_kind: asset.transport.kind.clone(),
            endpoint: asset.transport.endpoint.clone(),
            source: asset.source.clone(),
            trust_status: asset.trust_status.clone(),
            data_risk: asset.data_risk.clone(),
            severity: asset.severity.clone(),
            risk_reasons: asset.risk_reasons.clone(),
            recommended_action: asset.remediation.action.clone(),
            evidence_refs: evidence_refs(asset),
        }
    }
}

impl ShadowDoctorFinding {
    fn from_asset(asset: &ShadowAsset) -> Self {
        let status = match asset.severity {
            ShadowRiskSeverity::Low => ShadowDoctorStatus::Info,
            ShadowRiskSeverity::Medium | ShadowRiskSeverity::High => ShadowDoctorStatus::Warning,
            ShadowRiskSeverity::Critical => ShadowDoctorStatus::Critical,
        };
        let category = match asset.remediation.action {
            ShadowRemediationAction::AdoptIntoGateway => "adoptable_shadow_asset",
            ShadowRemediationAction::Quarantine => "restricted_shadow_asset",
            ShadowRemediationAction::RequestOwner => "owner_review_required",
            ShadowRemediationAction::IgnoreWithReason => "documented_shadow_asset",
            ShadowRemediationAction::Disable => "disable_shadow_asset",
            ShadowRemediationAction::EnterprisePolicyTicket => "enterprise_policy_required",
        };

        Self {
            finding_id: format!("shadow-doctor:{}", asset.id),
            asset_id: asset.id.clone(),
            status,
            category: category.to_string(),
            detail: format!("{} is unmanaged via {}.", asset.name, asset.transport.kind),
            remediation_action: asset.remediation.action.clone(),
            verification_step: asset.remediation.verification_step.clone(),
        }
    }
}

impl ShadowControlPlaneAsset {
    fn from_asset(asset: &ShadowAsset) -> Self {
        Self {
            asset_id: asset.id.clone(),
            display_name: asset.name.clone(),
            ownership: asset.ownership.clone(),
            transport_kind: asset.transport.kind.clone(),
            local_only: asset.transport.local_only,
            endpoint: asset.transport.endpoint.clone(),
            severity: asset.severity.clone(),
            recommended_action: asset.remediation.action.clone(),
            confirmation_required: asset.remediation.confirmation_required,
            evidence_refs: evidence_refs(asset),
        }
    }
}

#[cfg(test)]
mod tests;

/// Header names that carry a client credential, compared case-insensitively.
fn is_auth_header(name: &str) -> bool {
    ["authorization", "proxy-authorization", "x-api-key"]
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
}
