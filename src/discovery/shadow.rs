//! Passive `ShadowRadar` report model for unmanaged MCP discovery.
//!
//! The report builder only normalizes already-discovered config/process
//! evidence. It never handshakes with, lists tools from, or invokes a
//! discovered server.

use std::{collections::HashSet, path::Path};

use serde::{Deserialize, Serialize};

use crate::config::TransportConfig;

use super::{DiscoveredServer, DiscoverySource};

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
    /// Transport kind: stdio, http, or a2a.
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

impl ShadowScanReport {
    /// Build a passive local report from discovered servers.
    #[must_use]
    pub fn from_discovered(
        discovered: &[DiscoveredServer],
        registered_names: &HashSet<String>,
        gateway_config_path: Option<&Path>,
    ) -> Self {
        let discovered_total = discovered.len();
        let managed_total = discovered
            .iter()
            .filter(|server| registered_names.contains(&server.name))
            .count();
        let gateway_config = gateway_config_path.map(|path| path.display().to_string());

        let mut assets: Vec<ShadowAsset> = discovered
            .iter()
            .filter(|server| !registered_names.contains(&server.name))
            .map(|server| ShadowAsset::from_server(server, gateway_config.as_deref()))
            .collect();

        assets.sort_by(|left, right| left.id.cmp(&right.id).then(left.name.cmp(&right.name)));
        ensure_unique_ids(&mut assets);

        let high_or_critical_total = assets
            .iter()
            .filter(|asset| {
                matches!(
                    asset.severity,
                    ShadowRiskSeverity::High | ShadowRiskSeverity::Critical
                )
            })
            .count();
        let adoptable_total = assets
            .iter()
            .filter(|asset| asset.remediation.action == ShadowRemediationAction::AdoptIntoGateway)
            .count();
        let network_exposed_total = assets
            .iter()
            .filter(|asset| asset.auth_exposure == ShadowAuthExposure::NetworkHttpNoAuthMetadata)
            .count();
        let action_groups = build_action_groups(&assets);

        Self {
            schema_version: SHADOW_REPORT_SCHEMA_VERSION.to_string(),
            license_tier: ShadowLicenseTier::FreeCore,
            mode: ShadowScanMode::LocalPassive,
            passive: true,
            tools_invoked: false,
            summary: ShadowScanSummary {
                discovered_total,
                managed_total,
                unmanaged_total: assets.len(),
                high_or_critical_total,
                adoptable_total,
                network_exposed_total,
            },
            assets,
            action_groups,
        }
    }

    /// Build typed handoff feeds for `TrustCard`, doctor, and control-plane UI consumers.
    #[must_use]
    pub fn consumer_handoff(&self) -> ShadowConsumerHandoff {
        ShadowConsumerHandoff {
            schema_version: SHADOW_HANDOFF_SCHEMA_VERSION.to_string(),
            source_report_schema: self.schema_version.clone(),
            passive: self.passive,
            tools_invoked: self.tools_invoked,
            trustcard_inputs: self
                .assets
                .iter()
                .map(ShadowTrustCardInput::from_asset)
                .collect(),
            doctor_findings: self
                .assets
                .iter()
                .map(ShadowDoctorFinding::from_asset)
                .collect(),
            control_plane_assets: self
                .assets
                .iter()
                .map(ShadowControlPlaneAsset::from_asset)
                .collect(),
        }
    }
}

impl ShadowAsset {
    fn from_server(server: &DiscoveredServer, gateway_config: Option<&str>) -> Self {
        let transport = ShadowTransport::from_transport(&server.transport);
        let auth_exposure = ShadowAuthExposure::from_transport(&server.transport);
        let data_risk = classify_data_risk(server);
        let ownership = classify_ownership(server);
        let severity = classify_severity(&auth_exposure, &data_risk);
        let remediation = classify_remediation(
            server,
            &auth_exposure,
            &data_risk,
            &ownership,
            gateway_config,
        );
        let evidence =
            ShadowEvidence::from_server(server, gateway_config, transport.endpoint.as_deref());
        let risk_reasons = risk_reasons(server, &auth_exposure, &data_risk, &ownership);
        let id = stable_shadow_id(server, &transport);

        Self {
            id,
            name: server.name.clone(),
            description: server.description.clone(),
            source: server.source.clone(),
            ownership,
            transport,
            auth_exposure,
            trust_status: ShadowTrustStatus::Unmanaged,
            data_risk,
            severity,
            evidence,
            remediation,
            risk_reasons,
        }
    }
}

impl ShadowTransport {
    fn from_transport(transport: &TransportConfig) -> Self {
        match transport {
            TransportConfig::Stdio { .. } => Self {
                kind: "stdio".to_string(),
                endpoint: None,
                local_only: true,
            },
            TransportConfig::Http { http_url, .. } => {
                let endpoint = sanitize_url(http_url);
                Self {
                    kind: "http".to_string(),
                    endpoint,
                    local_only: is_loopback_url(http_url),
                }
            }
            #[cfg(feature = "a2a")]
            TransportConfig::A2a { a2a_url, .. } => {
                let endpoint = sanitize_url(a2a_url);
                Self {
                    kind: "a2a".to_string(),
                    endpoint,
                    local_only: is_loopback_url(a2a_url),
                }
            }
        }
    }
}

impl ShadowAuthExposure {
    fn from_transport(transport: &TransportConfig) -> Self {
        match transport {
            TransportConfig::Stdio { .. } => Self::StdioProcess,
            TransportConfig::Http { http_url, .. } => {
                if is_loopback_url(http_url) {
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
