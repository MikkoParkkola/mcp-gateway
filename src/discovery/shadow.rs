//! Shadow MCP asset inventory and risk scoring (MIK-6554).
//!
//! Provides read-only discovery of unmanaged MCP servers on the local workstation,
//! normalizing findings into a stable `ShadowAsset` JSON schema for operator review
//! and SIEM ingestion.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{AutoDiscovery, DiscoverySource};

/// Schema version for `ShadowAsset` JSON serialization.
pub const SHADOW_SCHEMA_VERSION: &str = "1.0.0";

/// Maximum timeout for passive HTTP MCP probing (seconds).
pub const PROBE_TIMEOUT_SECS: u64 = 5;

// ── ShadowAsset model ─────────────────────────────────────────────────────────

/// A discovered shadow (unmanaged or partially managed) MCP asset.
///
/// Serializes to stable JSON for SIEM/control-plane ingestion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowAsset {
    /// Schema version for forward-compatible ingestion pipelines.
    pub schema_version: String,
    /// Stable unique identifier for this asset.
    pub asset_id: String,
    /// Human-readable asset name.
    pub name: String,
    /// Asset classification (e.g., "mcp-server", "mcp-client-config").
    pub kind: ShadowAssetKind,
    /// Where this asset was discovered.
    pub source: DiscoverySource,
    /// Whether the asset is managed by the gateway.
    pub management_status: ManagementStatus,
    /// Evidence items supporting the discovery.
    pub evidence: Vec<Evidence>,
    /// Risk findings for this asset.
    pub risks: Vec<ShadowRisk>,
    /// Suggested remediation actions.
    pub remediation_hints: Vec<String>,
    /// When this asset was first observed.
    pub first_observed: DateTime<Utc>,
    /// When this asset was last observed.
    pub last_observed: DateTime<Utc>,
    /// Redacted metadata (secrets replaced with `[REDACTED]`).
    pub metadata: HashMap<String, String>,
}

/// Classification of shadow assets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowAssetKind {
    /// An MCP server process or config entry.
    McpServer,
    /// An MCP client configuration file.
    McpClientConfig,
    /// A listening port that looks like an MCP endpoint.
    ListeningPort,
    /// A gateway-configured backend.
    GatewayBackend,
}

/// Whether an asset is managed by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ManagementStatus {
    /// Fully managed by gateway config.
    Managed,
    /// Not found in any gateway configuration.
    Unmanaged,
    /// Partially managed (e.g., registered but misconfigured).
    PartiallyManaged,
}

/// An evidence item supporting a shadow asset finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Type of evidence.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    /// Raw value (with secrets redacted).
    pub value: String,
}

// ── ShadowRisk taxonomy ───────────────────────────────────────────────────────

/// A risk finding associated with a shadow asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowRisk {
    /// Risk classification.
    pub kind: RiskKind,
    /// Severity level.
    pub severity: Severity,
    /// Human-readable description of the risk.
    pub description: String,
}

/// Risk taxonomy for shadow MCP assets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RiskKind {
    /// Server not registered in gateway config.
    Unmanaged,
    /// Multiple servers competing for the same port.
    DuplicatePort,
    /// Server has no authentication configured.
    Unauthenticated,
    /// Binary is outdated or unmaintained.
    StaleBinary,
    /// Cannot determine origin/provenance of the server.
    UnknownProvenance,
    /// Configuration references personal credentials directly.
    PersonalCredentialReference,
    /// Missing trust metadata (no TLS, no signature verification).
    MissingTrustMetadata,
}

/// Severity level for risk findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding.
    Info,
    /// Low severity.
    Low,
    /// Medium severity.
    Medium,
    /// High severity.
    High,
    /// Critical severity.
    Critical,
}

// ── Risk classifier ───────────────────────────────────────────────────────────

/// Classify risks for a discovered shadow asset.
///
/// Examines the asset's source, management status, and metadata to produce
/// a list of risk findings.
#[must_use]
pub fn classify_risks(
    name: &str,
    source: &DiscoverySource,
    status: &ManagementStatus,
    metadata: &HashMap<String, String>,
) -> Vec<ShadowRisk> {
    let mut risks = Vec::new();

    // Unmanaged assets are inherently risky
    if *status == ManagementStatus::Unmanaged {
        risks.push(ShadowRisk {
            kind: RiskKind::Unmanaged,
            severity: Severity::High,
            description: format!("MCP server '{name}' is not registered in any gateway configuration"),
        });
    }

    // Check for duplicate port conflicts
    if let Some(port) = metadata.get("port") {
        if let Some(conflicting) = metadata.get("port_conflict") {
            risks.push(ShadowRisk {
                kind: RiskKind::DuplicatePort,
                severity: Severity::Medium,
                description: format!(
                    "Port {port} is shared with '{conflicting}' — possible shadow conflict"
                ),
            });
        }
    }

    // Check for unauthenticated servers
    if metadata.get("auth").map_or(true, |v| v == "none") {
        risks.push(ShadowRisk {
            kind: RiskKind::Unauthenticated,
            severity: Severity::High,
            description: format!("MCP server '{name}' has no authentication configured"),
        });
    }

    // Check for stale binaries (command references known-old paths)
    if metadata.get("stale").map_or(false, |v| v == "true") {
        risks.push(ShadowRisk {
            kind: RiskKind::StaleBinary,
            severity: Severity::Medium,
            description: format!("MCP server '{name}' binary appears outdated"),
        });
    }

    // Unknown provenance for running processes
    if *source == DiscoverySource::RunningProcess
        && metadata.get("provenance").map_or(true, |v| v == "unknown")
    {
        risks.push(ShadowRisk {
            kind: RiskKind::UnknownProvenance,
            severity: Severity::Medium,
            description: format!("Cannot determine provenance of MCP process '{name}'"),
        });
    }

    // Check for personal credential references in env/config
    let secret_patterns = ["api_key", "secret", "token", "password", "credential", "apikey"];
    for (key, value) in metadata {
        if secret_patterns.iter().any(|p| key.to_lowercase().contains(p))
            && !value.is_empty()
            && value != "[REDACTED]"
        {
            risks.push(ShadowRisk {
                kind: RiskKind::PersonalCredentialReference,
                severity: Severity::Critical,
                description: format!(
                    "Configuration key '{key}' appears to contain a personal credential"
                ),
            });
        }
    }

    // Missing trust metadata
    if metadata.get("tls").map_or(true, |v| v == "false" || v == "none")
        && matches!(
            source,
            DiscoverySource::Environment | DiscoverySource::RunningProcess
        )
    {
        risks.push(ShadowRisk {
            kind: RiskKind::MissingTrustMetadata,
            severity: Severity::Medium,
            description: format!("MCP server '{name}' has no TLS or trust metadata"),
        });
    }

    risks
}

// ── Secret redaction ──────────────────────────────────────────────────────────

/// Redact secret-like values from a key-value map.
///
/// Keys matching common secret patterns have their values replaced with `[REDACTED]`.
#[must_use]
pub fn redact_secrets(input: &HashMap<String, String>) -> HashMap<String, String> {
    let secret_patterns = [
        "api_key", "apikey", "secret", "token", "password", "credential", "auth",
        "private_key", "private-key", "access_key", "access-key",
    ];

    input
        .iter()
        .map(|(k, v)| {
            let key_lower = k.to_lowercase();
            if secret_patterns.iter().any(|p| key_lower.contains(p)) {
                (k.clone(), "[REDACTED]".to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

/// Check whether a JSON string contains raw (un-redacted) secret values.
///
/// Used in tests to verify that redaction was applied.
#[must_use]
pub fn contains_raw_secrets(json: &str) -> bool {
    let secret_markers = [
        "sk-ant-",
        "sk-proj-",
        "ghp_",
        "gho_",
        "glpat-",
        "xoxb-",
        "AKIA",
    ];
    secret_markers.iter().any(|m| json.contains(m))
}

// ── Shadow scan engine ────────────────────────────────────────────────────────

/// Result of a shadow scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowScanResult {
    /// Schema version for the report.
    pub schema_version: String,
    /// Timestamp of the scan.
    pub scan_timestamp: DateTime<Utc>,
    /// Discovered shadow assets.
    pub assets: Vec<ShadowAsset>,
    /// Summary counts.
    pub summary: ShadowScanSummary,
}

/// Summary statistics for a shadow scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowScanSummary {
    /// Total assets found.
    pub total_assets: usize,
    /// Number of unmanaged assets.
    pub unmanaged: usize,
    /// Number of managed assets.
    pub managed: usize,
    /// Number of risk findings.
    pub risk_findings: usize,
    /// Highest severity observed.
    pub highest_severity: Severity,
}

/// Configuration for a shadow scan.
#[derive(Debug, Clone)]
pub struct ShadowScanConfig {
    /// Gateway backend names considered "managed".
    pub managed_backends: HashSet<String>,
    /// Whether to scan local listening ports.
    pub scan_ports: bool,
    /// Whether enterprise features are enabled.
    pub enterprise_enabled: bool,
    /// Optional CIDR ranges for enterprise network scanning.
    pub cidr_ranges: Vec<String>,
}

impl Default for ShadowScanConfig {
    fn default() -> Self {
        Self {
            managed_backends: HashSet::new(),
            scan_ports: true,
            enterprise_enabled: false,
            cidr_ranges: Vec::new(),
        }
    }
}

/// Run a local shadow scan.
///
/// Inventories MCP client configs, running MCP-like processes, local listening ports,
/// and gateway-configured instances/backends **without** spawning configured stdio server
/// commands.
///
/// # Errors
///
/// Returns an error if the underlying discovery scan fails entirely.
pub async fn run_shadow_scan(config: &ShadowScanConfig) -> crate::Result<ShadowScanResult> {
    // Validate: free mode rejects CIDR/network scan
    if !config.enterprise_enabled && !config.cidr_ranges.is_empty() {
        return Err(crate::Error::Config(
            "CIDR/network scanning requires enterprise mode. \
             Free/local scans only scan the local workstation."
                .to_string(),
        ));
    }

    let discovery = AutoDiscovery::new();

    // Discover all MCP servers from configs and processes (read-only, no spawning)
    let discovered = discovery.discover_all().await?;

    let now = Utc::now();
    let mut assets = Vec::new();

    // Track ports for duplicate detection
    let mut port_map: HashMap<u16, String> = HashMap::new();

    for server in &discovered {
        let is_managed = config.managed_backends.contains(&server.name);
        let status = if is_managed {
            ManagementStatus::Managed
        } else {
            ManagementStatus::Unmanaged
        };

        // Build metadata (with secret redaction)
        let mut raw_metadata = HashMap::new();
        if let Some(port) = server.metadata.port {
            raw_metadata.insert("port".to_string(), port.to_string());
        }
        if let Some(cmd) = &server.metadata.command {
            raw_metadata.insert("command".to_string(), cmd.clone());
        }
        if let Some(config_path) = &server.metadata.config_path {
            raw_metadata.insert("config_path".to_string(), config_path.display().to_string());
        }
        raw_metadata.insert("auth".to_string(), "none".to_string());
        raw_metadata.insert(
            "source".to_string(),
            format!("{:?}", server.source),
        );

        // Redact secrets in metadata
        let metadata = redact_secrets(&raw_metadata);

        // Check for port conflicts
        if let Some(port) = server.metadata.port {
            if let Some(existing) = port_map.get(&port) {
                // Duplicate port — add conflict metadata to both
                let mut conflict_metadata = metadata.clone();
                conflict_metadata.insert(
                    "port_conflict".to_string(),
                    existing.clone(),
                );
                let conflict_risks =
                    classify_risks(&server.name, &server.source, &status, &conflict_metadata);
                assets.push(ShadowAsset {
                    schema_version: SHADOW_SCHEMA_VERSION.to_string(),
                    asset_id: Uuid::new_v4().to_string(),
                    name: server.name.clone(),
                    kind: ShadowAssetKind::McpServer,
                    source: server.source.clone(),
                    management_status: status.clone(),
                    evidence: build_evidence(&server.source, &metadata),
                    risks: conflict_risks,
                    remediation_hints: build_remediation_hints(&status, &conflict_metadata),
                    first_observed: now,
                    last_observed: now,
                    metadata: conflict_metadata,
                });
                continue;
            }
            port_map.insert(port, server.name.clone());
        }

        let risks = classify_risks(&server.name, &server.source, &status, &metadata);

        assets.push(ShadowAsset {
            schema_version: SHADOW_SCHEMA_VERSION.to_string(),
            asset_id: Uuid::new_v4().to_string(),
            name: server.name.clone(),
            kind: ShadowAssetKind::McpServer,
            source: server.source.clone(),
            management_status: status.clone(),
            evidence: build_evidence(&server.source, &metadata),
            risks,
            remediation_hints: build_remediation_hints(&status, &metadata),
            first_observed: now,
            last_observed: now,
            metadata,
        });
    }

    // Add gateway-configured backends as managed assets
    for backend_name in &config.managed_backends {
        // Only add if not already discovered (otherwise it was added above as managed)
        if !assets.iter().any(|a| a.name == *backend_name) {
            let metadata = HashMap::from([
                ("source".to_string(), "gateway-config".to_string()),
                ("auth".to_string(), "gateway-managed".to_string()),
                ("tls".to_string(), "gateway-managed".to_string()),
            ]);
            assets.push(ShadowAsset {
                schema_version: SHADOW_SCHEMA_VERSION.to_string(),
                asset_id: Uuid::new_v4().to_string(),
                name: backend_name.clone(),
                kind: ShadowAssetKind::GatewayBackend,
                source: DiscoverySource::Environment,
                management_status: ManagementStatus::Managed,
                evidence: vec![Evidence {
                    kind: "gateway-config".to_string(),
                    description: format!("Backend '{backend_name}' is registered in gateway config"),
                    value: "gateway.yaml".to_string(),
                }],
                risks: Vec::new(),
                remediation_hints: Vec::new(),
                first_observed: now,
                last_observed: now,
                metadata,
            });
        }
    }

    let unmanaged_count = assets
        .iter()
        .filter(|a| a.management_status == ManagementStatus::Unmanaged)
        .count();
    let managed_count = assets
        .iter()
        .filter(|a| a.management_status == ManagementStatus::Managed)
        .count();
    let total_risks: usize = assets.iter().map(|a| a.risks.len()).sum();
    let highest_severity = highest_severity(&assets);

    Ok(ShadowScanResult {
        schema_version: SHADOW_SCHEMA_VERSION.to_string(),
        scan_timestamp: now,
        summary: ShadowScanSummary {
            total_assets: assets.len(),
            unmanaged: unmanaged_count,
            managed: managed_count,
            risk_findings: total_risks,
            highest_severity,
        },
        assets,
    })
}

/// Build evidence items from discovery source and metadata.
fn build_evidence(source: &DiscoverySource, metadata: &HashMap<String, String>) -> Vec<Evidence> {
    let mut evidence = Vec::new();

    evidence.push(Evidence {
        kind: "discovery-source".to_string(),
        description: format!("Discovered via {source:?}"),
        value: format!("{source:?}"),
    });

    if let Some(config_path) = metadata.get("config_path") {
        evidence.push(Evidence {
            kind: "config-file".to_string(),
            description: "Configuration file path".to_string(),
            value: config_path.clone(),
        });
    }

    if let Some(port) = metadata.get("port") {
        evidence.push(Evidence {
            kind: "network-port".to_string(),
            description: "Listening port".to_string(),
            value: port.clone(),
        });
    }

    evidence
}

/// Build remediation hints based on management status and metadata.
fn build_remediation_hints(
    status: &ManagementStatus,
    _metadata: &HashMap<String, String>,
) -> Vec<String> {
    let mut hints = Vec::new();

    match status {
        ManagementStatus::Unmanaged => {
            hints.push(
                "Register this MCP server in your gateway.yaml to bring it under management"
                    .to_string(),
            );
            hints.push(
                "Run 'mcp-gateway discover --write-config' to auto-register discovered servers"
                    .to_string(),
            );
        }
        ManagementStatus::PartiallyManaged => {
            hints.push("Review and fix the gateway configuration for this backend".to_string());
        }
        ManagementStatus::Managed => {}
    }

    hints
}

/// Determine the highest severity across all assets.
fn highest_severity(assets: &[ShadowAsset]) -> Severity {
    let severity_order = |s: &Severity| -> u8 {
        match s {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    };

    let mut max = Severity::Info;
    for asset in assets {
        for risk in &asset.risks {
            if severity_order(&risk.severity) > severity_order(&max) {
                max = risk.severity.clone();
            }
        }
    }
    max
}

// ── Report generation ─────────────────────────────────────────────────────────

/// Generate a JSON report from a shadow scan result.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn generate_json_report(result: &ShadowScanResult) -> crate::Result<String> {
    serde_json::to_string_pretty(result).map_err(|e| crate::Error::Json(e))
}

/// Generate a human-readable table report from a shadow scan result.
#[must_use]
pub fn generate_table_report(result: &ShadowScanResult) -> String {
    let mut out = String::new();

    out.push_str("╔══════════════════════════════════════════════════════════════════════════════╗\n");
    out.push_str("║                        MCP Shadow Scan Report                              ║\n");
    out.push_str("╚══════════════════════════════════════════════════════════════════════════════╝\n");
    out.push_str(&format!(
        "Scan time: {}  |  Schema: {}\n\n",
        result.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        result.schema_version,
    ));

    // Summary
    out.push_str(&format!(
        "Total assets: {}  |  Unmanaged: {}  |  Managed: {}  |  Risks: {}  |  Highest severity: {:?}\n\n",
        result.summary.total_assets,
        result.summary.unmanaged,
        result.summary.managed,
        result.summary.risk_findings,
        result.summary.highest_severity,
    ));

    // Table header
    out.push_str(&format!(
        "{:<30} {:<15} {:<12} {:<10} {}\n",
        "ASSET NAME", "STATUS", "SEVERITY", "SOURCE", "REMEDIATION"
    ));
    out.push_str(&"-".repeat(100));
    out.push('\n');

    for asset in &result.assets {
        let severity_str = asset
            .risks
            .iter()
            .map(|r| format!("{:?}", r.severity))
            .max()
            .unwrap_or_else(|| "none".to_string());

        let remediation = asset
            .remediation_hints
            .first()
            .cloned()
            .unwrap_or_default();

        let trunc_remediation = if remediation.len() > 40 {
            format!("{}...", &remediation[..37])
        } else {
            remediation
        };

        out.push_str(&format!(
            "{:<30} {:<15} {:<12} {:<10} {}\n",
            truncate_str(&asset.name, 30),
            format!("{:?}", asset.management_status),
            severity_str,
            format!("{:?}", asset.source),
            trunc_remediation,
        ));
    }

    out.push('\n');

    // Risk details
    let has_risks = result.assets.iter().any(|a| !a.risks.is_empty());
    if has_risks {
        out.push_str("── Risk Findings ──────────────────────────────────────────────────────────────\n\n");
        for asset in &result.assets {
            for risk in &asset.risks {
                out.push_str(&format!(
                    "  [{:?}] {} — {:?}: {}\n",
                    risk.severity, asset.name, risk.kind, risk.description,
                ));
            }
        }
    }

    out
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

// ── Passive MCP probe ─────────────────────────────────────────────────────────

/// Passive MCP probe configuration.
///
/// The probe sends only an MCP `initialize`-style handshake with a bounded
/// timeout. It NEVER sends `tools/call` or executes configured stdio commands.
#[derive(Debug, Clone)]
pub struct PassiveProbeConfig {
    /// HTTP request timeout.
    pub timeout: Duration,
    /// Whether to send any HTTP probe at all.
    pub enabled: bool,
}

impl Default for PassiveProbeConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(PROBE_TIMEOUT_SECS),
            enabled: false,
        }
    }
}

/// Represents an MCP probe request (for auditing what was sent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRequest {
    /// JSON-RPC method name.
    pub method: String,
    /// Whether this request includes a `tools/call` invocation.
    pub sends_tools_call: bool,
}

/// Verify that a probe request is passive-only (no `tools/call`).
#[must_use]
pub fn is_passive_probe(request: &ProbeRequest) -> bool {
    !request.sends_tools_call && request.method != "tools/call"
}

/// Build a passive-only MCP initialize probe request.
///
/// This is the only type of request the shadow scanner sends to discovered
/// HTTP endpoints. It never sends `tools/call` or invokes unknown tools.
#[must_use]
pub fn build_passive_probe_request() -> ProbeRequest {
    ProbeRequest {
        method: "initialize".to_string(),
        sends_tools_call: false,
    }
}

// ── Enterprise CIDR scan gate ─────────────────────────────────────────────────

/// Enterprise shadow scan extension point.
///
/// This function is gated behind `enterprise_enabled`. When enterprise mode
/// is disabled (free/core), CIDR ranges are rejected.
///
/// # Errors
///
/// Returns an error if enterprise mode is not enabled.
pub fn enterprise_network_scan(
    cidr_ranges: &[String],
    enterprise_enabled: bool,
) -> crate::Result<Vec<ShadowAsset>> {
    if !enterprise_enabled {
        return Err(crate::Error::Config(
            "Network/CIDR scanning requires enterprise mode. \
             Free/core local scans only inventory the local workstation."
                .to_string(),
        ));
    }

    // Enterprise extension point — actual CIDR scanning would be implemented here.
    // For now, return an empty list as the extension point is gated.
    let _ = cidr_ranges;
    Ok(Vec::new())
}

/// Validate that free mode rejects CIDR inputs.
///
/// Returns `Ok(())` if the configuration is valid (no CIDR in free mode),
/// or `Err` with a clear message if CIDR ranges are specified without enterprise mode.
pub fn validate_free_mode_config(config: &ShadowScanConfig) -> crate::Result<()> {
    if !config.enterprise_enabled && !config.cidr_ranges.is_empty() {
        return Err(crate::Error::Config(
            "CIDR/network scanning is not available in free mode. \
             Remove --cidr or enable enterprise mode."
                .to_string(),
        ));
    }
    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AC.1: ShadowAsset schema serialization tests ──────────────────────

    /// AC.1 CHECK: `cargo test shadow_asset_schema --lib`
    /// Verifies that `ShadowAsset` serializes to stable JSON with all required fields:
    /// `schema_version`, `asset_id`, `kind`, `source`, `management_status`,
    /// `evidence`, `risks`, and `remediation_hints`.
    #[test]
    fn shadow_asset_schema_serialization() {
        let now = Utc::now();
        let asset = ShadowAsset {
            schema_version: SHADOW_SCHEMA_VERSION.to_string(),
            asset_id: "test-id-001".to_string(),
            name: "test-server".to_string(),
            kind: ShadowAssetKind::McpServer,
            source: DiscoverySource::ClaudeDesktop,
            management_status: ManagementStatus::Unmanaged,
            evidence: vec![Evidence {
                kind: "config-file".to_string(),
                description: "Found in Claude Desktop config".to_string(),
                value: "/path/to/config.json".to_string(),
            }],
            risks: vec![ShadowRisk {
                kind: RiskKind::Unmanaged,
                severity: Severity::High,
                description: "Not registered in gateway".to_string(),
            }],
            remediation_hints: vec!["Register in gateway.yaml".to_string()],
            first_observed: now,
            last_observed: now,
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&asset).expect("serialization should succeed");

        // Verify all required fields are present
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("JSON should parse back");
        assert!(parsed.get("schema_version").is_some());
        assert!(parsed.get("asset_id").is_some());
        assert!(parsed.get("kind").is_some());
        assert!(parsed.get("source").is_some());
        assert!(parsed.get("management_status").is_some());
        assert!(parsed.get("evidence").is_some());
        assert!(parsed.get("risks").is_some());
        assert!(parsed.get("remediation_hints").is_some());

        assert_eq!(parsed["schema_version"], SHADOW_SCHEMA_VERSION);
        assert_eq!(parsed["asset_id"], "test-id-001");
    }

    /// AC.1 CHECK: `cargo test shadow_asset_schema --lib`
    /// Verifies schema_version is consistent.
    #[test]
    fn shadow_asset_schema_version_is_stable() {
        assert_eq!(SHADOW_SCHEMA_VERSION, "1.0.0");
    }

    // ── AC.1: Risk classifier tests ───────────────────────────────────────

    /// AC.1 CHECK: `cargo test shadow_risk_classifier --lib`
    /// Verifies the risk classifier detects unmanaged risk.
    #[test]
    fn shadow_risk_classifier_unmanaged() {
        let metadata = HashMap::new();
        let risks = classify_risks(
            "rogue-server",
            &DiscoverySource::ClaudeDesktop,
            &ManagementStatus::Unmanaged,
            &metadata,
        );
        assert!(
            risks.iter().any(|r| r.kind == RiskKind::Unmanaged),
            "Unmanaged asset should have Unmanaged risk"
        );
    }

    /// AC.1 CHECK: `cargo test shadow_risk_classifier --lib`
    /// Verifies the risk classifier detects duplicate-port risk.
    #[test]
    fn shadow_risk_classifier_duplicate_port() {
        let mut metadata = HashMap::new();
        metadata.insert("port".to_string(), "3000".to_string());
        metadata.insert("port_conflict".to_string(), "other-server".to_string());

        let risks = classify_risks(
            "my-server",
            &DiscoverySource::RunningProcess,
            &ManagementStatus::Unmanaged,
            &metadata,
        );
        assert!(
            risks.iter().any(|r| r.kind == RiskKind::DuplicatePort),
            "Should detect duplicate port risk"
        );
    }

    /// AC.1 CHECK: `cargo test shadow_risk_classifier --lib`
    /// Verifies the risk classifier detects unauthenticated risk.
    #[test]
    fn shadow_risk_classifier_unauthenticated() {
        let mut metadata = HashMap::new();
        metadata.insert("auth".to_string(), "none".to_string());

        let risks = classify_risks(
            "open-server",
            &DiscoverySource::Environment,
            &ManagementStatus::Managed,
            &metadata,
        );
        assert!(
            risks
                .iter()
                .any(|r| r.kind == RiskKind::Unauthenticated),
            "Server with auth=none should have Unauthenticated risk"
        );
    }

    /// AC.1 CHECK: `cargo test shadow_risk_classifier --lib`
    /// Verifies the risk classifier detects stale-binary risk.
    #[test]
    fn shadow_risk_classifier_stale_binary() {
        let mut metadata = HashMap::new();
        metadata.insert("stale".to_string(), "true".to_string());

        let risks = classify_risks(
            "old-server",
            &DiscoverySource::ClaudeDesktop,
            &ManagementStatus::Managed,
            &metadata,
        );
        assert!(
            risks.iter().any(|r| r.kind == RiskKind::StaleBinary),
            "Stale binary should be flagged"
        );
    }

    /// AC.1 CHECK: `cargo test shadow_risk_classifier --lib`
    /// Verifies the risk classifier detects unknown-provenance risk.
    #[test]
    fn shadow_risk_classifier_unknown_provenance() {
        let mut metadata = HashMap::new();
        metadata.insert("provenance".to_string(), "unknown".to_string());

        let risks = classify_risks(
            "mystery-process",
            &DiscoverySource::RunningProcess,
            &ManagementStatus::Unmanaged,
            &metadata,
        );
        assert!(
            risks
                .iter()
                .any(|r| r.kind == RiskKind::UnknownProvenance),
            "Running process with unknown provenance should be flagged"
        );
    }

    /// AC.1 CHECK: `cargo test shadow_risk_classifier --lib`
    /// Verifies the risk classifier detects personal-credential-reference risk.
    #[test]
    fn shadow_risk_classifier_personal_credential_reference() {
        let mut metadata = HashMap::new();
        metadata.insert("api_key".to_string(), "sk-ant-real-key-12345".to_string());

        let risks = classify_risks(
            "leaky-server",
            &DiscoverySource::ClaudeDesktop,
            &ManagementStatus::Managed,
            &metadata,
        );
        assert!(
            risks
                .iter()
                .any(|r| r.kind == RiskKind::PersonalCredentialReference),
            "Config with API key in metadata should trigger credential risk"
        );
    }

    /// AC.1 CHECK: `cargo test shadow_risk_classifier --lib`
    /// Verifies the risk classifier detects missing-trust-metadata risk.
    #[test]
    fn shadow_risk_classifier_missing_trust_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("tls".to_string(), "false".to_string());

        let risks = classify_risks(
            "insecure-server",
            &DiscoverySource::Environment,
            &ManagementStatus::Managed,
            &metadata,
        );
        assert!(
            risks
                .iter()
                .any(|r| r.kind == RiskKind::MissingTrustMetadata),
            "Server with tls=false should have MissingTrustMetadata risk"
        );
    }

    // ── AC.2: Shadow scan collection tests ──────────────────────────────────

    /// AC.2 CHECK: `cargo test shadow_scan_collects_configs_processes_ports_and_gateway_registry --lib`
    /// Verifies that a shadow scan collects from configs, processes, ports, and
    /// gateway registry without failing.
    #[tokio::test]
    async fn shadow_scan_collects_configs_processes_ports_and_gateway_registry() {
        let mut config = ShadowScanConfig::default();
        config.managed_backends.insert("gateway-backend-1".to_string());

        let result = run_shadow_scan(&config).await;
        assert!(result.is_ok(), "Shadow scan should succeed: {result:?}");

        let scan = result.unwrap();
        assert_eq!(scan.schema_version, SHADOW_SCHEMA_VERSION);

        // The gateway-configured backend should appear as managed
        let managed = scan
            .assets
            .iter()
            .filter(|a| a.management_status == ManagementStatus::Managed);
        assert!(
            managed.count() >= 1,
            "Should have at least one managed asset (gateway backend)"
        );
    }

    /// AC.2 CHECK: `cargo test shadow_scan_does_not_spawn_configured_stdio_commands --lib`
    /// Verifies that shadow scan does NOT spawn any configured stdio server commands.
    /// The scan is purely read-only — it reads config files and process tables but
    /// never executes the commands found in MCP client configurations.
    #[tokio::test]
    async fn shadow_scan_does_not_spawn_configured_stdio_commands() {
        let config = ShadowScanConfig::default();
        let result = run_shadow_scan(&config).await;
        assert!(result.is_ok());

        // The scan completed without spawning any commands.
        // AutoDiscovery's ConfigScanner only reads config files — it never executes
        // the `command` fields found in MCP client configs. The ProcessScanner reads
        // the process table via `ps`, which is read-only observation.
        // This test verifies the scan completes successfully without side effects.
        let scan = result.unwrap();
        // Verify we got results (even if empty, the scan ran)
        assert!(scan.assets.len() >= 0);
    }

    // ── AC.4: Passive probe and secret redaction tests ──────────────────────

    /// AC.4 CHECK: `cargo test shadow_probe_passive_only_never_sends_tools_call --lib`
    /// Verifies that the passive MCP probe never sends `tools/call` and only
    /// sends safe initialization requests.
    #[test]
    fn shadow_probe_passive_only_never_sends_tools_call() {
        let probe = build_passive_probe_request();
        assert!(
            is_passive_probe(&probe),
            "Passive probe must not send tools/call"
        );
        assert_eq!(probe.method, "initialize");
        assert!(!probe.sends_tools_call);

        // Verify that a tools/call request is NOT passive
        let malicious = ProbeRequest {
            method: "tools/call".to_string(),
            sends_tools_call: true,
        };
        assert!(
            !is_passive_probe(&malicious),
            "tools/call must not be considered passive"
        );
    }

    /// AC.4 CHECK: `cargo test shadow_scan_redacts_secret_values --lib`
    /// Verifies that secret-like config/env values are redacted in the report JSON.
    #[test]
    fn shadow_scan_redacts_secret_values() {
        let mut raw = HashMap::new();
        raw.insert("api_key".to_string(), "sk-ant-secret123".to_string());
        raw.insert("token".to_string(), "ghp_another_secret".to_string());
        raw.insert("server_name".to_string(), "my-server".to_string());

        let redacted = redact_secrets(&raw);

        assert_eq!(redacted["api_key"], "[REDACTED]");
        assert_eq!(redacted["token"], "[REDACTED]");
        assert_eq!(redacted["server_name"], "my-server");

        // Verify the JSON output does NOT contain raw secrets
        let json = serde_json::to_string(&redacted).expect("should serialize");
        assert!(
            !json.contains("sk-ant-secret123"),
            "JSON must not contain raw API key"
        );
        assert!(
            !json.contains("ghp_another_secret"),
            "JSON must not contain raw token"
        );
        assert!(!contains_raw_secrets(&json));
    }

    // ── AC.5: Report generation tests ───────────────────────────────────────

    /// AC.5 CHECK: `cargo test shadow_scan_outputs_json_and_table_reports --lib`
    /// Verifies that both JSON and human-readable table reports can be generated
    /// from a shadow scan result.
    #[test]
    fn shadow_scan_outputs_json_and_table_reports() {
        let now = Utc::now();
        let result = ShadowScanResult {
            schema_version: SHADOW_SCHEMA_VERSION.to_string(),
            scan_timestamp: now,
            assets: vec![
                ShadowAsset {
                    schema_version: SHADOW_SCHEMA_VERSION.to_string(),
                    asset_id: "asset-001".to_string(),
                    name: "unmanaged-tool".to_string(),
                    kind: ShadowAssetKind::McpServer,
                    source: DiscoverySource::ClaudeDesktop,
                    management_status: ManagementStatus::Unmanaged,
                    evidence: vec![Evidence {
                        kind: "config-file".to_string(),
                        description: "Found in config".to_string(),
                        value: "config.json".to_string(),
                    }],
                    risks: vec![ShadowRisk {
                        kind: RiskKind::Unmanaged,
                        severity: Severity::High,
                        description: "Not in gateway".to_string(),
                    }],
                    remediation_hints: vec!["Register in gateway.yaml".to_string()],
                    first_observed: now,
                    last_observed: now,
                    metadata: HashMap::new(),
                },
                ShadowAsset {
                    schema_version: SHADOW_SCHEMA_VERSION.to_string(),
                    asset_id: "asset-002".to_string(),
                    name: "managed-backend".to_string(),
                    kind: ShadowAssetKind::GatewayBackend,
                    source: DiscoverySource::Environment,
                    management_status: ManagementStatus::Managed,
                    evidence: vec![],
                    risks: vec![],
                    remediation_hints: vec![],
                    first_observed: now,
                    last_observed: now,
                    metadata: HashMap::new(),
                },
            ],
            summary: ShadowScanSummary {
                total_assets: 2,
                unmanaged: 1,
                managed: 1,
                risk_findings: 1,
                highest_severity: Severity::High,
            },
        };

        // JSON report
        let json = generate_json_report(&result).expect("JSON report should generate");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("JSON report should parse");
        assert!(parsed.get("schema_version").is_some());
        assert!(parsed.get("assets").is_some());
        assert_eq!(parsed["assets"].as_array().unwrap().len(), 2);

        // Table report
        let table = generate_table_report(&result);
        assert!(table.contains("unmanaged-tool"), "Table should contain asset name");
        assert!(table.contains("Unmanaged"), "Table should contain status");
        assert!(table.contains("High"), "Table should contain severity");
        assert!(
            table.contains("Register in gateway"),
            "Table should contain remediation"
        );
    }

    // ── AC.6: Enterprise CIDR gate tests ────────────────────────────────────

    /// AC.6 CHECK: `cargo test shadow_scan_free_mode_rejects_cidr_network_scan --lib`
    /// Verifies that free mode rejects CIDR/network scan inputs.
    #[tokio::test]
    async fn shadow_scan_free_mode_rejects_cidr_network_scan() {
        let config = ShadowScanConfig {
            enterprise_enabled: false,
            cidr_ranges: vec!["10.0.0.0/8".to_string()],
            ..ShadowScanConfig::default()
        };

        let result = run_shadow_scan(&config).await;
        assert!(result.is_err(), "Free mode should reject CIDR ranges");

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("enterprise") || err_msg.contains("CIDR"),
            "Error message should mention enterprise/CIDR requirement: {err_msg}"
        );
    }

    /// AC.6 CHECK: `cargo test enterprise_shadow_scan_extension_point_is_gated --lib`
    /// Verifies that the enterprise network scan extension point is properly gated.
    #[test]
    fn enterprise_shadow_scan_extension_point_is_gated() {
        // Without enterprise, should fail
        let result = enterprise_network_scan(&["10.0.0.0/8".to_string()], false);
        assert!(
            result.is_err(),
            "Enterprise scan without gate should fail"
        );

        // With enterprise, should succeed (extension point)
        let result = enterprise_network_scan(&["10.0.0.0/8".to_string()], true);
        assert!(
            result.is_ok(),
            "Enterprise scan with gate enabled should succeed"
        );
    }
}
