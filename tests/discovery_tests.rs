//! Discovery module tests

use mcp_gateway::discovery::{
    AutoDiscovery, DiscoverySource,
    shadow::{
        ShadowAuthExposure, ShadowConsumerHandoff, ShadowDataRisk, ShadowDoctorStatus,
        ShadowEnterpriseBoundary, ShadowEnterpriseCapability, ShadowLicenseTier,
        ShadowRemediationAction, ShadowRiskSeverity, ShadowScanActivity, ShadowScanCapability,
        ShadowScanMode, ShadowScanReport,
    },
};

#[tokio::test]
async fn test_auto_discovery_initialization() {
    let discovery = AutoDiscovery::new();

    // Discovery should not panic on creation
    let result = discovery.discover_all().await;
    assert!(result.is_ok(), "Discovery should not fail: {result:?}");
}

#[tokio::test]
async fn test_discover_from_environment() {
    let discovery = AutoDiscovery::new();
    let result = discovery
        .discover_from_source(DiscoverySource::Environment)
        .await;

    // Should not fail even if no environment variables are set
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_discover_from_process() {
    let discovery = AutoDiscovery::new();

    // Process scanning should not panic even if no processes found
    let result = discovery
        .discover_from_source(DiscoverySource::RunningProcess)
        .await;

    assert!(result.is_ok(), "Process scanning should not fail");
}

#[tokio::test]
async fn test_discover_claude_desktop_config() {
    let discovery = AutoDiscovery::new();

    // Should handle missing config gracefully
    let result = discovery
        .discover_from_source(DiscoverySource::ClaudeDesktop)
        .await;

    assert!(
        result.is_ok(),
        "Should handle missing Claude Desktop config gracefully"
    );
}

#[tokio::test]
async fn test_discover_vscode_config() {
    let discovery = AutoDiscovery::new();

    // Should handle missing config gracefully
    let result = discovery
        .discover_from_source(DiscoverySource::VsCode)
        .await;

    assert!(
        result.is_ok(),
        "Should handle missing VS Code config gracefully"
    );
}

#[tokio::test]
async fn test_discover_mcp_config_dir() {
    let discovery = AutoDiscovery::new();

    // Should handle missing directory gracefully
    let result = discovery
        .discover_from_source(DiscoverySource::McpConfig)
        .await;

    assert!(
        result.is_ok(),
        "Should handle missing MCP config dir gracefully"
    );
}

#[tokio::test]
async fn test_discovered_server_to_backend_config() {
    use mcp_gateway::config::TransportConfig;
    use mcp_gateway::discovery::{DiscoveredServer, ServerMetadata};

    let server = DiscoveredServer {
        name: "test-server".to_string(),
        description: "Test Server".to_string(),
        source: DiscoverySource::Environment,
        transport: TransportConfig::Http {
            http_url: "http://localhost:3000".to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        metadata: ServerMetadata {
            config_path: None,
            pid: None,
            port: Some(3000),
            command: None,
            working_dir: None,
        },
    };

    let backend_config = server.to_backend_config();
    assert_eq!(backend_config.description, "Test Server");
    assert!(backend_config.enabled);

    match backend_config.transport {
        TransportConfig::Http { http_url, .. } => {
            assert_eq!(http_url, "http://localhost:3000");
        }
        TransportConfig::Stdio { .. } => panic!("Expected HTTP transport"),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { .. } => panic!("Expected HTTP transport"),
    }
}

#[tokio::test]
async fn test_deduplication() {
    let discovery = AutoDiscovery::new();
    let result = discovery.discover_all().await;

    assert!(result.is_ok());
    let servers = result.unwrap();

    // Check that duplicate names are deduplicated
    let mut names = std::collections::HashSet::new();
    for server in &servers {
        assert!(
            names.insert(server.name.clone()),
            "Found duplicate server name: {}",
            server.name
        );
    }
}

// ── Shadow detection unit tests ───────────────────────────────────────────────

/// Build a minimal `DiscoveredServer` with the given name.
fn make_discovered(name: &str) -> mcp_gateway::discovery::DiscoveredServer {
    use mcp_gateway::config::TransportConfig;
    use mcp_gateway::discovery::{DiscoveredServer, ServerMetadata};

    DiscoveredServer {
        name: name.to_string(),
        description: format!("{name} server"),
        source: DiscoverySource::Environment,
        transport: TransportConfig::Http {
            http_url: format!("http://localhost:3000/{name}"),
            streamable_http: false,
            protocol_version: None,
        },
        metadata: ServerMetadata::default(),
    }
}

fn make_stdio_discovered(name: &str, command: &str) -> mcp_gateway::discovery::DiscoveredServer {
    use mcp_gateway::config::TransportConfig;
    use mcp_gateway::discovery::{DiscoveredServer, ServerMetadata};

    DiscoveredServer {
        name: name.to_string(),
        description: format!("{name} server"),
        source: DiscoverySource::ClaudeCode,
        transport: TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        metadata: ServerMetadata {
            config_path: Some(std::path::PathBuf::from("/tmp/client-config.json")),
            pid: None,
            port: None,
            command: Some(command.to_string()),
            working_dir: None,
        },
    }
}

fn make_http_discovered(name: &str, url: &str) -> mcp_gateway::discovery::DiscoveredServer {
    use mcp_gateway::config::TransportConfig;
    use mcp_gateway::discovery::{DiscoveredServer, ServerMetadata};

    DiscoveredServer {
        name: name.to_string(),
        description: format!("{name} server"),
        source: DiscoverySource::Environment,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        metadata: ServerMetadata {
            config_path: None,
            pid: None,
            port: None,
            command: None,
            working_dir: None,
        },
    }
}

#[test]
fn shadow_filter_excludes_registered_servers() {
    // GIVEN: a set of registered backend names
    let registered: std::collections::HashSet<String> = ["tavily", "github"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    // AND: discovered servers that overlap with registered ones
    let discovered = vec![
        make_discovered("tavily"),
        make_discovered("github"),
        make_discovered("unregistered-tool"),
    ];

    // WHEN: filtering to shadow (unregistered) servers
    let shadows: Vec<_> = discovered
        .into_iter()
        .filter(|s| !registered.contains(&s.name))
        .collect();

    // THEN: only the unregistered server remains
    assert_eq!(shadows.len(), 1);
    assert_eq!(shadows[0].name, "unregistered-tool");
}

#[test]
fn shadow_filter_returns_all_when_no_registered() {
    // GIVEN: an empty registry (gateway config has no backends)
    let registered: std::collections::HashSet<String> = std::collections::HashSet::new();

    let discovered = vec![make_discovered("server-a"), make_discovered("server-b")];

    // WHEN: filtering
    let shadows: Vec<_> = discovered
        .into_iter()
        .filter(|s| !registered.contains(&s.name))
        .collect();

    // THEN: all discovered servers are returned as shadows
    assert_eq!(shadows.len(), 2);
}

#[test]
fn shadow_filter_returns_empty_when_all_registered() {
    // GIVEN: all discovered servers are already registered
    let registered: std::collections::HashSet<String> = ["alpha", "beta"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    let discovered = vec![make_discovered("alpha"), make_discovered("beta")];

    // WHEN: filtering
    let shadows: Vec<_> = discovered
        .into_iter()
        .filter(|s| !registered.contains(&s.name))
        .collect();

    // THEN: no shadows
    assert!(shadows.is_empty());
}

#[test]
fn shadow_filter_is_case_sensitive() {
    // GIVEN: registered name "Tavily" (different case)
    let registered: std::collections::HashSet<String> = ["Tavily"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    let discovered = vec![make_discovered("tavily")];

    // WHEN: filtering (case-sensitive comparison matches gateway config keys)
    let shadows: Vec<_> = discovered
        .into_iter()
        .filter(|s| !registered.contains(&s.name))
        .collect();

    // THEN: "tavily" (lowercase) is treated as unregistered
    assert_eq!(shadows.len(), 1);
}

#[test]
fn shadow_report_is_passive_and_excludes_registered_servers() {
    let registered: std::collections::HashSet<String> = ["managed"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let discovered = vec![
        make_discovered("managed"),
        make_stdio_discovered(
            "local-tool",
            "npx -y @example/mcp-server --private PRIVATEVALUE",
        ),
    ];

    let report = ShadowScanReport::from_discovered(
        &discovered,
        &registered,
        Some(std::path::Path::new("gateway.yaml")),
    );

    assert!(report.passive);
    assert!(!report.tools_invoked);
    assert_eq!(report.summary.discovered_total, 2);
    assert_eq!(report.summary.managed_total, 1);
    assert_eq!(report.summary.unmanaged_total, 1);
    assert_eq!(report.assets[0].name, "local-tool");
    assert_eq!(
        report.assets[0].remediation.action,
        ShadowRemediationAction::AdoptIntoGateway
    );
}

#[test]
fn shadow_scan_flags_unmanaged_fixture_with_reason_evidence_remediation() {
    let registered: std::collections::HashSet<String> = ["managed-gateway"]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let discovered = vec![
        make_stdio_discovered("managed-gateway", "managed-gateway-mcp"),
        make_stdio_discovered("unmanaged-local", "unmanaged-local-mcp"),
    ];

    let report = ShadowScanReport::from_discovered(
        &discovered,
        &registered,
        Some(std::path::Path::new("gateway.yaml")),
    );

    assert_eq!(report.summary.managed_total, 1);
    assert_eq!(report.summary.unmanaged_total, 1);
    let asset = &report.assets[0];
    assert_eq!(asset.name, "unmanaged-local");
    assert_eq!(asset.management_status, "unmanaged");
    assert!(
        asset
            .risk_reasons
            .iter()
            .any(|reason| reason == "not_registered_in_gateway_config")
    );
    assert!(asset.evidence.command_present);
    assert!(!asset.remediation.verification_step.is_empty());
    assert!(!asset.remediation_hints.is_empty());
    assert_eq!(
        asset.remediation.action,
        ShadowRemediationAction::AdoptIntoGateway
    );
}

#[test]
fn shadow_report_redacts_command_arguments_and_url_private_values() {
    let registered = std::collections::HashSet::new();
    let discovered = vec![
        make_stdio_discovered(
            "filesystem",
            "/usr/local/bin/mcp-files --private PRIVATEVALUE",
        ),
        make_http_discovered(
            "remote",
            "https://user:PRIVATEVALUE@example.com:8443/mcp?session=PRIVATEVALUE#frag",
        ),
    ];

    let report = ShadowScanReport::from_discovered(&discovered, &registered, None);
    let serialized = serde_json::to_string(&report).unwrap();

    assert!(!serialized.contains("PRIVATEVALUE"));
    assert!(!serialized.contains("session="));
    assert_eq!(
        report
            .assets
            .iter()
            .find(|asset| asset.name == "filesystem")
            .unwrap()
            .evidence
            .executable
            .as_deref(),
        Some("mcp-files")
    );
}

#[test]
fn shadow_report_classifies_network_sensitive_assets_as_critical() {
    let registered = std::collections::HashSet::new();
    let discovered = vec![make_http_discovered("gmail", "https://mcp.example.com/sse")];

    let report = ShadowScanReport::from_discovered(&discovered, &registered, None);
    let asset = &report.assets[0];

    assert_eq!(
        asset.auth_exposure,
        ShadowAuthExposure::NetworkHttpNoAuthMetadata
    );
    assert_eq!(asset.data_risk, ShadowDataRisk::SensitiveData);
    assert_eq!(asset.severity, ShadowRiskSeverity::Critical);
    assert_eq!(
        asset.remediation.action,
        ShadowRemediationAction::Quarantine
    );
    assert!(asset.remediation.confirmation_required);
    assert_eq!(report.summary.high_or_critical_total, 1);
    assert_eq!(report.summary.network_exposed_total, 1);
}

#[test]
fn shadow_report_groups_findings_by_actionability() {
    let registered = std::collections::HashSet::new();
    let discovered = vec![
        make_stdio_discovered("safe-local", "npx -y safe-local"),
        make_http_discovered("unknown-remote", "https://mcp.example.com/mcp"),
    ];

    let report = ShadowScanReport::from_discovered(&discovered, &registered, None);

    assert!(report.action_groups.iter().any(|group| {
        group.action == ShadowRemediationAction::AdoptIntoGateway && group.count == 1
    }));
    assert!(
        report.action_groups.iter().any(|group| {
            group.action == ShadowRemediationAction::Quarantine && group.count == 1
        })
    );
}

#[test]
fn shadow_report_ids_are_stable_for_same_input() {
    let registered = std::collections::HashSet::new();
    let discovered = vec![make_stdio_discovered("stable", "npx -y stable")];

    let left = ShadowScanReport::from_discovered(&discovered, &registered, None);
    let right = ShadowScanReport::from_discovered(&discovered, &registered, None);

    assert_eq!(left.assets[0].id, right.assets[0].id);
}

#[test]
fn shadow_consumer_handoff_projects_report_for_product_surfaces() {
    let registered = std::collections::HashSet::new();
    let discovered = vec![
        make_stdio_discovered("safe-local", "npx -y safe-local --private PRIVATEVALUE"),
        make_http_discovered(
            "gmail",
            "https://user:PRIVATEVALUE@mcp.example.com/sse?session=PRIVATEVALUE#frag",
        ),
    ];

    let report = ShadowScanReport::from_discovered(
        &discovered,
        &registered,
        Some(std::path::Path::new("gateway.yaml")),
    );
    let handoff = report.consumer_handoff();

    assert_handoff_inventory_shape(&handoff, &report);
    assert_enterprise_boundary(&handoff.enterprise_boundary, &report);
    assert_handoff_surfaces_are_sanitized(&handoff);
}

fn assert_handoff_inventory_shape(handoff: &ShadowConsumerHandoff, report: &ShadowScanReport) {
    assert_eq!(handoff.schema_version, "shadow_radar.handoff.v1");
    assert_eq!(handoff.source_report_schema, "shadow_radar.v1");
    assert!(handoff.passive);
    assert!(!handoff.tools_invoked);
    assert_eq!(handoff.trustcard_inputs.len(), report.assets.len());
    assert_eq!(handoff.doctor_findings.len(), report.assets.len());
    assert_eq!(handoff.control_plane_assets.len(), report.assets.len());
}

fn assert_enterprise_boundary(boundary: &ShadowEnterpriseBoundary, report: &ShadowScanReport) {
    assert_eq!(
        boundary.schema_version,
        "shadow_radar.enterprise_boundary.v1"
    );
    assert_free_core_scan_boundary(boundary);
    assert_enterprise_scan_boundary(boundary);
    assert_enterprise_evidence_boundary(boundary);
    assert_eq!(
        boundary.local_unmanaged_total,
        report.summary.unmanaged_total
    );
    assert_eq!(
        boundary.local_network_exposed_total,
        report.summary.network_exposed_total
    );
}

fn assert_free_core_scan_boundary(boundary: &ShadowEnterpriseBoundary) {
    assert_eq!(
        boundary.free_core_scan.license_tier,
        ShadowLicenseTier::FreeCore
    );
    assert_eq!(boundary.free_core_scan.mode, ShadowScanMode::LocalPassive);
    assert_eq!(
        boundary.free_core_scan.activity,
        ShadowScanActivity::Passive
    );
    assert!(boundary.free_core_scan.allowed_capabilities.is_empty());
    assert!(
        boundary
            .free_core_scan
            .denied_capabilities
            .contains(&ShadowScanCapability::NetworkRangeScan)
    );
    assert!(
        boundary
            .free_core_scan
            .denied_capabilities
            .contains(&ShadowScanCapability::ScheduledScan)
    );
    assert!(
        boundary
            .free_core_scan
            .denied_capabilities
            .contains(&ShadowScanCapability::FleetScope)
    );
    assert!(
        boundary
            .free_core_scan
            .denied_capabilities
            .contains(&ShadowScanCapability::ToolInvocation)
    );
    assert!(
        boundary
            .free_core_scan
            .denied_capabilities
            .contains(&ShadowScanCapability::ConfigMutation)
    );
}

fn assert_enterprise_scan_boundary(boundary: &ShadowEnterpriseBoundary) {
    assert_eq!(
        boundary.enterprise_scan.license_tier,
        ShadowLicenseTier::Enterprise
    );
    assert_eq!(
        boundary.enterprise_scan.mode,
        ShadowScanMode::EnterpriseFleet
    );
    assert_eq!(
        boundary.enterprise_scan.activity,
        ShadowScanActivity::Passive
    );
    assert!(
        boundary
            .enterprise_scan
            .allowed_capabilities
            .contains(&ShadowScanCapability::NetworkRangeScan)
    );
    assert!(
        boundary
            .enterprise_scan
            .allowed_capabilities
            .contains(&ShadowScanCapability::ScheduledScan)
    );
    assert!(
        boundary
            .enterprise_scan
            .allowed_capabilities
            .contains(&ShadowScanCapability::FleetScope)
    );
    assert!(
        boundary
            .enterprise_scan
            .denied_capabilities
            .contains(&ShadowScanCapability::ToolInvocation)
    );
    assert!(
        boundary
            .enterprise_scan
            .denied_capabilities
            .contains(&ShadowScanCapability::ConfigMutation)
    );
}

fn assert_enterprise_evidence_boundary(boundary: &ShadowEnterpriseBoundary) {
    assert!(
        boundary
            .enterprise_capabilities
            .contains(&ShadowEnterpriseCapability::SiemExport)
    );
    assert!(
        boundary
            .enterprise_capabilities
            .contains(&ShadowEnterpriseCapability::DriftEvidence)
    );
    assert!(
        boundary
            .evidence_exports
            .iter()
            .all(|export| export.requires_enterprise_license)
    );
    assert!(
        boundary
            .evidence_exports
            .iter()
            .all(|export| !export.sensitive_values_included)
    );
}

fn assert_handoff_surfaces_are_sanitized(handoff: &ShadowConsumerHandoff) {
    let local_card = handoff
        .trustcard_inputs
        .iter()
        .find(|card| card.server_name == "safe-local")
        .unwrap();
    assert_eq!(
        local_card.recommended_action,
        ShadowRemediationAction::AdoptIntoGateway
    );
    assert!(
        local_card
            .evidence_refs
            .iter()
            .any(|reference| reference == "executable:npx")
    );

    let remote_doctor = handoff
        .doctor_findings
        .iter()
        .find(|finding| finding.category == "restricted_shadow_asset")
        .unwrap();
    assert_eq!(remote_doctor.status, ShadowDoctorStatus::Critical);
    assert_eq!(
        remote_doctor.remediation_action,
        ShadowRemediationAction::Quarantine
    );

    let remote_inventory = handoff
        .control_plane_assets
        .iter()
        .find(|asset| asset.display_name == "gmail")
        .unwrap();
    assert!(!remote_inventory.local_only);
    assert!(remote_inventory.confirmation_required);
    assert_eq!(
        remote_inventory.endpoint.as_deref(),
        Some("https://mcp.example.com/sse")
    );

    let serialized = serde_json::to_string(&handoff).unwrap();
    assert!(!serialized.contains("PRIVATEVALUE"));
    assert!(!serialized.contains("session="));
}
