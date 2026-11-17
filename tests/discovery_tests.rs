// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Discovery module tests

#[path = "common/private_home.rs"]
#[macro_use]
mod private_home;
#[path = "common/gateway_bin.rs"]
mod gateway_bin;

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
    require_private_home!();
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
    require_private_home!();
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
    require_private_home!();
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
    require_private_home!();
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

    let server = DiscoveredServer::new(
        "test-server".to_string(),
        "Test Server".to_string(),
        DiscoverySource::Environment,
        TransportConfig::Http {
            http_url: "http://localhost:3000".to_string(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        ServerMetadata {
            config_path: None,
            pid: None,
            port: Some(3000),
            command: None,
            working_dir: None,
        },
    );

    let backend_config = server.to_backend_config();
    assert_eq!(backend_config.description, "Test Server");
    assert!(backend_config.enabled);

    match backend_config.transport {
        TransportConfig::Http { http_url, .. } => {
            assert_eq!(http_url, "http://localhost:3000");
        }
        other => panic!("Expected HTTP transport, got {other:?}"),
    }
}

#[tokio::test]
async fn test_deduplication() {
    require_private_home!();
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

    DiscoveredServer::new(
        name.to_string(),
        format!("{name} server"),
        DiscoverySource::Environment,
        TransportConfig::Http {
            http_url: format!("http://localhost:3000/{name}"),
            streamable_http: Some(false),
            protocol_version: None,
        },
        ServerMetadata::default(),
    )
}

fn make_stdio_discovered(name: &str, command: &str) -> mcp_gateway::discovery::DiscoveredServer {
    use mcp_gateway::config::TransportConfig;
    use mcp_gateway::discovery::{DiscoveredServer, ServerMetadata};

    DiscoveredServer::new(
        name.to_string(),
        format!("{name} server"),
        DiscoverySource::ClaudeCode,
        TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        ServerMetadata {
            config_path: Some(std::path::PathBuf::from("/tmp/client-config.json")),
            pid: None,
            port: None,
            command: Some(command.to_string()),
            working_dir: None,
        },
    )
}

fn make_http_discovered(name: &str, url: &str) -> mcp_gateway::discovery::DiscoveredServer {
    use mcp_gateway::config::TransportConfig;
    use mcp_gateway::discovery::{DiscoveredServer, ServerMetadata};

    DiscoveredServer::new(
        name.to_string(),
        format!("{name} server"),
        DiscoverySource::Environment,
        TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(false),
            protocol_version: None,
        },
        ServerMetadata {
            config_path: None,
            pid: None,
            port: None,
            command: None,
            working_dir: None,
        },
    )
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

    let report = keyed_report(
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

    let report = keyed_report(
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

    let report = keyed_report(&discovered, &registered, None);
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

    let report = keyed_report(&discovered, &registered, None);
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

    let report = keyed_report(&discovered, &registered, None);

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

    let left = keyed_report(&discovered, &registered, None);
    let right = keyed_report(&discovered, &registered, None);

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

    let report = keyed_report(
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
    // The endpoint is the origin only: a URL path can carry a token.
    assert_eq!(
        remote_inventory.endpoint.as_deref(),
        Some("https://mcp.example.com")
    );

    let serialized = serde_json::to_string(&handoff).unwrap();
    assert!(!serialized.contains("PRIVATEVALUE"));
    assert!(!serialized.contains("session="));
}

/// A report keyed by a fixed record key in a fresh data dir, so its ids hold
/// across reports, as the gateway's do.
fn keyed_report(
    discovered: &[mcp_gateway::discovery::DiscoveredServer],
    registered: &std::collections::HashSet<String>,
    gateway_config: Option<&std::path::Path>,
) -> ShadowScanReport {
    let data_dir = tempfile::tempdir().expect("data dir");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        data_dir.path().join("record-principal.key"),
        "ab".repeat(32),
    )
    .expect("key file");
    ShadowScanReport::from_discovered(
        discovered,
        registered,
        gateway_config,
        None,
        data_dir.path(),
    )
}

/// T3-T5: this binary's gateway home routes to the test-home override.
#[test]
fn private_home_routes_to_the_override() {
    private_home::assert_routes_to_the_override(
        module_path!(),
        "private_home_routes_to_the_override",
    );
}

/// The sources T1 plants, as literal paths per OS (relative to a home) and the
/// file content for a server named `<n>` with the command `<n>`. One server
/// per source, each with a unique name and command, so de-duplication cannot
/// merge them. Parsers: src/discovery/config_scanner.rs parse_claude_config
/// :275, parse_vscode_config :303, parse_zed_config :454, parse_continue_config
/// :504, scan_mcp_config_dir :191.
fn int1_sources() -> Vec<(&'static str, String, fn(&str) -> String)> {
    let mcp_servers: fn(&str) -> String =
        |n| format!(r#"{{"mcpServers":{{"{n}":{{"command":"{n}"}}}}}}"#);
    let vscode: fn(&str) -> String =
        |n| format!(r#"{{"mcp":{{"servers":{{"{n}":{{"command":"{n}"}}}}}}}}"#);
    let continue_: fn(&str) -> String =
        |n| format!(r#"{{"mcpServers":[{{"name":"{n}","command":"{n}"}}]}}"#);
    let zed: fn(&str) -> String =
        |n| format!(r#"{{"context_servers":{{"{n}":{{"command":"{n}"}}}}}}"#);
    let app = if cfg!(target_os = "macos") {
        "Library/Application Support"
    } else if cfg!(windows) {
        "AppData/Roaming"
    } else {
        ".config"
    };
    let zed_path = if cfg!(windows) {
        ".config/Zed/settings.json"
    } else {
        ".config/zed/settings.json"
    };
    vec![
        ("claude-code", ".claude.json".into(), mcp_servers),
        ("cursor-mcp", ".cursor/mcp.json".into(), mcp_servers),
        ("continue", ".continue/config.json".into(), continue_),
        ("codex", ".codex/config.json".into(), mcp_servers),
        (
            "claude-desktop",
            format!("{app}/Claude/claude_desktop_config.json"),
            mcp_servers,
        ),
        (
            "windsurf",
            format!("{app}/Windsurf/windsurf_config.json"),
            mcp_servers,
        ),
        ("vscode", format!("{app}/Code/User/settings.json"), vscode),
        ("cursor", format!("{app}/Cursor/User/settings.json"), vscode),
        ("zed", zed_path.into(), zed),
        (
            "mcp-config",
            ".config/mcp/PLACEHOLDER.json".into(),
            mcp_servers,
        ),
    ]
}

/// Plant every source under `home` for the name prefix `prefix`; returns the
/// files written, with their bytes.
fn int1_plant(home: &std::path::Path, prefix: &str) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    int1_sources()
        .into_iter()
        .map(|(source, rel, content)| {
            let name = format!("{prefix}-{source}");
            let rel = rel.replace("PLACEHOLDER", &name);
            let path = home.join(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("source dir");
            let bytes = content(&name).into_bytes();
            std::fs::write(&path, &bytes).expect("source file");
            (path, bytes)
        })
        .collect()
}

/// T1 (INT.1): discovery reads only the private home. Canaries are
/// planted in a decoy real home (HOME, USERPROFILE, APPDATA), never the
/// developer's own dirs; private entries in the override home must all be
/// listed and no canary may be. On Windows `dirs` ignores USERPROFILE, so the
/// canary negative proves nothing about the decoy there; the preflight and the
/// private entries are the routing evidence.
#[test]
fn int1_discovery_reads_only_the_private_home() {
    const ME: &str = "int1_discovery_reads_only_the_private_home";
    if private_home::is_row_child(ME) {
        let a = std::path::PathBuf::from(
            std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR").expect("the override"),
        );
        let b = std::path::PathBuf::from(std::env::var_os("HOME").expect("the decoy home"));
        // Preflight: nothing is written or scanned unless every routing check holds.
        let temp = private_home::canonical(&std::env::temp_dir());
        for dir in [&a, &b] {
            let canonical = private_home::canonical(dir);
            assert!(
                canonical.starts_with(&temp) && canonical != temp,
                "{} is not a private temp dir",
                dir.display()
            );
        }
        let data = mcp_gateway::config_persistence::gateway_data_dir();
        assert_eq!(
            private_home::canonical_leaf(&data),
            private_home::canonical(&a).join(".mcp-gateway")
        );
        #[cfg(not(target_os = "macos"))]
        {
            let config = mcp_gateway::gateway::test_helpers::config_dir().expect("a config dir");
            assert_eq!(
                private_home::canonical_leaf(&config),
                private_home::canonical(&a).join(".config")
            );
        }
        let pid = std::process::id();
        let canaries = int1_plant(&b, &format!("canary-{pid}"));
        let _private = int1_plant(&a, &format!("private-{pid}"));
        let found = tokio::runtime::Runtime::new()
            .expect("a runtime")
            .block_on(AutoDiscovery::new().discover_all())
            .expect("discovery runs");
        let names: std::collections::BTreeSet<String> =
            found.iter().map(|server| server.name.clone()).collect();
        let private: std::collections::BTreeSet<String> = names
            .iter()
            .filter(|name| name.starts_with(&format!("private-{pid}-")))
            .cloned()
            .collect();
        let expected: std::collections::BTreeSet<String> = int1_sources()
            .iter()
            .map(|(source, _, _)| format!("private-{pid}-{source}"))
            .collect();
        assert_eq!(
            private, expected,
            "every private source is listed, exactly once"
        );
        let leaked: Vec<&String> = names
            .iter()
            .filter(|name| name.starts_with(&format!("canary-{pid}")))
            .collect();
        assert!(
            leaked.is_empty(),
            "decoy-home canaries were read: {leaked:?} (on Windows this negative proves nothing about the decoy: dirs ignores USERPROFILE)"
        );
        for (path, bytes) in canaries {
            assert_eq!(
                std::fs::read(&path).expect("canary readable"),
                bytes,
                "{} changed",
                path.display()
            );
        }
        return;
    }
    let a = private_home::fresh_private_dir();
    let b = private_home::fresh_private_dir();
    let command = gateway_bin::isolated_with_env_home(
        std::process::Command::new(std::env::current_exe().expect("the test binary")),
        a.path(),
        b.path(),
        gateway_bin::Inherit::Environment,
    );
    let _kept =
        private_home::run_row_child(command, ME, false, &private_home::Expect::Pass, vec![a, b]);
}

/// T6: with XDG_CONFIG_HOME removed, the config dir still routes to
/// the override, so a lookup that ignored the override cannot hide behind an
/// explicit XDG value.
#[cfg(not(target_os = "macos"))]
#[test]
fn t6_config_routes_to_the_override_without_xdg() {
    const ME: &str = "t6_config_routes_to_the_override_without_xdg";
    if private_home::is_row_child(ME) {
        assert!(
            std::env::var_os("XDG_CONFIG_HOME").is_none(),
            "premise: XDG_CONFIG_HOME is removed"
        );
        let a = std::path::PathBuf::from(
            std::env::var_os("MCP_GATEWAY_TEST_HOME_DIR").expect("the override"),
        );
        let config = mcp_gateway::gateway::test_helpers::config_dir().expect("a config dir");
        assert_eq!(
            private_home::canonical_leaf(&config),
            private_home::canonical(&a).join(".config")
        );
        return;
    }
    let a = private_home::fresh_private_dir();
    let b = private_home::fresh_private_dir();
    let mut command = gateway_bin::isolated_with_env_home(
        std::process::Command::new(std::env::current_exe().expect("the test binary")),
        a.path(),
        b.path(),
        gateway_bin::Inherit::Environment,
    );
    command.env_remove("XDG_CONFIG_HOME");
    let _kept =
        private_home::run_row_child(command, ME, false, &private_home::Expect::Pass, vec![a, b]);
}
