use std::{collections::HashSet, path::PathBuf};

use serde_json::Value;

use super::*;
use crate::discovery::{DiscoveredServer, ServerMetadata};

fn stdio_server(
    name: &str,
    description: &str,
    command: &str,
    source: DiscoverySource,
    config_path: Option<&str>,
    pid: Option<u32>,
    port: Option<u16>,
) -> DiscoveredServer {
    DiscoveredServer {
        name: name.to_string(),
        description: description.to_string(),
        source,
        transport: TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
            protocol_version: None,
        },
        metadata: ServerMetadata {
            config_path: config_path.map(PathBuf::from),
            pid,
            port,
            command: Some(command.to_string()),
            working_dir: None,
        },
    }
}

fn http_server(
    name: &str,
    description: &str,
    url: &str,
    source: DiscoverySource,
    pid: Option<u32>,
    port: Option<u16>,
) -> DiscoveredServer {
    DiscoveredServer {
        name: name.to_string(),
        description: description.to_string(),
        source,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: false,
            protocol_version: None,
        },
        metadata: ServerMetadata {
            config_path: None,
            pid,
            port,
            command: None,
            working_dir: None,
        },
    }
}

fn report(discovered: &[DiscoveredServer], registered: &[&str]) -> ShadowScanReport {
    let registered_names = registered
        .iter()
        .map(|name| (*name).to_string())
        .collect::<HashSet<_>>();
    ShadowScanReport::from_discovered(
        discovered,
        &registered_names,
        Some(Path::new("gateway.yaml")),
    )
}

fn risk_codes(asset: &ShadowAsset) -> HashSet<&str> {
    asset.risks.iter().map(|risk| risk.code.as_str()).collect()
}

#[test]
fn shadow_asset_schema() {
    let report = report(
        &[stdio_server(
            "local-filesystem",
            "Local filesystem MCP server",
            "mcp-files --private-value REDACTED",
            DiscoverySource::ClaudeCode,
            Some("/tmp/claude_desktop_config.json"),
            None,
            Some(7788),
        )],
        &[],
    );

    let value = serde_json::to_value(&report).unwrap();
    let asset = &value["assets"][0];

    assert_eq!(value["schema_version"], SHADOW_REPORT_SCHEMA_VERSION);
    assert_eq!(asset["asset_id"], asset["id"]);
    assert_eq!(asset["kind"], "mcp_server");
    assert_eq!(asset["management_status"], "unmanaged");
    assert!(asset["source"].is_string());
    assert!(asset["evidence"].is_object());
    assert!(
        asset["risks"]
            .as_array()
            .is_some_and(|risks| !risks.is_empty())
    );
    assert!(
        asset["remediation_hints"]
            .as_array()
            .is_some_and(|hints| !hints.is_empty())
    );
}

#[test]
fn shadow_risk_classifier() {
    let report = report(
        &[
            stdio_server(
                "legacy-filesystem",
                "deprecated filesystem server",
                "/tmp/stale-mcp-files --private-value REDACTED",
                DiscoverySource::ClaudeCode,
                Some("/tmp/claude.json"),
                None,
                Some(7777),
            ),
            http_server(
                "remote-gmail",
                "Gmail server",
                "https://mcp.example.com/sse",
                DiscoverySource::McpConfig,
                None,
                Some(7777),
            ),
            http_server(
                "unknown-owner",
                "Unknown provenance server",
                "http://127.0.0.1:3000/mcp",
                DiscoverySource::McpConfig,
                None,
                None,
            ),
        ],
        &[],
    );

    let all_codes = report
        .assets
        .iter()
        .flat_map(risk_codes)
        .collect::<HashSet<_>>();
    let all_details = report
        .assets
        .iter()
        .flat_map(|asset| asset.risks.iter().map(|risk| risk.detail.as_str()))
        .collect::<HashSet<_>>();

    for expected in [
        "unmanaged_server",
        "duplicate_port",
        "unauthenticated_http_endpoint",
        "stale_binary",
        "unknown_provenance",
        "personal_access_reference",
        "missing_trust_metadata",
    ] {
        assert!(all_codes.contains(expected), "missing risk code {expected}");
    }
    assert!(all_details.contains("Server is not managed by the compared gateway configuration."));
}

#[test]
fn shadow_scan_collects_configs_processes_ports_and_gateway_registry() {
    let report = report(
        &[
            stdio_server(
                "managed",
                "Managed server",
                "managed-mcp",
                DiscoverySource::ClaudeCode,
                Some("/tmp/managed.json"),
                None,
                None,
            ),
            stdio_server(
                "config-shadow",
                "Config shadow",
                "config-shadow-mcp",
                DiscoverySource::ClaudeCode,
                Some("/tmp/config.json"),
                None,
                None,
            ),
            http_server(
                "process-shadow",
                "Process shadow",
                "http://127.0.0.1:31337/mcp",
                DiscoverySource::RunningProcess,
                Some(4242),
                Some(31337),
            ),
        ],
        &["managed"],
    );

    assert_eq!(report.summary.discovered_total, 3);
    assert_eq!(report.summary.managed_total, 1);
    assert_eq!(report.summary.unmanaged_total, 2);
    assert!(
        report
            .assets
            .iter()
            .any(|asset| asset.evidence.config_path.as_deref() == Some("/tmp/config.json"))
    );
    assert!(
        report
            .assets
            .iter()
            .any(|asset| asset.evidence.pid == Some(4242))
    );
    assert!(
        report
            .assets
            .iter()
            .any(|asset| asset.evidence.port == Some(31337))
    );
    assert!(
        report
            .assets
            .iter()
            .all(|asset| asset.evidence.gateway_config.as_deref() == Some("gateway.yaml"))
    );
}

#[test]
fn shadow_scan_does_not_spawn_configured_stdio_commands() {
    let report = report(
        &[stdio_server(
            "never-spawn",
            "Configured stdio server",
            "dangerous-command --private-value REDACTED",
            DiscoverySource::ClaudeCode,
            Some("/tmp/client.json"),
            None,
            None,
        )],
        &[],
    );

    assert!(report.passive);
    assert!(!report.tools_invoked);
    assert!(report.assets[0].evidence.command_present);
    assert_eq!(
        report.assets[0].evidence.executable.as_deref(),
        Some("dangerous-command")
    );
}

#[test]
fn shadow_probe_passive_only_never_sends_tools_call() {
    let report = report(
        &[http_server(
            "remote-shadow",
            "Remote server",
            "https://mcp.example.com/mcp",
            DiscoverySource::Environment,
            None,
            None,
        )],
        &[],
    );

    let serialized = serde_json::to_string(&report).unwrap();
    assert!(report.passive);
    assert!(!report.tools_invoked);
    assert!(!serialized.contains("tools/call"));
}

#[test]
fn shadow_scan_outputs_json_and_table_reports() {
    let report = report(
        &[stdio_server(
            "table-ready",
            "Local table-ready server",
            "table-ready-mcp",
            DiscoverySource::Environment,
            None,
            None,
            None,
        )],
        &[],
    );

    let value: Value = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    assert_eq!(value["schema_version"], SHADOW_REPORT_SCHEMA_VERSION);
    let asset = &report.assets[0];
    assert_eq!(asset.name, "table-ready");
    assert_eq!(asset.management_status, "unmanaged");
    assert_eq!(asset.severity, ShadowRiskSeverity::Medium);
    assert_eq!(
        asset.remediation.action,
        ShadowRemediationAction::AdoptIntoGateway
    );
}

#[test]
fn shadow_scan_free_mode_rejects_cidr_network_scan() {
    let report = report(&[], &[]);
    let boundary = report.enterprise_boundary();

    assert_eq!(
        boundary.free_core_scan.license_tier,
        ShadowLicenseTier::FreeCore
    );
    assert_eq!(boundary.free_core_scan.mode, ShadowScanMode::LocalPassive);
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
}

#[test]
fn enterprise_shadow_scan_extension_point_is_gated() {
    let report = report(&[], &[]);
    let boundary = report.enterprise_boundary();

    assert_eq!(
        boundary.enterprise_scan.license_tier,
        ShadowLicenseTier::Enterprise
    );
    assert!(
        boundary
            .enterprise_scan
            .allowed_capabilities
            .contains(&ShadowScanCapability::NetworkRangeScan)
    );
    assert!(
        boundary
            .evidence_exports
            .iter()
            .all(|export| export.requires_enterprise_license)
    );
}
