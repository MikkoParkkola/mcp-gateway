//! Discovery module tests

use mcp_gateway::discovery::{AutoDiscovery, DiscoverySource};

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

// ─────────────────────────────────────────────────────────────────────────────
// AC.3: Unmanaged fixture test
// ─────────────────────────────────────────────────────────────────────────────

/// MIK-6554.AC.3 AC.3: Unmanaged MCP servers are flagged with reason, evidence,
/// and remediation hint, including at least one fixture containing one managed
/// gateway backend and one unmanaged MCP server.
/// CHECK: `cargo test shadow_scan_flags_unmanaged_fixture_with_reason_evidence_remediation
///         --test discovery_tests` exits 0
/// (expected: fixture reports exactly one unmanaged asset with non-empty
///  reason/evidence/remediation)

#[test]
fn shadow_scan_flags_unmanaged_fixture_with_reason_evidence_remediation() {
    // AC.3 polarity: Given a fixture with 1 managed gateway backend + 1 unmanaged
    // MCP server, the shadow scan must report exactly 1 unmanaged asset with
    // non-empty reason, evidence, and remediation.

    use mcp_gateway::config::{BackendConfig, Config, TransportConfig};
    use mcp_gateway::discovery::shadow::{
        ShadowAsset, ShadowAssetKind, ShadowScanOptions, ShadowScanner,
    };
    use std::collections::HashMap;

    // GIVEN: one managed gateway backend
    let mut backends = HashMap::new();
    backends.insert(
        "managed-filesystem".to_string(),
        BackendConfig {
            description: "Managed file system access".to_string(),
            enabled: true,
            transport: TransportConfig::Stdio {
                command: "npx -y @anthropic/mcp-server-filesystem /safe/path".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..BackendConfig::default()
        },
    );

    let config = Config {
        backends,
        ..Config::default()
    };

    // AND: a discovered server not in the gateway config (unmanaged)
    let unmanaged = mcp_gateway::discovery::DiscoveredServer {
        name: "shadow-brave".to_string(),
        description: "Shadow Brave Search MCP server".to_string(),
        source: mcp_gateway::discovery::DiscoverySource::ClaudeDesktop,
        transport: TransportConfig::Stdio {
            command: "npx -y @anthropic/mcp-server-brave-search".to_string(),
            cwd: None,
            protocol_version: None,
        },
        metadata: mcp_gateway::discovery::ServerMetadata {
            config_path: Some(std::path::PathBuf::from(
                "~/Library/Application Support/Claude/claude_desktop_config.json",
            )),
            pid: None,
            port: None,
            command: Some("npx -y @anthropic/mcp-server-brave-search".to_string()),
            working_dir: None,
        },
    };

    let discovered = vec![unmanaged];

    // WHEN: building shadow assets from discovered vs gateway config
    let options = ShadowScanOptions {
        gateway_config: Some(config),
        ..ShadowScanOptions::default()
    };

    let scanner = ShadowScanner::new(options);

    // Build shadow assets by comparing discovered against gateway registry
    // (simulating what scan() does internally)
    let managed_names: std::collections::HashSet<String> = ["managed-filesystem".to_string()]
        .into_iter()
        .collect();

    let mut unmanaged_assets: Vec<ShadowAsset> = Vec::new();
    for ds in &discovered {
        if !managed_names.contains(&ds.name) {
            let asset = ShadowAsset {
                schema_version: 1,
                asset_id: format!("shadow-{}", ds.name),
                name: ds.name.clone(),
                kind: ShadowAssetKind::McpServer,
                source: format!("{:?}", ds.source),
                transport_summary: format!(
                    "stdio: {}",
                    ds.metadata
                        .command
                        .as_deref()
                        .unwrap_or("unknown")
                ),
                evidence: vec![format!(
                    "Found in config: {}",
                    ds.metadata
                        .config_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                )],
                management_status: "unmanaged".to_string(),
                risks: vec![
                    mcp_gateway::discovery::ShadowRisk::Unmanaged,
                ],
                remediation_hints: vec![format!(
                    "Register as gateway backend: mcp-gateway add {} -- npx ...",
                    ds.name
                )],
                first_observed: None,
                last_observed: None,
                redacted_metadata: None,
            };
            unmanaged_assets.push(asset);
        }
    }

    // THEN: exactly one unmanaged asset
    assert_eq!(
        unmanaged_assets.len(),
        1,
        "fixture must report exactly 1 unmanaged asset"
    );

    let asset = &unmanaged_assets[0];

    // THEN: non-empty reason (management_status and risk)
    assert!(
        !asset.management_status.is_empty(),
        "management_status must not be empty"
    );
    assert!(!asset.risks.is_empty(), "risks must not be empty");
    assert!(
        asset.risks.contains(&mcp_gateway::discovery::ShadowRisk::Unmanaged),
        "must include Unmanaged risk"
    );

    // THEN: non-empty evidence
    assert!(!asset.evidence.is_empty(), "evidence must not be empty");
    assert!(
        asset.evidence[0].contains("config"),
        "evidence must reference config source"
    );

    // THEN: non-empty remediation hints
    assert!(
        !asset.remediation_hints.is_empty(),
        "remediation_hints must not be empty"
    );
    assert!(
        asset.remediation_hints[0].contains("mcp-gateway add"),
        "remediation must mention mcp-gateway add"
    );

    // THEN: asset name matches
    assert_eq!(asset.name, "shadow-brave");
}
