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

/// Build a minimal DiscoveredServer with the given name.
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
    let registered: std::collections::HashSet<String> =
        ["tavily", "github"].iter().map(|s| s.to_string()).collect();

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
    let registered: std::collections::HashSet<String> =
        ["alpha", "beta"].iter().map(|s| s.to_string()).collect();

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
    let registered: std::collections::HashSet<String> =
        ["Tavily"].iter().map(|s| s.to_string()).collect();

    let discovered = vec![make_discovered("tavily")];

    // WHEN: filtering (case-sensitive comparison matches gateway config keys)
    let shadows: Vec<_> = discovered
        .into_iter()
        .filter(|s| !registered.contains(&s.name))
        .collect();

    // THEN: "tavily" (lowercase) is treated as unregistered
    assert_eq!(shadows.len(), 1);
}
