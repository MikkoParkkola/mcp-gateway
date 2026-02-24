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
