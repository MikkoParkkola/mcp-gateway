//! Backend integration tests

use std::time::Duration;

use mcp_gateway::backend::Backend;
use mcp_gateway::config::{BackendConfig, FailsafeConfig, TransportConfig};

fn create_test_backend(name: &str, command: &str) -> Backend {
    let config = BackendConfig {
        description: format!("Test backend: {}", name),
        enabled: true,
        transport: TransportConfig::Stdio {
            command: command.to_string(),
            cwd: None,
        },
        idle_timeout: Duration::from_secs(60),
        timeout: Duration::from_secs(30),
        env: Default::default(),
        headers: Default::default(),
        oauth: None,
    };

    let failsafe = FailsafeConfig::default();
    Backend::new(name, config, &failsafe, Duration::from_secs(300))
}

#[test]
fn test_backend_creation() {
    let backend = create_test_backend("test", "echo hello");
    assert_eq!(backend.name, "test");
    assert!(!backend.is_running());
}

#[test]
fn test_backend_transport_type() {
    let stdio_config = TransportConfig::Stdio {
        command: "echo".to_string(),
        cwd: None,
    };
    assert_eq!(stdio_config.transport_type(), "stdio");

    let http_config = TransportConfig::Http {
        http_url: "http://localhost:8080/mcp".to_string(),
        streamable_http: false,
        protocol_version: None,
    };
    assert_eq!(http_config.transport_type(), "http");

    let sse_config = TransportConfig::Http {
        http_url: "http://localhost:8080/sse".to_string(),
        streamable_http: false,
        protocol_version: None,
    };
    assert_eq!(sse_config.transport_type(), "sse");

    let streamable_config = TransportConfig::Http {
        http_url: "http://localhost:8080/mcp".to_string(),
        streamable_http: true,
        protocol_version: None,
    };
    assert_eq!(streamable_config.transport_type(), "streamable-http");
}

#[tokio::test]
async fn test_backend_registry() {
    use mcp_gateway::backend::BackendRegistry;
    use std::sync::Arc;

    let registry = BackendRegistry::new();

    let backend = Arc::new(create_test_backend("test1", "echo"));
    registry.register(backend);

    assert!(registry.get("test1").is_some());
    assert!(registry.get("nonexistent").is_none());
    assert_eq!(registry.all().len(), 1);
}
