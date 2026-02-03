//! Integration tests for MCP Gateway

use mcp_gateway::config::{CircuitBreakerConfig, Config, RetryConfig};
use mcp_gateway::failsafe::{CircuitBreaker, CircuitState, RetryPolicy, with_retry};
use mcp_gateway::protocol::{
    JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION, RequestId, SUPPORTED_VERSIONS,
    negotiate_version,
};
use pretty_assertions::assert_eq;
use std::time::Duration;

#[test]
fn test_protocol_version() {
    // Latest protocol version
    assert_eq!(PROTOCOL_VERSION, "2024-11-05");
    // Supported versions include latest and older
    assert!(SUPPORTED_VERSIONS.contains(&"2024-11-05"));
    assert!(SUPPORTED_VERSIONS.contains(&"2024-10-07"));
}

#[test]
fn test_version_negotiation() {
    // Client requests supported version - gets it back
    assert_eq!(negotiate_version("2024-11-05"), "2024-11-05");
    assert_eq!(negotiate_version("2024-10-07"), "2024-10-07");

    // Client requests unknown version - gets latest as fallback
    assert_eq!(negotiate_version("2023-01-01"), "2024-11-05");
    assert_eq!(negotiate_version("unknown"), "2024-11-05");
}

#[test]
fn test_request_id_display() {
    let id_num = RequestId::Number(42);
    assert_eq!(id_num.to_string(), "42");

    let id_str = RequestId::String("test-123".to_string());
    assert_eq!(id_str.to_string(), "test-123");
}

#[test]
fn test_json_rpc_request_serialization() {
    let request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: RequestId::Number(1),
        method: "tools/list".to_string(),
        params: None,
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("\"jsonrpc\":\"2.0\""));
    assert!(json.contains("\"method\":\"tools/list\""));
    assert!(json.contains("\"id\":1"));
}

#[test]
fn test_json_rpc_response_success() {
    let response = JsonRpcResponse::success(RequestId::Number(1), serde_json::json!({"tools": []}));

    assert!(response.error.is_none());
    assert!(response.result.is_some());
    assert_eq!(response.id, Some(RequestId::Number(1)));
}

#[test]
fn test_json_rpc_response_error() {
    let response = JsonRpcResponse::error(Some(RequestId::Number(1)), -32600, "Invalid request");

    assert!(response.result.is_none());
    assert!(response.error.is_some());
    let error = response.error.unwrap();
    assert_eq!(error.code, -32600);
    assert_eq!(error.message, "Invalid request");
}

#[test]
fn test_config_defaults() {
    let config = Config::default();

    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 39400);
    assert!(config.meta_mcp.enabled);
    assert!(config.failsafe.circuit_breaker.enabled);
    assert!(config.failsafe.retry.enabled);
}

#[test]
fn test_circuit_breaker_starts_closed() {
    let config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 5,
        success_threshold: 3,
        reset_timeout: Duration::from_secs(30),
    };
    let cb = CircuitBreaker::new("test", &config);
    assert_eq!(cb.state(), CircuitState::Closed);
}

#[test]
fn test_circuit_breaker_opens_after_failures() {
    let config = CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 3,
        success_threshold: 2,
        reset_timeout: Duration::from_secs(30),
    };
    let cb = CircuitBreaker::new("test", &config);

    // Record failures
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed); // Still closed

    cb.record_failure(); // Third failure
    assert_eq!(cb.state(), CircuitState::Open); // Now open
}

#[test]
fn test_circuit_breaker_disabled() {
    let config = CircuitBreakerConfig {
        enabled: false, // Disabled
        failure_threshold: 1,
        success_threshold: 1,
        reset_timeout: Duration::from_secs(1),
    };
    let cb = CircuitBreaker::new("test", &config);

    // Even with failures, it stays closed when disabled
    cb.record_failure();
    cb.record_failure();
    assert!(cb.can_proceed());
}

#[tokio::test]
async fn test_retry_policy_retries_on_failure() {
    let config = RetryConfig {
        enabled: true,
        max_attempts: 3,
        initial_backoff: Duration::from_millis(1), // Fast for tests
        max_backoff: Duration::from_millis(10),
        multiplier: 2.0,
    };
    let policy = RetryPolicy::new(&config);

    let attempts = std::sync::atomic::AtomicU32::new(0);
    let result: Result<(), mcp_gateway::Error> = with_retry(&policy, "test", || {
        let attempt = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        async move {
            if attempt < 3 {
                Err(mcp_gateway::Error::Transport("test".to_string()))
            } else {
                Ok(())
            }
        }
    })
    .await;

    assert!(result.is_ok());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[tokio::test]
async fn test_retry_policy_disabled() {
    let config = RetryConfig {
        enabled: false, // Disabled
        max_attempts: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(10),
        multiplier: 2.0,
    };
    let policy = RetryPolicy::new(&config);

    let attempts = std::sync::atomic::AtomicU32::new(0);
    let result: Result<(), mcp_gateway::Error> = with_retry(&policy, "test", || {
        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async { Err(mcp_gateway::Error::Transport("test".to_string())) }
    })
    .await;

    // Only one attempt when disabled
    assert!(result.is_err());
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}
