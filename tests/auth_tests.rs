//! End-to-end authentication tests
//!
//! Tests the full auth flow including:
//! - Bearer token authentication
//! - API key authentication
//! - Rate limiting
//! - Backend access control

use mcp_gateway::config::{ApiKeyConfig, AuthConfig};
use mcp_gateway::gateway::auth::{AuthenticatedClient, ResolvedAuthConfig};

/// Test that ResolvedAuthConfig correctly resolves from AuthConfig
#[test]
fn test_auth_config_resolution() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: Some("test-token".to_string()),
        api_keys: vec![ApiKeyConfig {
            key: "api-key-1".to_string(),
            name: "Test Client".to_string(),
            rate_limit: 100,
            backends: vec!["tavily".to_string()],
        }],
        public_paths: vec!["/health".to_string()],
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config);

    assert!(resolved.enabled);
    assert_eq!(resolved.bearer_token, Some("test-token".to_string()));
    assert_eq!(resolved.api_keys.len(), 1);
    assert_eq!(resolved.api_keys[0].name, "Test Client");
    assert!(resolved.is_public_path("/health"));
    assert!(!resolved.is_public_path("/mcp"));
}

/// Test bearer token validation
#[test]
fn test_bearer_token_auth() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: Some("secret-bearer-token".to_string()),
        api_keys: vec![],
        public_paths: vec![],
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config);

    // Valid bearer token
    let client = resolved.validate_token("secret-bearer-token");
    assert!(client.is_some());
    let client = client.unwrap();
    assert_eq!(client.name, "bearer");
    assert!(client.can_access_backend("any-backend"));

    // Invalid token
    assert!(resolved.validate_token("wrong-token").is_none());
}

/// Test API key authentication with backend restrictions
#[test]
fn test_api_key_auth_with_restrictions() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            ApiKeyConfig {
                key: "restricted-key".to_string(),
                name: "Restricted Client".to_string(),
                rate_limit: 50,
                backends: vec!["tavily".to_string(), "brave".to_string()],
            },
            ApiKeyConfig {
                key: "unrestricted-key".to_string(),
                name: "Unrestricted Client".to_string(),
                rate_limit: 0,
                backends: vec![], // empty = all access
            },
        ],
        public_paths: vec![],
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config);

    // Restricted client
    let client = resolved.validate_token("restricted-key").unwrap();
    assert_eq!(client.name, "Restricted Client");
    assert_eq!(client.rate_limit, 50);
    assert!(client.can_access_backend("tavily"));
    assert!(client.can_access_backend("brave"));
    assert!(!client.can_access_backend("context7"));

    // Unrestricted client
    let client = resolved.validate_token("unrestricted-key").unwrap();
    assert_eq!(client.name, "Unrestricted Client");
    assert_eq!(client.rate_limit, 0);
    assert!(client.can_access_backend("any-backend"));
}

/// Test rate limiting enforcement
#[test]
fn test_rate_limiting() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: "rate-limited-key".to_string(),
            name: "Rate Limited".to_string(),
            rate_limit: 2, // Very low for testing
            backends: vec![],
        }],
        public_paths: vec![],
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config);

    // First requests should succeed (within limit)
    assert!(resolved.check_rate_limit("Rate Limited"));
    assert!(resolved.check_rate_limit("Rate Limited"));

    // Third request should be rate limited
    assert!(!resolved.check_rate_limit("Rate Limited"));

    // Unknown client should not be rate limited
    assert!(resolved.check_rate_limit("Unknown Client"));
}

/// Test public paths bypass authentication
#[test]
fn test_public_paths() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: Some("token".to_string()),
        api_keys: vec![],
        public_paths: vec![
            "/health".to_string(),
            "/metrics".to_string(),
            "/api/public/".to_string(),
        ],
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config);

    // Exact matches
    assert!(resolved.is_public_path("/health"));
    assert!(resolved.is_public_path("/metrics"));

    // Prefix matches
    assert!(resolved.is_public_path("/health/deep"));
    assert!(resolved.is_public_path("/api/public/anything"));

    // Non-public paths
    assert!(!resolved.is_public_path("/mcp"));
    assert!(!resolved.is_public_path("/api/private"));
    assert!(!resolved.is_public_path("/"));
}

/// Test auto-generated bearer token
#[test]
fn test_auto_generated_token() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: Some("auto".to_string()),
        api_keys: vec![],
        public_paths: vec![],
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config);

    // Auto-generated token should start with "mcp_" and be 47 chars
    let token = resolved.bearer_token.as_ref().unwrap();
    assert!(token.starts_with("mcp_"), "Token should start with mcp_");
    assert!(token.len() > 40, "Token should be reasonably long");

    // Token should be valid
    assert!(resolved.validate_token(token).is_some());
}

/// Test AuthenticatedClient backend access patterns
#[test]
fn test_client_backend_access_patterns() {
    // Wildcard access
    let wildcard_client = AuthenticatedClient {
        name: "wildcard".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
    };
    assert!(wildcard_client.can_access_backend("anything"));
    assert!(wildcard_client.can_access_backend("tavily"));

    // Empty backends = all access
    let all_access_client = AuthenticatedClient {
        name: "all".to_string(),
        rate_limit: 0,
        backends: vec![],
    };
    assert!(all_access_client.can_access_backend("anything"));

    // Specific backends only
    let restricted_client = AuthenticatedClient {
        name: "restricted".to_string(),
        rate_limit: 0,
        backends: vec!["backend-a".to_string(), "backend-b".to_string()],
    };
    assert!(restricted_client.can_access_backend("backend-a"));
    assert!(restricted_client.can_access_backend("backend-b"));
    assert!(!restricted_client.can_access_backend("backend-c"));
}

/// Test disabled auth passes through
#[test]
fn test_disabled_auth() {
    let auth_config = AuthConfig {
        enabled: false,
        bearer_token: Some("ignored".to_string()),
        api_keys: vec![],
        public_paths: vec![],
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config);
    assert!(!resolved.enabled);
}
