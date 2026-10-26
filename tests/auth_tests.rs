// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! End-to-end authentication tests
//!
//! Tests the full auth flow including:
//! - Bearer token authentication
//! - API key authentication
//! - Rate limiting
//! - Backend access control

#[path = "common/record_key.rs"]
mod record_key;

use std::time::Duration;

use mcp_gateway::config::{ApiKeyConfig, AuthConfig, CircuitBreakerConfig};
use mcp_gateway::failsafe::CircuitState;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;

/// Test that `ResolvedAuthConfig` correctly resolves from `AuthConfig`
#[test]
fn test_auth_config_resolution() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: Some("test-token".to_string()),
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                "api-key-1".as_bytes(),
            )),
            expires_at: None,
            name: "Test Client".to_string(),
            rate_limit: 100,
            backends: vec!["tavily".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: mcp_gateway::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);

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
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);

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
                key: None,
                key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                    "restricted-key".as_bytes(),
                )),
                expires_at: None,
                name: "Restricted Client".to_string(),
                rate_limit: 50,
                backends: vec!["tavily".to_string(), "brave".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                kind: mcp_gateway::config::ApiKeyKind::Shared,
                ..Default::default()
            },
            ApiKeyConfig {
                key: None,
                key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                    "unrestricted-key".as_bytes(),
                )),
                expires_at: None,
                name: "Unrestricted Client".to_string(),
                rate_limit: 0,
                backends: vec!["*".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                kind: mcp_gateway::config::ApiKeyKind::Shared,
                ..Default::default()
            },
        ],
        public_paths: vec![],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);

    // Restricted client
    let client = resolved.validate_token("restricted-key").unwrap();
    assert_eq!(client.name, "Restricted Client");
    assert_eq!(client.rate_limit, 50);
    assert!(client.can_access_backend("tavily"));
    assert!(client.can_access_backend("brave"));
    assert!(!client.can_access_backend("context7"));

    // Wildcard client
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
            key: None,
            key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                "rate-limited-key".as_bytes(),
            )),
            expires_at: None,
            name: "Rate Limited".to_string(),
            rate_limit: 2, // Very low for testing
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: mcp_gateway::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        public_paths: vec![],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);

    let client = resolved
        .validate_token("rate-limited-key")
        .expect("the configured key validates");

    // First requests should succeed (within limit)
    assert!(resolved.check_authenticated_client_rate_limit(&client));
    assert!(resolved.check_authenticated_client_rate_limit(&client));

    // Third request should be rate limited
    assert!(!resolved.check_authenticated_client_rate_limit(&client));

    // A client with no limit is never rate limited
    let unlimited = mcp_gateway::gateway::auth::anonymous_client();
    assert!(resolved.check_authenticated_client_rate_limit(&unlimited));
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
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);

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
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);

    // Auto-generated token should start with "mcp_" and be 47 chars
    let token = resolved.bearer_token.as_ref().unwrap();
    assert!(token.starts_with("mcp_"), "Token should start with mcp_");
    assert!(token.len() > 40, "Token should be reasonably long");

    // Token should be valid
    assert!(resolved.validate_token(token).is_some());
}

/// Test disabled auth passes through
#[test]
fn test_disabled_auth() {
    let auth_config = AuthConfig {
        enabled: false,
        bearer_token: Some("ignored".to_string()),
        api_keys: vec![],
        public_paths: vec![],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);
    assert!(!resolved.enabled);
}

#[test]
fn test_client_circuit_breaker_is_per_client() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            ApiKeyConfig {
                key: None,
                key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                    "client-a-key".as_bytes(),
                )),
                expires_at: None,
                name: "client-a".to_string(),
                rate_limit: 0,
                backends: vec!["*".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                kind: mcp_gateway::config::ApiKeyKind::Shared,
                ..Default::default()
            },
            ApiKeyConfig {
                key: None,
                key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                    "client-b-key".as_bytes(),
                )),
                expires_at: None,
                name: "client-b".to_string(),
                rate_limit: 0,
                backends: vec!["*".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                kind: mcp_gateway::config::ApiKeyKind::Shared,
                ..Default::default()
            },
        ],
        public_paths: vec![],
        client_circuit_breaker: Some(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            reset_timeout: Duration::from_secs(60),
        }),
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);
    let client_a = resolved.validate_token("client-a-key").expect("client-a");
    let client_b = resolved.validate_token("client-b-key").expect("client-b");

    assert!(resolved.check_client_circuit_breaker(&client_a));
    resolved.record_client_failure(&client_a);
    assert_eq!(
        resolved.client_circuit_state(&client_a),
        Some(CircuitState::Closed)
    );
    resolved.record_client_failure(&client_a);

    assert_eq!(
        resolved.client_circuit_state(&client_a),
        Some(CircuitState::Open)
    );
    assert!(!resolved.check_client_circuit_breaker(&client_a));
    assert!(resolved.check_client_circuit_breaker(&client_b));
}

#[test]
fn test_client_circuit_breaker_recovers_after_successful_probe() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(mcp_gateway::config::api_key_digest_spec(
                "client-key".as_bytes(),
            )),
            expires_at: None,
            name: "recovering-client".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: mcp_gateway::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        public_paths: vec![],
        client_circuit_breaker: Some(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            // Zero: the next check is the half-open probe, with no real time
            // to wait out.
            // timing: fixture
            reset_timeout: Duration::ZERO,
        }),
        single_user: false,
        dashboard_session: mcp_gateway::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(&auth_config, crate::record_key::RECORD_KEY);
    let client = resolved
        .validate_token("client-key")
        .expect("the configured key");

    resolved.record_client_failure(&client);
    assert_eq!(
        resolved.client_circuit_state(&client),
        Some(CircuitState::Open)
    );
    assert!(resolved.check_client_circuit_breaker(&client));
    assert_eq!(
        resolved.client_circuit_state(&client),
        Some(CircuitState::HalfOpen)
    );

    resolved.record_client_success(&client);

    assert_eq!(
        resolved.client_circuit_state(&client),
        Some(CircuitState::Closed)
    );
}
