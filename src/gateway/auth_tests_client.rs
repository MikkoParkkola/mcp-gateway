// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

// Moved from tests/auth_tests.rs when `AuthenticatedClient.principal` became
// crate-private.
#[test]
fn test_resolved_client_rate_limit_creates_identity_bucket() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![],
        public_paths: vec![],
        client_circuit_breaker: None,
        single_user: false,
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    };

    let resolved = ResolvedAuthConfig::from_config(
        &auth_config,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    );
    let temporary_client = AuthenticatedClient {
        quota_principal: None,
        principal: InternalPrincipal::new(String::new()),
        name: "temporary@example.com".to_string(),
        rate_limit: 2,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    assert!(resolved.check_authenticated_client_rate_limit(&temporary_client));
    assert!(resolved.check_authenticated_client_rate_limit(&temporary_client));
    assert!(!resolved.check_authenticated_client_rate_limit(&temporary_client));
}

/// Test `AuthenticatedClient` backend access patterns
#[test]
fn test_client_backend_access_patterns() {
    // Wildcard access
    let wildcard_client = AuthenticatedClient {
        quota_principal: None,
        principal: InternalPrincipal::new(String::new()),
        name: "wildcard".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };
    assert!(wildcard_client.can_access_backend("anything"));
    assert!(wildcard_client.can_access_backend("tavily"));

    // Empty backends = no backend (BACKENDGRANT.1)
    let no_backends_client = AuthenticatedClient {
        quota_principal: None,
        principal: InternalPrincipal::new(String::new()),
        name: "none".to_string(),
        rate_limit: 0,
        backends: vec![],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };
    assert!(!no_backends_client.can_access_backend("anything"));

    // Specific backends only
    let restricted_client = AuthenticatedClient {
        quota_principal: None,
        principal: InternalPrincipal::new(String::new()),
        name: "restricted".to_string(),
        rate_limit: 0,
        backends: vec!["backend-a".to_string(), "backend-b".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };
    assert!(restricted_client.can_access_backend("backend-a"));
    assert!(restricted_client.can_access_backend("backend-b"));
    assert!(!restricted_client.can_access_backend("backend-c"));
}
