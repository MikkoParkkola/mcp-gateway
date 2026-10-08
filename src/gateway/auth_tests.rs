// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::num::NonZeroU32;

use governor::Quota;

use super::*;
use crate::config::AuthConfig;

fn test_digest(key: &str) -> [u8; 32] {
    crate::config::parse_api_key_digest(&crate::config::api_key_digest_spec(key.as_bytes()))
        .expect("a computed digest parses")
}

#[test]
fn empty_bearer_refused_by_try_from_config() {
    let config = AuthConfig {
        enabled: true,
        bearer_token: Some(String::new()),
        ..AuthConfig::default()
    };
    let err = ResolvedAuthConfig::try_from_config(&config, &crate::config::EnvOverlay::none())
        .expect_err("an empty bearer would match an empty presented token");
    assert!(err.to_string().contains("empty"), "got: {err}");
}

// ── Anonymous identity (CWE-346) ──────────────────────────────────────────
//
// With auth off every caller is anonymous. Anonymous must reach ordinary
// tools so a local MCP client keeps working, and must NOT hold admin, so a
// local process or a browser that gets past the Origin gate cannot kill
// servers, reload config or read the admin dashboard.

#[test]
fn anonymous_is_not_admin() {
    assert!(!anonymous_client().admin, "admin must require a credential");
}

#[test]
fn anonymous_retains_backend_access() {
    // Asserts reachability, not the field: `can_access_backend` returns
    // true for an EMPTY list, so a fix that clears the vector grants
    // everything while looking like a restriction.
    let anon = anonymous_client();
    assert!(anon.can_access_backend("any-backend"));
}

#[test]
fn bearer_client_remains_admin() {
    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: Some("bearer-ADMIN".to_string()),
        bearer_quota_principal: Some(QuotaPrincipal::configured_bearer("bearer-ADMIN")),
        api_keys: vec![],
        public_paths: vec![],
        rate_limiters: DashMap::new(),
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };
    let bearer = config.validate_token("bearer-ADMIN").expect("bearer valid");
    assert!(bearer.admin, "an explicit credential still grants admin");
}

#[test]
fn looks_like_jwt_accepts_three_base64url_segments() {
    // Build from parts so no JWT-shaped literal trips the secret scanner.
    let jwt = format!("{}.{}.{}", "abc-_", "def-_", "ghi-_");
    assert!(looks_like_jwt(&jwt));
    assert!(looks_like_jwt("aGVhZGVy.cGF5bG9hZA.c2ln"));
}

#[test]
fn looks_like_jwt_rejects_non_jwt_tokens() {
    // opaque static keys / exchanged tokens have no JWT shape
    assert!(!looks_like_jwt("static-key-12345"));
    assert!(!looks_like_jwt("two.parts"));
    assert!(!looks_like_jwt("four.parts.here.nope"));
    assert!(!looks_like_jwt("a..c")); // empty middle segment
    assert!(!looks_like_jwt("")); // empty
    assert!(!looks_like_jwt("has spaces.in.it"));
    assert!(!looks_like_jwt("plus+slash/.b.c")); // base64 (not url) chars
}

#[test]
fn test_public_path_check() {
    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: Some("test".to_string()),
        bearer_quota_principal: Some(QuotaPrincipal::configured_bearer("test")),
        api_keys: vec![],
        public_paths: vec!["/health".to_string(), "/metrics".to_string()],
        rate_limiters: DashMap::new(),
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };

    assert!(config.is_public_path("/health"));
    assert!(config.is_public_path("/health/"));
    assert!(config.is_public_path("/metrics"));
    assert!(!config.is_public_path("/mcp"));
    assert!(!config.is_public_path("/"));
}

#[test]
fn debug_output_redacts_bearer_and_api_keys() {
    // CWE-532 / MIK-6733 sibling: {:?} must never leak resolved secrets.
    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: Some("super-secret-bearer-VALUE".to_string()),
        bearer_quota_principal: Some(QuotaPrincipal::configured_bearer(
            "super-secret-bearer-VALUE",
        )),
        api_keys: vec![ResolvedApiKey {
            digest: test_digest("api-key-SECRET-VALUE"),
            expires_at: None,
            quota_principal: QuotaPrincipal::api_key(&test_digest("api-key-SECRET-VALUE")),
            name: "client-a".to_string(),
            rate_limit: 60,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            personal: false,
        }],
        public_paths: vec![],
        rate_limiters: DashMap::new(),
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };
    let dbg = format!("{config:?}");
    assert!(
        !dbg.contains("super-secret-bearer-VALUE"),
        "Debug leaked the bearer token: {dbg}"
    );
    assert!(
        !dbg.contains("api-key-SECRET-VALUE"),
        "Debug leaked the API key: {dbg}"
    );
    assert!(
        dbg.contains("<redacted"),
        "expected redaction marker: {dbg}"
    );
    // Non-secret fields stay visible for diagnostics.
    assert!(
        dbg.contains("client-a"),
        "api key name should remain visible"
    );
}

#[test]
fn fingerprint_is_not_the_secret() {
    let fp = bearer_token_fingerprint("super-secret-bearer-VALUE");
    assert_eq!(fp.len(), 12);
    assert!(!fp.contains("secret"));
    assert_ne!(fp, "super-secret-bearer-VALUE");
}

#[test]
fn test_bearer_token_validation() {
    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: Some("secret123".to_string()),
        bearer_quota_principal: Some(QuotaPrincipal::configured_bearer("secret123")),
        api_keys: vec![],
        public_paths: vec![],
        rate_limiters: DashMap::new(),
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };

    let client = config.validate_token("secret123");
    assert!(client.is_some());
    assert_eq!(client.unwrap().name, "bearer");
    assert!(config.validate_token("wrong").is_none());
}

#[test]
fn constant_time_token_comparison_accepts_correct_rejects_wrong() {
    // CWE-208: `validate_token` compares bearer + API keys with
    // `subtle::ConstantTimeEq`. Timing cannot be asserted in a unit test,
    // so this pins the *functional* contract the constant-time path must
    // preserve: exact match authenticates; any mismatch (wrong value,
    // length mismatch, empty) is rejected.
    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: Some("bearer-EXACT".to_string()),
        bearer_quota_principal: Some(QuotaPrincipal::configured_bearer("bearer-EXACT")),
        api_keys: vec![ResolvedApiKey {
            digest: test_digest("apikey-EXACT"),
            expires_at: None,
            quota_principal: QuotaPrincipal::api_key(&test_digest("apikey-EXACT")),
            name: "client-ct".to_string(),
            rate_limit: 10,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            personal: false,
        }],
        public_paths: vec![],
        rate_limiters: DashMap::new(),
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };

    // Correct bearer authenticates as the admin "bearer" client.
    let bearer = config.validate_token("bearer-EXACT").expect("bearer valid");
    assert_eq!(bearer.name, "bearer");
    assert!(bearer.admin);

    // Correct API key authenticates as the named client.
    let keyed = config
        .validate_token("apikey-EXACT")
        .expect("api key valid");
    assert_eq!(keyed.name, "client-ct");
    assert!(!keyed.admin);

    // Mismatches are rejected: wrong value, length mismatch, empty, and a
    // prefix of a valid secret (guards against non-constant-time shortcuts).
    for wrong in [
        "bearer-WRONG",
        "apikey-WRONG",
        "bearer-EXAC",
        "",
        "bearer-EXACTx",
    ] {
        assert!(
            config.validate_token(wrong).is_none(),
            "token {wrong:?} must not authenticate"
        );
    }
}

#[test]
fn test_api_key_validation() {
    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: None,
        bearer_quota_principal: None,
        api_keys: vec![
            ResolvedApiKey {
                digest: test_digest("key1"),
                expires_at: None,
                quota_principal: QuotaPrincipal::api_key(&test_digest("key1")),
                name: "Client A".to_string(),
                rate_limit: 100,
                backends: vec!["tavily".to_string()],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                personal: false,
            },
            ResolvedApiKey {
                digest: test_digest("key2"),
                expires_at: None,
                quota_principal: QuotaPrincipal::api_key(&test_digest("key2")),
                name: "Client B".to_string(),
                rate_limit: 0,
                backends: vec![],
                allowed_tools: None,
                denied_tools: None,
                admin: false,
                personal: false,
            },
        ],
        public_paths: vec![],
        rate_limiters: DashMap::new(),
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };

    let client_a = config.validate_token("key1").unwrap();
    assert_eq!(client_a.name, "Client A");
    assert!(client_a.can_access_backend("tavily"));
    assert!(!client_a.can_access_backend("brave"));

    let client_b = config.validate_token("key2").unwrap();
    assert_eq!(client_b.name, "Client B");
    assert!(!client_b.can_access_backend("anything"));

    assert!(config.validate_token("wrong").is_none());
}

#[test]
fn test_rate_limiting() {
    let rate_limiters = DashMap::new();
    // Create a rate limiter with 2 requests per minute for testing
    let limiter = RateLimiter::direct(Quota::per_minute(NonZeroU32::new(2).unwrap()));
    rate_limiters.insert("limited_client".to_string(), Arc::new(limiter));

    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: None,
        bearer_quota_principal: None,
        api_keys: vec![],
        public_paths: vec![],
        rate_limiters,
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };

    // First two requests should succeed
    assert!(config.check_rate_limit("limited_client"));
    assert!(config.check_rate_limit("limited_client"));
    // Third request should be rate limited
    assert!(!config.check_rate_limit("limited_client"));
    // Unknown client (no limiter) should always succeed
    assert!(config.check_rate_limit("unknown_client"));
}

// ── Tool scope tests ──────────────────────────────────────────────────

#[test]
fn test_tool_scope_no_restrictions() {
    let client = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "unrestricted".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    // No restrictions = all tools allowed (fallback to global policy)
    assert!(client.check_tool_scope("server", "any_tool").is_ok());
    assert!(client.check_tool_scope("server", "write_file").is_ok());
}

#[test]
fn test_tool_scope_allowlist_exact_match() {
    let client = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "restricted".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: Some(vec!["search_web".to_string(), "read_file".to_string()]),
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    // Tools in allowlist
    assert!(client.check_tool_scope("server", "search_web").is_ok());
    assert!(client.check_tool_scope("server", "read_file").is_ok());

    // Tools NOT in allowlist
    assert!(client.check_tool_scope("server", "write_file").is_err());
    assert!(client.check_tool_scope("server", "delete_file").is_err());
}

#[test]
fn test_tool_scope_allowlist_glob_pattern() {
    let client = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "search_only".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: Some(vec!["search_*".to_string(), "read_*".to_string()]),
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    // Tools matching glob patterns
    assert!(client.check_tool_scope("server", "search_web").is_ok());
    assert!(client.check_tool_scope("server", "search_local").is_ok());
    assert!(client.check_tool_scope("server", "read_file").is_ok());
    assert!(client.check_tool_scope("server", "read_database").is_ok());

    // Tools NOT matching glob patterns
    assert!(client.check_tool_scope("server", "write_file").is_err());
    assert!(
        client
            .check_tool_scope("server", "execute_command")
            .is_err()
    );
}

#[test]
fn test_tool_scope_denylist_exact_match() {
    let client = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "no_writes".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: Some(vec!["write_file".to_string(), "delete_file".to_string()]),
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    // Tools in denylist
    assert!(client.check_tool_scope("server", "write_file").is_err());
    assert!(client.check_tool_scope("server", "delete_file").is_err());

    // Tools NOT in denylist
    assert!(client.check_tool_scope("server", "read_file").is_ok());
    assert!(client.check_tool_scope("server", "search_web").is_ok());
}

#[test]
fn test_tool_scope_denylist_glob_pattern() {
    let client = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "no_filesystem".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: Some(vec!["filesystem_*".to_string(), "exec_*".to_string()]),
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    // Tools matching deny glob patterns
    assert!(
        client
            .check_tool_scope("server", "filesystem_read")
            .is_err()
    );
    assert!(
        client
            .check_tool_scope("server", "filesystem_write")
            .is_err()
    );
    assert!(client.check_tool_scope("server", "exec_command").is_err());
    assert!(client.check_tool_scope("server", "exec_shell").is_err());

    // Tools NOT matching deny patterns
    assert!(client.check_tool_scope("server", "search_web").is_ok());
    assert!(client.check_tool_scope("server", "database_query").is_ok());
}

#[test]
fn test_tool_scope_qualified_name_match() {
    let client = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "specific_server".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: Some(vec![
            "filesystem:read_file".to_string(),
            "search_*".to_string(),
        ]),
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    // Qualified match: only filesystem:read_file allowed, not other servers
    assert!(client.check_tool_scope("filesystem", "read_file").is_ok());
    assert!(client.check_tool_scope("other", "read_file").is_err());

    // Glob still matches across all servers
    assert!(client.check_tool_scope("any_server", "search_web").is_ok());
}

#[test]
fn test_tool_scope_both_allow_and_deny() {
    let client = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "complex".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: Some(vec!["filesystem_*".to_string(), "search_*".to_string()]),
        denied_tools: Some(vec![
            "filesystem_write".to_string(),
            "filesystem_delete".to_string(),
        ]),
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    // In allowlist and NOT in denylist
    assert!(client.check_tool_scope("server", "filesystem_read").is_ok());
    assert!(client.check_tool_scope("server", "search_web").is_ok());

    // In allowlist BUT in denylist (denylist wins)
    assert!(
        client
            .check_tool_scope("server", "filesystem_write")
            .is_err()
    );
    assert!(
        client
            .check_tool_scope("server", "filesystem_delete")
            .is_err()
    );

    // NOT in allowlist
    assert!(
        client
            .check_tool_scope("server", "execute_command")
            .is_err()
    );
}

#[test]
fn test_tool_scope_error_messages() {
    let client_allow = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "frontend".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: Some(vec!["search_*".to_string()]),
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    let err = client_allow
        .check_tool_scope("server", "write_file")
        .unwrap_err();
    assert!(err.contains("write_file"));
    assert!(err.contains("server"));
    assert!(err.contains("allowlist"));
    assert!(err.contains("frontend"));

    let client_deny = AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: "restricted_bot".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: Some(vec!["exec_*".to_string()]),
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };

    let err = client_deny
        .check_tool_scope("server", "exec_command")
        .unwrap_err();
    assert!(err.contains("exec_command"));
    assert!(err.contains("server"));
    assert!(err.contains("blocked"));
    assert!(err.contains("restricted_bot"));
}

/// A dashboard bootstrap link for an install whose only admin credential is
/// an API key.
///
/// The value is exchanged for an opaque session handle, never for the
/// credential itself, so demanding a bearer specifically refuses every
/// API-key-only operator for a token the exchange would not have used.
fn bootstrap_state(bearer: Option<&str>, keys: Vec<ResolvedApiKey>) -> (AuthState, String) {
    let config = ResolvedAuthConfig {
        enabled: true,
        bearer_token: bearer.map(ToString::to_string),
        bearer_quota_principal: bearer.map(QuotaPrincipal::configured_bearer),
        api_keys: keys,
        public_paths: vec![],
        rate_limiters: DashMap::new(),
        client_circuit_breaker: None,
        client_circuit_breakers: DashMap::new(),
    };
    let bootstrap = Arc::new(DashboardBootstrap::new());
    let printed = bootstrap.peek().expect("a value is issued at startup");
    (
        AuthState {
            auth_config: Arc::new(config),
            key_server: None,
            dashboard_bootstrap: bootstrap,
            tls_enabled: false,
            live_config: Arc::new(crate::config_reload::LiveConfig::new(
                crate::config::Config::default(),
            )),
            agent_auth: crate::gateway::oauth::AgentAuthState::new(
                false,
                std::sync::Arc::default(),
            ),
        },
        printed,
    )
}

fn admin_key(admin: bool) -> ResolvedApiKey {
    ResolvedApiKey {
        digest: test_digest("key-value"),
        expires_at: None,
        quota_principal: QuotaPrincipal::api_key(&test_digest("key-value")),
        name: "ops".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        personal: false,
    }
}

fn redeem(state: &AuthState, printed: &str) -> axum::http::StatusCode {
    let request = Request::builder()
        .uri(format!("/dashboard?bootstrap={printed}"))
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))))
        .body(Body::empty())
        .expect("request builds");
    try_dashboard_bootstrap(state, &request)
        .expect("a bootstrap link is always answered here")
        .status()
}

#[path = "auth/tests/bootstrap_spend_tests.rs"]
mod bootstrap_spend_tests;
#[test]
fn an_admin_api_key_is_an_admin_credential_for_the_bootstrap_link() {
    let (state, printed) = bootstrap_state(None, vec![admin_key(true)]);
    assert_eq!(
        redeem(&state, &printed),
        axum::http::StatusCode::SEE_OTHER,
        "an install administered by API key must be able to open its own dashboard"
    );
}

/// The other half: a key that is not admin is not an admin credential.
///
/// Without this, a repair that only checks the list is non-empty hands a
/// full-admin dashboard session to an install that deliberately issued
/// nothing but restricted keys.
#[test]
fn a_restricted_api_key_does_not_open_the_dashboard() {
    let (state, printed) = bootstrap_state(None, vec![admin_key(false)]);
    assert_eq!(
        redeem(&state, &printed),
        axum::http::StatusCode::UNAUTHORIZED,
        "a restricted key is not an admin credential"
    );
}

/// A watch poll runs as the key its subscription stored. A key re-issued
/// under the same name has another secret, so it does not inherit the poll.
#[test]
fn a_key_reissued_under_the_same_name_is_another_caller() {
    let stored = principal_of("key-value");
    let (state, _) = bootstrap_state(None, vec![admin_key(false)]);
    assert!(state.auth_config.client_for_key("ops", &stored).is_some());
    let mut reissued = admin_key(false);
    reissued.digest = test_digest("new-value");
    let (state, _) = bootstrap_state(None, vec![reissued]);
    assert!(state.auth_config.client_for_key("ops", &stored).is_none());
}
